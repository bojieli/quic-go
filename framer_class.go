package quic

import (
	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/ackhandler"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/apernet/quic-go/quicvarint"
)

// minClassedStreamFrame is the least space worth offering a stream when a
// class is served: a STREAM frame's header and one byte. Unlike the ordinary
// builder's 128-byte threshold for leftover space, a class budget may be all
// a stream gets, so a small one must still make progress.
const minClassedStreamFrame protocol.ByteCount = 16

// ringEntry is a stream filed in a class ring. Only the entry whose
// generation is the stream's current one is live; re-filing a stream makes a
// new entry and leaves the old one to be skipped, so a stream that moves away
// from a class and back is still served once per round.
type ringEntry struct {
	id    protocol.StreamID
	class congestion.SendClass
	gen   uint64
}

// classedStream is a stream that can be served by class. A stream that is not
// one (a test double) is BULK.
type classedStream interface {
	streamClass() congestion.SendClass
	sendableClass(connWindow bool) (congestion.SendClass, bool)
	popClassedStreamFrame(maxBytes protocol.ByteCount, want congestion.SendClass, v protocol.Version) (_ ackhandler.StreamFrame, _ *wire.StreamDataBlockedFrame, hasMore bool, served, next congestion.SendClass)
}

var _ classedStream = &SendStream{}

func classOfStream(str streamFrameGetter) congestion.SendClass {
	if cs, ok := str.(classedStream); ok {
		return cs.streamClass()
	}
	return congestion.ClassBulk
}

// SetClassed switches the framer between one round-robin ring of streams and
// one ring per class. The active streams move with the switch.
func (f *framer) SetClassed(on bool) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.classed == on {
		return
	}
	f.classed = on
	if on {
		if f.ringOf == nil {
			f.ringOf = make(map[protocol.StreamID]ringEntry)
		}
		for !f.streamQueue.Empty() {
			id := f.streamQueue.PopFront()
			if str, ok := f.activeStreams[id]; ok {
				if _, filed := f.ringOf[id]; !filed {
					f.file(id, classOfStream(str))
				}
			}
		}
		return
	}
	for class := range f.classRings {
		ring := &f.classRings[class]
		for !ring.Empty() {
			e := ring.PopFront()
			if f.live(e) {
				delete(f.ringOf, e.id)
				f.streamQueue.PushBack(e.id)
			}
		}
	}
	clear(f.ringOf)
}

// file makes a new live entry for a stream in class's ring. It must be called
// with the mutex held.
func (f *framer) file(id protocol.StreamID, class congestion.SendClass) {
	f.ringGen++
	e := ringEntry{id: id, class: class, gen: f.ringGen}
	f.ringOf[id] = e
	f.classRings[class].PushBack(e)
}

// live says whether a ring entry is its stream's current one. It must be
// called with the mutex held.
func (f *framer) live(e ringEntry) bool {
	if _, ok := f.activeStreams[e.id]; !ok {
		return false
	}
	cur, ok := f.ringOf[e.id]
	return ok && cur == e
}

// fileStream makes a stream active, or re-files it when its effective class
// changed. It must be called with the mutex held.
func (f *framer) fileStream(id protocol.StreamID, str streamFrameGetter) {
	class := classOfStream(str)
	if _, ok := f.activeStreams[id]; !ok {
		f.activeStreams[id] = str
	} else if e, filed := f.ringOf[id]; filed && e.class == class {
		return
	}
	f.file(id, class)
}

// hasClassedStreams says whether any class ring holds a stream. It must be
// called with the mutex held.
func (f *framer) hasClassedStreams() bool {
	for i := range f.classRings {
		if !f.classRings[i].Empty() {
			return true
		}
	}
	return false
}

// StreamDemand reports per class whether an active stream of that effective
// class could send a frame now. It consumes nothing.
func (f *framer) StreamDemand(connWindow bool) [congestion.NumSendClasses]bool {
	var d [congestion.NumSendClasses]bool
	f.mutex.Lock()
	defer f.mutex.Unlock()
	for _, str := range f.activeStreams {
		cs, ok := str.(classedStream)
		if !ok {
			if s, ok := str.(interface{ hasSendableData(bool) bool }); !ok || s.hasSendableData(connWindow) {
				d[congestion.ClassBulk] = true
			}
			continue
		}
		if class, sendable := cs.sendableClass(connWindow); sendable {
			d[class] = true
		}
	}
	return d
}

// AppendClass appends frames of one class, up to maxLen bytes: for CONTROL
// the queued control frames other than exempt obligations, then the streams
// whose effective class it is, round-robin. Flow-control notifications that
// streams of another class produce are left for a CONTROL pass. Each STREAM
// frame keeps its length field, which the caller removes from the packet's
// last one; last says no other class follows in this packet, so a frame of
// this class may count on that and use the length field's bytes. The length
// returned counts the frames as they are.
func (f *framer) AppendClass(
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	class congestion.SendClass,
	maxLen protocol.ByteCount,
	last bool,
	now monotime.Time,
	v protocol.Version,
) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()
	var length protocol.ByteCount
	if class == congestion.ClassControl {
		frames, length = f.appendOrdinaryControlFrames(frames, 0, maxLen, now, v)
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()
	var sentStream bool
	var n protocol.ByteCount
	frames, streamFrames, n, sentStream = f.appendClassStreams(frames, streamFrames, class, maxLen-length, last, v)
	length += n
	if !sentStream && maxLen-length >= minClassedStreamFrame && f.refile(class) {
		// A stream whose class changed without being re-filed: every change
		// re-files, so this is a safety net, not the way streams move.
		frames, streamFrames, n, sentStream = f.appendClassStreams(frames, streamFrames, class, maxLen-length, last, v)
		length += n
	}
	if sentStream {
		if isBlocked, offset := f.connFlowController.IsNewlyBlocked(); isBlocked {
			blocked := &wire.DataBlockedFrame{MaximumData: offset}
			if l := blocked.Length(v); class == congestion.ClassControl && maxLen-length >= l {
				frames = append(frames, ackhandler.Frame{Frame: blocked})
				length += l
			} else {
				f.controlFrames = append(f.controlFrames, blocked)
			}
		}
	}
	return frames, streamFrames, length
}

// refile files every active stream in the ring of its current class, and
// says whether one moved into class. It must be called with the mutex held.
func (f *framer) refile(class congestion.SendClass) bool {
	var moved bool
	for id, str := range f.activeStreams {
		c := classOfStream(str)
		if e, ok := f.ringOf[id]; ok && e.class == c {
			continue
		}
		f.file(id, c)
		moved = moved || c == class
	}
	return moved
}

// appendClassStreams serves the streams filed in class, round-robin, up to
// maxLen bytes. A stream's class is checked under its own lock as its frame
// is taken; one whose class changed is re-filed instead. It must be called
// with both mutexes held.
func (f *framer) appendClassStreams(
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	class congestion.SendClass,
	maxLen protocol.ByteCount,
	last bool,
	v protocol.Version,
) (_ []ackhandler.Frame, _ []ackhandler.StreamFrame, length protocol.ByteCount, sentStream bool) {
	ring := &f.classRings[class]
	for range ring.Len() {
		remaining := maxLen - length
		if remaining < minClassedStreamFrame {
			break
		}
		e := ring.PopFront()
		if !f.live(e) {
			continue
		}
		str := f.activeStreams[e.id]
		popLen := remaining
		if last {
			// As in getNextStreamFrame: the length field of the packet's
			// last STREAM frame is removed later.
			popLen += protocol.ByteCount(quicvarint.Len(uint64(remaining)))
		}
		var (
			sf      ackhandler.StreamFrame
			blocked *wire.StreamDataBlockedFrame
			hasMore bool
			next    = class
		)
		if cs, ok := str.(classedStream); ok {
			var served congestion.SendClass
			sf, blocked, hasMore, served, next = cs.popClassedStreamFrame(popLen, class, v)
			if served != class {
				// Its class changed since it was filed; nothing was taken.
				f.file(e.id, served)
				continue
			}
		} else {
			sf, blocked, hasMore = str.popStreamFrame(popLen, v)
		}
		if hasMore {
			f.file(e.id, next)
		} else {
			delete(f.activeStreams, e.id)
			delete(f.ringOf, e.id)
		}
		if sf.Frame != nil {
			streamFrames = append(streamFrames, sf)
			length += sf.Frame.Length(v)
			sentStream = true
		}
		if blocked != nil {
			// A flow-control notification is CONTROL work.
			if l := blocked.Length(v); class == congestion.ClassControl && maxLen-length >= l {
				frames = append(frames, ackhandler.Frame{Frame: blocked})
				length += l
			} else {
				f.controlFrames = append(f.controlFrames, blocked)
			}
		}
	}
	return frames, streamFrames, length, sentStream
}

// appendAllClasses is Append's stream part on a class-scheduled connection,
// for a build outside class scheduling (a PTO probe). It takes the classes in
// priority order. It is called with both mutexes held and releases them.
func (f *framer) appendAllClasses(
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	controlFrameLen, maxLen protocol.ByteCount,
	v protocol.Version,
) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
	start := len(streamFrames)
	var length protocol.ByteCount
	var sentStream bool
	for _, class := range classOrder {
		var n protocol.ByteCount
		var sent bool
		// Only the last class may borrow the length field's bytes.
		frames, streamFrames, n, sent = f.appendClassStreams(frames, streamFrames, class, maxLen-length, class == congestion.ClassBulk, v)
		length += n
		sentStream = sentStream || sent
	}
	if sentStream {
		if isBlocked, offset := f.connFlowController.IsNewlyBlocked(); isBlocked {
			blocked := &wire.DataBlockedFrame{MaximumData: offset}
			if l := blocked.Length(v); maxLen-length >= l {
				frames = append(frames, ackhandler.Frame{Frame: blocked})
				length += l
			} else {
				f.controlFrames = append(f.controlFrames, blocked)
			}
		}
	}
	f.mutex.Unlock()
	f.controlFrameMutex.Unlock()
	if len(streamFrames) > start {
		last := streamFrames[len(streamFrames)-1].Frame
		withLen := last.Length(v)
		last.DataLenPresent = false
		length -= withLen - last.Length(v)
	}
	return frames, streamFrames, controlFrameLen + length
}
