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
	f.liveIn = [congestion.NumSendClasses]int{}
}

// file makes a new live entry for a stream in class's ring. It must be called
// with the mutex held.
func (f *framer) file(id protocol.StreamID, class congestion.SendClass) {
	f.unfile(id)
	f.ringGen++
	e := ringEntry{id: id, class: class, gen: f.ringGen}
	f.ringOf[id] = e
	f.liveIn[class]++
	f.classRings[class].PushBack(e)
}

// unfile makes a stream's live entry stale, and compacts its ring when stale
// entries outnumber live ones: a ring whose class gets no turns would
// otherwise keep every entry that moved away from it. It must be called with
// the mutex held.
func (f *framer) unfile(id protocol.StreamID) {
	old, ok := f.ringOf[id]
	if !ok {
		return
	}
	delete(f.ringOf, id)
	f.liveIn[old.class]--
	ring := &f.classRings[old.class]
	if f.serving || ring.Len() <= 2*f.liveIn[old.class]+32 {
		return
	}
	for range ring.Len() {
		e := ring.PopFront()
		if f.live(e) {
			ring.PushBack(e)
		}
	}
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
// class could send a frame now. It consumes nothing. Each class's ring is
// walked in order, and a stream is asked only until one of the class can
// send, so a class of busy streams costs one stream lock, not one per stream.
// A stream asked whose class changed is counted for its current class.
func (f *framer) StreamDemand(connWindow bool) [congestion.NumSendClasses]bool {
	var d [congestion.NumSendClasses]bool
	f.mutex.Lock()
	defer f.mutex.Unlock()
	for _, class := range classOrder {
		ring := &f.classRings[class]
		for i := 0; i < ring.Len() && !d[class]; i++ {
			e := ring.At(i)
			if !f.live(e) {
				continue
			}
			str := f.activeStreams[e.id]
			cs, ok := str.(classedStream)
			if !ok {
				if s, ok := str.(interface{ hasSendableData(bool) bool }); !ok || s.hasSendableData(connWindow) {
					d[congestion.ClassBulk] = true
				}
				continue
			}
			if c, sendable := cs.sendableClass(connWindow); sendable {
				d[c] = true
			}
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
		frames, length = f.appendClassedControlFrames(frames, maxLen, now, v)
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()
	var sentStream bool
	var n protocol.ByteCount
	frames, streamFrames, n, sentStream = f.appendClassStreams(frames, streamFrames, class, maxLen-length, last, v)
	length += n
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

// appendClassedControlFrames is the CONTROL pass's share of the queued
// control frames other than exempt obligations. A class budget can be
// smaller than a packet, so unlike the ordinary builder it does not stop at
// the first frame that does not fit: smaller ones behind it still go, and a
// CRYPTO frame is split to the space left. It must be called with
// controlFrameMutex held.
func (f *framer) appendClassedControlFrames(frames []ackhandler.Frame, maxLen protocol.ByteCount, now monotime.Time, v protocol.Version) ([]ackhandler.Frame, protocol.ByteCount) {
	// RESET_STREAM_AT, the largest stream control frame, is 33 bytes.
	frames, length := f.appendStreamControlFramesBelow(frames, 0, maxLen, maxStreamControlFrameSizeAt, now, v)
	// The queue is popped from its end. Frames are taken from the end down
	// to the first index examined; those kept are compacted in place over
	// the examined range, in their order, and the unexamined front stays
	// as it is, so a pass costs what it looks at.
	q := f.controlFrames
	w := len(q) // the retained frames are written down from the end
	i := len(q) - 1
	for ; i >= 0; i-- {
		room := maxLen - length
		if room <= 0 {
			break
		}
		frame := q[i]
		if l := frame.Length(v); l <= room {
			frames = append(frames, ackhandler.Frame{Frame: frame})
			length += l
			continue
		}
		if cf, ok := frame.(*wire.CryptoFrame); ok {
			if head, split := cf.MaybeSplitOffFrame(room, v); split && head != nil {
				frames = append(frames, ackhandler.Frame{Frame: head})
				length += head.Length(v)
			}
		}
		w--
		q[w] = frame
	}
	// q[:i+1] was not examined; q[w:] holds the retained frames in order.
	n := copy(q[i+1:], q[w:])
	clear(q[i+1+n:])
	f.controlFrames = q[:i+1+n]
	return frames, length
}

// maxStreamControlFrameSizeAt is the largest stream control frame,
// RESET_STREAM_AT with four eight-byte varints.
const maxStreamControlFrameSizeAt = 33

// RefileStream re-files an active stream whose effective class may have
// changed outside the framer's own pops (a verification grant's build path).
func (f *framer) RefileStream(id protocol.StreamID, str streamFrameGetter) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if !f.classed {
		return
	}
	if _, ok := f.activeStreams[id]; ok {
		f.fileStream(id, str)
	}
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
	f.serving = true
	defer func() { f.serving = false }()
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
		if last && remaining >= protocol.MinStreamFrameSize {
			// As in getNextStreamFrame: the length field of the packet's
			// last STREAM frame is removed later. With at least 128 bytes a
			// frame that fills the space has a length field as long as the
			// one borrowed, so removing it brings the frame within remaining;
			// below that a shorter field could leave it a byte over.
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
			f.unfile(e.id)
			delete(f.activeStreams, e.id)
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
