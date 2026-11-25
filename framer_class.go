package quic

import (
	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/ackhandler"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/apernet/quic-go/quicvarint"
)

// classedStream is a stream that can be served by class. A stream that is not
// one (a test double) is BULK.
type classedStream interface {
	streamClass() congestion.SendClass
	sendableClass(connWindow bool) (congestion.SendClass, bool)
	popClassedStreamFrame(maxBytes protocol.ByteCount, v protocol.Version) (_ ackhandler.StreamFrame, _ *wire.StreamDataBlockedFrame, hasMore bool, served, next congestion.SendClass)
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
			f.ringOf = make(map[protocol.StreamID]congestion.SendClass)
		}
		for !f.streamQueue.Empty() {
			id := f.streamQueue.PopFront()
			if str, ok := f.activeStreams[id]; ok {
				if _, filed := f.ringOf[id]; !filed {
					class := classOfStream(str)
					f.ringOf[id] = class
					f.classRings[class].PushBack(id)
				}
			}
		}
		return
	}
	for class := range f.classRings {
		ring := &f.classRings[class]
		for !ring.Empty() {
			id := ring.PopFront()
			if c, ok := f.ringOf[id]; ok && int(c) == class {
				delete(f.ringOf, id)
				if _, active := f.activeStreams[id]; active {
					f.streamQueue.PushBack(id)
				}
			}
		}
	}
	clear(f.ringOf)
}

// fileStream makes a stream active, or re-files it when its effective class
// changed. It must be called with the mutex held.
func (f *framer) fileStream(id protocol.StreamID, str streamFrameGetter) {
	class := classOfStream(str)
	if _, ok := f.activeStreams[id]; !ok {
		f.activeStreams[id] = str
	} else if c, filed := f.ringOf[id]; filed && c == class {
		return
	}
	f.ringOf[id] = class
	f.classRings[class].PushBack(id)
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
// the queued control frames, then the streams whose effective class it is,
// round-robin. Each STREAM frame keeps its length field; the caller removes
// the last one's when the packet is complete. The length returned counts the
// frames as they are.
func (f *framer) AppendClass(
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	class congestion.SendClass,
	maxLen protocol.ByteCount,
	now monotime.Time,
	v protocol.Version,
) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()
	var length protocol.ByteCount
	if class == congestion.ClassControl {
		var n protocol.ByteCount
		frames, n = f.appendControlFrames(frames, maxLen, now, v)
		length += n
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()
	var sentStream bool
	var n protocol.ByteCount
	frames, streamFrames, n, sentStream = f.appendClassStreams(frames, streamFrames, class, maxLen-length, v)
	length += n
	if !sentStream && maxLen-length >= protocol.MinStreamFrameSize && f.refile(class) {
		// A stream whose class changed without being re-filed: every change
		// re-files, so this is a safety net, not the way streams move.
		frames, streamFrames, n, sentStream = f.appendClassStreams(frames, streamFrames, class, maxLen-length, v)
		length += n
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
	return frames, streamFrames, length
}

// refile files every active stream in the ring of its current class, and
// says whether one moved into class. It must be called with the mutex held.
func (f *framer) refile(class congestion.SendClass) bool {
	var moved bool
	for id, str := range f.activeStreams {
		c := classOfStream(str)
		if filed, ok := f.ringOf[id]; ok && filed == c {
			continue
		}
		f.ringOf[id] = c
		f.classRings[c].PushBack(id)
		moved = moved || c == class
	}
	return moved
}

// appendClassStreams serves the streams filed in class, round-robin, up to
// maxLen bytes. It must be called with both mutexes held.
func (f *framer) appendClassStreams(
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	class congestion.SendClass,
	maxLen protocol.ByteCount,
	v protocol.Version,
) (_ []ackhandler.Frame, _ []ackhandler.StreamFrame, length protocol.ByteCount, sentStream bool) {
	ring := &f.classRings[class]
	for range ring.Len() {
		remaining := maxLen - length
		if protocol.MinStreamFrameSize > remaining {
			break
		}
		id := ring.PopFront()
		str, ok := f.activeStreams[id]
		if !ok || f.ringOf[id] != class {
			// Removed, or filed in another ring since.
			continue
		}
		cs, isClassed := str.(classedStream)
		if isClassed {
			if c := cs.streamClass(); c != class {
				f.ringOf[id] = c
				f.classRings[c].PushBack(id)
				continue
			}
		}
		// As in getNextStreamFrame: the length field of the packet's last
		// STREAM frame is removed later.
		popLen := remaining + protocol.ByteCount(quicvarint.Len(uint64(remaining)))
		var (
			sf      ackhandler.StreamFrame
			blocked *wire.StreamDataBlockedFrame
			hasMore bool
			next    = class
		)
		if isClassed {
			sf, blocked, hasMore, _, next = cs.popClassedStreamFrame(popLen, v)
		} else {
			sf, blocked, hasMore = str.popStreamFrame(popLen, v)
		}
		if hasMore {
			f.ringOf[id] = next
			f.classRings[next].PushBack(id)
		} else {
			delete(f.activeStreams, id)
			delete(f.ringOf, id)
		}
		if sf.Frame != nil {
			streamFrames = append(streamFrames, sf)
			length += sf.Frame.Length(v)
			sentStream = true
		}
		if blocked != nil {
			l := blocked.Length(v)
			if maxLen-length < l {
				f.controlFrames = append(f.controlFrames, blocked)
				break
			}
			frames = append(frames, ackhandler.Frame{Frame: blocked})
			length += l
		}
	}
	return frames, streamFrames, length, sentStream
}
