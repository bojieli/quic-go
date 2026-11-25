package quic

import (
	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/ackhandler"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
)

// Class scheduling on a send stream.
//
// A stream records the send class of the bytes it accepts (WriteClass) as a
// list of segments over stream offsets, and has a persistent boost property
// (SetBoost). Only a connection whose PathSender is a ClassScheduler reads
// them: its framer serves streams by their effective class and charges every
// frame to the class it was served at. A stream that was never written with a
// class and never boosted keeps no class state at all, and the ordinary
// builder never looks at any of it.

// classSeg says that the stream's bytes from start on, up to the next
// segment's start, are of class.
type classSeg struct {
	start protocol.ByteCount
	class congestion.SendClass
}

// noClassLimit means a class extends to whatever the stream holds.
const noClassLimit = protocol.MaxByteCount

// WriteClass writes p like Write, and records that its bytes are of class
// when they are sent for the first time. While the stream is boosted they are
// CONTROL instead. ClassExempt is not a class stream bytes can have; it is
// treated as BULK.
//
// The class matters only on a connection whose PathSender is a
// congestion.ClassScheduler; elsewhere WriteClass is Write.
func (s *SendStream) WriteClass(p []byte, class congestion.SendClass) (int, error) {
	if class == congestion.ClassExempt || class >= congestion.NumSendClasses {
		class = congestion.ClassBulk
	}
	s.writeOnce <- struct{}{}
	defer func() { <-s.writeOnce }()

	isNewlyCompleted, n, err := s.writeClassed(p, nil, class, true)
	if isNewlyCompleted {
		s.sender.onStreamCompleted(s.streamID)
	}
	return n, err
}

// SetBoost sets the stream's boost property. While it is on, every byte the
// stream holds -- a write in progress, a buffered tail, queued
// retransmissions -- and every byte it accepts afterwards is served at
// CONTROL. Turning it off affects only bytes accepted later: what the stream
// held while boosted stays CONTROL until it has been sent.
//
// Like WriteClass, it matters only on a connection whose PathSender is a
// congestion.ClassScheduler. It may be called from any goroutine, including
// while another goroutine is blocked in Write.
func (s *SendStream) SetBoost(on bool) {
	s.mutex.Lock()
	if s.boost == on {
		s.mutex.Unlock()
		return
	}
	s.boost = on
	s.classTagged = true
	if !on {
		// What the stream holds stays CONTROL until it has been sent.
		for _, f := range s.retransmissionQueue {
			f.Class = uint8(congestion.ClassControl)
		}
		if s.heldEnd() > s.writeOffset {
			s.recordClass(s.writeOffset, congestion.ClassControl)
		}
	}
	notify := s.holdsData()
	s.mutex.Unlock()
	if notify {
		// The effective class changed: the framer re-files the stream, and
		// the connection refreshes its demand.
		s.sender.onHasStreamData(s.streamID, s)
	}
}

// holdsData says whether the stream has bytes to send. It must be called with
// the mutex held.
func (s *SendStream) holdsData() bool {
	return len(s.retransmissionQueue) > 0 || s.nextFrame != nil || len(s.dataForWriting) > 0
}

// heldEnd is the offset after the last byte the stream holds: its buffered
// tail and the unconsumed part of a write in progress follow the write
// offset. It must be called with the mutex held.
func (s *SendStream) heldEnd() protocol.ByteCount {
	end := s.writeOffset
	if s.nextFrame != nil {
		end += s.nextFrame.DataLen()
	}
	return end + protocol.ByteCount(len(s.dataForWriting))
}

// recordClass records that the bytes from start on are of class. Segments
// starting at or after start describe bytes that were never accepted (a
// write that returned short) and are dropped. It must be called with the
// mutex held.
func (s *SendStream) recordClass(start protocol.ByteCount, class congestion.SendClass) {
	s.trimClassSegs(start)
	if n := len(s.classSegs); n > 0 && s.classSegs[n-1].class == class {
		return
	}
	s.classSegs = append(s.classSegs, classSeg{start: start, class: class})
}

// trimClassSegs drops the segments that start at or after end. It must be
// called with the mutex held.
func (s *SendStream) trimClassSegs(end protocol.ByteCount) {
	i := len(s.classSegs)
	for i > 0 && s.classSegs[i-1].start >= end {
		i--
	}
	s.classSegs = s.classSegs[:i]
}

// pruneClassSegs drops the segments that only describe bytes already sent for
// the first time. Retransmissions carry their class in the frame. It must be
// called with the mutex held.
func (s *SendStream) pruneClassSegs() {
	i := 0
	for i+1 < len(s.classSegs) && s.classSegs[i+1].start <= s.writeOffset {
		i++
	}
	if i > 0 {
		s.classSegs = append(s.classSegs[:0], s.classSegs[i:]...)
	}
}

// classAt is the recorded class of the byte at offset o, and the offset at
// which the next segment starts. Bytes before the first segment are BULK.
// It must be called with the mutex held.
func (s *SendStream) classAt(o protocol.ByteCount) (congestion.SendClass, protocol.ByteCount) {
	class, end := congestion.ClassBulk, noClassLimit
	for i := len(s.classSegs) - 1; i >= 0; i-- {
		if s.classSegs[i].start <= o {
			class = s.classSegs[i].class
			break
		}
		end = s.classSegs[i].start
	}
	return class, end
}

// unsentControlEnd is the offset after the last unsent byte recorded as
// CONTROL, or the write offset when there is none. It must be called with
// the mutex held.
func (s *SendStream) unsentControlEnd() protocol.ByteCount {
	held := s.heldEnd()
	end := s.writeOffset
	for i, seg := range s.classSegs {
		if seg.class != congestion.ClassControl {
			continue
		}
		segEnd := held
		if i+1 < len(s.classSegs) {
			segEnd = min(segEnd, s.classSegs[i+1].start)
		}
		if segEnd > end {
			end = segEnd
		}
	}
	return end
}

// frameClass is the class a queued retransmission was charged to.
func frameClass(f *wire.StreamFrame) congestion.SendClass {
	if f.Class == 0 {
		return congestion.ClassBulk
	}
	return congestion.SendClass(f.Class)
}

// effectiveClass is the class the stream is served at: CONTROL while it is
// boosted or holds a CONTROL byte that has not been sent for the first time
// or is queued for retransmission; otherwise the class of the next byte it
// would send. It must be called with the mutex held.
func (s *SendStream) effectiveClass() congestion.SendClass {
	if !s.classTagged {
		return congestion.ClassBulk
	}
	if s.boost {
		return congestion.ClassControl
	}
	for _, f := range s.retransmissionQueue {
		if frameClass(f) == congestion.ClassControl {
			return congestion.ClassControl
		}
	}
	if s.unsentControlEnd() > s.writeOffset {
		return congestion.ClassControl
	}
	if len(s.retransmissionQueue) > 0 {
		return frameClass(s.retransmissionQueue[0])
	}
	class, _ := s.classAt(s.writeOffset)
	return class
}

// newDataClass is the class new data at the write offset is served at, and
// the offset up to which that class holds: a frame of new data never mixes
// bytes served at different classes. It must be called with the mutex held.
func (s *SendStream) newDataClass() (congestion.SendClass, protocol.ByteCount) {
	if s.boost {
		return congestion.ClassControl, noClassLimit
	}
	if end := s.unsentControlEnd(); end > s.writeOffset {
		// Bytes ahead of a CONTROL byte are served at CONTROL with it.
		return congestion.ClassControl, end
	}
	return s.classAt(s.writeOffset)
}

// sendableClass reports, without consuming anything, the stream's effective
// class and whether it could send a frame now.
func (s *SendStream) sendableClass(connWindow bool) (congestion.SendClass, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.effectiveClass(), s.hasSendableDataLocked(connWindow)
}

// streamClass reports the stream's effective class.
func (s *SendStream) streamClass() congestion.SendClass {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.effectiveClass()
}

// popClassedStreamFrame is popStreamFrame for a class-scheduled connection.
// The frame is charged to the stream's effective class, which it returns
// along with the effective class after the pop; new data is cut where the
// class it is served at changes.
func (s *SendStream) popClassedStreamFrame(maxBytes protocol.ByteCount, v protocol.Version) (_ ackhandler.StreamFrame, _ *wire.StreamDataBlockedFrame, hasMore bool, served, next congestion.SendClass) {
	s.mutex.Lock()
	served = s.effectiveClass()
	if s.classTagged && len(s.retransmissionQueue) == 0 {
		if _, end := s.newDataClass(); end != noClassLimit && end > s.writeOffset {
			s.classLimit = end - s.writeOffset
		}
	}
	f, blocked, hasMoreData := s.popNewOrRetransmittedStreamFrame(maxBytes, v)
	s.classLimit = 0
	if f != nil {
		s.numOutstandingFrames++
		if s.classTagged {
			f.Class = uint8(served)
		}
	}
	s.capturePrefix(f)
	if s.classTagged {
		s.pruneClassSegs()
	}
	if repair := s.prefixRepair; repair != nil {
		if len(repair.data) > 0 {
			if f == nil {
				copyFrame := &wire.StreamFrame{StreamID: s.streamID, Data: repair.data, DataLenPresent: true}
				if copyFrame.Length(v) <= maxBytes {
					if s.classTagged {
						copyFrame.Class = uint8(served)
					}
					repair.remaining--
					if repair.remaining == 0 {
						s.discardPrefixRepair()
					}
					more := hasMoreData || repair.remaining > 0
					next = s.effectiveClass()
					s.mutex.Unlock()
					return ackhandler.StreamFrame{Frame: copyFrame, Handler: (*prefixRepairHandler)(s)}, blocked, more, served, next
				}
			}
			hasMoreData = true
		}
	}
	next = s.effectiveClass()
	s.mutex.Unlock()

	if f == nil {
		return ackhandler.StreamFrame{}, blocked, hasMoreData, served, next
	}
	return ackhandler.StreamFrame{
		Frame:   f,
		Handler: (*sendStreamAckHandler)(s),
	}, blocked, hasMoreData, served, next
}

// recordWriteClass records the class of bytes a write is about to hand over,
// from start on: CONTROL while the stream is boosted. It must be called with
// the mutex held.
func (s *SendStream) recordWriteClass(class congestion.SendClass, start protocol.ByteCount) {
	if s.boost {
		class = congestion.ClassControl
	}
	s.recordClass(start, class)
}
