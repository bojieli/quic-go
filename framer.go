package quic

import (
	"slices"
	"sync"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/ackhandler"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils/ringbuffer"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/apernet/quic-go/quicvarint"
)

const (
	maxPathResponses = 256
	maxControlFrames = 16 << 10
)

// This is the largest possible size of a stream-related control frame
// (which is the RESET_STREAM frame).
const maxStreamControlFrameSize = 25

type streamFrameGetter interface {
	popStreamFrame(protocol.ByteCount, protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool)
}

type streamControlFrameGetter interface {
	getControlFrame(monotime.Time) (_ ackhandler.Frame, ok, hasMore bool)
}

type framer struct {
	mutex sync.Mutex

	activeStreams            map[protocol.StreamID]streamFrameGetter
	streamQueue              ringbuffer.RingBuffer[protocol.StreamID]
	streamsWithControlFrames map[protocol.StreamID]streamControlFrameGetter

	// classed is set while the connection's PathSender schedules classes.
	// Active streams are then queued in classRings by effective class
	// instead of in streamQueue, round-robin within a class. ringOf is the
	// one live entry of each filed stream; any other entry is stale and
	// skipped. See framer_class.go.
	classed    bool
	classRings [congestion.NumSendClasses]ringbuffer.RingBuffer[ringEntry]
	ringOf     map[protocol.StreamID]ringEntry
	ringGen    uint64

	controlFrameMutex sync.Mutex
	controlFrames     []wire.Frame
	// exemptFrames are obligations that may be sent without a permit, such
	// as a liveness PING. They are also packed into ordinary packets.
	exemptFrames               []ackhandler.Frame
	pathResponses              []*wire.PathResponseFrame
	connFlowController         *connectionFlowController
	queuedTooManyControlFrames bool
}

func newFramer(connFlowController *connectionFlowController) *framer {
	return &framer{
		activeStreams:            make(map[protocol.StreamID]streamFrameGetter),
		streamsWithControlFrames: make(map[protocol.StreamID]streamControlFrameGetter),
		connFlowController:       connFlowController,
	}
}

func (f *framer) HasData() bool {
	f.mutex.Lock()
	hasData := !f.streamQueue.Empty() || (f.classed && f.hasClassedStreams())
	f.mutex.Unlock()
	if hasData {
		return true
	}
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()
	return len(f.streamsWithControlFrames) > 0 || len(f.controlFrames) > 0 || len(f.pathResponses) > 0 || len(f.exemptFrames) > 0
}

// QueueExemptFrame queues a frame that may be sent without a permit. Its
// handler, if any, is kept.
func (f *framer) QueueExemptFrame(frame ackhandler.Frame) {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()
	if len(f.exemptFrames) >= maxPathResponses {
		return
	}
	f.exemptFrames = append(f.exemptFrames, frame)
}

// HasExemptData says whether exempt obligations are queued.
func (f *framer) HasExemptData() bool {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()
	return len(f.pathResponses) > 0 || len(f.exemptFrames) > 0
}

// HasControlData says whether control frames other than exempt ones are
// queued. It does not consume them.
func (f *framer) HasControlData() bool {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()
	return len(f.streamsWithControlFrames) > 0 || len(f.controlFrames) > 0
}

// HasStreamData says whether a queued stream could send a frame now. It
// consumes nothing; a stream that cannot say is assumed able to.
func (f *framer) HasStreamData(connWindow bool) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.streamQueue.Empty() {
		return false
	}
	for _, str := range f.activeStreams {
		s, ok := str.(interface{ hasSendableData(bool) bool })
		if !ok || s.hasSendableData(connWindow) {
			return true
		}
	}
	return false
}

// AppendExempt appends only exempt obligations: one PATH_RESPONSE and the
// queued exempt frames.
func (f *framer) AppendExempt(frames []ackhandler.Frame, maxLen protocol.ByteCount, v protocol.Version) ([]ackhandler.Frame, protocol.ByteCount) {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()
	return f.appendExemptFrames(frames, maxLen, v)
}

func (f *framer) appendExemptFrames(frames []ackhandler.Frame, maxLen protocol.ByteCount, v protocol.Version) ([]ackhandler.Frame, protocol.ByteCount) {
	var length protocol.ByteCount
	// only pack a single PATH_RESPONSE per packet
	if len(f.pathResponses) > 0 {
		frame := f.pathResponses[0]
		frameLen := frame.Length(v)
		if frameLen <= maxLen {
			frames = append(frames, ackhandler.Frame{Frame: frame})
			length += frameLen
			f.pathResponses = f.pathResponses[1:]
		}
	}
	for len(f.exemptFrames) > 0 {
		frame := f.exemptFrames[len(f.exemptFrames)-1]
		frameLen := frame.Frame.Length(v)
		if length+frameLen > maxLen {
			break
		}
		frames = append(frames, frame)
		length += frameLen
		f.exemptFrames = f.exemptFrames[:len(f.exemptFrames)-1]
	}
	return frames, length
}

func (f *framer) QueueControlFrame(frame wire.Frame) {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()

	if pr, ok := frame.(*wire.PathResponseFrame); ok {
		// Only queue up to maxPathResponses PATH_RESPONSE frames.
		// This limit should be high enough to never be hit in practice,
		// unless the peer is doing something malicious.
		if len(f.pathResponses) >= maxPathResponses {
			return
		}
		f.pathResponses = append(f.pathResponses, pr)
		return
	}
	// This is a hack.
	if len(f.controlFrames) >= maxControlFrames {
		f.queuedTooManyControlFrames = true
		return
	}
	f.controlFrames = append(f.controlFrames, frame)
}

func (f *framer) Append(
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	maxLen protocol.ByteCount,
	now monotime.Time,
	v protocol.Version,
) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
	f.controlFrameMutex.Lock()
	frames, controlFrameLen := f.appendControlFrames(frames, maxLen, now, v)
	maxLen -= controlFrameLen

	var lastFrame ackhandler.StreamFrame
	var streamFrameLen protocol.ByteCount
	f.mutex.Lock()
	if f.classed {
		// A build outside class scheduling's own (a PTO probe) takes the
		// classes in priority order.
		return f.appendAllClasses(frames, streamFrames, controlFrameLen, maxLen, v)
	}
	// pop STREAM frames, until less than 128 bytes are left in the packet
	numActiveStreams := f.streamQueue.Len()
	for range numActiveStreams {
		if protocol.MinStreamFrameSize > maxLen {
			break
		}
		sf, blocked := f.getNextStreamFrame(maxLen, v)
		if sf.Frame != nil {
			streamFrames = append(streamFrames, sf)
			maxLen -= sf.Frame.Length(v)
			lastFrame = sf
			streamFrameLen += sf.Frame.Length(v)
		}
		// If the stream just became blocked on stream flow control, attempt to pack the
		// STREAM_DATA_BLOCKED into the same packet.
		if blocked != nil {
			l := blocked.Length(v)
			// In case it doesn't fit, queue it for the next packet.
			if maxLen < l {
				f.controlFrames = append(f.controlFrames, blocked)
				break
			}
			frames = append(frames, ackhandler.Frame{Frame: blocked})
			maxLen -= l
			controlFrameLen += l
		}
	}

	// The only way to become blocked on connection-level flow control is by sending STREAM frames.
	if isBlocked, offset := f.connFlowController.IsNewlyBlocked(); isBlocked {
		blocked := &wire.DataBlockedFrame{MaximumData: offset}
		l := blocked.Length(v)
		// In case it doesn't fit, queue it for the next packet.
		if maxLen >= l {
			frames = append(frames, ackhandler.Frame{Frame: blocked})
			controlFrameLen += l
		} else {
			f.controlFrames = append(f.controlFrames, blocked)
		}
	}

	f.mutex.Unlock()
	f.controlFrameMutex.Unlock()

	if lastFrame.Frame != nil {
		// account for the smaller size of the last STREAM frame
		streamFrameLen -= lastFrame.Frame.Length(v)
		lastFrame.Frame.DataLenPresent = false
		streamFrameLen += lastFrame.Frame.Length(v)
	}

	return frames, streamFrames, controlFrameLen + streamFrameLen
}

func (f *framer) appendControlFrames(
	frames []ackhandler.Frame,
	maxLen protocol.ByteCount,
	now monotime.Time,
	v protocol.Version,
) ([]ackhandler.Frame, protocol.ByteCount) {
	// add a PATH_RESPONSE first, but only pack a single PATH_RESPONSE per packet
	frames, length := f.appendExemptFrames(frames, maxLen, v)
	return f.appendOrdinaryControlFrames(frames, length, maxLen, now, v)
}

// appendOrdinaryControlFrames appends the queued control frames that are not
// exempt obligations, after length bytes already in the packet.
func (f *framer) appendOrdinaryControlFrames(
	frames []ackhandler.Frame,
	length protocol.ByteCount,
	maxLen protocol.ByteCount,
	now monotime.Time,
	v protocol.Version,
) ([]ackhandler.Frame, protocol.ByteCount) {
	// add stream-related control frames
	for id, str := range f.streamsWithControlFrames {
	start:
		remainingLen := maxLen - length
		if remainingLen <= maxStreamControlFrameSize {
			break
		}
		fr, ok, hasMore := str.getControlFrame(now)
		if !hasMore {
			delete(f.streamsWithControlFrames, id)
		}
		if !ok {
			continue
		}
		frames = append(frames, fr)
		length += fr.Frame.Length(v)
		if hasMore {
			// It is rare that a stream has more than one control frame to queue.
			// We don't want to spawn another loop for just to cover that case.
			goto start
		}
	}

	for len(f.controlFrames) > 0 {
		frame := f.controlFrames[len(f.controlFrames)-1]
		frameLen := frame.Length(v)
		if length+frameLen > maxLen {
			break
		}
		frames = append(frames, ackhandler.Frame{Frame: frame})
		length += frameLen
		f.controlFrames = f.controlFrames[:len(f.controlFrames)-1]
	}

	return frames, length
}

// QueuedTooManyControlFrames says if the control frame queue exceeded its maximum queue length.
// This is a hack.
// It is easier to implement than propagating an error return value in QueueControlFrame.
// The correct solution would be to queue frames with their respective structs.
// See https://github.com/apernet/quic-go/issues/4271 for the queueing of stream-related control frames.
func (f *framer) QueuedTooManyControlFrames() bool {
	return f.queuedTooManyControlFrames
}

func (f *framer) AddActiveStream(id protocol.StreamID, str streamFrameGetter) {
	f.mutex.Lock()
	if f.classed {
		f.fileStream(id, str)
		f.mutex.Unlock()
		return
	}
	if _, ok := f.activeStreams[id]; !ok {
		f.streamQueue.PushBack(id)
		f.activeStreams[id] = str
	}
	f.mutex.Unlock()
}

func (f *framer) AddStreamWithControlFrames(id protocol.StreamID, str streamControlFrameGetter) {
	f.controlFrameMutex.Lock()
	if _, ok := f.streamsWithControlFrames[id]; !ok {
		f.streamsWithControlFrames[id] = str
	}
	f.controlFrameMutex.Unlock()
}

// RemoveActiveStream is called when a stream completes.
func (f *framer) RemoveActiveStream(id protocol.StreamID) {
	f.mutex.Lock()
	delete(f.activeStreams, id)
	delete(f.ringOf, id)
	// We don't delete the stream from the streamQueue,
	// since we'd have to iterate over the ringbuffer.
	// Instead, we check if the stream is still in activeStreams when appending STREAM frames.
	f.mutex.Unlock()
}

func (f *framer) getNextStreamFrame(maxLen protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame) {
	id := f.streamQueue.PopFront()
	// This should never return an error. Better check it anyway.
	// The stream will only be in the streamQueue, if it enqueued itself there.
	str, ok := f.activeStreams[id]
	// The stream might have been removed after being enqueued.
	if !ok {
		return ackhandler.StreamFrame{}, nil
	}
	// For the last STREAM frame, we'll remove the DataLen field later.
	// Therefore, we can pretend to have more bytes available when popping
	// the STREAM frame (which will always have the DataLen set).
	maxLen += protocol.ByteCount(quicvarint.Len(uint64(maxLen)))
	frame, blocked, hasMoreData := str.popStreamFrame(maxLen, v)
	if hasMoreData { // put the stream back in the queue (at the end)
		f.streamQueue.PushBack(id)
	} else { // no more data to send. Stream is not active
		delete(f.activeStreams, id)
	}
	// Note that the frame.Frame can be nil:
	// * if the stream was canceled after it said it had data
	// * the remaining size doesn't allow us to add another STREAM frame
	return frame, blocked
}

func (f *framer) Handle0RTTRejection() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()

	f.streamQueue.Clear()
	for id := range f.activeStreams {
		delete(f.activeStreams, id)
	}
	for i := range f.classRings {
		f.classRings[i].Clear()
	}
	clear(f.ringOf)
	clear(f.streamsWithControlFrames)
	var j int
	for i, frame := range f.controlFrames {
		switch frame.(type) {
		case *wire.MaxDataFrame, *wire.MaxStreamDataFrame, *wire.MaxStreamsFrame,
			*wire.DataBlockedFrame, *wire.StreamDataBlockedFrame, *wire.StreamsBlockedFrame:
			continue
		default:
			f.controlFrames[j] = f.controlFrames[i]
			j++
		}
	}
	f.controlFrames = slices.Delete(f.controlFrames, j, len(f.controlFrames))
}
