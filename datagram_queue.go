package quic

import (
	"context"
	"slices"
	"sync"

	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/utils/ringbuffer"
	"github.com/apernet/quic-go/internal/wire"
)

const (
	maxDatagramSendQueueLen = 32
	maxDatagramRcvQueueLen  = 128
)

type datagramQueue struct {
	sendMx    sync.Mutex
	sendQueue ringbuffer.RingBuffer[*wire.DatagramFrame]
	sent      chan struct{} // used to notify Add that a datagram was dequeued

	rcvMx    sync.Mutex
	rcvQueue [][]byte
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	closeErr error
	closed   chan struct{}

	hasData func()
	// discarded, if set, is told about frames the packer discards.
	discarded func(*wire.DatagramFrame)
	// closing is set, under sendMx, when the queue is closed. A tagged frame
	// is refused from then on, since nothing would report its outcome; so
	// every accepted tagged frame is either drained at close or popped.
	closing bool
	// popped holds the tagged frames the packer popped for a packet that has
	// not been registered yet. Only the run loop touches it.
	popped []*wire.DatagramFrame

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	return &datagramQueue{
		hasData: hasData,
		rcvd:    make(chan struct{}, 1),
		sent:    make(chan struct{}, 1),
		closed:  make(chan struct{}),
		logger:  logger,
	}
}

// Add queues a new DATAGRAM frame for sending.
// Up to 32 DATAGRAM frames will be queued.
// Once that limit is reached, Add blocks until the queue size has reduced.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMx.Lock()

	for {
		if f.Tagged && h.closing {
			// Nothing would report the outcome.
			h.sendMx.Unlock()
			return h.closeErr
		}
		if h.sendQueue.Len() < maxDatagramSendQueueLen {
			h.sendQueue.PushBack(f)
			h.sendMx.Unlock()
			h.hasData()
			return nil
		}
		select {
		case <-h.sent: // drain the queue so we don't loop immediately
		default:
		}
		h.sendMx.Unlock()
		select {
		case <-h.closed:
			return h.closeErr
		case <-h.sent:
		}
		h.sendMx.Lock()
	}
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if h.sendQueue.Empty() {
		return nil
	}
	return h.sendQueue.PeekFront()
}

// PopDiscarded removes the next DATAGRAM frame without sending it.
func (h *datagramQueue) PopDiscarded() {
	h.sendMx.Lock()
	f := h.sendQueue.PopFront()
	select {
	case h.sent <- struct{}{}:
	default:
	}
	h.sendMx.Unlock()
	if h.discarded != nil && f != nil {
		h.discarded(f)
	}
}

func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if f := h.sendQueue.PopFront(); f != nil && f.Tagged {
		h.popped = append(h.popped, f)
	}
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	data := make([]byte, len(f.Data))
	copy(data, f.Data)
	var queued bool
	h.rcvMx.Lock()
	if len(h.rcvQueue) < maxDatagramRcvQueueLen {
		h.rcvQueue = append(h.rcvQueue, data)
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	}
	h.rcvMx.Unlock()
	if !queued && h.logger.Debug() {
		h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
	}
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	for {
		h.rcvMx.Lock()
		if len(h.rcvQueue) > 0 {
			data := h.rcvQueue[0]
			h.rcvQueue = h.rcvQueue[1:]
			h.rcvMx.Unlock()
			return data, nil
		}
		h.rcvMx.Unlock()
		select {
		case <-h.rcvd:
			continue
		case <-h.closed:
			return nil, h.closeErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// CloseWithError closes the queue. It returns the tagged frames that will
// never be sent: those still queued and those popped for a packet that was
// never registered. Closing and refusing further tagged frames are atomic.
func (h *datagramQueue) CloseWithError(e error) []*wire.DatagramFrame {
	h.sendMx.Lock()
	h.closeErr = e
	h.closing = true
	// Untagged frames stay where they are, as before.
	var unsent []*wire.DatagramFrame
	var kept []*wire.DatagramFrame
	for !h.sendQueue.Empty() {
		if f := h.sendQueue.PopFront(); f.Tagged {
			unsent = append(unsent, f)
		} else {
			kept = append(kept, f)
		}
	}
	for _, f := range kept {
		h.sendQueue.PushBack(f)
	}
	unsent = append(unsent, h.popped...)
	h.popped = nil
	h.sendMx.Unlock()
	close(h.closed)
	return unsent
}

// Registered says the packet carrying f was registered.
func (h *datagramQueue) Registered(f *wire.DatagramFrame) bool {
	for i, p := range h.popped {
		if p == f {
			h.popped = slices.Delete(h.popped, i, i+1)
			return true
		}
	}
	return false
}

// hasPopped says tagged frames await registration. Run loop only.
func (h *datagramQueue) hasPopped() bool { return len(h.popped) > 0 }
