package ackhandler

import (
	"github.com/apernet/quic-go/internal/wire"
)

// FrameHandler handles the acknowledgement and the loss of a frame.
type FrameHandler interface {
	OnAcked(wire.Frame)
	OnLost(wire.Frame)
}

type Frame struct {
	Frame   wire.Frame // nil if the frame has already been acknowledged in another packet
	Handler FrameHandler
}

type StreamFrame struct {
	Frame   *wire.StreamFrame
	Handler FrameHandler
}

// livenessPing marks the keep-alive PING, so the packet it is packed into is
// recognised as carrying it. Its loss needs no retransmission: the PTO that
// follows probes the path anyway.
type livenessPing struct{}

func (livenessPing) OnAcked(wire.Frame) {}
func (livenessPing) OnLost(wire.Frame)  {}

// LivenessPingHandler is the handler of a keep-alive PING frame.
var LivenessPingHandler FrameHandler = livenessPing{}

func isLivenessPing(f Frame) bool {
	_, ok := f.Handler.(livenessPing)
	return ok
}
