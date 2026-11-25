package utils

import (
	"sync"
	"sync/atomic"

	"github.com/apernet/quic-go/internal/monotime"
)

// ConnectionStats stores stats for the connection. See the public
// ConnectionStats struct in connection.go for more information
type ConnectionStats struct {
	BytesSent       atomic.Uint64
	PacketsSent     atomic.Uint64
	BytesReceived   atomic.Uint64
	PacketsReceived atomic.Uint64
	BytesLost       atomic.Uint64
	PacketsLost     atomic.Uint64

	progressMx sync.Mutex
	progress   TransportProgress
}

// TransportProgress is the connection's transport progress, as seen by its
// sent packet handler.
type TransportProgress struct {
	// Epoch is incremented whenever an ack-eliciting application-data packet
	// is newly acknowledged.
	Epoch uint64
	// Last is when Epoch was last incremented.
	Last monotime.Time
	// PTOExpiries counts probe timeouts since Epoch last moved. Unlike the
	// handler's PTO count, dropping a key does not reset it.
	PTOExpiries uint32
	// ElicitingOutstanding says an ack-eliciting application-data packet is
	// outstanding.
	ElicitingOutstanding bool
}

// SetProgress publishes a progress snapshot. It is called on the run loop.
func (s *ConnectionStats) SetProgress(p TransportProgress) {
	s.progressMx.Lock()
	s.progress = p
	s.progressMx.Unlock()
}

// Progress returns the last published progress snapshot, which is coherent:
// all of its fields were taken at the same instant on the run loop.
func (s *ConnectionStats) Progress() TransportProgress {
	s.progressMx.Lock()
	defer s.progressMx.Unlock()
	return s.progress
}
