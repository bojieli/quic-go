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

	// A probe-timeout episode is a run of one or more probe timeouts that
	// ends when Epoch next moves. Its peak is PTOExpiries just before that.
	// The episode fields are kept where the episode ends, so an episode that
	// opens and closes between two reads of the snapshot is still counted.
	//
	// PTOEpisodes counts completed episodes. It only grows.
	PTOEpisodes uint64
	// LastEpisodePeak is the peak of the last completed episode.
	LastEpisodePeak uint32
	// EpisodesReaching[n-1] counts completed episodes whose peak reached n
	// probe timeouts; the last bucket counts every episode that reached
	// PTOEpisodeBuckets or more. Every bucket only grows.
	EpisodesReaching [PTOEpisodeBuckets]uint64
}

// PTOEpisodeBuckets is the number of peak buckets in
// TransportProgress.EpisodesReaching.
const PTOEpisodeBuckets = 16

// EndEpisode records the progress at t that ends the current probe-timeout
// episode, if one is open, and moves Epoch.
func (p *TransportProgress) EndEpisode(t monotime.Time) {
	if n := p.PTOExpiries; n > 0 {
		p.PTOEpisodes++
		p.LastEpisodePeak = n
		for i := range min(n, PTOEpisodeBuckets) {
			p.EpisodesReaching[i]++
		}
	}
	p.Epoch++
	p.Last = t
	p.PTOExpiries = 0
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
