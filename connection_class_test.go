package quic

import (
	"net"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/ackhandler"
	mockackhandler "github.com/apernet/quic-go/internal/mocks/ackhandler"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// demandRecorder is a PathSender that records the demand it is told.
type demandRecorder struct {
	mu      sync.Mutex
	demands []congestion.Demand
}

func (r *demandRecorder) last() congestion.Demand {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.demands) == 0 {
		return congestion.Demand{}
	}
	return r.demands[len(r.demands)-1]
}

func (r *demandRecorder) OnAttach(monotime.Time, congestion.ByteCount, congestion.ByteCount, func()) {}
func (r *demandRecorder) OnDemand(d congestion.Demand) {
	r.mu.Lock()
	r.demands = append(r.demands, d)
	r.mu.Unlock()
}
func (r *demandRecorder) Admit(monotime.Time, congestion.ByteCount) congestion.Permit {
	return congestion.Permit{}
}
func (r *demandRecorder) OnSent(congestion.SentPacket)    {}
func (r *demandRecorder) OnAckEvent(congestion.AckEvent) {}
func (r *demandRecorder) OnDiscarded(monotime.Time, congestion.ByteCount, []congestion.PacketRef, bool, congestion.DiscardReason) {
}
func (r *demandRecorder) OnPathMigrated(monotime.Time, net.Addr, net.Addr, net.Addr, net.Addr) {}
func (r *demandRecorder) OnDetach(monotime.Time)                                               {}
func (r *demandRecorder) SetRTTStatsProvider(congestion.RTTStatsProvider)                      {}
func (r *demandRecorder) TimeUntilSend(congestion.ByteCount) monotime.Time                     { return 0 }
func (r *demandRecorder) HasPacingBudget(monotime.Time) bool                                   { return true }
func (r *demandRecorder) OnPacketSent(monotime.Time, congestion.ByteCount, congestion.PacketNumber, congestion.ByteCount, bool) {
}
func (r *demandRecorder) CanSend(congestion.ByteCount) bool { return true }
func (r *demandRecorder) MaybeExitSlowStart()               {}
func (r *demandRecorder) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
}
func (r *demandRecorder) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
}
func (r *demandRecorder) OnRetransmissionTimeout(bool)            {}
func (r *demandRecorder) SetMaxDatagramSize(congestion.ByteCount) {}
func (r *demandRecorder) InSlowStart() bool                       { return false }
func (r *demandRecorder) InRecovery() bool                        { return false }
func (r *demandRecorder) GetCongestionWindow() congestion.ByteCount {
	return 1 << 20
}

// An empty build can use up the last eligible work without producing a
// packet -- here the packer discards the only queued DATAGRAM. Demand is
// refreshed after it, in both batch loops and in the exempt builder, so the
// PathSender is not left holding a class nothing can serve.
func TestDemandIsRefreshedAfterAnEmptyBuild(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gso    bool
		exempt bool
	}{
		{name: "batch loop without GSO"},
		{name: "batch loop with GSO", gso: true},
		{name: "exempt builder", exempt: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testDemandRefreshedAfterEmptyBuild(t, tc.gso, tc.exempt)
		})
	}
}

func testDemandRefreshedAfterEmptyBuild(t *testing.T, gso, exempt bool) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			&Config{DisablePathMTUDiscovery: true, EnableDatagrams: true},
			gso,
			connectionOptHandshakeConfirmed(),
			connectionOptSentPacketHandler(sph),
		)
		rec := &demandRecorder{}
		tc.conn.pathSender = rec
		tc.conn.hasPathSender.Store(true)

		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).Return(protocol.ECNNon).AnyTimes()
		sph.EXPECT().TimeUntilSend().Return(monotime.Now().Add(1 << 40)).AnyTimes()
		sph.EXPECT().AdmissionRefused().Return(exempt).AnyTimes()
		sph.EXPECT().DetachPathSender(gomock.Any()).AnyTimes()
		discard := func() { tc.conn.datagramQueue.PopDiscarded() }
		if exempt {
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited).AnyTimes()
			tc.packer.EXPECT().PackExemptPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(protocol.ByteCount, monotime.Time, func(protocol.ByteCount, protocol.Version) ackhandler.StreamFrame, protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
					discard()
					return shortHeaderPacket{}, nil, errNothingToPack
				}).AnyTimes()
		} else {
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(*packetBuffer, protocol.ByteCount, monotime.Time, protocol.Version) (shortHeaderPacket, error) {
					discard()
					return shortHeaderPacket{}, errNothingToPack
				}).AnyTimes()
		}
		require.NoError(t, tc.conn.datagramQueue.Add(&wire.DatagramFrame{Data: []byte("x")}))

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()
		synctest.Wait()

		rec.mu.Lock()
		var sawDatagram bool
		for _, d := range rec.demands {
			sawDatagram = sawDatagram || d.Eligible[congestion.ClassInteractive]
		}
		rec.mu.Unlock()
		require.True(t, sawDatagram, "the queued datagram was demand before the build")
		require.False(t, rec.last().Eligible[congestion.ClassInteractive], "demand is withdrawn after the build that discarded it")

		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)
		synctest.Wait()
		require.NoError(t, <-errChan)
	})
}
