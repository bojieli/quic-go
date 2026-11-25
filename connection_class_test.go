package quic

import (
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

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

func (r *demandRecorder) OnAttach(monotime.Time, congestion.ByteCount, congestion.ByteCount, func()) {
}
func (r *demandRecorder) OnDemand(d congestion.Demand) {
	r.mu.Lock()
	r.demands = append(r.demands, d)
	r.mu.Unlock()
}
func (r *demandRecorder) Admit(monotime.Time, congestion.ByteCount) congestion.Permit {
	return congestion.Permit{}
}
func (r *demandRecorder) OnSent(congestion.SentPacket)   {}
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

// A grant bound for a controller that has been requested but not yet
// installed covers nothing until it is: the controller installed now never
// has packets charged to a grant meant for its successor.
func TestGrantForAPendingControllerWaitsForItsInstallation(t *testing.T) {
	c := &Conn{}
	c.grant = &boundGrant{grant: congestion.VerificationGrant{ID: 1, Expiry: monotime.Now().Add(time.Hour)}, remaining: 1000, epoch: 2}
	c.installedEpoch = 1
	require.False(t, c.hasGrant(monotime.Now()), "a grant for the pending controller was usable under the installed one")
	require.NotNil(t, c.grant, "it is kept, not dropped")
	c.clearGrantsBefore(2) // the controller of epoch 2 is installed
	require.True(t, c.hasGrant(monotime.Now()))
}

// permittingHandler adds the permit accessor to the mock handler.
type permittingHandler struct {
	*mockackhandler.MockSentPacketHandler
	permit congestion.Permit
}

func (h permittingHandler) Permit() (congestion.Permit, bool) { return h.permit, true }

// emptyBuildRecorder is a demand recorder that is also told of empty builds.
type emptyBuildRecorder struct {
	demandRecorder
	empty []congestion.Permit
}

func (r *emptyBuildRecorder) OnEmptyBuild(_ monotime.Time, p congestion.Permit) {
	r.mu.Lock()
	r.empty = append(r.empty, p)
	r.mu.Unlock()
}

// When an admitted class-built pass builds nothing and demand is unchanged
// -- the work does not fit the permit -- the scheduler is told, so it can
// decide differently; the connection does not spin on the same permit.
func TestEmptyAdmittedBuildIsReportedToTheScheduler(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		permit := congestion.Permit{OK: true, Turn: congestion.ClassInteractive, MaxBytes: 300}
		tc := newServerTestConnection(t, mockCtrl,
			&Config{DisablePathMTUDiscovery: true, EnableDatagrams: true}, false,
			connectionOptHandshakeConfirmed(),
			connectionOptSentPacketHandler(permittingHandler{sph, permit}),
		)
		rec := &emptyBuildRecorder{}
		tc.conn.pathSender = rec
		tc.conn.hasPathSender.Store(true)
		tc.conn.classed = true
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).Return(protocol.ECNNon).AnyTimes()
		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().DetachPathSender(gomock.Any()).AnyTimes()
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		var builds int
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(*packetBuffer, protocol.ByteCount, monotime.Time, protocol.Version) (shortHeaderPacket, error) {
				builds++ // the datagram does not fit 300 bytes: nothing is built
				return shortHeaderPacket{}, errNothingToPack
			}).AnyTimes()
		require.NoError(t, tc.conn.datagramQueue.Add(&wire.DatagramFrame{Data: make([]byte, 900)}))

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()
		synctest.Wait()

		rec.mu.Lock()
		empty := append([]congestion.Permit(nil), rec.empty...)
		rec.mu.Unlock()
		require.Equal(t, []congestion.Permit{permit}, empty)
		require.Equal(t, 1, builds, "the connection retried the same permit")

		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)
		synctest.Wait()
		require.NoError(t, <-errChan)
	})
}

// An MTU probe goes only under a class permit that covers the largest probe.
func TestMTUProbeNeedsAPermitThatCoversIt(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	for _, c := range []struct {
		max  congestion.ByteCount
		want bool
	}{{128, false}, {1252, false}, {congestion.ByteCount(protocol.MaxPacketBufferSize), true}} {
		conn := &Conn{classed: true, handshakeConfirmed: true, sentPacketHandler: permittingHandler{sph, congestion.Permit{OK: true, MaxBytes: c.max}}}
		require.Equal(t, c.want, conn.permitCoversMTUProbe(), "MaxBytes %d", c.max)
	}
	require.True(t, (&Conn{}).permitCoversMTUProbe(), "without class scheduling probes are as before")
}
