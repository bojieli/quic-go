package self_test

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"

	"github.com/stretchr/testify/require"
)

// gatePathSender admits everything until blocked, then refuses every
// ordinary packet as window-limited. It records what it is told.
type gatePathSender struct {
	blocked atomic.Bool

	mu       sync.Mutex
	attached int
	sent     []congestion.SentPacket
	acks     int
	migrated int
	detached bool
}

func (g *gatePathSender) OnAttach(monotime.Time, congestion.ByteCount, congestion.ByteCount, func()) {
	g.mu.Lock()
	g.attached++
	g.mu.Unlock()
}
func (g *gatePathSender) OnDemand(congestion.Demand) {}
func (g *gatePathSender) Admit(_ monotime.Time, maxBytes congestion.ByteCount) congestion.Permit {
	if g.blocked.Load() {
		return congestion.Permit{}
	}
	return congestion.Permit{OK: true, Turn: congestion.ClassBulk, MaxBytes: maxBytes}
}
func (g *gatePathSender) OnSent(p congestion.SentPacket) {
	g.mu.Lock()
	g.sent = append(g.sent, p)
	g.mu.Unlock()
}
func (g *gatePathSender) OnAckEvent(congestion.AckEvent) {
	g.mu.Lock()
	g.acks++
	g.mu.Unlock()
}
func (g *gatePathSender) OnDiscarded(monotime.Time, congestion.ByteCount, []congestion.PacketRef, bool, congestion.DiscardReason) {
}
func (g *gatePathSender) OnPathMigrated(monotime.Time, net.Addr, net.Addr, net.Addr, net.Addr) {
	g.mu.Lock()
	g.migrated++
	g.mu.Unlock()
}
func (g *gatePathSender) OnDetach(monotime.Time) {
	g.mu.Lock()
	g.detached = true
	g.mu.Unlock()
}
func (g *gatePathSender) SetRTTStatsProvider(congestion.RTTStatsProvider)  {}
func (g *gatePathSender) TimeUntilSend(congestion.ByteCount) monotime.Time { panic("legacy call") }
func (g *gatePathSender) HasPacingBudget(monotime.Time) bool               { panic("legacy call") }
func (g *gatePathSender) CanSend(congestion.ByteCount) bool                { panic("legacy call") }
func (g *gatePathSender) MaybeExitSlowStart()                              { panic("legacy call") }
func (g *gatePathSender) OnRetransmissionTimeout(bool)                     {}
func (g *gatePathSender) SetMaxDatagramSize(congestion.ByteCount)          {}
func (g *gatePathSender) InSlowStart() bool                                { return false }
func (g *gatePathSender) InRecovery() bool                                 { return false }
func (g *gatePathSender) GetCongestionWindow() congestion.ByteCount        { return 1 << 20 }
func (g *gatePathSender) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
	panic("legacy call")
}
func (g *gatePathSender) OnPacketSent(monotime.Time, congestion.ByteCount, congestion.PacketNumber, congestion.ByteCount, bool) {
	panic("legacy call")
}
func (g *gatePathSender) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
	panic("legacy call")
}

func (g *gatePathSender) kinds() map[congestion.PacketKind]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	m := make(map[congestion.PacketKind]int)
	for _, p := range g.sent {
		m[p.Kind]++
	}
	return m
}

func (g *gatePathSender) livenessTimes() []monotime.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	var ts []monotime.Time
	for _, p := range g.sent {
		if p.Kind == congestion.KindLiveness {
			ts = append(ts, p.Time)
		}
	}
	return ts
}

func dialPathSenderPair(t *testing.T, clientConf *quic.Config) (client, server *quic.Conn) {
	t.Helper()
	ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true}))
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err = quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), getQuicConfig(clientConf))
	require.NoError(t, err)
	t.Cleanup(func() { client.CloseWithError(0, "") })
	server, err = ln.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { server.CloseWithError(0, "") })
	select {
	case <-client.HandshakeComplete():
	case <-ctx.Done():
		t.Fatal("handshake did not complete")
	}
	return client, server
}

func installPathSender(t *testing.T, conn *quic.Conn, g *gatePathSender) {
	t.Helper()
	conn.SetCongestionControl(g)
	require.Eventually(t, func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.attached == 1
	}, time.Second, time.Millisecond, "a PathSender is installed on the run loop")
}

// A connection whose controller refuses every ordinary packet still sends its
// keep-alive PING and its acknowledgements, and stays alive on them.
func TestPathSenderExemptObligationsWhileWindowBlocked(t *testing.T) {
	const keepAlive = 50 * time.Millisecond
	client, server := dialPathSenderPair(t, &quic.Config{KeepAlivePeriod: keepAlive, MaxIdleTimeout: 400 * time.Millisecond})
	g := &gatePathSender{}
	installPathSender(t, client, g)

	// The server sends; the client only acknowledges.
	str, err := server.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(make([]byte, 64<<10))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	cstr, err := client.AcceptUniStream(context.Background())
	require.NoError(t, err)
	buf := make([]byte, 64<<10)
	n := 0
	for n < len(buf) {
		m, err := cstr.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	require.Equal(t, len(buf), n)

	g.blocked.Store(true)
	before := client.ConnectionStats().ProgressEpoch
	time.Sleep(time.Second) // well past the idle timeout
	select {
	case <-client.Context().Done():
		t.Fatalf("connection died while window-blocked: %v", context.Cause(client.Context()))
	default:
	}
	kinds := g.kinds()
	require.Positive(t, kinds[congestion.KindLiveness], "the keep-alive PING has an exempt build path")
	require.Positive(t, kinds[congestion.KindAckOnly], "ACK-only packets are reported")
	stats := client.ConnectionStats()
	require.Greater(t, stats.ProgressEpoch, before, "acknowledged liveness PINGs are transport progress")
	require.False(t, stats.LastProgress.IsZero())

	client.CloseWithError(0, "")
	require.Eventually(t, func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.detached
	}, time.Second, time.Millisecond)
}

// Without a PathSender, a window-blocked connection cannot send its keep-alive
// PING, which is today's behaviour.
func TestWindowBlockedConnectionWithoutPathSenderSuppressesKeepAlive(t *testing.T) {
	client, _ := dialPathSenderPair(t, &quic.Config{KeepAlivePeriod: 50 * time.Millisecond, MaxIdleTimeout: 400 * time.Millisecond})
	client.SetCongestionControl(&blockedLegacyController{})
	select {
	case <-client.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("expected the idle timeout")
	}
}

type blockedLegacyController struct{}

func (blockedLegacyController) SetRTTStatsProvider(congestion.RTTStatsProvider)  {}
func (blockedLegacyController) TimeUntilSend(congestion.ByteCount) monotime.Time { return 0 }
func (blockedLegacyController) HasPacingBudget(monotime.Time) bool               { return true }
func (blockedLegacyController) OnPacketSent(monotime.Time, congestion.ByteCount, congestion.PacketNumber, congestion.ByteCount, bool) {
}
func (blockedLegacyController) CanSend(congestion.ByteCount) bool { return false }
func (blockedLegacyController) MaybeExitSlowStart()               {}
func (blockedLegacyController) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
}
func (blockedLegacyController) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
}
func (blockedLegacyController) OnRetransmissionTimeout(bool)              {}
func (blockedLegacyController) SetMaxDatagramSize(congestion.ByteCount)   {}
func (blockedLegacyController) InSlowStart() bool                         { return false }
func (blockedLegacyController) InRecovery() bool                          { return false }
func (blockedLegacyController) GetCongestionWindow() congestion.ByteCount { return 0 }

// The adaptive keep-alive schedule doubles after each PING and is not reset
// by a PING's own acknowledgement.
func TestAdaptiveKeepAliveSchedule(t *testing.T) {
	const floor = 40 * time.Millisecond
	client, _ := dialPathSenderPair(t, &quic.Config{KeepAlivePeriod: 320 * time.Millisecond, MaxIdleTimeout: 5 * time.Second})
	g := &gatePathSender{}
	installPathSender(t, client, g)
	client.SetKeepAliveSchedule(floor)
	time.Sleep(1500 * time.Millisecond)
	ts := g.livenessTimes()
	require.GreaterOrEqual(t, len(ts), 4)
	gaps := make([]time.Duration, 0, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		gaps = append(gaps, ts[i].Sub(ts[i-1]))
	}
	require.Greater(t, gaps[2], 2*floor, "the interval grows: %v", gaps)
	for _, gap := range gaps {
		require.Less(t, gap, 320*time.Millisecond+150*time.Millisecond, "the interval is capped at the keep-alive period: %v", gaps)
	}
	// Application payload returns it to the floor.
	str, err := client.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("payload"))
	require.NoError(t, err)
	sentAt := monotime.Now()
	time.Sleep(floor * 4)
	var next monotime.Time
	for _, t := range g.livenessTimes() {
		if t.After(sentAt) {
			next = t
			break
		}
	}
	require.False(t, next.IsZero(), "a keep-alive PING follows the floor after payload")
	require.Less(t, next.Sub(sentAt), 2*floor+50*time.Millisecond)
}

func TestTaggedDatagramOutcomes(t *testing.T) {
	client, server := dialPathSenderPair(t, &quic.Config{EnableDatagrams: true})
	var mu sync.Mutex
	outcomes := make(map[uint64]quic.DatagramOutcome)
	client.SetDatagramObserver(func(tag uint64, o quic.DatagramOutcome) {
		mu.Lock()
		outcomes[tag] = o
		mu.Unlock()
	})
	require.NoError(t, client.SendDatagramTagged([]byte("tagged"), 7))
	data, err := server.ReceiveDatagram(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("tagged"), data)
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return outcomes[7] == quic.DatagramRegistered
	}, time.Second, time.Millisecond)
}

// Replacing a PathSender is done on the run loop: the controller is detached
// and the connection goes on with the replacement.
func TestReplacingAPathSender(t *testing.T) {
	client, server := dialPathSenderPair(t, &quic.Config{})
	g := &gatePathSender{}
	installPathSender(t, client, g)
	client.SetCongestionControl(blockedLegacyController{})
	require.Eventually(t, func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.detached
	}, time.Second, time.Millisecond)
	client.SetCongestionControl(&gatePathSender{})
	str, err := server.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("still working"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	cstr, err := client.AcceptUniStream(context.Background())
	require.NoError(t, err)
	buf := make([]byte, 13)
	_, err = io.ReadFull(cstr, buf)
	require.NoError(t, err)
}
