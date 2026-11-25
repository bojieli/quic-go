package self_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"

	"github.com/stretchr/testify/require"
)

// reissuePathSender is a blocked gate that binds a second verification grant
// from OnDemand once armed: the controller-side reissue of issue 176.
type reissuePathSender struct {
	*gatePathSender
	conn  *quic.Conn
	armed atomic.Bool
	str   quic.GrantableStream
	next  congestion.VerificationGrant
	// boundAt is the number of packets registered when the reissue bound.
	boundAt atomic.Int64
}

func (r *reissuePathSender) OnDemand(d congestion.Demand) {
	if r.armed.CompareAndSwap(true, false) {
		if err := r.conn.BindVerificationGrant(r.str, r.next); err != nil {
			panic(err)
		}
		r.mu.Lock()
		r.boundAt.Store(int64(len(r.sent)))
		r.mu.Unlock()
	}
}

// A grant reissued from the controller's own callback takes effect at once:
// no packet registered after the bind is charged to the superseded grant,
// even when admission refuses in the same pass (issue 176, item 1).
func TestReissuedGrantTakesEffectAtBind(t *testing.T) {
	client, server := dialPathSenderPair(t, &quic.Config{EnableDatagrams: true})
	r := &reissuePathSender{gatePathSender: &gatePathSender{}, conn: client}
	r.boundAt.Store(-1)
	client.SetCongestionControl(r)
	require.Eventually(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.attached == 1
	}, time.Second, time.Millisecond)
	r.blocked.Store(true)

	first, err := client.OpenUniStream()
	require.NoError(t, err)
	second, err := client.OpenUniStream()
	require.NoError(t, err)
	require.NoError(t, client.BindVerificationGrant(first, congestion.VerificationGrant{
		ID: 10, Start: 0, End: 1 << 20, Budget: 1 << 30, Expiry: monotime.Now().Add(10 * time.Second),
	}))
	r.str = second
	r.next = congestion.VerificationGrant{ID: 11, Start: 0, End: 1 << 20, Budget: 1 << 30, Expiry: monotime.Now().Add(10 * time.Second)}
	go func() { _, _ = first.Write(make([]byte, 1<<20)) }()
	go func() { _, _ = second.Write(make([]byte, 1<<20)) }()
	require.Eventually(t, func() bool { return r.granted()[10] >= 3 }, 2*time.Second, time.Millisecond)

	// A queued datagram changes demand; the controller reissues from OnDemand
	// at the start of the next send pass, which admission then refuses.
	r.armed.Store(true)
	require.NoError(t, client.SendDatagram([]byte("demand")))
	require.Eventually(t, func() bool { return r.boundAt.Load() >= 0 }, 2*time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return r.granted()[11] >= 3 }, 2*time.Second, time.Millisecond)

	r.mu.Lock()
	after := append([]congestion.SentPacket(nil), r.sent[r.boundAt.Load():]...)
	r.mu.Unlock()
	for _, p := range after {
		require.NotEqual(t, uint64(10), p.Grant, "a packet registered after the reissue was charged to the superseded grant")
	}
	_ = server
}

// Installing another controller clears a grant bound for its predecessor:
// the new controller never sees a grant ID it did not issue (issue 176,
// item 1).
func TestControllerReplacementClearsGrant(t *testing.T) {
	client, server := dialPathSenderPair(t, &quic.Config{})
	first := &gatePathSender{}
	installPathSender(t, client, first)
	first.blocked.Store(true)
	str, err := client.OpenUniStream()
	require.NoError(t, err)
	require.NoError(t, client.BindVerificationGrant(str, congestion.VerificationGrant{
		ID: 20, Start: 0, End: 4000, Budget: 64 << 10, Expiry: monotime.Now().Add(10 * time.Second),
	}))

	second := &gatePathSender{}
	second.blocked.Store(true)
	installPathSender(t, client, second)
	go func() { _, _ = str.Write(make([]byte, 4000)) }()
	time.Sleep(300 * time.Millisecond)
	require.Empty(t, second.granted(), "the replacement controller was charged for its predecessor's grant")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if rstr, err := server.AcceptUniStream(ctx); err == nil {
		data, _ := readWithin(t, rstr, 1, 100*time.Millisecond)
		require.Empty(t, data, "bytes crossed a blocked connection under a cleared grant")
	}
}

// classPathSender schedules classes with a permit chosen by the test.
type classPathSender struct {
	*gatePathSender
	turn    atomic.Uint32
	fill    [congestion.NumSendClasses]atomic.Int64
	demands []congestion.Demand
	dmu     sync.Mutex
}

func (c *classPathSender) SchedulesClasses() bool { return true }
func (c *classPathSender) OnDemand(d congestion.Demand) {
	c.dmu.Lock()
	c.demands = append(c.demands, d)
	c.dmu.Unlock()
}
func (c *classPathSender) lastDemand() congestion.Demand {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if len(c.demands) == 0 {
		return congestion.Demand{}
	}
	return c.demands[len(c.demands)-1]
}
func (c *classPathSender) Admit(now monotime.Time, maxBytes congestion.ByteCount) congestion.Permit {
	p := c.gatePathSender.Admit(now, maxBytes)
	if !p.OK {
		return p
	}
	p.Turn = congestion.SendClass(c.turn.Load())
	for i := range c.fill {
		p.Fill[i] = congestion.ByteCount(c.fill[i].Load())
	}
	return p
}

func (c *classPathSender) ordinaryClassBytes() [congestion.NumSendClasses]congestion.ByteCount {
	c.mu.Lock()
	defer c.mu.Unlock()
	var sum [congestion.NumSendClasses]congestion.ByteCount
	for _, p := range c.sent {
		if p.Exempt || p.Kind != congestion.KindOrdinary {
			// MTU probes are INTERACTIVE whatever the turn.
			continue
		}
		for i, b := range p.ClassBytes {
			sum[i] += b
		}
	}
	return sum
}

var _ congestion.ClassScheduler = (*classPathSender)(nil)

// Over a real connection, a class-scheduled packet whose permit has an empty
// Fill carries its turn's class only, whatever else is queued; changing the
// turn serves the other classes.
func TestClassScheduledPacketsCarryOnlyTheirTurn(t *testing.T) {
	client, server := dialPathSenderPair(t, &quic.Config{EnableDatagrams: true})
	c := &classPathSender{gatePathSender: &gatePathSender{}}
	c.turn.Store(uint32(congestion.ClassBulk))
	client.SetCongestionControl(c)
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.attached == 1
	}, time.Second, time.Millisecond)

	bulk, err := client.OpenUniStream()
	require.NoError(t, err)
	control, err := client.OpenUniStream()
	require.NoError(t, err)
	go func() { _, _ = control.WriteClass(make([]byte, 5000), congestion.ClassControl) }()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, client.SendDatagram([]byte("interactive")))
	go func() { _, _ = bulk.WriteClass(make([]byte, 20000), congestion.ClassBulk) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var bulkRecv *quic.ReceiveStream
	for bulkRecv == nil {
		rstr, err := server.AcceptUniStream(ctx)
		require.NoError(t, err)
		if rstr.StreamID() == bulk.StreamID() {
			bulkRecv = rstr
		}
	}
	got, err := readWithin(t, bulkRecv, 20000, 3*time.Second)
	require.NoError(t, err)
	require.Len(t, got, 20000)
	sum := c.ordinaryClassBytes()
	require.Zero(t, sum[congestion.ClassControl], "no CONTROL byte rode a BULK turn with an empty Fill")
	require.Zero(t, sum[congestion.ClassInteractive], "no datagram rode a BULK turn with an empty Fill")
	require.True(t, c.lastDemand().Eligible[congestion.ClassControl])
	require.True(t, c.lastDemand().Eligible[congestion.ClassInteractive])

	c.turn.Store(uint32(congestion.ClassControl))
	c.fill[congestion.ClassInteractive].Store(2000)
	client.SetKeepAliveSchedule(0) // any call that wakes the connection
	rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer rcancel()
	dg, err := server.ReceiveDatagram(rctx)
	require.NoError(t, err)
	require.Equal(t, []byte("interactive"), dg)
	require.Eventually(t, func() bool { return c.ordinaryClassBytes()[congestion.ClassControl] >= 5000 }, 3*time.Second, time.Millisecond)
}

// A write whose limiter grants nothing leaves no demand behind: the empty
// build that discovered it refreshes demand (issue 176, item 2).
func TestZeroWriteLimitWithdrawsDemand(t *testing.T) {
	client, _ := dialPathSenderPair(t, &quic.Config{})
	c := &classPathSender{gatePathSender: &gatePathSender{}}
	c.turn.Store(uint32(congestion.ClassBulk))
	client.SetCongestionControl(c)
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.attached == 1
	}, time.Second, time.Millisecond)
	str, err := client.OpenUniStream()
	require.NoError(t, err)
	_, err = str.WriteWithLimit(make([]byte, 1000), func(int) int { return 0 })
	require.ErrorIs(t, err, quic.ErrWriteLimitReached)
	require.Eventually(t, func() bool { return !c.lastDemand().Eligible[congestion.ClassBulk] }, 500*time.Millisecond, time.Millisecond,
		"the stream's demand is withdrawn without waiting for an unrelated event")
}
