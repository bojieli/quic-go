package ackhandler

import (
	"net"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// recordingPathSender records every PathSender call and keeps the flight
// gauge the events report.
type recordingPathSender struct {
	attached  bool
	attachedF congestion.ByteCount
	gauge     congestion.ByteCount
	admit     congestion.Permit
	admits    int
	sent      []congestion.SentPacket
	acks      []congestion.AckEvent
	discards  []congestion.DiscardReason
	discarded [][]congestion.PacketRef
	migrated  int
	detached  bool
	demand    congestion.Demand
	// legacy counts calls to the per-packet CongestionControl methods,
	// which a PathSender must never receive.
	legacy int
}

func newRecordingPathSender() *recordingPathSender {
	return &recordingPathSender{admit: congestion.Permit{OK: true, MaxBytes: 1200}}
}

func (r *recordingPathSender) OnAttach(_ monotime.Time, inFlight, _ congestion.ByteCount, _ func()) {
	r.attached = true
	r.attachedF = inFlight
	r.gauge = inFlight
}
func (r *recordingPathSender) OnDemand(d congestion.Demand) { r.demand = d }
func (r *recordingPathSender) Admit(monotime.Time, congestion.ByteCount) congestion.Permit {
	r.admits++
	return r.admit
}
func (r *recordingPathSender) OnSent(p congestion.SentPacket) {
	r.sent = append(r.sent, p)
	r.gauge = p.InFlight
}
func (r *recordingPathSender) OnAckEvent(e congestion.AckEvent) {
	e.Acked = append([]congestion.PacketRef(nil), e.Acked...)
	e.Lost = append([]congestion.PacketRef(nil), e.Lost...)
	e.Spurious = append([]congestion.PacketRef(nil), e.Spurious...)
	r.acks = append(r.acks, e)
	r.gauge = e.InFlight
}
func (r *recordingPathSender) OnDiscarded(_ monotime.Time, inFlight congestion.ByteCount, refs []congestion.PacketRef, _ bool, reason congestion.DiscardReason) {
	r.discards = append(r.discards, reason)
	r.discarded = append(r.discarded, append([]congestion.PacketRef(nil), refs...))
	r.gauge = inFlight
}
func (r *recordingPathSender) OnPathMigrated(monotime.Time, net.Addr, net.Addr, net.Addr, net.Addr) {
	r.migrated++
}
func (r *recordingPathSender) OnDetach(monotime.Time) { r.detached = true }

func (r *recordingPathSender) SetRTTStatsProvider(congestion.RTTStatsProvider) {}
func (r *recordingPathSender) TimeUntilSend(congestion.ByteCount) monotime.Time {
	r.legacy++
	return 0
}
func (r *recordingPathSender) HasPacingBudget(monotime.Time) bool { r.legacy++; return true }
func (r *recordingPathSender) OnPacketSent(monotime.Time, congestion.ByteCount, congestion.PacketNumber, congestion.ByteCount, bool) {
	r.legacy++
}
func (r *recordingPathSender) CanSend(congestion.ByteCount) bool { r.legacy++; return true }
func (r *recordingPathSender) MaybeExitSlowStart()               { r.legacy++ }
func (r *recordingPathSender) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
	r.legacy++
}
func (r *recordingPathSender) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
	r.legacy++
}
func (r *recordingPathSender) OnRetransmissionTimeout(bool)              {}
func (r *recordingPathSender) SetMaxDatagramSize(congestion.ByteCount)   {}
func (r *recordingPathSender) InSlowStart() bool                         { return false }
func (r *recordingPathSender) InRecovery() bool                          { return false }
func (r *recordingPathSender) GetCongestionWindow() congestion.ByteCount { return 1 << 20 }
func (r *recordingPathSender) lastSent() congestion.SentPacket           { return r.sent[len(r.sent)-1] }
func (r *recordingPathSender) lastAck() congestion.AckEvent              { return r.acks[len(r.acks)-1] }
func (r *recordingPathSender) lastDiscard() congestion.DiscardReason {
	return r.discards[len(r.discards)-1]
}
func (r *recordingPathSender) lastDiscarded() []congestion.PacketRef {
	return r.discarded[len(r.discarded)-1]
}
func (r *recordingPathSender) requireNoLegacyCalls(t *testing.T) {
	t.Helper()
	require.Zero(t, r.legacy)
}

func newPathSenderHandler(t *testing.T, ps *recordingPathSender, pers protocol.Perspective) *sentPacketHandler {
	t.Helper()
	sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, pers, false, nil, utils.DefaultLogger).(*sentPacketHandler)
	sph.InstallPathSender(ps, monotime.Now(), func() {})
	return sph
}

func requireGauge(t *testing.T, sph *sentPacketHandler, ps *recordingPathSender) {
	t.Helper()
	require.Equal(t, congestion.ByteCount(sph.bytesInFlight), ps.gauge, "the PathSender's gauge must equal the handler's bytes in flight")
}

func sendPing(sph *sentPacketHandler, tr *packetTracker, now monotime.Time, encLevel protocol.EncryptionLevel, size protocol.ByteCount) protocol.PacketNumber {
	pn := sph.PopPacketNumber(encLevel)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{tr.NewPingFrame(pn)}, encLevel, protocol.ECNNon, size, false, false)
	return pn
}

func TestPathSenderAttachCarriesFlight(t *testing.T) {
	sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, false, nil, utils.DefaultLogger).(*sentPacketHandler)
	var tr packetTracker
	sendPing(sph, &tr, monotime.Now(), protocol.Encryption1RTT, 1000)
	ps := newRecordingPathSender()
	sph.InstallPathSender(ps, monotime.Now(), func() {})
	require.True(t, ps.attached)
	require.Equal(t, congestion.ByteCount(1000), ps.attachedF)

	// Replacing it with an ordinary controller detaches it.
	sph.SetCongestionControl(newRecordingPathSender())
	require.True(t, ps.detached)
	require.Nil(t, sph.getPathSender())
}

func TestPathSenderSentPacketsAreClassifiedAsBuilt(t *testing.T) {
	ps := newRecordingPathSender()
	sph := newPathSenderHandler(t, ps, protocol.PerspectiveClient)
	now := monotime.Now()

	// An ACK-only packet is reported, not ack-eliciting and not in flight.
	pn := sph.PopPacketNumber(protocol.Encryption1RTT)
	sph.SentPacket(now, pn, 3, nil, nil, protocol.Encryption1RTT, protocol.ECNNon, 50, false, false)
	p := ps.lastSent()
	require.Equal(t, congestion.KindAckOnly, p.Kind)
	require.False(t, p.AckEliciting)
	require.False(t, p.InFlightCounted)
	require.Equal(t, congestion.SpaceApplication, p.Space)
	require.True(t, p.Exempt, "no permit was issued for it")

	// An ACK packet that gained a PING is ACK_PING, ack-eliciting.
	pn = sph.PopPacketNumber(protocol.Encryption1RTT)
	sph.SentPacket(now, pn, 3, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 51, false, false)
	require.Equal(t, congestion.KindAckPing, ps.lastSent().Kind)
	require.True(t, ps.lastSent().AckEliciting)

	// A queued keep-alive PING is a liveness packet.
	sph.ExpectLivenessPing()
	pn = sph.PopPacketNumber(protocol.Encryption1RTT)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 30, false, false)
	require.Equal(t, congestion.KindLiveness, ps.lastSent().Kind)

	// A packet built under a permit is ordinary and not exempt.
	require.Equal(t, SendAny, sph.SendMode(now))
	pn = sph.PopPacketNumber(protocol.Encryption1RTT)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, []StreamFrame{{Frame: &wire.StreamFrame{StreamID: 4, Data: make([]byte, 100)}}}, []Frame{{Frame: &wire.DatagramFrame{Data: make([]byte, 20)}}}, protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
	p = ps.lastSent()
	require.Equal(t, congestion.KindOrdinary, p.Kind)
	require.False(t, p.Exempt)
	require.True(t, p.HasDatagram)
	require.NotZero(t, p.ClassBytes[congestion.ClassBulk])
	require.NotZero(t, p.ClassBytes[congestion.ClassInteractive])
	var total congestion.ByteCount
	for _, n := range p.ClassBytes {
		total += n
	}
	require.Equal(t, congestion.ByteCount(1000), total, "every byte is charged to a class")
	// The permit covered one packet only.
	pn = sph.PopPacketNumber(protocol.Encryption1RTT)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 30, false, false)
	require.True(t, ps.lastSent().Exempt)

	// MTU probes, path probes and handshake packets.
	pn = sph.PopPacketNumber(protocol.Encryption1RTT)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 1400, true, false)
	require.Equal(t, congestion.KindMTUProbe, ps.lastSent().Kind)
	pn = sph.PopPacketNumber(protocol.Encryption1RTT)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PathChallengeFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, true)
	require.Equal(t, congestion.KindPathProbe, ps.lastSent().Kind)
	require.False(t, ps.lastSent().InFlightCounted)
	pn = sph.PopPacketNumber(protocol.EncryptionHandshake)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionHandshake, protocol.ECNNon, 1200, false, false)
	require.Equal(t, congestion.KindHandshake, ps.lastSent().Kind)
	require.Equal(t, congestion.SpaceHandshake, ps.lastSent().Space)

	requireGauge(t, sph, ps)
	ps.requireNoLegacyCalls(t)
}

func TestPathSenderAdmissionMapsToSendModes(t *testing.T) {
	ps := newRecordingPathSender()
	sph := newPathSenderHandler(t, ps, protocol.PerspectiveClient)
	now := monotime.Now()

	require.Equal(t, SendAny, sph.SendMode(now))
	retry := now.Add(3 * time.Millisecond)
	ps.admit = congestion.Permit{RetryAt: retry}
	require.Equal(t, SendPacingLimited, sph.SendMode(now))
	require.Equal(t, retry, sph.TimeUntilSend(), "RetryAt replaces TimeUntilSend")
	ps.admit = congestion.Permit{}
	require.Equal(t, SendAck, sph.SendMode(now), "a refusal without RetryAt is window-limited")
	ps.requireNoLegacyCalls(t)
}

func TestPathSenderGetsOneEventPerAck(t *testing.T) {
	ps := newRecordingPathSender()
	sph := newPathSenderHandler(t, ps, protocol.PerspectiveClient)
	var tr packetTracker
	start := monotime.Now()
	var pns []protocol.PacketNumber
	for i := range 10 {
		pns = append(pns, sendPing(sph, &tr, start.Add(time.Duration(i)*time.Millisecond), protocol.Encryption1RTT, 1000))
	}
	// An ACK-only packet in between is acknowledged too but was never in flight.
	ackOnly := sph.PopPacketNumber(protocol.Encryption1RTT)
	sph.SentPacket(start, ackOnly, 2, nil, nil, protocol.Encryption1RTT, protocol.ECNNon, 40, false, false)

	now := start.Add(100 * time.Millisecond)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[4], pns[5], pns[6], pns[7], pns[8], pns[9], ackOnly)}, protocol.Encryption1RTT, now)
	require.NoError(t, err)
	require.Len(t, ps.acks, 1)
	e := ps.lastAck()
	require.Len(t, e.Acked, 6, "only packets counted in flight are listed as acknowledged")
	require.Len(t, e.Lost, 4, "packets 0-3 are past the reordering threshold")
	for _, r := range append(e.Acked, e.Lost...) {
		require.Equal(t, congestion.SpaceApplication, r.Space)
		require.Equal(t, congestion.ByteCount(1000), r.Bytes)
	}
	require.NotZero(t, e.RTTSample)
	requireGauge(t, sph, ps)

	// An ACK that covers only packets already declared lost is a spurious
	// correction, and still produces an event.
	_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[1], pns[4], pns[5], pns[6], pns[7], pns[8], pns[9], ackOnly)}, protocol.Encryption1RTT, now.Add(time.Millisecond))
	require.NoError(t, err)
	require.Len(t, ps.acks, 2)
	require.Equal(t, []congestion.PacketRef{{Space: congestion.SpaceApplication, Number: congestion.PacketNumber(pns[1]), Bytes: 1000}}, ps.lastAck().Spurious,
		"a correction names exactly the reference that was reported lost")
	require.Empty(t, ps.lastAck().Acked)
	requireGauge(t, sph, ps)
	ps.requireNoLegacyCalls(t)

	p := sph.connStats.Progress()
	require.Equal(t, uint64(7), p.Epoch, "each newly acknowledged ack-eliciting packet is progress, a corrected loss included")
	require.Equal(t, now.Add(time.Millisecond), p.Last)
	require.False(t, p.ElicitingOutstanding)
}

func TestPathSenderLossTimerProducesAnEvent(t *testing.T) {
	ps := newRecordingPathSender()
	sph := newPathSenderHandler(t, ps, protocol.PerspectiveClient)
	var tr packetTracker
	start := monotime.Now()
	first := sendPing(sph, &tr, start, protocol.Encryption1RTT, 1000)
	second := sendPing(sph, &tr, start.Add(10*time.Millisecond), protocol.Encryption1RTT, 1000)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(second)}, protocol.Encryption1RTT, start.Add(100*time.Millisecond))
	require.NoError(t, err)
	require.Empty(t, ps.lastAck().Lost, "the first packet is not yet lost by time")
	timeout := sph.GetLossDetectionTimeout()
	require.NoError(t, sph.OnLossDetectionTimeout(timeout))
	require.Len(t, ps.acks, 2)
	require.Equal(t, []congestion.PacketRef{{Space: congestion.SpaceApplication, Number: congestion.PacketNumber(first), Bytes: 1000}}, ps.lastAck().Lost)
	requireGauge(t, sph, ps)
	ps.requireNoLegacyCalls(t)
}

func TestPathSenderFlightReconciliation(t *testing.T) {
	t.Run("PTO probe declaration", func(t *testing.T) {
		ps := newRecordingPathSender()
		sph := newPathSenderHandler(t, ps, protocol.PerspectiveClient)
		sph.DropPackets(protocol.EncryptionInitial, monotime.Now())
		sph.DropPackets(protocol.EncryptionHandshake, monotime.Now())
		var tr packetTracker
		start := monotime.Now()
		sendPing(sph, &tr, start, protocol.Encryption1RTT, 1000)
		sendPing(sph, &tr, start, protocol.Encryption1RTT, 1000)
		require.NoError(t, sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout()))
		require.Equal(t, SendPTOAppData, sph.SendMode(start))
		require.Equal(t, uint32(1), sph.connStats.Progress().PTOExpiries)
		require.True(t, sph.QueueProbePacket(protocol.Encryption1RTT))
		require.Equal(t, congestion.DiscardPTOProbe, ps.lastDiscard())
		requireGauge(t, sph, ps)
		// The probe itself is labelled as one.
		sendPing(sph, &tr, start, protocol.Encryption1RTT, 1000)
		require.Equal(t, congestion.KindPTOProbe, ps.lastSent().Kind)
		requireGauge(t, sph, ps)
	})

	t.Run("key drop", func(t *testing.T) {
		ps := newRecordingPathSender()
		sph := newPathSenderHandler(t, ps, protocol.PerspectiveClient)
		var tr packetTracker
		now := monotime.Now()
		sendPing(sph, &tr, now, protocol.EncryptionInitial, 1200)
		sendPing(sph, &tr, now, protocol.EncryptionHandshake, 1200)
		sendPing(sph, &tr, now, protocol.Encryption1RTT, 1000)
		sph.DropPackets(protocol.EncryptionInitial, now)
		require.Equal(t, congestion.DiscardKeyDrop, ps.lastDiscard())
		require.Equal(t, []congestion.PacketRef{{Space: congestion.SpaceInitial, Number: 0, Bytes: 1200}}, ps.lastDiscarded())
		requireGauge(t, sph, ps)
		sph.DropPackets(protocol.EncryptionHandshake, now)
		require.Equal(t, congestion.SpaceHandshake, ps.lastDiscarded()[0].Space, "packet numbers are named with their space")
		requireGauge(t, sph, ps)
		require.Equal(t, congestion.ByteCount(1000), ps.gauge)
	})

	t.Run("0-RTT rejection", func(t *testing.T) {
		ps := newRecordingPathSender()
		sph := newPathSenderHandler(t, ps, protocol.PerspectiveClient)
		var tr packetTracker
		now := monotime.Now()
		sendPing(sph, &tr, now, protocol.Encryption0RTT, 1000)
		sendPing(sph, &tr, now, protocol.Encryption0RTT, 1000)
		sph.DropPackets(protocol.Encryption0RTT, now)
		require.Equal(t, congestion.DiscardZeroRTTRejected, ps.lastDiscard())
		require.Len(t, ps.lastDiscarded(), 2)
		requireGauge(t, sph, ps)
	})

	t.Run("Retry", func(t *testing.T) {
		ps := newRecordingPathSender()
		sph := newPathSenderHandler(t, ps, protocol.PerspectiveClient)
		var tr packetTracker
		now := monotime.Now()
		sendPing(sph, &tr, now, protocol.EncryptionInitial, 1200)
		sendPing(sph, &tr, now, protocol.Encryption0RTT, 1000)
		sph.ResetForRetry(now.Add(10 * time.Millisecond))
		require.Equal(t, congestion.DiscardRetry, ps.lastDiscard())
		require.Len(t, ps.lastDiscarded(), 2)
		requireGauge(t, sph, ps)
	})

	t.Run("migration keeps the controller", func(t *testing.T) {
		ps := newRecordingPathSender()
		sph := newPathSenderHandler(t, ps, protocol.PerspectiveServer)
		var tr packetTracker
		now := monotime.Now()
		sendPing(sph, &tr, now, protocol.Encryption1RTT, 1000)
		sendPing(sph, &tr, now, protocol.Encryption1RTT, 1000)
		sph.MigratedPath(now, 1200)
		require.Equal(t, congestion.DiscardMigration, ps.lastDiscard())
		require.Len(t, ps.lastDiscarded(), 2)
		requireGauge(t, sph, ps)
		require.Same(t, ps, sph.getPathSender().(*recordingPathSender), "the controller is kept across migration")
		// It keeps receiving events.
		sendPing(sph, &tr, now, protocol.Encryption1RTT, 1000)
		requireGauge(t, sph, ps)
		ps.requireNoLegacyCalls(t)
	})
}

// Without a PathSender a migration still replaces the controller with Reno.
func TestMigrationWithoutPathSenderReplacesTheController(t *testing.T) {
	sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveServer, false, nil, utils.DefaultLogger).(*sentPacketHandler)
	installed := newRecordingPathSender()
	sph.SetCongestionControl(installed)
	sph.MigratedPath(monotime.Now(), 1200)
	_, isAdapter := sph.getCongestionControl().(*ccAdapter)
	require.False(t, isAdapter)
}

// A late acknowledgement of a packet declared lost is transport progress for
// every connection, and a correction only for the PathSender it was reported
// to.
func TestLateAcknowledgementIsProgressAndScopedCorrection(t *testing.T) {
	for _, withPathSender := range []bool{false, true} {
		sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, false, nil, utils.DefaultLogger).(*sentPacketHandler)
		ps := newRecordingPathSender()
		if withPathSender {
			sph.InstallPathSender(ps, monotime.Now(), func() {})
		}
		var tr packetTracker
		start := monotime.Now()
		var pns []protocol.PacketNumber
		for i := range 5 {
			pns = append(pns, sendPing(sph, &tr, start.Add(time.Duration(i)*time.Millisecond), protocol.Encryption1RTT, 1000))
		}
		now := start.Add(50 * time.Millisecond)
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[4])}, protocol.Encryption1RTT, now)
		require.NoError(t, err)
		require.Equal(t, uint64(1), sph.connStats.Progress().Epoch)
		if withPathSender {
			require.Len(t, ps.lastAck().Lost, 2)
			// Replace and reinstall: the new controller was never told of
			// the loss, so it gets no correction for it.
			sph.SetCongestionControl(newRecordingPathSender())
			ps = newRecordingPathSender()
			sph.InstallPathSender(ps, now, func() {})
		}
		// A reordered ACK covering the lost packet.
		_, err = sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[4])}, protocol.Encryption1RTT, now.Add(time.Millisecond))
		require.NoError(t, err)
		require.Equal(t, uint64(2), sph.connStats.Progress().Epoch, "with a PathSender: %v", withPathSender)
		if withPathSender {
			require.Empty(t, ps.acks)
		}
	}
}
