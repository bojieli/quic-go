package ackhandler

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	congestionExt "github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/congestion"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/qerr"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/apernet/quic-go/qlog"
	"github.com/apernet/quic-go/qlogwriter"
)

const (
	// Maximum reordering in time space before time based loss detection considers a packet lost.
	// Specified as an RTT multiplier.
	timeThreshold = 9.0 / 8
	// Maximum reordering in packets before packet threshold loss detection considers a packet lost.
	packetThreshold = 3
	// Before validating the client's address, the server won't send more than 3x bytes than it received.
	amplificationFactor = 3
	// We use Retry packets to derive an RTT estimate. Make sure we don't set the RTT to a super low value yet.
	minRTTAfterRetry = 5 * time.Millisecond
	// The PTO duration uses exponential backoff, but is truncated to a maximum value, as allowed by RFC 8961, section 4.4.
	maxPTODuration = 60 * time.Second
)

// Path probe packets are declared lost after this time.
const pathProbePacketLossTimeout = time.Second

// minDatagramRoomForSizing is the least room left in a datagram that is still
// used to size the next packet number. The imitated client needs the room to
// fit a header before it caps a packet to it; below that it keeps the full
// datagram size. A header size is not a constant, so this approximates it.
const minDatagramRoomForSizing protocol.ByteCount = 40

type packetNumberSpace struct {
	history sentPacketHistory
	pns     packetNumberGenerator

	lossTime                   monotime.Time
	lastAckElicitingPacketTime monotime.Time

	largestAcked protocol.PacketNumber
	largestSent  protocol.PacketNumber
}

func newPacketNumberSpace(initialPN protocol.PacketNumber, isAppData bool) *packetNumberSpace {
	var pns packetNumberGenerator
	if isAppData {
		pns = newSkippingPacketNumberGenerator(initialPN, protocol.SkipPacketInitialPeriod, protocol.SkipPacketMaxPeriod)
	} else {
		pns = newSequentialPacketNumberGenerator(initialPN)
	}
	return &packetNumberSpace{
		history:      *newSentPacketHistory(isAppData),
		pns:          pns,
		largestSent:  protocol.InvalidPacketNumber,
		largestAcked: protocol.InvalidPacketNumber,
	}
}

type alarmTimer struct {
	Time            monotime.Time
	TimerType       qlog.TimerType
	EncryptionLevel protocol.EncryptionLevel
}

type sentPacketHandler struct {
	initialPackets   *packetNumberSpace
	handshakePackets *packetNumberSpace
	appDataPackets   *packetNumberSpace
	lostPackets      lostPacketTracker // only for application-data packet number space
	// send time of the largest acknowledged packet, across all packet number spaces
	largestAckedTime monotime.Time

	// Do we know that the peer completed address validation yet?
	// Always true for the server.
	peerCompletedAddressValidation bool
	bytesReceived                  protocol.ByteCount
	bytesSent                      protocol.ByteCount
	// Have we validated the peer's address yet?
	// Always true for the client.
	peerAddressValidated bool

	handshakeConfirmed bool

	ignorePacketsBelow func(protocol.PacketNumber)

	ackedPackets     []packetWithPacketNumber // to avoid allocations in detectAndRemoveAckedPackets
	ackedPacketsInfo []congestionExt.AckedPacketInfo
	lostPacketsInfo  []congestionExt.LostPacketInfo

	bytesInFlight protocol.ByteCount

	congestion      congestion.SendAlgorithmWithDebugInfos
	congestionMutex sync.RWMutex
	// pathSender is set when the installed controller implements
	// congestion.PathSender. It then receives exact packet events instead of
	// the per-packet callbacks, and admits every ordinary packet.
	pathSender congestionExt.PathSender
	// permit is the answer to the last Admit. It covers the next packet only.
	permit congestionExt.Permit
	// classed says the installed PathSender schedules classes
	// (congestion.ClassScheduler): packets are classed by the class their
	// bytes were served at, and overhead is charged to the permit's turn.
	classed bool
	// admissionRefused says the last SendMode refused for the PathSender,
	// not for a transport limit.
	admissionRefused bool
	// grantPending is the verification grant the next packet was built
	// under, or zero.
	grantPending uint64
	// classBuiltPending says the next packet was built executing its
	// permit's class decision.
	classBuiltPending bool
	// ackLenPending is the size of the next packet's ACK frame.
	ackLenPending protocol.ByteCount
	// discardRefs is scratch space for OnDiscarded.
	discardRefs []congestionExt.PacketRef
	// lateAcks holds the ack-eliciting application packets declared lost,
	// for the horizon of the lost-packet tracker. A later acknowledgement of
	// one is transport progress and, if it was reported lost to the installed
	// PathSender, a correction of exactly that reference.
	// It is sorted by packet number and pruned from the front, so matching an
	// ACK against it is linear in the ACK's ranges and the records it covers.
	lateAcks []lostRecord
	// controllerGen identifies the installed PathSender.
	controllerGen uint32
	// appInFlight is the application-data part of bytesInFlight.
	appInFlight protocol.ByteCount

	progress  utils.TransportProgress
	published utils.TransportProgress
	rttStats  *utils.RTTStats
	connStats *utils.ConnectionStats

	// The number of times a PTO has been sent without receiving an ack.
	ptoCount uint32
	ptoMode  SendMode
	// The number of PTO probe packets that should be sent.
	// Only applies to the application-data packet number space.
	numProbesToSend int

	// The alarm timeout
	alarm alarmTimer

	enableECN  bool
	ecnTracker ecnHandler

	perspective protocol.Perspective

	// shortPacketNumbers allows single-byte packet numbers, as Chrome uses.
	shortPacketNumbers bool
	// maxDatagramSize converts the congestion window into a packet count, which
	// is what the packet number length depends on when shortPacketNumbers is set.
	maxDatagramSize protocol.ByteCount
	// lastDatagramPadding is the room left in the datagram that was packed last,
	// which is what the imitated client measures the window against instead.
	lastDatagramPadding protocol.ByteCount

	qlogger     qlogwriter.Recorder
	lastMetrics qlog.MetricsUpdated
	logger      utils.Logger
}

var _ SentPacketHandler = &sentPacketHandler{}

type lostRecord struct {
	pn       protocol.PacketNumber
	size     protocol.ByteCount
	sent     monotime.Time
	reported bool   // to a PathSender
	gen      uint32 // the PathSender it was reported to
	// counted says the loss was added to the connection's PacketsLost and
	// BytesLost by the transport, which takes it back on a correction.
	counted bool
}

// clientAddressValidated indicates whether the address was validated beforehand by an address validation token.
// If the address was validated, the amplification limit doesn't apply. It has no effect for a client.
func NewSentPacketHandler(
	initialPN protocol.PacketNumber,
	initialMaxDatagramSize protocol.ByteCount,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	clientAddressValidated bool,
	enableECN bool,
	ignorePacketsBelow func(protocol.PacketNumber),
	pers protocol.Perspective,
	shortPacketNumbers bool,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
) SentPacketHandler {
	congestion := congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		connStats,
		initialMaxDatagramSize,
		true, // use Reno
		qlogger,
	)

	h := &sentPacketHandler{
		shortPacketNumbers:             shortPacketNumbers,
		maxDatagramSize:                initialMaxDatagramSize,
		peerCompletedAddressValidation: pers == protocol.PerspectiveServer,
		peerAddressValidated:           pers == protocol.PerspectiveClient || clientAddressValidated,
		initialPackets:                 newPacketNumberSpace(initialPN, false),
		handshakePackets:               newPacketNumberSpace(0, false),
		appDataPackets:                 newPacketNumberSpace(0, true),
		lostPackets:                    *newLostPacketTracker(64),
		rttStats:                       rttStats,
		connStats:                      connStats,
		congestion:                     congestion,
		ignorePacketsBelow:             ignorePacketsBelow,
		perspective:                    pers,
		qlogger:                        qlogger,
		logger:                         logger,
	}
	if enableECN {
		h.enableECN = true
		h.ecnTracker = newECNTracker(logger, qlogger)
	}
	return h
}

func (h *sentPacketHandler) removeFromBytesInFlight(p *packet) {
	if p.includedInBytesInFlight {
		if p.Length > h.bytesInFlight {
			panic("negative bytes_in_flight")
		}
		h.bytesInFlight -= p.Length
		if p.EncryptionLevel == protocol.Encryption1RTT || p.EncryptionLevel == protocol.Encryption0RTT {
			h.appInFlight -= p.Length
		}
		p.includedInBytesInFlight = false
	}
}

func (h *sentPacketHandler) DropPackets(encLevel protocol.EncryptionLevel, now monotime.Time) {
	// The server won't await address validation after the handshake is confirmed.
	// This applies even if we didn't receive an ACK for a Handshake packet.
	if h.perspective == protocol.PerspectiveClient && encLevel == protocol.EncryptionHandshake {
		h.peerCompletedAddressValidation = true
	}
	ps := h.getPathSender()
	h.discardRefs = h.discardRefs[:0]
	// remove outstanding packets from bytes_in_flight
	if encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake {
		pnSpace := h.getPacketNumberSpace(encLevel)
		// We might already have dropped this packet number space.
		if pnSpace == nil {
			return
		}
		for pn, p := range pnSpace.history.Packets() {
			if ps != nil && p.includedInBytesInFlight {
				h.discardRefs = append(h.discardRefs, packetRef(encLevel, pn, p.Length))
			}
			h.removeFromBytesInFlight(p)
		}
	}
	// drop the packet history
	//nolint:exhaustive // Not every packet number space can be dropped.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.initialPackets = nil
	case protocol.EncryptionHandshake:
		// Dropping the handshake packet number space means that the handshake is confirmed,
		// see section 4.9.2 of RFC 9001.
		h.handshakeConfirmed = true
		h.handshakePackets = nil
	case protocol.Encryption0RTT:
		// This function is only called when 0-RTT is rejected,
		// and not when the client drops 0-RTT keys when the handshake completes.
		// When 0-RTT is rejected, all application data sent so far becomes invalid.
		// Delete the packets from the history and remove them from bytes_in_flight.
		for pn, p := range h.appDataPackets.history.Packets() {
			if p.EncryptionLevel != protocol.Encryption0RTT {
				break
			}
			if ps != nil && p.includedInBytesInFlight {
				h.discardRefs = append(h.discardRefs, packetRef(protocol.Encryption0RTT, pn, p.Length))
			}
			h.removeFromBytesInFlight(p)
			h.appDataPackets.history.Remove(pn)
		}
	default:
		panic(fmt.Sprintf("Cannot drop keys for encryption level %s", encLevel))
	}
	if ps != nil {
		if encLevel == protocol.Encryption0RTT {
			ps.OnDiscarded(now, congestionExt.ByteCount(h.bytesInFlight), h.discardRefs, false, congestionExt.DiscardZeroRTTRejected)
		} else {
			ps.OnDiscarded(now, congestionExt.ByteCount(h.bytesInFlight), h.discardRefs, true, congestionExt.DiscardKeyDrop)
		}
		clear(h.discardRefs)
		h.discardRefs = h.discardRefs[:0]
	}
	if h.qlogger != nil && h.ptoCount != 0 {
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
	}
	h.ptoCount = 0
	h.numProbesToSend = 0
	h.ptoMode = SendNone
	h.setLossDetectionTimer(now)
}

func (h *sentPacketHandler) ReceivedBytes(n protocol.ByteCount, t monotime.Time) {
	h.connStats.BytesReceived.Add(uint64(n))
	wasAmplificationLimit := h.isAmplificationLimited()
	h.bytesReceived += n
	if wasAmplificationLimit && !h.isAmplificationLimited() {
		h.setLossDetectionTimer(t)
	}
}

func (h *sentPacketHandler) ReceivedPacket(l protocol.EncryptionLevel, t monotime.Time) {
	h.connStats.PacketsReceived.Add(1)
	if h.perspective == protocol.PerspectiveServer && l == protocol.EncryptionHandshake && !h.peerAddressValidated {
		h.peerAddressValidated = true
		h.setLossDetectionTimer(t)
	}
}

func (h *sentPacketHandler) packetsInFlight() int {
	packetsInFlight := h.appDataPackets.history.NumOutstanding()
	if h.handshakePackets != nil {
		packetsInFlight += h.handshakePackets.history.NumOutstanding()
	}
	if h.initialPackets != nil {
		packetsInFlight += h.initialPackets.history.NumOutstanding()
	}
	return packetsInFlight
}

func (h *sentPacketHandler) SentPacket(
	t monotime.Time,
	pn, largestAcked protocol.PacketNumber,
	streamFrames []StreamFrame,
	frames []Frame,
	encLevel protocol.EncryptionLevel,
	ecn protocol.ECN,
	size protocol.ByteCount,
	isPathMTUProbePacket bool,
	isPathProbePacket bool,
) {
	h.bytesSent += size
	h.connStats.BytesSent.Add(uint64(size))
	h.connStats.PacketsSent.Add(1)

	pnSpace := h.getPacketNumberSpace(encLevel)
	if h.logger.Debug() && (pnSpace.history.HasOutstandingPackets() || pnSpace.history.HasOutstandingPathProbes()) {
		for p := max(0, pnSpace.largestSent+1); p < pn; p++ {
			h.logger.Debugf("Skipping packet number %d", p)
		}
	}

	pnSpace.largestSent = pn

	p := getPacket()
	p.SendTime = t
	p.EncryptionLevel = encLevel
	p.Length = size
	p.Frames = frames
	p.LargestAcked = largestAcked
	p.StreamFrames = streamFrames
	p.IsPathMTUProbePacket = isPathMTUProbePacket
	p.isPathProbePacket = isPathProbePacket
	isAckEliciting := p.IsAckEliciting()

	cc, ps := h.getControllers()
	// A permit covers exactly one packet. It is only used, and only touched,
	// on the run loop while a PathSender is installed.
	// A permit covers the build that follows the Admit that issued it --
	// every packet of a coalesced datagram, handshake-only builds included --
	// and is withdrawn by the next SendMode. Each packet of a batch is
	// preceded by its own SendMode.
	var underPermit bool
	if ps != nil {
		underPermit = h.permit.OK
	}

	if isPathProbePacket {
		pnSpace.history.SentPathProbePacket(pn, p)
		if ps != nil {
			h.ackLenPending = 0
			ps.OnSent(h.sentPacketInfo(t, encLevel, pn, p, congestionExt.KindPathProbe, true, 0, false))
		}
		h.setLossDetectionTimer(t)
		return
	}
	isProbe := false
	if isAckEliciting {
		pnSpace.lastAckElicitingPacketTime = t
		h.bytesInFlight += size
		if encLevel == protocol.Encryption1RTT || encLevel == protocol.Encryption0RTT {
			h.appInFlight += size
		}
		p.includedInBytesInFlight = true
		if h.numProbesToSend > 0 {
			h.numProbesToSend--
			isProbe = true
		}
	}

	if ps != nil {
		kind := h.packetKind(encLevel, p, isAckEliciting, isProbe)
		grant := h.grantPending
		h.grantPending = 0
		if grant != 0 {
			kind = congestionExt.KindVerification
		}
		ackLen := h.ackLenPending
		h.ackLenPending = 0
		classBuilt := h.classBuiltPending
		h.classBuiltPending = false
		info := h.sentPacketInfo(t, encLevel, pn, p, kind, !underPermit, ackLen, classBuilt)
		info.Grant = grant
		info.ClassBuilt = classBuilt && underPermit
		ps.OnSent(info)
	} else {
		cc.OnPacketSent(t, h.bytesInFlight, pn, size, isAckEliciting)
	}

	if encLevel == protocol.Encryption1RTT && h.ecnTracker != nil {
		h.ecnTracker.SentPacket(pn, ecn)
	}

	pnSpace.history.SentPacket(pn, p)
	if !isAckEliciting {
		if !h.peerCompletedAddressValidation {
			h.setLossDetectionTimer(t)
		}
		return
	}
	if h.qlogger != nil {
		h.qlogMetricsUpdated()
	}
	h.setLossDetectionTimer(t)
}

func (h *sentPacketHandler) qlogMetricsUpdated() {
	var metricsUpdatedEvent qlog.MetricsUpdated
	var updated bool
	if h.rttStats.HasMeasurement() {
		if h.lastMetrics.MinRTT != h.rttStats.MinRTT() {
			metricsUpdatedEvent.MinRTT = h.rttStats.MinRTT()
			h.lastMetrics.MinRTT = metricsUpdatedEvent.MinRTT
			updated = true
		}
		if h.lastMetrics.SmoothedRTT != h.rttStats.SmoothedRTT() {
			metricsUpdatedEvent.SmoothedRTT = h.rttStats.SmoothedRTT()
			h.lastMetrics.SmoothedRTT = metricsUpdatedEvent.SmoothedRTT
			updated = true
		}
		if h.lastMetrics.LatestRTT != h.rttStats.LatestRTT() {
			metricsUpdatedEvent.LatestRTT = h.rttStats.LatestRTT()
			h.lastMetrics.LatestRTT = metricsUpdatedEvent.LatestRTT
			updated = true
		}
		if h.lastMetrics.RTTVariance != h.rttStats.MeanDeviation() {
			metricsUpdatedEvent.RTTVariance = h.rttStats.MeanDeviation()
			h.lastMetrics.RTTVariance = metricsUpdatedEvent.RTTVariance
			updated = true
		}
	}
	if cwnd := h.getCongestionControl().GetCongestionWindow(); h.lastMetrics.CongestionWindow != int(cwnd) {
		metricsUpdatedEvent.CongestionWindow = int(cwnd)
		h.lastMetrics.CongestionWindow = metricsUpdatedEvent.CongestionWindow
		updated = true
	}
	if h.lastMetrics.BytesInFlight != int(h.bytesInFlight) {
		metricsUpdatedEvent.BytesInFlight = int(h.bytesInFlight)
		h.lastMetrics.BytesInFlight = metricsUpdatedEvent.BytesInFlight
		updated = true
	}
	packetsInFlight := h.packetsInFlight()
	if h.lastMetrics.PacketsInFlight != packetsInFlight {
		metricsUpdatedEvent.PacketsInFlight = packetsInFlight
		h.lastMetrics.PacketsInFlight = metricsUpdatedEvent.PacketsInFlight
		updated = true
	}
	if updated {
		h.qlogger.RecordEvent(metricsUpdatedEvent)
	}
}

func (h *sentPacketHandler) getPacketNumberSpace(encLevel protocol.EncryptionLevel) *packetNumberSpace {
	switch encLevel {
	case protocol.EncryptionInitial:
		return h.initialPackets
	case protocol.EncryptionHandshake:
		return h.handshakePackets
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		return h.appDataPackets
	default:
		panic("invalid packet number space")
	}
}

func (h *sentPacketHandler) ReceivedAck(ack *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) (bool /* contained 1-RTT packet */, error) {
	pnSpace := h.getPacketNumberSpace(encLevel)

	largestAcked := ack.LargestAcked()
	if largestAcked > pnSpace.largestSent {
		return false, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received ACK for an unsent packet",
		}
	}

	// Servers complete address validation when a protected packet is received.
	if h.perspective == protocol.PerspectiveClient && !h.peerCompletedAddressValidation &&
		(encLevel == protocol.EncryptionHandshake || encLevel == protocol.Encryption1RTT) {
		h.peerCompletedAddressValidation = true
		h.logger.Debugf("Peer doesn't await address validation any longer.")
		// Make sure that the timer is reset, even if this ACK doesn't acknowledge any (ack-eliciting) packets.
		h.setLossDetectionTimer(rcvTime)
	}

	priorInFlight := h.bytesInFlight
	ackedPackets, hasAckEliciting, err := h.detectAndRemoveAckedPackets(ack, encLevel)
	if err != nil {
		return false, err
	}
	cc, ps := h.getControllers()
	if len(ackedPackets) == 0 {
		// An ACK that covers only packets already declared lost still
		// corrects them, as long as the lost-packet tracker holds them.
		if encLevel == protocol.Encryption1RTT {
			spurious := h.creditLateAcks(ack, rcvTime, ps)
			h.publishProgress()
			if ps != nil && len(spurious) > 0 {
				ps.OnAckEvent(congestionExt.AckEvent{
					Time:     rcvTime,
					InFlight: congestionExt.ByteCount(h.bytesInFlight),
					Spurious: spurious,
				})
			}
		}
		return false, nil
	}
	var event congestionExt.AckEvent

	// update the RTT, if:
	// * the largest acked is newly acknowledged, AND
	// * at least one new ack-eliciting packet was acknowledged
	if len(ackedPackets) > 0 {
		if p := ackedPackets[len(ackedPackets)-1]; p.PacketNumber == ack.LargestAcked() && !p.isPathProbePacket && hasAckEliciting {
			// don't use the ack delay for Initial and Handshake packets
			var ackDelay time.Duration
			if encLevel == protocol.Encryption1RTT {
				ackDelay = min(ack.DelayTime, h.rttStats.MaxAckDelay())
			}
			if h.largestAckedTime.IsZero() || !p.SendTime.Before(h.largestAckedTime) {
				h.rttStats.UpdateRTT(rcvTime.Sub(p.SendTime), ackDelay)
				event.RTTSample = rcvTime.Sub(p.SendTime)
				if h.logger.Debug() {
					h.logger.Debugf("\tupdated RTT: %s (σ: %s)", h.rttStats.SmoothedRTT(), h.rttStats.MeanDeviation())
				}
				h.largestAckedTime = p.SendTime
			}
			if ps == nil {
				cc.MaybeExitSlowStart()
			}
		}
	}

	// Only inform the ECN tracker about new 1-RTT ACKs if the ACK increases the largest acked.
	if encLevel == protocol.Encryption1RTT && h.ecnTracker != nil && largestAcked > pnSpace.largestAcked {
		congested := h.ecnTracker.HandleNewlyAcked(ackedPackets, int64(ack.ECT0), int64(ack.ECT1), int64(ack.ECNCE))
		if congested {
			if ps != nil {
				event.ECNCongestion = true
			} else {
				cc.OnCongestionEvent(largestAcked, 0, priorInFlight)
			}
		}
	}

	pnSpace.largestAcked = max(pnSpace.largestAcked, largestAcked)

	h.detectLostPackets(rcvTime, encLevel)
	h.ackedPacketsInfo = h.ackedPacketsInfo[:0]
	if encLevel == protocol.Encryption1RTT {
		h.detectLostPathProbes(rcvTime)
	}
	var acked1RTTPacket bool
	for _, p := range ackedPackets {
		if p.includedInBytesInFlight {
			if ps != nil {
				event.Acked = append(event.Acked, packetRef(encLevel, p.PacketNumber, p.Length))
			} else {
				cc.OnPacketAcked(p.PacketNumber, p.Length, priorInFlight, rcvTime)
			}
			h.ackedPacketsInfo = append(h.ackedPacketsInfo, congestionExt.AckedPacketInfo{
				PacketNumber: congestionExt.PacketNumber(p.PacketNumber),
				BytesAcked:   congestionExt.ByteCount(p.Length),
			})
		}
		if p.EncryptionLevel == protocol.Encryption1RTT {
			acked1RTTPacket = true
		}
		if (p.EncryptionLevel == protocol.Encryption1RTT || p.EncryptionLevel == protocol.Encryption0RTT) &&
			!p.isPathProbePacket && p.IsAckEliciting() {
			h.progress.Epoch++
			h.progress.Last = rcvTime
			h.progress.PTOExpiries = 0
		}
		h.removeFromBytesInFlight(p.packet)
		if !p.isPathProbePacket {
			putPacket(p.packet)
		}
	}

	if ps == nil {
		// The aggregate event goes to the controller that received this
		// ACK's per-packet callbacks, and is withheld from it if it was
		// replaced while they were delivered, and never redirected to its
		// successor. A replacement on another goroutine that races the call
		// itself is not excluded: legacy controllers are swapped outside the
		// run loop, as before.
		if cex, ok := cc.(congestion.SendAlgorithmEx); ok && h.getCongestionControl() == cc &&
			(len(h.ackedPacketsInfo) != 0 || len(h.lostPacketsInfo) != 0) {
			cex.OnCongestionEventEx(priorInFlight, rcvTime, h.ackedPacketsInfo, h.lostPacketsInfo)
		}
	}

	// A late acknowledgement of a packet declared lost, from a reordered ACK
	// too, is progress and corrects the loss.
	if encLevel == protocol.Encryption1RTT {
		event.Spurious = h.creditLateAcks(ack, rcvTime, ps)
	}
	// detect spurious losses for application data packets, if the ACK was not reordered
	if encLevel == protocol.Encryption1RTT && largestAcked == pnSpace.largestAcked {
		h.detectSpuriousLosses(
			ack,
			rcvTime.Add(-min(ack.DelayTime, h.rttStats.MaxAckDelay())),
		)
		// clean up lost packet history
		h.lostPackets.DeleteBefore(rcvTime.Add(-3 * h.rttStats.PTO(false)))
	}
	if ps != nil {
		event.Time = rcvTime
		event.InFlight = congestionExt.ByteCount(h.bytesInFlight)
		event.Lost = h.lostRefs(encLevel)
		ps.OnAckEvent(event)
	}

	// After this point, we must not use ackedPackets any longer!
	// We've already returned the buffers.
	ackedPackets = nil    //nolint:ineffassign // This is just to be on the safe side.
	clear(h.ackedPackets) // make sure the memory is released
	h.ackedPackets = h.ackedPackets[:0]
	h.ackedPacketsInfo = nil //nolint:ineffassign // This is just to be on the safe side.
	h.lostPacketsInfo = nil  //nolint:ineffassign // This is just to be on the safe side.

	// Reset the pto_count unless the client is unsure if the server has validated the client's address.
	if h.peerCompletedAddressValidation {
		if h.qlogger != nil && h.ptoCount != 0 {
			h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
		}
		h.ptoCount = 0
	}
	h.numProbesToSend = 0

	if h.qlogger != nil {
		h.qlogMetricsUpdated()
	}

	h.setLossDetectionTimer(rcvTime)
	return acked1RTTPacket, nil
}

func (h *sentPacketHandler) detectSpuriousLosses(ack *wire.AckFrame, ackTime monotime.Time) {
	var maxPacketReordering protocol.PacketNumber
	var maxTimeReordering time.Duration
	ackRangeIdx := len(ack.AckRanges) - 1
	var spuriousLosses []protocol.PacketNumber
	for pn, sendTime := range h.lostPackets.All() {
		ackRange := ack.AckRanges[ackRangeIdx]
		for pn > ackRange.Largest {
			// this should never happen, since detectSpuriousLosses is only called for ACKs that increase the largest acked
			if ackRangeIdx == 0 {
				break
			}
			ackRangeIdx--
			ackRange = ack.AckRanges[ackRangeIdx]
		}
		if pn < ackRange.Smallest {
			continue
		}
		if pn <= ackRange.Largest {
			packetReordering := h.appDataPackets.history.Difference(ack.LargestAcked(), pn)
			timeReordering := ackTime.Sub(sendTime)
			maxPacketReordering = max(maxPacketReordering, packetReordering)
			maxTimeReordering = max(maxTimeReordering, timeReordering)

			if h.qlogger != nil {
				h.qlogger.RecordEvent(qlog.SpuriousLoss{
					EncryptionLevel:  protocol.Encryption1RTT,
					PacketNumber:     pn,
					PacketReordering: uint64(packetReordering),
					TimeReordering:   timeReordering,
				})
			}
			spuriousLosses = append(spuriousLosses, pn)
		}
	}
	for _, pn := range spuriousLosses {
		h.lostPackets.Delete(pn)
	}
}

// maxLateAcks bounds the late-acknowledgement history.
const maxLateAcks = 256

// creditLateAcks finds the ack-eliciting application packets declared lost
// that this ACK acknowledges. Each is transport progress. It returns those
// reported lost to the installed PathSender, as the references that were
// reported, and forgets records past the lost-packet tracker's horizon. The
// records are sorted by packet number, so each ACK range is found by binary
// search: an ACK that covers none of them costs O(ranges * log records).
func (h *sentPacketHandler) creditLateAcks(ack *wire.AckFrame, rcvTime monotime.Time, ps congestionExt.PathSender) []congestionExt.PacketRef {
	if len(h.lateAcks) == 0 {
		return nil
	}
	// Records are appended in roughly send order, so expiry is at the front.
	horizon := rcvTime.Add(-3 * h.rttStats.PTO(false))
	n := 0
	for n < len(h.lateAcks) && h.lateAcks[n].sent.Before(horizon) {
		n++
	}
	if n > 0 {
		h.lateAcks = slices.Delete(h.lateAcks, 0, n)
	}
	byNumber := func(e lostRecord, pn protocol.PacketNumber) int { return cmp.Compare(e.pn, pn) }
	var refs []congestionExt.PacketRef
	for _, r := range ack.AckRanges {
		lo, _ := slices.BinarySearchFunc(h.lateAcks, r.Smallest, byNumber)
		hi, found := slices.BinarySearchFunc(h.lateAcks, r.Largest, byNumber)
		if found {
			hi++
		}
		if lo >= hi {
			continue
		}
		for _, rec := range h.lateAcks[lo:hi] {
			h.progress.Epoch++
			h.progress.Last = rcvTime
			h.progress.PTOExpiries = 0
			if rec.counted {
				// A spurious loss: the transport takes back what it counted.
				h.connStats.PacketsLost.Add(^uint64(0))
				h.connStats.BytesLost.Add(^uint64(rec.size - 1))
			}
			if ps != nil && rec.reported && rec.gen == h.controllerGen {
				refs = append(refs, congestionExt.PacketRef{Space: congestionExt.SpaceApplication, Number: congestionExt.PacketNumber(rec.pn), Bytes: congestionExt.ByteCount(rec.size)})
			}
		}
		h.lateAcks = slices.Delete(h.lateAcks, lo, hi)
	}
	slices.SortFunc(refs, func(a, b congestionExt.PacketRef) int { return cmp.Compare(a.Number, b.Number) })
	return refs
}

// recordLateAck remembers an ack-eliciting application packet that left the
// flight without a fate known to be final.
func (h *sentPacketHandler) recordLateAck(r lostRecord) {
	i, _ := slices.BinarySearchFunc(h.lateAcks, r.pn, func(e lostRecord, pn protocol.PacketNumber) int { return cmp.Compare(e.pn, pn) })
	if i < len(h.lateAcks) && h.lateAcks[i].pn == r.pn {
		h.lateAcks[i] = r
		return
	}
	h.lateAcks = slices.Insert(h.lateAcks, i, r)
	if len(h.lateAcks) > maxLateAcks {
		h.lateAcks = slices.Delete(h.lateAcks, 0, len(h.lateAcks)-maxLateAcks)
	}
}

// Packets are returned in ascending packet number order.
func (h *sentPacketHandler) detectAndRemoveAckedPackets(
	ack *wire.AckFrame,
	encLevel protocol.EncryptionLevel,
) (_ []packetWithPacketNumber, hasAckEliciting bool, _ error) {
	if len(h.ackedPackets) > 0 {
		return nil, false, errors.New("ackhandler BUG: ackedPackets slice not empty")
	}

	pnSpace := h.getPacketNumberSpace(encLevel)

	if encLevel == protocol.Encryption1RTT {
		for p := range pnSpace.history.SkippedPackets() {
			if ack.AcksPacket(p) {
				return nil, false, &qerr.TransportError{
					ErrorCode:    qerr.ProtocolViolation,
					ErrorMessage: fmt.Sprintf("received an ACK for skipped packet number: %d (%s)", p, encLevel),
				}
			}
		}
	}

	var ackRangeIndex int
	lowestAcked := ack.LowestAcked()
	largestAcked := ack.LargestAcked()
	for pn, p := range pnSpace.history.Packets() {
		// ignore packets below the lowest acked
		if pn < lowestAcked {
			continue
		}
		if pn > largestAcked {
			break
		}

		if ack.HasMissingRanges() {
			ackRange := ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]

			for pn > ackRange.Largest && ackRangeIndex < len(ack.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]
			}

			if pn < ackRange.Smallest { // packet not contained in ACK range
				continue
			}
			if pn > ackRange.Largest {
				return nil, false, fmt.Errorf("BUG: ackhandler would have acked wrong packet %d, while evaluating range %d -> %d", pn, ackRange.Smallest, ackRange.Largest)
			}
		}
		if p.isPathProbePacket {
			probePacket := pnSpace.history.RemovePathProbe(pn)
			// the probe packet might already have been declared lost
			if probePacket != nil {
				h.ackedPackets = append(h.ackedPackets, packetWithPacketNumber{PacketNumber: pn, packet: probePacket})
			}
			continue
		}
		if p.IsAckEliciting() {
			hasAckEliciting = true
		}
		h.ackedPackets = append(h.ackedPackets, packetWithPacketNumber{PacketNumber: pn, packet: p})
	}
	if h.logger.Debug() && len(h.ackedPackets) > 0 {
		pns := make([]protocol.PacketNumber, len(h.ackedPackets))
		for i, p := range h.ackedPackets {
			pns[i] = p.PacketNumber
		}
		h.logger.Debugf("\tnewly acked packets (%d): %d", len(pns), pns)
	}

	for _, p := range h.ackedPackets {
		if p.LargestAcked != protocol.InvalidPacketNumber && encLevel == protocol.Encryption1RTT && h.ignorePacketsBelow != nil {
			h.ignorePacketsBelow(p.LargestAcked + 1)
		}

		for _, f := range p.Frames {
			if f.Handler != nil {
				f.Handler.OnAcked(f.Frame)
			}
		}
		for _, f := range p.StreamFrames {
			if f.Handler != nil {
				f.Handler.OnAcked(f.Frame)
			}
		}
		if err := pnSpace.history.Remove(p.PacketNumber); err != nil {
			return nil, false, err
		}
	}
	// TODO: add support for the transport:packets_acked qlog event
	return h.ackedPackets, hasAckEliciting, nil
}

func (h *sentPacketHandler) getLossTimeAndSpace() (monotime.Time, protocol.EncryptionLevel) {
	var encLevel protocol.EncryptionLevel
	var lossTime monotime.Time

	if h.initialPackets != nil {
		lossTime = h.initialPackets.lossTime
		encLevel = protocol.EncryptionInitial
	}
	if h.handshakePackets != nil && (lossTime.IsZero() || (!h.handshakePackets.lossTime.IsZero() && h.handshakePackets.lossTime.Before(lossTime))) {
		lossTime = h.handshakePackets.lossTime
		encLevel = protocol.EncryptionHandshake
	}
	if lossTime.IsZero() || (!h.appDataPackets.lossTime.IsZero() && h.appDataPackets.lossTime.Before(lossTime)) {
		lossTime = h.appDataPackets.lossTime
		encLevel = protocol.Encryption1RTT
	}
	return lossTime, encLevel
}

func (h *sentPacketHandler) getScaledPTO(includeMaxAckDelay bool) time.Duration {
	pto := h.rttStats.PTO(includeMaxAckDelay) << h.ptoCount
	if pto > maxPTODuration || pto <= 0 {
		return maxPTODuration
	}
	return pto
}

// same logic as getLossTimeAndSpace, but for lastAckElicitingPacketTime instead of lossTime
func (h *sentPacketHandler) getPTOTimeAndSpace(now monotime.Time) (pto monotime.Time, encLevel protocol.EncryptionLevel) {
	// We only send application data probe packets once the handshake is confirmed,
	// because before that, we don't have the keys to decrypt ACKs sent in 1-RTT packets.
	if !h.handshakeConfirmed && !h.hasOutstandingCryptoPackets() {
		if h.peerCompletedAddressValidation {
			return
		}
		t := now.Add(h.getScaledPTO(false))
		if h.initialPackets != nil {
			return t, protocol.EncryptionInitial
		}
		return t, protocol.EncryptionHandshake
	}

	if h.initialPackets != nil && h.initialPackets.history.HasOutstandingPackets() &&
		!h.initialPackets.lastAckElicitingPacketTime.IsZero() {
		encLevel = protocol.EncryptionInitial
		if t := h.initialPackets.lastAckElicitingPacketTime; !t.IsZero() {
			pto = t.Add(h.getScaledPTO(false))
		}
	}
	if h.handshakePackets != nil && h.handshakePackets.history.HasOutstandingPackets() &&
		!h.handshakePackets.lastAckElicitingPacketTime.IsZero() {
		t := h.handshakePackets.lastAckElicitingPacketTime.Add(h.getScaledPTO(false))
		if pto.IsZero() || (!t.IsZero() && t.Before(pto)) {
			pto = t
			encLevel = protocol.EncryptionHandshake
		}
	}
	if h.handshakeConfirmed && h.appDataPackets.history.HasOutstandingPackets() &&
		!h.appDataPackets.lastAckElicitingPacketTime.IsZero() {
		t := h.appDataPackets.lastAckElicitingPacketTime.Add(h.getScaledPTO(true))
		if pto.IsZero() || (!t.IsZero() && t.Before(pto)) {
			pto = t
			encLevel = protocol.Encryption1RTT
		}
	}
	return pto, encLevel
}

func (h *sentPacketHandler) hasOutstandingCryptoPackets() bool {
	if h.initialPackets != nil && h.initialPackets.history.HasOutstandingPackets() {
		return true
	}
	if h.handshakePackets != nil && h.handshakePackets.history.HasOutstandingPackets() {
		return true
	}
	return false
}

func (h *sentPacketHandler) setLossDetectionTimer(now monotime.Time) {
	h.publishProgress()
	oldAlarm := h.alarm // only needed in case tracing is enabled
	newAlarm := h.lossDetectionTime(now)
	h.alarm = newAlarm

	hasAlarm := !newAlarm.Time.IsZero()
	if !hasAlarm && !oldAlarm.Time.IsZero() {
		h.logger.Debugf("Canceling loss detection timer.")
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.LossTimerUpdated{
				Type: qlog.LossTimerUpdateTypeCancelled,
			})
		}
	}

	if h.qlogger != nil && hasAlarm && newAlarm != oldAlarm {
		h.qlogger.RecordEvent(qlog.LossTimerUpdated{
			Type:      qlog.LossTimerUpdateTypeSet,
			TimerType: newAlarm.TimerType,
			EncLevel:  newAlarm.EncryptionLevel,
			Time:      newAlarm.Time.ToTime(),
		})
	}
}

func (h *sentPacketHandler) lossDetectionTime(now monotime.Time) alarmTimer {
	// cancel the alarm if no packets are outstanding
	if h.peerCompletedAddressValidation && !h.hasOutstandingCryptoPackets() &&
		!h.appDataPackets.history.HasOutstandingPackets() && !h.appDataPackets.history.HasOutstandingPathProbes() {
		return alarmTimer{}
	}

	// cancel the alarm if amplification limited
	if h.isAmplificationLimited() {
		return alarmTimer{}
	}

	var pathProbeLossTime monotime.Time
	if h.appDataPackets.history.HasOutstandingPathProbes() {
		if _, p := h.appDataPackets.history.FirstOutstandingPathProbe(); p != nil {
			pathProbeLossTime = p.SendTime.Add(pathProbePacketLossTimeout)
		}
	}

	// early retransmit timer or time loss detection
	lossTime, encLevel := h.getLossTimeAndSpace()
	if !lossTime.IsZero() && (pathProbeLossTime.IsZero() || lossTime.Before(pathProbeLossTime)) {
		return alarmTimer{
			Time:            lossTime,
			TimerType:       qlog.TimerTypeACK,
			EncryptionLevel: encLevel,
		}
	}
	ptoTime, encLevel := h.getPTOTimeAndSpace(now)
	if !ptoTime.IsZero() && (pathProbeLossTime.IsZero() || ptoTime.Before(pathProbeLossTime)) {
		return alarmTimer{
			Time:            ptoTime,
			TimerType:       qlog.TimerTypePTO,
			EncryptionLevel: encLevel,
		}
	}
	if !pathProbeLossTime.IsZero() {
		return alarmTimer{
			Time:            pathProbeLossTime,
			TimerType:       qlog.TimerTypePathProbe,
			EncryptionLevel: protocol.Encryption1RTT,
		}
	}
	return alarmTimer{}
}

func (h *sentPacketHandler) detectLostPathProbes(now monotime.Time) {
	if !h.appDataPackets.history.HasOutstandingPathProbes() {
		return
	}
	lossTime := now.Add(-pathProbePacketLossTimeout)
	// RemovePathProbe cannot be called while iterating.
	var lostPathProbes []packetWithPacketNumber
	for pn, p := range h.appDataPackets.history.PathProbes() {
		if !p.SendTime.After(lossTime) {
			lostPathProbes = append(lostPathProbes, packetWithPacketNumber{PacketNumber: pn, packet: p})
		}
	}
	for _, p := range lostPathProbes {
		for _, f := range p.Frames {
			f.Handler.OnLost(f.Frame)
		}
		h.appDataPackets.history.RemovePathProbe(p.PacketNumber)
	}
}

func (h *sentPacketHandler) detectLostPackets(now monotime.Time, encLevel protocol.EncryptionLevel) {
	h.lostPacketsInfo = h.lostPacketsInfo[:0]
	pnSpace := h.getPacketNumberSpace(encLevel)
	pnSpace.lossTime = 0

	maxRTT := float64(max(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT()))
	lossDelay := time.Duration(timeThreshold * maxRTT)

	// Minimum time of granularity before packets are deemed lost.
	lossDelay = max(lossDelay, protocol.TimerGranularity)

	// Packets sent before this time are deemed lost.
	lostSendTime := now.Add(-lossDelay)

	cc, ps := h.getControllers()

	priorInFlight := h.bytesInFlight
	for pn, p := range pnSpace.history.Packets() {
		if pn > pnSpace.largestAcked {
			break
		}

		var packetLost bool
		if !p.SendTime.After(lostSendTime) {
			packetLost = true
			if !p.isPathProbePacket && p.IsAckEliciting() {
				if h.logger.Debug() {
					h.logger.Debugf("\tlost packet %d (time threshold)", pn)
				}
				if h.qlogger != nil {
					h.qlogger.RecordEvent(qlog.PacketLost{
						Header: qlog.PacketHeader{
							PacketType:   qlog.EncryptionLevelToPacketType(p.EncryptionLevel),
							PacketNumber: pn,
						},
						Trigger: qlog.PacketLossTimeThreshold,
					})
				}
			}
		} else if pnSpace.history.Difference(pnSpace.largestAcked, pn) >= packetThreshold {
			packetLost = true
			if !p.isPathProbePacket && p.IsAckEliciting() {
				if h.logger.Debug() {
					h.logger.Debugf("\tlost packet %d (reordering threshold)", pn)
				}
				if h.qlogger != nil {
					h.qlogger.RecordEvent(qlog.PacketLost{
						Header: qlog.PacketHeader{
							PacketType:   qlog.EncryptionLevelToPacketType(p.EncryptionLevel),
							PacketNumber: pn,
						},
						Trigger: qlog.PacketLossReorderingThreshold,
					})
				}
			}
		} else if pnSpace.lossTime.IsZero() {
			// Note: This conditional is only entered once per call
			lossTime := p.SendTime.Add(lossDelay)
			if h.logger.Debug() {
				h.logger.Debugf("\tsetting loss timer for packet %d (%s) to %s (in %s)", pn, encLevel, lossDelay, lossTime)
			}
			pnSpace.lossTime = lossTime
		}
		if packetLost {
			if encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT {
				h.lostPackets.Add(pn, p.SendTime)
			}
			pnSpace.history.DeclareLost(pn)
			if !p.isPathProbePacket && p.IsAckEliciting() {
				// the bytes in flight need to be reduced no matter if the frames in this packet will be retransmitted
				h.removeFromBytesInFlight(p)
				h.queueFramesForRetransmission(p)
				if !p.IsPathMTUProbePacket {
					if ps == nil {
						cc.OnCongestionEvent(pn, p.Length, priorInFlight)
					} else {
						// The legacy controller counts these; with a
						// PathSender the transport does.
						h.connStats.PacketsLost.Add(1)
						h.connStats.BytesLost.Add(uint64(p.Length))
					}
				}
				h.lostPacketsInfo = append(h.lostPacketsInfo, congestionExt.LostPacketInfo{
					PacketNumber: congestionExt.PacketNumber(pn),
					BytesLost:    congestionExt.ByteCount(p.Length),
				})
				if encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT {
					h.recordLateAck(lostRecord{pn: pn, size: p.Length, sent: p.SendTime, reported: ps != nil, gen: h.controllerGen, counted: ps != nil && !p.IsPathMTUProbePacket})
				}
				if encLevel == protocol.Encryption1RTT && h.ecnTracker != nil {
					h.ecnTracker.LostPacket(pn)
				}
			}
		}
	}
}

func (h *sentPacketHandler) OnLossDetectionTimeout(now monotime.Time) error {
	defer h.setLossDetectionTimer(now)

	if h.handshakeConfirmed {
		h.detectLostPathProbes(now)
	}

	priorInFlight := h.bytesInFlight
	earliestLossTime, encLevel := h.getLossTimeAndSpace()
	if !earliestLossTime.IsZero() {
		if h.logger.Debug() {
			h.logger.Debugf("Loss detection alarm fired in loss timer mode. Loss time: %s", earliestLossTime)
		}
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeExpired,
				TimerType: qlog.TimerTypeACK,
				EncLevel:  encLevel,
			})
		}
		// Early retransmit or time loss detection
		h.detectLostPackets(now, encLevel)

		cc, ps := h.getControllers()
		if ps != nil {
			ps.OnAckEvent(congestionExt.AckEvent{
				Time:     now,
				InFlight: congestionExt.ByteCount(h.bytesInFlight),
				Lost:     h.lostRefs(encLevel),
			})
			return nil
		}
		if cex, ok := cc.(congestion.SendAlgorithmEx); ok &&
			len(h.lostPacketsInfo) != 0 {
			cex.OnCongestionEventEx(priorInFlight, now, nil, h.lostPacketsInfo)
		}
		return nil
	}

	// PTO
	// When all outstanding are acknowledged, the alarm is canceled in setLossDetectionTimer.
	// However, there's no way to reset the timer in the connection.
	// When OnLossDetectionTimeout is called, we therefore need to make sure that there are
	// actually packets outstanding.
	if h.bytesInFlight == 0 && !h.peerCompletedAddressValidation {
		h.ptoCount++
		h.progress.PTOExpiries++
		h.numProbesToSend++
		if h.initialPackets != nil {
			h.ptoMode = SendPTOInitial
		} else if h.handshakePackets != nil {
			h.ptoMode = SendPTOHandshake
		} else {
			return errors.New("sentPacketHandler BUG: PTO fired, but bytes_in_flight is 0 and Initial and Handshake already dropped")
		}
		return nil
	}

	ptoTime, encLevel := h.getPTOTimeAndSpace(now)
	if ptoTime.IsZero() {
		return nil
	}
	ps := h.getPacketNumberSpace(encLevel)
	if !ps.history.HasOutstandingPackets() && !ps.history.HasOutstandingPathProbes() && !h.peerCompletedAddressValidation {
		return nil
	}
	h.ptoCount++
	h.progress.PTOExpiries++
	if h.logger.Debug() {
		h.logger.Debugf("Loss detection alarm for %s fired in PTO mode. PTO count: %d", encLevel, h.ptoCount)
	}
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.LossTimerUpdated{
			Type:      qlog.LossTimerUpdateTypeExpired,
			TimerType: qlog.TimerTypePTO,
			EncLevel:  encLevel,
		})
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: h.ptoCount})
	}
	h.numProbesToSend += 2
	//nolint:exhaustive // We never arm a PTO timer for 0-RTT packets.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.ptoMode = SendPTOInitial
	case protocol.EncryptionHandshake:
		h.ptoMode = SendPTOHandshake
	case protocol.Encryption1RTT:
		// skip a packet number in order to elicit an immediate ACK
		pn := h.PopPacketNumber(protocol.Encryption1RTT)
		h.getPacketNumberSpace(protocol.Encryption1RTT).history.SkippedPacket(pn)
		h.ptoMode = SendPTOAppData
	default:
		return fmt.Errorf("PTO timer in unexpected encryption level: %s", encLevel)
	}
	return nil
}

func (h *sentPacketHandler) GetLossDetectionTimeout() monotime.Time {
	return h.alarm.Time
}

func (h *sentPacketHandler) ECNMode(isShortHeaderPacket bool) protocol.ECN {
	if !h.enableECN {
		return protocol.ECNUnsupported
	}
	if !isShortHeaderPacket {
		return protocol.ECNNon
	}
	return h.ecnTracker.Mode()
}

// packetNumberSizingUnit is the packet size the congestion window is expressed
// in when deriving the packet number length. The imitated client coalesces a
// packet into a datagram and then caps the next packet to the room that is
// left, so a nearly full datagram makes the window look like a large number of
// packets and lengthens the packet number for exactly one packet. Too little
// room for a header and it keeps the full size instead.
func (h *sentPacketHandler) packetNumberSizingUnit() protocol.ByteCount {
	if h.lastDatagramPadding >= minDatagramRoomForSizing {
		return h.lastDatagramPadding
	}
	return h.maxDatagramSize
}

func (h *sentPacketHandler) PeekPacketNumber(encLevel protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	pnSpace := h.getPacketNumberSpace(encLevel)
	pn := pnSpace.pns.Peek()
	// See section 17.1 of RFC 9000.
	if h.shortPacketNumbers {
		var cwndPackets protocol.PacketNumber
		if size := h.packetNumberSizingUnit(); size > 0 {
			cwndPackets = protocol.PacketNumber(h.getCongestionControl().GetCongestionWindow() / size)
		}
		return pn, protocol.PacketNumberLengthForHeaderChrome(pn, pnSpace.largestAcked, cwndPackets)
	}
	return pn, protocol.PacketNumberLengthForHeader(pn, pnSpace.largestAcked)
}

func (h *sentPacketHandler) PopPacketNumber(encLevel protocol.EncryptionLevel) protocol.PacketNumber {
	pnSpace := h.getPacketNumberSpace(encLevel)
	skipped, pn := pnSpace.pns.Pop()
	if skipped {
		skippedPN := pn - 1
		pnSpace.history.SkippedPacket(skippedPN)
		if h.logger.Debug() {
			h.logger.Debugf("Skipping packet number %d", skippedPN)
		}
	}
	return pn
}

func (h *sentPacketHandler) SendMode(now monotime.Time) SendMode {
	cc, ps := h.getControllers()
	if ps != nil {
		// A permit covers only the build that follows the Admit that issued it.
		h.permit = congestionExt.Permit{}
	}
	numTrackedPackets := h.appDataPackets.history.Len()
	if h.initialPackets != nil {
		numTrackedPackets += h.initialPackets.history.Len()
	}
	if h.handshakePackets != nil {
		numTrackedPackets += h.handshakePackets.history.Len()
	}

	if h.isAmplificationLimited() {
		h.logger.Debugf("Amplification window limited. Received %d bytes, already sent out %d bytes", h.bytesReceived, h.bytesSent)
		return SendNone
	}
	// Don't send any packets if we're keeping track of the maximum number of packets.
	// Note that since MaxOutstandingSentPackets is smaller than MaxTrackedSentPackets,
	// we will stop sending out new data when reaching MaxOutstandingSentPackets,
	// but still allow sending of retransmissions and ACKs.
	if numTrackedPackets >= protocol.MaxTrackedSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Limited by the number of tracked packets: tracking %d packets, maximum %d", numTrackedPackets, protocol.MaxTrackedSentPackets)
		}
		return SendNone
	}
	if h.numProbesToSend > 0 {
		return h.ptoMode
	}
	if ps != nil {
		return h.pathSenderSendMode(ps, now, numTrackedPackets)
	}
	// Only send ACKs if we're congestion limited.
	if !cc.CanSend(h.bytesInFlight) {
		if h.logger.Debug() {
			h.logger.Debugf("Congestion limited: bytes in flight %d, window %d", h.bytesInFlight, cc.GetCongestionWindow())
		}
		return SendAck
	}
	if numTrackedPackets >= protocol.MaxOutstandingSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Max outstanding limited: tracking %d packets, maximum: %d", numTrackedPackets, protocol.MaxOutstandingSentPackets)
		}
		return SendAck
	}
	if !cc.HasPacingBudget(now) {
		return SendPacingLimited
	}
	return SendAny
}

// pathSenderSendMode asks a PathSender for a permit in place of CanSend and
// HasPacingBudget. A window refusal (no RetryAt) maps to SendAck, a pacing or
// precedence refusal to SendPacingLimited, in the same order as for any other
// controller.
func (h *sentPacketHandler) pathSenderSendMode(ps congestionExt.PathSender, now monotime.Time, numTrackedPackets int) SendMode {
	h.permit = ps.Admit(now, congestionExt.ByteCount(h.maxDatagramSize))
	if h.classed && h.permit.OK && h.permit.MaxBytes < congestionExt.MinClassedPermit {
		// Too small to build a packet in: a window refusal, so the exempt
		// obligations, due ACKs among them, still go.
		h.permit = congestionExt.Permit{}
	}
	// The transport's outstanding-packet limit comes first: whatever the
	// controller answered, only an ACK may go, and no exempt obligation or
	// grant may spend the headroom kept for ACKs.
	if numTrackedPackets >= protocol.MaxOutstandingSentPackets {
		h.permit = congestionExt.Permit{}
		h.admissionRefused = false
		if h.logger.Debug() {
			h.logger.Debugf("Max outstanding limited: tracking %d packets, maximum: %d", numTrackedPackets, protocol.MaxOutstandingSentPackets)
		}
		return SendAck
	}
	h.admissionRefused = !h.permit.OK
	if !h.permit.OK && h.permit.RetryAt.IsZero() {
		if h.logger.Debug() {
			h.logger.Debugf("Congestion limited: bytes in flight %d", h.bytesInFlight)
		}
		return SendAck
	}
	if !h.permit.OK {
		return SendPacingLimited
	}
	return SendAny
}

func (h *sentPacketHandler) TimeUntilSend() monotime.Time {
	cc, ps := h.getControllers()
	if ps != nil {
		return h.permit.RetryAt
	}
	return cc.TimeUntilSend(h.bytesInFlight)
}

func (h *sentPacketHandler) SetMaxDatagramSize(s protocol.ByteCount) {
	h.maxDatagramSize = s
	h.getCongestionControl().SetMaxDatagramSize(s)
}

func (h *sentPacketHandler) SetLastDatagramPadding(n protocol.ByteCount) {
	h.lastDatagramPadding = n
}

func (h *sentPacketHandler) isAmplificationLimited() bool {
	if h.peerAddressValidated {
		return false
	}
	return h.bytesSent >= amplificationFactor*h.bytesReceived
}

func (h *sentPacketHandler) QueueProbePacket(encLevel protocol.EncryptionLevel) bool {
	pnSpace := h.getPacketNumberSpace(encLevel)
	pn, p := pnSpace.history.FirstOutstanding()
	if p == nil {
		return false
	}
	// TODO: don't declare the packet lost here.
	// Keep track of acknowledged frames instead.
	// Call DeclareLost before queueFramesForRetransmission, which clears the packet's frames.
	pnSpace.history.DeclareLost(pn)
	wasInFlight := p.includedInBytesInFlight
	if (encLevel == protocol.Encryption1RTT || encLevel == protocol.Encryption0RTT) && p.IsAckEliciting() && !p.isPathProbePacket {
		// It may still be acknowledged: that is progress, not a correction.
		h.recordLateAck(lostRecord{pn: pn, size: p.Length, sent: p.SendTime})
	}
	h.removeFromBytesInFlight(p)
	if ps := h.getPathSender(); ps != nil && wasInFlight {
		refs := append(h.discardRefs[:0], packetRef(encLevel, pn, p.Length))
		ps.OnDiscarded(monotime.Now(), congestionExt.ByteCount(h.bytesInFlight), refs, false, congestionExt.DiscardPTOProbe)
		h.discardRefs = refs[:0]
	}
	h.queueFramesForRetransmission(p)
	return true
}

func (h *sentPacketHandler) queueFramesForRetransmission(p *packet) {
	if len(p.Frames) == 0 && len(p.StreamFrames) == 0 {
		panic("no frames")
	}
	for _, f := range p.Frames {
		if f.Handler != nil {
			f.Handler.OnLost(f.Frame)
		}
	}
	for _, f := range p.StreamFrames {
		if f.Handler != nil {
			f.Handler.OnLost(f.Frame)
		}
	}
	p.StreamFrames = nil
	p.Frames = nil
}

func (h *sentPacketHandler) ResetForRetry(now monotime.Time) {
	h.bytesInFlight = 0
	h.appInFlight = 0
	ps := h.getPathSender()
	h.discardRefs = h.discardRefs[:0]
	var firstPacketSendTime monotime.Time
	for pn, p := range h.initialPackets.history.Packets() {
		if firstPacketSendTime.IsZero() {
			firstPacketSendTime = p.SendTime
		}
		if ps != nil && p.includedInBytesInFlight {
			h.discardRefs = append(h.discardRefs, packetRef(protocol.EncryptionInitial, pn, p.Length))
		}
		if p.IsAckEliciting() {
			h.queueFramesForRetransmission(p)
		}
	}
	// All application data packets sent at this point are 0-RTT packets.
	// In the case of a Retry, we can assume that the server dropped all of them.
	for pn, p := range h.appDataPackets.history.Packets() {
		if ps != nil && p.includedInBytesInFlight {
			h.discardRefs = append(h.discardRefs, packetRef(protocol.Encryption0RTT, pn, p.Length))
		}
		if p.IsAckEliciting() {
			h.queueFramesForRetransmission(p)
		}
	}
	if ps != nil {
		ps.OnDiscarded(now, 0, h.discardRefs, true, congestionExt.DiscardRetry)
		clear(h.discardRefs)
		h.discardRefs = h.discardRefs[:0]
	}

	// Only use the Retry to estimate the RTT if we didn't send any retransmission for the Initial.
	// Otherwise, we don't know which Initial the Retry was sent in response to.
	if h.ptoCount == 0 {
		// Don't set the RTT to a value lower than 5ms here.
		h.rttStats.UpdateRTT(max(minRTTAfterRetry, now.Sub(firstPacketSendTime)), 0)
		if h.logger.Debug() {
			h.logger.Debugf("\tupdated RTT: %s (σ: %s)", h.rttStats.SmoothedRTT(), h.rttStats.MeanDeviation())
		}
		if h.qlogger != nil {
			h.qlogMetricsUpdated()
		}
	}
	h.initialPackets = newPacketNumberSpace(h.initialPackets.pns.Peek(), false)
	h.appDataPackets = newPacketNumberSpace(h.appDataPackets.pns.Peek(), true)
	h.publishProgress()
	oldAlarm := h.alarm
	h.alarm = alarmTimer{}
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
		if !oldAlarm.Time.IsZero() {
			h.qlogger.RecordEvent(qlog.LossTimerUpdated{
				Type: qlog.LossTimerUpdateTypeCancelled,
			})
		}
	}
	h.ptoCount = 0
}

func (h *sentPacketHandler) MigratedPath(now monotime.Time, initialMaxDatagramSize protocol.ByteCount) {
	h.rttStats.ResetForPathMigration()
	ps := h.getPathSender()
	h.discardRefs = h.discardRefs[:0]
	for pn, p := range h.appDataPackets.history.Packets() {
		h.appDataPackets.history.DeclareLost(pn)
		if !p.isPathProbePacket {
			if ps != nil && p.includedInBytesInFlight {
				h.discardRefs = append(h.discardRefs, packetRef(protocol.Encryption1RTT, pn, p.Length))
			}
			if p.IsAckEliciting() {
				// A late acknowledgement is still progress, not a correction.
				h.recordLateAck(lostRecord{pn: pn, size: p.Length, sent: p.SendTime})
			}
			h.removeFromBytesInFlight(p)
			if p.IsAckEliciting() {
				h.queueFramesForRetransmission(p)
			}
		}
	}
	for pn := range h.appDataPackets.history.PathProbes() {
		h.appDataPackets.history.RemovePathProbe(pn)
	}
	if ps != nil {
		// A PathSender is kept across a migration. The connection tells it
		// the old and new addresses once it has recorded them.
		ps.OnDiscarded(now, congestionExt.ByteCount(h.bytesInFlight), h.discardRefs, true, congestionExt.DiscardMigration)
		clear(h.discardRefs)
		h.discardRefs = h.discardRefs[:0]
		h.permit = congestionExt.Permit{}
		// Path MTU discovery starts again on the new path.
		h.maxDatagramSize = initialMaxDatagramSize
		ps.SetMaxDatagramSize(congestionExt.ByteCount(initialMaxDatagramSize))
		h.setLossDetectionTimer(now)
		return
	}
	h.congestionMutex.Lock()
	h.congestion = congestion.NewCubicSender(
		congestion.DefaultClock{},
		h.rttStats,
		h.connStats,
		initialMaxDatagramSize,
		true, // use Reno
		h.qlogger,
	)
	h.congestionMutex.Unlock()
	h.setLossDetectionTimer(now)
}

func (h *sentPacketHandler) getCongestionControl() congestion.SendAlgorithmWithDebugInfos {
	h.congestionMutex.RLock()
	cc := h.congestion
	h.congestionMutex.RUnlock()
	return cc
}

func (h *sentPacketHandler) getPathSender() congestionExt.PathSender {
	h.congestionMutex.RLock()
	ps := h.pathSender
	h.congestionMutex.RUnlock()
	return ps
}

func (h *sentPacketHandler) getControllers() (congestion.SendAlgorithmWithDebugInfos, congestionExt.PathSender) {
	h.congestionMutex.RLock()
	cc, ps := h.congestion, h.pathSender
	h.congestionMutex.RUnlock()
	return cc, ps
}

// SetCongestionControl installs a controller. A congestion.PathSender must be
// installed with InstallPathSender, on the run loop; passed here it is driven
// through the per-packet callbacks like any other controller. Replacing a
// PathSender detaches it, and must then happen on the run loop too.
func (h *sentPacketHandler) SetCongestionControl(cc congestionExt.CongestionControl) {
	h.congestionMutex.Lock()
	old := h.pathSender
	h.pathSender = nil
	h.classed = false
	cc.SetRTTStatsProvider(h.rttStats)
	if ccEx, isEx := cc.(congestionExt.CongestionControlEx); isEx {
		h.congestion = &ccAdapterEx{ccEx}
	} else {
		h.congestion = &ccAdapter{cc}
	}
	h.congestionMutex.Unlock()
	if old != nil {
		// Replacing a PathSender happens on the run loop.
		h.permit = congestionExt.Permit{}
		h.controllerGen++
		old.OnDetach(monotime.Now())
	}
}

// InstallPathSender installs a PathSender. It must be called on the run loop.
// OnAttach is the controller's first call and carries the current flight.
func (h *sentPacketHandler) InstallPathSender(ps congestionExt.PathSender, now monotime.Time, wake func()) {
	h.congestionMutex.RLock()
	old := h.pathSender
	h.congestionMutex.RUnlock()
	if old != nil {
		old.OnDetach(now)
	}
	// OnAttach is the new controller's first call.
	ps.OnAttach(now, congestionExt.ByteCount(h.bytesInFlight), congestionExt.ByteCount(h.maxDatagramSize), wake)
	ps.SetRTTStatsProvider(h.rttStats)
	h.congestionMutex.Lock()
	h.congestion = &ccAdapter{ps}
	h.pathSender = ps
	h.classed = SchedulesClasses(ps)
	h.permit = congestionExt.Permit{}
	h.controllerGen++
	h.congestionMutex.Unlock()
}

// DetachPathSender tells an installed PathSender that the connection is gone.
func (h *sentPacketHandler) DetachPathSender(now monotime.Time) {
	h.congestionMutex.Lock()
	ps := h.pathSender
	h.pathSender = nil
	h.classed = false
	h.congestionMutex.Unlock()
	if ps != nil {
		ps.OnDetach(now)
	}
}

// AdmissionRefused says the last SendMode refused because the PathSender
// refused admission. A transport limit (the outstanding-packet limit) is not
// an admission refusal, and grants the exempt path no more than an ACK.
func (h *sentPacketHandler) AdmissionRefused() bool { return h.admissionRefused }

// SchedulesClasses says whether a PathSender asks the builder to execute
// its class decisions.
func SchedulesClasses(ps congestionExt.PathSender) bool {
	cs, ok := ps.(congestionExt.ClassScheduler)
	return ok && cs.SchedulesClasses()
}

// Permit is the permit the next packet is built under, and whether the
// installed PathSender schedules classes. Run loop only.
func (h *sentPacketHandler) Permit() (congestionExt.Permit, bool) {
	return h.permit, h.classed && h.pathSender != nil
}

// ExpectClassBuilt says the next packet was built executing its permit's
// class decision.
func (h *sentPacketHandler) ExpectClassBuilt() { h.classBuiltPending = true }

// ExpectGrantedPacket says the next packet was built under a verification
// grant.
func (h *sentPacketHandler) ExpectGrantedPacket(id uint64) { h.grantPending = id }

// ExpectAckLength says how long the next packet's ACK frame is.
func (h *sentPacketHandler) ExpectAckLength(n protocol.ByteCount) { h.ackLenPending = n }

// BytesInFlight returns the connection's bytes in flight.
func (h *sentPacketHandler) BytesInFlight() protocol.ByteCount { return h.bytesInFlight }

func spaceOf(encLevel protocol.EncryptionLevel) congestionExt.PacketSpace {
	switch encLevel {
	case protocol.EncryptionInitial:
		return congestionExt.SpaceInitial
	case protocol.EncryptionHandshake:
		return congestionExt.SpaceHandshake
	default:
		return congestionExt.SpaceApplication
	}
}

func packetRef(encLevel protocol.EncryptionLevel, pn protocol.PacketNumber, size protocol.ByteCount) congestionExt.PacketRef {
	return congestionExt.PacketRef{Space: spaceOf(encLevel), Number: congestionExt.PacketNumber(pn), Bytes: congestionExt.ByteCount(size)}
}

// lostRefs converts the packets detectLostPackets just declared lost.
func (h *sentPacketHandler) lostRefs(encLevel protocol.EncryptionLevel) []congestionExt.PacketRef {
	if len(h.lostPacketsInfo) == 0 {
		return nil
	}
	refs := make([]congestionExt.PacketRef, len(h.lostPacketsInfo))
	for i, l := range h.lostPacketsInfo {
		refs[i] = congestionExt.PacketRef{Space: spaceOf(encLevel), Number: l.PacketNumber, Bytes: l.BytesLost}
	}
	return refs
}

// packetKind labels a packet from what was actually assembled.
func (h *sentPacketHandler) packetKind(encLevel protocol.EncryptionLevel, p *packet, ackEliciting, ptoProbe bool) congestionExt.PacketKind {
	switch {
	case encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake:
		return congestionExt.KindHandshake
	case p.IsPathMTUProbePacket:
		return congestionExt.KindMTUProbe
	case !ackEliciting:
		return congestionExt.KindAckOnly
	case ptoProbe:
		return congestionExt.KindPTOProbe
	}
	if len(p.StreamFrames) > 0 {
		return congestionExt.KindOrdinary
	}
	onlyPing, pathValidation, liveness := true, false, false
	for _, f := range p.Frames {
		switch f.Frame.(type) {
		case *wire.PingFrame:
			// The keep-alive PING is recognised by its own marker, not by
			// what was queued, so an unrelated PING is never mistaken for it.
			liveness = liveness || isLivenessPing(f)
		case *wire.PathChallengeFrame, *wire.PathResponseFrame:
			pathValidation = true
		default:
			onlyPing = false
		}
	}
	if !onlyPing {
		return congestionExt.KindOrdinary
	}
	if liveness {
		return congestionExt.KindLiveness
	}
	if pathValidation {
		// A packet of path validation frames (and perhaps a PING) built
		// on the current path. Unlike a probe packet it is in flight.
		return congestionExt.KindPathProbe
	}
	if p.LargestAcked != protocol.InvalidPacketNumber {
		return congestionExt.KindAckPing
	}
	return congestionExt.KindOrdinary
}

// sentPacketInfo describes a registered packet. Without class tags, bytes are
// classed by frame type: stream data is BULK, DATAGRAM frames INTERACTIVE,
// ACK, PING and path validation EXEMPT, anything else CONTROL. Packet
// overhead is charged to the first non-exempt class the packet carries.
func (h *sentPacketHandler) sentPacketInfo(t monotime.Time, encLevel protocol.EncryptionLevel, pn protocol.PacketNumber, p *packet, kind congestionExt.PacketKind, exempt bool, ackLen protocol.ByteCount, classBuilt bool) congestionExt.SentPacket {
	info := congestionExt.SentPacket{
		Space:           spaceOf(encLevel),
		Number:          congestionExt.PacketNumber(pn),
		Bytes:           congestionExt.ByteCount(p.Length),
		AckEliciting:    p.IsAckEliciting(),
		InFlightCounted: p.includedInBytesInFlight,
		Exempt:          exempt, // the build path actually used
		Kind:            kind,
		InFlight:        congestionExt.ByteCount(h.bytesInFlight),
		Time:            t,
	}
	// The ACK frame is exempt.
	framed := min(ackLen, p.Length)
	info.ClassBytes[congestionExt.ClassExempt] += congestionExt.ByteCount(framed)
	for _, f := range p.StreamFrames {
		n := f.Frame.Length(protocol.Version1)
		class := congestionExt.ClassBulk
		if h.classed && f.Frame.Class != 0 {
			// The class the bytes were served at.
			class = congestionExt.SendClass(f.Frame.Class)
		}
		info.ClassBytes[class] += congestionExt.ByteCount(n)
		framed += n
	}
	for _, f := range p.Frames {
		n := f.Frame.Length(protocol.Version1)
		framed += n
		switch f.Frame.(type) {
		case *wire.DatagramFrame:
			info.HasDatagram = true
			info.ClassBytes[congestionExt.ClassInteractive] += congestionExt.ByteCount(n)
		case *wire.PingFrame, *wire.PathChallengeFrame, *wire.PathResponseFrame:
			info.ClassBytes[congestionExt.ClassExempt] += congestionExt.ByteCount(n)
		default:
			info.ClassBytes[congestionExt.ClassControl] += congestionExt.ByteCount(n)
		}
	}
	if h.classed && p.IsPathMTUProbePacket {
		// An MTU probe is INTERACTIVE work, whatever it is made of.
		info.ClassBytes = [congestionExt.NumSendClasses]congestionExt.ByteCount{}
		info.ClassBytes[congestionExt.ClassExempt] = congestionExt.ByteCount(min(ackLen, p.Length))
		info.ClassBytes[congestionExt.ClassInteractive] = congestionExt.ByteCount(p.Length) - info.ClassBytes[congestionExt.ClassExempt]
		return info
	}
	if framed < p.Length {
		overhead := congestionExt.ByteCount(p.Length - framed)
		class := congestionExt.ClassExempt
		if turn := h.permit.Turn; h.classed && classBuilt && !exempt && h.permit.OK && turn < congestionExt.NumSendClasses {
			// A class-built packet's overhead is its turn's, even when only
			// fill classes, or only exempt frames, found room in it.
			class = turn
		} else {
			for _, c := range []congestionExt.SendClass{congestionExt.ClassControl, congestionExt.ClassInteractive, congestionExt.ClassBulk} {
				if info.ClassBytes[c] > 0 {
					class = c
					break
				}
			}
		}
		info.ClassBytes[class] += overhead
	}
	return info
}

// publishProgress publishes the transport progress snapshot when it changed.
func (h *sentPacketHandler) publishProgress() {
	h.progress.ElicitingOutstanding = h.appInFlight > 0
	if h.progress != h.published {
		h.published = h.progress
		h.connStats.SetProgress(h.progress)
	}
}
