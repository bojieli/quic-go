package congestion

import (
	"net"
	"time"

	"github.com/apernet/quic-go/monotime"
)

// PacketSpace identifies a QUIC packet number space. Packet numbers are only
// unique within a space, so every packet a PathSender is told about carries
// one.
type PacketSpace uint8

const (
	SpaceInitial PacketSpace = iota
	SpaceHandshake
	SpaceApplication
)

// SendClass is the class of work a packet, or part of one, carries.
type SendClass uint8

const (
	ClassExempt SendClass = iota
	ClassControl
	ClassInteractive
	ClassBulk
)

// NumSendClasses is the number of SendClass values.
const NumSendClasses = 4

// PacketKind labels a packet by what it was built as.
type PacketKind uint8

const (
	// KindOrdinary is a packet built under a permit.
	KindOrdinary PacketKind = iota
	// KindPTOProbe is a probe sent because the probe timeout fired.
	KindPTOProbe
	// KindMTUProbe is a path MTU discovery probe.
	KindMTUProbe
	// KindPathProbe carries PATH_CHALLENGE or PATH_RESPONSE.
	KindPathProbe
	// KindAckOnly elicits no acknowledgement.
	KindAckOnly
	// KindAckPing is an ACK packet that gained a PING to elicit an
	// acknowledgement. It is not a sample.
	KindAckPing
	// KindHandshake is an Initial or Handshake packet.
	KindHandshake
	// KindLiveness carries a keep-alive PING and nothing ordinary.
	KindLiveness
	// KindVerification carries stream bytes covered by a verification grant,
	// built without a permit.
	KindVerification
)

func (k PacketKind) String() string {
	switch k {
	case KindOrdinary:
		return "ordinary"
	case KindPTOProbe:
		return "pto-probe"
	case KindMTUProbe:
		return "mtu-probe"
	case KindPathProbe:
		return "path-probe"
	case KindAckOnly:
		return "ack-only"
	case KindAckPing:
		return "ack-ping"
	case KindHandshake:
		return "handshake"
	case KindLiveness:
		return "liveness"
	case KindVerification:
		return "verification"
	default:
		return "unknown"
	}
}

// DiscardReason says why packets left the flight without a known fate.
type DiscardReason uint8

const (
	// DiscardKeyDrop is the drop of the Initial or Handshake keys.
	DiscardKeyDrop DiscardReason = iota
	// DiscardRetry is a Retry, which invalidates everything sent so far.
	DiscardRetry
	// DiscardZeroRTTRejected is the rejection of 0-RTT.
	DiscardZeroRTTRejected
	// DiscardPTOProbe is a packet declared lost only so that its frames can
	// be sent in a probe.
	DiscardPTOProbe
	// DiscardMigration is a path migration, after which every outstanding
	// application packet is retransmitted.
	DiscardMigration
)

func (r DiscardReason) String() string {
	switch r {
	case DiscardKeyDrop:
		return "key-drop"
	case DiscardRetry:
		return "retry"
	case DiscardZeroRTTRejected:
		return "0rtt-rejected"
	case DiscardPTOProbe:
		return "pto-probe"
	case DiscardMigration:
		return "migration"
	default:
		return "unknown"
	}
}

// Demand is a connection's level-triggered eligible demand: per class,
// whether it has work it could put in a packet now if admitted.
type Demand struct{ Eligible [NumSendClasses]bool }

// Permit is the answer to Admit. A permit reserves nothing: it is a value
// owned by one build operation, and all state changes at OnSent.
//
// The packet builder executes Turn, Fill and MaxBytes only for a PathSender
// that is a ClassScheduler. For any other PathSender it fills a permitted
// packet as it would any other, up to the connection's packet size, so such a
// PathSender must admit whole packets of any class.
type Permit struct {
	OK   bool
	Turn SendClass
	// Fill lists bytes of other classes that may fill space left over after
	// the turn's class. All zero means the turn's class only.
	Fill     [NumSendClasses]ByteCount
	MaxBytes ByteCount
	// RetryAt is when a refusal for pacing or precedence may clear. It is zero
	// when the refusal is window-limited.
	RetryAt monotime.Time
}

// ClassScheduler is a PathSender that arbitrates between send classes and
// whose permits the packet builder executes. When SchedulesClasses reports
// true at installation, every packet built under a permit:
//
//   - is at most MaxBytes long;
//   - carries bytes of class Turn first, then, in the order CONTROL,
//     INTERACTIVE, BULK, bytes of each other class up to its Fill allowance,
//     and otherwise goes out short;
//   - carries exempt obligations (an ACK, PATH_RESPONSE, a liveness PING)
//     whatever its turn.
//
// Stream bytes are classed by SendStream.WriteClass and SetBoost, DATAGRAM
// frames are INTERACTIVE, and control frames, their retransmissions, window
// updates and post-handshake crypto data are CONTROL. Demand is reported per
// class, and SentPacket.ClassBytes reports the bytes actually built by class,
// with the packet overhead charged to the turn. A datagram that does not fit
// a class's allowance stays queued. PTO probes and MTU probes are built
// without regard to the turn; an MTU probe's bytes are INTERACTIVE.
//
// A permit's MaxBytes must be at least MinClassedPermit. A smaller permit
// is treated as a window refusal: the connection sends only its exempt
// obligations, due ACKs among them, until a usable permit comes.
type ClassScheduler interface {
	PathSender
	SchedulesClasses() bool
}

// MinClassedPermit is the smallest packet a class-scheduled permit may
// allow: room for the header, the AEAD tag, a truncated ACK frame and some
// class work, whatever the connection ID and packet number lengths.
const MinClassedPermit ByteCount = 128

// SentPacket describes a packet as it was actually built and registered.
type SentPacket struct {
	Space        PacketSpace
	Number       PacketNumber
	Bytes        ByteCount
	AckEliciting bool // as actually built
	// InFlightCounted says the packet is included in this connection's bytes
	// in flight.
	InFlightCounted bool
	// Exempt says the packet was built without a permit.
	Exempt      bool
	Kind        PacketKind
	ClassBytes  [NumSendClasses]ByteCount
	HasDatagram bool
	// InFlight is this connection's bytes in flight after this packet.
	InFlight ByteCount
	Time     monotime.Time
	// Grant is the ID of the verification grant the packet was built under,
	// or zero.
	Grant uint64
}

// PacketRef names one packet.
type PacketRef struct {
	Space  PacketSpace
	Number PacketNumber
	Bytes  ByteCount
}

// AckEvent is the outcome of one received ACK frame or one loss-timer firing.
//
// Acked lists the newly acknowledged packets that were counted in bytes in
// flight, Lost the packets newly declared lost that were, and Spurious the
// packets that had been reported lost and are now acknowledged.
type AckEvent struct {
	Time          monotime.Time
	InFlight      ByteCount     // after this event
	RTTSample     time.Duration // zero when none
	ECNCongestion bool
	Acked, Lost   []PacketRef
	Spurious      []PacketRef
}

// PathSender is a controller that receives the connection's packet events
// exactly, once each, on the connection's run loop. A connection whose
// controller implements PathSender asks it for admission before every
// ordinary packet and never calls the per-packet methods of
// CongestionControl (OnPacketSent, OnPacketAcked, OnCongestionEvent,
// OnCongestionEventEx, CanSend, HasPacingBudget, TimeUntilSend).
//
// The slices in events are only valid during the call.
type PathSender interface {
	CongestionControl
	// OnAttach is the first call. inFlight is the connection's flight at
	// installation; wake asks the connection to try sending again and may be
	// called from any goroutine.
	OnAttach(now monotime.Time, inFlight, maxPacket ByteCount, wake func())
	OnDemand(d Demand)
	Admit(now monotime.Time, maxBytes ByteCount) Permit
	OnSent(p SentPacket)
	OnAckEvent(e AckEvent)
	// OnDiscarded reports packets that left the flight without a fate. all
	// says every outstanding packet of the space was discarded.
	OnDiscarded(now monotime.Time, inFlight ByteCount, refs []PacketRef, all bool, reason DiscardReason)
	// OnPathMigrated is called after the connection has recorded its new
	// addresses. The controller stays installed.
	OnPathMigrated(now monotime.Time, oldLocal, newLocal, oldRemote, newRemote net.Addr)
	OnDetach(now monotime.Time)
}

// VerificationGrant is the one reservation of the design: an admission
// opportunity for a recovery transaction's verification exchange, issued to
// one connection at a time, that is gated by neither the window nor the
// balance. It covers the stream bytes [Start, End) of the stream it is bound
// to (see Conn.BindVerificationGrant), including their retransmissions, and
// the QUIC packets that carry them, up to Budget packet bytes, until Expiry.
// Packets built under it are reported with its ID and settled at OnSent like
// any other. Binding another grant to the connection reissues: the earlier
// one covers nothing from then on.
type VerificationGrant struct {
	ID         uint64 // nonzero
	Start, End ByteCount
	Budget     ByteCount
	Expiry     monotime.Time
}
