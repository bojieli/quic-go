package quic

import (
	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/ackhandler"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
)

// classedFrameSource is the framer's class-aware interface. A frame source
// that does not implement it (a test double) is built from as before.
type classedFrameSource interface {
	AppendClass(_ []ackhandler.Frame, _ []ackhandler.StreamFrame, _ congestion.SendClass, maxLen protocol.ByteCount, last bool, _ monotime.Time, _ protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount)
}

var _ classedFrameSource = &framer{}

// classOrder is the order in which classes fill a packet after its turn.
var classOrder = [...]congestion.SendClass{congestion.ClassControl, congestion.ClassInteractive, congestion.ClassBulk}

// minAckPayload is the least payload an ACK is put in under a class permit:
// an ACK frame truncated to its first range, with ECN counts, and a PING fit
// in it, so taking the ACK never makes a packet larger than its permit. A
// smaller permit leaves the ACK for a later packet and still carries what
// fits.
const minAckPayload protocol.ByteCount = 64

// currentClassPermit returns the permit the next packet is built under, if
// the connection schedules classes and holds a permit. A permit of zero bytes
// is returned too: it builds nothing, rather than an unrestricted packet.
func (p *packetPacker) currentClassPermit(onlyAck bool) (congestion.Permit, bool) {
	if onlyAck || p.classPermit == nil {
		return congestion.Permit{}, false
	}
	if _, ok := p.framer.(classedFrameSource); !ok {
		return congestion.Permit{}, false
	}
	permit, ok := p.classPermit()
	if !ok || !permit.OK {
		return congestion.Permit{}, false
	}
	return permit, true
}

// maybeGetClassedPacket builds a 1-RTT payload under a
// class-scheduling permit (congestion.ClassScheduler): exempt obligations,
// then bytes of the permit's turn, then bytes of each class listed in Fill up
// to its allowance. Whatever space is left stays empty. fullPayload is the
// payload a packet of the connection's maximum size would have, which decides
// whether a DATAGRAM can ever be sent; zero means it is not known here.
func (p *packetPacker) maybeGetClassedPacket(maxPayloadSize, fullPayload protocol.ByteCount, permit congestion.Permit, ackAllowed bool, now monotime.Time, v protocol.Version) payload {
	if maxPayloadSize <= 0 {
		return payload{}
	}
	pl := p.composeClassedPacket(maxPayloadSize, fullPayload, permit, ackAllowed && maxPayloadSize >= minAckPayload, now, v)
	if len(pl.frames) == 0 && len(pl.streamFrames) == 0 {
		if pl.ack == nil {
			return payload{}
		}
		ping := &wire.PingFrame{}
		if p.numNonAckElicitingAcks >= protocol.MaxNonAckElicitingAcks && pl.length+ping.Length(v) <= maxPayloadSize {
			pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping})
			pl.length += ping.Length(v)
			p.numNonAckElicitingAcks = 0
		} else {
			p.numNonAckElicitingAcks++
		}
	} else {
		p.numNonAckElicitingAcks = 0
	}
	return pl
}

func (p *packetPacker) composeClassedPacket(maxPayloadSize, fullPayload protocol.ByteCount, permit congestion.Permit, ackAllowed bool, now monotime.Time, v protocol.Version) payload {
	cf := p.framer.(classedFrameSource)
	hasData := p.framer.HasData()
	hasRetransmission := p.retransmissionQueue.HasData(protocol.Encryption1RTT)

	var pl payload
	if ackAllowed {
		// An ACK that is not yet due is taken only if work this permit
		// allows can ride with it.
		early := p.permitHasWork(permit, hasRetransmission, maxPayloadSize, now, v)
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, now, !early); ack != nil {
			ack.Truncate(maxPayloadSize, v)
			pl.ack = ack
			pl.length += ack.Length(v)
		}
	}
	startLen := len(pl.frames)
	// Exempt obligations ride whatever the turn.
	if p.framer.HasExemptData() {
		var n protocol.ByteCount
		pl.frames, n = p.framer.AppendExempt(pl.frames, maxPayloadSize-pl.length, v)
		pl.length += n
	}

	order := make([]congestion.SendClass, 0, len(classOrder))
	if permit.Turn != congestion.ClassExempt && permit.Turn < congestion.NumSendClasses {
		order = append(order, permit.Turn)
	}
	for _, c := range classOrder {
		if c != permit.Turn {
			order = append(order, c)
		}
	}
	for _, class := range order {
		remaining := maxPayloadSize - pl.length
		if remaining <= 0 {
			break
		}
		limit := remaining
		if class != permit.Turn {
			limit = min(limit, protocol.ByteCount(permit.Fill[class]))
		}
		if limit <= 0 {
			continue
		}
		var used protocol.ByteCount
		switch class {
		case congestion.ClassControl:
			if hasRetransmission {
				var n protocol.ByteCount
				pl.frames, n = p.retransmissionQueue.AppendFittingFrames(pl.frames, limit, v)
				used += n
			}
		case congestion.ClassInteractive:
			used += p.appendClassedDatagram(&pl, limit, maxPayloadSize, fullPayload, class == permit.Turn, v)
		}
		if hasData && limit > used {
			// A class that has the rest of the packet may count on being
			// last and use the bytes of the final length field.
			last := limit >= remaining
			if b, ok := p.framer.(interface{ SetBoundSmallScans(bool) }); ok {
				b.SetBoundSmallScans(len(pl.frames) > startLen || len(pl.streamFrames) > 0 || used > 0)
			}
			var n protocol.ByteCount
			pl.frames, pl.streamFrames, n = cf.AppendClass(pl.frames, pl.streamFrames, class, limit-used, last, now, v)
			used += n
		}
		pl.length += used
	}
	if n := len(pl.streamFrames); n > 0 {
		// The last STREAM frame of the packet has no length field.
		last := pl.streamFrames[n-1].Frame
		withLen := last.Length(v)
		last.DataLenPresent = false
		pl.length -= withLen - last.Length(v)
	}
	for i := startLen; i < len(pl.frames); i++ {
		if pl.frames[i].Handler != nil {
			continue
		}
		switch pl.frames[i].Frame.(type) {
		case *wire.PathChallengeFrame, *wire.PathResponseFrame, *wire.DatagramFrame:
		default:
			pl.frames[i].Handler = p.retransmissionQueue.AckHandler(protocol.Encryption1RTT)
		}
	}
	return pl
}

// permitHasWork says whether there is work a permit allows into a packet:
// an exempt obligation, or work of its turn or of a class it lists in Fill.
// maxPayloadSize is the packet's payload budget: the permit's MaxBytes less
// the header and the AEAD tag.
func (p *packetPacker) permitHasWork(permit congestion.Permit, hasRetransmission bool, maxPayloadSize protocol.ByteCount, now monotime.Time, v protocol.Version) bool {
	if p.framer.HasExemptData() {
		return true
	}
	allowed := func(c congestion.SendClass) bool { return c == permit.Turn || permit.Fill[c] > 0 }
	f, ok := p.framer.(interface {
		HasControlData() bool
		StreamDemand(bool) [congestion.NumSendClasses]bool
		connWindowOpen() bool
	})
	if !ok {
		return p.framer.HasData() || hasRetransmission
	}
	if allowed(congestion.ClassControl) && (hasRetransmission || f.HasControlData()) {
		return true
	}
	if allowed(congestion.ClassInteractive) && p.datagramQueue != nil {
		// Only a datagram the packet has room for beside the ACK that
		// would be taken for it, within its fill allowance.
		if d := p.datagramQueue.Peek(); d != nil {
			budget := maxPayloadSize - p.ackFrameLength(now, maxPayloadSize, v)
			if permit.Turn != congestion.ClassInteractive {
				budget = min(budget, protocol.ByteCount(permit.Fill[congestion.ClassInteractive]))
			}
			if d.Length(v) <= budget {
				return true
			}
		}
	}
	streams := f.StreamDemand(f.connWindowOpen())
	for _, c := range classOrder {
		if allowed(c) && streams[c] {
			return true
		}
	}
	return false
}

// ackFrameLength is the length of the 1-RTT ACK frame a packet with
// maxPayloadSize bytes of payload built now would take early, truncated as
// the builder truncates it, without taking it; zero if the ACK source cannot
// say.
func (p *packetPacker) ackFrameLength(now monotime.Time, maxPayloadSize protocol.ByteCount, v protocol.Version) protocol.ByteCount {
	if a, ok := p.acks.(interface {
		AckFrameLength(monotime.Time, protocol.ByteCount, protocol.Version) protocol.ByteCount
	}); ok {
		return a.AckFrameLength(now, maxPayloadSize, v)
	}
	return 0
}

// appendClassedDatagram adds the queued DATAGRAM frame if it fits within
// limit. A frame that cannot fit a packet of the connection's maximum size
// is discarded, as by the ordinary builder. One that could stays queued,
// whatever kept it out of this packet -- a Fill allowance, a short permit, or
// an ACK or exempt frame taking the room -- and goes in a packet with room.
// Unlike the ordinary builder, it is never dropped for being crowded out.
func (p *packetPacker) appendClassedDatagram(pl *payload, limit, maxPayloadSize, fullPayload protocol.ByteCount, turn bool, v protocol.Version) protocol.ByteCount {
	if p.datagramQueue == nil {
		return 0
	}
	f := p.datagramQueue.Peek()
	for f != nil && fullPayload > 0 && f.Length(v) > fullPayload {
		// It would not fit a packet that carried nothing else; the next
		// one may.
		if p.datagramQueue.logger != nil && p.datagramQueue.logger.Debug() {
			p.datagramQueue.logger.Debugf("Discarded DATAGRAM frame (%d bytes payload)", f.Length(v))
		}
		p.datagramQueue.PopDiscarded()
		p.peekTimes = 0
		f = p.datagramQueue.Peek()
	}
	if f == nil {
		return 0
	}
	size := f.Length(v)
	if size <= limit {
		pl.frames = append(pl.frames, ackhandler.Frame{Frame: f})
		p.datagramQueue.Pop()
		p.peekTimes = 0
		return size
	}
	if fullPayload == 0 {
		return 0
	}
	// It fits a packet of this connection: it stays queued, however many
	// turns an ACK or exempt frame crowds it out of, and goes when one has
	// room.
	return 0
}
