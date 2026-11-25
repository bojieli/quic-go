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
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, now, !hasRetransmission && !hasData); ack != nil {
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
				for {
					f := p.retransmissionQueue.GetFrame(protocol.Encryption1RTT, limit-used, v)
					if f == nil {
						break
					}
					pl.frames = append(pl.frames, ackhandler.Frame{Frame: f, Handler: p.retransmissionQueue.AckHandler(protocol.Encryption1RTT)})
					used += f.Length(v)
				}
			}
		case congestion.ClassInteractive:
			used += p.appendClassedDatagram(&pl, limit, maxPayloadSize, fullPayload, class == permit.Turn, v)
		}
		if hasData && limit > used {
			// A class that has the rest of the packet may count on being
			// last and use the bytes of the final length field.
			last := limit >= remaining
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

// appendClassedDatagram adds the queued DATAGRAM frame if it fits within
// limit. A frame that cannot fit a packet of the connection's maximum size
// is discarded, as by the ordinary builder. One that could stays queued:
// when its class has the turn of a full-size packet and an ACK or exempt
// frame took the room, the ordinary builder's retry count applies; when its
// class only fills leftover space, or the permit is short, nothing is
// counted, so it waits for a turn with room instead of being dropped.
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
	if !turn || maxPayloadSize < fullPayload || size <= maxPayloadSize-pl.length {
		// Only the class's allowance or the permit, not the packet, was too
		// small.
		return 0
	}
	p.peekTimes++
	if p.peekTimes > DatagramFrameMaxPeekTimes {
		if p.datagramQueue.logger != nil && p.datagramQueue.logger.Debug() {
			p.datagramQueue.logger.Debugf("Discarded DATAGRAM frame (%d bytes payload)", size)
		}
		p.datagramQueue.PopDiscarded()
		p.peekTimes = 0
	}
	return 0
}
