package quic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/ackhandler"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// framerSender files streams with a real framer.
type framerSender struct{ f *framer }

func (s framerSender) onHasConnectionData() {}
func (s framerSender) onHasStreamData(id protocol.StreamID, str *SendStream) {
	s.f.AddActiveStream(id, str)
}
func (s framerSender) onHasStreamControlFrame(id protocol.StreamID, str streamControlFrameGetter) {
	s.f.AddStreamWithControlFrames(id, str)
}
func (s framerSender) onStreamCompleted(protocol.StreamID) {}

type noAcks struct{}

func (noAcks) GetAckFrame(protocol.EncryptionLevel, monotime.Time, bool) *wire.AckFrame { return nil }

// builderHarness is the real 1-RTT builder -- packer, framer, send streams,
// datagram queue -- without a connection around it.
type builderHarness struct {
	framer *framer
	dq     *datagramQueue
	packer *packetPacker
}

func newBuilderHarness(classed bool) *builderHarness {
	connFC := newConnectionFlowController(protocol.MaxByteCount, protocol.MaxByteCount, nil, utils.NewRTTStats(), utils.DefaultLogger)
	connFC.UpdateSendWindow(protocol.MaxByteCount)
	h := &builderHarness{
		framer: newFramer(connFC),
		dq:     newDatagramQueue(func() {}, utils.DefaultLogger),
	}
	h.framer.SetClassed(classed)
	h.packer = &packetPacker{
		framer:              h.framer,
		acks:                noAcks{},
		datagramQueue:       h.dq,
		retransmissionQueue: newRetransmissionQueue(),
	}
	return h
}

func (h *builderHarness) stream(id protocol.StreamID) *SendStream {
	return newSendStream(context.Background(), id, framerSender{h.framer}, newTestStreamFlowControllerWithSendWindow(id, protocol.MaxByteCount), false)
}

func (h *builderHarness) datagram(n int, b byte) {
	if err := h.dq.Add(&wire.DatagramFrame{DataLenPresent: true, Data: bytes.Repeat([]byte{b}, n)}); err != nil {
		panic(err)
	}
}

// classBytes is what a payload carries per class, as the sent packet
// handler of a class-scheduled connection counts it.
func classBytes(pl payload) [congestion.NumSendClasses]protocol.ByteCount {
	var c [congestion.NumSendClasses]protocol.ByteCount
	for _, f := range pl.streamFrames {
		c[frameClass(f.Frame)] += f.Frame.Length(protocol.Version1)
	}
	for _, f := range pl.frames {
		switch f.Frame.(type) {
		case *wire.DatagramFrame:
			c[congestion.ClassInteractive] += f.Frame.Length(protocol.Version1)
		case *wire.PingFrame, *wire.PathChallengeFrame, *wire.PathResponseFrame:
			c[congestion.ClassExempt] += f.Frame.Length(protocol.Version1)
		default:
			c[congestion.ClassControl] += f.Frame.Length(protocol.Version1)
		}
	}
	return c
}

const testPayload protocol.ByteCount = 1200

// A permit with an empty Fill builds a packet of its turn's class only, even
// with every other class queued; Fill admits each other class up to its
// allowance; whatever is left goes out empty.
func TestClassedBuilderExecutesThePermit(t *testing.T) {
	h := newBuilderHarness(true)
	control, interactive, bulk := h.stream(4), h.stream(8), h.stream(12)
	writeClassBuffered(t, control, 1000, congestion.ClassControl)
	writeClassBuffered(t, interactive, 1000, congestion.ClassInteractive)
	writeClassBuffered(t, bulk, 1000, congestion.ClassBulk)
	h.datagram(300, 1)
	h.framer.QueueControlFrame(&wire.MaxDataFrame{MaximumData: 1 << 20})

	pl := h.packer.composeClassedPacket(testPayload, testPayload, congestion.Permit{OK: true, Turn: congestion.ClassBulk, MaxBytes: 1252}, true, monotime.Now(), protocol.Version1)
	c := classBytes(pl)
	require.Positive(t, c[congestion.ClassBulk])
	require.Zero(t, c[congestion.ClassControl], "empty Fill: no CONTROL rides along")
	require.Zero(t, c[congestion.ClassInteractive], "empty Fill: no datagram or INTERACTIVE stream rides along")
	require.NotNil(t, h.dq.Peek(), "the datagram stays queued")

	writeClassBuffered(t, bulk, 1000, congestion.ClassBulk)
	pl = h.packer.composeClassedPacket(testPayload, testPayload, congestion.Permit{OK: true, Turn: congestion.ClassBulk, MaxBytes: 1252,
		Fill: [congestion.NumSendClasses]congestion.ByteCount{congestion.ClassControl: 200}}, true, monotime.Now(), protocol.Version1)
	c = classBytes(pl)
	require.Positive(t, c[congestion.ClassBulk])
	require.Positive(t, c[congestion.ClassControl])
	require.LessOrEqual(t, c[congestion.ClassControl], protocol.ByteCount(200+8), "CONTROL fills up to its allowance")
	require.Zero(t, c[congestion.ClassInteractive])

	pl = h.packer.composeClassedPacket(testPayload, testPayload, congestion.Permit{OK: true, Turn: congestion.ClassInteractive, MaxBytes: 1252}, true, monotime.Now(), protocol.Version1)
	require.IsType(t, &wire.DatagramFrame{}, pl.frames[0].Frame, "the turn's class comes first, and the datagram first within INTERACTIVE")
	c = classBytes(pl)
	require.Zero(t, c[congestion.ClassControl])
	require.Zero(t, c[congestion.ClassBulk])
	require.LessOrEqual(t, pl.length, testPayload)
}

// A datagram that only exceeds its class's Fill allowance stays queued; it
// goes when its class has the turn. One that cannot fit any packet is
// discarded, as by the ordinary builder.
func TestClassedBuilderKeepsADatagramLargerThanItsAllowance(t *testing.T) {
	h := newBuilderHarness(true)
	bulk := h.stream(4)
	writeClassBuffered(t, bulk, 1400, congestion.ClassBulk)
	h.datagram(900, 7)
	fill := [congestion.NumSendClasses]congestion.ByteCount{congestion.ClassInteractive: 300}
	for range 3 * DatagramFrameMaxPeekTimes {
		pl := h.packer.composeClassedPacket(testPayload, testPayload, congestion.Permit{OK: true, Turn: congestion.ClassBulk, Fill: fill, MaxBytes: 1252}, true, monotime.Now(), protocol.Version1)
		require.Zero(t, classBytes(pl)[congestion.ClassInteractive])
		require.NotNil(t, h.dq.Peek(), "a datagram over its allowance is not discarded")
		writeClassBuffered(t, bulk, 1000, congestion.ClassBulk)
	}
	pl := h.packer.composeClassedPacket(testPayload, testPayload, congestion.Permit{OK: true, Turn: congestion.ClassInteractive, MaxBytes: 1252}, true, monotime.Now(), protocol.Version1)
	require.Equal(t, (&wire.DatagramFrame{DataLenPresent: true, Data: make([]byte, 900)}).Length(protocol.Version1), classBytes(pl)[congestion.ClassInteractive])
	require.Nil(t, h.dq.Peek())

	h.datagram(int(testPayload), 8) // larger than any payload of this size
	pl = h.packer.composeClassedPacket(testPayload, testPayload, congestion.Permit{OK: true, Turn: congestion.ClassInteractive, MaxBytes: 1252}, true, monotime.Now(), protocol.Version1)
	require.Zero(t, classBytes(pl)[congestion.ClassInteractive])
	require.Nil(t, h.dq.Peek(), "a datagram that fits no packet is discarded")
}

// frameLog renders a payload's frames for comparison.
func frameLog(pl payload) string {
	var b bytes.Buffer
	for _, f := range pl.frames {
		switch fr := f.Frame.(type) {
		case *wire.DatagramFrame:
			fmt.Fprintf(&b, "DATAGRAM(%x) ", fr.Data)
		default:
			fmt.Fprintf(&b, "%T%+v ", fr, fr)
		}
	}
	for _, f := range pl.streamFrames {
		fmt.Fprintf(&b, "STREAM(%d,%d,%d,%v,%v,%x) ", f.Frame.StreamID, f.Frame.Offset, f.Frame.DataLen(), f.Frame.Fin, f.Frame.DataLenPresent, f.Frame.Data)
	}
	fmt.Fprintf(&b, "len=%d", pl.length)
	return b.String()
}

// v1 safety: on a connection that does not schedule classes, class tags and
// boost change nothing the builder does. The same workload, written once with
// Write and once with WriteClass and boost toggles, packs byte-identical
// packets, and no frame carries a class.
func TestUnclassedBuilderIsUnchangedByClassTags(t *testing.T) {
	run := func(tagged bool) []string {
		h := newBuilderHarness(false)
		streams := []*SendStream{h.stream(4), h.stream(8), h.stream(12)}
		classes := []congestion.SendClass{congestion.ClassControl, congestion.ClassInteractive, congestion.ClassBulk}
		write := func(i, n int, b byte) {
			p := bytes.Repeat([]byte{b}, n)
			var err error
			if tagged {
				_, err = streams[i].WriteClass(p, classes[(i+int(b))%3])
			} else {
				_, err = streams[i].Write(p)
			}
			require.NoError(t, err)
		}
		var log []string
		pack := func(size protocol.ByteCount) {
			pl := h.packer.composeNextPacket(size, false, true, monotime.Now(), protocol.Version1)
			for _, f := range pl.streamFrames {
				require.Zero(t, f.Frame.Class, "no class is recorded in a frame on an unclassed connection")
			}
			log = append(log, frameLog(pl))
			// Lose every third packet's stream frames to exercise retransmission.
			if len(log)%3 == 0 {
				for _, f := range pl.streamFrames {
					f.Handler.OnLost(f.Frame)
				}
			}
		}
		for round := range 12 {
			b := byte(round)
			write(round%3, 300+37*round, b)
			if tagged && round%4 == 1 {
				streams[round%3].SetBoost(true)
			}
			if round%5 == 2 {
				h.datagram(200+round, b)
			}
			if round%4 == 0 {
				h.framer.QueueControlFrame(&wire.MaxStreamsFrame{MaxStreamNum: protocol.StreamNum(round + 1)})
			}
			pack(protocol.ByteCount(400 + 61*round))
			if tagged && round%4 == 3 {
				streams[(round+2)%3].SetBoost(false)
			}
			pack(1200)
		}
		for range 20 {
			pack(1200)
		}
		return log
	}
	plain, tagged := run(false), run(true)
	require.Equal(t, plain, tagged)
	// The same workload on the builder before class scheduling existed
	// (queqiao-v0.61 at 61c2dcc1) packed exactly these packets.
	require.Equal(t, unclassedBuilderGolden, fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(plain)))))
}

const unclassedBuilderGolden = "e367ad3b125c9a8f212017899c560a43817abf8cd605af50f03973138c6c6a23"

// A build outside the class-scheduled path -- a PTO probe uses the ordinary
// builder -- still finds a class-scheduled connection's streams, in priority
// order, and leaves the packet's last STREAM frame without a length.
func TestOrdinaryBuildOnAClassedFramerServesEveryClass(t *testing.T) {
	h := newBuilderHarness(true)
	bulk, control := h.stream(4), h.stream(8)
	writeClassBuffered(t, bulk, 300, congestion.ClassBulk)
	writeClassBuffered(t, control, 300, congestion.ClassControl)
	pl := h.packer.composeNextPacket(testPayload, false, true, monotime.Now(), protocol.Version1)
	require.Len(t, pl.streamFrames, 2)
	require.Equal(t, control.StreamID(), pl.streamFrames[0].Frame.StreamID, "CONTROL first")
	require.True(t, pl.streamFrames[0].Frame.DataLenPresent)
	require.False(t, pl.streamFrames[1].Frame.DataLenPresent)
	var sum protocol.ByteCount
	for _, f := range pl.streamFrames {
		sum += f.Frame.Length(protocol.Version1)
	}
	require.Equal(t, sum, pl.length)
}

// Small permits still move a stream; a permit too small for a minimal packet
// builds nothing rather than an oversized packet or an unrestricted one.
func TestClassedBuilderUnderSmallPermits(t *testing.T) {
	h := newBuilderHarness(true)
	bulk := h.stream(4)
	writeClassBuffered(t, bulk, 1000, congestion.ClassBulk)
	permit := congestion.Permit{OK: true, Turn: congestion.ClassBulk, MaxBytes: 100}
	pl := h.packer.maybeGetClassedPacket(70, 1200, permit, true, monotime.Now(), protocol.Version1)
	require.Len(t, pl.streamFrames, 1, "a 70-byte payload carries a STREAM frame")
	require.LessOrEqual(t, pl.length, protocol.ByteCount(70))
	require.Empty(t, h.packer.maybeGetClassedPacket(minClassedPayload-1, 1200, permit, true, monotime.Now(), protocol.Version1).streamFrames)
	require.Empty(t, h.packer.maybeGetClassedPacket(0, 1200, congestion.Permit{OK: true, Turn: congestion.ClassBulk}, true, monotime.Now(), protocol.Version1).streamFrames)
}

// A datagram that fits the connection's packets but not a short permit stays
// queued however many short INTERACTIVE turns come first.
func TestClassedBuilderKeepsADatagramAcrossShortPermits(t *testing.T) {
	h := newBuilderHarness(true)
	h.datagram(900, 3)
	permit := congestion.Permit{OK: true, Turn: congestion.ClassInteractive, MaxBytes: 600}
	for range 3 * DatagramFrameMaxPeekTimes {
		pl := h.packer.composeClassedPacket(500, testPayload, permit, true, monotime.Now(), protocol.Version1)
		require.Empty(t, pl.frames)
		require.NotNil(t, h.dq.Peek())
	}
}

// A STREAM frame that fills a class's allowance keeps its length field when
// another class follows, and stays within the allowance on the wire.
func TestClassedBuilderKeepsFillFramesWithinTheirAllowance(t *testing.T) {
	h := newBuilderHarness(true)
	control, bulk := h.stream(4), h.stream(8)
	writeClassBuffered(t, control, 1000, congestion.ClassControl)
	writeClassBuffered(t, bulk, 1000, congestion.ClassBulk)
	const allowance = 300
	// BULK has the turn; CONTROL fills first (priority order) up to its
	// allowance, and BULK's frame follows it.
	pl := h.packer.composeClassedPacket(testPayload, testPayload, congestion.Permit{OK: true, Turn: congestion.ClassBulk, MaxBytes: 1252,
		Fill: [congestion.NumSendClasses]congestion.ByteCount{congestion.ClassControl: allowance}}, true, monotime.Now(), protocol.Version1)
	var controlWire protocol.ByteCount
	for _, f := range pl.streamFrames {
		if f.Frame.StreamID == control.StreamID() {
			controlWire += f.Frame.Length(protocol.Version1)
		}
	}
	require.Len(t, pl.streamFrames, 2)
	require.Positive(t, controlWire)
	require.LessOrEqual(t, controlWire, protocol.ByteCount(allowance))
	require.LessOrEqual(t, pl.length, testPayload)
}

// Flow-control notifications are CONTROL work: a BULK-only packet leaves a
// stream's STREAM_DATA_BLOCKED for a CONTROL pass.
func TestClassedBuilderLeavesBlockedFramesToControl(t *testing.T) {
	h := newBuilderHarness(true)
	str := newSendStream(context.Background(), 4, framerSender{h.framer}, newTestStreamFlowControllerWithSendWindow(4, 100), false)
	writeClassBuffered(t, str, 100, congestion.ClassBulk)
	pl := h.packer.composeClassedPacket(testPayload, testPayload, congestion.Permit{OK: true, Turn: congestion.ClassBulk, MaxBytes: 1252}, true, monotime.Now(), protocol.Version1)
	require.Len(t, pl.streamFrames, 1)
	for _, f := range pl.frames {
		require.NotEqual(t, "*wire.StreamDataBlockedFrame", fmt.Sprintf("%T", f.Frame), "a BULK-only packet carried a CONTROL frame")
	}
	require.True(t, h.framer.HasControlData(), "the notification waits for a CONTROL pass")
	pl = h.packer.composeClassedPacket(testPayload, testPayload, congestion.Permit{OK: true, Turn: congestion.ClassControl, MaxBytes: 1252}, true, monotime.Now(), protocol.Version1)
	require.IsType(t, &wire.StreamDataBlockedFrame{}, pl.frames[0].Frame)
}

// One PATH_RESPONSE per packet, as in the ordinary builder: the CONTROL pass
// does not take exempt obligations a second time.
func TestClassedBuilderPacksOnePathResponse(t *testing.T) {
	h := newBuilderHarness(true)
	h.framer.QueueControlFrame(&wire.PathResponseFrame{Data: [8]byte{1}})
	h.framer.QueueControlFrame(&wire.PathResponseFrame{Data: [8]byte{2}})
	pl := h.packer.composeClassedPacket(testPayload, testPayload, congestion.Permit{OK: true, Turn: congestion.ClassControl, MaxBytes: 1252}, true, monotime.Now(), protocol.Version1)
	var n int
	for _, f := range pl.frames {
		if _, ok := f.Frame.(*wire.PathResponseFrame); ok {
			n++
		}
	}
	require.Equal(t, 1, n)
}

// fakeClassedStream has endless data of a settable class.
type fakeClassedStream struct {
	id    protocol.StreamID
	class congestion.SendClass
}

func (s *fakeClassedStream) popStreamFrame(protocol.ByteCount, protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
	panic("ordinary pop on a classed framer")
}
func (s *fakeClassedStream) streamClass() congestion.SendClass { return s.class }
func (s *fakeClassedStream) sendableClass(bool) (congestion.SendClass, bool) {
	return s.class, true
}
func (s *fakeClassedStream) popClassedStreamFrame(_ protocol.ByteCount, want congestion.SendClass, _ protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool, congestion.SendClass, congestion.SendClass) {
	if want != s.class {
		return ackhandler.StreamFrame{}, nil, true, s.class, s.class
	}
	f := &wire.StreamFrame{StreamID: s.id, Data: make([]byte, 10), DataLenPresent: true}
	return ackhandler.StreamFrame{Frame: f}, nil, true, s.class, s.class
}

// A stream that leaves a class and comes back before its old ring entry is
// reached is still served once per round.
func TestClassedFramerServesARefiledStreamOncePerRound(t *testing.T) {
	h := newBuilderHarness(true)
	x := &fakeClassedStream{id: 4, class: congestion.ClassBulk}
	y := &fakeClassedStream{id: 8, class: congestion.ClassBulk}
	h.framer.AddActiveStream(x.id, x)
	h.framer.AddActiveStream(y.id, y)
	for range 3 {
		x.class = congestion.ClassControl
		h.framer.AddActiveStream(x.id, x)
		x.class = congestion.ClassBulk
		h.framer.AddActiveStream(x.id, x)
	}
	_, sfs, _ := h.framer.AppendClass(nil, nil, congestion.ClassBulk, 1200, true, monotime.Now(), protocol.Version1)
	served := map[protocol.StreamID]int{}
	for _, f := range sfs {
		served[f.Frame.StreamID]++
	}
	require.Equal(t, map[protocol.StreamID]int{4: 1, 8: 1}, served, "one turn each per round")
}
