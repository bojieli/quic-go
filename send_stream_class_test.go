package quic

import (
	"context"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/ackhandler"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func newClassTestStream(t *testing.T, id protocol.StreamID) *SendStream {
	t.Helper()
	mockCtrl := gomock.NewController(t)
	fc := newTestStreamFlowControllerWithSendWindow(1<<20, protocol.MaxByteCount)
	sender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), id, sender, fc, false)
	sender.EXPECT().onHasStreamData(id, str).AnyTimes()
	sender.EXPECT().onStreamCompleted(gomock.Any()).AnyTimes()
	sender.EXPECT().onHasStreamControlFrame(id, gomock.Any()).AnyTimes()
	return str
}

// writeClassBuffered writes a short write, which the stream buffers and
// returns from at once.
func writeClassBuffered(t *testing.T, str *SendStream, n int, class congestion.SendClass) {
	t.Helper()
	written, err := str.WriteClass(make([]byte, n), class)
	require.NoError(t, err)
	require.Equal(t, n, written)
}

func popClassed(t *testing.T, str *SendStream, maxBytes protocol.ByteCount) (ackhandler.StreamFrame, congestion.SendClass, congestion.SendClass) {
	t.Helper()
	f, _, _, served, next := str.popClassedStreamFrame(maxBytes, str.streamClass(), protocol.Version1)
	require.NotNil(t, f.Frame)
	return f, served, next
}

// Bytes are served at the class they were written with; bytes ahead of a
// CONTROL byte go with it, and a frame never mixes bytes served at different
// classes.
func TestSendStreamServesBytesByClass(t *testing.T) {
	str := newClassTestStream(t, 4)
	require.Equal(t, congestion.ClassBulk, str.streamClass(), "an untagged stream is BULK")

	writeClassBuffered(t, str, 100, congestion.ClassInteractive)
	writeClassBuffered(t, str, 50, congestion.ClassControl)
	writeClassBuffered(t, str, 200, congestion.ClassBulk)
	require.Equal(t, congestion.ClassControl, str.streamClass())

	f, served, next := popClassed(t, str, 1200)
	require.Equal(t, congestion.ClassControl, served)
	require.Equal(t, protocol.ByteCount(0), f.Frame.Offset)
	require.Equal(t, protocol.ByteCount(150), f.Frame.DataLen(), "the INTERACTIVE bytes ahead of the CONTROL frame go with it, and no further")
	require.Equal(t, uint8(congestion.ClassControl), f.Frame.Class)
	require.Equal(t, congestion.ClassBulk, next)

	f2, served, _ := popClassed(t, str, 1200)
	require.Equal(t, congestion.ClassBulk, served)
	require.Equal(t, protocol.ByteCount(150), f2.Frame.Offset)
	require.Equal(t, protocol.ByteCount(200), f2.Frame.DataLen())

	// A lost CONTROL frame is CONTROL again until it is retransmitted.
	f.Handler.OnLost(f.Frame)
	require.Equal(t, congestion.ClassControl, str.streamClass())
	r, served, _ := popClassed(t, str, 1200)
	require.Equal(t, congestion.ClassControl, served)
	require.Equal(t, protocol.ByteCount(0), r.Frame.Offset)
	// A lost BULK frame is BULK.
	f2.Handler.OnLost(f2.Frame)
	require.Equal(t, congestion.ClassBulk, str.streamClass())
}

// Boost covers what the stream holds and what it accepts while boosted;
// turning it off affects only bytes accepted later.
func TestSendStreamBoost(t *testing.T) {
	str := newClassTestStream(t, 8)
	writeClassBuffered(t, str, 600, congestion.ClassBulk)
	require.Equal(t, congestion.ClassBulk, str.streamClass())

	str.SetBoost(true)
	require.Equal(t, congestion.ClassControl, str.streamClass(), "a buffered tail is boosted")
	f, served, _ := popClassed(t, str, 200)
	require.Equal(t, congestion.ClassControl, served)
	writeClassBuffered(t, str, 100, congestion.ClassBulk) // accepted while boosted

	// A queued retransmission held while boosted stays CONTROL.
	f.Frame.Class = uint8(congestion.ClassBulk)
	f.Handler.OnLost(f.Frame)
	str.SetBoost(false)
	require.Equal(t, congestion.ClassControl, str.streamClass(), "what was held while boosted stays CONTROL")
	writeClassBuffered(t, str, 300, congestion.ClassBulk) // accepted after

	var controlBytes, bulkBytes protocol.ByteCount
	for {
		sf, _, _, served, _ := str.popClassedStreamFrame(1200, str.streamClass(), protocol.Version1)
		if sf.Frame == nil {
			break
		}
		switch served {
		case congestion.ClassControl:
			require.Zero(t, bulkBytes, "CONTROL bytes are served before the BULK bytes behind them")
			controlBytes += sf.Frame.DataLen()
		case congestion.ClassBulk:
			bulkBytes += sf.Frame.DataLen()
		}
	}
	require.Equal(t, protocol.ByteCount(600+100), controlBytes, "the retransmission, the boosted tail and the write accepted while boosted")
	require.Equal(t, protocol.ByteCount(300), bulkBytes, "only bytes accepted after the boost ended are BULK")
}

// A stream that is never classed keeps no class state and its frames carry
// none, so the ordinary builder's accounting is untouched.
func TestSendStreamUnclassedKeepsNoClassState(t *testing.T) {
	str := newClassTestStream(t, 12)
	_, err := str.Write(make([]byte, 300))
	require.NoError(t, err)
	require.False(t, str.classTagged)
	require.Empty(t, str.classSegs)
	f, _, _ := str.popStreamFrame(1200, protocol.Version1)
	require.Zero(t, f.Frame.Class)
}

// New bytes sent under a verification grant carry their class, so a
// retransmission keeps it.
func TestGrantedFramesCarryTheirClass(t *testing.T) {
	str := newClassTestStream(t, 16)
	writeClassBuffered(t, str, 100, congestion.ClassInteractive)
	writeClassBuffered(t, str, 100, congestion.ClassBulk)
	f, _ := str.popGrantedStreamFrame(1200, 0, 1000, true, protocol.Version1)
	require.NotNil(t, f.Frame)
	require.Equal(t, protocol.ByteCount(100), f.Frame.DataLen(), "a granted frame does not mix classes")
	require.Equal(t, uint8(congestion.ClassInteractive), f.Frame.Class)
	f.Handler.OnLost(f.Frame)
	require.Equal(t, congestion.ClassInteractive, str.streamClass())
}

// A classed write that times out before any of its bytes are accepted leaves
// the stream served at the class of what it still holds, and re-files it.
func TestShortClassedWriteRestoresTheStreamsClass(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	fc := newTestStreamFlowControllerWithSendWindow(1<<20, protocol.MaxByteCount)
	sender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), 20, sender, fc, false)
	var notified int
	sender.EXPECT().onHasStreamData(protocol.StreamID(20), str).Do(func(protocol.StreamID, *SendStream) { notified++ }).AnyTimes()
	writeClassBuffered(t, str, 1000, congestion.ClassBulk) // buffered tail
	require.NoError(t, str.SetWriteDeadline(time.Now().Add(20*time.Millisecond)))
	// Larger than the buffer, so it blocks, and nothing is popped.
	_, err := str.WriteClass(make([]byte, 4000), congestion.ClassControl)
	require.Error(t, err)
	require.Equal(t, congestion.ClassBulk, str.streamClass())
	require.GreaterOrEqual(t, notified, 3, "buffered write, blocked write, and the re-file on its return")
}

// A retransmission sent under a grant while the stream is boosted is charged
// to CONTROL, like one sent by the ordinary classed path.
func TestGrantedRetransmissionIsChargedAtTheBoostedClass(t *testing.T) {
	str := newClassTestStream(t, 24)
	writeClassBuffered(t, str, 100, congestion.ClassBulk)
	f, _, _ := popClassed(t, str, 1200)
	f.Handler.OnLost(f.Frame)
	str.SetBoost(true)
	r, _ := str.popGrantedStreamFrame(1200, 0, 1000, true, protocol.Version1)
	require.NotNil(t, r.Frame)
	require.Equal(t, uint8(congestion.ClassControl), r.Frame.Class)
}

// Item 4: granted new data is charged to the stream's effective class -- here
// CONTROL, because a CONTROL retransmission outside the grant is queued.
func TestGrantedNewDataIsChargedAtTheEffectiveClass(t *testing.T) {
	str := newClassTestStream(t, 28)
	writeClassBuffered(t, str, 50, congestion.ClassControl)
	f, served, _ := popClassed(t, str, 1200)
	require.Equal(t, congestion.ClassControl, served)
	f.Handler.OnLost(f.Frame) // a CONTROL retransmission of [0, 50)
	writeClassBuffered(t, str, 100, congestion.ClassBulk)
	g, _ := str.popGrantedStreamFrame(1200, 50, 150, true, protocol.Version1)
	require.NotNil(t, g.Frame)
	require.Equal(t, protocol.ByteCount(50), g.Frame.Offset)
	require.Equal(t, uint8(congestion.ClassControl), g.Frame.Class, "charged to the class the stream is served at")
}

// Item 5: the count of queued CONTROL retransmissions matches the queue
// through every way the queue changes, so the effective class needs no scan.
func TestControlRetransmissionCountTracksTheQueue(t *testing.T) {
	str := newClassTestStream(t, 32)
	check := func() {
		t.Helper()
		str.mutex.Lock()
		defer str.mutex.Unlock()
		n := 0
		for _, f := range str.retransmissionQueue {
			if f.Class == uint8(congestion.ClassControl) {
				n++
			}
		}
		require.Equal(t, n, str.controlRetx)
	}
	var sent []ackhandler.StreamFrame
	for i := range 6 {
		class := congestion.ClassBulk
		if i%2 == 0 {
			class = congestion.ClassControl
		}
		writeClassBuffered(t, str, 100, class)
		f, _, _ := popClassed(t, str, 1200)
		sent = append(sent, f)
	}
	for _, f := range sent {
		f.Handler.OnLost(f.Frame)
		check()
	}
	str.SetBoost(true)
	str.SetBoost(false)
	check()
	for {
		f, _, more, _, _ := str.popClassedStreamFrame(60, str.streamClass(), protocol.Version1)
		check()
		if f.Frame == nil && !more {
			break
		}
		if f.Frame == nil {
			break
		}
	}
	str.CancelWrite(1)
	check()
}

// A classed write that times out re-files what the stream still has to send
// by its class: a BULK retransmission filed as CONTROL by the write must be
// found again on a BULK turn.
func TestTimedOutClassedWriteRefilesAPendingRetransmission(t *testing.T) {
	h := newBuilderHarness(true)
	str := h.stream(36)
	writeClassBuffered(t, str, 100, congestion.ClassBulk)
	_, sfs, _ := h.framer.AppendClass(nil, nil, congestion.ClassBulk, 1200, true, monotime.Now(), protocol.Version1)
	require.Len(t, sfs, 1)
	sfs[0].Handler.OnLost(sfs[0].Frame) // a BULK retransmission, no new data
	require.NoError(t, str.SetWriteDeadline(time.Now().Add(20*time.Millisecond)))
	_, err := str.WriteClass(make([]byte, 4000), congestion.ClassControl)
	require.Error(t, err)
	require.Equal(t, congestion.ClassBulk, str.streamClass())
	_, sfs, _ = h.framer.AppendClass(nil, nil, congestion.ClassBulk, 1200, true, monotime.Now(), protocol.Version1)
	require.Len(t, sfs, 1, "the retransmission is stranded in the CONTROL ring")
}

// A failed TryWriteAll accepts nothing and records no class: the stream's
// FIN stays at the class of its last accepted bytes.
func TestFailedTryWriteAllRecordsNoClass(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), 40, sender, newTestStreamFlowControllerWithSendWindow(40, 100), false)
	sender.EXPECT().onHasStreamData(gomock.Any(), gomock.Any()).AnyTimes()
	writeClassBuffered(t, str, 100, congestion.ClassInteractive)
	_, _, _ = popClassed(t, str, 1200)
	require.ErrorIs(t, str.TryWriteAll(make([]byte, 10)), ErrWouldBlock)
	require.NoError(t, str.Close())
	require.Equal(t, congestion.ClassInteractive, str.streamClass())
}

// CancelWrite with a reliable boundary re-files what survives: a BULK
// retransmission below it is found on a BULK turn once the CONTROL one
// beyond it is dropped.
func TestCancelWriteRefilesTheReliablePrefix(t *testing.T) {
	h := newBuilderHarness(true)
	str := h.stream(44)
	str.enableResetStreamAt()
	writeClassBuffered(t, str, 100, congestion.ClassBulk)
	_, bulk, _ := h.framer.AppendClass(nil, nil, congestion.ClassBulk, 1200, true, monotime.Now(), protocol.Version1)
	require.Len(t, bulk, 1)   // [0, 100) at BULK
	str.SetReliableBoundary() // at 100
	writeClassBuffered(t, str, 100, congestion.ClassControl)
	_, control, _ := h.framer.AppendClass(nil, nil, congestion.ClassControl, 1200, true, monotime.Now(), protocol.Version1)
	require.Len(t, control, 1) // [100, 200) at CONTROL
	bulk[0].Handler.OnLost(bulk[0].Frame)
	control[0].Handler.OnLost(control[0].Frame)
	require.Equal(t, congestion.ClassControl, str.streamClass())
	str.CancelWrite(1)
	require.Equal(t, congestion.ClassBulk, str.streamClass())
	_, sfs, _ := h.framer.AppendClass(nil, nil, congestion.ClassBulk, 1200, true, monotime.Now(), protocol.Version1)
	require.Len(t, sfs, 1, "the reliable prefix is stranded in the CONTROL ring")
}

// Cancelling with a reliable boundary drops the classes of the bytes it
// cancels: a BULK prefix is not filed as CONTROL for a CONTROL write
// beyond the boundary that will never be sent.
func TestCancelWriteForgetsTheClassOfCancelledBytes(t *testing.T) {
	h := newBuilderHarness(true)
	str := h.stream(48)
	str.enableResetStreamAt()
	writeClassBuffered(t, str, 100, congestion.ClassBulk)
	str.SetReliableBoundary() // at 100
	writeClassBuffered(t, str, 100, congestion.ClassControl)
	require.Equal(t, congestion.ClassControl, str.streamClass())
	str.CancelWrite(1)
	require.Equal(t, congestion.ClassBulk, str.streamClass())
	_, sfs, _ := h.framer.AppendClass(nil, nil, congestion.ClassBulk, 1200, true, monotime.Now(), protocol.Version1)
	require.Len(t, sfs, 1, "the reliable prefix is filed as CONTROL")
	require.Equal(t, protocol.ByteCount(100), sfs[0].Frame.DataLen())
}

// A reliable cancel during a blocked CONTROL write forgets that write's
// class too: the reliable BULK prefix is served at BULK.
func TestCancelWriteDuringABlockedWriteForgetsItsClass(t *testing.T) {
	h := newBuilderHarness(true)
	str := h.stream(52)
	str.enableResetStreamAt()
	writeClassBuffered(t, str, 100, congestion.ClassBulk)
	str.SetReliableBoundary() // at 100
	done := make(chan error, 1)
	go func() {
		_, err := str.WriteClass(make([]byte, 4000), congestion.ClassControl) // blocks: larger than the buffer
		done <- err
	}()
	require.Eventually(t, func() bool { return str.streamClass() == congestion.ClassControl }, time.Second, time.Millisecond)
	str.CancelWrite(1)
	require.Equal(t, congestion.ClassBulk, str.streamClass())
	require.Error(t, <-done)
}
