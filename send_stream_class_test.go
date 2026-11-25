package quic

import (
	"context"
	"testing"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/ackhandler"
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
