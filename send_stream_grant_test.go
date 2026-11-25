package quic

import (
	"context"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// A grant's build path takes only bytes of its range: new data up to the
// range's end, and retransmissions inside it, never ones outside it.
func TestSendStreamGrantedFramesStayInTheirRange(t *testing.T) {
	const streamID protocol.StreamID = 1000
	mockCtrl := gomock.NewController(t)
	mockFC := newTestStreamFlowControllerWithSendWindow(1<<20, protocol.MaxByteCount)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC, false)
	mockSender.EXPECT().onHasStreamData(streamID, str).AnyTimes()
	mockSender.EXPECT().onStreamCompleted(gomock.Any()).AnyTimes()

	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}
	_, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write(data[:40])
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(40), str.AcceptedOffset())

	// Bytes [0, 10) go out ordinarily and are lost.
	ordinary, _, _ := str.popStreamFrame(10+expectedFrameHeaderLen(streamID, 0), protocol.Version1)
	require.Equal(t, protocol.ByteCount(10), ordinary.Frame.DataLen())

	// The grant covers [10, 30).
	f := str.popGrantedStreamFrame(1200, 10, 30, protocol.Version1)
	require.NotNil(t, f.Frame)
	require.Equal(t, protocol.ByteCount(10), f.Frame.Offset)
	require.Equal(t, protocol.ByteCount(20), f.Frame.DataLen(), "new data stops at the range's end")
	require.Nil(t, str.popGrantedStreamFrame(1200, 10, 30, protocol.Version1).Frame, "nothing more in range")

	// Lose both: the ordinary frame outside the range and the granted one.
	ordinary.Handler.OnLost(ordinary.Frame)
	f.Handler.OnLost(f.Frame)
	r := str.popGrantedStreamFrame(1200, 10, 30, protocol.Version1)
	require.NotNil(t, r.Frame, "a granted frame's retransmission is still covered")
	require.Equal(t, protocol.ByteCount(10), r.Frame.Offset)
	require.Equal(t, protocol.ByteCount(20), r.Frame.DataLen())
	require.Nil(t, str.popGrantedStreamFrame(1200, 10, 30, protocol.Version1).Frame, "the retransmission outside the range is not")

	// The ordinary path still sends the rest.
	rest, _, _ := str.popStreamFrame(1200, protocol.Version1)
	require.Equal(t, protocol.ByteCount(0), rest.Frame.Offset)
}
