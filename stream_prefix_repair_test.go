package quic

import (
	"context"
	"testing"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestInitialPrefixRepair(t *testing.T) {
	const id = protocol.StreamID(42)
	body := []byte("open-request-body")
	for _, stopAt := range []string{"loss", "original ack", "repair ack", "cancel"} {
		t.Run(stopAt, func(t *testing.T) {
			sender := NewMockStreamSender(gomock.NewController(t))
			window := newTestStreamFlowControllerWithSendWindow(id, protocol.ByteCount(len(body)))
			send := newSendStream(context.Background(), id, sender, window, false)
			stream := &Stream{sendStr: send}
			stop := stream.ProtectInitialPrefix(4, 50)
			require.NotNil(t, stop)
			sender.EXPECT().onHasStreamData(id, send)
			_, err := send.Write(body)
			require.NoError(t, err)
			original, _, more := send.popStreamFrame(1000, protocol.Version1)
			require.True(t, more)
			require.Equal(t, body, original.Frame.Data)
			require.Equal(t, int64(1), send.numOutstandingFrames)
			require.Zero(t, window.SendWindowSize())
			tooSmall, _, more := send.popStreamFrame(2, protocol.Version1)
			require.Nil(t, tooSmall.Frame)
			require.True(t, more)
			repair, _, more := send.popStreamFrame(1000, protocol.Version1)
			require.True(t, more)
			require.Equal(t, id, repair.Frame.StreamID)
			require.Zero(t, repair.Frame.Offset)
			require.False(t, repair.Frame.Fin)
			require.Equal(t, body[:4], repair.Frame.Data)
			switch stopAt {
			case "original ack":
				original.Handler.OnAcked(original.Frame)
				repair.Handler.OnLost(repair.Frame)
			case "repair ack":
				repair.Handler.OnAcked(repair.Frame)
			case "cancel":
				stop()
				repair.Handler.OnLost(repair.Frame)
			case "loss":
				repair.Handler.OnLost(repair.Frame)
				for range 2 {
					next, _, _ := send.popStreamFrame(1000, protocol.Version1)
					require.NotNil(t, next.Frame)
					next.Handler.OnLost(next.Frame)
				}
			}
			extra, _, more := send.popStreamFrame(1000, protocol.Version1)
			require.Nil(t, extra.Frame)
			require.False(t, more)
			if stopAt != "original ack" {
				require.Equal(t, int64(1), send.numOutstandingFrames)
				original.Handler.OnAcked(original.Frame)
			}
			stop()
			require.Nil(t, send.prefixRepair)
			require.Zero(t, send.numOutstandingFrames)
			require.Len(t, send.retransmissionQueue, 0)
			require.Equal(t, protocol.ByteCount(len(body)), send.writeOffset)
			require.Nil(t, stream.ProtectInitialPrefix(4, 1))
		})
	}
}

func TestPrefixRepairAckPreservesReliableSuffixAndFIN(t *testing.T) {
	const id = protocol.StreamID(42)
	body := []byte("open-request-body")
	sender := NewMockStreamSender(gomock.NewController(t))
	window := newTestStreamFlowControllerWithSendWindow(id, protocol.ByteCount(len(body)))
	send := newSendStream(context.Background(), id, sender, window, false)
	stream := &Stream{sendStr: send}
	require.NotNil(t, stream.ProtectInitialPrefix(4, 3))
	sender.EXPECT().onHasStreamData(id, send).AnyTimes()
	_, err := send.Write(body)
	require.NoError(t, err)
	require.NoError(t, send.Close())
	original, _, _ := send.popStreamFrame(1000, protocol.Version1)
	require.True(t, original.Frame.Fin)
	repair, _, _ := send.popStreamFrame(1000, protocol.Version1)
	require.False(t, repair.Frame.Fin)
	repair.Handler.OnAcked(repair.Frame)
	original.Handler.OnLost(original.Frame)
	retry, _, _ := send.popStreamFrame(1000, protocol.Version1)
	require.Equal(t, body, retry.Frame.Data)
	require.True(t, retry.Frame.Fin)
	sender.EXPECT().onStreamCompleted(id)
	retry.Handler.OnAcked(retry.Frame)
	require.Zero(t, send.numOutstandingFrames)
}

func TestPrefixRepairClearsReferencesOnShutdownAfterFIN(t *testing.T) {
	const id = protocol.StreamID(42)
	sender := NewMockStreamSender(gomock.NewController(t))
	send := newSendStream(context.Background(), id, sender, newTestStreamFlowControllerWithSendWindow(id, 10), false)
	stream := &Stream{sendStr: send}
	stop := stream.ProtectInitialPrefix(4, 3)
	state := send.prefixRepair
	sender.EXPECT().onHasStreamData(id, send).AnyTimes()
	_, err := send.Write([]byte("OPEN"))
	require.NoError(t, err)
	require.NoError(t, send.Close())
	original, _, _ := send.popStreamFrame(1000, protocol.Version1)
	require.NotEmpty(t, state.data)
	send.closeForShutdown(context.Canceled)
	require.Nil(t, send.prefixRepair)
	require.Nil(t, state.data)
	stop()
	original.Frame.PutBack()
}
