package quic

import (
	"testing"

	"github.com/apernet/quic-go/internal/ackhandler"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestRetransmissionQueueFrames(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testRetransmissionQueueFrames(t, protocol.EncryptionInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testRetransmissionQueueFrames(t, protocol.EncryptionHandshake)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testRetransmissionQueueFrames(t, protocol.Encryption1RTT)
	})
}

func testRetransmissionQueueFrames(t *testing.T, encLevel protocol.EncryptionLevel) {
	q := newRetransmissionQueue()

	require.False(t, q.HasData(encLevel))
	require.Nil(t, q.GetFrame(encLevel, protocol.MaxByteCount, protocol.Version1))

	ah := q.AckHandler(encLevel)
	require.NotNil(t, ah)
	ah.OnLost(&wire.PingFrame{})
	require.True(t, q.HasData(encLevel))
	require.Equal(t, &wire.PingFrame{}, q.GetFrame(encLevel, protocol.MaxByteCount, protocol.Version1))
	require.False(t, q.HasData(encLevel))
	require.Nil(t, q.GetFrame(encLevel, protocol.MaxByteCount, protocol.Version1))

	f := &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	ah.OnLost(f)
	require.True(t, q.HasData(encLevel))
	require.Nil(t, q.GetFrame(encLevel, f.Length(protocol.Version1)-1, protocol.Version1))
	require.Equal(t, f, q.GetFrame(encLevel, f.Length(protocol.Version1), protocol.Version1))
	require.False(t, q.HasData(encLevel))

	if encLevel == protocol.Encryption1RTT {
		require.Panics(t, func() { ah.OnLost(&wire.StreamFrame{}) })
	}
}

func TestRetransmissionQueueCryptoFrames(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testRetransmissionQueueCryptoFrames(t, protocol.EncryptionInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testRetransmissionQueueCryptoFrames(t, protocol.EncryptionHandshake)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testRetransmissionQueueCryptoFrames(t, protocol.Encryption1RTT)
	})
}

func testRetransmissionQueueCryptoFrames(t *testing.T, encLevel protocol.EncryptionLevel) {
	q := newRetransmissionQueue()

	var otherEncLevel protocol.EncryptionLevel
	switch encLevel {
	case protocol.EncryptionInitial:
		otherEncLevel = protocol.EncryptionHandshake
	case protocol.EncryptionHandshake:
		otherEncLevel = protocol.Encryption1RTT
	case protocol.Encryption1RTT:
		otherEncLevel = protocol.EncryptionInitial
	}

	ah := q.AckHandler(encLevel)
	require.NotNil(t, ah)
	ah.OnLost(&wire.CryptoFrame{Data: []byte("foobar")})
	require.True(t, q.HasData(encLevel))
	require.False(t, q.HasData(otherEncLevel))
	require.Equal(t, &wire.CryptoFrame{Data: []byte("foobar")}, q.GetFrame(encLevel, protocol.MaxByteCount, protocol.Version1))
	require.False(t, q.HasData(encLevel))
	require.Nil(t, q.GetFrame(encLevel, protocol.MaxByteCount, protocol.Version1))

	f := &wire.CryptoFrame{Offset: 100, Data: []byte("foobar")}
	ah.OnLost(f)
	ah.OnLost(&wire.PingFrame{})
	require.True(t, q.HasData(encLevel))
	require.False(t, q.HasData(otherEncLevel))
	// the CRYPTO frame wouldn't fit, not even if it was split
	require.IsType(t, &wire.PingFrame{}, q.GetFrame(encLevel, 2, protocol.Version1))

	f1 := q.GetFrame(encLevel, f.Length(protocol.Version1)-3, protocol.Version1)
	require.NotNil(t, f1)
	require.IsType(t, &wire.CryptoFrame{}, f1)
	require.Equal(t, &wire.CryptoFrame{Offset: 100, Data: []byte("foo")}, f1)
	f2 := q.GetFrame(encLevel, protocol.MaxByteCount, protocol.Version1)
	require.NotNil(t, f2)
	require.IsType(t, &wire.CryptoFrame{}, f2)
	require.Equal(t, &wire.CryptoFrame{Offset: 103, Data: []byte("bar")}, f2)
}

func TestRetransmissionQueueDropEncLevel(t *testing.T) {
	q := newRetransmissionQueue()
	require.Panics(t, func() { q.DropPackets(protocol.Encryption0RTT) })
	require.Panics(t, func() { q.DropPackets(protocol.Encryption1RTT) })

	t.Run("Initial", func(t *testing.T) {
		testRetransmissionQueueDropEncLevel(t, protocol.EncryptionInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testRetransmissionQueueDropEncLevel(t, protocol.EncryptionHandshake)
	})
}

func testRetransmissionQueueDropEncLevel(t *testing.T, encLevel protocol.EncryptionLevel) {
	q := newRetransmissionQueue()

	ah := q.AckHandler(encLevel)
	require.NotNil(t, ah)
	ah.OnLost(&wire.PingFrame{})
	ah.OnLost(&wire.CryptoFrame{Data: []byte("foobar")})
	require.True(t, q.HasData(encLevel))
	q.DropPackets(encLevel)
	require.False(t, q.HasData(encLevel))
	require.Nil(t, q.GetFrame(encLevel, protocol.MaxByteCount, protocol.Version1))

	// losing more frame is a no-op
	ah.OnLost(&wire.CryptoFrame{Data: []byte("foobar")})
	ah.OnLost(&wire.PingFrame{})
	require.False(t, q.HasData(encLevel))
}

func TestRetransmissionQueueAppendFittingFrames(t *testing.T) {
	q := newRetransmissionQueue()
	big := &wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: protocol.ParseConnectionID(make([]byte, 20))}
	q.addAppData(&wire.MaxDataFrame{MaximumData: 1})
	q.addAppData(big)
	q.addAppData(&wire.MaxDataFrame{MaximumData: 2})
	q.addAppData(big)
	q.addAppData(&wire.MaxDataFrame{MaximumData: 3})
	q.addAppData(&wire.MaxDataFrame{MaximumData: 4})
	small := (&wire.MaxDataFrame{MaximumData: 1}).Length(protocol.Version1)

	// Room for three small frames: the first three, skipping what does not fit.
	frames, n := q.AppendFittingFrames(nil, 3*small, protocol.Version1)
	require.Equal(t, 3*small, n)
	require.Len(t, frames, 3)
	for i, f := range frames {
		require.Equal(t, &wire.MaxDataFrame{MaximumData: protocol.ByteCount(i + 1)}, f.Frame)
		require.NotNil(t, f.Handler)
	}
	require.Equal(t, []wire.Frame{big, big, &wire.MaxDataFrame{MaximumData: 4}}, q.appData.other)

	// A prefix that fits is taken without disturbing the rest.
	frames, _ = q.AppendFittingFrames(nil, big.Length(protocol.Version1), protocol.Version1)
	require.Equal(t, []ackhandler.Frame{{Frame: big, Handler: q.AckHandler(protocol.Encryption1RTT)}}, frames)
	require.Equal(t, []wire.Frame{big, &wire.MaxDataFrame{MaximumData: 4}}, q.appData.other)

	frames, n = q.AppendFittingFrames(nil, 0, protocol.Version1)
	require.Empty(t, frames)
	require.Zero(t, n)
	frames, _ = q.AppendFittingFrames(nil, 1000, protocol.Version1)
	require.Len(t, frames, 2)
	require.False(t, q.HasData(protocol.Encryption1RTT))
}
