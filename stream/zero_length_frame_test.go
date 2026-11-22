package stream

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
)

// zeroLengthFrame is the 5-byte CEDAR header an on-path peer can splice into a
// session: end-of-message flag 1, declared length 0.
var zeroLengthFrame = []byte{0x01, 0x00, 0x00, 0x00, 0x00}

func encryptedStreamPair(t *testing.T) (net.Conn, *Stream) {
	t.Helper()
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })

	s := NewStream(local)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := s.SetSymmetricKey(key); err != nil {
		t.Fatalf("set key: %v", err)
	}
	return peer, s
}

// An encrypted stream must refuse a zero-length frame. Accepting one returns an
// end-of-message flag that never passed AEAD verification, so a peer with no key
// can inject message boundaries with 5 bytes.
func TestReceiveFrameWithEndRejectsZeroLengthWhenEncrypted(t *testing.T) {
	peer, s := encryptedStreamPair(t)

	go func() { _, _ = peer.Write(zeroLengthFrame) }()

	data, end, err := s.ReceiveFrameWithEnd(context.Background())
	if err == nil {
		t.Fatalf("accepted a zero-length frame on an encrypted stream: data=%q end=%d", data, end)
	}
}

func TestReceiveFrameRejectsZeroLengthWhenEncrypted(t *testing.T) {
	peer, s := encryptedStreamPair(t)

	go func() { _, _ = peer.Write(zeroLengthFrame) }()

	data, err := s.ReceiveFrame(context.Background())
	if err == nil {
		t.Fatalf("accepted a zero-length frame on an encrypted stream: data=%q", data)
	}
}

// A plaintext stream still accepts one: sendMessageWithEnd writes len(data)
// verbatim when unencrypted, so flushing an empty send buffer legitimately puts
// a zero-length frame on the wire. The guard above must not reach this path.
func TestReceiveFrameWithEndAllowsZeroLengthWhenPlaintext(t *testing.T) {
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	s := NewStream(local)

	go func() { _, _ = peer.Write(zeroLengthFrame) }()

	data, end, err := s.ReceiveFrameWithEnd(context.Background())
	if err != nil {
		t.Fatalf("rejected a legitimate plaintext zero-length frame: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("data = %q, want empty", data)
	}
	if end != 1 {
		t.Errorf("end flag = %d, want 1", end)
	}
}
