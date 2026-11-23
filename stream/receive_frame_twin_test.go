package stream

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"testing"
)

// keyedPlaintextPair returns two streams that share an AES key but have
// encryption turned off -- the state C++ reaches with integrity on and
// SEC_*_ENCRYPTION false. SetSymmetricKey enables encryption as a side effect,
// so this is the only way to hold a key without using it.
func keyedPlaintextPair(t *testing.T) (sender, receiver *Stream) {
	t.Helper()

	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	sender, receiver = NewStream(a), NewStream(b)
	for _, s := range []*Stream{sender, receiver} {
		if err := s.SetSymmetricKey(key); err != nil {
			t.Fatalf("set key: %v", err)
		}
		s.SetEncrypted(false)
	}
	return sender, receiver
}

// Both exported readers must agree with the SEND path, which encrypts on
// `s.gcm != nil && s.encrypted`: a frame written in the clear with a key
// installed has to read back in the clear. Nothing else covered that state --
// every other encryption test keys the stream and leaves encryption on.
//
// The guarantee rests on decryptDataWithAAD's own `!s.encrypted` check, not on
// either caller's condition; dropping it from the helper fails this test with
// "cipher: message authentication failed".
//
// This replaces TestReceiveFrameZeroLengthDigestMatchesTwin, which compared the
// two readers to each other. Now that one is implemented in terms of the other,
// that comparison holds by construction and could never fail again.
func TestReceivePathsHonorEncryptionDisabled(t *testing.T) {
	want := []byte("sent in the clear with a key installed")

	for _, tc := range []struct {
		name string
		read func(*Stream, context.Context) ([]byte, error)
	}{
		{"ReceiveFrame", func(s *Stream, ctx context.Context) ([]byte, error) {
			return s.ReceiveFrame(ctx)
		}},
		{"ReceiveFrameWithEnd", func(s *Stream, ctx context.Context) ([]byte, error) {
			data, _, err := s.ReceiveFrameWithEnd(ctx)
			return data, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender, receiver := keyedPlaintextPair(t)
			ctx := context.Background()

			errc := make(chan error, 1)
			go func() { errc <- sender.SendMessage(ctx, want) }()

			got, err := tc.read(receiver, ctx)
			if err != nil {
				t.Fatalf("%s on a plaintext frame with a key installed: %v", tc.name, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s returned %q, want %q", tc.name, got, want)
			}
			if err := <-errc; err != nil {
				t.Fatalf("send: %v", err)
			}
		})
	}
}
