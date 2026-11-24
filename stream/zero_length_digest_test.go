package stream

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
)

// A zero-length plaintext frame is legal (flushing an empty send buffer emits
// one), and the sender feeds its header to the handshake digest. That digest
// becomes the AAD of the first encrypted frame, so a receiver that skips the
// header leaves the two sides disagreeing and the session never decrypts.
func TestZeroLengthFrameKeepsHandshakeDigestsInStep(t *testing.T) {
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	sender, receiver := NewStream(peer), NewStream(local)
	ctx := context.Background()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	sent := make(chan error, 1)
	go func() {
		sent <- func() error {
			// An empty partial frame, then key the session and send for real.
			if err := sender.SendPartialMessage(ctx, nil); err != nil {
				return err
			}
			if err := sender.SetSymmetricKey(key); err != nil {
				return err
			}
			return sender.SendMessage(ctx, []byte("after the empty frame"))
		}()
	}()

	empty, err := receiver.ReceiveFrame(ctx)
	if err != nil {
		t.Fatalf("ReceiveFrame on a zero-length plaintext frame: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("frame = %q, want empty", empty)
	}
	if err := receiver.SetSymmetricKey(key); err != nil {
		t.Fatalf("set key: %v", err)
	}

	got, err := receiver.ReceiveFrame(ctx)
	if err != nil {
		t.Fatalf("first encrypted frame failed after a zero-length frame read by ReceiveFrame: %v", err)
	}
	if want := "after the empty frame"; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if err := <-sent; err != nil {
		t.Fatalf("send: %v", err)
	}
}
