package stream

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// SetTimeout must deadline whatever connection the stream holds. It used to
// apply only to a *net.TCPConn and return nil for everything else, so on a
// TLS, Unix-socket or otherwise wrapped connection a caller was told the
// timeout was armed when nothing was.
func TestSetTimeoutArmsDeadlineOnNonTCPConn(t *testing.T) {
	peer, local := net.Pipe() // not a *net.TCPConn, but it honours deadlines
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	s := NewStream(local)

	if err := s.SetTimeout(100 * time.Millisecond); err != nil {
		t.Fatalf("SetTimeout: %v", err)
	}

	// The read is in a goroutine so an unarmed deadline fails this test by
	// name instead of blocking it forever; the cleanup close releases it.
	done := make(chan error, 1)
	go func() {
		_, err := s.ReceiveFrame(context.Background())
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read returned success with nothing on the wire")
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("error = %v, want a deadline-exceeded error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SetTimeout armed no deadline on a non-TCP connection: the read is still blocked long past the 100ms timeout")
	}
}

// Clearing the timeout must reach the same connection, not quietly succeed.
func TestSetTimeoutZeroClearsDeadlineOnNonTCPConn(t *testing.T) {
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	s := NewStream(local)

	if err := s.SetTimeout(10 * time.Millisecond); err != nil {
		t.Fatalf("SetTimeout: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // let the first deadline lapse
	if err := s.SetTimeout(0); err != nil {
		t.Fatalf("SetTimeout(0): %v", err)
	}
	if s.GetTimeout() != 0 {
		t.Errorf("GetTimeout() = %v, want 0", s.GetTimeout())
	}

	go func() { writeFrame(peer, []byte("still readable")) }()

	got, err := s.ReceiveFrame(context.Background())
	if err != nil {
		t.Fatalf("read after clearing the timeout: %v", err)
	}
	if string(got) != "still readable" {
		t.Errorf("got %q, want %q", got, "still readable")
	}
}

// With no connection there is nothing to arm, and saying so beats reporting
// success.
func TestSetTimeoutWithoutConnection(t *testing.T) {
	s := NewStream(nil)
	if err := s.SetTimeout(time.Second); err == nil {
		t.Error("SetTimeout reported success on a stream with no connection")
	}
}
