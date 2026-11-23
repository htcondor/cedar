package security

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

// sendKeyExchange writes the server half of the post-authentication key
// exchange -- hasKey=1 followed by keyLength, protocol, duration and inputLen
// -- with no key bytes after it. The key exchange runs before the stream is
// encrypted, so these are bytes any peer, or anything on the path, can send.
func sendKeyExchange(t *testing.T, conn net.Conn, inputLen int) {
	t.Helper()
	go func() {
		ctx := context.Background()
		st := stream.NewStream(conn)

		// exchangeKey reads all five of these from one Message: the hasKey
		// flag, then keyLength, protocol, duration and inputLen.
		hdr := message.NewMessageForStream(st)
		for _, v := range []int{1, 24, 1, 0, inputLen} {
			if err := hdr.PutInt(ctx, v); err != nil {
				return
			}
		}
		_ = hdr.FinishMessage(ctx)
	}()
}

// clientExchangeKey runs the client side of exchangeKey against conn and
// returns its error, or fails the test if it does not return in time.
func clientExchangeKey(t *testing.T, conn net.Conn) error {
	t.Helper()
	auth := &Authenticator{
		config: &SecurityConfig{},
		stream: stream.NewStream(conn),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- auth.exchangeKey(ctx, &SecurityNegotiation{IsClient: true}) }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("exchangeKey did not return")
		return nil
	}
}

// TestKeyExchangeRejectsNegativeLength: a peer-declared negative key length
// must be reported as an error. It sizes a make() directly, so without a
// bound it panics with "makeslice: len out of range" -- and that panic is on
// the client's own goroutine, which no recover in this library covers, so it
// takes down a daemon acting as a CEDAR client rather than failing the one
// connection.
func TestKeyExchangeRejectsNegativeLength(t *testing.T) {
	for _, inputLen := range []int{-1, -4096, -1 << 40} {
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() {
			_ = serverConn.Close()
			_ = clientConn.Close()
		})
		sendKeyExchange(t, serverConn, inputLen)

		err := clientExchangeKey(t, clientConn)
		if err == nil {
			t.Fatalf("inputLen %d: exchangeKey returned nil, want an error", inputLen)
		}
		if !strings.Contains(err.Error(), "invalid encrypted key length") {
			t.Errorf("inputLen %d: error = %q, want it to name the invalid length", inputLen, err)
		}
	}
}

// TestKeyExchangeRejectsOversizeLength: a length far above any real wrapped
// key is refused before it reaches make(), instead of being used to size an
// allocation on the peer's word.
func TestKeyExchangeRejectsOversizeLength(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	sendKeyExchange(t, serverConn, maxExchangedKeyLen+1)

	err := clientExchangeKey(t, clientConn)
	if err == nil {
		t.Fatal("exchangeKey returned nil for an oversize length, want an error")
	}
	if !strings.Contains(err.Error(), "invalid encrypted key length") {
		t.Errorf("error = %q, want it to name the invalid length", err)
	}
}

// TestKeyExchangeAcceptsLegitimateLength guards against fixing the panic by
// rejecting everything: a plausible wrapped-key length is still read, and the
// short stream that follows is reported as the read failure it is, not as a
// bad length.
func TestKeyExchangeAcceptsLegitimateLength(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	sendKeyExchange(t, serverConn, 32)

	err := clientExchangeKey(t, clientConn)
	if err != nil && strings.Contains(err.Error(), "invalid encrypted key length") {
		t.Errorf("a 32-byte key was rejected as an invalid length: %v", err)
	}
}
