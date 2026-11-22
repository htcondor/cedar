package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/htcondor/cedar/security"
)

func TestIsConnResetOrEOF(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"eof", io.EOF, true},
		{"unexpected-eof", io.ErrUnexpectedEOF, true},
		{"econnreset-typed", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, true},
		{"econnreset-wrapped", fmt.Errorf("failed to read frame header: %w",
			&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}), true},
		{"reset-string-only", errors.New("read tcp 1.2.3.4:5->6.7.8.9:9618: read: connection reset by peer"), true},
		{"broken-pipe", &net.OpError{Op: "write", Err: syscall.EPIPE}, true},
		{"auth-rejection", errors.New("authentication phase failed: all methods failed"), false},
		{"timeout", errors.New("i/o timeout"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isConnResetOrEOF(c.err); got != c.want {
				t.Errorf("isConnResetOrEOF(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestAnnotateSharedPortReset(t *testing.T) {
	reset := errors.New("failed to parse server response: failed to read frame header: " +
		"read tcp 10.0.0.1:53042->10.0.0.1:9618: read: connection reset by peer")

	// Shared-port endpoint + a bare reset with NO prior response -> annotated with an
	// actionable hint that names the shared_port endpoint and the socket, and preserves
	// the original error.
	got := annotateSharedPortReset("<10.0.0.1:9618?sock=htcondordb_8063_2036>", false, reset)
	for _, want := range []string{"shared_port", "10.0.0.1:9618", "htcondordb_8063_2036", "did not respond"} {
		if !strings.Contains(got.Error(), want) {
			t.Errorf("annotated error missing %q; got: %v", want, got)
		}
	}
	if !errors.Is(got, reset) {
		t.Error("annotated error should wrap (errors.Is) the original")
	}

	// Same reset, but the daemon already responded (a post-auth EOF, say) -> NOT
	// annotated: claiming the daemon never answered would be a lie. This is the
	// regression guard for the reported post-auth EOF being blamed on shared_port.
	if got := annotateSharedPortReset("<10.0.0.1:9618?sock=htcondordb_8063_2036>", true, reset); got != reset {
		t.Errorf("a reset after the daemon responded must pass through verbatim, got: %v", got)
	}

	// Not a shared-port address -> returned unchanged.
	if got := annotateSharedPortReset("10.0.0.1:9618", false, reset); got != reset {
		t.Errorf("non-shared-port address should pass through verbatim, got: %v", got)
	}

	// Shared-port address but a real protocol/auth rejection (not a bare reset) -> unchanged.
	authErr := errors.New("authentication phase failed: all authentication methods failed")
	if got := annotateSharedPortReset("10.0.0.1:9618?sock=some_daemon", false, authErr); got != authErr {
		t.Errorf("auth rejection should pass through verbatim, got: %v", got)
	}

	// nil in, nil out.
	if got := annotateSharedPortReset("10.0.0.1:9618?sock=x", false, nil); got != nil {
		t.Errorf("nil error should stay nil, got: %v", got)
	}
}

// TestConnectAndAuthenticateSharedPortDaemonAbsent reproduces the reported failure: a
// shared_port server accepts the TCP connection but has no daemon registered behind the
// socket name, so it resets the connection during the handshake. The client should surface
// the shared-port hint instead of a bare "connection reset by peer".
func TestConnectAndAuthenticateSharedPortDaemonAbsent(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	// Fake shared_port: accept, drain the client's SHARED_PORT_CONNECT request and
	// handshake bytes, then abruptly reset -- exactly what shared_port does when nothing
	// is registered under the requested socket name.
	go func() {
		conn, aerr := listener.Accept()
		if aerr != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 4096)
		for {
			if _, rerr := conn.Read(buf); rerr != nil {
				break
			}
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0) // Close() now sends RST -> ECONNRESET on the client's read
		}
		_ = conn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	config := &ClientConfig{
		Address: fmt.Sprintf("<%s?sock=htcondordb_8063_2036>", listener.Addr().String()),
		Timeout: 5 * time.Second,
		Security: &security.SecurityConfig{
			Command:        60010, // DC_NOP_WRITE
			AuthMethods:    []security.AuthMethod{security.AuthNone},
			Authentication: security.SecurityOptional,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			Encryption:     security.SecurityOptional,
			Integrity:      security.SecurityOptional,
		},
	}

	_, err = ConnectAndAuthenticateWithConfig(ctx, config)
	if err == nil {
		t.Fatal("expected an error connecting through shared_port with no daemon behind it")
	}
	msg := err.Error()
	if !strings.Contains(msg, "shared_port") || !strings.Contains(msg, "htcondordb_8063_2036") {
		t.Fatalf("expected a shared-port hint naming the socket, got: %v", err)
	}
}
