package server

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/htcondor/cedar/stream"
)

// soKeepAlive reads SO_KEEPALIVE from a net.Conn's underlying fd.
func soKeepAlive(t *testing.T, conn net.Conn) int {
	t.Helper()
	sc, ok := conn.(syscall.Conn)
	if !ok {
		t.Fatalf("conn %T does not implement syscall.Conn", conn)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var val int
	var operr error
	if err := raw.Control(func(fd uintptr) {
		val, operr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
	}); err != nil {
		t.Fatalf("raw.Control: %v", err)
	}
	if operr != nil {
		t.Fatalf("GetsockoptInt SO_KEEPALIVE: %v", operr)
	}
	return val
}

// capturingListener wraps a net.Listener and publishes each accepted conn so a
// test can inspect the exact connection Serve operated on.
type capturingListener struct {
	net.Listener
	conns chan net.Conn
}

func (l *capturingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.conns <- c
	}
	return c, err
}

func TestNewServerHasKeepAliveDefault(t *testing.T) {
	s := New(nil)
	if s.KeepAlive != stream.DefaultKeepAliveConfig() {
		t.Errorf("New().KeepAlive = %+v, want default %+v", s.KeepAlive, stream.DefaultKeepAliveConfig())
	}
}

// TestServeEnablesKeepAlive verifies that Server.Serve turns on TCP keepalives
// on connections it accepts, mirroring C++ HTCondor's accepted-socket behavior.
func TestServeEnablesKeepAlive(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cl := &capturingListener{Listener: base, conns: make(chan net.Conn, 1)}

	s := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = s.Serve(ctx, cl) }()

	dialed, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = dialed.Close() }()

	var accepted net.Conn
	select {
	case accepted = <-cl.conns:
	case <-time.After(3 * time.Second):
		t.Fatal("server never accepted the connection")
	}
	defer func() { _ = accepted.Close() }()

	// Serve applies keepalive right after Accept returns, before spawning the
	// handler goroutine; poll briefly to avoid racing that application.
	deadline := time.Now().Add(2 * time.Second)
	for soKeepAlive(t, accepted) == 0 {

		if time.Now().After(deadline) {
			t.Fatalf("SO_KEEPALIVE never became enabled on the accepted connection")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestServeKeepAliveDisabled verifies the option is honored: with keepalives
// turned off, Serve must not enable SO_KEEPALIVE.
func TestServeKeepAliveDisabled(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cl := &capturingListener{Listener: base, conns: make(chan net.Conn, 1)}

	s := New(nil)
	s.KeepAlive = stream.KeepAliveConfig{Enable: false}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = s.Serve(ctx, cl) }()

	dialed, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = dialed.Close() }()

	var accepted net.Conn
	select {
	case accepted = <-cl.conns:
	case <-time.After(3 * time.Second):
		t.Fatal("server never accepted the connection")
	}
	defer func() { _ = accepted.Close() }()

	// Give Serve a moment to (not) apply keepalive.
	time.Sleep(200 * time.Millisecond)
	if got := soKeepAlive(t, accepted); got != 0 {
		t.Errorf("SO_KEEPALIVE = %d, want 0 when keepalive disabled", got)
	}
}
