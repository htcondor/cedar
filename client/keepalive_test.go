package client

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/htcondor/cedar/stream"
)

func clientSOKeepAlive(t *testing.T, conn net.Conn) int {
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

// startEchoListener starts a TCP listener that accepts and holds connections
// (the direct-dial path of Connect does not exchange any bytes).
func startEchoListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// hold the conn open; do not close so the client side stays up
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// TestClientDialEnablesKeepAlive verifies the direct TCP dial path turns on
// keepalives by default.
func TestClientDialEnablesKeepAlive(t *testing.T) {
	ln := startEchoListener(t)

	c := NewClient(&ClientConfig{Address: ln.Addr().String(), Timeout: 3 * time.Second})
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = c.Close() }()

	conn := c.GetStream().GetConnection()
	if got := clientSOKeepAlive(t, conn); got == 0 {
		t.Errorf("SO_KEEPALIVE = %d on dialed conn, want non-zero (enabled by default)", got)
	}
}

// TestClientDialKeepAliveDisabled verifies the option is honored on the client.
func TestClientDialKeepAliveDisabled(t *testing.T) {
	ln := startEchoListener(t)

	c := NewClient(&ClientConfig{
		Address:   ln.Addr().String(),
		Timeout:   3 * time.Second,
		KeepAlive: &stream.KeepAliveConfig{Enable: false},
	})
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = c.Close() }()

	conn := c.GetStream().GetConnection()
	if got := clientSOKeepAlive(t, conn); got != 0 {
		t.Errorf("SO_KEEPALIVE = %d, want 0 when disabled via ClientConfig.KeepAlive", got)
	}
}
