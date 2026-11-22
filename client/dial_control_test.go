package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/htcondor/cedar/security"
)

// countingListener accepts TCP connections on 127.0.0.1 and counts them,
// holding each open until the test ends.
type countingListener struct {
	ln       net.Listener
	accepted atomic.Int32
	mu       sync.Mutex
	conns    []net.Conn
}

func newCountingListener(t *testing.T) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			cl.accepted.Add(1)
			cl.mu.Lock()
			cl.conns = append(cl.conns, c)
			cl.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		cl.mu.Lock()
		defer cl.mu.Unlock()
		for _, c := range cl.conns {
			_ = c.Close()
		}
	})
	return cl
}

func (cl *countingListener) port() int { return cl.ln.Addr().(*net.TCPAddr).Port }

// recorder is a DialControl that records every address it is shown and
// returns err.
type recorder struct {
	mu    sync.Mutex
	addrs []string
	err   error
}

func (r *recorder) control(network, address string, _ syscall.RawConn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addrs = append(r.addrs, address)
	return r.err
}

func (r *recorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.addrs...)
}

// assertResolvedIPs checks that every address the hook saw is an IP literal
// (name resolution already happened) and that want is among them.
func assertResolvedIPs(t *testing.T, seen []string, want string) {
	t.Helper()
	if len(seen) == 0 {
		t.Fatal("DialControl was never called")
	}
	found := false
	for _, a := range seen {
		host, _, err := net.SplitHostPort(a)
		if err != nil || net.ParseIP(host) == nil {
			t.Errorf("DialControl saw %q, want a resolved ip:port", a)
		}
		if a == want {
			found = true
		}
	}
	if !found {
		t.Errorf("DialControl saw %v, want it to include %s", seen, want)
	}
}

// assertNoConnection checks that the listener never accepted a connection.
func assertNoConnection(t *testing.T, cl *countingListener) {
	t.Helper()
	time.Sleep(100 * time.Millisecond) // let a stray connect land, if one was made
	if n := cl.accepted.Load(); n != 0 {
		t.Errorf("listener accepted %d connection(s) after DialControl refused", n)
	}
}

var errRefused = errors.New("destination refused by test")

func TestDialControlDirect(t *testing.T) {
	cl := newCountingListener(t)
	rec := &recorder{}
	c := NewClient(&ClientConfig{
		Address:     fmt.Sprintf("localhost:%d", cl.port()),
		Timeout:     5 * time.Second,
		DialControl: rec.control,
	})
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = c.Close() }()
	assertResolvedIPs(t, rec.seen(), fmt.Sprintf("127.0.0.1:%d", cl.port()))
}

func TestDialControlDirectRefused(t *testing.T) {
	cl := newCountingListener(t)
	rec := &recorder{err: errRefused}
	c := NewClient(&ClientConfig{
		Address:     fmt.Sprintf("127.0.0.1:%d", cl.port()),
		Timeout:     5 * time.Second,
		DialControl: rec.control,
	})
	err := c.Connect(context.Background())
	if !errors.Is(err, errRefused) {
		t.Fatalf("Connect error = %v, want %v", err, errRefused)
	}
	assertResolvedIPs(t, rec.seen(), fmt.Sprintf("127.0.0.1:%d", cl.port()))
	assertNoConnection(t, cl)
}

func TestDialControlSharedPort(t *testing.T) {
	cl := newCountingListener(t)
	rec := &recorder{}
	c := NewClient(&ClientConfig{
		Address:     fmt.Sprintf("<localhost:%d?sock=schedd>", cl.port()),
		Timeout:     5 * time.Second,
		DialControl: rec.control,
	})
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = c.Close() }()
	assertResolvedIPs(t, rec.seen(), fmt.Sprintf("127.0.0.1:%d", cl.port()))
}

func TestDialControlSharedPortRefused(t *testing.T) {
	cl := newCountingListener(t)
	rec := &recorder{err: errRefused}
	c := NewClient(&ClientConfig{
		Address:     fmt.Sprintf("<127.0.0.1:%d?sock=schedd>", cl.port()),
		Timeout:     5 * time.Second,
		DialControl: rec.control,
	})
	err := c.Connect(context.Background())
	if !errors.Is(err, errRefused) {
		t.Fatalf("Connect error = %v, want %v", err, errRefused)
	}
	assertResolvedIPs(t, rec.seen(), fmt.Sprintf("127.0.0.1:%d", cl.port()))
	assertNoConnection(t, cl)
}

// TestDialControlCCBRefused checks the hook is applied to the CCB broker dial:
// the broker's address is shown to it, and refusing it means the broker is
// never connected to.
func TestDialControlCCBRefused(t *testing.T) {
	broker := newCountingListener(t)
	rec := &recorder{err: errRefused}
	c := NewClient(&ClientConfig{
		Address: fmt.Sprintf("<10.0.0.5:41339?CCBID=127.0.0.1:%d%%231&noUDP>", broker.port()),
		Timeout: 5 * time.Second,
		Security: &security.SecurityConfig{
			AuthMethods:    []security.AuthMethod{},
			Authentication: security.SecurityNever,
			Encryption:     security.SecurityNever,
			Integrity:      security.SecurityNever,
		},
		DialControl: rec.control,
	})
	if err := c.Connect(context.Background()); err == nil {
		_ = c.Close()
		t.Fatal("Connect succeeded although DialControl refused the broker")
	}
	assertResolvedIPs(t, rec.seen(), fmt.Sprintf("127.0.0.1:%d", broker.port()))
	assertNoConnection(t, broker)
}
