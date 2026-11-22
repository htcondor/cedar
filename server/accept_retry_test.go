package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// errOutOfDescriptors stands in for EMFILE/ENFILE: the listener is still open
// and still bound, it just cannot produce a connection right now.
var errOutOfDescriptors = errors.New("accept: too many open files")

// scriptedListener returns a scripted sequence of Accept outcomes. A nil error
// with a nil conn means "hand over one connection".
type scriptedListener struct {
	mu        sync.Mutex
	script    []error // one entry per Accept call; nil = deliver a connection
	calls     int
	delivered int
	toClose   []net.Conn
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.calls >= len(l.script) {
		return nil, net.ErrClosed
	}
	err := l.script[l.calls]
	l.calls++
	if err != nil {
		return nil, err
	}
	a, b := net.Pipe()
	l.toClose = append(l.toClose, a, b)
	l.delivered++
	return a, nil
}

func (l *scriptedListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.toClose {
		_ = c.Close()
	}
	return nil
}

func (l *scriptedListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func (l *scriptedListener) counts() (int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls, l.delivered
}

// A transient Accept failure must not end the accept loop. Returning on any
// error made descriptor exhaustion permanent: the loop exited, the listener
// stayed bound so nothing could take the port, and the daemon never accepted
// again even once descriptors were free.
func TestServeRetriesTransientAcceptErrors(t *testing.T) {
	ln := &scriptedListener{script: []error{
		errOutOfDescriptors,
		errOutOfDescriptors,
		errOutOfDescriptors,
		nil, // descriptors free again: a connection gets through
	}}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv := &Server{}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	select {
	case err := <-done:
		if errors.Is(err, errOutOfDescriptors) {
			t.Fatal("Serve returned the transient accept error instead of retrying")
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve error = %v, want net.ErrClosed once the listener closed", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Serve did not return after the listener closed")
	}

	calls, delivered := ln.counts()
	if delivered != 1 {
		t.Errorf("connections accepted = %d, want 1: the loop never recovered", delivered)
	}
	if calls < 4 {
		t.Errorf("Accept calls = %d, want at least 4: the loop stopped early", calls)
	}
}

// A closed listener is still terminal, so shutdown and a genuinely dead
// listener both end the loop rather than spinning.
func TestServeStopsOnClosedListener(t *testing.T) {
	ln := &scriptedListener{script: nil} // every Accept returns net.ErrClosed
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv := &Server{}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve error = %v, want net.ErrClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve kept looping on a closed listener")
	}
}
