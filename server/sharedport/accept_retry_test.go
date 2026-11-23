package sharedport

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

// scriptedListener returns a scripted sequence of Accept outcomes. A nil entry
// means "hand over one connection"; running off the end means closed.
type scriptedListener struct {
	mu        sync.Mutex
	script    []error
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

// A transient Accept failure must not end the router's accept loop. Returning
// on any error made descriptor exhaustion permanent: the loop exited, the
// listener stayed bound so nothing else could take the port, and every
// shared-port id this process advertises became unreachable.
func TestServeRetriesTransientAcceptErrors(t *testing.T) {
	ln := &scriptedListener{script: []error{
		errOutOfDescriptors,
		errOutOfDescriptors,
		errOutOfDescriptors,
		nil, // descriptors free again: a connection gets through
	}}
	defer func() { _ = ln.Close() }()

	srv := New(Options{Logger: quietLogger()})
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	select {
	case err := <-done:
		if errors.Is(err, errOutOfDescriptors) {
			t.Fatal("Serve returned the transient accept error instead of retrying")
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
	if got := srv.Stats().Accepted; got != 1 {
		t.Errorf("Stats().Accepted = %d, want 1", got)
	}
}

// A closed listener stays terminal, so a genuinely dead listener ends the loop
// instead of spinning on it forever.
func TestServeStopsOnClosedListener(t *testing.T) {
	ln := &scriptedListener{script: nil} // every Accept returns net.ErrClosed
	defer func() { _ = ln.Close() }()

	srv := New(Options{Logger: quietLogger()})
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve error = %v, want it to wrap net.ErrClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve kept looping on a closed listener")
	}
}

// Shutdown through Close must still unblock Serve with ErrServerClosed, not be
// mistaken for a transient failure and retried.
func TestServeReturnsServerClosedOnClose(t *testing.T) {
	// Descriptors never free up, so the loop stays in retry until Close.
	persistent := make([]error, 1000)
	for i := range persistent {
		persistent[i] = errOutOfDescriptors
	}
	ln := &scriptedListener{script: persistent}
	defer func() { _ = ln.Close() }()

	srv := New(Options{Logger: quietLogger()})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	// Let the loop reach its retry sleep, then shut down.
	time.Sleep(20 * time.Millisecond)
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, ErrServerClosed) {
			t.Errorf("Serve error = %v, want ErrServerClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not unblock Serve from its accept retry")
	}
}
