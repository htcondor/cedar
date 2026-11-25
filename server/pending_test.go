package server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/htcondor/cedar/ccb"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// acceptPair returns a connected client conn and the accepted server conn.
func acceptPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// closedWithin reports whether the server closed conn within d: a read returns
// EOF (or another error) rather than timing out.
func closedWithin(t *testing.T, conn net.Conn, d time.Duration) bool {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(d))
	var b [1]byte
	_, err := conn.Read(b[:])
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return err != nil
}

// TestHandshakeDeadlineClosesIdleConnection: a connection that never sends its
// command is closed once HandshakeDeadline passes.
func TestHandshakeDeadlineClosesIdleConnection(t *testing.T) {
	srv := New(nil)
	srv.HandshakeDeadline = 200 * time.Millisecond
	client, server := acceptPair(t)

	served := make(chan error, 1)
	go func() { served <- srv.ServeConn(context.Background(), server) }()

	if !closedWithin(t, client, 5*time.Second) {
		t.Fatal("idle connection still open after the handshake deadline")
	}
	select {
	case err := <-served:
		if !errors.Is(err, ErrHandshakeDeadline) {
			t.Errorf("ServeConn = %v, want ErrHandshakeDeadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn did not return")
	}
	if n := srv.pending.Load(); n != 0 {
		t.Errorf("%d connections still counted pending", n)
	}
}

// TestHandshakeDeadlineSparesHandler: the deadline stops at the handler; a
// handler running longer than it is not cut off, for a raw command or an
// authenticated one.
func TestHandshakeDeadlineSparesHandler(t *testing.T) {
	const authCmd = 60123
	slowReply := func(ctx context.Context, c *Conn) error {
		time.Sleep(400 * time.Millisecond)
		reply := message.NewMessageForStream(c.Stream)
		if err := reply.PutInt(ctx, 42); err != nil {
			return err
		}
		return reply.FinishMessage(ctx)
	}
	plaintext := func() *security.SecurityConfig {
		return &security.SecurityConfig{
			Authentication: security.SecurityNever,
			Encryption:     security.SecurityNever,
			Integrity:      security.SecurityNever,
		}
	}
	for _, tc := range []struct {
		name string
		send func(ctx context.Context, st *stream.Stream) error
	}{
		{"raw", func(ctx context.Context, st *stream.Stream) error {
			return ccb.WriteReverseConnect(ctx, st, "id", "1", "<10.0.0.9:9618>")
		}},
		{"authenticated", func(ctx context.Context, st *stream.Stream) error {
			cfg := plaintext()
			cfg.Command = authCmd
			_, err := security.NewAuthenticator(cfg, st).ClientHandshake(ctx)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := New(plaintext())
			srv.HandshakeDeadline = 100 * time.Millisecond
			srv.HandleRaw(ccb.CommandReverseConnect, slowReply)
			srv.Handle(authCmd, slowReply)
			client, server := acceptPair(t)
			go func() { _ = srv.ServeConn(context.Background(), server) }()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			st := stream.NewStream(client)
			if err := tc.send(ctx, st); err != nil {
				t.Fatal(err)
			}
			got, err := message.NewMessageFromStream(st).GetInt(ctx)
			if err != nil || got != 42 {
				t.Fatalf("handler reply = %d, %v; want 42", got, err)
			}
		})
	}
}

// TestMaxPendingConnections: beyond MaxPendingConnections connections awaiting
// a handler, a new connection is closed at once; when one of them ends, a new
// one is admitted again.
func TestMaxPendingConnections(t *testing.T) {
	srv := New(nil)
	srv.HandshakeDeadline = 0
	srv.MaxPendingConnections = 2
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serve := func() (net.Conn, chan error) {
		client, server := acceptPair(t)
		served := make(chan error, 1)
		go func() { served <- srv.ServeConn(ctx, server) }()
		return client, served
	}
	waitPending := func(want int64) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for srv.pending.Load() != want {
			if time.Now().After(deadline) {
				t.Fatalf("pending = %d, want %d", srv.pending.Load(), want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	first, firstServed := serve()
	_, _ = serve()
	waitPending(2)

	over, overServed := serve()
	if !closedWithin(t, over, 5*time.Second) {
		t.Fatal("connection over the cap was not closed")
	}
	if err := <-overServed; !errors.Is(err, ErrTooManyPendingConnections) {
		t.Errorf("ServeConn over the cap = %v, want ErrTooManyPendingConnections", err)
	}
	waitPending(2)

	// One pending connection goes away; its slot is free again.
	_ = first.Close()
	if err := <-firstServed; err == nil {
		t.Error("ServeConn returned nil for a connection closed before its command")
	}
	waitPending(1)
	again, _ := serve()
	waitPending(2)
	if closedWithin(t, again, 200*time.Millisecond) {
		t.Error("connection under the cap was closed")
	}
}

// TestAdmitConnectionRefuses: a connection AdmitConnection refuses is closed
// unread, ServeConn reports why, and it does not stay counted as pending.
func TestAdmitConnectionRefuses(t *testing.T) {
	srv := New(nil)
	errBusy := errors.New("source over its rate")
	srv.AdmitConnection = func(net.Conn) (func(), error) { return nil, errBusy }
	client, server := acceptPair(t)

	served := make(chan error, 1)
	go func() { served <- srv.ServeConn(context.Background(), server) }()

	if !closedWithin(t, client, 5*time.Second) {
		t.Fatal("refused connection was not closed")
	}
	err := <-served
	if !errors.Is(err, ErrConnectionNotAdmitted) || !errors.Is(err, errBusy) {
		t.Errorf("ServeConn = %v, want ErrConnectionNotAdmitted wrapping the callback's error", err)
	}
	if n := srv.pending.Load(); n != 0 {
		t.Errorf("%d connections still counted pending", n)
	}
}

// TestAdmitConnectionReleaseBracketsPending: release runs exactly once, when
// the connection leaves the pending phase -- on reaching its handler (before
// the handler finishes), or on the handshake deadline.
func TestAdmitConnectionReleaseBracketsPending(t *testing.T) {
	t.Run("handler", func(t *testing.T) {
		srv := New(nil)
		srv.HandshakeDeadline = 0
		var releases atomic.Int32
		srv.AdmitConnection = func(net.Conn) (func(), error) {
			return func() { releases.Add(1) }, nil
		}
		inHandler := make(chan int32, 1)
		finish := make(chan struct{})
		srv.HandleRaw(ccb.CommandReverseConnect, func(context.Context, *Conn) error {
			inHandler <- releases.Load()
			<-finish
			return nil
		})
		client, server := acceptPair(t)
		served := make(chan error, 1)
		go func() { served <- srv.ServeConn(context.Background(), server) }()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := ccb.WriteReverseConnect(ctx, stream.NewStream(client), "id", "1", "<10.0.0.9:9618>"); err != nil {
			t.Fatal(err)
		}
		select {
		case n := <-inHandler:
			if n != 1 {
				t.Errorf("release ran %d times before the handler, want 1", n)
			}
		case <-ctx.Done():
			t.Fatal("handler never ran")
		}
		close(finish)
		if err := <-served; err != nil {
			t.Errorf("ServeConn = %v", err)
		}
		if n := releases.Load(); n != 1 {
			t.Errorf("release ran %d times, want 1", n)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		srv := New(nil)
		srv.HandshakeDeadline = 100 * time.Millisecond
		var releases atomic.Int32
		srv.AdmitConnection = func(net.Conn) (func(), error) {
			return func() { releases.Add(1) }, nil
		}
		_, server := acceptPair(t)
		served := make(chan error, 1)
		go func() { served <- srv.ServeConn(context.Background(), server) }()
		select {
		case err := <-served:
			if !errors.Is(err, ErrHandshakeDeadline) {
				t.Errorf("ServeConn = %v, want ErrHandshakeDeadline", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ServeConn did not return")
		}
		if n := releases.Load(); n != 1 {
			t.Errorf("release ran %d times, want 1", n)
		}
	})
}

// TestAdmitConnectionSkippedOverGlobalCap: a connection refused by
// MaxPendingConnections never reaches AdmitConnection, so a callback counting
// what it admitted is not left holding a slot nothing will release.
func TestAdmitConnectionSkippedOverGlobalCap(t *testing.T) {
	srv := New(nil)
	srv.HandshakeDeadline = 0
	srv.MaxPendingConnections = 1
	var admitted, released atomic.Int32
	srv.AdmitConnection = func(net.Conn) (func(), error) {
		admitted.Add(1)
		return func() { released.Add(1) }, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, first := acceptPair(t)
	go func() { _ = srv.ServeConn(ctx, first) }()
	deadline := time.Now().Add(5 * time.Second)
	for admitted.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("first connection never admitted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, over := acceptPair(t)
	if err := srv.ServeConn(ctx, over); !errors.Is(err, ErrTooManyPendingConnections) {
		t.Fatalf("ServeConn over the cap = %v, want ErrTooManyPendingConnections", err)
	}
	if n := admitted.Load(); n != 1 {
		t.Errorf("AdmitConnection ran %d times, want 1", n)
	}
	if n := released.Load(); n != 0 {
		t.Errorf("release ran %d times with the first connection still pending", n)
	}
}
