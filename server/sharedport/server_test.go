package sharedport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	clientsharedport "github.com/htcondor/cedar/client/sharedport"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

// quietLogger keeps the router's diagnostics out of test output unless a test
// is actually about them.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// acceptWithin bounds a Route.Accept. A router that fails to route leaves
// Accept blocked forever, which would surface only as the package test timeout
// minutes later with no indication of which test was stuck.
func acceptWithin(t *testing.T, route *Route, d time.Duration) net.Conn {
	t.Helper()
	type res struct {
		conn net.Conn
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		conn, err := route.Accept()
		ch <- res{conn, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Accept on route %q: %v", route.ID(), r.err)
		}
		return r.conn
	case <-time.After(d):
		t.Fatalf("no connection routed to %q within %s", route.ID(), d)
		return nil
	}
}

// acceptOrTimeout is acceptWithin for use off the test goroutine, where
// t.Fatalf is not allowed.
func acceptOrTimeout(route *Route, d time.Duration) (net.Conn, error) {
	type res struct {
		conn net.Conn
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		conn, err := route.Accept()
		ch <- res{conn, err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-time.After(d):
		return nil, fmt.Errorf("no connection routed to %q within %s", route.ID(), d)
	}
}

func newTestServer(t *testing.T, opts Options) *Server {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = quietLogger()
	}
	s, err := Listen("127.0.0.1:0", opts)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestRoundTripFromSharedPortClient is the test that matters most: it drives
// the router with this module's own SharedPortClient -- the same code that
// talks to real condor_shared_port daemons -- rather than with a hand-rolled
// request. A router that only satisfies a request this package also wrote
// would prove nothing about the wire.
func TestRoundTripFromSharedPortClient(t *testing.T) {
	srv := newTestServer(t, Options{})

	route, err := srv.Register("")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer func() { _ = route.Close() }()

	want := "<" + srv.AdvertisedAddr() + "?sock=" + route.ID() + ">"
	if route.Sinful() != want {
		t.Errorf("Sinful() = %q, want %q", route.Sinful(), want)
	}

	// Echo whatever arrives on the route, so the test can prove the post-
	// handshake byte stream is intact and correctly positioned.
	done := make(chan error, 1)
	go func() {
		conn, err := acceptOrTimeout(route, 10*time.Second)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			done <- err
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			done <- err
			return
		}
		if _, err := conn.Write(append([]byte("echo:"), buf...)); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	spc := clientsharedport.NewSharedPortClient("test-client")
	st, err := spc.ConnectViaSharedPort(context.Background(), srv.AdvertisedAddr(), route.ID(), 5*time.Second)
	if err != nil {
		t.Fatalf("ConnectViaSharedPort: %v", err)
	}
	conn := st.GetConnection()
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("route side: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("route side never completed; nothing was routed")
	}
	reply := make([]byte, len("echo:hello"))
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(reply) != "echo:hello" {
		t.Errorf("reply = %q, want %q", reply, "echo:hello")
	}

	if got := srv.Stats().Routed; got != 1 {
		t.Errorf("Stats().Routed = %d, want 1", got)
	}
}

// TestPostHandshakeStreamIsCedarClean checks the specific hazard in handing a
// live connection across a protocol boundary: that the router consumed exactly
// the shared-port request and not one byte more, so a fresh CEDAR stream on
// the accepted connection reads what the peer sent next.
func TestPostHandshakeStreamIsCedarClean(t *testing.T) {
	srv := newTestServer(t, Options{})
	route, err := srv.Register("")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer func() { _ = route.Close() }()

	got := make(chan string, 1)
	errc := make(chan error, 1)
	go func() {
		conn, err := acceptOrTimeout(route, 10*time.Second)
		if err != nil {
			errc <- err
			return
		}
		defer func() { _ = conn.Close() }()
		// A brand new stream, exactly as a real consumer would build.
		msg := message.NewMessageFromStream(stream.NewStream(conn))
		s, err := msg.GetString(context.Background())
		if err != nil {
			errc <- err
			return
		}
		got <- s
	}()

	spc := clientsharedport.NewSharedPortClient("test-client")
	st, err := spc.ConnectViaSharedPort(context.Background(), srv.AdvertisedAddr(), route.ID(), 5*time.Second)
	if err != nil {
		t.Fatalf("ConnectViaSharedPort: %v", err)
	}
	defer func() { _ = st.GetConnection().Close() }()

	out := message.NewMessageForStream(st)
	ctx := context.Background()
	if err := out.PutString(ctx, "after-the-handshake"); err != nil {
		t.Fatalf("PutString: %v", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		t.Fatalf("FinishMessage: %v", err)
	}

	select {
	case s := <-got:
		if s != "after-the-handshake" {
			t.Errorf("read %q, want %q", s, "after-the-handshake")
		}
	case err := <-errc:
		t.Fatalf("route side: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the post-handshake message")
	}
}

// sendRequest writes a SHARED_PORT_CONNECT request by hand so tests can send
// things the well-behaved client never would.
func sendRequest(t *testing.T, conn net.Conn, cmd int32, id, name string, deadline int64, extra []string) {
	t.Helper()
	ctx := context.Background()
	msg := message.NewMessageForStream(stream.NewStream(conn))
	if err := msg.PutInt32(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	if err := msg.PutString(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := msg.PutString(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := msg.PutInt64(ctx, deadline); err != nil {
		t.Fatal(err)
	}
	if err := msg.PutInt32(ctx, int32(len(extra))); err != nil {
		t.Fatal(err)
	}
	for _, e := range extra {
		if err := msg.PutString(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := msg.FinishMessage(ctx); err != nil {
		t.Fatal(err)
	}
}

// dialRouter opens a raw TCP connection to the router.
func dialRouter(t *testing.T, srv *Server) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", srv.AdvertisedAddr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial router: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// expectClosed asserts the router hung up without sending anything.
func expectClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("expected the router to close the connection; read %d byte(s): %q", n, buf[:n])
	}
}

// TestMoreArgsAreDrained covers the protocol's forward-compatibility escape
// hatch: a newer client may append arguments this router does not know, and
// SharedPortServer ignores them rather than failing. Routing must survive it,
// and -- the part that actually bites -- the connection must still be
// positioned correctly afterwards.
func TestMoreArgsAreDrained(t *testing.T) {
	srv := newTestServer(t, Options{})
	route, err := srv.Register("with-extras")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer func() { _ = route.Close() }()

	conn := dialRouter(t, srv)
	sendRequest(t, conn, int32(commands.SHARED_PORT_CONNECT), "with-extras", "future-client", 30,
		[]string{"unknown-a", "unknown-b"})
	if _, err := conn.Write([]byte("payload")); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	routed := acceptWithin(t, route, 10*time.Second)
	defer func() { _ = routed.Close() }()
	if err := routed.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("payload"))
	if _, err := io.ReadFull(routed, buf); err != nil {
		t.Fatalf("reading payload after drained args: %v", err)
	}
	if string(buf) != "payload" {
		t.Errorf("payload = %q, want %q", buf, "payload")
	}
}

func TestRejectedRequests(t *testing.T) {
	cases := []struct {
		name  string
		send  func(t *testing.T, srv *Server, conn net.Conn)
		stat  func(Stats) uint64
		label string
	}{
		{
			name: "wrong command",
			send: func(t *testing.T, srv *Server, conn net.Conn) {
				sendRequest(t, conn, int32(commands.SHARED_PORT_PASS_SOCK), "anything", "c", 30, nil)
			},
			stat:  func(s Stats) uint64 { return s.BadRequest },
			label: "BadRequest",
		},
		{
			name: "unregistered id",
			send: func(t *testing.T, srv *Server, conn net.Conn) {
				sendRequest(t, conn, int32(commands.SHARED_PORT_CONNECT), "nobody-home", "c", 30, nil)
			},
			stat:  func(s Stats) uint64 { return s.UnknownID },
			label: "UnknownID",
		},
		{
			name: "id with a path separator",
			send: func(t *testing.T, srv *Server, conn net.Conn) {
				// The id names a registration, never a path, but it has been a
				// filesystem name in every other shared-port implementation --
				// so reject traversal shapes explicitly rather than relying on
				// the lookup to miss.
				sendRequest(t, conn, int32(commands.SHARED_PORT_CONNECT), "../../etc/passwd", "c", 30, nil)
			},
			stat:  func(s Stats) uint64 { return s.BadRequest },
			label: "BadRequest",
		},
		{
			name: "more_args beyond the bound",
			send: func(t *testing.T, srv *Server, conn net.Conn) {
				ctx := context.Background()
				msg := message.NewMessageForStream(stream.NewStream(conn))
				for _, err := range []error{
					msg.PutInt32(ctx, int32(commands.SHARED_PORT_CONNECT)),
					msg.PutString(ctx, "some-id"),
					msg.PutString(ctx, "c"),
					msg.PutInt64(ctx, 30),
					msg.PutInt32(ctx, maxMoreArgs+1),
					msg.FinishMessage(ctx),
				} {
					if err != nil {
						t.Fatal(err)
					}
				}
			},
			stat:  func(s Stats) uint64 { return s.BadRequest },
			label: "BadRequest",
		},
		{
			name: "garbage instead of a request",
			send: func(t *testing.T, srv *Server, conn net.Conn) {
				if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
					t.Fatal(err)
				}
			},
			stat:  func(s Stats) uint64 { return s.BadRequest },
			label: "BadRequest",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, Options{})
			conn := dialRouter(t, srv)
			tc.send(t, srv, conn)
			expectClosed(t, conn)

			// The counter is bumped before the close in handle(), but the
			// close is what we observed, so give the store a moment rather
			// than racing it.
			deadline := time.Now().Add(2 * time.Second)
			for tc.stat(srv.Stats()) == 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if got := tc.stat(srv.Stats()); got != 1 {
				t.Errorf("Stats().%s = %d, want 1 (stats: %+v)", tc.label, got, srv.Stats())
			}
		})
	}
}

// TestRouteCloseUnregisters checks that an id stops routing once its Route is
// closed -- the property that makes per-dial registration safe to reuse.
func TestRouteCloseUnregisters(t *testing.T) {
	srv := newTestServer(t, Options{})
	route, err := srv.Register("transient")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := route.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := route.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Close = %v, want net.ErrClosed", err)
	}

	// The same id is free again.
	again, err := srv.Register("transient")
	if err != nil {
		t.Fatalf("re-Register after Close: %v", err)
	}
	defer func() { _ = again.Close() }()
}

func TestDuplicateRegistrationRejected(t *testing.T) {
	srv := newTestServer(t, Options{})
	r1, err := srv.Register("taken")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer func() { _ = r1.Close() }()
	if _, err := srv.Register("taken"); !errors.Is(err, ErrDuplicateID) {
		t.Errorf("duplicate Register = %v, want ErrDuplicateID", err)
	}
}

func TestRegisterGeneratesDistinctValidIDs(t *testing.T) {
	srv := newTestServer(t, Options{})
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		r, err := srv.Register("")
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		defer func() { _ = r.Close() }()
		if seen[r.ID()] {
			t.Fatalf("duplicate generated id %q", r.ID())
		}
		seen[r.ID()] = true
		if !strings.HasPrefix(r.Sinful(), "<"+srv.AdvertisedAddr()+"?sock=") {
			t.Fatalf("sinful %q does not advertise the router address", r.Sinful())
		}
	}
}

// TestConcurrentRoutesDoNotCross is the property the whole design rests on:
// one port, many simultaneous callers, each getting only its own connection.
func TestConcurrentRoutesDoNotCross(t *testing.T) {
	srv := newTestServer(t, Options{})

	const n = 16
	var wg sync.WaitGroup
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		route, err := srv.Register(fmt.Sprintf("route-%d", i))
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		defer func() { _ = route.Close() }()

		wg.Add(1)
		go func(i int, route *Route) {
			defer wg.Done()
			conn, err := acceptOrTimeout(route, 15*time.Second)
			if err != nil {
				errc <- fmt.Errorf("route %d accept: %w", i, err)
				return
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				errc <- err
				return
			}
			want := fmt.Sprintf("payload-%d", i)
			buf := make([]byte, len(want))
			if _, err := io.ReadFull(conn, buf); err != nil {
				errc <- fmt.Errorf("route %d read: %w", i, err)
				return
			}
			if string(buf) != want {
				errc <- fmt.Errorf("route %d got %q, want %q", i, buf, want)
			}
		}(i, route)
	}

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", srv.AdvertisedAddr(), 5*time.Second)
			if err != nil {
				errc <- err
				return
			}
			defer func() { _ = conn.Close() }()
			ctx := context.Background()
			msg := message.NewMessageForStream(stream.NewStream(conn))
			for _, err := range []error{
				msg.PutInt32(ctx, int32(commands.SHARED_PORT_CONNECT)),
				msg.PutString(ctx, fmt.Sprintf("route-%d", i)),
				msg.PutString(ctx, "concurrent-client"),
				msg.PutInt64(ctx, 30),
				msg.PutInt32(ctx, 0),
				msg.FinishMessage(ctx),
			} {
				if err != nil {
					errc <- err
					return
				}
			}
			if _, err := fmt.Fprintf(conn, "payload-%d", i); err != nil {
				errc <- err
			}
			// Hold the connection open until the reader has had its turn.
			time.Sleep(500 * time.Millisecond)
		}(i)
	}

	wg.Wait()
	close(errc)
	for err := range errc {
		t.Error(err)
	}
	if got := srv.Stats().Routed; got != n {
		t.Errorf("Stats().Routed = %d, want %d", got, n)
	}
}

// TestUndeliveredConnectionIsClosed covers the caller that registers an id and
// then stops accepting: the connection must not be pinned indefinitely.
func TestUndeliveredConnectionIsClosed(t *testing.T) {
	srv := newTestServer(t, Options{DeliveryTimeout: 250 * time.Millisecond})
	route, err := srv.Register("never-accepted")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer func() { _ = route.Close() }()

	// Fill the Route's queue and then one more, which is the one that has to
	// time out; nothing ever calls Accept.
	var conns []net.Conn
	for i := 0; i < routeQueueDepth+1; i++ {
		conn := dialRouter(t, srv)
		sendRequest(t, conn, int32(commands.SHARED_PORT_CONNECT), "never-accepted", "c", 30, nil)
		conns = append(conns, conn)
	}
	last := conns[len(conns)-1]

	if err := last.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := last.Read(buf); err == nil {
		t.Fatal("expected the undelivered connection to be closed")
	}
	if got := srv.Stats().Undelivered; got == 0 {
		t.Errorf("Stats().Undelivered = 0, want at least 1 (stats: %+v)", srv.Stats())
	}
}

// newHookedServer is newTestServer with test hooks installed by setHooks
// before the router starts, so they are in place for the first connection.
func newHookedServer(t *testing.T, setHooks func(*Server)) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := New(Options{Logger: quietLogger()})
	setHooks(srv)
	if err := srv.resolveAdvertised(ln); err != nil {
		t.Fatalf("resolveAdvertised: %v", err)
	}
	go func() { _ = srv.Serve(context.Background(), ln) }()
	return srv
}

// TestRoutedCountedBeforeAcceptReturns covers a consumer that checks Stats as
// soon as it has the connection: Routed must already count it, even while the
// router goroutine that queued it has not run again.
func TestRoutedCountedBeforeAcceptReturns(t *testing.T) {
	queued := make(chan struct{})
	release := make(chan struct{})
	srv := newHookedServer(t, func(s *Server) {
		s.afterDeliver = func() {
			close(queued)
			<-release
		}
	})
	// Close waits for the stalled handler, so release it first.
	t.Cleanup(func() { _ = srv.Close() })
	t.Cleanup(func() { close(release) })

	route, err := srv.Register("counted")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer func() { _ = route.Close() }()

	conn := dialRouter(t, srv)
	sendRequest(t, conn, int32(commands.SHARED_PORT_CONNECT), "counted", "c", 30, nil)
	select {
	case <-queued:
	case <-time.After(10 * time.Second):
		t.Fatal("connection was never queued on the route")
	}

	got := acceptWithin(t, route, 5*time.Second)
	defer func() { _ = got.Close() }()
	if stats := srv.Stats(); stats.Routed != 1 || stats.Undelivered != 0 {
		t.Errorf("after Accept returned: Routed = %d, Undelivered = %d, want 1 and 0 (stats: %+v)",
			stats.Routed, stats.Undelivered, stats)
	}
}

// TestQueuedConnectionClosedWithRouteIsUndelivered covers a connection queued
// on a Route that closes before accepting it: no consumer ever had it, so it
// counts as Undelivered, not Routed.
func TestQueuedConnectionClosedWithRouteIsUndelivered(t *testing.T) {
	queued := make(chan struct{})
	srv := newHookedServer(t, func(s *Server) {
		s.afterDeliver = func() { close(queued) }
	})
	t.Cleanup(func() { _ = srv.Close() })

	route, err := srv.Register("dropped")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	conn := dialRouter(t, srv)
	sendRequest(t, conn, int32(commands.SHARED_PORT_CONNECT), "dropped", "c", 30, nil)
	select {
	case <-queued:
	case <-time.After(10 * time.Second):
		t.Fatal("connection was never queued on the route")
	}

	if err := route.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	expectClosed(t, conn)
	if stats := srv.Stats(); stats.Routed != 0 || stats.Undelivered != 1 {
		t.Errorf("Routed = %d, Undelivered = %d, want 0 and 1 (stats: %+v)",
			stats.Routed, stats.Undelivered, stats)
	}
}

// TestDeliverRacingCloseLeavesNothingQueued covers a Route that closes while
// a connection is being handed to it. deliver's select may still take the send
// after the close, and after shutdown has already drained the queue; the
// connection must be closed and counted as Undelivered, not left queued and
// open. Which select case wins is random, so run enough rounds that both do.
func TestDeliverRacingCloseLeavesNothingQueued(t *testing.T) {
	const rounds = 64
	srv := newHookedServer(t, func(s *Server) {
		s.beforeDeliver = func(r *Route) { _ = r.Close() }
	})
	t.Cleanup(func() { _ = srv.Close() })

	for i := 0; i < rounds; i++ {
		id := fmt.Sprintf("closing-%d", i)
		route, err := srv.Register(id)
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		conn := dialRouter(t, srv)
		sendRequest(t, conn, int32(commands.SHARED_PORT_CONNECT), id, "c", 30, nil)

		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("round %d: connection left open; %d still queued on the closed route (stats: %+v)",
				i, len(route.conns), srv.Stats())
		}
		if err == nil {
			t.Fatalf("round %d: expected the router to close the connection", i)
		}
		if stats := srv.Stats(); stats.Routed != 0 || stats.Undelivered != uint64(i+1) {
			t.Fatalf("round %d: Routed = %d, Undelivered = %d, want 0 and %d (stats: %+v)",
				i, stats.Routed, stats.Undelivered, i+1, stats)
		}
		_ = conn.Close()
	}
}

// TestHandshakeTimeout covers a peer that connects and then says nothing: it
// must not hold a handshake slot forever.
func TestHandshakeTimeout(t *testing.T) {
	srv := newTestServer(t, Options{HandshakeTimeout: 250 * time.Millisecond})
	conn := dialRouter(t, srv)
	expectClosed(t, conn)
	if got := srv.Stats().BadRequest; got == 0 {
		t.Errorf("Stats().BadRequest = 0, want at least 1")
	}
}

// TestWildcardBindRequiresAdvertisedAddr covers the misconfiguration that
// would otherwise be discovered as a reverse connection that never arrives:
// binding the wildcard address and advertising it verbatim gives peers
// "0.0.0.0" to dial.
func TestWildcardBindRequiresAdvertisedAddr(t *testing.T) {
	if _, err := Listen(":0", Options{Logger: quietLogger()}); err == nil {
		t.Fatal("expected a wildcard bind with no AdvertisedAddr to be rejected")
	} else if !strings.Contains(err.Error(), "AdvertisedAddr") {
		t.Errorf("error should name the setting to fix; got %v", err)
	}

	// With one supplied it is fine, and that is what gets advertised.
	srv, err := Listen("127.0.0.1:0", Options{AdvertisedAddr: "condor.example.com:9618", Logger: quietLogger()})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = srv.Close() }()
	route, err := srv.Register("x")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer func() { _ = route.Close() }()
	if route.Sinful() != "<condor.example.com:9618?sock=x>" {
		t.Errorf("Sinful() = %q, want the configured advertised address", route.Sinful())
	}
}

func TestCloseShutsDownRoutes(t *testing.T) {
	srv := newTestServer(t, Options{})
	route, err := srv.Register("live")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := route.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after server Close = %v, want net.ErrClosed", err)
	}
	if _, err := srv.Register("another"); !errors.Is(err, ErrServerClosed) {
		t.Errorf("Register after Close = %v, want ErrServerClosed", err)
	}
}

func TestRegisterBeforeListenFails(t *testing.T) {
	srv := New(Options{Logger: quietLogger()})
	if _, err := srv.Register("early"); err == nil {
		t.Fatal("expected Register before Serve/Listen to fail")
	}
}

func TestRegisterRejectsInvalidID(t *testing.T) {
	srv := newTestServer(t, Options{})
	for _, id := range []string{"has/slash", "has space", "has:colon"} {
		if _, err := srv.Register(id); err == nil {
			t.Errorf("Register(%q) succeeded; want rejection", id)
		}
	}
}
