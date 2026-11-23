// Package sharedport implements the server half of HTCondor's shared-port
// connect protocol, routing accepted connections to in-process registrations
// rather than to other processes.
//
// HTCondor's condor_shared_port multiplexes one TCP port across many daemons:
// a client dials the port, names a "sock id" with a SHARED_PORT_CONNECT
// request, and the server hands the connected file descriptor to whichever
// daemon owns that id (SCM_RIGHTS over a Unix socket). This package speaks the
// same client-facing protocol but stops short of the fd pass: an id is
// registered by a caller in this process, and a connection for it is delivered
// as a net.Conn on a Route that implements net.Listener.
//
// That is enough to serve the case this exists for. A process behind a
// firewall cannot accept CCB's connection reversal, because the private daemon
// is told to dial back to an address nothing routes to. It can, however,
// advertise "<host:port?sock=NAME>" for a port it does own, since every
// HTCondor connect path honors a shared-port id on any sinful -- including the
// reverse-connect address a CCB broker relays to the target (see
// Sock::special_connect in src/condor_io/sock.cpp). One inbound port then
// serves any number of concurrent reverse connections, each addressed by an
// unguessable id, with no condor_shared_port daemon and no fd passing.
//
// The protocol on the wire, per SharedPortClient::sendSharedPortID in
// src/condor_io/shared_port_client.cpp, is a single CEDAR message:
//
//	int    SHARED_PORT_CONNECT (75)
//	string shared port id
//	string client name (debugging only)
//	int    deadline, in seconds remaining, or -1 for none
//	int    more_args, followed by that many strings to ignore
//
// There is no reply. The client then resets its stream and speaks whatever
// protocol the target daemon expects, so the connection handed to a Route is
// positioned at the first byte after the request and must be wrapped in a
// fresh stream.
package sharedport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

const (
	// defaultHandshakeTimeout bounds one SHARED_PORT_CONNECT exchange. The
	// request is a single small message sent immediately on connect, so this
	// only has to be generous enough for a slow network, not for anything the
	// peer might think about.
	defaultHandshakeTimeout = 20 * time.Second

	// defaultDeliveryTimeout bounds how long a routed connection waits for its
	// Route to accept it. A Route is normally parked in Accept before the peer
	// dials, so this is a backstop against a caller that registered an id and
	// then stopped accepting: without it the connection (and its goroutine)
	// would be pinned until the peer gave up.
	defaultDeliveryTimeout = 30 * time.Second

	// defaultMaxPending bounds concurrent in-flight handshakes. The port is
	// open to anyone who can route to it and the handshake precedes any
	// authentication, so an unbounded accept loop is a free way to make this
	// process allocate.
	defaultMaxPending = 256

	// maxStringField mirrors the fixed 1024-byte buffers SharedPortServer
	// reads the id and client name into (shared_port_server.cpp).
	maxStringField = 1024

	// maxMoreArgs mirrors SharedPortServer's bound on the trailing
	// forward-compatibility arguments.
	maxMoreArgs = 100

	// routeQueueDepth is how many connections a Route buffers for a consumer
	// that is between Accept calls. Reverse connections arrive one per dial,
	// so this only absorbs bursts.
	routeQueueDepth = 4
)

// ErrServerClosed is returned by Serve after Close, and by Register once the
// server is closed.
var ErrServerClosed = errors.New("sharedport: server closed")

// ErrDuplicateID is returned by Register when the id is already registered.
var ErrDuplicateID = errors.New("sharedport: shared port id already registered")

// Options configures a Server.
type Options struct {
	// AdvertisedAddr is the "host:port" a peer dials to reach this server. It
	// is the only thing a Route's sinful can be built from, and it is not
	// always the bound address: behind NAT, a container port mapping, or a
	// Kubernetes Service, what peers dial is not what this process bound.
	//
	// It may be left empty only when the listener is bound to a specific
	// address (not the wildcard), in which case the bound address is used.
	// Serve fails rather than guessing otherwise -- an unroutable advertised
	// address fails later, at the far end, as a connection that never arrives.
	AdvertisedAddr string

	// HandshakeTimeout bounds one SHARED_PORT_CONNECT exchange (default 20s).
	HandshakeTimeout time.Duration

	// DeliveryTimeout bounds how long a routed connection waits to be accepted
	// by its Route (default 30s).
	DeliveryTimeout time.Duration

	// MaxPending bounds concurrent in-flight handshakes (default 256).
	// Connections beyond it are closed immediately.
	MaxPending int

	// Logger receives protocol diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
}

// Stats counts what the router has done, for logging and for tests that need
// to prove a connection actually took this path.
type Stats struct {
	// Accepted is connections accepted on the listener.
	Accepted uint64
	// Routed is connections handed to a Route's consumer by Accept. It is
	// counted before Accept returns, so a caller that has the connection
	// already sees it here.
	Routed uint64
	// UnknownID is requests naming an id nobody has registered. Expected in
	// small numbers (a dial that races a Route's Close); a steady stream means
	// a stale advertised address or a port scan.
	UnknownID uint64
	// BadRequest is connections that failed the handshake: not a
	// SHARED_PORT_CONNECT, malformed, or too slow.
	BadRequest uint64
	// Undelivered is connections for a registered id that no one accepted:
	// not taken within DeliveryTimeout, or still queued when the Route closed.
	Undelivered uint64
	// Overloaded is connections closed without a handshake because MaxPending
	// in-flight handshakes were already running.
	Overloaded uint64
}

// Server routes connections arriving on one TCP port to in-process
// registrations keyed by shared-port id.
type Server struct {
	opts Options
	log  *slog.Logger

	mu        sync.Mutex
	routes    map[string]*Route
	advertise string // resolved AdvertisedAddr; set by Serve
	closed    bool

	pending chan struct{} // semaphore bounding in-flight handshakes
	done    chan struct{}
	handles sync.WaitGroup

	accepted, routed, unknownID, badRequest, undelivered, overloaded atomic.Uint64

	// beforeDeliver and afterDeliver, if set, run in handle just before a
	// connection is handed to its Route and once it has been queued there.
	// Tests use them to force interleavings with the Route's consumer.
	beforeDeliver func(*Route)
	afterDeliver  func()
}

// New creates a Server. It does not listen; pass a listener to Serve.
func New(opts Options) *Server {
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = defaultHandshakeTimeout
	}
	if opts.DeliveryTimeout <= 0 {
		opts.DeliveryTimeout = defaultDeliveryTimeout
	}
	if opts.MaxPending <= 0 {
		opts.MaxPending = defaultMaxPending
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		opts:      opts,
		log:       log,
		routes:    make(map[string]*Route),
		advertise: strings.TrimSpace(opts.AdvertisedAddr),
		pending:   make(chan struct{}, opts.MaxPending),
		done:      make(chan struct{}),
	}
}

// Listen binds addr, starts routing on it in the background, and returns the
// running Server. Close stops it.
func Listen(addr string, opts Options) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sharedport: listen %s: %w", addr, err)
	}
	s := New(opts)
	if err := s.resolveAdvertised(ln); err != nil {
		_ = ln.Close()
		return nil, err
	}
	go func() {
		if err := s.Serve(context.Background(), ln); err != nil && !errors.Is(err, ErrServerClosed) {
			s.log.Error("shared-port router stopped", "error", err)
		}
	}()
	return s, nil
}

// AdvertisedAddr is the "host:port" peers dial to reach this server, as
// resolved by Listen or Serve. Empty before either has run.
func (s *Server) AdvertisedAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.advertise
}

// resolveAdvertised fixes the advertised address from the configured value or
// the listener's own, and rejects a wildcard bind with nothing configured.
func (s *Server) resolveAdvertised(ln net.Listener) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.advertise != "" {
		return nil
	}
	addr := ln.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("sharedport: cannot derive advertised address from %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		return fmt.Errorf("sharedport: listener is bound to %q, which peers cannot dial; set Options.AdvertisedAddr to the host:port they should use", addr)
	}
	s.advertise = net.JoinHostPort(host, port)
	return nil
}

// Serve routes connections accepted on ln until ctx is cancelled or Close is
// called, then returns ErrServerClosed. ln is closed on return.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if err := s.resolveAdvertised(ln); err != nil {
		_ = ln.Close()
		return err
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-s.done:
		}
		_ = ln.Close()
	}()
	defer func() { _ = ln.Close() }()

	// Backoff for a listener that is still open but momentarily cannot produce
	// a connection, as when the process is out of file descriptors.
	const (
		acceptRetryMin = 5 * time.Millisecond
		acceptRetryMax = time.Second
	)
	var acceptDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ErrServerClosed
			case <-s.done:
				return ErrServerClosed
			default:
			}
			// Only a closed listener is terminal. Returning on every error
			// made a transient descriptor exhaustion (EMFILE/ENFILE)
			// permanent: the router exited, the listener stayed bound so
			// nothing else could take the port, and every shared-port id this
			// process advertises became unreachable even once descriptors were
			// free again. MaxPending does not prevent it -- the descriptor is
			// spent by Accept, before the pending check below runs.
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("sharedport: accept: %w", err)
			}
			if acceptDelay == 0 {
				acceptDelay = acceptRetryMin
			} else if acceptDelay *= 2; acceptDelay > acceptRetryMax {
				acceptDelay = acceptRetryMax
			}
			s.log.Error("shared-port router: accept failed; retrying",
				"error", err, "retry_in", acceptDelay)
			select {
			case <-time.After(acceptDelay):
			case <-ctx.Done():
				return ErrServerClosed
			case <-s.done:
				return ErrServerClosed
			}
			continue
		}
		acceptDelay = 0
		s.accepted.Add(1)

		select {
		case s.pending <- struct{}{}:
		default:
			// At MaxPending in-flight handshakes. Drop rather than queue: a
			// caller waiting on a reverse connection has its own deadline, and
			// a connection we cannot get to promptly is one it has given up on.
			s.overloaded.Add(1)
			s.log.Warn("shared-port router dropping connection: too many handshakes in flight",
				"peer", conn.RemoteAddr().String(), "max_pending", s.opts.MaxPending)
			_ = conn.Close()
			continue
		}

		s.handles.Add(1)
		go func() {
			defer s.handles.Done()
			defer func() { <-s.pending }()
			s.handle(ctx, conn)
		}()
	}
}

// Close stops the server, unblocks Serve, and unregisters every Route. It
// waits for in-flight handshakes to finish. Connections already delivered to a
// Route are left alone: they belong to whoever accepted them.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	routes := make([]*Route, 0, len(s.routes))
	for _, r := range s.routes {
		routes = append(routes, r)
	}
	s.routes = make(map[string]*Route)
	s.mu.Unlock()

	close(s.done)
	for _, r := range routes {
		r.shutdown()
	}
	s.handles.Wait()
	return nil
}

// Stats returns a snapshot of the router's counters.
func (s *Server) Stats() Stats {
	return Stats{
		Accepted:    s.accepted.Load(),
		Routed:      s.routed.Load(),
		UnknownID:   s.unknownID.Load(),
		BadRequest:  s.badRequest.Load(),
		Undelivered: s.undelivered.Load(),
		Overloaded:  s.overloaded.Load(),
	}
}

// Register claims a shared-port id and returns the Route that receives
// connections addressed to it. An empty id generates a random one, which is
// what a per-dial registration wants: the id travels to the peer inside the
// advertised sinful and is the only thing distinguishing one caller's inbound
// connection from another's, so it should not be guessable.
//
// The caller must Close the Route when done, which unregisters the id.
func (s *Server) Register(id string) (*Route, error) {
	if id == "" {
		generated, err := randomID()
		if err != nil {
			return nil, err
		}
		id = generated
	}
	if !addresses.IsValidSharedPortID(id) {
		return nil, fmt.Errorf("sharedport: invalid shared port id %q", id)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrServerClosed
	}
	if s.advertise == "" {
		return nil, errors.New("sharedport: server is not listening yet; call Listen or Serve before Register")
	}
	if _, exists := s.routes[id]; exists {
		return nil, fmt.Errorf("%w: %s", ErrDuplicateID, redactID(id))
	}
	r := &Route{
		srv:    s,
		id:     id,
		sinful: "<" + s.advertise + "?sock=" + id + ">",
		conns:  make(chan net.Conn, routeQueueDepth),
		closed: make(chan struct{}),
		addr:   routeAddr(s.advertise + "?sock=" + id),
	}
	s.routes[id] = r
	return r, nil
}

// lookup finds a registered Route, or nil.
func (s *Server) lookup(id string) *Route {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routes[id]
}

// unregister removes a Route's id, if it is still the registered owner.
func (s *Server) unregister(r *Route) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.routes[r.id]; ok && cur == r {
		delete(s.routes, r.id)
	}
}

// handle reads one SHARED_PORT_CONNECT request and routes the connection.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	peer := conn.RemoteAddr().String()

	if err := conn.SetDeadline(time.Now().Add(s.opts.HandshakeTimeout)); err != nil {
		s.badRequest.Add(1)
		_ = conn.Close()
		return
	}
	id, clientName, err := readConnectRequest(ctx, conn)
	if err != nil {
		s.badRequest.Add(1)
		// Debug, not warn: this port is reachable by anything that can route
		// to it, so a health check or a scanner produces these routinely.
		s.log.Debug("shared-port request rejected", "peer", peer, "error", err)
		_ = conn.Close()
		return
	}

	route := s.lookup(id)
	if route == nil {
		s.unknownID.Add(1)
		s.log.Debug("shared-port request for an unregistered id",
			"peer", peer, "sock", redactID(id), "client", clientName)
		_ = conn.Close()
		return
	}

	// Hand the peer a connection with no deadline of our making: from here on
	// the timeouts that matter are the accepting caller's.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		s.badRequest.Add(1)
		_ = conn.Close()
		return
	}

	if s.beforeDeliver != nil {
		s.beforeDeliver(route)
	}
	// Routed is counted by Accept, not here: once deliver queues the
	// connection the consumer can take it and finish its whole exchange
	// before this goroutine runs again.
	if route.deliver(ctx, conn, s.opts.DeliveryTimeout) {
		if s.afterDeliver != nil {
			s.afterDeliver()
		}
		s.log.Debug("shared-port connection queued", "peer", peer, "sock", redactID(id), "client", clientName)
		return
	}
	s.undelivered.Add(1)
	s.log.Warn("shared-port connection went unaccepted", "peer", peer, "sock", redactID(id), "client", clientName)
	_ = conn.Close()
}

// readConnectRequest consumes exactly the SHARED_PORT_CONNECT message and
// returns the requested id and the client's self-description.
//
// It must not read past the end of that message: the bytes after it are the
// peer's first real protocol message, and they stay on the connection for
// whoever accepts it. CEDAR's reader is frame-at-a-time with no read-ahead
// beyond the frame carrying the end-of-message flag, so consuming every field
// of this one-frame request leaves the connection positioned exactly there.
func readConnectRequest(ctx context.Context, conn net.Conn) (id, clientName string, err error) {
	msg := message.NewMessageFromStream(stream.NewStream(conn))

	cmd, err := msg.GetInt32(ctx)
	if err != nil {
		return "", "", fmt.Errorf("reading command: %w", err)
	}
	if cmd != int32(commands.SHARED_PORT_CONNECT) {
		return "", "", fmt.Errorf("got command %d, want SHARED_PORT_CONNECT (%d)", cmd, commands.SHARED_PORT_CONNECT)
	}
	id, err = msg.GetStringWithMaxSize(ctx, maxStringField)
	if err != nil {
		return "", "", fmt.Errorf("reading shared port id: %w", err)
	}
	clientName, err = msg.GetStringWithMaxSize(ctx, maxStringField)
	if err != nil {
		return "", "", fmt.Errorf("reading client name: %w", err)
	}
	if _, err := msg.GetInt64(ctx); err != nil { // deadline; advisory, and we impose our own
		return "", "", fmt.Errorf("reading deadline: %w", err)
	}
	moreArgs, err := msg.GetInt32(ctx)
	if err != nil {
		return "", "", fmt.Errorf("reading more_args: %w", err)
	}
	if moreArgs < 0 || moreArgs > maxMoreArgs {
		return "", "", fmt.Errorf("invalid more_args %d", moreArgs)
	}
	// Reserved for future use by the protocol; drain and ignore, as
	// SharedPortServer does, so a newer client still routes.
	for i := int32(0); i < moreArgs; i++ {
		if _, err := msg.GetStringWithMaxSize(ctx, maxStringField); err != nil {
			return "", "", fmt.Errorf("reading trailing argument %d: %w", i, err)
		}
	}
	if !addresses.IsValidSharedPortID(id) {
		return "", "", fmt.Errorf("invalid shared port id %q", id)
	}
	return id, clientName, nil
}

// generatedIDPrefix marks an id this package minted, as opposed to one the
// caller named.
const generatedIDPrefix = "cedar-"

// randomID generates an unguessable shared-port id made only of characters
// IsValidSharedPortID accepts.
func randomID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("sharedport: generating id: %w", err)
	}
	return generatedIDPrefix + hex.EncodeToString(buf[:]), nil
}

// redactID returns a short, log-safe rendering of a shared-port id, mirroring
// security.redactSessionID. An id is a capability: the router performs no
// authentication, so whoever knows an id is handed the connections addressed
// to it, and HTCondor's daemon logs are world-readable on stock installs (mode
// 0644). The first 8 characters (32 bits for a hex id) are kept so the log
// lines for one connection can still be correlated, and the rest is dropped
// behind an ASCII "...". For an id we generated the kept characters are
// counted past the constant "cedar-" prefix, which carries no entropy.
// Returns "<empty>" for the empty string so a missing id stays distinguishable
// from a present one.
//
// Every site in this package that renders an id into a log line or an error
// goes through this helper; errors count, because a caller logs them.
func redactID(id string) string {
	if id == "" {
		return "<empty>"
	}
	keep := 8
	if strings.HasPrefix(id, generatedIDPrefix) {
		keep += len(generatedIDPrefix)
	}
	if len(id) <= keep {
		return id + "..."
	}
	return id[:keep] + "..."
}
