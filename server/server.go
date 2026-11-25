// Package server provides reusable scaffolding for building CEDAR command
// servers (daemons that accept connections, authenticate, and dispatch
// HTCondor commands). It complements the client-focused packages in this
// module.
//
// Two kinds of command handlers are supported:
//
//   - Authenticated commands: the client opens the exchange with a
//     DC_AUTHENTICATE command and a security ClassAd that carries the real
//     command (e.g. CCB_REGISTER). The server performs the security handshake
//     and dispatches on the real command. A DC_SEC_QUERY (condor_ping) or a
//     DC_AUTHENTICATE real command dispatches nothing: the server authorizes
//     the command the client names as AuthCommand and answers for it.
//   - Raw commands: the client sends a bare command integer with no security
//     handshake (e.g. CCB_REVERSE_CONNECT, which HTCondor registers as ALLOW
//     and sends via the "raw" command protocol). These are dispatched
//     directly with no authentication.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// Conn is the per-connection context handed to a command handler.
type Conn struct {
	// Stream is the CEDAR stream for the connection. For authenticated
	// commands it is authenticated (and possibly encrypted) by the time the
	// handler runs; for raw commands it is plaintext.
	Stream *stream.Stream

	// Command is the real HTCondor command being dispatched.
	Command int

	// Negotiation is the result of the security handshake, or nil for raw
	// commands. Its User is the peer's authenticated identity, or "" when the
	// session did not authenticate (see AuthorizationUser).
	Negotiation *security.SecurityNegotiation

	// Message is the inbound Message the leading command integer was read
	// from. Raw-command handlers read their payload (e.g. a ClassAd) from
	// this message; authenticated handlers normally start a fresh message.
	// For a follow-on command on a kept-alive connection (see KeepAlive) it is
	// the message the follow-on command integer was read from, so the handler
	// reads that command's ad from the same message.
	Message *message.Message

	// RemoteAddr is the peer's network address.
	RemoteAddr string

	// keepAlive, set via KeepAlive, asks the server to keep the connection open
	// after this handler and read a follow-on command integer on the same
	// (already-established) session -- HTCondor's persistent command socket, how
	// a daemon streams several updates (schedd ad + submitter ads, ...) down one
	// connection without re-authenticating.
	keepAlive bool
}

// KeepAlive requests that, after this handler returns nil, the server keep the
// connection open and dispatch the next command the peer sends on the same
// session (rather than closing). Used by update handlers to serve HTCondor's
// persistent command-socket protocol. Ignored if the handler returns an error.
func (c *Conn) KeepAlive() { c.keepAlive = true }

// PeerVersion returns the peer's reported $CondorVersion$ string, or "" if it
// was not exchanged (e.g. for raw commands).
func (c *Conn) PeerVersion() string {
	if c.Negotiation != nil && c.Negotiation.ClientConfig != nil {
		return c.Negotiation.ClientConfig.RemoteVersion
	}
	return ""
}

// AuthorizationUser returns the identity to authorize this connection's peer as:
// its authenticated identity, or UnauthenticatedFQU when the peer did not
// authenticate (including raw commands). Handlers that consult an authorizer
// themselves should pass this rather than Negotiation.User.
func (c *Conn) AuthorizationUser() string {
	if c.Negotiation == nil {
		return UnauthenticatedFQU
	}
	return authorizationUser(c.Negotiation.User, c.Negotiation.Authentication)
}

// AuthorizationLimits returns the authorization levels the peer's credential
// was limited to (e.g. by an IDTOKEN's "condor:/<LEVEL>" scopes), or nil if the
// session has no such bounding set (including raw commands). The server applies
// it to the command's registered levels before dispatch; a handler that
// authorizes at some other level itself should also check that level with
// InAuthorizationBoundingSet, as HTCondor daemons call
// Sock::isAuthorizationInBoundingSet.
func (c *Conn) AuthorizationLimits() []string {
	if c.Negotiation == nil {
		return nil
	}
	return c.Negotiation.AuthorizationLimits
}

// InAuthorizationBoundingSet reports whether the session's authorization
// bounding set permits the level perm: always for ALLOW or a session with no
// bounding set, otherwise if perm is one of its levels or a level one of them
// implies (DAEMON implies WRITE and READ, ADVERTISE_STARTD implies READ, ...).
func (c *Conn) InAuthorizationBoundingSet(perm string) bool {
	return security.AuthorizationLimitsPermit(c.AuthorizationLimits(), []string{perm})
}

// UnauthenticatedFQU is the identity HTCondor gives a peer that did not
// authenticate (UNAUTHENTICATED_FQU, src/condor_io/authentication.cpp).
// Sock::getFullyQualifiedUser (sock.cpp) returns it for an unauthenticated
// socket and DaemonCore passes that to IpVerify::Verify (daemon_command.cpp), so
// an ALLOW_* list admits such a peer only through an entry matching this string,
// e.g. "*" or "unauthenticated@unmapped". It is not "", which IpVerify::Verify
// treats as the wildcard user "*" (condor_ipverify.cpp).
const UnauthenticatedFQU = "unauthenticated@unmapped"

// authorizationUser returns user if the session authenticated, else
// UnauthenticatedFQU: an identity on an unauthenticated session (e.g. recorded
// on a cached session, or left by a failed method) was not proven by the peer.
func authorizationUser(user string, authenticated bool) string {
	if !authenticated {
		return UnauthenticatedFQU
	}
	return user
}

// HandlerFunc handles a single dispatched command. Returning an error closes
// the connection unless the handler has taken ownership of it (see KeepOpen).
type HandlerFunc func(ctx context.Context, c *Conn) error

type registeredHandler struct {
	fn    HandlerFunc
	raw   bool
	perms []string
}

// Server accepts CEDAR connections and dispatches commands to handlers.
type Server struct {
	// SecurityConfig is used for the server side of the security handshake on
	// authenticated commands. It must be non-nil if any authenticated handler
	// is registered.
	SecurityConfig *security.SecurityConfig

	// SecurityConfigForCommand, if set, selects a per-command security policy for
	// the handshake: once the client's requested command is known, the returned
	// config replaces SecurityConfig for that connection's negotiation. This lets
	// a daemon serve different commands at different HTCondor authorization levels
	// (e.g. a collector negotiating a QUERY at READ but an UPDATE at ADVERTISE).
	// Returning nil falls back to SecurityConfig. A returned config without its
	// own PostAuthPolicy or CommandPerms takes SecurityConfig's (installed by
	// New), so FQUMapper, the advertised ValidCommands and authorization limits
	// apply whatever the command's policy. Optional.
	SecurityConfigForCommand func(command int) *security.SecurityConfig

	// Authorizer, if set, reports whether a peer is allowed at a given
	// authorization level. perm is an HTCondor DCpermission name (e.g. "READ",
	// "DAEMON"); peerAddr is the peer's "host:port"; user is the mapped FQU of an
	// authenticated peer, or UnauthenticatedFQU for one that did not
	// authenticate, whatever identity its session records. The server consults
	// it — for every registered authenticated command's levels — to compute the
	// session's ValidCommands after authentication, so a peer can reuse the
	// session for any command it is authorized for. It also authorizes every
	// command before dispatch, except a command registered with no levels,
	// which carries no authorization requirement; on a full handshake that
	// happens before the handshake's reply, so a refused command is answered
	// DENIED and its session is not cached. Leaving it nil advertises only the
	// negotiated command (no authorization table applied).
	Authorizer func(perm, peerAddr, user string) bool

	// FQUMapper, if set, maps an authenticated identity to the fully-qualified
	// user to advertise and authorize as (e.g. via a mapfile). authUser is the
	// FQU the authentication method produced, as C++ HTCondor reports it before
	// any map file (e.g. condor@pool for an IDTOKENS peer, alice@$(UID_DOMAIN)
	// for FS). As with a C++ map file's result, a returned name without an '@'
	// takes SecurityConfig's UID domain (security.SecurityConfig.CanonicalUser).
	// Returning "" keeps the authenticated identity. Optional.
	FQUMapper func(authUser, peerAddr string) string

	// KeepAlive configures TCP keepalives applied to every connection accepted
	// in Serve. New() initializes it to stream.DefaultKeepAliveConfig
	// (SO_KEEPALIVE on; idle 360s, interval 5s, count 5), mirroring C++
	// HTCondor which enables keepalives on accepted daemon sockets so a
	// silently-dead peer (e.g. a powered-off execute host) is detected rather
	// than leaking a blocked handler goroutine. Set Enable=false to disable.
	KeepAlive stream.KeepAliveConfig

	// HandshakeDeadline bounds how long a connection may take to reach its
	// handler: reading the command and, for an authenticated command, the
	// whole security handshake. A connection still short of its handler then
	// is closed. Handlers themselves are not bounded by it, nor are follow-on
	// commands on a kept-alive connection. It matches DaemonCore's
	// SEC_TCP_SESSION_DEADLINE, the deadline C++ sets on a new command socket
	// while it waits for the command protocol to finish. New() sets it to
	// DefaultHandshakeDeadline; zero means no deadline.
	HandshakeDeadline time.Duration

	// MaxPendingConnections caps the connections that have not yet reached
	// a handler (those HandshakeDeadline bounds), so unauthenticated peers
	// cannot hold an unbounded number of descriptors and goroutines. A
	// connection beyond the cap is closed at once. New() sets it to
	// DefaultMaxPendingConnections; zero or less means no cap. DaemonCore has
	// no inbound counterpart: its NETWORK_MAX_PENDING_CONNECTS limits
	// outbound connection attempts.
	MaxPendingConnections int

	// AdmitConnection, if set, decides whether to take a connection before
	// anything is read from it. Serve calls it once per connection, after the
	// MaxPendingConnections check; ServeConn does too, so a connection a
	// program hands it directly is subject to the same policy (a program that
	// trusts such a connection can recognise it in the callback).
	//
	// A non-nil error refuses the connection: it is closed unread and ServeConn
	// returns the error wrapped in ErrConnectionNotAdmitted. Otherwise release,
	// if non-nil, runs exactly once when the connection leaves the pending
	// phase -- it reached its handler, or it failed or ran out of
	// HandshakeDeadline first. Between the two the connection is pending, so a
	// program can bound what one source holds there (a per-source
	// MaxPendingConnections) as well as how often it may connect.
	//
	// It runs on the accept path, so it must be quick and must not block.
	AdmitConnection func(conn net.Conn) (release func(), err error)

	pending atomic.Int64

	mu       sync.RWMutex
	handlers map[int]registeredHandler
}

// DefaultHandshakeDeadline is SEC_TCP_SESSION_DEADLINE's default.
const DefaultHandshakeDeadline = 120 * time.Second

// DefaultMaxPendingConnections is New's MaxPendingConnections.
const DefaultMaxPendingConnections = 4096

// ErrTooManyPendingConnections is returned by ServeConn for a connection
// refused because MaxPendingConnections connections are already pending.
var ErrTooManyPendingConnections = errors.New("cedar/server: too many connections awaiting a handler")

// ErrHandshakeDeadline is returned by ServeConn for a connection closed
// because it did not reach its handler within HandshakeDeadline.
var ErrHandshakeDeadline = errors.New("cedar/server: connection did not reach a handler before the handshake deadline")

// ErrConnectionNotAdmitted is returned by ServeConn, wrapping the callback's
// error, for a connection AdmitConnection refused.
var ErrConnectionNotAdmitted = errors.New("cedar/server: connection not admitted")

// New creates a Server with the given server-side security configuration. It
// installs the server's ValidCommands computation as the security layer's
// post-auth policy, so authenticating peers learn every command they are
// authorized for (see Authorizer).
func New(secConfig *security.SecurityConfig) *Server {
	s := &Server{
		SecurityConfig: secConfig,
		handlers:       map[int]registeredHandler{},
		KeepAlive:      stream.DefaultKeepAliveConfig(),

		HandshakeDeadline:     DefaultHandshakeDeadline,
		MaxPendingConnections: DefaultMaxPendingConnections,
	}
	if secConfig != nil {
		secConfig.PostAuthPolicy = s.postAuthPolicy
		// Lets the security layer drop from the advertised commands those
		// outside a limited credential's bounding set.
		secConfig.CommandPerms = s.CommandPerms
	}
	return s
}

// inheritPolicyHooks gives a per-command config (SecurityConfigForCommand) the
// post-auth policy and command levels New installed on SecurityConfig, unless
// it sets its own, so a session negotiated under it maps its identity
// (FQUMapper), advertises every command it is authorized for, and is bounded
// by its credential's authorization limits as one negotiated under
// SecurityConfig is.
func (s *Server) inheritPolicyHooks(c *security.SecurityConfig) {
	if c.PostAuthPolicy == nil {
		c.PostAuthPolicy = s.SecurityConfig.PostAuthPolicy
	}
	if c.CommandPerms == nil {
		c.CommandPerms = s.SecurityConfig.CommandPerms
	}
}

// Handle registers an authenticated handler for a command. The optional perms
// are the authorization levels (HTCondor DCpermission names, e.g. "READ" or
// "DAEMON") that authorize the command; a peer is authorized if it satisfies any
// one of them. The levels drive both the ValidCommands the server advertises
// after authentication and, for callers that enforce it, per-command
// authorization (see CommandPerms). Registering with no perms advertises the
// command only as the negotiated one and applies no authorization table; a
// session whose credential limits its authorization levels may not run it.
func (s *Server) Handle(command int, fn HandlerFunc, perms ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[command] = registeredHandler{fn: fn, raw: false, perms: perms}
}

// HandleRaw registers a handler for a raw (un-authenticated) command. The
// command integer arrives with no preceding DC_AUTHENTICATE.
func (s *Server) HandleRaw(command int, fn HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[command] = registeredHandler{fn: fn, raw: true}
}

// CommandPerms returns the authorization levels registered for command, or nil
// if it is unregistered or raw. Callers enforcing per-command authorization
// should verify a peer against these levels so their decision matches the
// ValidCommands the server advertises.
func (s *Server) CommandPerms(command int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.handlers[command].perms
}

// sessionSatisfies reports whether an already-established session may run
// realCmd, enforcing two properties beyond the initial handshake so that a
// permissive session cannot be reused (kept-alive or resumed) for a command that
// demands a stronger security level:
//
//   - Security level: realCmd's negotiated policy (SecurityConfigForCommand, or
//     SecurityConfig) may mandate authentication and/or encryption; the session
//     must actually provide them. A session negotiated at READ (encryption
//     optional, possibly unauthenticated/plaintext) therefore cannot run an
//     ADVERTISE command that requires authentication and encryption.
//   - Authorization bounding set: if the peer's credential limited its
//     authorization levels (Negotiation.AuthorizationLimits), one of realCmd's
//     registered levels must be ALLOW or within those limits, whether or not
//     an Authorizer is set.
//   - Authorization: when an Authorizer gates the server, the identity must
//     satisfy one of realCmd's registered authorization levels. A command
//     registered with no levels has none to satisfy and is not gated here (see
//     Handle); access to it is bounded by the two checks above. Without an
//     Authorizer, authorization is not enforced here and reuse is bounded by
//     the security-level and bounding-set checks alone.
func (s *Server) sessionSatisfies(realCmd int, peerAddr string, neg *security.SecurityNegotiation) error {
	if neg == nil {
		return fmt.Errorf("no negotiated session")
	}
	// Security level, re-evaluated against CURRENT policy: a persisted/resumed
	// session may cross a reconfig or restart, so a command that now mandates
	// authentication or encryption is refused on a session that lacks it,
	// regardless of what the session was originally granted.
	if !s.commandLevelSatisfied(realCmd, neg.Authentication, neg.Encryption) {
		return fmt.Errorf("session (authenticated=%t encrypted=%t) does not meet the command's security level", neg.Authentication, neg.Encryption)
	}
	// The credential's bounding set comes before the Authorizer, as in
	// DaemonCore (daemon_command.cpp): a level it excludes is refused whatever
	// the identity is allowed. It is carried in the session, so it also holds
	// for a resumed or kept-alive session.
	perms := s.CommandPerms(realCmd)
	if !security.AuthorizationLimitsPermit(neg.AuthorizationLimits, perms) {
		return fmt.Errorf("authorization levels %v are outside the session's authorization limits %v", perms, neg.AuthorizationLimits)
	}
	// Authorization, also re-evaluated against the CURRENT Authorizer rather than
	// the session's advertised ValidCommands (which may be stale after a policy
	// change): the identity must satisfy one of the command's registered levels.
	if s.Authorizer != nil {
		user := authorizationUser(neg.User, neg.Authentication)
		if !s.authorized(realCmd, peerAddr, user) {
			return fmt.Errorf("identity %q does not satisfy any of the command's authorization levels %v", user, perms)
		}
	}
	return nil
}

// commandRefusal returns why the session neg may not run realCmd, or nil if it
// may: realCmd must have an authenticated handler, and the session must satisfy
// it (sessionSatisfies). An unregistered command's error wraps
// security.ErrCommandNotFound.
func (s *Server) commandRefusal(realCmd int, peerAddr string, neg *security.SecurityNegotiation) error {
	if h, ok := s.lookup(realCmd); !ok || h.raw {
		return fmt.Errorf("cedar/server: no authenticated handler for command %d (%s): %w", realCmd, commands.GetCommandName(realCmd), security.ErrCommandNotFound)
	}
	if err := s.sessionSatisfies(realCmd, peerAddr, neg); err != nil {
		return fmt.Errorf("cedar/server: command %d (%s) refused: %w", realCmd, commands.GetCommandName(realCmd), err)
	}
	return nil
}

// commandLevelSatisfied reports whether a session with the given negotiated
// properties meets realCmd's current security requirements (authentication and
// encryption/integrity). It takes no lock itself, but it calls the
// application's SecurityConfigForCommand hook, which is free to call back into
// the server (CommandPerms does this in several consumers), so it must not be
// called with s.mu held.
func (s *Server) commandLevelSatisfied(realCmd int, authenticated, encrypted bool) bool {
	req := s.SecurityConfig
	if s.SecurityConfigForCommand != nil {
		if perCmd := s.SecurityConfigForCommand(realCmd); perCmd != nil {
			req = perCmd
		}
	}
	if req == nil {
		return true
	}
	if req.Authentication == security.SecurityRequired && !authenticated {
		return false
	}
	// cedar's encryption (AES-GCM) is authenticated encryption, so an encrypted
	// session also provides integrity; a command mandating either needs encryption.
	if (req.Encryption == security.SecurityRequired || req.Integrity == security.SecurityRequired) && !encrypted {
		return false
	}
	return true
}

// authorized reports whether user may run realCmd under the current Authorizer
// and the command's registered authorization levels. A command registered with
// no levels carries no authorization requirement (Handle: "applies no
// authorization table"), so there is nothing for the Authorizer to decide and
// it is authorized.
func (s *Server) authorized(realCmd int, peerAddr, user string) bool {
	perms := s.CommandPerms(realCmd)
	if len(perms) == 0 {
		return true
	}
	for _, perm := range perms {
		if s.Authorizer(perm, peerAddr, user) {
			return true
		}
	}
	return false
}

// mapFQU applies FQUMapper (if set) to resolve the identity to advertise and
// authorize as, falling back to the authenticated identity.
func (s *Server) mapFQU(authUser, peerAddr string) string {
	if s.FQUMapper != nil {
		if mapped := s.FQUMapper(authUser, peerAddr); mapped != "" {
			return s.SecurityConfig.CanonicalUser(mapped)
		}
	}
	return authUser
}

// postAuthPolicy is installed as the security layer's PostAuthPolicy. After a
// successful handshake it returns the FQU to advertise and the set of commands
// this session is authorized for — every registered authenticated command whose
// levels the Authorizer accepts. With no Authorizer set it returns no commands,
// so the security layer advertises just the negotiated command (its default).
// An unauthenticated session is advertised and authorized as
// UnauthenticatedFQU, unmapped, whatever authUser holds. The security layer
// then drops any command outside the session's authorization bounding set,
// using CommandPerms (installed by New), so a limited credential is not
// advertised commands it cannot run.
func (s *Server) postAuthPolicy(authUser, peerAddr string, authenticated, encrypted bool) (string, []int) {
	fqu := UnauthenticatedFQU
	if authenticated {
		fqu = s.mapFQU(authUser, peerAddr)
	}
	if s.Authorizer == nil {
		return fqu, nil
	}
	// Snapshot the candidates under the lock and release it before running any
	// application callback, as authorized does. Both callbacks below
	// (SecurityConfigForCommand, via commandLevelSatisfied, and Authorizer) are
	// supplied by the embedding program and are documented to be free to call
	// back into the server — CommandPerms in particular. s.mu is a
	// sync.RWMutex, which is not reentrant: a callback re-entering RLock while
	// a Handle is queued on the write lock would wedge both goroutines, and
	// every later handshake behind them, permanently.
	type candidate struct {
		cmd   int
		perms []string
	}
	s.mu.RLock()
	candidates := make([]candidate, 0, len(s.handlers))
	for cmd, h := range s.handlers {
		if h.raw || len(h.perms) == 0 {
			continue
		}
		candidates = append(candidates, candidate{cmd: cmd, perms: h.perms})
	}
	s.mu.RUnlock()

	var valid []int
	for _, c := range candidates {
		// Only advertise a command the session could run right now: it must both
		// clear the command's security level for this session AND be authorized.
		// Advertising a command the session can't immediately use (e.g. an
		// encryption-mandating command over a plaintext session) would be an
		// overly-broad ValidCommands that the dispatch-time check then rejects.
		if !s.commandLevelSatisfied(c.cmd, authenticated, encrypted) {
			continue
		}
		for _, perm := range c.perms {
			if s.Authorizer(perm, peerAddr, fqu) {
				valid = append(valid, c.cmd)
				break
			}
		}
	}
	sort.Ints(valid)
	return fqu, valid
}

// Serve accepts connections from l until the context is cancelled or the
// listener is closed. Each connection is handled in its own goroutine.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	// Backoff for a listener that is still open but momentarily cannot produce
	// a connection, as when the process is out of file descriptors.
	const (
		acceptRetryMin = 5 * time.Millisecond
		acceptRetryMax = time.Second
	)
	var acceptDelay time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Only a closed listener is terminal. Returning on every error made
			// a transient descriptor exhaustion (EMFILE/ENFILE) permanent: the
			// accept loop exited, the listener stayed bound so nothing else
			// could take the port, and the daemon was deaf from then on even
			// once descriptors were free again. MaxPendingConnections does not
			// prevent it -- the descriptor is spent before admit runs, and the
			// default cap is above a typical RLIMIT_NOFILE.
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			if acceptDelay == 0 {
				acceptDelay = acceptRetryMin
			} else if acceptDelay *= 2; acceptDelay > acceptRetryMax {
				acceptDelay = acceptRetryMax
			}
			slog.Error("cedar/server: accept failed; retrying",
				"error", err, "retry_in", acceptDelay, "destination", "cedar")
			select {
			case <-time.After(acceptDelay):
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		acceptDelay = 0
		// Enable TCP keepalives on the accepted connection so a silently-dead
		// peer is detected instead of blocking the handler goroutine forever.
		// Best-effort: a no-op for non-TCP listeners and never fatal.
		_ = s.KeepAlive.Apply(conn)
		go func() {
			// Isolate each connection: a panic in one handler must not take
			// down the whole daemon. Recover, log the stack, and drop just this
			// connection.
			defer func() {
				if r := recover(); r != nil {
					slog.Error("cedar/server: panic in connection handler; recovered",
						"panic", r, "remote", conn.RemoteAddr().String(),
						"stack", string(debug.Stack()), "destination", "cedar")
					_ = conn.Close()
				}
			}()
			if err := s.ServeConn(ctx, conn); err != nil {
				// Best-effort; connection-level errors are not fatal to the
				// server. Callers that want visibility can wrap ServeConn.
				_ = err
			}
		}()
	}
}

// errKeepOpen is a sentinel a handler can return (via KeepOpen) to indicate it
// has taken ownership of the connection and ServeConn must not close it.
var errKeepOpen = fmt.Errorf("cedar/server: connection kept open by handler")

// KeepOpen is returned by a handler that has taken ownership of the connection
// (e.g. a persistent CCB registration socket or a proxied stream). ServeConn
// will not close the underlying connection in that case.
func KeepOpen() error { return errKeepOpen }

// pendingConn is a connection that has not reached its handler: it holds one of
// MaxPendingConnections and is closed if HandshakeDeadline passes first.
type pendingConn struct {
	s       *Server
	timer   *time.Timer
	release func() // from AdmitConnection; nil if none
	expired atomic.Bool
	once    sync.Once
	err     error
}

// admit counts conn as pending and arms its deadline. It returns
// ErrTooManyPendingConnections when the cap is reached, and
// ErrConnectionNotAdmitted when AdmitConnection refuses it.
func (s *Server) admit(conn net.Conn) (*pendingConn, error) {
	n := s.pending.Add(1)
	if limit := s.MaxPendingConnections; limit > 0 && n > int64(limit) {
		s.pending.Add(-1)
		return nil, ErrTooManyPendingConnections
	}
	p := &pendingConn{s: s}
	if s.AdmitConnection != nil {
		release, err := s.AdmitConnection(conn)
		if err != nil {
			s.pending.Add(-1)
			return nil, fmt.Errorf("%w: %w", ErrConnectionNotAdmitted, err)
		}
		p.release = release
	}
	if d := s.HandshakeDeadline; d > 0 {
		p.timer = time.AfterFunc(d, func() {
			p.expired.Store(true)
			_ = conn.Close()
		})
	}
	return p, nil
}

// done ends the pending phase: it releases the slot and disarms the deadline.
// It returns ErrHandshakeDeadline if the deadline already closed the
// connection. Calls after the first return the first's result.
func (p *pendingConn) done() error {
	p.once.Do(func() {
		p.s.pending.Add(-1)
		if p.release != nil {
			p.release()
		}
		if p.timer != nil && !p.timer.Stop() {
			p.err = ErrHandshakeDeadline
		}
	})
	return p.err
}

// failed returns err, or ErrHandshakeDeadline wrapping it when the deadline
// closing the connection is what made the operation fail.
func (p *pendingConn) failed(err error) error {
	if p.expired.Load() {
		return fmt.Errorf("%w: %w", ErrHandshakeDeadline, err)
	}
	return err
}

// ServeConn handles a single already-accepted connection: it reads the leading
// command integer, performs the security handshake for authenticated commands,
// and dispatches to the registered handler. Until the handler runs the
// connection counts against MaxPendingConnections and is bounded by
// HandshakeDeadline.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) error {
	// Give each connection its own cancellable child context. The stream layer
	// registers a context.AfterFunc per frame write to interrupt a blocked write on
	// cancellation; anchoring those on a per-connection context (which has a single
	// writer goroutine) instead of the shared server context eliminates the
	// cross-connection contention on the parent context's mutex that per-frame
	// registration would otherwise cause. cancel() on return also tears down any
	// per-connection cancellation state.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	pc, err := s.admit(conn)
	if err != nil {
		_ = conn.Close()
		slog.Debug("cedar/server: refusing connection", "remote", conn.RemoteAddr().String(), "error", err, "destination", "cedar")
		return err
	}
	defer func() { _ = pc.done() }()

	st := stream.NewStream(conn)
	st.SetPeerAddr(conn.RemoteAddr().String())

	msg := message.NewMessageFromStream(st)
	cmd, err := msg.GetInt(ctx)
	if err != nil {
		_ = conn.Close()
		return pc.failed(fmt.Errorf("cedar/server: failed to read command: %w", err))
	}

	if cmd == commands.DC_AUTHENTICATE {
		if s.SecurityConfig == nil {
			_ = conn.Close()
			return fmt.Errorf("cedar/server: authenticated command received but no SecurityConfig set")
		}
		// The handshake mutates its config per-connection (e.g. NewAuthenticator
		// stores this connection's ephemeral ECDH public key in it), so give each
		// connection a private shallow copy rather than the server's shared config.
		// A shallow copy is enough: the mutated fields are values (ECDHPublicKey,
		// negotiated levels, ...), while the shared pointer fields (credentials) are
		// read-only during the handshake. Without this, concurrent handshakes race
		// on -- and clobber each other's -- ECDH key. (Shared config = data race.)
		connConfig := *s.SecurityConfig
		auth := security.NewAuthenticator(&connConfig, st)
		if s.SecurityConfigForCommand != nil {
			// Select a per-command policy once the handshake reveals the command,
			// giving each connection its own shallow copy (same rationale as above).
			auth.ServerConfigForCommand = func(command int) *security.SecurityConfig {
				cfg := s.SecurityConfigForCommand(command)
				if cfg == nil {
					return nil
				}
				c := *cfg
				s.inheritPolicyHooks(&c)
				return &c
			}
		}
		// Decide whether the negotiated command may run before the handshake
		// replies, so a refused command is answered DENIED (or CMD_NOT_FOUND) and
		// its session is not cached, as in DaemonCore. For DC_AUTHENTICATE and
		// DC_SEC_QUERY that is the command the peer named as AuthCommand.
		peerAddr := conn.RemoteAddr().String()
		auth.AuthorizeCommand = func(neg *security.SecurityNegotiation) error {
			return s.commandRefusal(neg.ClientConfig.AuthorizedCommand(), peerAddr, neg)
		}
		neg, err := auth.ServerHandshakeWithMessage(ctx, msg, cmd)
		if err != nil {
			_ = conn.Close()
			var refused *security.CommandRefusedError
			if errors.As(err, &refused) {
				return refused.Err
			}
			return pc.failed(fmt.Errorf("cedar/server: handshake failed: %w", err))
		}
		if err := pc.done(); err != nil {
			_ = conn.Close()
			return err
		}
		realCmd := 0
		if neg.ClientConfig != nil {
			realCmd = neg.ClientConfig.Command
		}
		// A session that did not authenticate has no identity, whatever User it
		// carries (a resumed session's cached User, or one set by a method that
		// then failed). Clear it so handlers cannot mistake it for the peer's.
		if !neg.Authentication {
			neg.User = ""
		}
		if realCmd == commands.DC_AUTHENTICATE || realCmd == commands.DC_SEC_QUERY {
			err := s.answerSessionCommand(ctx, st, peerAddr, neg)
			_ = conn.Close()
			return err
		}
		// Dispatch the negotiated command, then -- if its handler opted into
		// keepalive -- keep serving follow-on commands on the same established
		// session (HTCondor's persistent command socket: the peer sends a raw
		// command integer over the still-encrypted stream, no re-handshake).
		var followMsg *message.Message // nil for the first command (ad is a fresh message)
		for {
			// Enforce that the established session actually satisfies THIS command's
			// security level before dispatching. A fresh handshake already checked
			// its command, but a kept-alive or resumed session may carry weaker
			// properties than a follow-on command needs -- e.g. a session negotiated
			// at READ (encryption optional, maybe unauthenticated/plaintext) must not
			// be reused to run an ADVERTISE command that mandates authentication and
			// encryption. Without this, per-command negotiation could be bypassed by
			// establishing a permissive session and then sending a privileged command.
			if err := s.commandRefusal(realCmd, peerAddr, neg); err != nil {
				_ = conn.Close()
				return err
			}
			h, _ := s.lookup(realCmd)
			c := &Conn{
				Stream:      st,
				Command:     realCmd,
				Negotiation: neg,
				Message:     followMsg,
				RemoteAddr:  conn.RemoteAddr().String(),
			}
			if err := h.fn(ctx, c); err != nil {
				if err == errKeepOpen {
					return nil
				}
				_ = conn.Close()
				return err
			}
			if !c.keepAlive {
				_ = conn.Close()
				return nil
			}
			// Read the next command integer on the same session. EOF/any error
			// means the peer finished sending updates and closed -- a clean end.
			followMsg = message.NewMessageFromStream(st)
			realCmd, err = followMsg.GetInt(ctx)
			if err != nil {
				_ = conn.Close()
				return nil
			}
		}
	}

	// Raw command path: no handshake, payload follows in the same message.
	h, ok := s.lookup(cmd)
	if !ok || !h.raw {
		_ = conn.Close()
		return fmt.Errorf("cedar/server: no raw handler for command %d (%s)", cmd, commands.GetCommandName(cmd))
	}
	if err := pc.done(); err != nil {
		_ = conn.Close()
		return err
	}
	return s.run(ctx, h, &Conn{
		Stream:     st,
		Command:    cmd,
		Message:    msg,
		RemoteAddr: conn.RemoteAddr().String(),
	}, conn)
}

// answerSessionCommand completes a DC_AUTHENTICATE or DC_SEC_QUERY handshake,
// which dispatches no handler, as DaemonCore does (daemon_command.cpp,
// ExecCommand). The command the peer named as AuthCommand is authorized again
// here because a resumed session got no post-auth reply; a refused one ends the
// connection unanswered. DC_AUTHENTICATE only establishes the session. A
// DC_SEC_QUERY is answered with AuthorizationSucceeded, which condor_ping
// reports.
func (s *Server) answerSessionCommand(ctx context.Context, st *stream.Stream, peerAddr string, neg *security.SecurityNegotiation) error {
	if err := s.commandRefusal(neg.ClientConfig.AuthorizedCommand(), peerAddr, neg); err != nil {
		return err
	}
	if neg.ClientConfig.Command == commands.DC_AUTHENTICATE {
		return nil
	}
	reply := classad.New()
	_ = reply.Set("AuthorizationSucceeded", true)
	msg := message.NewMessageForStream(st)
	if err := msg.PutClassAd(ctx, reply); err != nil {
		return fmt.Errorf("cedar/server: send DC_SEC_QUERY reply: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("cedar/server: send DC_SEC_QUERY reply: %w", err)
	}
	return nil
}

func (s *Server) run(ctx context.Context, h registeredHandler, c *Conn, conn net.Conn) error {
	err := h.fn(ctx, c)
	if err == errKeepOpen {
		return nil
	}
	_ = conn.Close()
	return err
}

func (s *Server) lookup(command int) (registeredHandler, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.handlers[command]
	return h, ok
}
