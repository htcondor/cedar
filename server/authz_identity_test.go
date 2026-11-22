package server

import (
	"context"
	"net"
	"path"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

const (
	adminCmd  = 81001 // registered at ADMINISTRATOR
	poolAdmin = "condor@pool"
)

// globAuthorizer is an ALLOW_* table in miniature: perm -> user glob patterns.
// It records every identity it is asked about.
type globAuthorizer struct {
	allow map[string][]string

	mu   sync.Mutex
	seen []string
}

func (a *globAuthorizer) authorize(perm, _, user string) bool {
	a.mu.Lock()
	a.seen = append(a.seen, user)
	a.mu.Unlock()
	for _, p := range a.allow[perm] {
		if ok, _ := path.Match(p, user); ok {
			return true
		}
	}
	return false
}

func (a *globAuthorizer) users() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.seen)
}

// handlerView is what the ADMINISTRATOR handler saw, if it ran.
type handlerView struct {
	user, authzUser string
}

// dispatchResult is the outcome of one connection served by ServeConn.
type dispatchResult struct {
	clientErr error // the client's handshake error
	serveErr  error
	handler   *handlerView // nil if the handler did not run
	seen      []string     // identities the Authorizer was asked about
}

// newAdminServer returns a server with one ADMINISTRATOR command whose handler
// reports what it saw on ran.
func newAdminServer(cfg *security.SecurityConfig, authz *globAuthorizer, ran chan<- handlerView) *Server {
	srv := New(cfg)
	srv.Authorizer = authz.authorize
	srv.Handle(adminCmd, func(_ context.Context, c *Conn) error {
		ran <- handlerView{user: c.Negotiation.User, authzUser: c.AuthorizationUser()}
		return nil
	}, "ADMINISTRATOR")
	return srv
}

// serve runs srv on one end of a pipe, runs client on the other, and collects
// the result once ServeConn returns.
func serve(t *testing.T, srv *Server, authz *globAuthorizer, ran chan handlerView, client func(ctx context.Context, conn net.Conn) error) dispatchResult {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.ServeConn(ctx, serverConn) }()
	var res dispatchResult
	// A command refused on a full handshake fails the client's handshake.
	res.clientErr = client(ctx, clientConn)
	_ = clientConn.Close()
	select {
	case res.serveErr = <-done:
	case <-ctx.Done():
		t.Fatalf("ServeConn did not return: %v", ctx.Err())
	}
	select {
	case v := <-ran:
		res.handler = &v
	default:
	}
	res.seen = authz.users()
	return res
}

// resumeSession serves one command over a resumed session whose server-side
// record names user and has the given authentication outcome. The session is a
// claim session imported into both caches and then rewritten on the server side,
// so the server's resumption sees exactly that record.
func resumeSession(t *testing.T, user string, authenticated bool, allow map[string][]string) dispatchResult {
	t.Helper()
	const serverAddr = "<127.0.0.1:9618>"
	claimID := serverAddr + "#1700000000#7#" +
		`[Encryption="YES";Integrity="YES";CryptoMethods="AES";]` +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	clientCache := security.NewSessionCache()
	serverCache := security.NewSessionCache()
	sesid, err := security.ImportClaimSession(clientCache, claimID, security.ClaimSessionOptions{PeerAddr: serverAddr})
	if err != nil {
		t.Fatalf("client ImportClaimSession: %v", err)
	}
	if _, err := security.ImportClaimSession(serverCache, claimID, security.ClaimSessionOptions{PeerAddr: serverAddr}); err != nil {
		t.Fatalf("server ImportClaimSession: %v", err)
	}
	entry, ok := serverCache.Lookup(sesid)
	if !ok {
		t.Fatal("server session not cached")
	}
	if err := entry.Policy().Set("User", user); err != nil {
		t.Fatal(err)
	}
	if err := entry.Policy().Set("Authenticated", authenticated); err != nil {
		t.Fatal(err)
	}

	authz := &globAuthorizer{allow: allow}
	ran := make(chan handlerView, 1)
	srv := newAdminServer(&security.SecurityConfig{
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   serverCache,
	}, authz, ran)

	return serve(t, srv, authz, ran, func(ctx context.Context, conn net.Conn) error {
		st := stream.NewStream(conn)
		st.SetPeerAddr(serverAddr)
		neg, err := security.NewAuthenticator(&security.SecurityConfig{
			Command:      adminCmd,
			PeerName:     serverAddr,
			SessionCache: clientCache,
			SessionID:    sesid,
		}, st).ClientHandshake(ctx)
		if err == nil && !neg.SessionResumed {
			t.Error("client did not resume the session")
		}
		return err
	})
}

// freshHandshake serves one command after a full handshake. With fs the client
// authenticates by FS and the server maps that identity to poolAdmin; otherwise
// neither side offers a method and the session is unauthenticated. Both sides
// use empty private caches, so nothing is resumed.
func freshHandshake(t *testing.T, fs bool, allow map[string][]string) dispatchResult {
	t.Helper()
	srvCfg := &security.SecurityConfig{
		Authentication: security.SecurityOptional,
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		SessionCache:   security.NewSessionCache(),
	}
	cliCfg := &security.SecurityConfig{
		Authentication: security.SecurityOptional,
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Command:        adminCmd,
		SessionCache:   security.NewSessionCache(),
	}
	if fs {
		srvCfg.AuthMethods = []security.AuthMethod{security.AuthFS}
		srvCfg.Authentication = security.SecurityRequired
		cliCfg.AuthMethods = []security.AuthMethod{security.AuthFS}
		cliCfg.Authentication = security.SecurityRequired
	}
	authz := &globAuthorizer{allow: allow}
	ran := make(chan handlerView, 1)
	srv := newAdminServer(srvCfg, authz, ran)
	srv.FQUMapper = func(authUser, _ string) string {
		if authUser == "" {
			t.Errorf("FQUMapper called for an unauthenticated peer")
		}
		return poolAdmin
	}
	return serve(t, srv, authz, ran, func(ctx context.Context, conn net.Conn) error {
		neg, err := security.NewAuthenticator(cliCfg, stream.NewStream(conn)).ClientHandshake(ctx)
		if err == nil && neg.SessionResumed {
			t.Error("client resumed a session, want a full handshake")
		}
		return err
	})
}

var (
	adminOnlyPool     = map[string][]string{"ADMINISTRATOR": {poolAdmin}}
	adminAnyone       = map[string][]string{"ADMINISTRATOR": {"*"}}
	adminUnauthorized = map[string][]string{"ADMINISTRATOR": {UnauthenticatedFQU}}
)

func assertRefused(t *testing.T, res dispatchResult) {
	t.Helper()
	if res.serveErr == nil {
		t.Error("ServeConn returned nil, want the command refused")
	}
	if res.handler != nil {
		t.Errorf("handler ran (saw user %q), want it refused", res.handler.user)
	}
	if !slices.Contains(res.seen, UnauthenticatedFQU) {
		t.Errorf("Authorizer saw %q, want %q", res.seen, UnauthenticatedFQU)
	}
	if slices.Contains(res.seen, poolAdmin) {
		t.Errorf("Authorizer was asked about %q on an unauthenticated session (saw %q)", poolAdmin, res.seen)
	}
}

func assertRanUnauthenticated(t *testing.T, res dispatchResult) {
	t.Helper()
	if res.clientErr != nil {
		t.Fatalf("client handshake: %v", res.clientErr)
	}
	if res.serveErr != nil {
		t.Fatalf("ServeConn: %v", res.serveErr)
	}
	if res.handler == nil {
		t.Fatal("handler did not run")
	}
	if res.handler.user != "" {
		t.Errorf("handler saw Negotiation.User %q on an unauthenticated session, want \"\"", res.handler.user)
	}
	if res.handler.authzUser != UnauthenticatedFQU {
		t.Errorf("AuthorizationUser() = %q, want %q", res.handler.authzUser, UnauthenticatedFQU)
	}
	if slices.Contains(res.seen, poolAdmin) {
		t.Errorf("Authorizer was asked about %q on an unauthenticated session (saw %q)", poolAdmin, res.seen)
	}
}

func assertRanAs(t *testing.T, res dispatchResult, user string) {
	t.Helper()
	if res.clientErr != nil {
		t.Fatalf("client handshake: %v", res.clientErr)
	}
	if res.serveErr != nil {
		t.Fatalf("ServeConn: %v", res.serveErr)
	}
	if res.handler == nil {
		t.Fatal("handler did not run")
	}
	if res.handler.user != user || res.handler.authzUser != user {
		t.Errorf("handler saw User %q / AuthorizationUser %q, want %q", res.handler.user, res.handler.authzUser, user)
	}
}

// TestResumedUnauthenticatedSessionIsNotItsUser: a resumed session that records
// User=condor@pool but did not authenticate is authorized as
// unauthenticated@unmapped, so a policy granting ADMINISTRATOR only to
// condor@pool refuses it.
func TestResumedUnauthenticatedSessionIsNotItsUser(t *testing.T) {
	assertRefused(t, resumeSession(t, poolAdmin, false, adminOnlyPool))
}

// TestResumedAuthenticatedSessionKeepsItsUser: the same record, authenticated,
// is authorized as condor@pool.
func TestResumedAuthenticatedSessionKeepsItsUser(t *testing.T) {
	assertRanAs(t, resumeSession(t, poolAdmin, true, adminOnlyPool), poolAdmin)
}

// TestResumedUnauthenticatedSessionWildcardPolicy: as in HTCondor, a policy that
// admits "*" or names unauthenticated@unmapped lets the unauthenticated session
// through, and the handler does not see the recorded identity.
func TestResumedUnauthenticatedSessionWildcardPolicy(t *testing.T) {
	t.Run("star", func(t *testing.T) {
		assertRanUnauthenticated(t, resumeSession(t, poolAdmin, false, adminAnyone))
	})
	t.Run("unauthenticated@unmapped", func(t *testing.T) {
		assertRanUnauthenticated(t, resumeSession(t, poolAdmin, false, adminUnauthorized))
	})
}

// TestFreshUnauthenticatedHandshake: a full handshake that does not
// authenticate is authorized as unauthenticated@unmapped, unmapped, on the same
// policies.
func TestFreshUnauthenticatedHandshake(t *testing.T) {
	t.Run("pool-only", func(t *testing.T) {
		assertRefused(t, freshHandshake(t, false, adminOnlyPool))
	})
	t.Run("star", func(t *testing.T) {
		assertRanUnauthenticated(t, freshHandshake(t, false, adminAnyone))
	})
	t.Run("unauthenticated@unmapped", func(t *testing.T) {
		assertRanUnauthenticated(t, freshHandshake(t, false, adminUnauthorized))
	})
}

// TestFreshAuthenticatedHandshake: an FS-authenticated peer mapped to
// condor@pool is allowed ADMINISTRATOR.
func TestFreshAuthenticatedHandshake(t *testing.T) {
	assertRanAs(t, freshHandshake(t, true, adminOnlyPool), poolAdmin)
}

// TestPostAuthPolicyUnauthenticatedIdentity covers a fresh handshake whose
// negotiation carries an identity although it did not authenticate (as a method
// that set User and then failed leaves it): the identity is neither mapped nor
// authorized, nothing it alone is allowed is advertised, and the advertised FQU
// is unauthenticated@unmapped.
func TestPostAuthPolicyUnauthenticatedIdentity(t *testing.T) {
	authz := &globAuthorizer{allow: adminOnlyPool}
	srv := newAdminServer(nil, authz, make(chan handlerView, 1))
	srv.FQUMapper = func(authUser, _ string) string {
		t.Errorf("FQUMapper(%q) called for an unauthenticated session", authUser)
		return authUser
	}

	fqu, valid := srv.postAuthPolicy(poolAdmin, "127.0.0.1:1", false, true)
	if fqu != UnauthenticatedFQU {
		t.Errorf("fqu = %q, want %q", fqu, UnauthenticatedFQU)
	}
	if slices.Contains(valid, adminCmd) {
		t.Errorf("ValidCommands %v includes the ADMINISTRATOR command", valid)
	}
	if got := authz.users(); !slices.Equal(got, []string{UnauthenticatedFQU}) {
		t.Errorf("Authorizer saw %q, want [%q]", got, UnauthenticatedFQU)
	}

	// The same identity, authenticated, is authorized as itself.
	srv.FQUMapper = nil
	if fqu, valid := srv.postAuthPolicy(poolAdmin, "127.0.0.1:1", true, true); fqu != poolAdmin || !slices.Contains(valid, adminCmd) {
		t.Errorf("authenticated: fqu = %q, valid = %v; want %q with the ADMINISTRATOR command", fqu, valid, poolAdmin)
	}
}

// TestAuthorizationUserRawCommand: a raw command has no negotiation and is
// unauthenticated.
func TestAuthorizationUserRawCommand(t *testing.T) {
	if got := (&Conn{}).AuthorizationUser(); got != UnauthenticatedFQU {
		t.Errorf("AuthorizationUser() = %q, want %q", got, UnauthenticatedFQU)
	}
}
