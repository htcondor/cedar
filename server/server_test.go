package server

import (
	"context"
	"net"
	"os/user"
	"testing"
	"time"

	"github.com/htcondor/cedar/ccb"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// TestRawDispatch verifies that a bare command integer (no DC_AUTHENTICATE) is
// routed to a raw handler, which can then read the payload from the same
// message — exactly the CCB_REVERSE_CONNECT path.
func TestRawDispatch(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const connectID = "00112233445566778899aabbccddeeff00112233"

	got := make(chan string, 1)
	srv := New(nil)
	srv.HandleRaw(ccb.CommandReverseConnect, func(ctx context.Context, c *Conn) error {
		ad, err := ccb.ReadReverseConnectAd(ctx, c.Message, c.Command)
		if err != nil {
			return err
		}
		got <- ccb.AdString(ad, ccb.AttrClaimID)
		return nil
	})

	go func() {
		s := stream.NewStream(c1)
		_ = ccb.WriteReverseConnect(ctx, s, connectID, "1", "<10.0.0.9:9618>")
	}()

	if err := srv.ServeConn(ctx, c2); err != nil {
		t.Fatalf("ServeConn: %v", err)
	}
	select {
	case id := <-got:
		if id != connectID {
			t.Errorf("handler saw ClaimId %q, want %q", id, connectID)
		}
	default:
		t.Fatal("handler did not run")
	}
}

// TestAuthenticatedDispatch runs a real client<->server exchange through
// Server.ServeConn: the client performs a full CEDAR security handshake (FS
// authentication), the server dispatches to the authenticated handler for the
// negotiated command, and a ClassAd request/reply round-trips over the
// authenticated stream. It verifies the server learns the client's
// authenticated identity rather than just accepting a bare command.
func TestAuthenticatedDispatch(t *testing.T) {
	const authCmd = 60123 // arbitrary authenticated command

	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
	})

	type seen struct {
		user string
		cmd  int
		hi   string
	}
	handlerDone := make(chan seen, 1)
	handlerErr := make(chan error, 1)
	srv.Handle(authCmd, func(ctx context.Context, c *Conn) error {
		req, err := ccb.ReadControlAd(ctx, c.Stream)
		if err != nil {
			handlerErr <- err
			return err
		}
		// Echo the authenticated user back to the client.
		reply := ccb.NewAd(map[string]any{
			"AuthenticatedUser": c.Negotiation.User,
		})
		if err := ccb.WriteControlAd(ctx, c.Stream, reply); err != nil {
			handlerErr <- err
			return err
		}
		handlerDone <- seen{user: c.Negotiation.User, cmd: c.Command, hi: ccb.AdString(req, "Hello")}
		return nil
	})

	go func() { _ = srv.ServeConn(ctx, serverConn) }()

	cliStream := stream.NewStream(clientConn)
	auth := security.NewAuthenticator(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		Command:        authCmd,
	}, cliStream)
	if _, err := auth.ClientHandshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	// Send a request and read the reply over the now-authenticated stream.
	if err := ccb.WriteControlAd(ctx, cliStream, ccb.NewAd(map[string]any{"Hello": "world"})); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply, err := ccb.ReadControlAd(ctx, cliStream)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}

	select {
	case err := <-handlerErr:
		t.Fatalf("handler error: %v", err)
	case s := <-handlerDone:
		if s.cmd != authCmd {
			t.Errorf("handler dispatched cmd=%d, want %d", s.cmd, authCmd)
		}
		if s.user == "" {
			t.Error("server did not record an authenticated user")
		}
		if s.hi != "world" {
			t.Errorf("server saw request Hello=%q, want %q", s.hi, "world")
		}
	case <-ctx.Done():
		t.Fatalf("handler did not complete: %v", ctx.Err())
	}

	if got := ccb.AdString(reply, "AuthenticatedUser"); got == "" {
		t.Error("reply missing AuthenticatedUser")
	} else {
		t.Logf("authenticated as %q (os user %q)", got, me.Username)
	}
}

// TestUnknownRawCommand verifies an unregistered command is rejected.
func TestUnknownRawCommand(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := New(nil)

	go func() {
		s := stream.NewStream(c1)
		_ = ccb.WriteReverseConnect(ctx, s, "x", "", "")
	}()

	if err := srv.ServeConn(ctx, c2); err == nil {
		t.Fatal("expected error for unregistered command")
	}
}

// TestValidCommandsComputation verifies that the server computes a session's
// ValidCommands from each registered command's authorization levels and the
// Authorizer, and that FQUMapper maps the advertised identity.
func TestValidCommandsComputation(t *testing.T) {
	const (
		cmdRead  = 1001
		cmdWrite = 1002
		cmdMulti = 1003 // authorized by either DAEMON or ADVERTISE_STARTD
		cmdRaw   = 1004
		cmdBare  = 1005 // registered with no perms
	)
	nop := func(context.Context, *Conn) error { return nil }

	srv := New(nil)
	srv.Handle(cmdRead, nop, "READ")
	srv.Handle(cmdWrite, nop, "WRITE")
	srv.Handle(cmdMulti, nop, "DAEMON", "ADVERTISE_STARTD")
	srv.HandleRaw(cmdRaw, nop)
	srv.Handle(cmdBare, nop)

	// CommandPerms reflects registration; raw/bare commands have none.
	if got := srv.CommandPerms(cmdMulti); len(got) != 2 || got[0] != "DAEMON" || got[1] != "ADVERTISE_STARTD" {
		t.Errorf("CommandPerms(cmdMulti) = %v, want [DAEMON ADVERTISE_STARTD]", got)
	}
	if got := srv.CommandPerms(cmdRaw); got != nil {
		t.Errorf("CommandPerms(cmdRaw) = %v, want nil", got)
	}

	// An Authorizer that grants READ and ADVERTISE_STARTD (but not WRITE/DAEMON).
	srv.Authorizer = func(perm, peerAddr, user string) bool {
		return perm == "READ" || perm == "ADVERTISE_STARTD"
	}
	srv.FQUMapper = func(authUser, peerAddr string) string {
		if authUser == "alice@example.com" {
			return "alice@mapped"
		}
		return ""
	}

	fqu, valid := srv.postAuthPolicy("alice@example.com", "127.0.0.1:5000", true, true)
	if fqu != "alice@mapped" {
		t.Errorf("fqu = %q, want alice@mapped", fqu)
	}
	// cmdRead (READ ✓) and cmdMulti (ADVERTISE_STARTD ✓) authorized; cmdWrite
	// (WRITE ✗) denied; cmdRaw/cmdBare excluded (raw / no perms). Sorted.
	if len(valid) != 2 || valid[0] != cmdRead || valid[1] != cmdMulti {
		t.Errorf("valid = %v, want [%d %d]", valid, cmdRead, cmdMulti)
	}

	// With no Authorizer, no commands are computed (only the negotiated one is
	// advertised by the security layer), but FQU mapping still applies.
	srv.Authorizer = nil
	fqu, valid = srv.postAuthPolicy("bob@example.com", "127.0.0.1:5000", true, true)
	if fqu != "bob@example.com" { // FQUMapper returns "" -> keep authUser
		t.Errorf("fqu = %q, want bob@example.com", fqu)
	}
	if valid != nil {
		t.Errorf("valid = %v, want nil with no Authorizer", valid)
	}
}

// TestPerCommandSecurityConfig verifies SecurityConfigForCommand lets one server
// apply different security policies per command: an unauthenticated (OPTIONAL,
// no-methods) client succeeds on a command served at a permissive level but is
// rejected on a command that keeps the strict default -- the collector's
// "condor_status READ works, condor_advertise needs auth" behavior in miniature.
func TestPerCommandSecurityConfig(t *testing.T) {
	const readCmd = 70001  // served permissively (like a QUERY at READ)
	const writeCmd = 70002 // keeps the strict default (like an UPDATE at ADVERTISE)

	// Strict default: authentication REQUIRED via FS.
	strict := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
	}
	// Permissive per-command policy for readCmd: no authentication required.
	permissive := &security.SecurityConfig{
		Authentication: security.SecurityOptional,
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
	}

	newServer := func() *Server {
		srv := New(strict)
		srv.SecurityConfigForCommand = func(command int) *security.SecurityConfig {
			if command == readCmd {
				return permissive
			}
			return nil // fall back to the strict default
		}
		h := func(ctx context.Context, c *Conn) error { return nil }
		srv.Handle(readCmd, h, "READ")
		srv.Handle(writeCmd, h, "DAEMON")
		return srv
	}

	// An unauthenticated client: OPTIONAL, offering no auth methods.
	clientCfg := func(cmd int) *security.SecurityConfig {
		return &security.SecurityConfig{
			Authentication: security.SecurityOptional,
			Encryption:     security.SecurityOptional,
			Integrity:      security.SecurityOptional,
			Command:        cmd,
		}
	}

	handshake := func(t *testing.T, cmd int) error {
		t.Helper()
		srv := newServer()
		serverConn, clientConn := net.Pipe()
		defer func() { _ = clientConn.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		go func() { _ = srv.ServeConn(ctx, serverConn) }()
		auth := security.NewAuthenticator(clientCfg(cmd), stream.NewStream(clientConn))
		_, err := auth.ClientHandshake(ctx)
		return err
	}

	// READ command: unauthenticated client is accepted (permissive per-command policy).
	if err := handshake(t, readCmd); err != nil {
		t.Errorf("unauthenticated client should reach the READ command, got handshake error: %v", err)
	}

	// DAEMON command: unauthenticated client is rejected (strict default, no common method).
	if err := handshake(t, writeCmd); err == nil {
		t.Error("unauthenticated client should be REJECTED at the DAEMON command, but the handshake succeeded")
	}
}

// TestSessionSatisfiesPerCommandLevel is the positive+negative confirmation that
// a session established at one level cannot be reused (kept-alive or resumed) for
// a command that demands a stronger level. It exercises the exact hazard of
// per-command negotiation: READ has encryption/authentication optional, but
// ADVERTISE mandates both, so a permissive READ session must be refused for an
// ADVERTISE command even though the connection is already open.
func TestSessionSatisfiesPerCommandLevel(t *testing.T) {
	const readCmd = 80001
	const advertiseCmd = 80002

	readCfg := &security.SecurityConfig{
		Authentication: security.SecurityOptional,
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
	}
	advertiseCfg := &security.SecurityConfig{
		Authentication: security.SecurityRequired,
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityRequired,
	}
	srv := New(readCfg)
	srv.SecurityConfigForCommand = func(cmd int) *security.SecurityConfig {
		switch cmd {
		case advertiseCmd:
			return advertiseCfg
		default:
			return readCfg
		}
	}

	sess := func(auth, enc bool) *security.SecurityNegotiation {
		return &security.SecurityNegotiation{Authentication: auth, Encryption: enc}
	}

	cases := []struct {
		name   string
		cmd    int
		neg    *security.SecurityNegotiation
		wantOK bool
	}{
		{"READ on plaintext+unauth session", readCmd, sess(false, false), true},
		{"READ on auth+encrypted session (harmless reuse)", readCmd, sess(true, true), true},
		{"ADVERTISE on plaintext+unauth session", advertiseCmd, sess(false, false), false},
		{"ADVERTISE on encrypted-but-UNAUTH session", advertiseCmd, sess(false, true), false},
		{"ADVERTISE on auth-but-PLAINTEXT session", advertiseCmd, sess(true, false), false},
		{"ADVERTISE on auth+encrypted session", advertiseCmd, sess(true, true), true},
	}
	for _, tc := range cases {
		err := srv.sessionSatisfies(tc.cmd, "127.0.0.1:1", tc.neg)
		switch {
		case tc.wantOK && err != nil:
			t.Errorf("%s: expected ALLOWED, got refused: %v", tc.name, err)
		case !tc.wantOK && err == nil:
			t.Errorf("%s: expected REFUSED, but it was allowed", tc.name)
		}
	}
}

// TestSessionSatisfiesReevaluatesAuthorizer verifies that authorization is
// re-evaluated against the CURRENT Authorizer and the command's registered
// levels -- not a session's (possibly stale) advertised ValidCommands. A policy
// change is simulated by swapping the Authorizer and confirming the same session
// is then refused.
func TestSessionSatisfiesReevaluatesAuthorizer(t *testing.T) {
	const readCmd = 80101
	const writeCmd = 80102
	srv := New(&security.SecurityConfig{Authentication: security.SecurityOptional})
	srv.Handle(readCmd, func(context.Context, *Conn) error { return nil }, "READ")
	srv.Handle(writeCmd, func(context.Context, *Conn) error { return nil }, "WRITE")

	// Authorizer allows READ, denies WRITE.
	srv.Authorizer = func(perm, peerAddr, user string) bool { return perm == "READ" }
	neg := &security.SecurityNegotiation{Authentication: true, Encryption: true, User: "someone@pool"}

	if err := srv.sessionSatisfies(readCmd, "127.0.0.1:1", neg); err != nil {
		t.Errorf("READ command should be allowed by the Authorizer, got: %v", err)
	}
	if err := srv.sessionSatisfies(writeCmd, "127.0.0.1:1", neg); err == nil {
		t.Error("WRITE command should be refused by the Authorizer, but was allowed")
	}

	// Simulate a policy change (now WRITE is allowed): the same session is
	// re-evaluated and the command becomes usable -- proving current policy, not a
	// cached ValidCommands, is what governs.
	srv.Authorizer = func(perm, peerAddr, user string) bool { return true }
	if err := srv.sessionSatisfies(writeCmd, "127.0.0.1:1", neg); err != nil {
		t.Errorf("after policy change WRITE should be allowed, got: %v", err)
	}
}

// TestPostAuthPolicyExcludesUnusableCommands verifies ValidCommands is not
// overly broad: a command the session is authorized for but whose security level
// it does not meet (e.g. an encryption-mandating command on a plaintext session)
// is excluded from the advertised set.
func TestPostAuthPolicyExcludesUnusableCommands(t *testing.T) {
	const readCmd = 80201
	const advertiseCmd = 80202
	readCfg := &security.SecurityConfig{Authentication: security.SecurityOptional, Encryption: security.SecurityOptional}
	advCfg := &security.SecurityConfig{Authentication: security.SecurityRequired, Encryption: security.SecurityRequired}
	srv := New(readCfg)
	srv.SecurityConfigForCommand = func(cmd int) *security.SecurityConfig {
		if cmd == advertiseCmd {
			return advCfg
		}
		return readCfg
	}
	srv.Handle(readCmd, func(context.Context, *Conn) error { return nil }, "READ")
	srv.Handle(advertiseCmd, func(context.Context, *Conn) error { return nil }, "ADVERTISE")
	srv.Authorizer = func(perm, peerAddr, user string) bool { return true } // authorized for everything

	// Full matrix over the session's negotiated properties. READ (optional
	// everything) is always usable; ADVERTISE (auth+encryption required) is usable
	// only on an auth+encrypted session -- so it must appear in ValidCommands there
	// and be excluded everywhere else, even though the identity is authorized for
	// it in every case.
	contains := func(list []int, cmd int) bool {
		for _, c := range list {
			if c == cmd {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct {
		name          string
		auth, enc     bool
		wantAdvertise bool
	}{
		{"plaintext+unauth", false, false, false},
		{"encrypted-but-unauth", false, true, false},
		{"auth-but-plaintext", true, false, false},
		{"auth+encrypted", true, true, true},
	} {
		_, valid := srv.postAuthPolicy("someone@pool", "127.0.0.1:1", tc.auth, tc.enc)
		if !contains(valid, readCmd) {
			t.Errorf("%s: READ should always be advertised, got %v", tc.name, valid)
		}
		if got := contains(valid, advertiseCmd); got != tc.wantAdvertise {
			t.Errorf("%s: ADVERTISE in ValidCommands = %v, want %v (list %v)", tc.name, got, tc.wantAdvertise, valid)
		}
	}
}
