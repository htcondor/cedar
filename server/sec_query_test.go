package server

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// secQueryResult is what one DC_SEC_QUERY (or DC_AUTHENTICATE) connection to a
// server produced.
type secQueryResult struct {
	client    *security.SecurityNegotiation
	clientErr error            // the client's handshake error
	reply     *classad.ClassAd // the DC_SEC_QUERY reply, or nil
	replyErr  error            // why no reply was read
	serveErr  error
	ran       bool // some handler ran
}

// secQueryConfig is a CLAIMTOBE client config sending command (DC_SEC_QUERY or
// DC_AUTHENTICATE) about authCommand, caching its sessions in cache.
func secQueryConfig(command, authCommand int, cache *security.SessionCache) *security.SecurityConfig {
	cfg := claimToBeClientConfig(command, cache)
	cfg.AuthCommand = authCommand
	return cfg
}

// secQuery serves one connection: the client handshakes with cliCfg and, for a
// DC_SEC_QUERY that the handshake accepted, reads the server's reply.
func secQuery(t *testing.T, srv *Server, ran chan limitsDispatch, cliCfg *security.SecurityConfig) secQueryResult {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.ServeConn(ctx, serverConn) }()

	st := stream.NewStream(clientConn)
	st.SetPeerAddr(limitsServerAddr)
	var res secQueryResult
	res.client, res.clientErr = security.NewAuthenticator(cliCfg, st).ClientHandshake(ctx)
	if res.clientErr == nil && cliCfg.Command == commands.DC_SEC_QUERY {
		res.reply, res.replyErr = message.NewMessageFromStream(st).GetClassAd(ctx)
	}
	_ = clientConn.Close()
	select {
	case res.serveErr = <-done:
	case <-ctx.Done():
		t.Fatalf("ServeConn did not return: %v", ctx.Err())
	}
	select {
	case <-ran:
		res.ran = true
	default:
	}
	return res
}

// authorizationSucceeded reports the reply's AuthorizationSucceeded, failing
// the test if the query got no reply.
func (r secQueryResult) authorizationSucceeded(t *testing.T) bool {
	t.Helper()
	if r.clientErr != nil || r.replyErr != nil {
		t.Fatalf("query got no reply: handshake err=%v reply err=%v serve err=%v", r.clientErr, r.replyErr, r.serveErr)
	}
	ok, found := r.reply.EvaluateAttrBool("AuthorizationSucceeded")
	if !found {
		t.Fatalf("reply %s has no AuthorizationSucceeded", r.reply)
	}
	return ok
}

// TestSecQuery: DC_SEC_QUERY authenticates, authorizes the command named as
// AuthCommand, and answers without running its handler, as DaemonCore does. A
// permitted command is answered AUTHORIZED, then AuthorizationSucceeded, and
// its session is cached under that command; a refused one DENIED and an
// unregistered one CMD_NOT_FOUND, with no session cached.
func TestSecQuery(t *testing.T) {
	ran := make(chan limitsDispatch, 1)
	srv := newClaimToBeServer(ran)
	user := uniqueUser(t)
	srv.FQUMapper = func(string, string) string { return user }
	srv.Authorizer = func(perm, _, u string) bool { return u == user && perm == "READ" }

	t.Run("authorized", func(t *testing.T) {
		res := secQuery(t, srv, ran, secQueryConfig(commands.DC_SEC_QUERY, readCmd, security.NewSessionCache()))
		if !res.authorizationSucceeded(t) {
			t.Error("AuthorizationSucceeded = false, want true")
		}
		if res.ran {
			t.Error("the queried command's handler ran")
		}
		if res.serveErr != nil {
			t.Errorf("ServeConn error = %v, want nil", res.serveErr)
		}
		if res.client.User != user {
			t.Errorf("User = %q, want %q", res.client.User, user)
		}
		if valid := validCommands(res.client); !slices.Contains(valid, readCmd) || slices.Contains(valid, commands.DC_SEC_QUERY) {
			t.Errorf("ValidCommands = %v, want the queried command %d", valid, readCmd)
		}
		if !sessionCachedFor(user) {
			t.Error("the authorized query's session was not cached")
		}
	})

	for _, tc := range []struct {
		name       string
		authCmd    int
		returnCode string
	}{
		{"denied", adminCmd, "DENIED"},
		{"unregistered", unregisteredCmd, "CMD_NOT_FOUND"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := uniqueUser(t)
			srv.FQUMapper = func(string, string) string { return user }
			res := secQuery(t, srv, ran, secQueryConfig(commands.DC_SEC_QUERY, tc.authCmd, security.NewSessionCache()))
			ae := denial(t, res.clientErr, tc.returnCode)
			if ae.User != user {
				t.Errorf("AuthorizationError.User = %q, want %q", ae.User, user)
			}
			if res.ran {
				t.Error("a handler ran")
			}
			if res.serveErr == nil {
				t.Error("ServeConn returned nil, want the refusal")
			}
			if notFound := errors.Is(res.serveErr, security.ErrCommandNotFound); notFound != (tc.returnCode == "CMD_NOT_FOUND") {
				t.Errorf("ServeConn error = %v, ErrCommandNotFound %t", res.serveErr, notFound)
			}
			if sessionCachedFor(user) {
				t.Error("the refused query's session was cached")
			}
		})
	}
}

// TestSecQueryResumed: a DC_SEC_QUERY on a resumed session gets no post-auth
// reply, so the server authorizes the queried command afterwards: a permitted
// one is answered AuthorizationSucceeded, a refused one closes the connection
// unanswered, as DaemonCore does. The session is CLAIMTOBE, limited to the
// level of the command first queried (READ), although the Authorizer allows
// every level.
func TestSecQueryResumed(t *testing.T) {
	ran := make(chan limitsDispatch, 1)
	srv := newClaimToBeServer(ran)
	cache := security.NewSessionCache()

	first := secQuery(t, srv, ran, secQueryConfig(commands.DC_SEC_QUERY, readCmd, cache))
	if !first.authorizationSucceeded(t) {
		t.Fatal("first query: AuthorizationSucceeded = false")
	}
	resume := func(authCmd int) secQueryResult {
		cfg := secQueryConfig(commands.DC_SEC_QUERY, authCmd, cache)
		cfg.SessionID = first.client.SessionId
		res := secQuery(t, srv, ran, cfg)
		if res.clientErr != nil || !res.client.SessionResumed {
			t.Fatalf("client did not resume the session: %v", res.clientErr)
		}
		if res.ran {
			t.Errorf("query for %d: a handler ran", authCmd)
		}
		return res
	}

	if res := resume(readCmd); !res.authorizationSucceeded(t) || res.serveErr != nil {
		t.Errorf("resumed READ query: serve err=%v, want it authorized", res.serveErr)
	}
	res := resume(adminCmd)
	if res.replyErr == nil {
		t.Errorf("resumed ADMINISTRATOR query was answered %s, want the connection closed", res.reply)
	}
	if res.serveErr == nil || !strings.Contains(res.serveErr.Error(), "authorization limits") {
		t.Errorf("ServeConn error = %v, want the query refused by the session's authorization limits", res.serveErr)
	}
}

// TestDCAuthenticateAsCommand: DC_AUTHENTICATE sent as the command establishes
// a session for the command named as AuthCommand without running anything, as
// DaemonCore does for a UDP command's TCP session. The session's level is that
// command's: its security policy, its authorization and, with no Authorizer,
// the ValidCommands reported.
func TestDCAuthenticateAsCommand(t *testing.T) {
	ran := make(chan limitsDispatch, 1)
	srv := newClaimToBeServer(ran)
	var policyFor []int
	srv.SecurityConfigForCommand = func(command int) *security.SecurityConfig {
		policyFor = append(policyFor, command)
		return nil
	}
	user := uniqueUser(t)
	srv.FQUMapper = func(string, string) string { return user }
	srv.Authorizer = nil

	res := secQuery(t, srv, ran, secQueryConfig(commands.DC_AUTHENTICATE, readCmd, security.NewSessionCache()))
	if res.clientErr != nil || res.serveErr != nil {
		t.Fatalf("client err=%v serve err=%v", res.clientErr, res.serveErr)
	}
	if res.ran {
		t.Error("a handler ran")
	}
	if valid := validCommands(res.client); !slices.Equal(valid, []int{readCmd}) {
		t.Errorf("ValidCommands = %v, want [%d]", valid, readCmd)
	}
	if !sessionCachedFor(user) {
		t.Error("the session was not cached")
	}
	if len(policyFor) == 0 || slices.ContainsFunc(policyFor, func(c int) bool { return c != readCmd }) {
		t.Errorf("security policy selected for commands %v, want only %d", policyFor, readCmd)
	}

	res = secQuery(t, srv, ran, secQueryConfig(commands.DC_AUTHENTICATE, unregisteredCmd, security.NewSessionCache()))
	_ = denial(t, res.clientErr, "CMD_NOT_FOUND")
}
