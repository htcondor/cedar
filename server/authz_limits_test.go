package server

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// Commands registered by newLimitsServer, one per authorization level.
const (
	advertiseStartdCmd = 81010 // ADVERTISE_STARTD
	readCmd            = 81011 // READ
	negotiatorCmd      = 81012 // NEGOTIATOR
	allowCmd           = 81013 // ALLOW
	daemonOrStartdCmd  = 81014 // DAEMON, with ADVERTISE_STARTD as an alternate
	// adminCmd (ADMINISTRATOR) is shared with authz_identity_test.go.

	limitsTrustDomain = "test.domain"
	limitsServerAddr  = "<127.0.0.1:9618>"
)

// tokenKeyDir writes a POOL signing key, scrambled as HTCondor stores it, and
// returns its directory.
func tokenKeyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	key := []byte("authz_limits_test_pool_key_32by!")
	deadbeef := []byte{0xde, 0xad, 0xbe, 0xef}
	for i := range key {
		key[i] ^= deadbeef[i%len(deadbeef)]
	}
	if err := os.WriteFile(filepath.Join(dir, "POOL"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// idToken returns an IDTOKEN for alice signed with the POOL key in keyDir, with
// one "condor:/<LEVEL>" scope per entry of limits (no scope if limits is nil).
func idToken(t *testing.T, keyDir string, limits []string) string {
	t.Helper()
	now := time.Now().Unix()
	tok, err := security.GenerateJWT(keyDir, "POOL", "alice@"+limitsTrustDomain, limitsTrustDomain, now, now+3600, limits)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// limitsDispatch is what one connection to newLimitsServer produced.
type limitsDispatch struct {
	serveErr  error
	ran       bool     // the handler ran
	limits    []string // Conn.AuthorizationLimits() in the handler
	client    *security.SecurityNegotiation
	clientErr error // the client's handshake error
}

// newLimitsServer returns a server that requires TOKEN and whose Authorizer
// allows every authenticated identity at every level, so any refusal comes from
// the token's limits. It serves the commands of handleEveryLevel.
func newLimitsServer(keyDir string, ran chan<- limitsDispatch) *Server {
	srv := New(&security.SecurityConfig{
		AuthMethods:             []security.AuthMethod{security.AuthToken},
		Authentication:          security.SecurityRequired,
		Encryption:              security.SecurityRequired,
		Integrity:               security.SecurityRequired,
		CryptoMethods:           []security.CryptoMethod{security.CryptoAES},
		TrustDomain:             limitsTrustDomain,
		TokenPoolSigningKeyFile: filepath.Join(keyDir, "POOL"),
		TokenSigningKeyDir:      keyDir,
		SessionCache:            security.NewSessionCache(),
	})
	srv.Authorizer = func(_, _, user string) bool { return user != UnauthenticatedFQU }
	handleEveryLevel(srv, ran)
	return srv
}

// handleEveryLevel registers the commands newLimitsServer serves, one per
// authorization level. Every handler records into ran; advertiseStartdCmd also
// keeps the connection open for a follow-on command.
func handleEveryLevel(srv *Server, ran chan<- limitsDispatch) {
	handler := func(_ context.Context, c *Conn) error {
		ran <- limitsDispatch{ran: true, limits: c.AuthorizationLimits()}
		if c.Command == advertiseStartdCmd {
			c.KeepAlive()
		}
		return nil
	}
	srv.Handle(advertiseStartdCmd, handler, "ADVERTISE_STARTD")
	srv.Handle(readCmd, handler, "READ")
	srv.Handle(negotiatorCmd, handler, "NEGOTIATOR")
	srv.Handle(adminCmd, handler, "ADMINISTRATOR")
	srv.Handle(allowCmd, handler, "ALLOW")
	srv.Handle(daemonOrStartdCmd, handler, "DAEMON", "ADVERTISE_STARTD")
}

// limitsClientConfig is a client config presenting token for command, caching
// its sessions in cache.
func limitsClientConfig(token string, command int, cache *security.SessionCache) *security.SecurityConfig {
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityRequired,
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Token:          token,
		TrustDomain:    limitsTrustDomain,
		IssuerKeys:     []string{"POOL"},
		Command:        command,
		PeerName:       limitsServerAddr,
		SessionCache:   cache,
	}
}

// dispatchLimits serves one connection: the client handshakes with cliCfg and,
// if followOn is non-zero, then sends followOn as a command on the same session.
// It returns once ServeConn does.
func dispatchLimits(t *testing.T, srv *Server, ran chan limitsDispatch, cliCfg *security.SecurityConfig, followOn int) []limitsDispatch {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.ServeConn(ctx, serverConn) }()

	st := stream.NewStream(clientConn)
	st.SetPeerAddr(limitsServerAddr)
	// A command refused on a full handshake fails the client's handshake.
	neg, clientErr := security.NewAuthenticator(cliCfg, st).ClientHandshake(ctx)
	if clientErr != nil && followOn != 0 {
		t.Fatalf("client handshake: %v", clientErr)
	}
	var results []limitsDispatch
	if followOn != 0 {
		// The first command's handler must finish before the follow-on is
		// sent; its result is the first entry.
		select {
		case r := <-ran:
			results = append(results, r)
		case <-ctx.Done():
			t.Fatalf("first command did not run: %v", ctx.Err())
		}
		msg := message.NewMessageForStream(st)
		if err := msg.PutInt(ctx, followOn); err != nil {
			t.Fatalf("send follow-on command: %v", err)
		}
		if err := msg.FinishMessage(ctx); err != nil {
			t.Fatalf("send follow-on command: %v", err)
		}
	}
	// Nothing more to send: a kept-alive session reads EOF and ends.
	_ = clientConn.Close()
	var serveErr error
	select {
	case serveErr = <-done:
	case <-ctx.Done():
		t.Fatalf("ServeConn did not return: %v", ctx.Err())
	}
	select {
	case r := <-ran:
		results = append(results, r)
	default:
	}
	if len(results) == 0 || followOn != 0 && len(results) == 1 {
		results = append(results, limitsDispatch{})
	}
	last := &results[len(results)-1]
	last.serveErr = serveErr
	results[0].client = neg
	results[0].clientErr = clientErr
	return results
}

func validCommands(neg *security.SecurityNegotiation) []int {
	var cmds []int
	for _, s := range strings.Split(neg.ValidCommands, ",") {
		if c, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			cmds = append(cmds, c)
		}
	}
	return cmds
}

// TestTokenAuthorizationLimits: an IDTOKEN limited to ADVERTISE_STARTD may run
// ADVERTISE_STARTD commands, READ ones (implied), ALLOW ones, and a command with
// ADVERTISE_STARTD as an alternate level, but is refused NEGOTIATOR and
// ADMINISTRATOR although the Authorizer allows the identity everything. The
// post-auth ValidCommands lists only what it may run. An unlimited token is
// refused nothing.
func TestTokenAuthorizationLimits(t *testing.T) {
	keyDir := tokenKeyDir(t)
	limited := idToken(t, keyDir, []string{"ADVERTISE_STARTD"})
	unlimited := idToken(t, keyDir, nil)

	permitted := []int{advertiseStartdCmd, readCmd, allowCmd, daemonOrStartdCmd}
	refused := []int{negotiatorCmd, adminCmd}

	run := func(t *testing.T, token string, cmd int) limitsDispatch {
		t.Helper()
		ran := make(chan limitsDispatch, 2)
		srv := newLimitsServer(keyDir, ran)
		return dispatchLimits(t, srv, ran, limitsClientConfig(token, cmd, security.NewSessionCache()), 0)[0]
	}

	for _, cmd := range permitted {
		t.Run("limited/permitted/"+strconv.Itoa(cmd), func(t *testing.T) {
			res := run(t, limited, cmd)
			if res.clientErr != nil || res.serveErr != nil || !res.ran {
				t.Fatalf("command %d: ran=%t client err=%v err=%v, want it run", cmd, res.ran, res.clientErr, res.serveErr)
			}
			if !slices.Equal(res.limits, []string{"ADVERTISE_STARTD"}) {
				t.Errorf("Conn.AuthorizationLimits() = %q, want [ADVERTISE_STARTD]", res.limits)
			}
			valid := validCommands(res.client)
			for _, p := range permitted {
				if !slices.Contains(valid, p) {
					t.Errorf("ValidCommands %v lacks permitted command %d", valid, p)
				}
			}
			for _, r := range refused {
				if slices.Contains(valid, r) {
					t.Errorf("ValidCommands %v includes command %d outside the token's limits", valid, r)
				}
			}
		})
	}
	for _, cmd := range refused {
		t.Run("limited/refused/"+strconv.Itoa(cmd), func(t *testing.T) {
			res := run(t, limited, cmd)
			if res.ran {
				t.Fatalf("command %d ran, want it refused", cmd)
			}
			if res.serveErr == nil || !strings.Contains(res.serveErr.Error(), "authorization limits") {
				t.Errorf("ServeConn error = %v, want a refusal naming the authorization limits", res.serveErr)
			}
			// Refused before the handshake's reply, which says so.
			_ = denial(t, res.clientErr, "DENIED")
		})
	}
	for _, cmd := range append(slices.Clone(permitted), refused...) {
		t.Run("unlimited/"+strconv.Itoa(cmd), func(t *testing.T) {
			res := run(t, unlimited, cmd)
			if res.clientErr != nil || res.serveErr != nil || !res.ran {
				t.Fatalf("command %d: ran=%t err=%v, want it run", cmd, res.ran, res.serveErr)
			}
			if res.limits != nil {
				t.Errorf("Conn.AuthorizationLimits() = %q, want nil", res.limits)
			}
			valid := validCommands(res.client)
			for _, c := range append(slices.Clone(permitted), refused...) {
				if !slices.Contains(valid, c) {
					t.Errorf("ValidCommands %v lacks command %d", valid, c)
				}
			}
		})
	}
}

// TestTokenAuthorizationLimitsSurviveSessionReuse: the limits are kept with the
// session, so a command outside them is refused on a resumed session and as a
// follow-on command on a kept-alive one, while one inside them still runs.
func TestTokenAuthorizationLimitsSurviveSessionReuse(t *testing.T) {
	keyDir := tokenKeyDir(t)
	limited := idToken(t, keyDir, []string{"ADVERTISE_STARTD"})
	ran := make(chan limitsDispatch, 2)
	srv := newLimitsServer(keyDir, ran)

	clientCache := security.NewSessionCache()
	first := dispatchLimits(t, srv, ran, limitsClientConfig(limited, readCmd, clientCache), 0)[0]
	if first.serveErr != nil || !first.ran {
		t.Fatalf("first command: ran=%t err=%v", first.ran, first.serveErr)
	}
	sesid := first.client.SessionId
	if sesid == "" {
		t.Fatal("no session id")
	}

	resume := func(t *testing.T, cmd int) limitsDispatch {
		t.Helper()
		cfg := limitsClientConfig(limited, cmd, clientCache)
		cfg.SessionID = sesid
		res := dispatchLimits(t, srv, ran, cfg, 0)[0]
		if !res.client.SessionResumed {
			t.Fatal("client did not resume the session")
		}
		return res
	}
	t.Run("resumed/refused", func(t *testing.T) {
		for _, cmd := range []int{negotiatorCmd, adminCmd} {
			if res := resume(t, cmd); res.ran || res.serveErr == nil {
				t.Errorf("command %d on the resumed session: ran=%t err=%v, want it refused", cmd, res.ran, res.serveErr)
			}
		}
	})
	t.Run("resumed/permitted", func(t *testing.T) {
		res := resume(t, advertiseStartdCmd)
		if res.serveErr != nil || !res.ran {
			t.Fatalf("ran=%t err=%v, want it run", res.ran, res.serveErr)
		}
		if !slices.Equal(res.limits, []string{"ADVERTISE_STARTD"}) {
			t.Errorf("Conn.AuthorizationLimits() = %q on the resumed session, want [ADVERTISE_STARTD]", res.limits)
		}
	})

	t.Run("kept-alive", func(t *testing.T) {
		for _, tc := range []struct {
			followOn int
			want     bool
		}{{negotiatorCmd, false}, {readCmd, true}} {
			res := dispatchLimits(t, srv, ran, limitsClientConfig(limited, advertiseStartdCmd, security.NewSessionCache()), tc.followOn)
			if !res[0].ran {
				t.Fatal("first command did not run")
			}
			if got := res[1].ran; got != tc.want {
				t.Errorf("follow-on command %d ran=%t (err %v), want %t", tc.followOn, got, res[1].serveErr, tc.want)
			}
		}
	})
}
