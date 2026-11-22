package server

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/security"
)

// unregisteredCmd is a command no test server registers.
const unregisteredCmd = 81999

// newClaimToBeServer returns a server that requires CLAIMTOBE and encryption
// and whose Authorizer allows every authenticated identity at every level. It
// serves the commands of handleEveryLevel.
func newClaimToBeServer(ran chan<- limitsDispatch) *Server {
	srv := New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthClaimToBe},
		Authentication: security.SecurityRequired,
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		UIDDomain:      "pool",
		SessionCache:   security.NewSessionCache(),
	})
	srv.Authorizer = func(_, _, user string) bool { return user != UnauthenticatedFQU }
	handleEveryLevel(srv, ran)
	return srv
}

// claimToBeClientConfig is a client config that authenticates by CLAIMTOBE for
// command, caching its sessions in cache.
func claimToBeClientConfig(command int, cache *security.SessionCache) *security.SecurityConfig {
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthClaimToBe},
		Authentication: security.SecurityRequired,
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		UIDDomain:      "pool",
		Command:        command,
		PeerName:       limitsServerAddr,
		SessionCache:   cache,
	}
}

// uniqueUser returns an identity no other test uses, to find the sessions
// cached for it.
func uniqueUser(t *testing.T) string {
	return fmt.Sprintf("%s-%d@pool", strings.ReplaceAll(t.Name(), "/", "-"), time.Now().UnixNano())
}

// sessionCachedFor reports whether the server's session cache holds a session
// for user. A full handshake caches its session in the global cache.
func sessionCachedFor(user string) bool {
	for _, e := range security.GetSessionCache().Snapshot() {
		if p := e.Policy(); p != nil {
			if u, ok := p.EvaluateAttrString("User"); ok && u == user {
				return true
			}
		}
	}
	return false
}

// denial returns the AuthorizationError a client handshake failed with,
// checking that the server's post-auth reply carried returnCode.
func denial(t *testing.T, clientErr error, returnCode string) security.AuthorizationError {
	t.Helper()
	var ae *security.AuthorizationError
	if !errors.As(clientErr, &ae) {
		t.Fatalf("client handshake error = %v, want an AuthorizationError with ReturnCode %s", clientErr, returnCode)
	}
	if ae.ReturnCode != returnCode {
		t.Errorf("ReturnCode = %q, want %q", ae.ReturnCode, returnCode)
	}
	return *ae
}

// TestRefusedCommandIsDenied: a command the Authorizer refuses on a full
// handshake is answered DENIED in the post-auth reply, which reports the
// mapped identity and that the server authenticated the peer; the session is
// not cached; ServeConn reports the refusal itself. A command the identity may
// run is answered AUTHORIZED and its session cached.
func TestRefusedCommandIsDenied(t *testing.T) {
	user := uniqueUser(t)
	ran := make(chan limitsDispatch, 2)
	srv := newClaimToBeServer(ran)
	srv.FQUMapper = func(string, string) string { return user }
	srv.Authorizer = func(perm, _, u string) bool { return u == user && perm == "READ" }

	res := dispatchLimits(t, srv, ran, claimToBeClientConfig(adminCmd, security.NewSessionCache()), 0)[0]
	if res.ran {
		t.Fatal("refused command ran")
	}
	ae := denial(t, res.clientErr, "DENIED")
	if ae.User != user {
		t.Errorf("AuthorizationError.User = %q, want %q", ae.User, user)
	}
	if !ae.TriedAuthKnown || !ae.TriedAuthentication {
		t.Errorf("TriedAuthentication = %t (reported %t), want true", ae.TriedAuthentication, ae.TriedAuthKnown)
	}
	if res.serveErr == nil || !strings.Contains(res.serveErr.Error(), "refused: identity") ||
		strings.Contains(res.serveErr.Error(), "handshake failed") {
		t.Errorf("ServeConn error = %v, want the command's refusal", res.serveErr)
	}
	if sessionCachedFor(user) {
		t.Error("the refused command's session was cached")
	}

	res = dispatchLimits(t, srv, ran, claimToBeClientConfig(readCmd, security.NewSessionCache()), 0)[0]
	if res.clientErr != nil || res.serveErr != nil || !res.ran {
		t.Fatalf("permitted command: ran=%t client err=%v err=%v", res.ran, res.clientErr, res.serveErr)
	}
	if !sessionCachedFor(user) {
		t.Error("the permitted command's session was not cached")
	}
}

// TestUnauthenticatedDenialReportsNoAuthentication: a peer the server did not
// try to authenticate is refused without TriedAuthentication, as DaemonCore
// sends it only when true.
func TestUnauthenticatedDenialReportsNoAuthentication(t *testing.T) {
	res := freshHandshake(t, false, adminOnlyPool)
	assertRefused(t, res)
	ae := denial(t, res.clientErr, "DENIED")
	if ae.TriedAuthKnown {
		t.Errorf("TriedAuthentication reported (%t) for a peer the server did not authenticate", ae.TriedAuthentication)
	}
}

// TestUnregisteredCommandIsNotFound: a command the server has no handler for is
// answered CMD_NOT_FOUND, and its session is not cached.
func TestUnregisteredCommandIsNotFound(t *testing.T) {
	user := uniqueUser(t)
	ran := make(chan limitsDispatch, 1)
	srv := newClaimToBeServer(ran)
	srv.FQUMapper = func(string, string) string { return user }

	res := dispatchLimits(t, srv, ran, claimToBeClientConfig(unregisteredCmd, security.NewSessionCache()), 0)[0]
	_ = denial(t, res.clientErr, "CMD_NOT_FOUND")
	if !errors.Is(res.serveErr, security.ErrCommandNotFound) {
		t.Errorf("ServeConn error = %v, want ErrCommandNotFound", res.serveErr)
	}
	if sessionCachedFor(user) {
		t.Error("the unregistered command's session was cached")
	}
}

// TestClaimToBeLimitedToCommandLevel: a CLAIMTOBE session is limited to the
// level of the command it was negotiated for and the levels that implies, as in
// DaemonCore, although the Authorizer allows the claimed identity everything.
// The limit is advertised in ValidCommands and kept with the session, so a
// resumed or kept-alive session cannot run a command at another level.
func TestClaimToBeLimitedToCommandLevel(t *testing.T) {
	ran := make(chan limitsDispatch, 2)
	srv := newClaimToBeServer(ran)
	clientCache := security.NewSessionCache()

	first := dispatchLimits(t, srv, ran, claimToBeClientConfig(readCmd, clientCache), 0)[0]
	if first.clientErr != nil || first.serveErr != nil || !first.ran {
		t.Fatalf("READ command: ran=%t client err=%v err=%v", first.ran, first.clientErr, first.serveErr)
	}
	if !slices.Equal(first.limits, []string{"READ"}) {
		t.Errorf("Conn.AuthorizationLimits() = %q, want [READ]", first.limits)
	}
	valid := validCommands(first.client)
	for _, c := range []int{readCmd, allowCmd} {
		if !slices.Contains(valid, c) {
			t.Errorf("ValidCommands %v lacks command %d", valid, c)
		}
	}
	for _, c := range []int{adminCmd, negotiatorCmd, advertiseStartdCmd, daemonOrStartdCmd} {
		if slices.Contains(valid, c) {
			t.Errorf("ValidCommands %v includes command %d above the session's level", valid, c)
		}
	}

	resume := func(t *testing.T, cmd int) limitsDispatch {
		t.Helper()
		cfg := claimToBeClientConfig(cmd, clientCache)
		cfg.SessionID = first.client.SessionId
		res := dispatchLimits(t, srv, ran, cfg, 0)[0]
		if res.clientErr != nil || !res.client.SessionResumed {
			t.Fatalf("client did not resume the session: %v", res.clientErr)
		}
		return res
	}
	t.Run("resumed/refused", func(t *testing.T) {
		for _, cmd := range []int{adminCmd, negotiatorCmd} {
			res := resume(t, cmd)
			if res.ran || res.serveErr == nil || !strings.Contains(res.serveErr.Error(), "authorization limits") {
				t.Errorf("command %d on the resumed session: ran=%t err=%v, want it refused by the authorization limits", cmd, res.ran, res.serveErr)
			}
		}
	})
	t.Run("resumed/permitted", func(t *testing.T) {
		for _, cmd := range []int{readCmd, allowCmd} {
			if res := resume(t, cmd); res.serveErr != nil || !res.ran {
				t.Errorf("command %d on the resumed session: ran=%t err=%v, want it run", cmd, res.ran, res.serveErr)
			}
		}
	})

	t.Run("kept-alive", func(t *testing.T) {
		for _, tc := range []struct {
			followOn int
			want     bool
		}{{negotiatorCmd, false}, {readCmd, true}} {
			res := dispatchLimits(t, srv, ran, claimToBeClientConfig(advertiseStartdCmd, security.NewSessionCache()), tc.followOn)
			if !res[0].ran || !slices.Equal(res[0].limits, []string{"ADVERTISE_STARTD", "READ"}) {
				t.Fatalf("first command: ran=%t limits=%q, want it run limited to [ADVERTISE_STARTD READ]", res[0].ran, res[0].limits)
			}
			if got := res[1].ran; got != tc.want {
				t.Errorf("follow-on command %d ran=%t (err %v), want %t", tc.followOn, got, res[1].serveErr, tc.want)
			}
		}
	})

	// A full handshake for a higher level is limited to that level; with
	// alternates, to the primary one.
	t.Run("fresh", func(t *testing.T) {
		for _, tc := range []struct {
			cmd  int
			want []string
		}{
			{adminCmd, []string{"ADMINISTRATOR", "WRITE", "READ"}},
			{daemonOrStartdCmd, []string{"DAEMON", "WRITE", "READ"}},
		} {
			res := dispatchLimits(t, srv, ran, claimToBeClientConfig(tc.cmd, security.NewSessionCache()), 0)[0]
			if res.clientErr != nil || !res.ran {
				t.Fatalf("command %d: ran=%t client err=%v err=%v", tc.cmd, res.ran, res.clientErr, res.serveErr)
			}
			if !slices.Equal(res.limits, tc.want) {
				t.Errorf("command %d: Conn.AuthorizationLimits() = %q, want %q", tc.cmd, res.limits, tc.want)
			}
		}
	})
}

// TestMethodNamesIgnoreCase: method names match whatever their case, as in
// HTCondor, from either side's configuration, and are reported in upper case.
// IDTOKENS still matches TOKEN.
func TestMethodNamesIgnoreCase(t *testing.T) {
	t.Run("claimtobe", func(t *testing.T) {
		ran := make(chan limitsDispatch, 1)
		srv := newClaimToBeServer(ran)
		srv.SecurityConfig.AuthMethods = []security.AuthMethod{"claimtobe"}
		srv.SecurityConfig.CryptoMethods = []security.CryptoMethod{"aes"}
		cliCfg := claimToBeClientConfig(readCmd, security.NewSessionCache())
		cliCfg.AuthMethods = []security.AuthMethod{"ClaimToBe"}
		cliCfg.CryptoMethods = []security.CryptoMethod{"Aes"}

		res := dispatchLimits(t, srv, ran, cliCfg, 0)[0]
		if res.clientErr != nil || res.serveErr != nil || !res.ran {
			t.Fatalf("ran=%t client err=%v err=%v", res.ran, res.clientErr, res.serveErr)
		}
		if res.client.NegotiatedAuth != security.AuthClaimToBe || !res.client.Authentication {
			t.Errorf("client NegotiatedAuth = %q (authenticated %t), want CLAIMTOBE", res.client.NegotiatedAuth, res.client.Authentication)
		}
		if res.client.NegotiatedCrypto != security.CryptoAES || !res.client.Encryption {
			t.Errorf("client NegotiatedCrypto = %q (encrypted %t), want AES", res.client.NegotiatedCrypto, res.client.Encryption)
		}
		// The server recognized the method as CLAIMTOBE, so it limited the session.
		if !slices.Equal(res.limits, []string{"READ"}) {
			t.Errorf("Conn.AuthorizationLimits() = %q, want [READ]", res.limits)
		}
	})

	t.Run("idtokens", func(t *testing.T) {
		keyDir := tokenKeyDir(t)
		seen := make(chan tokenMethodSeen, 1)
		srv := newTokenMethodServer(keyDir, []security.AuthMethod{"idtokens"}, seen)
		cliCfg := limitsClientConfig(idToken(t, keyDir, nil), readCmd, security.NewSessionCache())
		cliCfg.AuthMethods = []security.AuthMethod{"Token"}

		ran := make(chan limitsDispatch, 1)
		res := dispatchLimits(t, srv, ran, cliCfg, 0)[0]
		if res.clientErr != nil || res.serveErr != nil {
			t.Fatalf("client err=%v err=%v", res.clientErr, res.serveErr)
		}
		if res.client.NegotiatedAuth != security.AuthToken {
			t.Errorf("client NegotiatedAuth = %q, want TOKEN", res.client.NegotiatedAuth)
		}
		select {
		case s := <-seen:
			if s.method != security.AuthIDTokens || s.user != "alice@"+limitsTrustDomain {
				t.Errorf("server saw %q via %q, want alice@%s via IDTOKENS", s.user, s.method, limitsTrustDomain)
			}
		default:
			t.Fatal("handler did not run")
		}
	})
}
