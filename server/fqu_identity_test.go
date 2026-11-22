package server

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// tokenHandshake serves one ADMINISTRATOR command to a client that
// authenticates by IDTOKENS with a token whose subject is sub, issued by the
// server's trust domain "pool" under its POOL key.
func tokenHandshake(t *testing.T, sub string, allow map[string][]string, mapper func(authUser, peerAddr string) string) dispatchResult {
	t.Helper()
	keyDir := t.TempDir()
	if err := security.GeneratePoolSigningKey(filepath.Join(keyDir, "POOL")); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	token, err := security.GenerateJWT(keyDir, "POOL", sub, "pool", now, now+3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &security.SecurityConfig{
		AuthMethods:             []security.AuthMethod{security.AuthToken},
		Authentication:          security.SecurityRequired,
		Encryption:              security.SecurityOptional,
		Integrity:               security.SecurityOptional,
		TrustDomain:             "pool",
		UIDDomain:               "uid.example",
		TokenPoolSigningKeyFile: filepath.Join(keyDir, "POOL"),
		TokenSigningKeyDir:      keyDir,
		SessionCache:            security.NewSessionCache(),
	}
	cliCfg := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityRequired,
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Command:        adminCmd,
		Token:          token,
		TokenDir:       t.TempDir(),
		TrustDomain:    "pool",
		SessionCache:   security.NewSessionCache(),
	}
	authz := &globAuthorizer{allow: allow}
	ran := make(chan handlerView, 1)
	srv := newAdminServer(srvCfg, authz, ran)
	srv.FQUMapper = mapper
	return serve(t, srv, authz, ran, func(ctx context.Context, conn net.Conn) error {
		_, err := security.NewAuthenticator(cliCfg, stream.NewStream(conn)).ClientHandshake(ctx)
		return err
	})
}

var adminAnyCondor = map[string][]string{"ADMINISTRATOR": {"condor@*"}}

// TestIDTokenPeerIsItsSubject: an IDTOKENS peer is authorized as its token
// subject, domain included, so ALLOW condor@* admits sub condor@pool.
func TestIDTokenPeerIsItsSubject(t *testing.T) {
	res := tokenHandshake(t, poolAdmin, adminAnyCondor, nil)
	assertRanAs(t, res, poolAdmin)
}

// TestIDTokenBareSubjectStaysBare: C++ leaves a subject with no '@' bare, so it
// matches neither condor@* nor gets the UID domain appended.
func TestIDTokenBareSubjectStaysBare(t *testing.T) {
	res := tokenHandshake(t, "condor", adminAnyCondor, nil)
	if res.handler != nil {
		t.Errorf("handler ran as %q, want condor refused by condor@*", res.handler.user)
	}
	for _, u := range res.seen {
		if u != "condor" {
			t.Errorf("Authorizer saw %q, want only the bare subject condor", u)
		}
	}
	if len(res.seen) == 0 {
		t.Error("Authorizer was never asked")
	}
	res = tokenHandshake(t, "condor", map[string][]string{"ADMINISTRATOR": {"condor"}}, nil)
	assertRanAs(t, res, "condor")
}

// TestFQUMapperSeesFQU: FQUMapper receives the method's FQU, and a mapped name
// without an '@' takes the UID domain, as a C++ map file's result does.
func TestFQUMapperSeesFQU(t *testing.T) {
	var got string
	mapper := func(authUser, _ string) string {
		got = authUser
		return "Admin"
	}
	res := tokenHandshake(t, "alice@Pool", map[string][]string{"ADMINISTRATOR": {"Admin@uid.example"}}, mapper)
	if got != "alice@pool" {
		t.Errorf("FQUMapper saw %q, want alice@pool", got)
	}
	assertRanAs(t, res, "Admin@uid.example")

	res = tokenHandshake(t, "alice@pool", map[string][]string{"ADMINISTRATOR": {"admin@other"}},
		func(string, string) string { return "admin@Other" })
	assertRanAs(t, res, "admin@other")
}

// TestResumedBareSessionFailsClosed: a session cached with a bare user, as an
// older cedar recorded every identity, is not admitted by a user@domain rule.
func TestResumedBareSessionFailsClosed(t *testing.T) {
	res := resumeSession(t, "condor", true, adminAnyCondor)
	if res.handler != nil {
		t.Errorf("handler ran as %q, want the bare session refused", res.handler.user)
	}
	assertRanAs(t, resumeSession(t, poolAdmin, true, adminAnyCondor), poolAdmin)
}
