package server

import (
	"context"
	"net"
	"os"
	"os/user"
	"strings"
	"testing"

	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// poolUIDDomain is the pool's UID_DOMAIN, the domain an ALLOW_<PERM> rule is
// written against. It is deliberately nothing like this host's name.
const poolUIDDomain = "chtc.example"

// fsServe runs one FS handshake against a server configured with uidDomain and
// an FQUMapper shaped like the one a daemon embedding cedar installs: it
// qualifies a bare name with the pool's UID domain and declines a name that
// already carries a domain, because that one came from the authentication
// method and is not the mapper's to rewrite.
func fsServe(t *testing.T, uidDomain string, allow map[string][]string) dispatchResult {
	t.Helper()
	srvCfg := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		UIDDomain:      uidDomain,
		SessionCache:   security.NewSessionCache(),
	}
	cliCfg := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Command:        adminCmd,
		SessionCache:   security.NewSessionCache(),
	}
	authz := &globAuthorizer{allow: allow}
	ran := make(chan handlerView, 1)
	srv := newAdminServer(srvCfg, authz, ran)
	srv.FQUMapper = func(authUser, _ string) string {
		if authUser == "" || strings.ContainsRune(authUser, '@') {
			return "" // anonymous, or already fully qualified
		}
		return authUser + "@" + poolUIDDomain
	}
	return serve(t, srv, authz, ran, func(ctx context.Context, conn net.Conn) error {
		_, err := security.NewAuthenticator(cliCfg, stream.NewStream(conn)).ClientHandshake(ctx)
		return err
	})
}

// TestFSPeerReachesTheMapperWithNoUIDDomain pins the regression that locked
// unprivileged users out of a daemon: a server that configures no UID domain
// must hand FS's bare owner to its FQUMapper, so the mapper can qualify it with
// the pool's UID_DOMAIN and ALLOW_<PERM> = *@<uid domain> admits the peer.
//
// Qualifying the owner with this host's name inside the authentication method
// instead produces owner@<hostname>. The mapper, seeing a domain, declines --
// it cannot tell a guess apart from a domain the method really established --
// and the peer is authorized as an identity no rule in the pool matches, so
// every local user is refused at the first command.
func TestFSPeerReachesTheMapperWithNoUIDDomain(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	want := cur.Username + "@" + poolUIDDomain
	res := fsServe(t, "", map[string][]string{"ADMINISTRATOR": {"*@" + poolUIDDomain}})
	assertRanAs(t, res, want)
	for _, seen := range res.seen {
		if seen != want {
			t.Errorf("Authorizer was asked about %q, want only %q (this host is %q)", seen, want, host)
		}
	}
}

// TestFSPeerKeepsAConfiguredUIDDomain: with UID_DOMAIN configured, FS qualifies
// the owner itself and the mapper leaves that identity alone -- the fix above
// must not cost a correctly configured daemon its domain.
func TestFSPeerKeepsAConfiguredUIDDomain(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	want := cur.Username + "@" + poolUIDDomain
	assertRanAs(t, fsServe(t, poolUIDDomain, map[string][]string{"ADMINISTRATOR": {"*@" + poolUIDDomain}}), want)
}
