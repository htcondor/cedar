package security

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

// Authentication REQUIRED on either side means authentication must succeed
// (condor_secman.cpp ReconcileSecurityAttribute / ReconcileSecurityPolicyAds).
// These tests pin that for a client at REQUIRED talking to a server that only
// has authentication OPTIONAL, and the other direction for a client that is
// itself OPTIONAL.

type handshakeResult struct {
	neg *SecurityNegotiation
	err error
}

// runTokenHandshake runs a cedar server and client over a pipe. The server
// offers only TOKEN, trusts example.com and holds the POOL signing key. The
// client offers only TOKEN, presenting clientToken.
func runTokenHandshake(t *testing.T, clientLevel, serverLevel SecurityLevel, clientToken string, clientIssuerKeys []string) (client, server handshakeResult) {
	t.Helper()
	poolKeyFile, namedKeyDir, cleanup := setupTestSigningKeys(t)
	defer cleanup()

	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthToken},
		Authentication: clientLevel,
		Encryption:     SecurityNever,
		Integrity:      SecurityNever,
		Command:        commands.DC_AUTHENTICATE,
		Token:          clientToken,
		TokenDir:       t.TempDir(), // nothing to discover
		TrustDomain:    "example.com",
		IssuerKeys:     clientIssuerKeys,
		SessionCache:   NewSessionCache(),
	}
	serverConfig := &SecurityConfig{
		AuthMethods:             []AuthMethod{AuthToken},
		Authentication:          serverLevel,
		Encryption:              SecurityNever,
		Integrity:               SecurityNever,
		TrustDomain:             "example.com",
		TokenPoolSigningKeyFile: poolKeyFile,
		TokenSigningKeyDir:      namedKeyDir,
		SessionCache:            NewSessionCache(),
	}

	serverDone := make(chan handshakeResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		neg, err := NewAuthenticator(serverConfig, stream.NewStream(serverConn)).ServerHandshake(ctx)
		serverDone <- handshakeResult{neg, err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client.neg, client.err = NewAuthenticator(clientConfig, stream.NewStream(clientConn)).ClientHandshake(ctx)
	// A failed client stops talking; closing its end unblocks a server still
	// waiting for the next auth message.
	if client.err != nil {
		_ = clientConn.Close()
	}

	select {
	case server = <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake did not complete")
	}
	return client, server
}

// (a) client REQUIRED + server OPTIONAL + the client's only method fails:
// the connection fails on both ends, and the client says why.
func TestClientRequiredFailsAgainstOptionalServer(t *testing.T) {
	cases := []struct {
		name       string
		token      string
		issuerKeys []string
	}{
		// The token's issuer is not the server's trust domain, so TOKEN is
		// never attempted: no compatible method at all.
		{"incompatible token", createTestJWT("alice", "other.example.org", 3600), nil},
		// The token is attempted and the server rejects it.
		{"rejected token", createUnknownKeyTestJWT("alice", "example.com"), []string{"UNKNOWN_SIGNING_KEY"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := runTokenHandshake(t, SecurityRequired, SecurityOptional, tc.token, tc.issuerKeys)
			if client.err == nil {
				t.Fatalf("client at REQUIRED completed with authenticated=%v method=%s; want failure",
					client.neg.Authentication, client.neg.NegotiatedAuth)
			}
			t.Logf("client: %v", client.err)
			if !strings.Contains(client.err.Error(), "authentication is required") {
				t.Errorf("client error does not say authentication was required: %v", client.err)
			}
			if server.err == nil {
				t.Errorf("server served a REQUIRED client unauthenticated (authenticated=%v)", server.neg.Authentication)
			}
		})
	}
}

// (b) neither side REQUIRED + the method fails: still completes
// unauthenticated on both ends, as before. OPTIONAL/OPTIONAL does not enact
// authentication at all; with either side PREFERRED it is enacted, fails,
// and falls back.
func TestClientOptionalFallsBackAgainstOptionalServer(t *testing.T) {
	for _, tc := range []struct{ client, server SecurityLevel }{
		{SecurityOptional, SecurityOptional},
		{SecurityPreferred, SecurityOptional},
		{SecurityOptional, SecurityPreferred},
	} {
		t.Run("client "+string(tc.client)+"/server "+string(tc.server), func(t *testing.T) {
			client, server := runTokenHandshake(t, tc.client, tc.server,
				createUnknownKeyTestJWT("alice", "example.com"), []string{"UNKNOWN_SIGNING_KEY"})
			if client.err != nil {
				t.Fatalf("client handshake failed instead of falling back to unauthenticated: %v", client.err)
			}
			if client.neg.Authentication {
				t.Errorf("client: authenticated via %s, want an unauthenticated session", client.neg.NegotiatedAuth)
			}
			if server.err != nil {
				t.Fatalf("server dropped the connection instead of serving anonymously: %v", server.err)
			}
			if server.neg.Authentication || server.neg.User != "" {
				t.Errorf("server: authenticated=%v user=%q, want an unauthenticated session",
					server.neg.Authentication, server.neg.User)
			}
		})
	}
}

// (c) client REQUIRED + server OPTIONAL + the method succeeds: authenticated
// as the token's subject.
func TestClientRequiredAuthenticatesAgainstOptionalServer(t *testing.T) {
	client, server := runTokenHandshake(t, SecurityRequired, SecurityOptional,
		createTestJWT("alice@example.com", "example.com", 3600), []string{"POOL"})
	if client.err != nil {
		t.Fatalf("client handshake failed: %v", client.err)
	}
	if server.err != nil {
		t.Fatalf("server handshake failed: %v", server.err)
	}
	if !client.neg.Authentication || client.neg.NegotiatedAuth != AuthToken {
		t.Errorf("client: authenticated=%v method=%s, want TOKEN", client.neg.Authentication, client.neg.NegotiatedAuth)
	}
	if server.neg.User != "alice@example.com" {
		t.Errorf("server authenticated %q, want alice@example.com", server.neg.User)
	}
}

// A server that advertises AuthRequired=false to a REQUIRED client (an older
// cedar server did, from its own level alone) does not get to downgrade it.
// The fake server below speaks only the auth-method exchange, so this pins
// the client's own check independently of the server-side fix.
func TestClientRequiredIgnoresServerAuthRequiredFalse(t *testing.T) {
	notRequired := false
	for _, tc := range []struct {
		name  string
		token string
		keys  []string
	}{
		{"incompatible token", createTestJWT("alice", "other.example.org", 3600), nil},
		{"server rejects every method", createTestJWT("alice", "example.com", 3600), []string{"POOL"}},
	} {
		for _, level := range []SecurityLevel{SecurityRequired, SecurityOptional} {
			t.Run(tc.name+"/client "+string(level), func(t *testing.T) {
				serverConn, clientConn := net.Pipe()
				defer func() { _ = serverConn.Close() }()
				defer func() { _ = clientConn.Close() }()

				// Answer every bitmask with 0: no method acceptable.
				go func() {
					s := stream.NewStream(serverConn)
					ctx := context.Background()
					for {
						bitmask, err := message.NewMessageFromStream(s).GetInt(ctx)
						if err != nil || bitmask == 0 {
							return
						}
						reply := message.NewMessageForStream(s)
						if reply.PutInt(ctx, 0) != nil || reply.FinishMessage(ctx) != nil {
							return
						}
					}
				}()

				a := NewAuthenticator(&SecurityConfig{
					AuthMethods:    []AuthMethod{AuthToken},
					Authentication: level,
					Token:          tc.token,
					TokenDir:       t.TempDir(),
					TrustDomain:    "example.com",
					IssuerKeys:     tc.keys,
				}, stream.NewStream(clientConn))
				neg := &SecurityNegotiation{
					ClientConfig: a.config,
					ServerConfig: &SecurityConfig{
						Authentication: "YES",
						AuthRequired:   &notRequired,
						AuthMethods:    []AuthMethod{AuthToken},
						TrustDomain:    "example.com",
					},
					IsClient:       true,
					Authentication: true,
					NegotiatedAuth: AuthToken,
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				err := a.handleClientAuthentication(ctx, neg)

				if level == SecurityRequired {
					if err == nil {
						t.Fatal("REQUIRED client proceeded unauthenticated because the server said AuthRequired=false")
					}
					if !strings.Contains(err.Error(), "authentication is required") {
						t.Errorf("error does not say authentication was required: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("OPTIONAL client should fall back when the server allows it: %v", err)
				}
				if neg.Authentication || neg.NegotiatedAuth != AuthNone {
					t.Errorf("authenticated=%v method=%s, want unauthenticated", neg.Authentication, neg.NegotiatedAuth)
				}
			})
		}
	}
}

// A server that answers Authentication=NO to a REQUIRED client is not
// believed either: a reconciling server enacts authentication or rejects.
func TestClientRequiredRejectsServerNotEnactingAuth(t *testing.T) {
	for _, level := range []SecurityLevel{SecurityRequired, SecurityOptional} {
		t.Run("client "+string(level), func(t *testing.T) {
			a := &Authenticator{config: &SecurityConfig{Authentication: level}}
			neg := &SecurityNegotiation{
				ClientConfig: a.config,
				ServerConfig: &SecurityConfig{Authentication: "NO", AuthMethods: []AuthMethod{AuthToken}},
				IsClient:     true,
			}
			// No stream: neither outcome may touch the wire.
			err := a.handleClientAuthentication(context.Background(), neg)
			if level == SecurityRequired {
				if err == nil || !strings.Contains(err.Error(), "authentication is required") {
					t.Errorf("REQUIRED client accepted Authentication=NO: err=%v", err)
				}
				return
			}
			if err != nil {
				t.Errorf("OPTIONAL client should accept Authentication=NO: %v", err)
			}
		})
	}
}

// The server folds the client's level into AuthRequired: an OPTIONAL server
// enacting auth for a REQUIRED client must not advertise AuthRequired=false,
// while it still does for an OPTIONAL client.
func TestServerAdvertisesClientRequiredAuth(t *testing.T) {
	server := &Authenticator{config: &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthToken},
		Authentication: SecurityOptional,
	}}
	for _, tc := range []struct {
		client    SecurityLevel
		wantFalse bool
	}{
		{SecurityRequired, false},
		{SecurityPreferred, true},
		{SecurityOptional, true},
	} {
		ad := server.createServerSecurityAd(&SecurityNegotiation{
			ClientConfig:   &SecurityConfig{Authentication: tc.client},
			Authentication: true,
			NegotiatedAuth: AuthToken,
		})
		v, ok := ad.EvaluateAttrBool("AuthRequired")
		if gotFalse := ok && !v; gotFalse != tc.wantFalse {
			t.Errorf("client %s: advertised AuthRequired=false is %v, want %v", tc.client, gotFalse, tc.wantFalse)
		}
	}
}

// The server half: a client that advertised REQUIRED and then gives up (a 0
// bitmask) is refused even by an OPTIONAL server, as daemon_command.cpp
// refuses when the reconciled ATTR_SEC_AUTH_REQUIRED is true. The client is
// hand-driven because a compliant one never gives up while REQUIRED.
func TestServerRejectsGiveUpFromRequiredClient(t *testing.T) {
	for _, tc := range []struct {
		client    SecurityLevel
		wantError bool
	}{
		{SecurityRequired, true},
		{SecurityOptional, false},
	} {
		t.Run("client "+string(tc.client), func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer func() { _ = clientConn.Close() }()

			serverConfig := &SecurityConfig{
				AuthMethods:    []AuthMethod{AuthToken},
				Authentication: SecurityPreferred, // enacts auth for an OPTIONAL client too
				Encryption:     SecurityNever,
				Integrity:      SecurityNever,
				TrustDomain:    "example.com",
				SessionCache:   NewSessionCache(),
			}
			serverErr := make(chan error, 1)
			go func() {
				defer func() { _ = serverConn.Close() }()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_, err := NewAuthenticator(serverConfig, stream.NewStream(serverConn)).ServerHandshake(ctx)
				serverErr <- err
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s := stream.NewStream(clientConn)
			clientAd := (&Authenticator{config: &SecurityConfig{
				AuthMethods:    []AuthMethod{AuthToken},
				Authentication: tc.client,
				Encryption:     SecurityNever,
				Integrity:      SecurityNever,
				Command:        commands.DC_AUTHENTICATE,
			}}).createClientSecurityAd()
			hello := message.NewMessageForStream(s)
			if err := hello.PutInt(ctx, commands.DC_AUTHENTICATE); err != nil {
				t.Fatal(err)
			}
			if err := hello.PutClassAd(ctx, clientAd); err != nil {
				t.Fatal(err)
			}
			if err := hello.FinishMessage(ctx); err != nil {
				t.Fatal(err)
			}
			resp, err := message.NewMessageFromStream(s).GetClassAd(ctx)
			if err != nil {
				t.Fatalf("reading the server's response: %v", err)
			}
			v, ok := resp.EvaluateAttrBool("AuthRequired")
			if advertisedFalse := ok && !v; advertisedFalse == tc.wantError {
				t.Errorf("server advertised AuthRequired=false: %v, want %v", advertisedFalse, !tc.wantError)
			}
			giveUp := message.NewMessageForStream(s)
			if err := giveUp.PutInt(ctx, 0); err != nil {
				t.Fatal(err)
			}
			if err := giveUp.FinishMessage(ctx); err != nil {
				t.Fatal(err)
			}
			// Drain the post-auth ad, if the server sends one.
			_, _ = message.NewMessageFromStream(s).GetClassAd(ctx)

			select {
			case err := <-serverErr:
				if tc.wantError && err == nil {
					t.Error("server served a REQUIRED client that gave up on authentication")
				}
				if !tc.wantError && err != nil {
					t.Errorf("server refused an OPTIONAL client that gave up: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server handshake did not complete")
			}
		})
	}
}
