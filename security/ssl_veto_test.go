package security

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/stream"
)

// TestServerOfferedAuthMethodsVetoesSSLWithoutCert unit-tests the filter: SSL and
// SCITOKENS are dropped only when a cert is configured but unreadable.
func TestServerOfferedAuthMethodsVetoesSSLWithoutCert(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := GenerateTestCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	goodCert, goodKey := filepath.Join(dir, "h.crt"), filepath.Join(dir, "h.key")
	if err := GenerateTestHostCert(goodCert, goodKey, caCert, caKey, "localhost"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name              string
		methods           []AuthMethod
		certFile, keyFile string
		want              []AuthMethod
	}{
		{"configured but unreadable => veto TLS", []AuthMethod{AuthSSL, AuthSciTokens, AuthClaimToBe}, "/no/cert.pem", "/no/key.pem", []AuthMethod{AuthClaimToBe}},
		{"readable cert => keep TLS", []AuthMethod{AuthSSL, AuthClaimToBe}, goodCert, goodKey, []AuthMethod{AuthSSL, AuthClaimToBe}},
		{"empty cert config => unchanged", []AuthMethod{AuthSSL, AuthClaimToBe}, "", "", []AuthMethod{AuthSSL, AuthClaimToBe}},
		{"no TLS method => unchanged", []AuthMethod{AuthFS, AuthClaimToBe}, "/no/cert.pem", "/no/key.pem", []AuthMethod{AuthFS, AuthClaimToBe}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Authenticator{config: &SecurityConfig{AuthMethods: tc.methods, CertFile: tc.certFile, KeyFile: tc.keyFile}}
			got := a.serverOfferedAuthMethods()
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestServerVetoesSSLEndToEnd verifies that against a server whose configured cert
// is unreadable, a client offering [SSL, ClaimToBe] never attempts SSL and
// negotiates ClaimToBe instead -- the server did not advertise SSL.
func TestServerVetoesSSLEndToEnd(t *testing.T) {
	GetSessionCache().Clear()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthSSL, AuthClaimToBe},
		Authentication: SecurityRequired,
		Encryption:     SecurityNever,
		Integrity:      SecurityNever,
		Command:        commands.DC_AUTHENTICATE,
		TrustDomain:    "test.domain",
	}
	serverConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthSSL, AuthClaimToBe},
		Authentication: SecurityRequired,
		Encryption:     SecurityNever,
		Integrity:      SecurityNever,
		TrustDomain:    "test.domain",
		// Cert configured but unreadable => SSL must be vetoed, not offered.
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}

	serverDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := NewAuthenticator(serverConfig, stream.NewStream(serverConn)).ServerHandshake(ctx)
		serverDone <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	neg, err := NewAuthenticator(clientConfig, stream.NewStream(clientConn)).ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	if neg.NegotiatedAuth != AuthClaimToBe {
		t.Errorf("negotiated %s, want CLAIMTOBE (SSL should have been vetoed and never attempted)", neg.NegotiatedAuth)
	}
	select {
	case serr := <-serverDone:
		if serr != nil {
			t.Errorf("server handshake failed: %v", serr)
		}
	case <-time.After(5 * time.Second):
		t.Error("server handshake did not complete")
	}
}
