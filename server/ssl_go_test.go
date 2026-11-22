package server

import (
	"context"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
)

// sslTestCerts holds a CA, a server certificate for "localhost" and a client
// certificate, all signed by the CA, plus a second CA that signed nothing
// the server uses.
type sslTestCerts struct {
	caCert, otherCACert   string
	hostCert, hostKey     string
	clientCert, clientKey string
}

func newSSLTestCerts(t *testing.T) sslTestCerts {
	t.Helper()
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	c := sslTestCerts{
		caCert:      p("ca.crt"),
		otherCACert: p("other-ca.crt"),
		hostCert:    p("host.crt"),
		hostKey:     p("host.key"),
		clientCert:  p("client.crt"),
		clientKey:   p("client.key"),
	}
	if err := security.GenerateTestCA(c.caCert, p("ca.key")); err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	if err := security.GenerateTestCA(c.otherCACert, p("other-ca.key")); err != nil {
		t.Fatalf("generate other CA: %v", err)
	}
	if err := security.GenerateTestHostCert(c.hostCert, c.hostKey, c.caCert, p("ca.key"), "localhost"); err != nil {
		t.Fatalf("generate host cert: %v", err)
	}
	if err := security.GenerateTestHostCert(c.clientCert, c.clientKey, c.caCert, p("ca.key"), "client.test"); err != nil {
		t.Fatalf("generate client cert: %v", err)
	}
	return c
}

const sslEchoCmd = 60124 // arbitrary authenticated command

// newSSLServer returns a server that authenticates by methods (SSL first) with
// the host certificate, requires encryption, and serves sslEchoCmd: it reads
// an ad and replies with the peer's identity, whether the server-side stream
// is encrypted, and the request's Hello. It also serves DC_NOP_READ, which
// condor_ping READ queries.
func newSSLServer(t *testing.T, certs sslTestCerts, methods ...security.AuthMethod) string {
	t.Helper()
	return newSSLServerWithAuth(t, certs, security.SecurityRequired, methods...)
}

// newSSLServerWithAuth is newSSLServer with an explicit Authentication level,
// so a test can tell apart a server that demands an identified peer from one
// that merely prefers one.
func newSSLServerWithAuth(t *testing.T, certs sslTestCerts, authLevel security.SecurityLevel, methods ...security.AuthMethod) string {
	t.Helper()
	srv := New(&security.SecurityConfig{
		AuthMethods:    methods,
		Authentication: authLevel,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityOptional,
		CertFile:       certs.hostCert,
		KeyFile:        certs.hostKey,
		CAFile:         certs.caCert,
	})
	srv.Authorizer = func(string, string, string) bool { return true }
	srv.Handle(sslEchoCmd, func(ctx context.Context, c *Conn) error {
		req, err := ccb.ReadControlAd(ctx, c.Stream)
		if err != nil {
			return err
		}
		return ccb.WriteControlAd(ctx, c.Stream, ccb.NewAd(map[string]any{
			"User":      c.AuthorizationUser(),
			"Method":    string(c.Negotiation.NegotiatedAuth),
			"Encrypted": c.Stream.IsEncrypted(),
			"Hello":     ccb.AdString(req, "Hello"),
		}))
	}, "READ")
	srv.Handle(commands.DC_NOP_READ, func(context.Context, *Conn) error { return nil }, "READ")
	return serveTCP(t, srv)
}

// sslClientConfig returns a client configuration that authenticates by methods
// (SSL first), trusts caFile, and verifies the server as "localhost". Its
// session cache starts empty, so its first connection authenticates in full;
// it is not the process default, where the server in this process keeps its
// end of the same sessions.
func sslClientConfig(caFile string, methods ...security.AuthMethod) *security.SecurityConfig {
	return &security.SecurityConfig{
		AuthMethods:    methods,
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityOptional,
		CAFile:         caFile,
		ServerName:     "localhost",
		Command:        sslEchoCmd,
		SessionCache:   security.NewSessionCache(),
	}
}

type sslEchoReply struct {
	user, method, hello string
	encrypted           bool
	resumed             bool
}

// sslEcho connects with cfg, runs sslEchoCmd over the authenticated stream and
// returns what the server reported, after checking the client's side of the
// session is encrypted with AES.
func sslEcho(t *testing.T, addr string, cfg *security.SecurityConfig) (sslEchoReply, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cl, err := client.ConnectAndAuthenticate(ctx, addr, cfg)
	if err != nil {
		return sslEchoReply{}, err
	}
	defer func() { _ = cl.Close() }()
	neg := cl.GetSecurityNegotiation()
	s := cl.GetStream()
	if !neg.Encryption || neg.NegotiatedCrypto != security.CryptoAES || !s.IsEncrypted() {
		t.Errorf("client session: Encryption=%v crypto=%q stream encrypted=%v, want AES encryption",
			neg.Encryption, neg.NegotiatedCrypto, s.IsEncrypted())
	}
	if err := ccb.WriteControlAd(ctx, s, ccb.NewAd(map[string]any{"Hello": "world"})); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply, err := ccb.ReadControlAd(ctx, s)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	encrypted, _ := reply.EvaluateAttrBool("Encrypted")
	return sslEchoReply{
		user:      ccb.AdString(reply, "User"),
		method:    ccb.AdString(reply, "Method"),
		hello:     ccb.AdString(reply, "Hello"),
		encrypted: encrypted,
		resumed:   neg.SessionResumed,
	}, nil
}

func checkSSLEcho(t *testing.T, got sslEchoReply, wantUser string) {
	t.Helper()
	if got.method != string(security.AuthSSL) {
		t.Errorf("server negotiated %q, want SSL", got.method)
	}
	if got.user != wantUser {
		t.Errorf("server saw user %q, want %q", got.user, wantUser)
	}
	if !got.encrypted {
		t.Error("server-side stream is not encrypted")
	}
	if got.hello != "world" {
		t.Errorf("server read Hello=%q, want %q", got.hello, "world")
	}
}

// TestGoSSLAuthentication runs SSL authentication between a cedar client and a
// cedar server over TCP, with the server presenting a certificate and the
// client presenting one or not, then sends a command over the encrypted
// session. A second connection resumes the session; one with an empty session
// cache performs the SSL exchange again.
func TestGoSSLAuthentication(t *testing.T) {
	certs := newSSLTestCerts(t)
	addr := newSSLServer(t, certs, security.AuthSSL)

	// A peer presenting no client certificate completes the TLS handshake --
	// ClientAuth is VerifyClientCertIfGiven -- but SSL has then identified
	// nobody, and the identity it yields is UnauthenticatedFQU. This server
	// requires authentication, so the command must be refused rather than
	// authorized under that literal name.
	t.Run("server certificate only is refused when authentication is required", func(t *testing.T) {
		_, err := sslEcho(t, addr, sslClientConfig(certs.caCert, security.AuthSSL))
		if err == nil {
			t.Fatal("an SSL peer with no client certificate satisfied Authentication=REQUIRED")
		}
	})

	// The same peer against a server that only prefers authentication: the
	// session is admitted, encrypted, and recorded as unauthenticated. This is
	// the legitimate case -- encryption without a client identity -- and the
	// guard above must not break it.
	t.Run("server certificate only is admitted when authentication is optional", func(t *testing.T) {
		optAddr := newSSLServerWithAuth(t, certs, security.SecurityOptional, security.AuthSSL)
		got, err := sslEcho(t, optAddr, sslClientConfig(certs.caCert, security.AuthSSL))
		if err != nil {
			t.Fatalf("SSL authentication: %v", err)
		}
		checkSSLEcho(t, got, UnauthenticatedFQU)
		if got.resumed {
			t.Error("first connection resumed a session")
		}
	})

	t.Run("mutual certificates", func(t *testing.T) {
		cfg := sslClientConfig(certs.caCert, security.AuthSSL)
		cfg.CertFile, cfg.KeyFile = certs.clientCert, certs.clientKey
		got, err := sslEcho(t, addr, cfg)
		if err != nil {
			t.Fatalf("SSL authentication: %v", err)
		}
		checkSSLEcho(t, got, "ssl@unmapped")

		// The second connection resumes the session the first one
		// established; the third, with an empty cache, authenticates again.
		got, err = sslEcho(t, addr, cfg)
		if err != nil {
			t.Fatalf("second connection: %v", err)
		}
		checkSSLEcho(t, got, "ssl@unmapped")
		if !got.resumed {
			t.Error("second connection did not resume the session")
		}
		cfg.SessionCache = security.NewSessionCache()
		got, err = sslEcho(t, addr, cfg)
		if err != nil {
			t.Fatalf("connection with an empty session cache: %v", err)
		}
		checkSSLEcho(t, got, "ssl@unmapped")
		if got.resumed {
			t.Error("connection with an empty session cache resumed a session")
		}
	})

	t.Run("many handshakes", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			cfg := sslClientConfig(certs.caCert, security.AuthSSL)
			withCert := i%2 == 1
			if withCert {
				cfg.CertFile, cfg.KeyFile = certs.clientCert, certs.clientKey
			}
			_, err := sslEcho(t, addr, cfg)
			if withCert && err != nil {
				t.Fatalf("handshake %d with a client certificate: %v", i, err)
			}
			if !withCert && err == nil {
				t.Fatalf("handshake %d had no client certificate yet satisfied Authentication=REQUIRED", i)
			}
		}
	})
}

// TestGoSSLUntrustedServerFallsBack has a client that does not trust the
// server's CA. The TLS handshake fails, both sides learn it in-band through the
// SSL status exchange, and they go on to authenticate with the next method on
// the same connection.
func TestGoSSLUntrustedServerFallsBack(t *testing.T) {
	certs := newSSLTestCerts(t)
	addr := newSSLServer(t, certs, security.AuthSSL, security.AuthClaimToBe)

	cfg := sslClientConfig(certs.otherCACert, security.AuthSSL, security.AuthClaimToBe)
	cfg.CertFile, cfg.KeyFile = certs.clientCert, certs.clientKey
	got, err := sslEcho(t, addr, cfg)
	if err != nil {
		t.Fatalf("authentication: %v", err)
	}
	if got.method != string(security.AuthClaimToBe) {
		t.Errorf("server negotiated %q, want CLAIMTOBE after SSL failed", got.method)
	}

	// With SSL as the only method the failure is reported, without hanging.
	_, err = sslEcho(t, addr, sslClientConfig(certs.otherCACert, security.AuthSSL))
	if err == nil {
		t.Fatal("SSL authentication succeeded against an untrusted server certificate")
	}
	if !strings.Contains(err.Error(), "SSL") {
		t.Errorf("error %q does not mention SSL", err)
	}
}

// TestCppPingSSL runs the installed condor_ping against a cedar server with SSL
// as the only authentication method, with and without a client certificate.
// Skipped when condor_ping is not installed.
func TestCppPingSSL(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	condorPing, err := exec.LookPath("condor_ping")
	if err != nil {
		t.Skip("condor_ping not installed")
	}
	certs := newSSLTestCerts(t)
	sinful := newSSLServer(t, certs, security.AuthSSL)
	// The alias is the name the C++ client checks the server certificate against.
	sinful = strings.TrimSuffix(sinful, ">") + "?alias=localhost>"

	for _, tc := range []struct {
		name  string
		extra []string
		user  string
	}{
		{"server certificate only", nil, UnauthenticatedFQU},
		{"mutual certificates", []string{
			"AUTH_SSL_CLIENT_CERTFILE = " + certs.clientCert,
			"AUTH_SSL_CLIENT_KEYFILE = " + certs.clientKey,
		}, "ssl@unmapped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := cppToolConfig(t, append([]string{
				"SEC_CLIENT_AUTHENTICATION_METHODS = SSL",
				"SEC_CLIENT_ENCRYPTION = REQUIRED",
				"SEC_CLIENT_CRYPTO_METHODS = AES",
				"AUTH_SSL_CLIENT_CAFILE = " + certs.caCert,
			}, tc.extra...)...)
			stdout, stderr, err := runTool(t, config, condorPing, "-addr", sinful, "-verbose", "READ")
			t.Logf("condor_ping: %v\nstdout:\n%s", err, stdout)
			if err != nil {
				t.Logf("stderr:\n%s", stderr)
				t.Fatalf("condor_ping READ over SSL failed: %v", err)
			}
			for _, want := range []*regexp.Regexp{
				regexp.MustCompile(`Authenticated using:\s+SSL\n`),
				regexp.MustCompile(`Encryption:\s+AES`),
				regexp.MustCompile(`Remote Mapping:\s+` + regexp.QuoteMeta(tc.user) + `\n`),
				regexp.MustCompile(`Authorized:\s+TRUE`),
			} {
				if !want.MatchString(stdout) {
					t.Errorf("condor_ping output does not match %s", want)
				}
			}
		})
	}
}
