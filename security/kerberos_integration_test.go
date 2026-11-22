package security_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/internal/condortest"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// TestKerberosAuthenticationIntegration authenticates the pure-Go Kerberos client
// against a real C++ condor collector, both driven off an ephemeral KDC. It skips
// unless the MIT krb5 tools and condor_master are installed (i.e. it runs in the
// Docker interop image, not on a plain dev box).
//
// The service principal, the address the client dials, and KERBEROS_SERVER_SERVICE
// must all agree on the host component; we use the machine hostname throughout.
// Kerberos hostname canonicalization is the thing most likely to need tuning when
// this first runs against C++ — see kerberosServerSPN in kerberos_auth.go.
func TestKerberosAuthenticationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	host, err := os.Hostname()
	if err != nil {
		t.Fatalf("hostname: %v", err)
	}

	kfix := condortest.SetupKerberos(t, host) // skips if krb5 tools are absent

	harness := condortest.NewWithConfig(t, kfix.CondorConfig())
	t.Logf("Collector at %s:%d, realm %s, service %s/%s",
		harness.GetCollectorHost(), harness.GetCollectorPort(), kfix.Realm, kfix.Service, host)

	// Point the Go krb5 client at the fixture's config + client ccache.
	t.Setenv("KRB5_CONFIG", kfix.Krb5Conf)
	t.Setenv("KRB5CCNAME", "FILE:"+kfix.CCacheFile)

	collectorHost, port := harness.GetCollectorHost(), harness.GetCollectorPort()
	addr := net.JoinHostPort(collectorHost, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial collector %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()

	cedarStream := stream.NewStream(conn)
	// Carry the collector's advertised address (with alias=<hostname>) so the
	// Kerberos SPN resolves to host/<hostname> matching the keytab — no DNS. A real
	// client gets this sinful string from the collector's MyAddress.
	cedarStream.SetPeerAddr(fmt.Sprintf("<%s:%d?alias=%s>", collectorHost, port, host))
	clientConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthKerberos},
		Authentication: security.SecurityRequired,
		// Require encryption so the collector performs the wrapped-key exchange and
		// we exercise the krb5 unwrap of the CEDAR session key.
		CryptoMethods: []security.CryptoMethod{security.CryptoAES},
		Encryption:    security.SecurityRequired,
		Integrity:     security.SecurityRequired,
		Command:       commands.DC_NOP,
	}

	auth := security.NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("KERBEROS handshake against C++ collector failed: %v", err)
	}

	t.Logf("✅ KERBEROS interop OK — negotiated=%s crypto=%s encryption=%t user=%q session=%s",
		negotiation.NegotiatedAuth, negotiation.NegotiatedCrypto, negotiation.Encryption,
		negotiation.User, negotiation.SessionId)
	if negotiation.NegotiatedAuth != security.AuthKerberos {
		t.Errorf("negotiated auth = %s, want KERBEROS", negotiation.NegotiatedAuth)
	}
	// The client required encryption, so a real AES-256-GCM session key must have
	// been established (via the ECDH exchange, independent of Kerberos). If this is
	// false the handshake authenticated but silently fell back to plaintext.
	if !negotiation.Encryption {
		t.Errorf("session is not encrypted; expected AES-256-GCM after requiring encryption")
	}
	if !isAESGCMCrypto(negotiation.NegotiatedCrypto) {
		t.Errorf("negotiated crypto = %s, want AES", negotiation.NegotiatedCrypto)
	}
}

// isAESGCMCrypto reports whether the negotiated crypto name denotes AES-256-GCM;
// a freshly negotiated session records "AES" while inherited sessions use "AESGCM".
func isAESGCMCrypto(m security.CryptoMethod) bool {
	return m == security.CryptoAES || m == "AESGCM"
}
