package security_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/internal/condortest"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// TestKerberosRoundTrip runs the pure-Go Kerberos client against the pure-Go
// Kerberos server over an in-memory pipe, both backed by an ephemeral KDC. It
// exercises the server half — keytab verify (krb5_rd_req) and the mutual-auth
// AP_REP — which the C++ interop test does not (that only drives our client), and
// confirms client and server agree end to end with an encrypted AES session.
//
// Skips unless the MIT krb5 tools are installed (i.e. the Docker interop image).
func TestKerberosRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Kerberos round-trip in short mode")
	}

	host, err := os.Hostname()
	if err != nil {
		t.Fatalf("hostname: %v", err)
	}
	kfix := condortest.SetupKerberos(t, host) // skips if krb5 tools are absent

	// Point both halves at the fixture: the client reads the ccache, the server the
	// keytab (loadKerberosServerKeytab honors KRB5_KTNAME).
	t.Setenv("KRB5_CONFIG", kfix.Krb5Conf)
	t.Setenv("KRB5CCNAME", "FILE:"+kfix.CCacheFile)
	t.Setenv("KRB5_KTNAME", "FILE:"+kfix.KeytabFile)

	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	clientStream := stream.NewStream(clientConn)
	serverStream := stream.NewStream(serverConn)
	// The client derives the SPN host/<host> from the peer's sinful alias.
	clientStream.SetPeerAddr(fmt.Sprintf("<127.0.0.1:0?alias=%s>", host))

	newConfig := func() *security.SecurityConfig {
		return &security.SecurityConfig{
			AuthMethods:    []security.AuthMethod{security.AuthKerberos},
			Authentication: security.SecurityRequired,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			Encryption:     security.SecurityRequired,
			Integrity:      security.SecurityRequired,
			Command:        commands.DC_NOP,
		}
	}
	clientAuth := security.NewAuthenticator(newConfig(), clientStream)
	serverAuth := security.NewAuthenticator(newConfig(), serverStream)

	type handshakeResult struct {
		neg *security.SecurityNegotiation
		err error
	}
	serverCh := make(chan handshakeResult, 1)
	go func() {
		neg, err := serverAuth.ServerHandshake(context.Background())
		serverCh <- handshakeResult{neg, err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clientNeg, err := clientAuth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	sr := <-serverCh
	if sr.err != nil {
		t.Fatalf("server handshake: %v", sr.err)
	}

	if clientNeg.NegotiatedAuth != security.AuthKerberos {
		t.Errorf("client negotiated %s, want KERBEROS", clientNeg.NegotiatedAuth)
	}
	if sr.neg.NegotiatedAuth != security.AuthKerberos {
		t.Errorf("server negotiated %s, want KERBEROS", sr.neg.NegotiatedAuth)
	}
	// Encryption required on both sides: a real AES-256-GCM key must have been
	// derived (via ECDH) for both to report an encrypted session.
	if !clientNeg.Encryption || !sr.neg.Encryption {
		t.Errorf("expected encrypted session, got client=%t server=%t", clientNeg.Encryption, sr.neg.Encryption)
	}
	// The server proved the keytab (krb5_rd_req) and learned the client identity.
	if want := "client@" + kfix.Realm; !strings.EqualFold(sr.neg.User, want) {
		t.Errorf("server saw user %q, want %q (case-insensitive)", sr.neg.User, want)
	}
	t.Logf("✅ Go↔Go KERBEROS round-trip OK — client user=%q server user=%q crypto=%s",
		clientNeg.User, sr.neg.User, clientNeg.NegotiatedCrypto)
}
