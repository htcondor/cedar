package ccb

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/htcondor/cedar/security"
	cedarserver "github.com/htcondor/cedar/server"
)

// TestBrokerSSLVerifiesTheBrokersOwnName: the security config handed to a CCB
// dial is the caller's config for the TARGET, so a caller that pins the
// target's TLS name arrives here with ServerName set to it. An explicit
// ServerName beats the name the SSL handshake would derive from the peer
// address, so if the broker leg keeps it the broker's certificate is verified
// against the target's hostname and the dial fails outright --
//
//	tls: failed to verify certificate: x509: certificate is valid for
//	localhost, not target.example.org
//
// -- naming a host the caller never asked the broker to be.
func TestBrokerSSLVerifiesTheBrokersOwnName(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	caCert, caKey := p("ca.crt"), p("ca.key")
	if err := security.GenerateTestCA(caCert, caKey); err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	// The broker's certificate names the broker, and only the broker.
	hostCert, hostKey := p("host.crt"), p("host.key")
	if err := security.GenerateTestHostCert(hostCert, hostKey, caCert, caKey, "localhost"); err != nil {
		t.Fatalf("generate broker cert: %v", err)
	}
	clientCert, clientKey := p("client.crt"), p("client.key")
	if err := security.GenerateTestHostCert(clientCert, clientKey, caCert, caKey, "client.test"); err != nil {
		t.Fatalf("generate client cert: %v", err)
	}

	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthSSL},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityOptional,
		CertFile:       hostCert,
		KeyFile:        hostKey,
		CAFile:         caCert,
	})
	srv.Authorizer = func(string, string, string) bool { return true }
	srv.Handle(CommandRequest, func(context.Context, *cedarserver.Conn) error { return nil }, "READ")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() { _ = srv.ServeConn(ctx, conn) }()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	brokerAddr := net.JoinHostPort("localhost", port)

	sec := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthSSL},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityOptional,
		CAFile:         caCert,
		CertFile:       clientCert,
		KeyFile:        clientKey,
		SessionCache:   security.NewSessionCache(),
		RemoteVersion:  "$CondorVersion: 25.13.0 2026-06-21 BuildID: test $",
		// What a caller dialling a target behind CCB actually passes: the
		// target's identity, not the broker's.
		PeerName:   "<10.0.0.5:41339?CCBID=broker-a%2367>",
		ServerName: "target.example.org",
	}

	conn, _, _, err := dialBrokerAuthCmd(ctx, brokerAddr, sec, CommandRequest, brokerDial{})
	if err != nil {
		t.Fatalf("the broker leg verified the broker's certificate against the "+
			"TARGET's name instead of the broker's: %v", err)
	}
	_ = conn.Close()
}
