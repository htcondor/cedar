// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/htcondor/cedar/stream"
)

// writeUnreadableTLSCert writes a cert/key pair that is present and readable but
// not a valid certificate, so readCredential succeeds (passing the #54
// readability veto) but createTLSConfig fails at tls.X509KeyPair -- a TLS-setup
// failure that happens before the SSL status exchange.
func writeInvalidTLSCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, []byte("not a certificate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("not a key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func handshakePair(t *testing.T) (clientStream, serverStream *stream.Stream, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	type res struct {
		c   net.Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- res{c, err}
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	r := <-accepted
	_ = ln.Close()
	if r.err != nil {
		t.Fatal(r.err)
	}
	return stream.NewStream(cc), stream.NewStream(r.c), func() {
		_ = cc.Close()
		_ = r.c.Close()
	}
}

// TestServerFallsBackAfterTLSSetupFailure is the point of this change: when the
// server cannot set up TLS for a selected SSL method, it must NOT abort the
// connection. Instead it signals the failure through the SSL status exchange so
// the client falls back to the next offered method over the same connection.
func TestServerFallsBackAfterTLSSetupFailure(t *testing.T) {
	GetSessionCache().Clear()
	certFile, keyFile := writeInvalidTLSCert(t)
	clientStream, serverStream, cleanup := handshakePair(t)
	defer cleanup()

	serverCfg := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthSSL, AuthClaimToBe},
		Authentication: SecurityRequired,
		CryptoMethods:  []CryptoMethod{CryptoAES},
		TrustDomain:    "test.domain",
		CertFile:       certFile, // readable but invalid => createTLSConfig fails
		KeyFile:        keyFile,
	}
	clientCfg := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthSSL, AuthClaimToBe},
		Authentication: SecurityRequired,
		CryptoMethods:  []CryptoMethod{CryptoAES},
		TrustDomain:    "test.domain",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sErr := make(chan error, 1)
	go func() {
		_, err := NewAuthenticator(serverCfg, serverStream).ServerHandshake(ctx)
		sErr <- err
	}()

	done := make(chan struct{})
	var neg *SecurityNegotiation
	var cErr error
	go func() {
		neg, cErr = NewAuthenticator(clientCfg, clientStream).ClientHandshake(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("client handshake hung: server did not fall back after TLS setup failure")
	}
	if cErr != nil {
		t.Fatalf("client handshake failed instead of falling back: %v", cErr)
	}
	if neg.NegotiatedAuth != AuthClaimToBe {
		t.Errorf("negotiated %s, want CLAIMTOBE (SSL should have failed setup and fallen back)", neg.NegotiatedAuth)
	}
	select {
	case serr := <-sErr:
		if serr != nil {
			t.Errorf("server handshake failed: %v", serr)
		}
	case <-time.After(5 * time.Second):
		t.Error("server handshake did not complete")
	}
}

// TestClientFailsFastWhenTLSSetupFailsAndNoFallback confirms the connection is
// not left hanging when there is nothing to fall back to: the client offers only
// SSL, the server cannot set up TLS, and the client returns an error promptly
// rather than blocking forever.
func TestClientFailsFastWhenTLSSetupFailsAndNoFallback(t *testing.T) {
	GetSessionCache().Clear()
	certFile, keyFile := writeInvalidTLSCert(t)
	clientStream, serverStream, cleanup := handshakePair(t)
	defer cleanup()

	serverCfg := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthSSL},
		Authentication: SecurityRequired,
		CryptoMethods:  []CryptoMethod{CryptoAES},
		CertFile:       certFile,
		KeyFile:        keyFile,
	}
	clientCfg := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthSSL},
		Authentication: SecurityRequired,
		CryptoMethods:  []CryptoMethod{CryptoAES},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	go func() {
		_, _ = NewAuthenticator(serverCfg, serverStream).ServerHandshake(ctx)
	}()

	cDone := make(chan error, 1)
	go func() {
		_, err := NewAuthenticator(clientCfg, clientStream).ClientHandshake(ctx)
		cDone <- err
	}()

	select {
	case err := <-cDone:
		if err == nil {
			t.Fatal("client handshake unexpectedly succeeded against a server that cannot do TLS")
		}
		t.Logf("client failed (as expected, no fallback available): %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("client handshake hung: no fallback and no failure signaled")
	}
}
