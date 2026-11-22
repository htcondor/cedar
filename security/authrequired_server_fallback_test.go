package security

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/stream"
)

// TestServerContinuesUnauthenticatedWhenClientGivesUp is the server half of the
// AuthRequired=false fallback, and a regression test for the asymmetry that
// PR #58 left behind: it taught the client to proceed unauthenticated when its
// enacted methods all fail, but the server still dropped the connection the
// instant the client signalled give-up (a 0 bitmask), so a Go client talking to
// a Go server never actually completed -- the client fell through to read the
// post-auth ClassAd while the server had closed the socket, surfacing as a bare
// EOF ("failed to read frame header: EOF"). That is exactly what an htcondordb
// mirror with only-PREFERRED read auth did to the webapp.
//
// Setup mirrors production: a PREFERRED server and an OPTIONAL client that share
// exactly one method (KERBEROS) which fails on both ends -- the production log
// shows a Go<->Go KERBEROS attempt aborting cleanly ("client aborted
// (readiness=-1)") without hanging. With auth enacted and every method spent,
// the client sends its final 0 bitmask; the server must serve the command with
// an anonymous session rather than erroring, because its own policy only
// PREFERS auth and it advertised AuthRequired=false.
func TestServerContinuesUnauthenticatedWhenClientGivesUp(t *testing.T) {
	GetSessionCache().Clear()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	// Only KERBEROS in common: it is offered by both, selected by the server,
	// and fails the handshake, leaving the client with no method left to try.
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthKerberos},
		Authentication: SecurityOptional,
		Encryption:     SecurityNever,
		Integrity:      SecurityNever,
		Command:        commands.DC_AUTHENTICATE,
		TrustDomain:    "test.domain",
	}
	serverConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthKerberos},
		Authentication: SecurityPreferred, // PREFERRED, not REQUIRED => anonymous is allowed
		Encryption:     SecurityNever,
		Integrity:      SecurityNever,
		TrustDomain:    "test.domain",
	}

	serverDone := make(chan struct {
		neg *SecurityNegotiation
		err error
	}, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		neg, err := NewAuthenticator(serverConfig, stream.NewStream(serverConn)).ServerHandshake(ctx)
		serverDone <- struct {
			neg *SecurityNegotiation
			err error
		}{neg, err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	neg, err := NewAuthenticator(clientConfig, stream.NewStream(clientConn)).ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("client handshake failed instead of falling back to unauthenticated: %v", err)
	}
	if neg.Authentication {
		t.Errorf("client: expected an unauthenticated session, got authenticated (%s)", neg.NegotiatedAuth)
	}
	if neg.NegotiatedAuth != AuthNone {
		t.Errorf("client: NegotiatedAuth = %s, want NONE", neg.NegotiatedAuth)
	}

	select {
	case res := <-serverDone:
		if res.err != nil {
			t.Fatalf("server dropped the connection instead of serving anonymously: %v", res.err)
		}
		if res.neg.Authentication {
			t.Errorf("server: expected an unauthenticated session, got authenticated (%s)", res.neg.NegotiatedAuth)
		}
		if res.neg.NegotiatedAuth != AuthNone {
			t.Errorf("server: NegotiatedAuth = %s, want NONE", res.neg.NegotiatedAuth)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake did not complete")
	}
}

// TestServerRejectsGiveUpWhenAuthRequired is the guard on the other side of the
// policy: a REQUIRED server must still fail when the client exhausts its methods,
// never silently downgrade to anonymous.
func TestServerRejectsGiveUpWhenAuthRequired(t *testing.T) {
	GetSessionCache().Clear()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthKerberos},
		Authentication: SecurityOptional,
		Encryption:     SecurityNever,
		Integrity:      SecurityNever,
		Command:        commands.DC_AUTHENTICATE,
		TrustDomain:    "test.domain",
	}
	serverConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthKerberos},
		Authentication: SecurityRequired, // REQUIRED => give-up is fatal
		Encryption:     SecurityNever,
		Integrity:      SecurityNever,
		TrustDomain:    "test.domain",
	}

	serverErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := NewAuthenticator(serverConfig, stream.NewStream(serverConn)).ServerHandshake(ctx)
		serverErr <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := NewAuthenticator(clientConfig, stream.NewStream(clientConn)).ClientHandshake(ctx); err == nil {
		t.Error("client handshake succeeded against a REQUIRED server with no usable method; want failure")
	}

	select {
	case err := <-serverErr:
		if err == nil {
			t.Error("server accepted an unauthenticated session under REQUIRED auth; want failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake did not complete")
	}
}
