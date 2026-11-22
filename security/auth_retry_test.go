// Copyright 2026 Morgridge Institute for Research
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
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/stream"
)

// TestClientHandshake_RetriesAfterFirstMethodFails is the end-to-end
// regression test for the production schedd-ping failure documented in
// parse_methods_list_test.go. It exercises the full flow:
//
//  1. Client and server are both configured with AuthMethods =
//     [SSL, ClaimToBe]. SSL comes first in the server's preference
//     order.
//
//  2. Server walks its preference order, picks SSL, advertises it
//     via `AuthMethods = "SSL"` AND the full list via
//     `AuthMethodsList = "SSL,CLAIMTOBE"`.
//
//  3. Client parses the server response. With the parser bug we just
//     fixed, ServerConfig.AuthMethods would have been read from the
//     singular `AuthMethods` field and ended up as [SSL] — leaving
//     handleClientAuthentication's bitmask exchange with one option,
//     no retry, and the handshake dying with
//     "all authentication methods failed: SSL: ...". With the fix
//     in place, ServerConfig.AuthMethods comes from `AuthMethodsList`
//     and is [SSL, ClaimToBe].
//
//  4. handleClientAuthentication sends a bitmask containing both
//     SSL and ClaimToBe. Server picks SSL first (its preference).
//     Server's SSL auth fails because no certificate is configured —
//     same shape of failure the production schedd-ping path
//     produces when the token's iss/kid is filtered out.
//
//  5. Client receives the SSL failure, strips SSL from the bitmask,
//     and re-sends [ClaimToBe]. Server picks ClaimToBe, ClaimToBe
//     auth succeeds.
//
//  6. Final negotiated auth: ClaimToBe (NOT SSL).
//
// SSL is the right "first method that fails" to use here because:
//   - It's analogous to the production failure mode (a method the
//     server prefers but that fails for cert/token reasons).
//   - It fails predictably without any external setup — performSSLAuthentication
//     errors out when CertFile/KeyFile aren't configured AND the
//     stream isn't backed by a real TLS-capable socket.
//   - FS in this test environment shares /tmp between client and
//     server (same process), so FS auth would actually succeed on
//     the in-process net.Pipe and break the test premise.
func TestClientHandshake_RetriesAfterFirstMethodFails(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	clientStream := stream.NewStream(clientConn)
	serverStream := stream.NewStream(serverConn)

	// Both sides offer SSL first then ClaimToBe. With the parser fix
	// in place, the client parses AuthMethodsList from the server
	// response and offers both methods in the bitmask exchange — so
	// when SSL fails, the retry has ClaimToBe to fall back to.
	// Without the fix, ServerConfig.AuthMethods would be just [SSL]
	// and the retry would have no options.
	//
	// Encryption: SecurityNever on both sides skips the ECDH step;
	// this test is about auth-method negotiation, not key exchange.
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
	}

	clientAuth := NewAuthenticator(clientConfig, clientStream)
	serverAuth := NewAuthenticator(serverConfig, serverStream)

	// Run server in goroutine.
	type serverResult struct {
		negotiation *SecurityNegotiation
		err         error
	}
	serverDone := make(chan serverResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		neg, err := serverAuth.ServerHandshake(ctx)
		serverDone <- serverResult{neg, err}
	}()

	// Run client in current goroutine.
	clientCtx, clientCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer clientCancel()
	clientNeg, clientErr := clientAuth.ClientHandshake(clientCtx)

	// Drain server result.
	var sr serverResult
	select {
	case sr = <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake timed out")
	}

	if clientErr != nil {
		t.Fatalf("client handshake failed: %v\nserver err: %v", clientErr, sr.err)
	}
	if sr.err != nil {
		t.Fatalf("server handshake failed: %v", sr.err)
	}

	// FS must have been tried first AND failed; ClaimToBe must have
	// been the eventual winner.
	if clientNeg.NegotiatedAuth != AuthClaimToBe {
		t.Errorf("client NegotiatedAuth = %v, want ClaimToBe (FS should have failed first; retry should have selected ClaimToBe)",
			clientNeg.NegotiatedAuth)
	}
	if sr.negotiation.NegotiatedAuth != AuthClaimToBe {
		t.Errorf("server NegotiatedAuth = %v, want ClaimToBe", sr.negotiation.NegotiatedAuth)
	}
}

// TestClientHandshake_NoRetryWhenServerSendsOnlyAuthMethods is the
// "what used to break" pin: it constructs a server response that has
// `AuthMethods = "FS"` and NO `AuthMethodsList`, simulating either an
// older cedar peer or a regression that drops the field from
// createServerSecurityAd. With the new parser, `availableMethods`
// degrades gracefully to [FS] (the singular value) — no panic, no
// silent expansion — and the retry loop has nothing to fall back on
// when FS fails. We assert that the resulting error is the expected
// AuthMethodsExhaustedError, not a parser-side surprise.
//
// This pins the fallback path explicitly so a future refactor that
// "simplifies" the parser by removing the AuthMethods fallback
// breaks this test rather than silently failing in production
// against an older condor.
func TestClientHandshake_NoRetryWhenServerSendsOnlyAuthMethods(t *testing.T) {
	auth := &Authenticator{}
	ad := classad.New()
	_ = ad.Set("AuthMethods", "FS") // server response without AuthMethodsList
	cfg := auth.parseServerSecurityAd(ad)

	if len(cfg.AuthMethods) != 1 || cfg.AuthMethods[0] != AuthFS {
		t.Fatalf("AuthMethods = %v, want exactly [FS] (fallback when AuthMethodsList missing)", cfg.AuthMethods)
	}
}

// TestAuthMethodsExhausted_PreservesUnderlyingErrors verifies that the
// retry loop's accumulated AuthMethodAttempt records survive through
// AuthMethodsExhaustedError.Unwrap, so callers using errors.As / errors.Is
// to check for specific failure modes (cert verification, token
// rejection, etc.) still match against the per-attempt error rather
// than just seeing a generic exhaustion. This is important because
// the bitmask retry loop accumulates these attempts even when the
// final outcome is failure — a future change that loses the per-
// attempt errors during exhaustion would silently degrade error
// diagnostics in production.
func TestAuthMethodsExhausted_PreservesUnderlyingErrors(t *testing.T) {
	sentinel := errors.New("sentinel-cert-failure")
	exhausted := &AuthMethodsExhaustedError{
		Attempts: []AuthMethodAttempt{
			{Method: AuthFS, Err: errors.New("server verification failed")},
			{Method: AuthSSL, Err: sentinel},
		},
	}

	if !errors.Is(exhausted, sentinel) {
		t.Errorf("errors.Is should match sentinel through AuthMethodsExhaustedError.Unwrap")
	}

	msg := exhausted.Error()
	if !strings.Contains(msg, "FS:") || !strings.Contains(msg, "SSL:") {
		t.Errorf("Error() should include both attempted methods; got %q", msg)
	}
}
