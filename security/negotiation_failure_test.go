package security

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/stream"
)

// TestNegotiationFailureSendsGracefulResponse verifies that when server/client
// security policies cannot be reconciled, the server sends a response ClassAd
// describing the failure (rather than silently closing), so the client returns a
// specific, actionable error instead of a bare EOF/closed-socket error. A silent
// close is what makes HTCondor report the misleading SECMAN:2011 "Connection
// closed during command authorization. Probably due to an unknown command."
func TestNegotiationFailureSendsGracefulResponse(t *testing.T) {
	cases := []struct {
		name         string
		clientConfig *SecurityConfig
		serverConfig *SecurityConfig
		wantSubstr   string // must appear in the client's error
	}{
		{
			name: "encryption required, no common crypto method",
			clientConfig: &SecurityConfig{
				AuthMethods:    []AuthMethod{AuthNone},
				Authentication: SecurityOptional,
				CryptoMethods:  []CryptoMethod{}, // client offers no crypto
				Encryption:     SecurityOptional,
				Integrity:      SecurityOptional,
				Command:        42,
			},
			serverConfig: &SecurityConfig{
				AuthMethods:    []AuthMethod{AuthNone},
				Authentication: SecurityOptional,
				CryptoMethods:  []CryptoMethod{CryptoAES},
				Encryption:     SecurityRequired, // server mandates encryption
				Integrity:      SecurityOptional,
			},
			wantSubstr: "no compatible encryption",
		},
		{
			name: "authentication required, no common method",
			clientConfig: &SecurityConfig{
				AuthMethods:    []AuthMethod{AuthFS}, // client only FS
				Authentication: SecurityOptional,
				CryptoMethods:  []CryptoMethod{CryptoAES},
				Encryption:     SecurityOptional,
				Integrity:      SecurityOptional,
				Command:        42,
			},
			serverConfig: &SecurityConfig{
				AuthMethods:    []AuthMethod{AuthToken}, // server only TOKEN
				Authentication: SecurityRequired,        // server mandates auth
				CryptoMethods:  []CryptoMethod{CryptoAES},
				Encryption:     SecurityOptional,
				Integrity:      SecurityOptional,
			},
			wantSubstr: "no compatible authentication",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer func() { _ = serverConn.Close() }()
			defer func() { _ = clientConn.Close() }()

			clientAuth := NewAuthenticator(tc.clientConfig, stream.NewStream(clientConn))
			serverAuth := NewAuthenticator(tc.serverConfig, stream.NewStream(serverConn))

			serverErr := make(chan error, 1)
			go func() {
				_, err := serverAuth.ServerHandshake(context.Background())
				serverErr <- err
			}()

			time.Sleep(10 * time.Millisecond)

			_, err := clientAuth.ClientHandshake(context.Background())
			if err == nil {
				t.Fatal("expected client handshake to fail on incompatible policy, got nil")
			}
			// The client must get a specific negotiation error, NOT a bare
			// read/EOF error from a silently closed socket.
			if strings.Contains(err.Error(), "failed to parse server response") {
				t.Fatalf("client saw a silent close (no graceful response): %v", err)
			}
			if !strings.Contains(err.Error(), "rejected by server") {
				t.Fatalf("client error is not the graceful-rejection error: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("client error missing reason %q: %v", tc.wantSubstr, err)
			}
			t.Logf("client got graceful rejection: %v", err)

			// Drain the server goroutine.
			select {
			case err := <-serverErr:
				t.Logf("server handshake returned: %v", err)
			case <-time.After(time.Second):
				t.Fatal("server handshake did not return")
			}
		})
	}
}
