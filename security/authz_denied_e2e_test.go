package security_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/internal/condortest"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// TestDeniedCommandReportsAuthorization drives a real HTCondor collector into
// refusing a command and checks what the client makes of the refusal.
//
// The collector authenticates the client perfectly well and then declines the
// command, which is the shape of every "DENIED" an operator ever files a bug
// about. The error has to say that: name the command, carry the identity the
// peer authenticated, and not call it an authentication failure, because the
// configuration an operator would then go and check is the wrong one.
func TestDeniedCommandReportsAuthorization(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Authorize nobody for administrator commands. Authentication is
	// untouched, so the client still authenticates and is still refused.
	harness := condortest.NewWithConfig(t, `
ALLOW_ADMINISTRATOR = nobody@example.invalid
`)

	addr := net.JoinHostPort(harness.GetCollectorHost(), fmt.Sprintf("%d", harness.GetCollectorPort()))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("connecting to the collector: %v", err)
	}
	defer func() { _ = conn.Close() }()

	cfg := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS, security.AuthToken},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Command:        commands.DC_RECONFIG,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = security.NewAuthenticator(cfg, stream.NewStream(conn)).ClientHandshake(ctx)
	if err == nil {
		t.Fatal("the collector accepted an administrator command it was configured to refuse")
	}

	var authzErr *security.AuthorizationError
	if !errors.As(err, &authzErr) {
		t.Fatalf("got %T (%v), want *security.AuthorizationError", err, err)
	}
	t.Logf("error: %v", err)

	if authzErr.ReturnCode != "DENIED" {
		t.Errorf("ReturnCode = %q, want DENIED", authzErr.ReturnCode)
	}
	if authzErr.Command != commands.DC_RECONFIG {
		t.Errorf("Command = %d, want %d", authzErr.Command, commands.DC_RECONFIG)
	}
	// The point of the change: the peer told us who it authenticated, and a
	// denial that omits it is the one an operator cannot act on.
	if authzErr.User == "" {
		t.Error("the authenticated identity was dropped from the refusal")
	}
	if authzErr.ValidCommands == "" {
		t.Error("the peer's list of permitted commands was dropped from the refusal")
	}
	// The message has to carry the identity, and must not describe an
	// authorization result as an authentication failure.
	msg := err.Error()
	if !contains(msg, authzErr.User) {
		t.Errorf("the message does not name the authenticated identity: %q", msg)
	}
	if contains(msg, "authentication failed") {
		t.Errorf("an authorization result is reported as an authentication failure: %q", msg)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
