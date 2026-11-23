package ccb

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/security"
)

// delegatedConfig is a caller config of the shape a daemon builds when it is
// acting for somebody else: a token that is not this host's, flagged as such.
func delegatedConfig() *security.SecurityConfig {
	return &security.SecurityConfig{
		AuthMethods:         []security.AuthMethod{security.AuthToken},
		Authentication:      security.SecurityRequired,
		Token:               "header.payload.signature",
		DelegatedCredential: true,
	}
}

// A delegated credential must not be presented to a CCB broker. The broker is
// named by the target's own advertised address, not by configuration, so
// forwarding the caller's credential hands it to a party the caller never
// chose. The refusal has to be a DelegatedCredentialError so a transport can
// report it as the authentication failure it is.
func TestBrokerDialRefusesADelegatedCredential(t *testing.T) {
	var dialed atomic.Int32
	dialer := brokerDial{carrier: func(ctx context.Context, brokerAddr string) (net.Conn, error) {
		dialed.Add(1)
		return nil, errors.New("the broker should never have been dialled")
	}}

	_, _, err := dialBrokerAuthOnce(context.Background(), "broker.example.org:9618",
		"ccb-requester", delegatedConfig(), CommandRequest, dialer)
	if err == nil {
		t.Fatal("the broker leg accepted a delegated credential")
	}
	if !security.IsDelegatedCredentialRefused(err) {
		t.Errorf("error = %v, want a DelegatedCredentialError", err)
	}
	if !strings.Contains(err.Error(), "broker.example.org:9618") {
		t.Errorf("error = %q, want it to name the broker", err)
	}
	// The guard runs before the dial: refusing after connecting would still
	// have opened a connection, and on a reused carrier that is observable.
	if n := dialed.Load(); n != 0 {
		t.Errorf("dialled the broker %d times while refusing; want 0", n)
	}
}

// The refusal must be terminal. dialBrokerAuthenticated retries a stale
// session once, and a refusal that looked retryable would burn both attempts
// and report the wrong cause.
func TestDelegatedCredentialRefusalIsNotRetried(t *testing.T) {
	var dialed atomic.Int32
	dialer := brokerDial{carrier: func(ctx context.Context, brokerAddr string) (net.Conn, error) {
		dialed.Add(1)
		return nil, errors.New("the broker should never have been dialled")
	}}

	_, _, err := dialBrokerAuthenticated(context.Background(), "broker.example.org:9618",
		"ccb-requester", delegatedConfig(), CommandRequest, dialer)
	if !security.IsDelegatedCredentialRefused(err) {
		t.Fatalf("error = %v, want a DelegatedCredentialError", err)
	}
	if security.IsSessionResumptionError(err) {
		t.Error("the refusal reads as a session-resumption error, so it would be retried")
	}
	if n := dialed.Load(); n != 0 {
		t.Errorf("dialled the broker %d times; want 0", n)
	}
}

// Every path that reaches a broker goes through the same guard: the requester,
// the outbound proxy, the tunnel-address lookup and the listener registration.
func TestEveryBrokerCommandRefusesADelegatedCredential(t *testing.T) {
	for _, cmd := range []struct {
		name string
		code int
	}{
		{"CommandRequest", CommandRequest},
		{"CommandProxyConnect", CommandProxyConnect},
		{"CommandGetTunnelAddress", CommandGetTunnelAddress},
		{"CommandRegister", CommandRegister},
	} {
		t.Run(cmd.name, func(t *testing.T) {
			_, _, err := dialBrokerAuthOnce(context.Background(), "broker.example.org:9618",
				"ccb-requester", delegatedConfig(), cmd.code, brokerDial{})
			if !security.IsDelegatedCredentialRefused(err) {
				t.Errorf("error = %v, want a DelegatedCredentialError", err)
			}
		})
	}
}

// A config that is not delegated is untouched: this guard must not become a
// reason that ordinary CCB dials stop working.
func TestBrokerDialAllowsAnOrdinaryCredential(t *testing.T) {
	cfg := delegatedConfig()
	cfg.DelegatedCredential = false

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var dialed atomic.Int32
	dialer := brokerDial{carrier: func(ctx context.Context, brokerAddr string) (net.Conn, error) {
		dialed.Add(1)
		return nil, errors.New("dial refused by the test")
	}}

	_, _, err := dialBrokerAuthOnce(ctx, "broker.example.org:9618", "ccb-requester",
		cfg, CommandRequest, dialer)
	if err == nil {
		t.Fatal("expected the test dialer's error")
	}
	if security.IsDelegatedCredentialRefused(err) {
		t.Errorf("a non-delegated credential was refused as delegated: %v", err)
	}
	if n := dialed.Load(); n != 1 {
		t.Errorf("dialled the broker %d times; want 1 (the guard must not block it)", n)
	}
}

// Dial is the entry point client.Connect uses, and it is handed the broker
// list out of the target's sinful. The refusal must survive to that surface
// rather than being flattened into "all brokers failed".
func TestDialSurfacesTheDelegatedRefusal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := Dial(ctx, []addresses.CCBContact{{BrokerAddr: "broker.example.org:9618", CCBID: "1"}},
		DialOptions{Security: delegatedConfig()})
	if err == nil {
		t.Fatal("Dial accepted a delegated credential")
	}
	if !security.IsDelegatedCredentialRefused(err) {
		t.Errorf("error = %v, want a DelegatedCredentialError through the chain", err)
	}
}
