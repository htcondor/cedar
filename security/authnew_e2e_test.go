package security_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/internal/condortest"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"

	"github.com/PelicanPlatform/classad/classad"
)

// TestUnauthenticatedEncryptedReadQuery reproduces issue #172 against a real
// collector configured like a stock cm (encryption/integrity required, read
// authentication optional). A client offering AuthenticationNew must end up with
// an encrypted-but-UNauthenticated session (server enacts Authentication=NO) and
// the READ query must still return results -- matching condor_status.
func TestUnauthenticatedEncryptedReadQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := condortest.NewWithConfig(t, `
SEC_DEFAULT_ENCRYPTION = REQUIRED
SEC_DEFAULT_INTEGRITY = REQUIRED
SEC_DEFAULT_AUTHENTICATION = OPTIONAL
SEC_READ_AUTHENTICATION = OPTIONAL
`)

	addr := net.JoinHostPort(harness.GetCollectorHost(), fmt.Sprintf("%d", harness.GetCollectorPort()))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to collector: %v", err)
	}
	defer func() { _ = conn.Close() }()

	cedarStream := stream.NewStream(conn)

	clientConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS, security.AuthToken, security.AuthNone},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Command:        commands.QUERY_STARTD_ADS,
	}

	auth := security.NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	// The session must be UNauthenticated (no identity) but encrypted.
	if negotiation.Authentication {
		t.Errorf("expected authentication NOT enacted, but negotiation.Authentication=true (NegotiatedAuth=%s)", negotiation.NegotiatedAuth)
	}
	// An unauthenticated session carries no real identity: cedar reports either an
	// empty User or the display placeholder "unauthenticated@unmapped".
	if negotiation.User != "" && negotiation.User != "unauthenticated@unmapped" {
		t.Errorf("expected an unauthenticated session, got authenticated User=%q", negotiation.User)
	}
	if !negotiation.Encryption {
		t.Errorf("expected encryption enacted for a required-encryption collector, got Encryption=false")
	}
	t.Logf("session: authEnacted=%v encryption=%v negotiatedAuth=%q user=%q",
		negotiation.Authentication, negotiation.Encryption, negotiation.NegotiatedAuth, negotiation.User)

	// The READ query must succeed over the encrypted-unauthenticated session.
	queryAd := classad.New()
	_ = queryAd.Set("MyType", "Query")
	_ = queryAd.Set("TargetType", "Machine")
	_ = queryAd.Set("Requirements", true)

	queryMsg := message.NewMessageForStream(cedarStream)
	if err := queryMsg.PutClassAd(ctx, queryAd); err != nil {
		t.Fatalf("failed to send query: %v", err)
	}
	if err := queryMsg.FlushFrame(ctx, true); err != nil {
		t.Fatalf("failed to flush query: %v", err)
	}

	respMsg := message.NewMessageFromStream(cedarStream)
	adsReceived := 0
	for {
		more, err := respMsg.GetInt32(ctx)
		if err != nil {
			t.Fatalf("failed to read 'more' flag (encrypted read likely failed): %v", err)
		}
		if more == 0 {
			break
		}
		if _, err := respMsg.GetClassAd(ctx); err != nil {
			t.Fatalf("failed to read ad %d: %v", adsReceived+1, err)
		}
		adsReceived++
	}
	// The query protocol completing cleanly (reaching the more==0 terminator over
	// the encrypted channel) is the proof; a startd may or may not be present, so
	// the ad count itself is not asserted.
	t.Logf("✅ encrypted-unauthenticated READ query completed; received %d ad(s)", adsReceived)
}
