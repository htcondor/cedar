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

// TestAuthRequiredFalseFallback validates the AuthRequired=false fallback against
// a real collector configured with PREFERRED read authentication: the server
// enacts Authentication=YES with AuthRequired=false, the client's only method
// (PASSWORD, unimplemented) fails, and the client must proceed with an
// encrypted-unauthenticated session and complete the READ -- as condor_status does.
func TestAuthRequiredFalseFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	h := condortest.NewWithConfig(t, `
SEC_DEFAULT_ENCRYPTION = REQUIRED
SEC_DEFAULT_INTEGRITY = REQUIRED
SEC_READ_AUTHENTICATION = PREFERRED
SEC_READ_AUTHENTICATION_METHODS = PASSWORD
`)
	addr := net.JoinHostPort(h.GetCollectorHost(), fmt.Sprintf("%d", h.GetCollectorPort()))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	cs := stream.NewStream(conn)

	cfg := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthPassword}, // will fail (unimplemented)
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Command:        commands.QUERY_STARTD_ADS,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	neg, err := security.NewAuthenticator(cfg, cs).ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("handshake aborted instead of falling back to unauthenticated: %v", err)
	}
	if neg.Authentication {
		t.Errorf("expected unauthenticated session, but authentication was enacted (%s)", neg.NegotiatedAuth)
	}
	if !neg.Encryption || !cs.IsEncrypted() {
		t.Errorf("expected an encrypted session: negEnc=%v streamEnc=%v", neg.Encryption, cs.IsEncrypted())
	}

	// The READ must complete over the encrypted-unauthenticated session.
	q := classad.New()
	_ = q.Set("MyType", "Query")
	_ = q.Set("TargetType", "Machine")
	_ = q.Set("Requirements", true)
	qm := message.NewMessageForStream(cs)
	if err := qm.PutClassAd(ctx, q); err != nil {
		t.Fatalf("send query: %v", err)
	}
	if err := qm.FlushFrame(ctx, true); err != nil {
		t.Fatalf("flush query: %v", err)
	}
	rm := message.NewMessageFromStream(cs)
	for {
		more, err := rm.GetInt32(ctx)
		if err != nil {
			t.Fatalf("read 'more' (encrypted read failed -> wire desync): %v", err)
		}
		if more == 0 {
			break
		}
		if _, err := rm.GetClassAd(ctx); err != nil {
			t.Fatalf("read ad: %v", err)
		}
	}
	t.Logf("✅ AuthRequired=false fallback: encrypted-unauthenticated READ completed (auth=%v enc=%v)", neg.Authentication, neg.Encryption)
}
