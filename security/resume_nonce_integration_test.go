package security_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/internal/condortest"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// TestEncryptedResumeWithCppCollector resumes a cedar client's session with a
// C++ collector that requires encryption and runs a query over the resumed,
// AES-GCM-encrypted connection. Both peers' resume nonces enter the handshake
// digest bound into the AAD, so each side decrypts the other's frames only if
// both computed it the same way. Skipped when condor_master is not installed.
func TestEncryptedResumeWithCppCollector(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	h := condortest.NewWithConfig(t, `
SEC_DEFAULT_ENCRYPTION = REQUIRED
SEC_DEFAULT_INTEGRITY = REQUIRED
SEC_DEFAULT_CRYPTO_METHODS = AES
`)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cache := security.NewSessionCache()
	addr := addresses.ParseHTCondorAddress(h.GetCollectorAddr()).ServerAddr

	query := func(label string, wantResumed bool) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("%s: dial: %v", label, err)
		}
		st := stream.NewStream(conn)
		defer func() { _ = st.Close() }()

		auth := security.NewAuthenticator(&security.SecurityConfig{
			PeerName:       h.GetCollectorAddr(),
			Command:        commands.QUERY_COLLECTOR_ADS,
			AuthMethods:    []security.AuthMethod{security.AuthToken, security.AuthFS},
			Authentication: security.SecurityOptional,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			Encryption:     security.SecurityRequired,
			Integrity:      security.SecurityRequired,
			TokenFile:      filepath.Join(h.TmpDir(), "test-token"),
			SessionCache:   cache,
		}, st)
		neg, err := auth.ClientHandshake(ctx)
		if err != nil {
			t.Fatalf("%s: handshake: %v", label, err)
		}
		if neg.SessionResumed != wantResumed || !st.IsEncrypted() {
			t.Fatalf("%s: SessionResumed=%v encrypted=%v, want resumed=%v and encrypted", label, neg.SessionResumed, st.IsEncrypted(), wantResumed)
		}

		q := classad.New()
		_ = q.Set("MyType", "Query")
		_ = q.Set("TargetType", "Collector")
		_ = q.Set("Requirements", true)
		msg := message.NewMessageForStream(st)
		if err := msg.PutClassAd(ctx, q); err != nil {
			t.Fatalf("%s: send query: %v", label, err)
		}
		if err := msg.FinishMessage(ctx); err != nil {
			t.Fatalf("%s: finish query: %v", label, err)
		}

		// The collector answers with (more=1, ad)* then more=0.
		resp := message.NewMessageFromStream(st)
		ads := 0
		for {
			more, err := resp.GetInt32(ctx)
			if err != nil {
				t.Fatalf("%s: read reply after %d ad(s): %v", label, ads, err)
			}
			if more == 0 {
				break
			}
			if _, err := resp.GetClassAd(ctx); err != nil {
				t.Fatalf("%s: read ad %d: %v", label, ads+1, err)
			}
			ads++
		}
		t.Logf("%s: %d collector ad(s) over an encrypted connection", label, ads)
	}

	query("full handshake", false)
	query("resumed", true)
}
