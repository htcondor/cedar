package security

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

// authenticatedPolicy is what storeSession records for a session that
// authenticated a peer: an identity, and the claim that it was authenticated.
func authenticatedPolicy(t *testing.T) *classad.ClassAd {
	t.Helper()
	p := classad.New()
	_ = p.Set("Authenticated", true)
	_ = p.Set("User", "victim@example.com")
	_ = p.Set("AuthMethods", "FS")
	_ = p.Set("ValidCommands", "60020")
	return p
}

func plantSession(t *testing.T, key *KeyInfo) (*SessionCache, *SessionEntry) {
	t.Helper()
	entry := NewSessionEntry(
		"planted:0123abcd", "<10.0.0.5:9618>", key, authenticatedPolicy(t),
		time.Now().Add(time.Hour), time.Hour, "",
	)
	cache := NewSessionCache()
	cache.Store(entry)
	return cache, entry
}

// Resuming a session is what proves possession of its key: the AES-GCM AAD
// binds the handshake digest and resume nonce. An entry with no key offers no
// such proof, so restoring its authenticated identity would hand that identity
// to anyone who learns or guesses the session id -- which travels in cleartext
// precisely on the sessions that end up keyless. The server must refuse, and
// the same session with a key must still resume, so that the key is the only
// thing distinguishing the two.
func TestServerRefusesKeylessAuthenticatedResume(t *testing.T) {
	for _, tc := range []struct {
		name       string
		key        *KeyInfo
		wantResume bool
	}{
		{"keyless", nil, false},
		{"keyed", &KeyInfo{Data: make([]byte, 32), Protocol: "AESGCM"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, entry := plantSession(t, tc.key)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			serverConn, clientConn := net.Pipe()
			defer func() { _ = serverConn.Close() }()
			defer func() { _ = clientConn.Close() }()

			type result struct {
				err  error
				user string
			}
			done := make(chan result, 1)
			go func() {
				ss := stream.NewStream(serverConn)
				neg, err := NewAuthenticator(&SecurityConfig{SessionCache: cache}, ss).ServerHandshake(ctx)
				if err != nil {
					_ = serverConn.Close()
					done <- result{err: err}
					return
				}
				done <- result{user: neg.User}
			}()

			cs := stream.NewStream(clientConn)
			msg := message.NewMessageForStream(cs)
			resumeAd := classad.New()
			_ = resumeAd.Set("Command", 60020)
			_ = resumeAd.Set("UseSession", "YES")
			_ = resumeAd.Set("Sid", entry.ID())
			_ = resumeAd.Set("ResumeResponse", true)
			if err := msg.PutInt(ctx, commands.DC_AUTHENTICATE); err != nil {
				t.Fatal(err)
			}
			if err := msg.PutClassAd(ctx, resumeAd); err != nil {
				t.Fatal(err)
			}
			if err := msg.FinishMessage(ctx); err != nil {
				t.Fatal(err)
			}

			resp, err := message.NewMessageFromStream(cs).GetClassAd(ctx)
			if err != nil {
				t.Fatalf("reading resume response: %v", err)
			}
			rc, _ := resp.EvaluateAttrString("ReturnCode")
			r := <-done

			if !tc.wantResume {
				if rc != "SID_NOT_FOUND" {
					t.Errorf("ReturnCode = %q, want SID_NOT_FOUND", rc)
				}
				if r.err == nil {
					t.Fatalf("server resumed a keyless session as %q with no credential", r.user)
				}
				if r.user == "victim@example.com" {
					t.Fatalf("server conferred the cached identity %q without proof of possession", r.user)
				}
				return
			}

			if r.err != nil {
				t.Fatalf("server refused a keyed session: %v", r.err)
			}
			if r.user != "victim@example.com" {
				t.Errorf("resumed user = %q, want the cached identity", r.user)
			}
		})
	}
}
