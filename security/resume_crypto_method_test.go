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

// familySessionInfo is the session info a 25.x condor_master exports for its
// family session (CONDOR_PRIVATE_INHERIT): HTCondor keys the session once per
// listed method.
const familySessionInfo = `[Integrity="YES";Encryption="YES";ShortVersion="25.8.0";CryptoMethods="BLOWFISH";CryptoMethodsList="AES.BLOWFISH.3DES";]`

func importFamilySession(t *testing.T) (*SessionCache, *SessionEntry) {
	t.Helper()
	entry, err := CreateNonNegotiatedSession(&InheritedSession{
		Type:        SessionTypeFamily,
		SessionID:   "family:0123abcd",
		SessionInfo: familySessionInfo,
		SessionKey:  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}, "<127.0.0.1:9618>")
	if err != nil {
		t.Fatalf("CreateNonNegotiatedSession: %v", err)
	}
	cache := NewSessionCache()
	cache.Store(entry)
	return cache, entry
}

// TestServerResumeHonorsClientCryptoMethod resumes an imported family session
// against a cedar server the way a C++ daemon does: the resume ad names the
// cipher the client keyed the connection with (SecManStartCommand::
// sendAuthInfo_inner), which is BLOWFISH once a UDP command has made it the
// session's preferred method. cedar cannot read that connection, so it must
// refuse the session with SID_NOT_FOUND -- which makes a C++ client stop using
// the family session with this address -- rather than accept it and fail to
// decrypt the payload. A client keyed on AES, or naming no method HTCondor
// knows (an older cedar's "AESGCM"), resumes and its payload is read.
func TestServerResumeHonorsClientCryptoMethod(t *testing.T) {
	for _, tc := range []struct {
		name       string
		clientCM   string // "" = attribute absent
		wantResume bool
	}{
		{"blowfish", "BLOWFISH", false},
		{"3des", "3DES", false},
		{"aes", "AES", true},
		{"older cedar", "AESGCM", true},
		{"absent", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, entry := importFamilySession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			serverConn, clientConn := net.Pipe()
			defer func() { _ = serverConn.Close() }()
			defer func() { _ = clientConn.Close() }()

			type result struct {
				err     error
				payload string
			}
			done := make(chan result, 1)
			go func() {
				ss := stream.NewStream(serverConn)
				if _, err := NewAuthenticator(&SecurityConfig{SessionCache: cache}, ss).ServerHandshake(ctx); err != nil {
					_ = serverConn.Close()
					done <- result{err: err}
					return
				}
				payload, err := message.NewMessageFromStream(ss).GetString(ctx)
				done <- result{err: err, payload: payload}
			}()

			cs := stream.NewStream(clientConn)
			msg := message.NewMessageForStream(cs)
			resumeAd := classad.New()
			_ = resumeAd.Set("Command", commands.CCB_REQUEST)
			_ = resumeAd.Set("UseSession", "YES")
			_ = resumeAd.Set("Sid", entry.ID())
			_ = resumeAd.Set("ResumeResponse", true)
			_ = resumeAd.Set("RemoteVersion", "$CondorVersion: 25.8.0 2026-03-11 $")
			if tc.clientCM != "" {
				_ = resumeAd.Set("CryptoMethods", tc.clientCM)
			}
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

			if !tc.wantResume {
				if rc != "SID_NOT_FOUND" {
					t.Fatalf("ReturnCode = %q, want SID_NOT_FOUND for a client keyed on %s", rc, tc.clientCM)
				}
				if r := <-done; r.err == nil {
					t.Fatal("server resumed a session the client keyed on a cipher cedar does not implement")
				}
				// The session stays usable by clients keyed on AES.
				if _, ok := cache.LookupNonExpired(entry.ID()); !ok {
					t.Error("refusing one connection dropped the session from the cache")
				}
				return
			}

			if rc != "AUTHORIZED" {
				t.Fatalf("ReturnCode = %q, want AUTHORIZED", rc)
			}
			if err := cs.SetSymmetricKey(entry.KeyInfo().Data); err != nil {
				t.Fatal(err)
			}
			out := message.NewMessageForStream(cs)
			if err := out.PutString(ctx, "ccb request"); err != nil {
				t.Fatal(err)
			}
			if err := out.FinishMessage(ctx); err != nil {
				t.Fatal(err)
			}
			r := <-done
			if r.err != nil {
				t.Fatalf("server: %v", r.err)
			}
			if r.payload != "ccb request" {
				t.Errorf("server read payload %q, want %q", r.payload, "ccb request")
			}
		})
	}
}

// TestClientResumeNamesAESAsHTCondorDoes pins the resume ad a cedar client
// sends for an imported session: it names the AES-GCM key it uses as "AES",
// the spelling HTCondor parses (SecMan::getCryptProtocolNameToEnum). A C++
// server holding a key per method uses the one named
// (DaemonCommandProtocol::ReadCommand); "AESGCM" names none, leaving it on its
// preferred key, BLOWFISH after a UDP command resumed the session.
func TestClientResumeNamesAESAsHTCondorDoes(t *testing.T) {
	cache, entry := importFamilySession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	got := make(chan *classad.ClassAd, 1)
	go func() {
		defer close(got)
		ss := stream.NewStream(serverConn)
		in := message.NewMessageFromStream(ss)
		if _, err := in.GetInt(ctx); err != nil {
			return
		}
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return
		}
		got <- ad
		resp := classad.New()
		_ = resp.Set("ReturnCode", "AUTHORIZED")
		out := message.NewMessageForStream(ss)
		if out.PutClassAd(ctx, resp) == nil {
			_ = out.FinishMessage(ctx)
		}
	}()

	a := NewAuthenticator(&SecurityConfig{Command: commands.DC_QUERY_READY, SessionCache: cache, SessionID: entry.ID()}, stream.NewStream(clientConn))
	if _, err := a.ClientHandshake(ctx); err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	ad := <-got
	if ad == nil {
		t.Fatal("server did not receive a resume ad")
	}
	cm, _ := ad.EvaluateAttrString("CryptoMethods")
	if cm != "AES" {
		t.Errorf("resume ad CryptoMethods = %q, want %q", cm, "AES")
	}
	if m := cryptoMethodFromWire(cm); m != CryptoAES {
		t.Errorf("HTCondor reads resume ad CryptoMethods %q as %q, want AES", cm, m)
	}
}

func TestCryptoMethodFromWire(t *testing.T) {
	for in, want := range map[string]CryptoMethod{
		"":                 "",
		"AES":              CryptoAES,
		"aes":              CryptoAES,
		"BLOWFISH":         CryptoBlowfish,
		"3DES":             Crypto3DES,
		"TRIPLEDES":        Crypto3DES,
		"AESGCM":           "",
		"AESGCM,BLOWFISH":  CryptoBlowfish,
		" BLOWFISH , AES ": CryptoBlowfish,
		"AES.BLOWFISH":     "",
	} {
		if got := cryptoMethodFromWire(in); got != want {
			t.Errorf("cryptoMethodFromWire(%q) = %q, want %q", in, got, want)
		}
	}
}
