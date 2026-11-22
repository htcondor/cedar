package security

import (
	"context"
	"net"
	"testing"

	"github.com/htcondor/cedar/stream"

	"github.com/PelicanPlatform/classad/classad"
)

// TestClientAdIncludesAuthenticationNew verifies the client advertises
// AuthenticationNew (HTCondor 23.10+), the authentication preference decoupled
// from encryption/integrity. Without it a peer treats us as a pre-9.0 client and
// forces authentication whenever encryption/integrity is required (issue #172).
func TestClientAdIncludesAuthenticationNew(t *testing.T) {
	a := &Authenticator{config: &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		Authentication: SecurityOptional,
	}}
	ad := a.createClientSecurityAd()

	authNew, ok := ad.EvaluateAttrString("AuthenticationNew")
	if !ok {
		t.Fatal("client ad is missing AuthenticationNew")
	}
	if authNew != string(SecurityOptional) {
		t.Errorf("AuthenticationNew = %q, want %q", authNew, SecurityOptional)
	}
}

// TestParseServerAdPrefersAuthenticationNew verifies the parser prefers a peer's
// AuthenticationNew over Authentication. A C++ peer sends Authentication coupled
// up to the encryption requirement (e.g. REQUIRED) while AuthenticationNew keeps
// its real, decoupled preference (e.g. OPTIONAL); honoring the latter is what
// keeps a required-encryption policy from forcing authentication on.
func TestParseServerAdPrefersAuthenticationNew(t *testing.T) {
	a := &Authenticator{config: &SecurityConfig{}}

	cases := []struct {
		name       string
		auth       string
		authNew    string // "" means omit
		wantResult SecurityLevel
	}{
		{"prefers AuthenticationNew when both present", "REQUIRED", "OPTIONAL", SecurityOptional},
		{"falls back to Authentication when New absent", "REQUIRED", "", SecurityRequired},
		{"New wins even when stronger", "OPTIONAL", "REQUIRED", SecurityRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ad := classad.New()
			_ = ad.Set("Authentication", tc.auth)
			if tc.authNew != "" {
				_ = ad.Set("AuthenticationNew", tc.authNew)
			}
			cfg := a.parseServerSecurityAd(ad)
			if cfg.Authentication != tc.wantResult {
				t.Errorf("parsed Authentication = %q, want %q", cfg.Authentication, tc.wantResult)
			}
		})
	}
}

// TestServerServesUnauthenticatedEncrypted is the server-side counterpart of
// issue #172: a cedar server with encryption/integrity REQUIRED but read
// authentication OPTIONAL must NOT force authentication -- it should establish an
// encrypted-but-unauthenticated session (as the C++ collector does), rather than
// demanding an auth method the client cannot satisfy.
func TestServerServesUnauthenticatedEncrypted(t *testing.T) {
	GetSessionCache().Clear()

	serverCfg := func() *SecurityConfig {
		return &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthFS},
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Authentication: SecurityOptional, // read auth optional
			Encryption:     SecurityRequired, // stock-cm-style requirements
			Integrity:      SecurityRequired,
			TrustDomain:    "repro.local",
		}
	}
	clientCfg := func() *SecurityConfig {
		return &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthFS, AuthNone},
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Authentication: SecurityOptional,
			Encryption:     SecurityOptional,
			Integrity:      SecurityOptional,
			TrustDomain:    "repro.local",
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	type res struct {
		neg *SecurityNegotiation
		st  *stream.Stream
		err error
	}
	sCh := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			sCh <- res{err: err}
			return
		}
		ss := stream.NewStream(c)
		neg, err := NewAuthenticator(serverCfg(), ss).ServerHandshake(context.Background())
		sCh <- res{neg: neg, st: ss, err: err}
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cs := stream.NewStream(cc)
	cNeg, err := NewAuthenticator(clientCfg(), cs).ClientHandshake(context.Background())
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	sr := <-sCh
	if sr.err != nil {
		t.Fatalf("server handshake: %v", sr.err)
	}

	// Authentication must NOT have been enacted on either end...
	if cNeg.Authentication {
		t.Errorf("client: authentication was enacted (NegotiatedAuth=%s); expected unauthenticated", cNeg.NegotiatedAuth)
	}
	if sr.neg.Authentication {
		t.Errorf("server: authentication was enacted; expected unauthenticated")
	}
	// ...but the session must be encrypted (required), keyed from ECDH.
	if !cs.IsEncrypted() || !sr.st.IsEncrypted() {
		t.Fatalf("stream not encrypted: client=%v server=%v", cs.IsEncrypted(), sr.st.IsEncrypted())
	}
	if !cNeg.Encryption || !sr.neg.Encryption {
		t.Errorf("encryption not recorded: client=%v server=%v", cNeg.Encryption, sr.neg.Encryption)
	}
}
