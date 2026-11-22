package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/stream"
)

// testIssuer is an https SciToken issuer: OIDC metadata and a JWKS holding
// one RSA key, "test-key". hits counts every request it receives.
type testIssuer struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	hits atomic.Int32
	// jwks, if set, replaces the key set the issuer serves.
	jwks func(w http.ResponseWriter)
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ti := &testIssuer{key: key}
	ti.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ti.hits.Add(1)
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(OIDCConfiguration{Issuer: ti.srv.URL, JWKSURI: ti.srv.URL + "/jwks"})
		case "/jwks":
			if ti.jwks != nil {
				ti.jwks(w)
				return
			}
			_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{rsaPublicKeyToJWK(key.PublicKey, "test-key")}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ti.srv.Close)
	return ti
}

func (ti *testIssuer) url() string { return ti.srv.URL }

// opts accepts this issuer and trusts its test certificate.
func (ti *testIssuer) opts() SciTokenVerifyOptions {
	return SciTokenVerifyOptions{Accept: AcceptIssuers(ti.url()), HTTPClient: ti.srv.Client()}
}

func (ti *testIssuer) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	s, err := token.SignedString(ti.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// currentClaims are the claims of a current SciTokens 1.0 token from iss.
func currentClaims(iss string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":   iss,
		"sub":   "alice",
		"scope": "condor:/READ condor:/WRITE",
		"iat":   now.Add(-time.Minute).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
}

func TestVerifySciTokenAcceptsValidToken(t *testing.T) {
	ti := newTestIssuer(t)
	claims, err := VerifySciToken(context.Background(), ti.sign(t, currentClaims(ti.url())), ti.opts())
	if err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	if claims.Issuer != ti.url() || claims.Subject != "alice" {
		t.Errorf("claims = %q/%q", claims.Issuer, claims.Subject)
	}
	if want := []string{"DENY", "READ", "WRITE"}; !slices.Equal(claims.AuthorizationLimits, want) {
		t.Errorf("AuthorizationLimits = %q, want %q", claims.AuthorizationLimits, want)
	}
	if ti.hits.Load() == 0 {
		t.Error("the issuer's keys were never fetched")
	}
}

func TestVerifySciTokenAcceptsES256(t *testing.T) {
	ti := newTestIssuer(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ti.jwks = func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{ecdsaPublicKeyToJWK(ecKey.PublicKey, "ec-key")}})
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, currentClaims(ti.url()))
	token.Header["kid"] = "ec-key"
	s, err := token.SignedString(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySciToken(context.Background(), s, ti.opts()); err != nil {
		t.Fatalf("ES256 token refused: %v", err)
	}
}

func TestVerifySciTokenRejectsExpired(t *testing.T) {
	ti := newTestIssuer(t)
	c := currentClaims(ti.url())
	c["exp"] = time.Now().Add(-10 * 24 * time.Hour).Unix()
	c["iat"] = time.Now().Add(-11 * 24 * time.Hour).Unix()
	c["nbf"] = c["iat"]
	_, err := VerifySciToken(context.Background(), ti.sign(t, c), ti.opts())
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token: err = %v, want expired", err)
	}
}

func TestVerifySciTokenRejectsBadTimes(t *testing.T) {
	ti := newTestIssuer(t)
	future := time.Now().Add(time.Hour).Unix()
	for name, mutate := range map[string]func(jwt.MapClaims){
		"no exp":        func(c jwt.MapClaims) { delete(c, "exp") },
		"no iat":        func(c jwt.MapClaims) { delete(c, "iat") },
		"iat in future": func(c jwt.MapClaims) { c["iat"] = future },
		"nbf in future": func(c jwt.MapClaims) { c["nbf"] = future },
		"string exp":    func(c jwt.MapClaims) { c["exp"] = "never" },
	} {
		t.Run(name, func(t *testing.T) {
			c := currentClaims(ti.url())
			mutate(c)
			if _, err := VerifySciToken(context.Background(), ti.sign(t, c), ti.opts()); err == nil {
				t.Fatal("token accepted")
			}
		})
	}
}

func TestVerifySciTokenRejectsWrongAudience(t *testing.T) {
	ti := newTestIssuer(t)
	opts := ti.opts()
	opts.Audiences = []string{"https://me.example:9618"}
	for name, aud := range map[string]interface{}{
		"foreign string":   "https://other.example",
		"foreign array":    []string{"https://other.example", "x"},
		"ANY in 1.0 token": "ANY",
		"empty array":      []string{},
	} {
		t.Run(name, func(t *testing.T) {
			c := currentClaims(ti.url())
			c["aud"] = aud
			_, err := VerifySciToken(context.Background(), ti.sign(t, c), opts)
			if err == nil || !strings.Contains(err.Error(), "aud") {
				t.Fatalf("err = %v, want an audience error", err)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		if _, err := VerifySciToken(context.Background(), ti.sign(t, currentClaims(ti.url())), opts); err == nil {
			t.Fatal("token without aud accepted although audiences are configured")
		}
	})
	t.Run("no audiences configured", func(t *testing.T) {
		c := currentClaims(ti.url())
		c["aud"] = "https://other.example"
		if _, err := VerifySciToken(context.Background(), ti.sign(t, c), ti.opts()); err == nil {
			t.Fatal("token naming an audience accepted by a server with none")
		}
	})
}

func TestVerifySciTokenAcceptsAudience(t *testing.T) {
	ti := newTestIssuer(t)
	opts := ti.opts()
	opts.Audiences = []string{"https://other.example", "https://me.example:9618"}
	for name, tc := range map[string]struct {
		extra jwt.MapClaims
		want  []string
	}{
		"string":          {jwt.MapClaims{"aud": "https://me.example:9618"}, []string{"https://me.example:9618"}},
		"array":           {jwt.MapClaims{"aud": []string{"x", "https://me.example:9618"}}, []string{"x", "https://me.example:9618"}},
		"scitokens 2 ANY": {jwt.MapClaims{"aud": "ANY", "ver": "scitokens:2.0"}, []string{"ANY"}},
		"wlcg any":        {jwt.MapClaims{"aud": wlcgAnyAudience, "wlcg.ver": "1.0"}, []string{wlcgAnyAudience}},
	} {
		t.Run(name, func(t *testing.T) {
			c := currentClaims(ti.url())
			for k, v := range tc.extra {
				c[k] = v
			}
			claims, err := VerifySciToken(context.Background(), ti.sign(t, c), opts)
			if err != nil {
				t.Fatalf("token refused: %v", err)
			}
			if !slices.Equal([]string(claims.Audience), tc.want) {
				t.Errorf("Audience = %q, want %q", claims.Audience, tc.want)
			}
		})
	}
}

func TestVerifySciTokenRejectsHTTPIssuer(t *testing.T) {
	ti := newTestIssuer(t)
	var hits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		ti.srv.Config.Handler.ServeHTTP(w, r)
	}))
	defer plain.Close()

	// The issuer is allowed; only its scheme is wrong.
	opts := SciTokenVerifyOptions{Accept: AcceptIssuers(plain.URL)}
	_, err := VerifySciToken(context.Background(), ti.sign(t, currentClaims(plain.URL)), opts)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http issuer: err = %v, want an https error", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("http issuer received %d requests", n)
	}
}

func TestVerifySciTokenRejectsUnacceptedIssuerWithoutFetching(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.sign(t, currentClaims(ti.url()))
	for name, accept := range map[string]func(string, string) bool{
		"nil Accept":     nil,
		"other issuer":   AcceptIssuers("https://issuer.example"),
		"other subject":  func(_, sub string) bool { return sub == "bob" },
		"prefix of name": AcceptIssuers(ti.url()[:len(ti.url())-1]),
	} {
		t.Run(name, func(t *testing.T) {
			opts := ti.opts()
			opts.Accept = accept
			_, err := VerifySciToken(context.Background(), token, opts)
			if err == nil || !strings.Contains(err.Error(), "not accepted") {
				t.Fatalf("err = %v, want not accepted", err)
			}
			if n := ti.hits.Load(); n != 0 {
				t.Errorf("issuer received %d requests", n)
			}
		})
	}
}

// TestVerifySciTokenRejectsReviewerToken is the token that used to verify: a
// self-signed token from a plain-http issuer the attacker runs, naming a
// foreign audience and expired ten days ago.
func TestVerifySciTokenRejectsReviewerToken(t *testing.T) {
	ti := newTestIssuer(t)
	var hits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		ti.srv.Config.Handler.ServeHTTP(w, r)
	}))
	defer plain.Close()

	c := currentClaims(plain.URL)
	c["aud"] = "https://elsewhere.example"
	c["exp"] = time.Now().Add(-10 * 24 * time.Hour).Unix()
	c["iat"] = time.Now().Add(-11 * 24 * time.Hour).Unix()
	token := ti.sign(t, c)
	for name, opts := range map[string]SciTokenVerifyOptions{
		"zero options":       {},
		"issuer allowed":     {Accept: AcceptIssuers(plain.URL)},
		"everything allowed": {Accept: func(string, string) bool { return true }, ForeignTokenIssuers: []string{"*"}},
	} {
		if _, err := VerifySciToken(context.Background(), token, opts); err == nil {
			t.Errorf("%s: token accepted", name)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("attacker issuer received %d requests", n)
	}
}

func TestVerifySciTokenRejectsWrongSignature(t *testing.T) {
	ti := newTestIssuer(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, currentClaims(ti.url()))
	token.Header["kid"] = "test-key"
	s, err := token.SignedString(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySciToken(context.Background(), s, ti.opts()); err == nil {
		t.Fatal("token signed by another key accepted")
	}
}

func TestVerifySciTokenRejectsUnsupportedAlgorithm(t *testing.T) {
	ti := newTestIssuer(t)
	token := jwt.NewWithClaims(jwt.SigningMethodPS256, currentClaims(ti.url()))
	token.Header["kid"] = "test-key"
	s, err := token.SignedString(ti.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySciToken(context.Background(), s, ti.opts()); err == nil {
		t.Fatal("PS256 token accepted; scitokens-cpp verifies only RS256 and ES256")
	}
}

func TestVerifySciTokenClaimRules(t *testing.T) {
	ti := newTestIssuer(t)
	for name, tc := range map[string]struct {
		mutate func(jwt.MapClaims)
		ok     bool
	}{
		"no scope":                    {func(c jwt.MapClaims) { delete(c, "scope") }, false},
		"no sub":                      {func(c jwt.MapClaims) { delete(c, "sub") }, false},
		"numeric sub":                 {func(c jwt.MapClaims) { c["sub"] = 7 }, false},
		"unknown claim, 1.0":          {func(c jwt.MapClaims) { c["client_id"] = "x" }, false},
		"unknown claim, explicit 1.0": {func(c jwt.MapClaims) { c["client_id"] = "x"; c["ver"] = "scitokens:1.0" }, false},
		"unknown claim, WLCG":         {func(c jwt.MapClaims) { c["client_id"] = "x"; c["wlcg.ver"] = "1.0"; c["aud"] = wlcgAnyAudience }, true},
		"WLCG without aud":            {func(c jwt.MapClaims) { c["wlcg.ver"] = "1.0" }, false},
		"unknown ver":                 {func(c jwt.MapClaims) { c["ver"] = "scitokens:3.0" }, false},
		"scitokens 2.0 without aud":   {func(c jwt.MapClaims) { c["ver"] = "scitokens:2.0" }, false},
		"opt and jti":                 {func(c jwt.MapClaims) { c["opt"] = map[string]int{"a": 1}; c["jti"] = "id" }, true},
	} {
		t.Run(name, func(t *testing.T) {
			c := currentClaims(ti.url())
			tc.mutate(c)
			_, err := VerifySciToken(context.Background(), ti.sign(t, c), ti.opts())
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestVerifySciTokenForeignToken(t *testing.T) {
	ti := newTestIssuer(t)
	c := currentClaims(ti.url())
	c["scope"] = "openid compute.read"
	c["client_id"] = "x"
	c["aud"] = "https://elsewhere.example"
	token := ti.sign(t, c)

	if _, err := VerifySciToken(context.Background(), token, ti.opts()); err == nil {
		t.Fatal("token failing the SciTokens checks accepted from an issuer not listed as foreign")
	}
	for _, foreign := range [][]string{{ti.url()}, {"*"}} {
		opts := ti.opts()
		opts.ForeignTokenIssuers = foreign
		claims, err := VerifySciToken(context.Background(), token, opts)
		if err != nil {
			t.Fatalf("foreign issuers %q: token refused: %v", foreign, err)
		}
		if want := []string{"DENY", "READ"}; !slices.Equal(claims.AuthorizationLimits, want) {
			t.Errorf("AuthorizationLimits = %q, want %q", claims.AuthorizationLimits, want)
		}
	}

	// Foreign tokens still have to be current.
	c["exp"] = time.Now().Add(-time.Hour).Unix()
	opts := ti.opts()
	opts.ForeignTokenIssuers = []string{"*"}
	if _, err := VerifySciToken(context.Background(), ti.sign(t, c), opts); err == nil {
		t.Fatal("expired foreign token accepted")
	}
}

func TestVerifySciTokenRefusesHTTPRedirect(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		http.NotFound(w, r)
	}))
	defer plain.Close()

	ti := newTestIssuer(t)
	ti.jwks = func(w http.ResponseWriter) {
		w.Header().Set("Location", plain.URL+"/jwks")
		w.WriteHeader(http.StatusFound)
	}
	_, err := VerifySciToken(context.Background(), ti.sign(t, currentClaims(ti.url())), ti.opts())
	if err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("err = %v, want a refused redirect", err)
	}
	if n := plainHits.Load(); n != 0 {
		t.Errorf("http redirect target received %d requests", n)
	}
}

func TestVerifySciTokenBoundsResponse(t *testing.T) {
	ti := newTestIssuer(t)
	ti.jwks = func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"keys":[],"pad":"`))
		_, _ = w.Write([]byte(strings.Repeat("x", sciTokenMaxResponse)))
		_, _ = w.Write([]byte(`"}`))
	}
	_, err := VerifySciToken(context.Background(), ti.sign(t, currentClaims(ti.url())), ti.opts())
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v, want a size error", err)
	}
}

func TestVerifySciTokenHonorsContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ti := newTestIssuer(t)
	ti.jwks = func(http.ResponseWriter) { <-release }
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := VerifySciToken(ctx, ti.sign(t, currentClaims(ti.url())), ti.opts()); err == nil {
		t.Fatal("token accepted although the key set never arrived")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("verification took %v after its context expired", d)
	}
}

func TestVerifyPeerSciTokenMapsIdentity(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.sign(t, currentClaims(ti.url()))
	var asked []string
	cfg := &SecurityConfig{
		UIDDomain:           "pool.example",
		SciTokensHTTPClient: ti.srv.Client(),
		SciTokensMapper: func(name string) (string, bool) {
			asked = append(asked, name)
			if name == ti.url()+",alice" {
				return "alice", true
			}
			return "", false
		},
	}
	user, limits, err := verifyPeerSciToken(context.Background(), cfg, token)
	if err != nil {
		t.Fatalf("mapped token refused: %v", err)
	}
	if user != "alice@pool.example" {
		t.Errorf("user = %q, want alice@pool.example", user)
	}
	if want := []string{"DENY", "READ", "WRITE"}; !slices.Equal(limits, want) {
		t.Errorf("limits = %q, want %q", limits, want)
	}
	if want := []string{ti.url() + ",alice"}; !slices.Equal(asked, want) {
		t.Errorf("mapper asked %q, want %q", asked, want)
	}
}

func TestVerifyPeerSciTokenRefusesUnmapped(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.sign(t, currentClaims(ti.url()))
	for name, cfg := range map[string]*SecurityConfig{
		"no mapper": {SciTokensHTTPClient: ti.srv.Client()},
		"unmapped": {
			SciTokensHTTPClient: ti.srv.Client(),
			SciTokensMapper:     func(string) (string, bool) { return "", false },
		},
		"mapped to nothing": {
			SciTokensHTTPClient: ti.srv.Client(),
			SciTokensMapper:     func(string) (string, bool) { return "", true },
		},
	} {
		if _, _, err := verifyPeerSciToken(context.Background(), cfg, token); err == nil {
			t.Errorf("%s: token accepted", name)
		}
	}
	if n := ti.hits.Load(); n != 0 {
		t.Errorf("issuer received %d requests for tokens no mapping accepts", n)
	}
}

// TestSciTokensHandshakeEndToEnd runs SCITOKENS between a cedar client and
// server: the server authenticates the peer as the mapped user, with the
// token's bounding set, and refuses a token the mapping does not accept.
func TestSciTokensHandshakeEndToEnd(t *testing.T) {
	ti := newTestIssuer(t)
	dir := t.TempDir()
	caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := GenerateTestCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	hostCert, hostKey := filepath.Join(dir, "h.crt"), filepath.Join(dir, "h.key")
	if err := GenerateTestHostCert(hostCert, hostKey, caCert, caKey, "localhost"); err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, mapped string) (*SecurityNegotiation, error, error) {
		GetSessionCache().Clear()
		serverConn, clientConn := net.Pipe()
		defer func() { _ = serverConn.Close() }()
		defer func() { _ = clientConn.Close() }()
		clientConfig := &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthSciTokens},
			Authentication: SecurityRequired,
			Encryption:     SecurityNever,
			Integrity:      SecurityNever,
			Command:        commands.DC_AUTHENTICATE,
			TrustDomain:    "test.domain",
			CAFile:         caCert,
			ServerName:     "localhost",
			Token:          ti.sign(t, currentClaims(ti.url())),
		}
		serverConfig := &SecurityConfig{
			AuthMethods:         []AuthMethod{AuthSciTokens},
			Authentication:      SecurityRequired,
			Encryption:          SecurityNever,
			Integrity:           SecurityNever,
			TrustDomain:         "test.domain",
			CertFile:            hostCert,
			KeyFile:             hostKey,
			UIDDomain:           "pool.example",
			SciTokensHTTPClient: ti.srv.Client(),
			SciTokensMapper: func(name string) (string, bool) {
				if name == ti.url()+",alice" && mapped != "" {
					return mapped, true
				}
				return "", false
			},
		}
		serverDone := make(chan error, 1)
		var serverNeg *SecurityNegotiation
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			neg, err := NewAuthenticator(serverConfig, stream.NewStream(serverConn)).ServerHandshake(ctx)
			serverNeg = neg
			serverDone <- err
			_ = serverConn.Close()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, clientErr := NewAuthenticator(clientConfig, stream.NewStream(clientConn)).ClientHandshake(ctx)
		_ = clientConn.Close()
		serverErr := <-serverDone
		return serverNeg, clientErr, serverErr
	}

	t.Run("mapped", func(t *testing.T) {
		neg, clientErr, serverErr := run(t, "alice")
		if clientErr != nil || serverErr != nil {
			t.Fatalf("handshake failed: client %v, server %v", clientErr, serverErr)
		}
		if neg.User != "alice@pool.example" {
			t.Errorf("server authenticated %q, want alice@pool.example", neg.User)
		}
		if want := []string{"DENY", "READ", "WRITE"}; !slices.Equal(neg.AuthorizationLimits, want) {
			t.Errorf("AuthorizationLimits = %q, want %q", neg.AuthorizationLimits, want)
		}
	})
	t.Run("unmapped", func(t *testing.T) {
		before := ti.hits.Load()
		_, clientErr, serverErr := run(t, "")
		if clientErr == nil && serverErr == nil {
			t.Fatal("handshake succeeded with an unmapped token")
		}
		if n := ti.hits.Load() - before; n != 0 {
			t.Errorf("issuer received %d requests for an unmapped token", n)
		}
	})
}
