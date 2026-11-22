package security

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// A token's identity must come from its signed "sub" claim, never from the
// client ID the peer sent on the wire. receiveServerTokenStep1 assigns that
// wire value to authData.ClientID before validation, so a validly-signed token
// with no "sub" -- an HTCondor capability token carries none -- used to leave
// the peer's own string in place, satisfy the emptiness check, and authenticate
// the holder as whatever identity they asserted, with no bounding set.
func TestTokenIdentityComesFromSubjectNotThePeer(t *testing.T) {
	poolKeyFile, namedKeyDir, cleanup := setupTestSigningKeys(t)
	defer cleanup()

	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	now := time.Now().Unix()
	token := func(payload map[string]any) string {
		return enc(map[string]any{"alg": "HS256", "typ": "JWT", "kid": "POOL"}) + "." + enc(payload)
	}
	cfg := &SecurityConfig{TrustDomain: "test.domain", TokenPoolSigningKeyFile: poolKeyFile, TokenSigningKeyDir: namedKeyDir}
	a := &Authenticator{config: cfg}

	const asserted = "condor@pool.example" // what the peer claims to be

	t.Run("no subject claim is refused", func(t *testing.T) {
		// A capability token: signed, in date, and naming nobody.
		data := &TokenAuthData{
			ClientID: asserted,
			Token:    token(map[string]any{"iss": "test.domain", "iat": now, "exp": now + 3600, "jti": "abc", "cap": true}),
		}
		err := a.validateTokenAndDeriveKeys(data, &SecurityNegotiation{ServerConfig: cfg})
		if err == nil {
			t.Fatalf("a token with no subject validated, authenticating the holder as %q", data.ClientID)
		}
		if data.ClientID == asserted {
			t.Errorf("ClientID is still the peer's asserted %q; the identity must not survive a missing subject", asserted)
		}
	})

	t.Run("subject claim overrides the asserted id", func(t *testing.T) {
		data := &TokenAuthData{
			ClientID: asserted,
			Token:    token(map[string]any{"sub": "alice@test.domain", "iss": "test.domain", "iat": now, "exp": now + 3600}),
		}
		if err := a.validateTokenAndDeriveKeys(data, &SecurityNegotiation{ServerConfig: cfg}); err != nil {
			t.Fatalf("a token naming a subject: %v", err)
		}
		if data.ClientID != "alice@test.domain" {
			t.Errorf("ClientID = %q, want the token's subject", data.ClientID)
		}
	})
}
