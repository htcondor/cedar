// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/internal/condortest"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// setupSciTokensCache pre-populates the SciTokens JWKS cache database
// This allows HTCondor's libscitokens-cpp to skip OIDC discovery and use cached keys
// Must be called BEFORE starting HTCondor
func setupSciTokensCache(issuer string, jwks security.JWKS, cacheHome string) error {
	// Create the scitokens cache directory
	scitokensCacheDir := filepath.Join(cacheHome, "scitokens")
	if err := os.MkdirAll(scitokensCacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create scitokens cache directory: %w", err)
	}

	// Marshal JWKS to JSON
	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		return fmt.Errorf("failed to marshal JWKS: %w", err)
	}

	// Calculate expiration timestamps (1 hour in the future)
	now := time.Now().Unix()
	expires := now + 3600
	nextUpdate := now + 3600

	// Create the cache value JSON
	cacheValue := fmt.Sprintf(`{"expires":%d,"jwks":%s, "next_update": %d}`, expires, string(jwksJSON), nextUpdate)
	//cilogon := `{"keys":[{"alg":"RS256","e":"AQAB","kid":"2FEC35C60764D27594EBEC4D98824CD8","kty":"RSA","n":"AKtyEMIR2_ymESOtrak2QJfdQvVTip-QoC_fIgorqO47p_iBkkrvwRdyQoi_MyNi-5nLQ1pPScaL3niLRvgzx11jY7GoIil2gMN8NhY6dX94dCQC3Qsvo5C3tvla1SkfEGO8y52z8biReVQZy8_Hdy6l__IGveR6aQmC1tKecf1e-kJROS46yA9qpsNEtkREdwZAD9tmrDgddbfXAcCUtfdc62dEZTryuDcJGoXEaWBAobVIGIE5e7IYjsiZz_KtIOgaDqoguXeyttZB1-g2ok8PT9S3Xdt3gP4Wy3PE_qO58UCAv5YejG6Uau8XyxKfxGQrPnXERVJl3PQF1NCJj-8","use":"sig"},{"alg":"RS384","e":"AQAB","kid":"680182D6A0BF3BFF98E7DC211991EA44","kty":"RSA","n":"ALVOmsYrvRb8jzjyS99p2J22bP7Tvv9FGNzW62xDLKy77rVud0zMAUh7RJwUROmAoRoJ1soDIDXJH3-F4V_pZpI80_nGalXjX2SSbeNFtQVSilXdlS-CPwBE59A4lueDTvIg4925pI5PR50ShWQHMXnXU4xM5iFs9V0wtZsbKvs8Flsu2va_pnbhOb_3otEaz68iI2SI8srP-cz5e18l5SI-xtGie_IOWYkVN9Bs2O0ELcpI2hMT86m_dXJGUy5rMRpk6gTLGh3kis4wZN4OLrLvO_qTo3BU9I54nvCwiaQVWJwpZAq4Vf5jwXdrSCNnHLYOiPB1jix-Yor4JUJP8lk","use":"sig"},{"alg":"RS512","e":"AQAB","kid":"90387F85055ECED268E374A28414A056","kty":"RSA","n":"AItqzHE1vr_intX7uYEz5wf7Ppn2FSJUdhDn-GNu4Pg6MWUOB9JV89M90a2v9xHD-mHLhVgiqiR5VBz7o6Oo75x5zREB_UauYO3P5TnJEREXAMGc_ZWQiXhHr9LrShUYBcEP2DB1xpibXnq2m6pCvK9bSCVxyMZFtTHKGes7cQV6KTUd5S4ujAa7EQgccf6WXTUu43h1_VRN9NxJcFgkD8C4JKJPz1jYmNP7neL3qQmVIBRurA_gMkXP2ipT--7pN3PsYMKdE6XhNhbbCUJMrNoX7cT-_urvLXYAjHfplch3VrRANgr2auCQ2DtOJb9bztaTdB0A14Imdvujbi1ISSc","use":"sig"}]}`
	//cacheValue := fmt.Sprintf(`{"expires":%d,"jwks":%s, "next_update": %d}`, expires, cilogon, nextUpdate)

	// Log the JWKS being added to cache for debugging
	fmt.Printf("\n📦 Adding JWKS to SQLite cache:\n")
	fmt.Printf("   Issuer: %s\n", issuer)
	fmt.Printf("   JWKS JSON: %s\n", string(jwksJSON))
	fmt.Printf("   Cache Value: %s\n", cacheValue)
	fmt.Printf("   Expires: %d (Unix timestamp)\n", expires)
	fmt.Printf("   Next Update: %d (Unix timestamp)\n\n", nextUpdate)

	// Create SQLite database using sqlite3 CLI
	dbPath := filepath.Join(scitokensCacheDir, "scitokens_cpp.sqllite")

	// Create the database and table
	createTableSQL := `CREATE TABLE IF NOT EXISTS keycache (
		issuer text UNIQUE PRIMARY KEY NOT NULL,
		keys text NOT NULL
	);`

	cmd := exec.Command("sqlite3", dbPath, createTableSQL)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create table: %w (output: %s)", err, string(output))
	}

	// Escape single quotes in the values for SQL
	issuerEscaped := strings.ReplaceAll(issuer, "'", "''")
	cacheValueEscaped := strings.ReplaceAll(cacheValue, "'", "''")

	// Insert the cache entry
	insertSQL := fmt.Sprintf("INSERT OR REPLACE INTO keycache (issuer, keys) VALUES ('%s', '%s');",
		issuerEscaped, cacheValueEscaped)

	cmd = exec.Command("sqlite3", dbPath, insertSQL)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to insert cache entry: %w (output: %s)", err, string(output))
	}

	return nil
}

// TestSciTokenIntegration tests SCITOKENS authentication with HTCondor
func TestSciTokenIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	// setupSciTokensCache shells out to the sqlite3 CLI to populate the
	// scitokens_cpp.sqllite key cache (matching what HTCondor's C++
	// SciTokens implementation expects on disk). Without sqlite3 in
	// $PATH there's nothing meaningful for the test to do — skip
	// rather than fail, so contributors on minimal dev containers or
	// CI runners that omit the sqlite3 package don't see a spurious
	// red.
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skipf("sqlite3 CLI not found in $PATH (%v); install it (e.g. `dnf install -y sqlite` / `apt-get install -y sqlite3`) to run this test", err)
	}

	// Generate RSA key pair for signing SciTokens BEFORE setting up the harness
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create JWKS with the public key
	jwk := security.JWK{
		Kty: "RSA",
		Kid: "test-scitoken-key",
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(intToBytes(privKey.E)),
	}

	jwks := security.JWKS{
		Keys: []security.JWK{jwk},
	}

	// Create mock OIDC server with proper TLS
	var mockServer *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			config := security.OIDCConfiguration{
				Issuer:  mockServer.URL,
				JWKSURI: mockServer.URL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(config)
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	})
	mockServer = httptest.NewTLSServer(handler)
	defer mockServer.Close()

	// Create a temporary directory for the XDG cache that will persist for the test
	cacheTmpDir, err := os.MkdirTemp("", "scitoken_cache")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(cacheTmpDir) }()

	cacheHome := filepath.Join(cacheTmpDir, "cache")
	if err := os.MkdirAll(cacheHome, 0755); err != nil {
		t.Fatalf("Failed to create cache home: %v", err)
	}

	// Pre-populate the SciTokens JWKS cache BEFORE starting HTCondor
	if err := setupSciTokensCache(mockServer.URL, jwks, cacheHome); err != nil {
		t.Fatalf("Failed to setup SciTokens cache: %v", err)
	}
	t.Logf("🔑 Pre-populated SciTokens cache at: %s", cacheHome)

	// Verify the cache was created
	dbPath := filepath.Join(cacheHome, "scitokens", "scitokens_cpp.sqllite")
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("❌ Cache database was not created at %s: %v", dbPath, err)
	}
	t.Logf("✅ Verified cache database exists at: %s", dbPath)
	t.Logf("🔍 Cache issuer URL: %s", mockServer.URL)

	// Set XDG_CACHE_HOME for this process and HTCondor
	_ = os.Setenv("XDG_CACHE_HOME", cacheHome)
	defer func() { _ = os.Unsetenv("XDG_CACHE_HOME") }()

	// NOW setup the HTCondor harness with the cache already configured
	harness := condortest.New(t)
	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())

	// Check if HTCondor supports SCITOKENS
	if !harness.SupportsAuthMethod("SCITOKENS") {
		t.Skip("HTCondor does not support SCITOKENS authentication method")
	}

	// Configure HTTP client to trust the test server's certificate
	// Store the test server's TLS config for later use
	testServerCert := mockServer.Certificate()

	// Generate test SciToken
	claims := &security.SciTokenClaims{
		Subject:   "testuser@scitoken.test",
		Issuer:    mockServer.URL,
		Scope:     "condor:/READ condor:/WRITE",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-scitoken-key"

	tokenStr, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("Failed to sign SciToken: %v", err)
	}

	// Save token to file
	tokenFile := filepath.Join(harness.TmpDir(), "test.scitoken")
	if err := os.WriteFile(tokenFile, []byte(tokenStr), 0600); err != nil {
		t.Fatalf("Failed to write SciToken file: %v", err)
	}

	t.Logf("🎫 Generated SciToken for user: %s", claims.Subject)
	t.Logf("🔐 Issuer: %s", claims.Issuer)
	t.Logf("🔍 SciToken JWT (length=%d bytes):\n%s", len(tokenStr), tokenStr)

	// Connect to collector
	addr := net.JoinHostPort(harness.GetCollectorHost(), fmt.Sprintf("%d", harness.GetCollectorPort()))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to collector: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}()

	// Create stream
	cedarStream := stream.NewStream(conn)

	// Create client configuration with SCITOKENS authentication
	clientConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthSciTokens},
		Authentication: security.SecurityRequired,
		TokenFile:      tokenFile,
		CertFile:       harness.HostCertFile(),
		KeyFile:        harness.HostKeyFile(),
		CAFile:         harness.CACertFile(),
		ServerName:     "localhost", // Match the hostname in the test certificate
		Command:        commands.DC_NOP,
	}

	// Temporarily configure HTTP client to trust test server certificate
	// This is needed for OIDC discovery during token verification
	originalTransport := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: mockServer.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		},
	}
	defer func() {
		http.DefaultTransport = originalTransport
	}()

	// Also add the test server certificate to a cert pool for verification
	// Note: In production, this would use proper CA certificates
	_ = testServerCert // Mark as used

	// Create authenticator and perform handshake
	auth := security.NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Perform client handshake with SCITOKENS
	t.Logf("🔐 Attempting SCITOKENS authentication...")
	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		// If SCITOKENS authentication isn't supported, skip test
		if containsString(err.Error(), "not supported") || containsString(err.Error(), "no compatible methods") {
			t.Skipf("SCITOKENS authentication not fully supported by this HTCondor version: %v", err)
		}
		t.Fatalf("SCITOKENS authentication handshake failed: %v", err)
	}

	t.Logf("✅ SCITOKENS authentication integration test completed successfully")
	t.Logf("  Negotiated Auth: %s", negotiation.NegotiatedAuth)
	t.Logf("  Session ID: %s", negotiation.SessionId)
	t.Logf("  User: %s", negotiation.User)

	// Verify the authenticated user contains the mapped username
	// HTCondor maps "testuser@scitoken.test" to "testuser" via the mapfile,
	// then appends the local domain, resulting in "testuser@hostname"
	expectedUser := "testuser" // The mapped username from the token subject
	if !containsString(negotiation.User, expectedUser) {
		t.Errorf("Authenticated user mismatch: got %s, expected to contain %s", negotiation.User, expectedUser)
	}
}

// TestSciTokenVerificationFailure tests that invalid SciTokens are rejected
func TestSciTokenVerificationFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := condortest.New(t)
	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())

	// Check if HTCondor supports SCITOKENS
	if !harness.SupportsAuthMethod("SCITOKENS") {
		t.Skip("HTCondor does not support SCITOKENS authentication method")
	}

	// Generate a SciToken with wrong signature
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate wrong RSA key: %v", err)
	}

	// Create mock OIDC server that will serve different key than used for signing
	correctKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate correct RSA key: %v", err)
	}

	jwk := security.JWK{
		Kty: "RSA",
		Kid: "test-key",
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(correctKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(intToBytes(correctKey.E)),
	}

	jwks := security.JWKS{Keys: []security.JWK{jwk}}

	// Create mock OIDC server with proper TLS
	// Use a variable to hold the URL that will be set after server creation
	var serverURL string
	mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			config := security.OIDCConfiguration{
				Issuer:  serverURL,
				JWKSURI: serverURL + "/jwks",
			}
			_ = json.NewEncoder(w).Encode(config)
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()
	serverURL = mockServer.URL

	// Generate token signed with wrong key
	claims := &security.SciTokenClaims{
		Subject:   "baduser@test.com",
		Issuer:    serverURL,
		Scope:     "condor:/READ",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	tokenStr, err := token.SignedString(wrongKey) // Sign with wrong key
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	tokenFile := filepath.Join(harness.TmpDir(), "bad.scitoken")
	if err := os.WriteFile(tokenFile, []byte(tokenStr), 0600); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

	// Connect to collector
	addr := net.JoinHostPort(harness.GetCollectorHost(), fmt.Sprintf("%d", harness.GetCollectorPort()))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to collector: %v", err)
	}
	defer func() { _ = conn.Close() }()

	cedarStream := stream.NewStream(conn)

	clientConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthSciTokens},
		Authentication: security.SecurityRequired,
		TokenFile:      tokenFile,
		CertFile:       harness.HostCertFile(),
		KeyFile:        harness.HostKeyFile(),
		CAFile:         harness.CACertFile(),
		ServerName:     "localhost",
		Command:        commands.DC_NOP,
	}

	// Configure HTTP client for mock server
	originalTransport := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: mockServer.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		},
	}
	defer func() {
		http.DefaultTransport = originalTransport
	}()

	auth := security.NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// This should fail due to signature mismatch
	_, err = auth.ClientHandshake(ctx)
	if err == nil {
		t.Fatal("Expected authentication to fail with invalid token, but it succeeded")
	}

	t.Logf("✅ Invalid SciToken correctly rejected: %v", err)
}

// Helper function to convert int to bytes for JWK encoding
func intToBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	result := []byte{}
	for n > 0 {
		result = append([]byte{byte(n & 0xFF)}, result...)
		n >>= 8
	}
	return result
}

// Helper function to check if string contains substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
