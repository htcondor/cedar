package security

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/htcondor/cedar/stream"
)

// setupTestSigningKeys creates temporary signing key files for testing
// Returns the pool key file path, named key directory, and cleanup function
func setupTestSigningKeys(t *testing.T) (string, string, func()) {
	// Create temporary directory for test keys
	tmpDir, err := os.MkdirTemp("", "token-auth-keys-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create pool signing key file
	// The key must be scrambled before writing (as HTCondor does)
	poolKeyFile := tmpDir + "/pool_signing_key"
	poolKeyUnscrambled := []byte("test_pool_signing_key_32_bytes!!")
	poolKeyScrambled := simple_scramble(poolKeyUnscrambled)
	if err := os.WriteFile(poolKeyFile, poolKeyScrambled, 0600); err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("Failed to write pool key file: %v", err)
	}

	// Create named signing keys directory
	namedKeyDir := tmpDir + "/named_keys"
	if err := os.MkdirAll(namedKeyDir, 0700); err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create named key directory: %v", err)
	}

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return poolKeyFile, namedKeyDir, cleanup
}

// Helper function to create a test JWT token with current timestamps
func createTestJWT(subject, issuer string, validForSeconds int) string {
	// Create JWT header with kid (key ID)
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
		"kid": "POOL", // Add key ID for compatibility checking
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Create JWT payload with current timestamps
	now := time.Now().Unix()
	payload := map[string]interface{}{
		"sub": subject,
		"iss": issuer,
		"iat": now,
		"exp": now + int64(validForSeconds),
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Create signature that matches what server will compute
	// Use HKDF + HMAC-SHA256 as implemented in computeTokenSignature
	tokenData := headerB64 + "." + payloadB64

	// For POOL key: unscrambled key is doubled (repeated twice) before use
	poolKeyUnscrambled := []byte("test_pool_signing_key_32_bytes!!")
	signingKey := make([]byte, len(poolKeyUnscrambled)*2)
	copy(signingKey, poolKeyUnscrambled)
	copy(signingKey[len(poolKeyUnscrambled):], poolKeyUnscrambled)

	// Expand the signing key using HKDF (matching HTCondor pattern)
	jwtKey := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, signingKey, []byte("htcondor"), []byte("master jwt"))
	_, _ = io.ReadFull(hkdfReader, jwtKey)

	// Compute HMAC-SHA256 with the expanded key
	mac := hmac.New(sha256.New, jwtKey)
	mac.Write([]byte(tokenData))
	signatureBytes := mac.Sum(nil)[:32] // Take first 32 bytes
	signature := base64.RawURLEncoding.EncodeToString(signatureBytes)

	return headerB64 + "." + payloadB64 + "." + signature
}

// Helper function to create a test JWT token that is structurally valid and
// unexpired (so it passes the client's pre-flight checks) but is stamped with
// a key ID the server has no signing key for. The client, configured to trust
// that kid, forwards the token; the server then fails to load the signing key
// and rejects the token during validation. This exercises the server-side
// token-validation failure path, which an expired token no longer can — the
// client refuses to even send an expired token.
//
// Note: a merely-wrong signature would NOT work here. In this AKEP2 scheme the
// server derives the shared secret by recomputing the signature from its own
// key rather than checking the token's, so a bad signature surfaces only as a
// downstream MAC mismatch ("client authentication failed"), not a token-
// validation error. An unloadable kid fails validation up front.
func createUnknownKeyTestJWT(subject, issuer string) string {
	// Header with a kid the server's key directory does not contain.
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
		"kid": "UNKNOWN_SIGNING_KEY",
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Payload with a future expiry so the client's expiration check passes.
	now := time.Now().Unix()
	payload := map[string]interface{}{
		"sub": subject,
		"iss": issuer,
		"iat": now,
		"exp": now + 3600, // expires in 1 hour
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Signature value is irrelevant: the server never reaches signature
	// derivation because key loading fails first.
	signature := base64.RawURLEncoding.EncodeToString([]byte("placeholder_signature_32_bytes!!"))

	return headerB64 + "." + payloadB64 + "." + signature
}

func TestSecurityHandshake(t *testing.T) {
	// Create a pair of connected sockets for testing
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	// Create streams
	serverStream := stream.NewStream(server)
	clientStream := stream.NewStream(client)

	// Client configuration - matches the example from the user request
	clientConfig := &SecurityConfig{
		AuthMethods:     []AuthMethod{AuthFS, AuthToken, AuthSSL},
		Authentication:  SecurityOptional,
		CryptoMethods:   []CryptoMethod{CryptoAES, CryptoBlowfish, Crypto3DES},
		Encryption:      SecurityOptional,
		Integrity:       SecurityOptional,
		RemoteVersion:   "$CondorVersion: 25.4.0 2025-10-31 BuildID: 847437 PackageID: 25.4.0-0.847437 GitSHA: a6507f91 RC $",
		TrustDomain:     "flock.opensciencegrid.org",
		Subsystem:       "TOOL",
		ServerPid:       1020614,
		SessionDuration: 60,
		SessionLease:    3600,
		ECDHPublicKey:   "BK3KBDM3/jWErtDthhy6PZNAlX2ILu3bM5HGRUylauDgNrUDa/C9uFyJPFaaJ6Ny3GrjHbrc3DV3r4sR5rdh5Uw=",
	}

	// Server configuration - matches the example response
	serverConfig := &SecurityConfig{
		AuthMethods:     []AuthMethod{AuthToken, AuthSSL, AuthFS},
		Authentication:  SecurityNever,
		CryptoMethods:   []CryptoMethod{CryptoAES, CryptoBlowfish, Crypto3DES},
		Encryption:      SecurityOptional,
		Integrity:       SecurityOptional,
		RemoteVersion:   "$CondorVersion: 25.4.0 2025-10-31 BuildID: 847437 PackageID: 25.4.0-0.847437 GitSHA: a6507f91 RC $",
		TrustDomain:     "flock.opensciencegrid.org",
		SessionDuration: 60,
		SessionLease:    3600,
		ECDHPublicKey:   "BAZ1s1V4p2zeZ+FjM6aa3AahivmQJ5NaJ9t2tp+Y1d8aXObfW5Zy81BV5N0F5qQY+tiQh3NaW28/Q6dMMe74lSU=",
	}

	ctx := context.Background()

	// Create authenticators
	clientAuth := NewAuthenticator(clientConfig, clientStream)
	serverAuth := NewAuthenticator(serverConfig, serverStream)

	// Channel to coordinate the handshake
	serverResultChan := make(chan *SecurityNegotiation, 1)
	serverErrChan := make(chan error, 1)

	// Start server handshake in a goroutine
	go func() {
		result, err := serverAuth.ServerHandshake(context.Background())
		if err != nil {
			slog.Info(fmt.Sprintf("Server handshake failed: %v", err), "destination", "cedar")
			serverErrChan <- err
		} else {
			slog.Info("Server handshake succeeded", "destination", "cedar")
			serverResultChan <- result
		}
	}()

	// Give server time to start listening
	time.Sleep(2 * time.Second)

	// Perform client handshake
	clientNegotiation, err := clientAuth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("Client handshake failed: %v", err)
	}

	// Wait for server handshake result
	var serverNegotiation *SecurityNegotiation
	select {
	case result := <-serverResultChan:
		serverNegotiation = result
	case err := <-serverErrChan:
		t.Fatalf("Server handshake failed: %v", err)
	case <-time.After(1 * time.Second):
		t.Fatal("Server handshake timed out")
	}

	// Verify negotiation results
	t.Logf("Client negotiation result:")
	t.Logf("  Command: %d", clientNegotiation.Command)
	t.Logf("  Negotiated Auth: %s", clientNegotiation.NegotiatedAuth)
	t.Logf("  Negotiated Crypto: %s", clientNegotiation.NegotiatedCrypto)
	t.Logf("  Enact: %v", clientNegotiation.Enact)

	t.Logf("Server negotiation result:")
	t.Logf("  Command: %d", serverNegotiation.Command)
	t.Logf("  Negotiated Auth: %s", serverNegotiation.NegotiatedAuth)
	t.Logf("  Negotiated Crypto: %s", serverNegotiation.NegotiatedCrypto)
	t.Logf("  Enact: %v", serverNegotiation.Enact)

	// Both sides should agree on the negotiation
	if clientNegotiation.Command != serverNegotiation.Command {
		t.Errorf("Command mismatch: client=%d, server=%d",
			clientNegotiation.Command, serverNegotiation.Command)
	}

	if clientNegotiation.NegotiatedAuth != serverNegotiation.NegotiatedAuth {
		t.Errorf("Auth method mismatch: client=%s, server=%s",
			clientNegotiation.NegotiatedAuth, serverNegotiation.NegotiatedAuth)
	}

	if clientNegotiation.NegotiatedCrypto != serverNegotiation.NegotiatedCrypto {
		t.Errorf("Crypto method mismatch: client=%s, server=%s",
			clientNegotiation.NegotiatedCrypto, serverNegotiation.NegotiatedCrypto)
	}

	// Verify we negotiated TOKEN auth (first common method)
	expectedAuth := AuthToken // First method in server list that client supports
	if clientNegotiation.NegotiatedAuth != expectedAuth {
		t.Errorf("Expected negotiated auth %s, got %s", expectedAuth, clientNegotiation.NegotiatedAuth)
	}

	// Verify we negotiated AES crypto (first common method)
	expectedCrypto := CryptoAES // First method in both lists
	if clientNegotiation.NegotiatedCrypto != expectedCrypto {
		t.Errorf("Expected negotiated crypto %s, got %s", expectedCrypto, clientNegotiation.NegotiatedCrypto)
	}

	// Both should enact since we have skipped auth
	if clientNegotiation.Enact || serverNegotiation.Enact {
		t.Error("Expected both sides to NOT enact security session")
	}
}

func TestSecurityHandshakeNoCommonMethods(t *testing.T) {
	// Start from a clean session cache so a session left resumable by an earlier
	// test cannot be resumed here (which would bypass this test's negotiation).
	GetSessionCache().Clear()

	// Create a pair of connected sockets for testing
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	// Create streams
	serverStream := stream.NewStream(server)
	clientStream := stream.NewStream(client)

	// Client configuration - only SSL
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthSSL},
		CryptoMethods:  []CryptoMethod{CryptoAES},
		Authentication: SecurityOptional,
		Encryption:     SecurityOptional,
		Integrity:      SecurityOptional,
	}

	// Server configuration - only FS (no common auth method)
	serverConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		CryptoMethods:  []CryptoMethod{CryptoBlowfish}, // No common crypto either
		Authentication: SecurityOptional,
		Encryption:     SecurityOptional,
		Integrity:      SecurityOptional,
	}

	ctx := context.Background()

	// Create authenticators
	clientAuth := NewAuthenticator(clientConfig, clientStream)
	serverAuth := NewAuthenticator(serverConfig, serverStream)

	// Channel to coordinate the handshake
	serverResultChan := make(chan *SecurityNegotiation, 1)
	serverErrChan := make(chan error, 1)

	// Start server handshake in a goroutine
	go func() {
		result, err := serverAuth.ServerHandshake(context.Background())
		if err != nil {
			serverErrChan <- err
		} else {
			serverResultChan <- result
		}
	}()

	// Give server time to start listening
	time.Sleep(10 * time.Millisecond)

	// Perform client handshake
	clientNegotiation, err := clientAuth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("Client handshake failed: %v", err)
	}

	// Wait for server handshake result
	var serverNegotiation *SecurityNegotiation
	select {
	case result := <-serverResultChan:
		serverNegotiation = result
	case err := <-serverErrChan:
		t.Fatalf("Server handshake failed: %v", err)
	case <-time.After(1 * time.Second):
		t.Fatal("Server handshake timed out")
	}

	// Verify no common methods were found
	if clientNegotiation.NegotiatedAuth != AuthNone {
		t.Errorf("Expected no common auth method, got %s", clientNegotiation.NegotiatedAuth)
	}

	if clientNegotiation.NegotiatedCrypto != "" {
		t.Errorf("Expected no common crypto method, got %s", clientNegotiation.NegotiatedCrypto)
	}

	// Should not enact without common methods
	if clientNegotiation.Enact || serverNegotiation.Enact {
		t.Error("Expected not to enact security session without common methods")
	}
}

func TestTokenAuthentication(t *testing.T) {
	// Start from a clean session cache so a NONE-auth session left resumable by
	// an earlier test cannot be resumed here in place of a real TOKEN handshake.
	GetSessionCache().Clear()

	// Setup test signing keys
	poolKeyFile, namedKeyDir, cleanup := setupTestSigningKeys(t)
	defer cleanup()

	// Create a valid JWT token with current timestamps (valid for 1 hour)
	// issuer must match TrustDomain for compatibility checking
	tokenContent := createTestJWT("testuser@example.com", "example.com", 3600)

	// Create temp file
	tmpfile, err := os.CreateTemp("", "test_token_*.jwt")
	if err != nil {
		t.Fatalf("Failed to create temp token file: %v", err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(tokenContent)); err != nil {
		t.Fatalf("Failed to write token content: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	// Create a pair of connected sockets for testing
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	// Create streams
	serverStream := stream.NewStream(server)
	clientStream := stream.NewStream(client)

	// Client configuration with TOKEN authentication
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthToken},
		Authentication: SecurityRequired,
		CryptoMethods:  []CryptoMethod{}, // No crypto to avoid key exchange issues
		Encryption:     SecurityNever,    // Disable encryption
		Integrity:      SecurityOptional,
		TokenFile:      tmpfile.Name(),
		TrustDomain:    "example.com",
		IssuerKeys:     []string{"POOL"}, // Accept tokens with kid="POOL"
		RemoteVersion:  "$CondorVersion: 25.4.0 2025-11-07 BuildID: 123456 $",
	}

	// Server configuration that supports TOKEN authentication
	serverConfig := &SecurityConfig{
		AuthMethods:             []AuthMethod{AuthToken, AuthSSL},
		Authentication:          SecurityRequired,
		CryptoMethods:           []CryptoMethod{}, // No crypto to avoid key exchange issues
		Encryption:              SecurityNever,    // Disable encryption
		Integrity:               SecurityOptional,
		TrustDomain:             "example.com",
		RemoteVersion:           "$CondorVersion: 25.4.0 2025-11-07 BuildID: 123456 $",
		TokenPoolSigningKeyFile: poolKeyFile,
		TokenSigningKeyDir:      namedKeyDir,
	}

	ctx := context.Background()

	// Create authenticators
	clientAuth := NewAuthenticator(clientConfig, clientStream)
	serverAuth := NewAuthenticator(serverConfig, serverStream)

	// Channel to coordinate the handshake
	serverResultChan := make(chan *SecurityNegotiation, 1)
	serverErrChan := make(chan error, 1)

	// Start server handshake in a goroutine
	go func() {
		result, err := serverAuth.ServerHandshake(context.Background())
		if err != nil {
			slog.Info(fmt.Sprintf("Server handshake failed: %v", err), "destination", "cedar")
			serverErrChan <- err
		} else {
			slog.Info("Server handshake succeeded with TOKEN auth", "destination", "cedar")
			serverResultChan <- result
		}
	}()

	// Give server time to start listening
	time.Sleep(100 * time.Millisecond)

	// Perform client handshake
	clientNegotiation, err := clientAuth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("Client handshake failed: %v", err)
	}

	// Wait for server handshake result
	var serverNegotiation *SecurityNegotiation
	select {
	case result := <-serverResultChan:
		serverNegotiation = result
	case err := <-serverErrChan:
		t.Fatalf("Server handshake failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server handshake timed out")
	}

	// Verify TOKEN authentication was negotiated
	if clientNegotiation.NegotiatedAuth != AuthToken {
		t.Errorf("Expected TOKEN authentication, got %s", clientNegotiation.NegotiatedAuth)
	}

	if serverNegotiation.NegotiatedAuth != AuthToken {
		t.Errorf("Server expected TOKEN authentication, got %s", serverNegotiation.NegotiatedAuth)
	}

	// Verify authentication was performed
	if !clientNegotiation.Authentication {
		t.Error("Expected client authentication to be performed")
	}

	if !serverNegotiation.Authentication {
		t.Error("Expected server authentication to be performed")
	}

	// Verify session key was established
	if len(clientNegotiation.GetSharedSecret()) == 0 {
		t.Error("Expected client to have shared secret")
	}

	if len(serverNegotiation.GetSharedSecret()) == 0 {
		t.Error("Expected server to have shared secret")
	}

	// Verify both sides have the same session key
	if !bytesEqual(clientNegotiation.GetSharedSecret(), serverNegotiation.GetSharedSecret()) {
		t.Error("Client and server session keys do not match")
	}

	// The token subject is the identity, domain and all.
	if serverNegotiation.User != "testuser@example.com" {
		t.Errorf("Expected user 'testuser@example.com', got '%s'", serverNegotiation.User)
	}

	t.Logf("TOKEN authentication test completed successfully")
	t.Logf("  Negotiated Auth: %s", clientNegotiation.NegotiatedAuth)
	t.Logf("  Session Key Length: %d bytes", len(clientNegotiation.GetSharedSecret()))
	t.Logf("  Authenticated User: %s", serverNegotiation.User)
}

func TestTokenAKEP2Protocol(t *testing.T) {
	// Setup test signing keys
	poolKeyFile, namedKeyDir, cleanup := setupTestSigningKeys(t)
	defer cleanup()

	// Test just the AKEP2 TOKEN authentication protocol without full handshake

	// Create test JWT token
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice@test.domain","iss":"test.domain"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("test_signature_32_bytes_for_auth"))
	tokenContent := header + "." + payload + "." + signature

	// Create temp file
	tmpfile, err := os.CreateTemp("", "akep2_token_*.jwt")
	if err != nil {
		t.Fatalf("Failed to create temp token file: %v", err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(tokenContent)); err != nil {
		t.Fatalf("Failed to write token content: %v", err)
	}
	_ = tmpfile.Close()

	// Create a pair of connected sockets
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := stream.NewStream(server)
	clientStream := stream.NewStream(client)

	// Create minimal configs for TOKEN auth
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthToken},
		Authentication: SecurityRequired,
		TokenFile:      tmpfile.Name(),
		TrustDomain:    "test.domain",
	}

	serverConfig := &SecurityConfig{
		AuthMethods:             []AuthMethod{AuthToken},
		Authentication:          SecurityRequired,
		TrustDomain:             "test.domain",
		TokenPoolSigningKeyFile: poolKeyFile,
		TokenSigningKeyDir:      namedKeyDir,
	}

	clientAuth := NewAuthenticator(clientConfig, clientStream)
	serverAuth := NewAuthenticator(serverConfig, serverStream)

	// Test client-side token loading and key derivation
	clientTokenData := &TokenAuthData{State: TokenStateInit}
	clientNegotiation := &SecurityNegotiation{
		ClientConfig: clientConfig,
		ServerConfig: serverConfig,
		IsClient:     true,
	}

	err = clientAuth.loadTokenForAuthentication(AuthToken, clientTokenData, clientNegotiation)
	if err != nil {
		t.Fatalf("Client token loading failed: %v", err)
	}

	if clientTokenData.ClientID != "alice@test.domain" {
		t.Errorf("Expected client ID 'alice@test.domain', got '%s'", clientTokenData.ClientID)
	}

	err = clientAuth.deriveTokenKeys(clientTokenData)
	if err != nil {
		t.Fatalf("Client key derivation failed: %v", err)
	}

	if len(clientTokenData.SharedKeyK) != TokenKeyLength {
		t.Errorf("Expected shared key K length %d, got %d", TokenKeyLength, len(clientTokenData.SharedKeyK))
	}

	if len(clientTokenData.SharedKeyKP) != TokenKeyLength {
		t.Errorf("Expected shared key K' length %d, got %d", TokenKeyLength, len(clientTokenData.SharedKeyKP))
	}

	// Test server-side validation with same signature
	serverTokenData := &TokenAuthData{
		Token:     clientTokenData.Token,
		ClientID:  clientTokenData.ClientID,
		Signature: clientTokenData.Signature,
		State:     TokenStateInit,
	}

	err = serverAuth.deriveTokenKeys(serverTokenData)
	if err != nil {
		t.Fatalf("Server key derivation failed: %v", err)
	}

	// Verify both sides derived the same keys
	if !bytesEqual(clientTokenData.SharedKeyK, serverTokenData.SharedKeyK) {
		t.Error("Client and server derived different shared key K")
	}

	if !bytesEqual(clientTokenData.SharedKeyKP, serverTokenData.SharedKeyKP) {
		t.Error("Client and server derived different shared key K'")
	}

	// Test MAC computation compatibility
	testData := "test message for MAC"
	clientMAC := clientAuth.computeTokenMAC(clientTokenData.SharedKeyK, testData)
	serverMAC := serverAuth.computeTokenMAC(serverTokenData.SharedKeyK, testData)

	if !bytesEqual(clientMAC, serverMAC) {
		t.Error("Client and server compute different MACs for same data")
	}

	// Test session key derivation
	testRB := []byte("test_random_nonce_32_bytes_here!")
	clientSessionKey := clientAuth.deriveSessionKey(testRB)
	serverSessionKey := serverAuth.deriveSessionKey(testRB)

	if !bytesEqual(clientSessionKey, serverSessionKey) {
		t.Error("Client and server derived different session keys")
	}

	t.Logf("AKEP2 TOKEN protocol test completed successfully")
	t.Logf("  Client ID: %s", clientTokenData.ClientID)
	t.Logf("  Token: %s", clientTokenData.Token[:50]+"...")
	t.Logf("  Shared Key K length: %d bytes", len(clientTokenData.SharedKeyK))
	t.Logf("  Shared Key K' length: %d bytes", len(clientTokenData.SharedKeyKP))
	t.Logf("  Session Key length: %d bytes", len(clientSessionKey))
}

// TestTokenAuthenticationErrorHandling tests graceful error handling during TOKEN authentication
func TestTokenAuthenticationErrorHandling(t *testing.T) {
	// Setup test signing keys
	poolKeyFile, namedKeyDir, cleanup := setupTestSigningKeys(t)
	defer cleanup()

	// Test client error handling - invalid token file
	t.Run("ClientInvalidToken", func(t *testing.T) {
		// Create a pair of connected sockets for testing
		server, client := net.Pipe()
		defer func() { _ = server.Close() }()
		defer func() { _ = client.Close() }()

		// Create streams
		serverStream := stream.NewStream(server)
		clientStream := stream.NewStream(client)

		// Create client authenticator with invalid token file
		clientConfig := &SecurityConfig{
			TokenFile:      "/nonexistent/token/file.jwt", // Invalid file path
			Authentication: SecurityRequired,
			Encryption:     SecurityNever,
			TrustDomain:    "example.com",
			RemoteVersion:  "$CondorVersion: 25.4.0 2025-11-07 BuildID: 123456 $",
		}
		clientAuth := NewAuthenticator(clientConfig, clientStream)

		// Create server authenticator
		serverConfig := &SecurityConfig{
			Authentication:          SecurityRequired,
			Encryption:              SecurityNever,
			TrustDomain:             "example.com",
			RemoteVersion:           "$CondorVersion: 25.4.0 2025-11-07 BuildID: 123456 $",
			TokenPoolSigningKeyFile: poolKeyFile,
			TokenSigningKeyDir:      namedKeyDir,
		}
		serverAuth := NewAuthenticator(serverConfig, serverStream)

		// Start server in background
		serverErr := make(chan error)
		go func() {
			serverNegotiation := &SecurityNegotiation{
				IsClient:     false,
				ServerConfig: serverConfig,
			}
			serverErr <- serverAuth.performTokenAuthentication(context.Background(), AuthToken, serverNegotiation)
		}()

		// Client should fail with invalid token file
		clientNegotiation := &SecurityNegotiation{
			IsClient:     true,
			ClientConfig: clientConfig,
		}
		clientErr := clientAuth.performTokenAuthentication(context.Background(), AuthToken, clientNegotiation)

		// Client should get an error related to token loading
		if clientErr == nil {
			t.Error("Expected client authentication to fail with invalid token file")
		}
		if clientErr != nil && !strings.Contains(clientErr.Error(), "failed to load token") {
			t.Errorf("Expected token loading error, got: %v", clientErr)
		}

		// Server should also get an error (client would have sent AUTH_PW_ERROR)
		select {
		case err := <-serverErr:
			if err == nil {
				t.Error("Expected server to receive authentication error")
			}
			t.Logf("Server received expected error: %v", err)
		case <-time.After(1 * time.Second):
			t.Error("Server authentication timed out")
		}
	})

	// Test server error handling - invalid token validation
	t.Run("ServerInvalidTokenValidation", func(t *testing.T) {
		// Create temporary token file for client
		tmpFile, err := os.CreateTemp("", "test_token_*.jwt")
		if err != nil {
			t.Fatalf("Failed to create temp token file: %v", err)
		}
		defer func() { _ = os.Remove(tmpFile.Name()) }()

		// Write a token that is compatible (matching issuer and kid) and
		// unexpired, but stamped with a kid the server has no signing key
		// for. The client accepts it (issuer matches, not expired, kid
		// trusted) and forwards it; the server then fails to load the key
		// and rejects it during token validation. An expired token can't
		// be used here — the client refuses to send one.
		invalidToken := createUnknownKeyTestJWT("invalid@example.com", "example.com")
		if _, err := tmpFile.WriteString(invalidToken); err != nil {
			t.Fatalf("Failed to write token file: %v", err)
		}
		_ = tmpFile.Close()

		// Create a pair of connected sockets for testing
		server, client := net.Pipe()
		defer func() { _ = server.Close() }()
		defer func() { _ = client.Close() }()

		// Create streams
		serverStream := stream.NewStream(server)
		clientStream := stream.NewStream(client)

		// Create client authenticator with valid token file
		clientConfig := &SecurityConfig{
			TokenFile:      tmpFile.Name(),
			Authentication: SecurityRequired,
			Encryption:     SecurityNever,
			TrustDomain:    "example.com",
			IssuerKeys:     []string{"UNKNOWN_SIGNING_KEY"}, // Client trusts this kid; server has no key for it
			RemoteVersion:  "$CondorVersion: 25.4.0 2025-11-07 BuildID: 123456 $",
		}
		clientAuth := NewAuthenticator(clientConfig, clientStream)

		// Create server authenticator that will fail validation
		serverConfig := &SecurityConfig{
			Authentication:          SecurityRequired,
			Encryption:              SecurityNever,
			TrustDomain:             "example.com",
			RemoteVersion:           "$CondorVersion: 25.4.0 2025-11-07 BuildID: 123456 $",
			TokenPoolSigningKeyFile: poolKeyFile,
			TokenSigningKeyDir:      namedKeyDir,
		}
		serverAuth := NewAuthenticator(serverConfig, serverStream)

		// Start server in background
		serverErr := make(chan error)
		go func() {
			serverNegotiation := &SecurityNegotiation{
				IsClient:     false,
				ServerConfig: serverConfig,
			}
			// Note: In real implementation, server would validate token and fail
			// For this test, server will proceed but should handle client's potential error gracefully
			serverErr <- serverAuth.performTokenAuthentication(context.Background(), AuthToken, serverNegotiation)
		}()

		// Start client
		clientNegotiation := &SecurityNegotiation{
			IsClient:     true,
			ClientConfig: clientConfig,
		}
		clientErr := clientAuth.performTokenAuthentication(context.Background(), AuthToken, clientNegotiation)

		// Wait for server completion
		var serverClientErr error
		select {
		case serverClientErr = <-serverErr:
		case <-time.After(2 * time.Second):
			t.Error("Server authentication timed out")
			return
		}

		// Both should complete the handshake but return authentication errors
		t.Logf("Client error (expected): %v", clientErr)
		t.Logf("Server error (expected): %v", serverClientErr)

		// At least one side should report an authentication error related to token validation
		// Server should fail on token validation (expired token)
		if clientErr == nil && serverClientErr == nil {
			t.Error("Expected at least one side to report authentication failure")
		}

		// Specifically check that server reports token validation failure
		if serverClientErr != nil && !strings.Contains(serverClientErr.Error(), "token") {
			t.Errorf("Expected server token validation error, got: %v", serverClientErr)
		}
	})
}

// TestTokenAuthenticationDirectToken tests TOKEN authentication using a direct token in SecurityConfig
func TestTokenAuthenticationDirectToken(t *testing.T) {
	poolKeyFile, namedKeyDir, cleanup := setupTestSigningKeys(t)
	defer cleanup()

	// Create a test JWT token
	testToken := createTestJWT("alice@test.domain", "test.domain", 3600)

	// Create a pair of connected sockets for testing
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	// Create streams
	serverStream := stream.NewStream(server)
	clientStream := stream.NewStream(client)

	// Client configuration with direct Token (not TokenFile)
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthToken},
		Authentication: SecurityRequired,
		CryptoMethods:  []CryptoMethod{}, // No crypto to avoid key exchange issues
		Encryption:     SecurityNever,    // Disable encryption
		Integrity:      SecurityOptional,
		Token:          testToken, // Use direct token instead of TokenFile
		TrustDomain:    "test.domain",
		IssuerKeys:     []string{"POOL"}, // Accept tokens with kid="POOL"
		RemoteVersion:  "$CondorVersion: 25.4.0 2025-11-07 BuildID: 123456 $",
	}

	// Server configuration that supports TOKEN authentication
	serverConfig := &SecurityConfig{
		AuthMethods:             []AuthMethod{AuthToken, AuthSSL},
		Authentication:          SecurityRequired,
		CryptoMethods:           []CryptoMethod{}, // No crypto to avoid key exchange issues
		Encryption:              SecurityNever,    // Disable encryption
		Integrity:               SecurityOptional,
		TrustDomain:             "test.domain",
		RemoteVersion:           "$CondorVersion: 25.4.0 2025-11-07 BuildID: 123456 $",
		TokenPoolSigningKeyFile: poolKeyFile,
		TokenSigningKeyDir:      namedKeyDir,
	}

	ctx := context.Background()

	// Create authenticators
	clientAuth := NewAuthenticator(clientConfig, clientStream)
	serverAuth := NewAuthenticator(serverConfig, serverStream)

	// Channel to coordinate the handshake
	serverResultChan := make(chan *SecurityNegotiation, 1)
	serverErrChan := make(chan error, 1)

	// Start server handshake in a goroutine
	go func() {
		result, err := serverAuth.ServerHandshake(context.Background())
		if err != nil {
			slog.Info(fmt.Sprintf("Server handshake failed: %v", err), "destination", "cedar")
			serverErrChan <- err
		} else {
			slog.Info("Server handshake succeeded with TOKEN auth using direct token", "destination", "cedar")
			serverResultChan <- result
		}
	}()

	// Give server time to start listening
	time.Sleep(100 * time.Millisecond)

	// Perform client handshake
	clientNegotiation, err := clientAuth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("Client handshake failed: %v", err)
	}

	// Wait for server completion
	var serverNegotiation *SecurityNegotiation
	select {
	case serverNegotiation = <-serverResultChan:
		// Success
	case err := <-serverErrChan:
		t.Fatalf("Server handshake failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server handshake timed out")
	}

	// Verify authentication succeeded
	if clientNegotiation.NegotiatedAuth != AuthToken {
		t.Errorf("Expected negotiated auth to be TOKEN, got %s", clientNegotiation.NegotiatedAuth)
	}
	if serverNegotiation.NegotiatedAuth != AuthToken {
		t.Errorf("Expected negotiated auth to be TOKEN, got %s", serverNegotiation.NegotiatedAuth)
	}

	t.Logf("✅ Direct token authentication succeeded")
	t.Logf("   Negotiated Auth: %s", clientNegotiation.NegotiatedAuth)
}

// TestDirectTokenLoading tests that loadTokenForAuthentication works with direct tokens
func TestDirectTokenLoading(t *testing.T) {
	poolKeyFile, namedKeyDir, cleanup := setupTestSigningKeys(t)
	defer cleanup()

	// Create a test JWT token
	testToken := createTestJWT("alice@test.domain", "test.domain", 3600)

	// Create configuration with direct token
	clientConfig := &SecurityConfig{
		Token:       testToken, // Use direct token
		TrustDomain: "test.domain",
		IssuerKeys:  []string{"POOL"},
	}

	serverConfig := &SecurityConfig{
		TrustDomain:             "test.domain",
		TokenPoolSigningKeyFile: poolKeyFile,
		TokenSigningKeyDir:      namedKeyDir,
	}

	// Create a test stream (not needed for this test, but required by authenticator)
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	clientStream := stream.NewStream(client)

	// Create authenticator
	auth := NewAuthenticator(clientConfig, clientStream)

	// Create auth data and negotiation objects
	authData := &TokenAuthData{State: TokenStateInit}
	negotiation := &SecurityNegotiation{
		ClientConfig: clientConfig,
		ServerConfig: serverConfig,
		IsClient:     true,
	}

	// Test token loading
	err := auth.loadTokenForAuthentication(AuthToken, authData, negotiation)
	if err != nil {
		t.Fatalf("Token loading failed: %v", err)
	}

	// Verify the token was loaded correctly
	if authData.ClientID != "alice@test.domain" {
		t.Errorf("Expected client ID 'alice@test.domain', got '%s'", authData.ClientID)
	}

	// Verify token content was loaded (header.payload part)
	if authData.Token == "" {
		t.Error("Expected token content to be loaded")
	}

	t.Logf("✅ Direct token loading test succeeded")
	t.Logf("   Client ID: %s", authData.ClientID)
	t.Logf("   Token loaded: %t", authData.Token != "")
}

// TestAuthMethodsExhaustedError covers the new error type returned by
// the client-side auth loop when every offered method fails. We
// verify three properties an operator and a programmatic caller both
// rely on:
//
//  1. Error() names every method that was tried, in order, with the
//     specific failure for each — that's what makes the difference
//     between "all auth methods failed" (useless) and "SSL: <x509
//     mismatch>; TOKEN: <bad signature>" (actionable).
//  2. errors.Is matches a sentinel embedded in any per-method
//     failure — callers checking for SessionResumptionError or
//     net.OpError shouldn't have to crawl the slice manually.
//  3. The empty-attempts case degrades to the historical message
//     so older log scrapers continue to match.
func TestAuthMethodsExhaustedError(t *testing.T) {
	tlsErr := errors.New("TLS handshake failed: x509: certificate is valid for cm-1.example.org, not unknown")
	tokenErr := errors.New("no compatible methods after token issuer filter")

	err := &AuthMethodsExhaustedError{
		Attempts: []AuthMethodAttempt{
			{Method: AuthSSL, Err: tlsErr},
			{Method: AuthToken, Err: tokenErr},
		},
	}

	msg := err.Error()
	for _, want := range []string{
		"all authentication methods failed",
		"SSL:", "x509",
		"TOKEN:", "no compatible methods",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, missing %q", msg, want)
		}
	}

	if !errors.Is(err, tlsErr) {
		t.Error("errors.Is should match the TLS handshake error")
	}
	if !errors.Is(err, tokenErr) {
		t.Error("errors.Is should match the token error")
	}

	empty := &AuthMethodsExhaustedError{}
	if got, want := empty.Error(), "all authentication methods failed"; got != want {
		t.Errorf("empty Error() = %q, want %q", got, want)
	}
}

// TestRedactSessionID covers the helper used by every slog log site
// that emits a cedar session identifier. The contract is:
//
//   - empty input → "<empty>" (so missing-ID code paths are still
//     distinguishable in logs)
//   - <= 8 chars → keep all chars + "..." (rare but possible during
//     tests / local sessions where IDs aren't real cedar tokens)
//   - longer → first 8 chars + "..." (32 bits — enough to correlate
//     consecutive log lines for the same session, not enough to
//     brute-force the remaining ~160 bits)
func TestRedactSessionID(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "<empty>"},
		{"short", "abc123", "abc123..."},
		{"exactly 8", "12345678", "12345678..."},
		{"long real-world ID", "c2a5f5d46610211bb58f80f0a37d99e7236fef4a30c2e5db", "c2a5f5d4..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactSessionID(tc.in); got != tc.want {
				t.Errorf("redactSessionID(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
