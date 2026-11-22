package security

import (
	"net"
	"testing"

	"github.com/htcondor/cedar/stream"
)

func TestSSLAuthentication(t *testing.T) {
	// Create a simple test to verify SSL authentication works with the correct bitmask

	// Test authMethodToBitmask conversion for SSL
	sslBitmask := authMethodToBitmask(AuthSSL)
	expectedSSLBitmask := AuthBitmaskSSL // Should be 256

	if sslBitmask != expectedSSLBitmask {
		t.Errorf("SSL bitmask mismatch: got %d, expected %d", sslBitmask, expectedSSLBitmask)
	}

	// Test bitmaskToAuthMethod conversion
	authMethod := bitmaskToAuthMethod(AuthBitmaskSSL)
	if authMethod != AuthSSL {
		t.Errorf("SSL auth method conversion failed: got %s, expected %s", authMethod, AuthSSL)
	}

	t.Logf("✅ SSL bitmask conversions working correctly:")
	t.Logf("    AuthSSL -> bitmask: %d (0x%x)", sslBitmask, sslBitmask)
	t.Logf("    bitmask -> AuthSSL: %s", authMethod)
}

func TestSSLAuthenticatorCreation(t *testing.T) {
	// Create a pair of connected sockets for testing
	server, client := net.Pipe()
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("Error closing server: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("Error closing client: %v", err)
		}
	}()

	stream1 := stream.NewStream(client)

	// Create authenticator config with SSL
	config := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthSSL},
		Authentication: SecurityRequired,
		CryptoMethods:  []CryptoMethod{CryptoAES},
		Encryption:     SecurityOptional,

		// SSL specific config
		CertFile: "/path/to/cert.pem", // Mock paths
		KeyFile:  "/path/to/key.pem",
		CAFile:   "/path/to/ca.pem",
	}

	// Create authenticator
	auth := NewAuthenticator(config, stream1)
	if auth == nil {
		t.Fatal("Failed to create authenticator")
	}

	// Create SSL authenticator
	sslAuth := NewSSLAuthenticator(auth)
	if sslAuth == nil {
		t.Fatal("Failed to create SSL authenticator")
	}

	if sslAuth.authenticator != auth {
		t.Error("SSL authenticator not properly linked to base authenticator")
	}

	if sslAuth.clientStatus != AuthSSLOK {
		t.Errorf("Initial SSL client status should be OK, got: %d", sslAuth.clientStatus)
	}

	t.Logf("✅ SSL authenticator created successfully")
	t.Logf("    Certificate file: %s", config.CertFile)
	t.Logf("    Key file: %s", config.KeyFile)
	t.Logf("    CA file: %s", config.CAFile)
}

func TestSSLSecurityNegotiation(t *testing.T) {
	// Test that SSL appears in security negotiation ClassAd

	// Create authenticator config with SSL
	config := &SecurityConfig{
		AuthMethods:   []AuthMethod{AuthSSL, AuthToken},
		CryptoMethods: []CryptoMethod{CryptoAES},
	}

	// Create mock stream using net.Pipe()
	server, client := net.Pipe()
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("Error closing server: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("Error closing client: %v", err)
		}
	}()

	stream1 := stream.NewStream(client)
	auth := NewAuthenticator(config, stream1)

	// Create client security ClassAd
	clientAd := auth.createClientSecurityAd()

	// Check that SSL is included in auth methods
	authMethods, ok := clientAd.EvaluateAttrString("AuthMethods")
	if !ok {
		t.Fatal("AuthMethods not found in client security ad")
	}

	if authMethods != "SSL,TOKEN" {
		t.Errorf("Expected SSL,TOKEN in auth methods, got: %s", authMethods)
	}

	// Parse the ClassAd back to verify SSL is supported
	parsedConfig := auth.parseClientSecurityAd(clientAd)

	sslSupported := false
	for _, method := range parsedConfig.AuthMethods {
		if method == AuthSSL {
			sslSupported = true
			break
		}
	}

	if !sslSupported {
		t.Error("SSL not found in parsed authentication methods")
	}

	t.Logf("✅ SSL properly included in security negotiation:")
	t.Logf("    Auth methods string: %s", authMethods)
	t.Logf("    SSL supported: %t", sslSupported)
}

func TestSSLBitmaskConstants(t *testing.T) {
	// Verify that our SSL bitmask matches HTCondor's CAUTH_SSL
	expectedSSL := 256 // CAUTH_SSL from HTCondor's condor_auth.h

	if AuthBitmaskSSL != expectedSSL {
		t.Errorf("SSL bitmask mismatch with HTCondor: got %d, expected %d", AuthBitmaskSSL, expectedSSL)
	}

	// Test that SSL bitmask is unique among all auth bitmasks
	allBitmasks := []int{
		AuthBitmaskNone,
		AuthBitmaskAny,
		AuthBitmaskClaimToBe,
		AuthBitmaskFS,
		AuthBitmaskFSRemote,
		AuthBitmaskNTSSPI,
		AuthBitmaskGSI,
		AuthBitmaskKerberos,
		AuthBitmaskAnonymous,
		AuthBitmaskSSL,
		AuthBitmaskPassword,
		AuthBitmaskMunge,
		AuthBitmaskToken,
		AuthBitmaskSciTokens,
	}

	seen := make(map[int]bool)
	for _, bitmask := range allBitmasks {
		if seen[bitmask] {
			t.Errorf("Duplicate bitmask value: %d", bitmask)
		}
		seen[bitmask] = true
	}

	t.Logf("✅ SSL bitmask constants verified:")
	t.Logf("    AuthBitmaskSSL: %d (0x%x)", AuthBitmaskSSL, AuthBitmaskSSL)
	t.Logf("    Matches HTCondor CAUTH_SSL: %t", AuthBitmaskSSL == expectedSSL)
}
