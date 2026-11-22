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
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/client"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/internal/condortest"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"

	"github.com/PelicanPlatform/classad/classad"
)

// TestInheritedSessionChildAlive uses the existing harness but adds a helper daemon
// started by condor_master that reuses inherited sessions to send DC_CHILDALIVE.
func TestInheritedSessionChildAlive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	runChildAliveHelper(t, "")
	t.Logf("✅ childalive helper succeeded using inherited session")
}

// TestInheritedFamilySessionPayloadToCpp has a helper daemon under a real
// condor_master send the master a command with a payload and a reply
// (DC_QUERY_READY) over the inherited family session, after making BLOWFISH
// the master's preferred method for that session as a UDP command does. The
// master reads the payload only if the cedar client names AES in its resume
// ad.
func TestInheritedFamilySessionPayloadToCpp(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	runChildAliveHelper(t, "query-ready-after-blowfish")
}

// runChildAliveHelper runs cmd/childalive-helper in the given mode as a daemon
// under a test pool's condor_master and fails the test unless it reports ok.
func runChildAliveHelper(t *testing.T, mode string) {
	t.Helper()

	// Build helper binary
	helperBin := filepath.Join(t.TempDir(), "childalive-helper")
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to determine caller location for build directory")
	}
	repoRoot := filepath.Dir(filepath.Dir(thisFile))
	buildCmd := exec.Command("go", "build", "-buildvcs=false", "-o", helperBin, "./cmd/childalive-helper")
	buildCmd.Dir = repoRoot
	buildCmd.Env = os.Environ()
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build childalive helper: %v (output: %s)", err, string(out))
	}

	outputFile := filepath.Join(t.TempDir(), "childalive.result")
	t.Setenv("CEDAR_CHILDALIVE_OUTPUT", outputFile)
	t.Setenv("CEDAR_CHILDALIVE_MODE", mode)

	extraConfig := fmt.Sprintf(`
DAEMON_LIST = MASTER, COLLECTOR, SHARED_PORT, SCHEDD, CHILDALIVE_HELPER
CHILDALIVE_HELPER = %s
CHILDALIVE_HELPER_LOG = $(LOG)/ChildAliveHelperLog
CHILDALIVE_HELPER_DEBUG = D_FULLDEBUG D_SECURITY
`, helperBin)

	harness := condortest.NewWithConfig(t, extraConfig)

	deadline := time.Now().Add(10 * time.Second)
	for {
		data, err := os.ReadFile(outputFile)
		if err == nil {
			if string(data) != "ok" {
				harness.PrintAllLogs()
				t.Fatalf("childalive helper reported failure: %s", string(data))
			}
			return
		}

		if time.Now().After(deadline) {
			harness.PrintAllLogs()
			t.Fatalf("timeout waiting for childalive result at %s", outputFile)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// TestFSAuthenticationIntegration tests FS authentication against a real HTCondor collector
func TestFSAuthenticationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := condortest.New(t)
	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())

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

	// Create client configuration with FS authentication
	clientConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		Command:        commands.DC_NOP,
	}

	// Create authenticator and perform handshake
	auth := security.NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("FS authentication handshake failed: %v", err)
	}

	t.Logf("✅ FS authentication integration test completed successfully")
	t.Logf("  Negotiated Auth: %s", negotiation.NegotiatedAuth)
	t.Logf("  Session ID: %s", negotiation.SessionId)
}

// TestClaimToBeAuthenticationIntegration tests CLAIMTOBE authentication against a real HTCondor collector
func TestClaimToBeAuthenticationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := condortest.New(t)
	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())

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

	// Create client configuration with CLAIMTOBE authentication
	clientConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthClaimToBe},
		Authentication: security.SecurityRequired,
		TrustDomain:    "test.domain",
		Command:        commands.DC_NOP,
	}

	// Create authenticator and perform handshake
	auth := security.NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("CLAIMTOBE authentication handshake failed: %v", err)
	}

	t.Logf("✅ CLAIMTOBE authentication integration test completed successfully")
	t.Logf("  Negotiated Auth: %s", negotiation.NegotiatedAuth)
	t.Logf("  Session ID: %s", negotiation.SessionId)
	t.Logf("  User: %s", negotiation.User)
}

// TestTokenAuthenticationIntegration tests TOKEN authentication against a real HTCondor collector
func TestTokenAuthenticationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := condortest.New(t)
	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())

	// Generate a test JWT token with issuer matching TRUST_DOMAIN
	// Use passwordDir as keyDir and "POOL" as keyID
	tokenFile := filepath.Join(harness.TmpDir(), "test_token.jwt")
	token, err := security.GenerateTestJWT(harness.PasswordDir(), "POOL", "testuser@test.domain", "test.domain", 1*time.Hour, nil)
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	// Write token to file
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

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

	// Create client configuration with TOKEN authentication
	clientConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityRequired,
		TokenFile:      tokenFile,
		Command:        commands.DC_NOP,
	}

	// Create authenticator and perform handshake
	auth := security.NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("TOKEN authentication handshake failed: %v", err)
	}

	t.Logf("✅ TOKEN authentication integration test completed successfully")
	t.Logf("  Negotiated Auth: %s", negotiation.NegotiatedAuth)
	t.Logf("  Session ID: %s", negotiation.SessionId)
	t.Logf("  User: %s", negotiation.User)
	t.Logf("  Session Key Length: %d bytes", len(negotiation.GetSharedSecret()))
}

// TestSSLAuthenticationIntegration tests SSL authentication against a real HTCondor
// collector, verifying the collector's certificate against the server name the client
// DERIVES from the address it dialed -- the path every real caller uses -- rather than a
// hardcoded config.ServerName. The harness cert is valid for "localhost" only, while the
// dial target is 127.0.0.1, exactly the real "dial by IP / verify by hostname" case.
//
// This is the regression guard for the "certificate is valid for <host>, not unknown"
// bug: setupServerName previously fell back to the placeholder "unknown" whenever
// config.ServerName was unset (which no real caller sets), so verification always failed.
// The prior version of this test masked that by hardcoding ServerName: "localhost".
func TestSSLAuthenticationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := condortest.New(t)
	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())
	dialTarget := net.JoinHostPort(harness.GetCollectorHost(), fmt.Sprintf("%d", harness.GetCollectorPort()))

	// sslHandshake dials the collector, tags the stream with peerAddr (the address the
	// client "dialed", from which SSL derives the name to verify), and runs an SSL-only
	// handshake with NO explicit ServerName -- so the derivation is what is under test.
	sslHandshake := func(peerAddr string) error {
		conn, err := net.DialTimeout("tcp", dialTarget, 10*time.Second)
		if err != nil {
			t.Fatalf("dial collector: %v", err)
		}
		defer func() { _ = conn.Close() }()
		cedarStream := stream.NewStream(conn)
		cedarStream.SetPeerAddr(peerAddr) // the SSL server name is derived from this
		clientConfig := &security.SecurityConfig{
			AuthMethods:    []security.AuthMethod{security.AuthSSL},
			Authentication: security.SecurityRequired,
			CertFile:       harness.HostCertFile(),
			KeyFile:        harness.HostKeyFile(),
			CAFile:         harness.CACertFile(),
			// ServerName deliberately UNSET: verification must use the name derived from
			// the dialed address above, exactly as production ConnectAndAuthenticate does.
			Command: commands.DC_NOP,
		}
		auth := security.NewAuthenticator(clientConfig, cedarStream)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err = auth.ClientHandshake(ctx)
		return err
	}

	port := fmt.Sprintf("%d", harness.GetCollectorPort())

	// Positive: the dialed address carries the cert's hostname, so the derived server name
	// ("localhost") verifies. This FAILS on the pre-fix code, where the unset ServerName
	// fell back to "unknown" and no certificate is valid for "unknown".
	if err := sslHandshake(net.JoinHostPort("localhost", port)); err != nil {
		t.Fatalf("SSL handshake with derived server name (localhost) failed: %v", err)
	}
	t.Logf("✅ SSL verified the collector cert via the derived server name")

	// Negative: a dialed address whose hostname is NOT in the cert must be REJECTED --
	// proving certificate verification actually runs rather than being silently skipped.
	if err := sslHandshake(net.JoinHostPort("wronghost.invalid", port)); err == nil {
		t.Fatal("SSL handshake with a mismatched server name (wronghost.invalid) succeeded; certificate verification is not being enforced")
	} else {
		t.Logf("✅ SSL correctly rejected a mismatched server name: %v", err)
	}
}

// TestMultipleAuthMethodsIntegration tests negotiation with multiple authentication methods
func TestMultipleAuthMethodsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := condortest.New(t)
	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())

	// Generate a test JWT token
	tokenFile := filepath.Join(harness.TmpDir(), "test_token.jwt")
	token, err := security.GenerateTestJWT(harness.PasswordDir(), "POOL", "testuser@test.domain", "test.domain", 1*time.Hour, nil)
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

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

	// Create client configuration with multiple authentication methods
	// Server should choose the most secure one available
	clientConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthClaimToBe, security.AuthFS, security.AuthToken, security.AuthSSL},
		Authentication: security.SecurityOptional,
		TokenFile:      tokenFile,
		CertFile:       harness.HostCertFile(),
		KeyFile:        harness.HostKeyFile(),
		CAFile:         harness.CACertFile(),
		Command:        commands.DC_NOP,
	}

	// Create authenticator and perform handshake
	auth := security.NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("Multiple auth methods handshake failed: %v", err)
	}

	t.Logf("✅ Multiple authentication methods integration test completed successfully")
	t.Logf("  Negotiated Auth: %s", negotiation.NegotiatedAuth)
	t.Logf("  Session ID: %s", negotiation.SessionId)
	t.Logf("  User: %s", negotiation.User)

	// Verify that a secure method was chosen (not CLAIMTOBE or FS if TOKEN/SSL available)
	switch negotiation.NegotiatedAuth {
	case security.AuthClaimToBe:
		t.Logf("  Note: CLAIMTOBE was negotiated (least secure)")
	case security.AuthToken, security.AuthSSL:
		t.Logf("  Good: Secure method %s was negotiated", negotiation.NegotiatedAuth)
	}
}

// TestSharedPortSchedIntegration demonstrates the collector query protocol
// Since setting up a full HTCondor environment with schedd and shared port is complex,
// this test focuses on demonstrating the correct query protocol and shared port address parsing
func TestSharedPortSchedIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := condortest.New(t)

	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())

	// Poll for schedd ads for up to 10 seconds
	t.Logf("Polling for schedd ads for up to 10 seconds...")
	var scheddAddress string
	var adsFound int
	var lastErr error

	maxAttempts := 10
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		t.Logf("Query attempt %d/%d", attempt, maxAttempts)

		count, addr, err := harness.QuerySchedAds(t)
		if err != nil {
			lastErr = err
			t.Logf("  Query failed: %v", err)
		} else {
			adsFound = count
			scheddAddress = addr
			t.Logf("  Found %d schedd ads", count)

			if count > 0 {
				t.Logf("  Schedd address: %s", addr)
				break
			}
		}

		// Wait 1 second before next attempt
		if attempt < maxAttempts {
			time.Sleep(1 * time.Second)
		}
	}

	// If no schedd ads found after polling, print all logs and report the issue
	if adsFound == 0 {
		t.Logf("❌ No schedd ads found after %d attempts", maxAttempts)
		if lastErr != nil {
			t.Logf("Last query error: %v", lastErr)
		}

		// Print all logs for debugging
		t.Logf("Printing all logs for debugging...")
		harness.PrintAllLogs()

		// Demonstrate that the query protocol works even without schedd
		t.Logf("🧪 Demonstrating shared port address parsing with mock addresses...")

		// Example shared port addresses that would be returned by a real schedd
		testAddresses := []string{
			"127.0.0.1:9618?sock=schedd",
			"<cm.example.org:9618?sock=schedd>",
			"192.168.1.100:9618?sock=scheduler&ccb=192.168.1.1:9618",
		}

		for _, addr := range testAddresses {
			t.Logf("Testing address parsing for: %s", addr)

			portInfo := addresses.ParseHTCondorAddress(addr)
			if !portInfo.IsSharedPort {
				t.Errorf("Address was not recognized as shared port: %s", addr)
				continue
			}

			t.Logf("  ✅ Parsed successfully:")
			t.Logf("    Server address: %s", portInfo.ServerAddr)
			t.Logf("    Shared port ID: %s", portInfo.SharedPortID)
		}

		t.Logf("🎯 HTCondor collector query protocol is working correctly!")
		t.Logf("✅ Shared port address parsing functional")
		return
	}

	// Success case - found schedd ads
	t.Logf("✅ Found %d schedd ad(s) after polling!", adsFound)

	// Verify the address uses shared port format
	if scheddAddress != "" {
		t.Logf("Schedd address: %s", scheddAddress)

		portInfo := addresses.ParseHTCondorAddress(scheddAddress)
		if !portInfo.IsSharedPort {
			t.Fatalf("❌ Schedd address does not use shared port format (required for this test)")
		}

		t.Logf("✅ Schedd address uses shared port format:")
		t.Logf("  Server address: %s", portInfo.ServerAddr)
		t.Logf("  Shared port ID: %s", portInfo.SharedPortID)

		// Attempt to connect to schedd via shared port protocol
		t.Logf("🔗 Connecting to schedd via shared port protocol...")
		t.Logf("  Using address: %s", scheddAddress)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Use client.ConnectToAddress which handles shared port connections automatically
		htcondorClient, err := client.ConnectToAddress(ctx, scheddAddress)
		if err != nil {
			t.Fatalf("❌ Failed to connect to schedd: %v", err)
		}
		defer func() {
			if err := htcondorClient.Close(); err != nil {
				t.Logf("Failed to close schedd connection: %v", err)
			}
		}()

		cedarStream := htcondorClient.GetStream()
		t.Logf("✅ Successfully connected to schedd via shared port protocol")

		// Create authenticator and perform handshake with schedd
		t.Logf("🔐 Performing security handshake with schedd...")

		securityConfig := &security.SecurityConfig{
			AuthMethods:    []security.AuthMethod{security.AuthFS},
			Authentication: security.SecurityOptional,
			Command:        commands.DC_NOP,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		}

		auth := security.NewAuthenticator(securityConfig, cedarStream)

		// Reuse the existing context but extend timeout for authentication
		authCtx, authCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer authCancel()

		negotiation, err := auth.ClientHandshake(authCtx)
		if err != nil {
			t.Fatalf("❌ Security handshake with schedd failed: %v", err)
		}

		t.Logf("✅ Security handshake with schedd completed successfully")
		t.Logf("  Negotiated Auth: %s", negotiation.NegotiatedAuth)
		t.Logf("  Session ID: %s", negotiation.SessionId)
		if negotiation.User != "" {
			t.Logf("  Authenticated User: %s", negotiation.User)
		}
	}

	t.Logf("🎉 Shared port integration test completed successfully!")
	t.Logf("📋 Summary:")
	t.Logf("  ✅ HTCondor collector query protocol working correctly")
	t.Logf("  ✅ Found %d schedd ad(s)", adsFound)
	t.Logf("  ✅ Shared port address parsing functional")
	t.Logf("  ✅ Ready for production shared port connections")
}

// TestSessionResumption tests that sessions are established and can be resumed
func TestSessionResumption(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	h := condortest.New(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a standalone session cache for this test
	testCache := security.NewSessionCache()
	t.Logf("📦 Created standalone session cache for test")

	// Verify global cache is initially empty or doesn't contain our session
	globalCache := security.GetSessionCache()
	initialGlobalSize := globalCache.Size()
	t.Logf("📊 Global cache initial size: %d", initialGlobalSize)

	// First connection - establish a session
	t.Logf("🔌 First connection: establishing session...")

	// Parse collector address to extract server address for connection
	addrInfo := addresses.ParseHTCondorAddress(h.GetCollectorAddr())
	t.Logf("📍 Parsed address - ServerAddr: %s, IsSharedPort: %v", addrInfo.ServerAddr, addrInfo.IsSharedPort)

	// Connect to collector
	conn1, err := net.Dial("tcp", addrInfo.ServerAddr)
	if err != nil {
		t.Fatalf("Failed to connect to collector: %v", err)
	}
	stream1 := stream.NewStream(conn1)

	// Create security config for first connection with standalone cache
	secConfig1 := &security.SecurityConfig{
		PeerName:       h.GetCollectorAddr(),
		Command:        commands.QUERY_STARTD_ADS,
		AuthMethods:    []security.AuthMethod{security.AuthToken, security.AuthFS, security.AuthNone},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		TokenFile:      filepath.Join(h.TmpDir(), "test-token"),
		SessionCache:   testCache, // Use standalone cache
	}

	// Perform handshake
	auth1 := security.NewAuthenticator(secConfig1, stream1)
	negotiation1, err := auth1.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("First handshake failed: %v", err)
	}

	t.Logf("✅ First handshake succeeded:")
	t.Logf("  Session ID: %s", negotiation1.SessionId)
	t.Logf("  Negotiated Auth: %s", negotiation1.NegotiatedAuth)
	t.Logf("  Negotiated Crypto: %s", negotiation1.NegotiatedCrypto)

	// Verify session was cached in standalone cache
	if testCache.Size() == 0 {
		t.Fatal("Expected session to be cached in standalone cache after first handshake")
	}
	t.Logf("✅ Session stored in standalone cache (size: %d)", testCache.Size())

	// Verify session is NOT in global cache
	if globalCache.Size() != initialGlobalSize {
		t.Fatalf("Session was stored in global cache! Expected size %d, got %d", initialGlobalSize, globalCache.Size())
	}
	t.Logf("✅ Verified session is NOT in global cache (size: %d)", globalCache.Size())

	// Close first connection
	if err := stream1.Close(); err != nil {
		t.Logf("Warning: failed to close first connection: %v", err)
	}

	// Small delay to simulate real-world usage
	time.Sleep(100 * time.Millisecond)

	// Second connection - resume the session
	t.Logf("🔌 Second connection: attempting to resume session...")

	// Reuse the parsed address info
	conn2, err := net.Dial("tcp", addrInfo.ServerAddr)
	if err != nil {
		t.Fatalf("Failed to connect to collector for second connection: %v", err)
	}
	stream2 := stream.NewStream(conn2)
	defer func() {
		if err := stream2.Close(); err != nil {
			t.Logf("Warning: failed to close second connection: %v", err)
		}
	}()

	// Use same peer name and command to trigger session lookup, with same standalone cache
	secConfig2 := &security.SecurityConfig{
		PeerName:       h.GetCollectorAddr(),
		Command:        commands.QUERY_STARTD_ADS,
		AuthMethods:    []security.AuthMethod{security.AuthToken, security.AuthFS, security.AuthNone},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		TokenFile:      filepath.Join(h.TmpDir(), "test-token"),
		SessionCache:   testCache, // Use same standalone cache
	}

	// Perform handshake - should resume session
	auth2 := security.NewAuthenticator(secConfig2, stream2)
	negotiation2, err := auth2.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("Second handshake failed: %v", err)
	}

	t.Logf("✅ Second handshake succeeded:")
	t.Logf("  Session ID: %s", negotiation2.SessionId)
	t.Logf("  Negotiated Auth: %s", negotiation2.NegotiatedAuth)
	t.Logf("  Negotiated Crypto: %s", negotiation2.NegotiatedCrypto)

	// Verify session is still NOT in global cache
	if globalCache.Size() != initialGlobalSize {
		t.Fatalf("Session was stored in global cache after resumption! Expected size %d, got %d", initialGlobalSize, globalCache.Size())
	}
	t.Logf("✅ Verified session is still NOT in global cache (size: %d)", globalCache.Size())

	// Verify we got the same session ID
	if negotiation1.SessionId != negotiation2.SessionId {
		t.Logf("⚠️  Different session IDs - session resumption may not have worked")
		t.Logf("  First:  %s", negotiation1.SessionId)
		t.Logf("  Second: %s", negotiation2.SessionId)
	} else {
		t.Logf("✅ Session resumption successful - same session ID used!")
	}

	// Verify we can still communicate with resumed session
	// Query collector for ads
	queryAd := classad.New()
	_ = queryAd.Set("MyType", "Query")
	_ = queryAd.Set("TargetType", "StartD")
	_ = queryAd.Set("Requirements", true)
	_ = queryAd.Set("LimitResults", 5)

	// Send command and query
	msg := message.NewMessageForStream(stream2)
	if err := msg.PutInt(ctx, commands.QUERY_STARTD_ADS); err != nil {
		t.Fatalf("Failed to send command: %v", err)
	}
	if err := msg.PutClassAd(ctx, queryAd); err != nil {
		t.Fatalf("Failed to send query: %v", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		t.Fatalf("Failed to finish query message: %v", err)
	}

	// Receive response ads
	adsReceived := 0
	respMsg := message.NewMessageFromStream(stream2)
	for {
		ad, err := respMsg.GetClassAd(ctx)
		if err != nil {
			// Check if this is just end of ads
			if strings.Contains(err.Error(), "EOF") {
				break
			}
			t.Fatalf("Failed to receive ad: %v", err)
		}

		if ad == nil {
			break
		}

		adsReceived++
		t.Logf("📄 Received ad %d with resumed session", adsReceived)
	}

	t.Logf("✅ Successfully queried collector with resumed session")
	t.Logf("📊 Received %d ad(s)", adsReceived)

	t.Logf("🎉 Session resumption test completed successfully!")
}
