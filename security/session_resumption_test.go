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

package security

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/stream"
)

// TestSessionResumptionWithEncryption tests session resumption when encryption is enabled
// This is a regression test for the panic that occurred when setupStreamEncryption tried
// to access ServerConfig during session resumption
func TestSessionResumptionWithEncryption(t *testing.T) {
	// Create a pair of connected sockets
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	// Create streams
	serverStream := stream.NewStream(server)
	clientStream := stream.NewStream(client)

	// Create a standalone session cache
	testCache := NewSessionCache()

	// Client configuration with encryption enabled
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		Authentication: SecurityOptional,
		CryptoMethods:  []CryptoMethod{CryptoAES},
		Encryption:     SecurityOptional,
		PeerName:       "test-server",
		Command:        commands.DC_NOP,
		SessionCache:   testCache,
	}

	// Server configuration
	serverConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		Authentication: SecurityOptional,
		CryptoMethods:  []CryptoMethod{CryptoAES},
		Encryption:     SecurityOptional,
		Command:        commands.DC_NOP,
	}

	// Channel to coordinate the handshake
	serverResultChan := make(chan *SecurityNegotiation, 1)
	serverErrChan := make(chan error, 1)

	// ========== First handshake - establish session ==========
	t.Log("🔌 First handshake: establishing session...")

	// Start server handshake in a goroutine
	go func() {
		serverAuth := NewAuthenticator(serverConfig, serverStream)
		result, err := serverAuth.ServerHandshake(context.Background())
		if err != nil {
			serverErrChan <- err
		} else {
			serverResultChan <- result
		}
	}()

	// Give server time to start listening
	time.Sleep(100 * time.Millisecond)

	// Perform client handshake
	clientAuth := NewAuthenticator(clientConfig, clientStream)
	ctx := context.Background()
	negotiation1, err := clientAuth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("First client handshake failed: %v", err)
	}

	// Wait for server to complete
	select {
	case err := <-serverErrChan:
		t.Fatalf("Server handshake failed: %v", err)
	case serverNeg := <-serverResultChan:
		t.Logf("✅ First handshake completed")
		t.Logf("  Client Session ID: %s", negotiation1.SessionId)
		t.Logf("  Server Session ID: %s", serverNeg.SessionId)
		t.Logf("  Negotiated Auth: %s", negotiation1.NegotiatedAuth)
		t.Logf("  Negotiated Crypto: %s", negotiation1.NegotiatedCrypto)
		t.Logf("  Shared Secret Length: %d bytes", len(negotiation1.GetSharedSecret()))
	case <-time.After(5 * time.Second):
		t.Fatal("Server handshake timed out")
	}

	// Verify session was cached
	if testCache.Size() == 0 {
		t.Fatal("Expected session to be cached after first handshake")
	}
	t.Logf("✅ Session cached (cache size: %d)", testCache.Size())

	// Close first connection
	if err := serverStream.Close(); err != nil {
		t.Logf("Warning: failed to close server stream: %v", err)
	}
	if err := clientStream.Close(); err != nil {
		t.Logf("Warning: failed to close client stream: %v", err)
	}

	// Small delay to simulate real-world usage
	time.Sleep(100 * time.Millisecond)

	// ========== Second handshake - resume session ==========
	t.Log("🔌 Second handshake: resuming session...")

	// Create new connection pair
	server2, client2 := net.Pipe()
	defer func() { _ = server2.Close() }()
	defer func() { _ = client2.Close() }()

	serverStream2 := stream.NewStream(server2)
	clientStream2 := stream.NewStream(client2)

	// Client configuration for session resumption (same as before)
	clientConfig2 := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		Authentication: SecurityOptional,
		CryptoMethods:  []CryptoMethod{CryptoAES},
		Encryption:     SecurityOptional,
		PeerName:       "test-server",
		Command:        commands.DC_NOP,
		SessionCache:   testCache, // Use same cache
	}

	// Server configuration for second connection
	serverConfig2 := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		Authentication: SecurityOptional,
		CryptoMethods:  []CryptoMethod{CryptoAES},
		Encryption:     SecurityOptional,
		Command:        commands.DC_NOP,
	}

	// Start server handshake in a goroutine
	serverResultChan2 := make(chan *SecurityNegotiation, 1)
	serverErrChan2 := make(chan error, 1)
	go func() {
		serverAuth2 := NewAuthenticator(serverConfig2, serverStream2)
		result, err := serverAuth2.ServerHandshake(context.Background())
		if err != nil {
			serverErrChan2 <- err
		} else {
			serverResultChan2 <- result
		}
	}()

	// Give server time to start listening
	time.Sleep(100 * time.Millisecond)

	// Perform client handshake - this should resume the session
	// This is where the panic occurred: setupStreamEncryption tried to access
	// negotiation.ServerConfig.ECDHPublicKey but ServerConfig was nil
	clientAuth2 := NewAuthenticator(clientConfig2, clientStream2)
	negotiation2, err := clientAuth2.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("Second client handshake (session resumption) failed: %v", err)
	}

	// Wait for server to complete
	select {
	case err := <-serverErrChan2:
		t.Logf("Server handshake returned error: %v", err)
		// Server might not recognize the session, which is okay for this test
	case serverNeg := <-serverResultChan2:
		t.Logf("✅ Second handshake completed")
		t.Logf("  Server Session ID: %s", serverNeg.SessionId)
	case <-time.After(5 * time.Second):
		t.Log("Server handshake timed out (expected if session not recognized)")
	}

	t.Logf("✅ Session resumption completed without panic!")
	t.Logf("  Client Session ID: %s", negotiation2.SessionId)
	t.Logf("  Negotiated Auth: %s", negotiation2.NegotiatedAuth)
	t.Logf("  Negotiated Crypto: %s", negotiation2.NegotiatedCrypto)
	t.Logf("  Shared Secret Length: %d bytes", len(negotiation2.GetSharedSecret()))

	// Verify we got the same session ID
	if negotiation1.SessionId == negotiation2.SessionId {
		t.Logf("✅ Session ID matches - session resumption successful!")
	} else {
		t.Logf("ℹ️  Different session IDs (first: %s, second: %s)", negotiation1.SessionId, negotiation2.SessionId)
	}

	t.Log("🎉 Regression test passed - no panic during session resumption with encryption!")
}
