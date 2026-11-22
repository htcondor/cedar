// This test file is in a separate package to test the shared port + security handshake integration
package sharedport_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/htcondor/cedar/client/sharedport"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// TestSharedPortWithSecurityHandshake tests that the security handshake succeeds
// after a shared port handoff. This is a regression test to ensure that stream
// state is properly reset after the shared port server reads the initial request.
func TestSharedPortWithSecurityHandshake(t *testing.T) {
	// Generate valid ECDH key pairs for client and server
	clientPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	serverPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}

	// Encode public keys as base64 DER
	clientPublicDER, err := x509.MarshalPKIXPublicKey(clientPrivate.PublicKey())
	if err != nil {
		t.Fatalf("Failed to marshal client public key: %v", err)
	}
	clientPublicB64 := base64.StdEncoding.EncodeToString(clientPublicDER)

	serverPublicDER, err := x509.MarshalPKIXPublicKey(serverPrivate.PublicKey())
	if err != nil {
		t.Fatalf("Failed to marshal server public key: %v", err)
	}
	serverPublicB64 := base64.StdEncoding.EncodeToString(serverPublicDER)

	// Create a mock shared port server that simulates the handoff
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	sharedPortAddr := listener.Addr().String()
	t.Logf("Mock shared port server listening at: %s", sharedPortAddr)

	// Channel to signal when the server is ready for security handshake
	serverReady := make(chan *stream.Stream, 1)
	serverError := make(chan error, 1)

	// Start the mock shared port server
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverError <- err
			return
		}

		// Simulate shared port server behavior
		serverStream := stream.NewStream(conn)
		msg := message.NewMessageFromStream(serverStream)
		ctx := context.Background()

		// Read the shared port request (this is what the shared port server does)
		cmd, err := msg.GetInt32(ctx)
		if err != nil {
			serverError <- err
			return
		}

		if cmd != int32(commands.SHARED_PORT_CONNECT) {
			t.Errorf("Unexpected command: %d (expected %d)", cmd, commands.SHARED_PORT_CONNECT)
			serverError <- err
			return
		}

		sharedPortID, err := msg.GetString(ctx)
		if err != nil {
			serverError <- err
			return
		}

		clientName, err := msg.GetString(ctx)
		if err != nil {
			serverError <- err
			return
		}

		deadline, err := msg.GetInt64(ctx)
		if err != nil {
			serverError <- err
			return
		}

		moreArgs, err := msg.GetInt32(ctx)
		if err != nil {
			serverError <- err
			return
		}

		t.Logf("Shared port request received: ID=%s, Client=%s, Deadline=%d, MoreArgs=%d",
			sharedPortID, clientName, deadline, moreArgs)

		// CRITICAL: Reset the stream state to simulate handoff to the actual daemon
		// This is what the shared port server does before handing the connection
		// to the target daemon. The stream needs to be reset so the security
		// handshake starts with a clean state.
		//
		// In HTCondor, the shared port server forwards the raw socket to the target
		// daemon, which then creates a fresh ReliSock/Cedar stream on it.
		// We simulate this by creating a new stream from the same connection.
		//
		// REGRESSION NOTE: Without this reset, the security handshake would fail
		// because the stream would still have state from reading the shared port
		// request (buffered data, frame state, etc.), causing the client's security
		// ClassAd to be misinterpreted or corrupted.
		serverStream = stream.NewStream(conn)

		// Signal that the server is ready for security handshake
		serverReady <- serverStream
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Client side: Connect via shared port
	sharedPortClient := sharedport.NewSharedPortClient("test-client")
	clientStream, err := sharedPortClient.ConnectViaSharedPort(
		context.Background(),
		sharedPortAddr,
		"testdaemon",
		10*time.Second,
	)
	if err != nil {
		t.Fatalf("Failed to connect via shared port: %v", err)
	}
	defer func() { _ = clientStream.Close() }()

	t.Logf("Client connected via shared port")

	// Wait for server to be ready
	var serverStream *stream.Stream
	select {
	case serverStream = <-serverReady:
		t.Logf("Server ready for security handshake")
	case err := <-serverError:
		t.Fatalf("Server error during shared port handling: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for server to be ready")
	}

	// Now perform the security handshake
	// Client configuration
	clientConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthClaimToBe},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		ECDHPublicKey:  clientPublicB64,
		Command:        commands.DC_NOP,
	}

	// Server configuration
	serverConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthClaimToBe},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		ECDHPublicKey:  serverPublicB64,
	}

	// Create authenticators
	clientAuth := security.NewAuthenticator(clientConfig, clientStream)
	serverAuth := security.NewAuthenticator(serverConfig, serverStream)

	// Channel for server handshake results
	serverHandshakeResult := make(chan *security.SecurityNegotiation, 1)
	serverHandshakeError := make(chan error, 1)

	// Start server handshake in a goroutine
	go func() {
		result, err := serverAuth.ServerHandshake(context.Background())
		if err != nil {
			serverHandshakeError <- err
		} else {
			serverHandshakeResult <- result
		}
	}()

	// Give server time to start listening
	time.Sleep(50 * time.Millisecond)

	// Perform client handshake
	t.Logf("Starting client security handshake")
	clientNegotiation, err := clientAuth.ClientHandshake(context.Background())
	if err != nil {
		t.Fatalf("Client security handshake failed: %v", err)
	}

	t.Logf("Client handshake completed successfully")
	t.Logf("  Negotiated Auth: %s", clientNegotiation.NegotiatedAuth)
	t.Logf("  Negotiated Crypto: %s", clientNegotiation.NegotiatedCrypto)
	t.Logf("  User: %s", clientNegotiation.User)

	// Wait for server handshake result
	var serverNegotiation *security.SecurityNegotiation
	select {
	case result := <-serverHandshakeResult:
		serverNegotiation = result
		t.Logf("Server handshake completed successfully")
	case err := <-serverHandshakeError:
		t.Fatalf("Server security handshake failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for server handshake to complete")
	}

	// Verify that both sides agree on the negotiation
	if clientNegotiation.NegotiatedAuth != serverNegotiation.NegotiatedAuth {
		t.Errorf("Auth method mismatch: client=%s, server=%s",
			clientNegotiation.NegotiatedAuth, serverNegotiation.NegotiatedAuth)
	}

	if clientNegotiation.NegotiatedCrypto != serverNegotiation.NegotiatedCrypto {
		t.Errorf("Crypto method mismatch: client=%s, server=%s",
			clientNegotiation.NegotiatedCrypto, serverNegotiation.NegotiatedCrypto)
	}

	t.Logf("✅ Shared port + security handshake test completed successfully")
}
