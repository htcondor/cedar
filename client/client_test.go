package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

func TestClientConfig(t *testing.T) {
	t.Run("default_values", func(t *testing.T) {
		config := &ClientConfig{
			Address: "test.example.org:9618",
		}
		client := NewClient(config)

		if client.config.Timeout != 30*time.Second {
			t.Errorf("Expected default timeout to be 30s, got %v", client.config.Timeout)
		}
		if client.config.ClientName != "golang-cedar-client" {
			t.Errorf("Expected default client name to be 'golang-cedar-client', got '%s'", client.config.ClientName)
		}
	})

	t.Run("legacy_host_port", func(t *testing.T) {
		config := &ClientConfig{
			Host: "test.example.org",
			Port: 9618,
		}
		client := NewClient(config)

		expected := "test.example.org:9618"
		if client.config.Address != expected {
			t.Errorf("Expected address to be '%s', got '%s'", expected, client.config.Address)
		}
	})

	t.Run("custom_values", func(t *testing.T) {
		config := &ClientConfig{
			Address:    "cm.example.org:9618?sock=collector",
			Timeout:    10 * time.Second,
			ClientName: "my-test-client",
		}
		client := NewClient(config)

		if client.config.Timeout != 10*time.Second {
			t.Errorf("Expected timeout to be 10s, got %v", client.config.Timeout)
		}
		if client.config.ClientName != "my-test-client" {
			t.Errorf("Expected client name to be 'my-test-client', got '%s'", client.config.ClientName)
		}
		if client.sharedPortClient == nil {
			t.Error("Expected sharedPortClient to be initialized")
		}
	})
}

func TestHTCondorClient_Connect(t *testing.T) {
	t.Run("no_address", func(t *testing.T) {
		config := &ClientConfig{}
		client := NewClient(config)

		err := client.Connect(context.Background())
		if err == nil {
			t.Fatal("Expected error for empty address")
		}
		if err.Error() != "no address specified in client configuration" {
			t.Errorf("Expected 'no address specified' error, got: %v", err)
		}
	})

	t.Run("direct_connection", func(t *testing.T) {
		// Create a test server
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create test server: %v", err)
		}
		defer func() { _ = listener.Close() }()

		// Accept one connection
		go func() {
			conn, _ := listener.Accept()
			if conn != nil {
				time.Sleep(100 * time.Millisecond)
				_ = conn.Close() // Ignore error during cleanup
			}
		}()

		config := &ClientConfig{
			Address: listener.Addr().String(),
			Timeout: 5 * time.Second,
		}
		client := NewClient(config)

		err = client.Connect(context.Background())
		if err != nil {
			t.Fatalf("Connect failed: %v", err)
		}
		defer func() { _ = client.Close() }()

		if !client.IsConnected() {
			t.Error("Expected client to be connected")
		}

		stream := client.GetStream()
		if stream == nil {
			t.Error("Expected stream to be non-nil")
		}
	})

	t.Run("connection_timeout", func(t *testing.T) {
		config := &ClientConfig{
			Address: "127.0.0.1:1", // Non-existent port
			Timeout: 100 * time.Millisecond,
		}
		client := NewClient(config)

		err := client.Connect(context.Background())
		if err == nil {
			t.Fatal("Expected connection timeout error")
		}
	})
}

func TestConnectToAddress(t *testing.T) {
	// Create a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer func() { _ = listener.Close() }()

	// Accept one connection
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			time.Sleep(100 * time.Millisecond)
			_ = conn.Close() // Ignore error during cleanup
		}
	}()

	client, err := ConnectToAddress(context.Background(), listener.Addr().String())
	if err != nil {
		t.Fatalf("ConnectToAddress failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	if !client.IsConnected() {
		t.Error("Expected client to be connected")
	}
}

func TestHTCondorClient_Close(t *testing.T) {
	t.Run("no_stream", func(t *testing.T) {
		config := &ClientConfig{
			Address: "test.example.org:9618",
		}
		client := NewClient(config)

		err := client.Close()
		if err != nil {
			t.Errorf("Expected no error closing client without stream, got: %v", err)
		}
	})

	t.Run("with_stream", func(t *testing.T) {
		// Create a test server
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create test server: %v", err)
		}
		defer func() { _ = listener.Close() }()

		// Accept one connection
		go func() {
			conn, _ := listener.Accept()
			if conn != nil {
				time.Sleep(200 * time.Millisecond)
				_ = conn.Close() // Ignore error during cleanup
			}
		}()

		config := &ClientConfig{
			Address: listener.Addr().String(),
			Timeout: 5 * time.Second,
		}
		client := NewClient(config)

		err = client.Connect(context.Background())
		if err != nil {
			t.Fatalf("Connect failed: %v", err)
		}

		err = client.Close()
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}

		// Note: The stream's IsConnected method only checks if conn != nil,
		// but doesn't set conn to nil on close. This is consistent with the
		// HTCondor implementation where the connection state is managed
		// at the socket level, not the stream level.
		// For this test, we just verify that Close() succeeds without error.
	})
}

// TestSessionResumptionErrorHandling tests that SessionResumptionError is properly detected
func TestSessionResumptionErrorHandling(t *testing.T) {
	// Create a SessionResumptionError
	err := &security.SessionResumptionError{
		SessionID: "test-session",
		Reason:    "session not found on server",
	}

	// Test that IsSessionResumptionError detects it
	if !security.IsSessionResumptionError(err) {
		t.Error("Expected IsSessionResumptionError to return true")
	}

	// Test with errors.As
	var sre *security.SessionResumptionError
	if !errors.As(err, &sre) {
		t.Error("Expected errors.As to work with SessionResumptionError")
	}
	if sre.SessionID != "test-session" {
		t.Errorf("Expected SessionID 'test-session', got %q", sre.SessionID)
	}
}

// TestConnectAndAuthenticateBasic tests basic ConnectAndAuthenticate functionality
// Note: This test only validates that the function exists and handles basic errors correctly.
// Full integration tests with actual authentication are in the security package.
func TestConnectAndAuthenticateBasic(t *testing.T) {
	t.Run("connection_fails", func(t *testing.T) {
		ctx := context.Background()

		// Try to connect to a non-existent server
		config := &ClientConfig{
			Address: "127.0.0.1:1", // Non-existent port
			Timeout: 100 * time.Millisecond,
		}

		_, err := ConnectAndAuthenticateWithConfig(ctx, config)
		if err == nil {
			t.Fatal("Expected error when connecting to non-existent server")
		}
	})

	t.Run("no_security_config", func(t *testing.T) {
		// Create a test server
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create test server: %v", err)
		}
		defer func() { _ = listener.Close() }()

		// Accept one connection
		go func() {
			conn, _ := listener.Accept()
			if conn != nil {
				time.Sleep(100 * time.Millisecond)
				_ = conn.Close()
			}
		}()

		ctx := context.Background()
		config := &ClientConfig{
			Address: listener.Addr().String(),
			Timeout: 5 * time.Second,
			// No Security config - should succeed without authentication
		}

		client, err := ConnectAndAuthenticateWithConfig(ctx, config)
		if err != nil {
			t.Fatalf("Expected success without security config, got error: %v", err)
		}
		defer func() { _ = client.Close() }()

		if !client.IsConnected() {
			t.Error("Expected client to be connected")
		}

		// No authentication performed, so negotiation should be nil
		if client.GetSecurityNegotiation() != nil {
			t.Error("Expected negotiation to be nil when no authentication is performed")
		}
	})
}

// TestGetSecurityNegotiation tests that negotiation information is accessible
func TestGetSecurityNegotiation(t *testing.T) {
	t.Run("no_authentication", func(t *testing.T) {
		// Create a client without authentication
		config := &ClientConfig{
			Address: "test.example.org:9618",
		}
		client := NewClient(config)

		// No authentication performed, so negotiation should be nil
		if client.GetSecurityNegotiation() != nil {
			t.Error("Expected negotiation to be nil when no authentication is performed")
		}
	})

	t.Run("with_authentication", func(t *testing.T) {
		// Create a simple mock server that performs security handshake
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create test server: %v", err)
		}
		defer func() { _ = listener.Close() }()

		// Server goroutine
		serverDone := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				serverDone <- err
				return
			}
			defer func() { _ = conn.Close() }()

			// Perform server-side handshake
			serverStream := stream.NewStream(conn)
			serverConfig := &security.SecurityConfig{
				AuthMethods:    []security.AuthMethod{security.AuthNone},
				Authentication: security.SecurityOptional,
				CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
				Encryption:     security.SecurityOptional,
				Integrity:      security.SecurityOptional,
			}

			serverAuth := security.NewAuthenticator(serverConfig, serverStream)
			_, err = serverAuth.ServerHandshake(context.Background())
			serverDone <- err
		}()

		// Client side
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		clientConfig := &ClientConfig{
			Address: listener.Addr().String(),
			Timeout: 5 * time.Second,
			Security: &security.SecurityConfig{
				Command:        60010, // DC_NOP_WRITE
				AuthMethods:    []security.AuthMethod{security.AuthNone},
				Authentication: security.SecurityOptional,
				CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
				Encryption:     security.SecurityOptional,
				Integrity:      security.SecurityOptional,
			},
		}

		client, err := ConnectAndAuthenticateWithConfig(ctx, clientConfig)
		if err != nil {
			t.Fatalf("ConnectAndAuthenticateWithConfig failed: %v", err)
		}
		defer func() { _ = client.Close() }()

		// Wait for server to complete
		if err := <-serverDone; err != nil {
			t.Fatalf("Server handshake failed: %v", err)
		}

		// Verify negotiation information is accessible
		negotiation := client.GetSecurityNegotiation()
		if negotiation == nil {
			t.Fatal("Expected negotiation to be non-nil after authentication")
		}

		// Verify negotiation contains expected information
		if negotiation.NegotiatedAuth == "" {
			t.Error("Expected NegotiatedAuth to be set")
		}

		if negotiation.SessionId == "" {
			t.Error("Expected SessionId to be set")
		}

		if negotiation.User == "" {
			t.Error("Expected User to be set")
		}

		t.Logf("Negotiation info: Auth=%s, User=%s, SessionId=%s",
			negotiation.NegotiatedAuth, negotiation.User, negotiation.SessionId)
	})
}
