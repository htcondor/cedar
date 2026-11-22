package sharedport

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

func TestIsValidSharedPortID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"startd", true},
		{"schedd", true},
		{"collector", true},
		{"negotiator", true},
		{"shared-port", true},
		{"test_daemon", true},
		{"daemon.123", true},
		{"", false},
		{"bad/path", false},
		{"bad\\path", false},
		{"bad space", false},
		{"bad|pipe", false},
		{"bad;semicolon", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			result := addresses.IsValidSharedPortID(tt.id)
			if result != tt.valid {
				t.Errorf("IsValidSharedPortID(%q) = %v, want %v", tt.id, result, tt.valid)
			}
		})
	}
}

func TestParseHTCondorAddress(t *testing.T) {
	tests := []struct {
		address        string
		expectedAddr   string
		expectedID     string
		expectedShared bool
	}{
		{
			address:        "192.168.1.100:9618?sock=startd",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "startd",
			expectedShared: true,
		},
		{
			address:        "<192.168.1.100:9618?sock=schedd>",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "schedd",
			expectedShared: true,
		},
		{
			address:        "192.168.1.100:9618?sock=collector&timeout=30",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "collector",
			expectedShared: true,
		},
		{
			address:        "192.168.1.100:9618",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "",
			expectedShared: false,
		},
		{
			address:        "<192.168.1.100:9618>",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "",
			expectedShared: false,
		},
		// Advanced test cases with multiple query parameters
		{
			address:        "127.0.0.1:9618?addrs=127.0.0.1-9618&sock=schedd_123_abc",
			expectedAddr:   "127.0.0.1:9618",
			expectedID:     "schedd_123_abc",
			expectedShared: true,
		},
		{
			address:        "<127.0.0.1:60720?addrs=127.0.0.1-60720&alias=host&noUDP&sock=schedd_45461_0b0e>",
			expectedAddr:   "127.0.0.1:60720",
			expectedID:     "schedd_45461_0b0e",
			expectedShared: true,
		},
		{
			address:        "cm.example.org:9618?timeout=30&sock=negotiator&retry=3",
			expectedAddr:   "cm.example.org:9618",
			expectedID:     "negotiator",
			expectedShared: true,
		},
		{
			address:        "192.168.1.100:9618?sock=negotiator?other=param",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "negotiator",
			expectedShared: true,
		},
		{
			address:        "cm.example.org:9618?sock=startd",
			expectedAddr:   "cm.example.org:9618",
			expectedID:     "startd",
			expectedShared: true,
		},
		{
			address:        "<172.20.10.2:9618?addrs=172.20.10.2-9618+[2600-1008-b1c5-ba50-1c57-ed5-2ddd-a4d1]-9618&alias=f4hp7ql65f-2.local&noUDP&sock=schedd_43621_f4cb>",
			expectedAddr:   "172.20.10.2:9618",
			expectedID:     "schedd_43621_f4cb",
			expectedShared: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			addrInfo := addresses.ParseHTCondorAddress(tt.address)
			if addrInfo.ServerAddr != tt.expectedAddr {
				t.Errorf("ParseHTCondorAddress(%q).ServerAddr = %q, want %q", tt.address, addrInfo.ServerAddr, tt.expectedAddr)
			}
			if addrInfo.SharedPortID != tt.expectedID {
				t.Errorf("ParseHTCondorAddress(%q).SharedPortID = %q, want %q", tt.address, addrInfo.SharedPortID, tt.expectedID)
			}
			if addrInfo.IsSharedPort != tt.expectedShared {
				t.Errorf("ParseHTCondorAddress(%q).IsSharedPort = %v, want %v", tt.address, addrInfo.IsSharedPort, tt.expectedShared)
			}
		})
	}
}

// MockSharedPortServer simulates a shared port server for testing
type MockSharedPortServer struct {
	listener  net.Listener
	address   string
	responses map[string]func(net.Conn) error
	t         *testing.T
	// wg tracks the serve loop and every per-connection handler so
	// Close can join them. Without it a handler goroutine can call
	// m.t.Logf after the test function has returned -- a data race on
	// the testing.common the race detector flags as "log after test
	// completed".
	wg sync.WaitGroup
}

func NewMockSharedPortServer(t *testing.T) (*MockSharedPortServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	server := &MockSharedPortServer{
		listener:  listener,
		address:   listener.Addr().String(),
		responses: make(map[string]func(net.Conn) error),
		t:         t,
	}

	server.wg.Add(1)
	go server.serve()
	return server, nil
}

func (m *MockSharedPortServer) serve() {
	defer m.wg.Done()
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			return // Server closed
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.handleConnection(conn)
		}()
	}
}

func (m *MockSharedPortServer) handleConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	s := stream.NewStream(conn)
	msg := message.NewMessageFromStream(s)
	ctx := context.Background()

	// Read the shared port request
	cmd, err := msg.GetInt32(ctx)
	if err != nil {
		m.t.Logf("Failed to read command: %v", err)
		return
	}

	if cmd != int32(commands.SHARED_PORT_CONNECT) {
		m.t.Logf("Unexpected command: %d", cmd)
		return
	}

	sharedPortID, err := msg.GetString(ctx)
	if err != nil {
		m.t.Logf("Failed to read shared port ID: %v", err)
		return
	}

	clientName, err := msg.GetString(ctx)
	if err != nil {
		m.t.Logf("Failed to read client name: %v", err)
		return
	}

	deadline, err := msg.GetInt64(ctx)
	if err != nil {
		m.t.Logf("Failed to read deadline: %v", err)
		return
	}

	moreArgs, err := msg.GetInt32(ctx)
	if err != nil {
		m.t.Logf("Failed to read more args: %v", err)
		return
	}

	m.t.Logf("Received shared port request: ID=%s, Client=%s, Deadline=%d, MoreArgs=%d",
		sharedPortID, clientName, deadline, moreArgs)

	// Call the registered response handler if available
	if handler, exists := m.responses[sharedPortID]; exists {
		if err := handler(conn); err != nil {
			m.t.Logf("Handler error: %v", err)
		}
	}
}

func (m *MockSharedPortServer) Address() string {
	return m.address
}

func (m *MockSharedPortServer) RegisterResponse(sharedPortID string, handler func(net.Conn) error) {
	m.responses[sharedPortID] = handler
}

func (m *MockSharedPortServer) Close() error {
	// Close the listener first so serve's Accept returns, then wait for
	// the serve loop and any in-flight handlers to finish before the
	// test returns -- otherwise a late m.t.Logf races the test's end.
	err := m.listener.Close()
	m.wg.Wait()
	return err
}

func TestSharedPortClient_ConnectViaSharedPort(t *testing.T) {
	// Start mock shared port server
	server, err := NewMockSharedPortServer(t)
	if err != nil {
		t.Fatalf("Failed to create mock server: %v", err)
	}
	defer func() { _ = server.Close() }()

	// Register a simple echo response for the "testdaemon" ID
	server.RegisterResponse("testdaemon", func(conn net.Conn) error {
		// For this test, we just keep the connection open
		// In a real scenario, this would be the target daemon's response
		time.Sleep(100 * time.Millisecond)
		return nil
	})

	// Create shared port client
	client := NewSharedPortClient("test-client")

	// Test successful connection
	t.Run("successful_connection", func(t *testing.T) {
		stream, err := client.ConnectViaSharedPort(context.Background(), server.Address(), "testdaemon", 5*time.Second)
		if err != nil {
			t.Fatalf("ConnectViaSharedPort failed: %v", err)
		}
		defer func() { _ = stream.Close() }()

		if stream == nil {
			t.Fatal("Expected stream to be non-nil")
		}
	})

	// Test invalid shared port ID
	t.Run("invalid_shared_port_id", func(t *testing.T) {
		_, err := client.ConnectViaSharedPort(context.Background(), server.Address(), "invalid/id", 5*time.Second)
		if err == nil {
			t.Fatal("Expected error for invalid shared port ID")
		}
		if !strings.Contains(fmt.Sprintf("%v", err), "invalid shared port ID") {
			t.Errorf("Expected 'invalid shared port ID' error, got: %v", err)
		}
	})

	// Test connection timeout
	t.Run("connection_timeout", func(t *testing.T) {
		_, err := client.ConnectViaSharedPort(context.Background(), "127.0.0.1:1", "testdaemon", 100*time.Millisecond)
		if err == nil {
			t.Fatal("Expected error for connection timeout")
		}
	})
}

func TestSharedPortClient_ConnectToHTCondorAddress(t *testing.T) {
	// Start mock shared port server
	server, err := NewMockSharedPortServer(t)
	if err != nil {
		t.Fatalf("Failed to create mock server: %v", err)
	}
	defer func() { _ = server.Close() }()

	// Register a simple response for the "testdaemon" ID
	server.RegisterResponse("testdaemon", func(conn net.Conn) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	})

	client := NewSharedPortClient("test-client")

	t.Run("shared_port_address", func(t *testing.T) {
		address := server.Address() + "?sock=testdaemon"
		stream, err := client.ConnectToHTCondorAddress(context.Background(), address, 5*time.Second)
		if err != nil {
			t.Fatalf("ConnectToHTCondorAddress failed: %v", err)
		}
		defer func() { _ = stream.Close() }()

		if stream == nil {
			t.Fatal("Expected stream to be non-nil")
		}
	})

	t.Run("regular_address", func(t *testing.T) {
		// Create a simple TCP server for regular connection
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create listener: %v", err)
		}
		defer func() { _ = listener.Close() }()

		go func() {
			conn, _ := listener.Accept()
			if conn != nil {
				time.Sleep(100 * time.Millisecond)
				_ = conn.Close() // Ignore error during cleanup
			}
		}()

		stream, err := client.ConnectToHTCondorAddress(context.Background(), listener.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("ConnectToHTCondorAddress failed: %v", err)
		}
		defer func() { _ = stream.Close() }()

		if stream == nil {
			t.Fatal("Expected stream to be non-nil")
		}
	})
}

func TestSharedPortClient_NewClient(t *testing.T) {
	t.Run("with_name", func(t *testing.T) {
		client := NewSharedPortClient("my-client")
		if client.clientName != "my-client" {
			t.Errorf("Expected client name 'my-client', got '%s'", client.clientName)
		}
	})

	t.Run("empty_name", func(t *testing.T) {
		client := NewSharedPortClient("")
		if client.clientName != "golang-cedar-client" {
			t.Errorf("Expected default client name 'golang-cedar-client', got '%s'", client.clientName)
		}
	})
}
