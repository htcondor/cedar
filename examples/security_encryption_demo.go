//go:build ignore

// Package main demonstrates security handshake and encryption
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

func main() {
	fmt.Println("HTCondor CEDAR Security Demo with Encryption")
	fmt.Println("==========================================")

	// Start server in a goroutine
	go runServer()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Run client
	runClient()
}

func runServer() {
	ctx := context.Background()

	// Listen on localhost:8080
	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to listen: %v", err), "destination", "cedar")
	}
	defer func() { _ = listener.Close() }()

	fmt.Println("[SERVER] Listening on localhost:8080...")

	// Accept connection
	conn, err := listener.Accept()
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to accept connection: %v", err), "destination", "cedar")
	}
	defer func() { _ = conn.Close() }()

	fmt.Println("[SERVER] Client connected")

	// Create stream
	serverStream := stream.NewStream(conn)

	// Create security manager
	secManager := security.NewSecurityManager()

	// Perform server-side handshake
	fmt.Println("[SERVER] Starting security handshake...")
	err = secManager.ServerHandshake(ctx, serverStream)
	if err != nil {
		slog.Error(fmt.Sprintf("[SERVER] Handshake failed: %v", err), "destination", "cedar")
	}

	fmt.Println("[SERVER] Security handshake completed successfully!")
	fmt.Printf("[SERVER] Authenticated: %t\n", serverStream.IsAuthenticated())
	fmt.Printf("[SERVER] Encrypted: %t\n", serverStream.IsEncrypted())

	// For demo purposes, let's add actual AES encryption
	// In real HTCondor, this key would be derived from ECDH key exchange
	demoKey := []byte("this-is-a-32-byte-demo-key-12345") // 32 bytes for AES-256
	if err := serverStream.SetSymmetricKey(demoKey); err != nil {
		slog.Error(fmt.Sprintf("[SERVER] Failed to set demo key: %v", err), "destination", "cedar")
	}
	fmt.Printf("[SERVER] Demo encryption enabled: %t\n", serverStream.IsEncrypted())

	// Wait for encrypted message from client
	fmt.Println("[SERVER] Waiting for encrypted message...")
	message, err := serverStream.ReceiveCompleteMessage(ctx)
	if err != nil {
		slog.Error(fmt.Sprintf("[SERVER] Failed to receive message: %v", err), "destination", "cedar")
	}

	fmt.Printf("[SERVER] Received encrypted message: %s\n", string(message))

	// Send encrypted response
	response := []byte("Hello from server! This response is encrypted too. 🔒")
	fmt.Printf("[SERVER] Sending encrypted response: %s\n", string(response))
	err = serverStream.SendMessage(context.Background(), response)
	if err != nil {
		slog.Error(fmt.Sprintf("[SERVER] Failed to send response: %v", err), "destination", "cedar")
	}

	fmt.Println("[SERVER] Demo completed successfully!")
}

func runClient() {
	ctx := context.Background()

	// Connect to server
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to connect: %v", err), "destination", "cedar")
	}
	defer func() { _ = conn.Close() }()

	fmt.Println("[CLIENT] Connected to server")

	// Create stream
	clientStream := stream.NewStream(conn)

	// Create security manager
	secManager := security.NewSecurityManager()

	// Perform client-side handshake
	fmt.Println("[CLIENT] Starting security handshake...")
	err = secManager.ClientHandshake(ctx, clientStream)
	if err != nil {
		slog.Error(fmt.Sprintf("[CLIENT] Handshake failed: %v", err), "destination", "cedar")
	}

	fmt.Println("[CLIENT] Security handshake completed successfully!")
	fmt.Printf("[CLIENT] Authenticated: %t\n", clientStream.IsAuthenticated())
	fmt.Printf("[CLIENT] Encrypted: %t\n", clientStream.IsEncrypted())

	// For demo purposes, let's add actual AES encryption
	// In real HTCondor, this key would be derived from ECDH key exchange
	demoKey := []byte("this-is-a-32-byte-demo-key-12345") // 32 bytes for AES-256
	if err := clientStream.SetSymmetricKey(demoKey); err != nil {
		slog.Error(fmt.Sprintf("[CLIENT] Failed to set demo key: %v", err), "destination", "cedar")
	}
	fmt.Printf("[CLIENT] Demo encryption enabled: %t\n", clientStream.IsEncrypted())

	// Send encrypted message
	message := []byte("Hello from client! This message is encrypted. 🚀")
	fmt.Printf("[CLIENT] Sending encrypted message: %s\n", string(message))
	err = clientStream.SendMessage(ctx, message)
	if err != nil {
		slog.Error(fmt.Sprintf("[CLIENT] Failed to send message: %v", err), "destination", "cedar")
	}

	// Receive encrypted response
	fmt.Println("[CLIENT] Waiting for encrypted response...")
	response, err := clientStream.ReceiveCompleteMessage(ctx)
	if err != nil {
		slog.Error(fmt.Sprintf("[CLIENT] Failed to receive response: %v", err), "destination", "cedar")
	}

	fmt.Printf("[CLIENT] Received encrypted response: %s\n", string(response))
	fmt.Println("[CLIENT] Demo completed successfully!")
}
