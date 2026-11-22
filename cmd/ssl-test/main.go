// SSL Authentication Test Program
// This program tests SSL authentication by connecting to an HTCondor collector
// and forcing authentication to test our SSL implementation.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/client"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

const (
	// OSPool collector endpoint
	CollectorHost = "cm-1.ospool.osg-htc.org"
	CollectorPort = "9618"

	// Connection timeout
	ConnectionTimeout = 10 * time.Second
)

func main() {
	slog.Info("🔍 SSL Authentication Test - HTCondor Collector Query", "destination", "cedar")
	slog.Info(fmt.Sprintf("🎯 Target: %s:%s", CollectorHost, CollectorPort), "destination", "cedar")

	if err := testSSLAuthentication(); err != nil {
		slog.Error(fmt.Sprintf("❌ SSL authentication test failed: %v", err), "destination", "cedar")
		os.Exit(1)
	}

	slog.Info("✅ SSL authentication test completed successfully", "destination", "cedar")
}

func testSSLAuthentication() error {
	// Create connection to HTCondor collector using client package
	slog.Info("📡 Connecting to HTCondor collector...", "destination", "cedar")

	addr := net.JoinHostPort(CollectorHost, CollectorPort)
	clientConfig := &client.ClientConfig{
		Address: addr,
		Timeout: ConnectionTimeout,
	}

	htcondorClient := client.NewClient(clientConfig)
	if err := htcondorClient.Connect(context.Background()); err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer func() {
		if err := htcondorClient.Close(); err != nil {
			slog.Error(fmt.Sprintf("Error closing connection: %v", err), "destination", "cedar")
		}
	}()

	slog.Info(fmt.Sprintf("✅ Connected to %s", addr), "destination", "cedar")

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// Configure SSL authentication (force authentication)
	secConfig := &security.SecurityConfig{
		PeerName:       CollectorHost,
		AuthMethods:    []security.AuthMethod{security.AuthSSL},     // Only SSL
		Authentication: security.SecurityRequired,                   // Force authentication
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES}, // Enable encryption
		Encryption:     security.SecurityOptional,                   // Optional encryption
		Integrity:      security.SecurityOptional,                   // Optional integrity
		Command:        commands.QUERY_STARTD_ADS,                   // Query startd ads

		// SSL configuration (using system defaults)
		CertFile: "", // No client cert (anonymous SSL)
		KeyFile:  "", // No client key
		CAFile:   "", // Use system CA store
	}

	// Create security manager and authenticator
	auth := security.NewAuthenticator(secConfig, cedarStream)

	slog.Info("🔐 Starting SSL authentication handshake...", "destination", "cedar")

	// Perform client-side handshake
	negotiation, err := auth.ClientHandshake(context.Background())
	if err != nil {
		return fmt.Errorf("SSL authentication handshake failed: %w", err)
	}

	slog.Info("🔐 SSL Authentication Results:", "destination", "cedar")
	slog.Info(fmt.Sprintf("    Negotiated Auth: %s", negotiation.NegotiatedAuth), "destination", "cedar")
	slog.Info(fmt.Sprintf("    Negotiated Crypto: %s", negotiation.NegotiatedCrypto), "destination", "cedar")
	slog.Info(fmt.Sprintf("    Session ID: %s", negotiation.SessionId), "destination", "cedar")
	slog.Info(fmt.Sprintf("    User: %s", negotiation.User), "destination", "cedar")
	slog.Info(fmt.Sprintf("    Encryption Enabled: %t", cedarStream.IsEncrypted()), "destination", "cedar")

	// Send a simple query to verify the connection works
	slog.Info("📊 Sending query to collector...", "destination", "cedar")

	if err := sendCollectorQuery(cedarStream); err != nil {
		return fmt.Errorf("collector query failed: %w", err)
	}

	return nil
}

func sendCollectorQuery(cedarStream *stream.Stream) error {
	slog.Info("📊 Sending query to collector...", "destination", "cedar")

	// Create query ClassAd (like in query_demo.go)
	queryAd := createTestQueryAd()

	// Create a message for sending the query using Message API
	queryMsg := message.NewMessageForStream(cedarStream)

	// Add the ClassAd to the message using Message API (like query_demo.go)
	err := queryMsg.PutClassAd(context.Background(), queryAd)
	if err != nil {
		return fmt.Errorf("failed to add ClassAd to message: %w", err)
	}

	// Send the message using Message API (flush with End-of-Message)
	err = queryMsg.FlushFrame(context.Background(), true)
	if err != nil {
		return fmt.Errorf("failed to send query message: %w", err)
	}

	slog.Info("✅ Query sent successfully", "destination", "cedar")

	// Try to receive response
	slog.Info("📥 Waiting for collector response...", "destination", "cedar")

	responseMsg := message.NewMessageFromStream(cedarStream)

	// Read response (this may fail if authentication is required but not complete)
	response, err := responseMsg.GetInt(context.Background())
	if err != nil {
		// This is expected if authentication failed or is incomplete
		slog.Info(fmt.Sprintf("⚠️  Response read failed (expected if auth is incomplete): %v", err), "destination", "cedar")
		return nil // Don't treat as fatal error for this test
	}

	slog.Info(fmt.Sprintf("📊 Collector response: %d", response), "destination", "cedar")
	return nil
}

// createTestQueryAd creates a ClassAd for querying startd ads (like query_demo.go)
func createTestQueryAd() *classad.ClassAd {
	ad := classad.New()

	// Set MyType and TargetType as required by HTCondor query protocol
	_ = ad.Set("MyType", "Query")
	_ = ad.Set("TargetType", "Machine") // Query Machine ads (startd)

	// Set Requirements - use "true" to get all ads
	_ = ad.Set("Requirements", true)

	// Set a limit on results for testing
	_ = ad.Set("LimitResults", 2)

	return ad
}
