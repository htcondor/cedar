// Token Authentication Query Test Program
// This program tests TOKEN authentication by connecting to an HTCondor collector
// and querying for startd ads using token-based authentication.
//
// Usage:
//   go run main.go [--token-file <path>] [--token-dir <path>]
//
// Environment variables:
//   TOKEN_FILE - Path to token file (alternative to --token-file)
//   TOKEN_DIR  - Path to token directory (alternative to --token-dir)
//
// The program will:
// 1. Connect to the OSPool collector
// 2. Perform TOKEN authentication
// 3. Query for startd ads
// 4. Display results

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
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

	// OSPool trust domain (use flock.opensciencegrid.org for OSPool)
	TrustDomain = "flock.opensciencegrid.org"
)

var (
	tokenFile = flag.String("token-file", "", "Path to token file")
	tokenDir  = flag.String("token-dir", "", "Path to token directory")
	verbose   = flag.Bool("verbose", false, "Enable verbose output")
	limit     = flag.Int("limit", 5, "Maximum number of results to display")
)

func main() {
	flag.Parse()

	slog.Info("🔍 TOKEN Authentication Query Test - HTCondor Collector", "destination", "cedar")
	slog.Info(fmt.Sprintf("🎯 Target: %s:%s", CollectorHost, CollectorPort), "destination", "cedar")

	// Get token configuration
	tokenFilePath := *tokenFile
	if tokenFilePath == "" {
		tokenFilePath = os.Getenv("TOKEN_FILE")
	}

	tokenDirPath := *tokenDir
	if tokenDirPath == "" {
		tokenDirPath = os.Getenv("TOKEN_DIR")
	}
	// Default to standard HTCondor token directory if not specified
	if tokenDirPath == "" && tokenFilePath == "" {
		tokenDirPath = os.Getenv("HOME") + "/.condor/tokens.d"
	}

	if tokenFilePath == "" && tokenDirPath == "" {
		slog.Info("❌ No token file or directory specified", "destination", "cedar")
		slog.Info("   Use --token-file or --token-dir, or set TOKEN_FILE/TOKEN_DIR environment variables", "destination", "cedar")
		os.Exit(1)
	}

	slog.Info("🔑 Token configuration:", "destination", "cedar")
	if tokenFilePath != "" {
		slog.Info(fmt.Sprintf("   Token file: %s", tokenFilePath), "destination", "cedar")
	}
	if tokenDirPath != "" {
		slog.Info(fmt.Sprintf("   Token directory: %s", tokenDirPath), "destination", "cedar")
	}

	if err := performTokenQuery(tokenFilePath, tokenDirPath); err != nil {
		slog.Info(fmt.Sprintf("❌ Token authentication query failed: %v", err), "destination", "cedar")
		os.Exit(1)
	}

	slog.Info("✅ Token authentication query completed successfully", "destination", "cedar")
}

func performTokenQuery(tokenFile, tokenDir string) error {
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
			slog.Info(fmt.Sprintf("Error closing connection: %v", err), "destination", "cedar")
		}
	}()

	slog.Info(fmt.Sprintf("✅ Connected to %s", addr), "destination", "cedar")

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// Configure TOKEN authentication (force authentication)
	secConfig := &security.SecurityConfig{
		PeerName:       CollectorHost,
		AuthMethods:    []security.AuthMethod{security.AuthToken}, // Only TOKEN
		Authentication: security.SecurityRequired,                 // Force authentication
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional, // Optional encryption
		Integrity:      security.SecurityOptional, // Optional integrity
		Command:        commands.QUERY_STARTD_ADS, // Query startd ads
		TrustDomain:    TrustDomain,               // OSPool trust domain

		// Token configuration
		TokenFile: tokenFile,
		TokenDir:  tokenDir,
	}

	// Create security manager and authenticator
	auth := security.NewAuthenticator(secConfig, cedarStream)

	slog.Info("🔐 Starting TOKEN authentication handshake...", "destination", "cedar")

	// Perform client-side handshake
	negotiation, err := auth.ClientHandshake(context.Background())
	if err != nil {
		return fmt.Errorf("TOKEN authentication handshake failed: %w", err)
	}

	slog.Info("🔐 TOKEN Authentication Results:", "destination", "cedar")
	slog.Info(fmt.Sprintf("    Negotiated Auth: %s", negotiation.NegotiatedAuth), "destination", "cedar")
	slog.Info(fmt.Sprintf("    Negotiated Crypto: %s", negotiation.NegotiatedCrypto), "destination", "cedar")
	slog.Info(fmt.Sprintf("    Session ID: %s", negotiation.SessionId), "destination", "cedar")
	slog.Info(fmt.Sprintf("    User: %s", negotiation.User), "destination", "cedar")
	slog.Info(fmt.Sprintf("    Encryption Enabled: %t", cedarStream.IsEncrypted()), "destination", "cedar")

	// Mark stream as authenticated
	cedarStream.SetAuthenticated(true)

	// Send query for startd ads
	slog.Info("📊 Sending QUERY_STARTD_ADS query...", "destination", "cedar")

	if err := sendStartdQuery(cedarStream); err != nil {
		return fmt.Errorf("startd query failed: %w", err)
	}

	return nil
}

func sendStartdQuery(cedarStream *stream.Stream) error {
	// Create query ClassAd
	queryAd := createStartdQueryAd()

	if *verbose {
		slog.Info("📋 Query ClassAd:", "destination", "cedar")
		slog.Info("   MyType = \"Query\"", "destination", "cedar")
		slog.Info("   TargetType = \"Machine\"", "destination", "cedar")
		slog.Info("   Requirements = true", "destination", "cedar")
		slog.Info(fmt.Sprintf("   LimitResults = %d", *limit), "destination", "cedar")
	}

	// Create a message for sending the query
	queryMsg := message.NewMessageForStream(cedarStream)

	// Add the ClassAd to the message
	err := queryMsg.PutClassAd(context.Background(), queryAd)
	if err != nil {
		return fmt.Errorf("failed to add ClassAd to message: %w", err)
	}

	// Send the message (flush with End-of-Message)
	err = queryMsg.FinishMessage(context.Background())
	if err != nil {
		return fmt.Errorf("failed to send query message: %w", err)
	}

	slog.Info("✅ Query sent successfully", "destination", "cedar")

	// Receive and process response
	slog.Info("📥 Waiting for collector response...", "destination", "cedar")

	return receiveQueryResponse(cedarStream)
}

func receiveQueryResponse(cedarStream *stream.Stream) error {
	responseMsg := message.NewMessageFromStream(cedarStream)

	// Process response ads
	adsReceived := 0
	for {
		// Read "more" flag
		more, err := responseMsg.GetInt32(context.Background())
		if err != nil {
			slog.Error(fmt.Sprintf("Failed to read 'more' flag: %v", err), "destination", "cedar")
		}

		if more == 0 {
			fmt.Printf("\n✅ Query complete! Received %d ads\n", adsReceived)
			break
		}

		// Read ClassAd
		ad, err := responseMsg.GetClassAd(context.Background())
		if err != nil {
			slog.Error(fmt.Sprintf("Failed to read ClassAd: %v", err), "destination", "cedar")
		}

		adsReceived++
		displayStartdAd(ad, adsReceived)
		fmt.Print("\n" + strings.Repeat("-", 60) + "\n")
	}

	slog.Info(fmt.Sprintf("✅ Successfully received %d ads", adsReceived), "destination", "cedar")
	return nil
}

func displayStartdAd(ad *classad.ClassAd, num int) {
	slog.Info(fmt.Sprintf("\n📋 Ad #%d:", num), "destination", "cedar")

	// Extract interesting attributes
	if name, ok := ad.EvaluateAttrString("Name"); ok {
		slog.Info(fmt.Sprintf("   Name: %s", name), "destination", "cedar")
	}

	if machine, ok := ad.EvaluateAttrString("Machine"); ok {
		slog.Info(fmt.Sprintf("   Machine: %s", machine), "destination", "cedar")
	}

	if state, ok := ad.EvaluateAttrString("State"); ok {
		slog.Info(fmt.Sprintf("   State: %s", state), "destination", "cedar")
	}

	if activity, ok := ad.EvaluateAttrString("Activity"); ok {
		slog.Info(fmt.Sprintf("   Activity: %s", activity), "destination", "cedar")
	}

	if cpus, ok := ad.EvaluateAttrInt("TotalSlotCpus"); ok {
		slog.Info(fmt.Sprintf("   CPUs: %d", cpus), "destination", "cedar")
	} else if cpus, ok := ad.EvaluateAttrInt("Cpus"); ok {
		slog.Info(fmt.Sprintf("   CPUs: %d", cpus), "destination", "cedar")
	}

	if memory, ok := ad.EvaluateAttrInt("TotalSlotMemory"); ok {
		slog.Info(fmt.Sprintf("   Memory: %d MB", memory), "destination", "cedar")
	} else if memory, ok := ad.EvaluateAttrInt("Memory"); ok {
		slog.Info(fmt.Sprintf("   Memory: %d MB", memory), "destination", "cedar")
	}

	if disk, ok := ad.EvaluateAttrInt("TotalSlotDisk"); ok {
		slog.Info(fmt.Sprintf("   Disk: %d KB", disk), "destination", "cedar")
	} else if disk, ok := ad.EvaluateAttrInt("Disk"); ok {
		slog.Info(fmt.Sprintf("   Disk: %d KB", disk), "destination", "cedar")
	}

	if *verbose {
		// Display all attributes in verbose mode
		slog.Info("   All attributes:", "destination", "cedar")
		attrs := ad.GetAttributes()
		for _, attr := range attrs {
			if expr, ok := ad.Lookup(attr); ok {
				slog.Info(fmt.Sprintf("     %s = %s", attr, expr), "destination", "cedar")
			}
		}
	}
}

// createStartdQueryAd creates a ClassAd for querying startd ads
func createStartdQueryAd() *classad.ClassAd {
	ad := classad.New()

	// Set MyType and TargetType as required by HTCondor query protocol
	_ = ad.Set("MyType", "Query")
	_ = ad.Set("TargetType", "Machine") // Query Machine ads (startd)

	// Set Requirements - use "true" to get all ads
	_ = ad.Set("Requirements", true)

	// Set a limit on results
	_ = ad.Set("LimitResults", int64(*limit))

	return ad
}
