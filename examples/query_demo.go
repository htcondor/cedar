//go:build ignore

// Demo client for querying HTCondor startd ads
//
// This program connects to a HTCondor collector using the CEDAR protocol,
// performs a security handshake, sends a query ad, and processes the response ads.
//
// Usage: go run query_demo.go [hostname] [port]
//
// Example: go run query_demo.go cm-1.ospool.osg-htc.org 9618
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/client"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
)

func main() {
	// Parse command line arguments
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <hostname> <port>\n", os.Args[0])
		fmt.Printf("Example: %s cm-1.ospool.osg-htc.org 9618\n", os.Args[0])
		os.Exit(1)
	}

	hostname := os.Args[1]
	portStr := os.Args[2]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		slog.Error(fmt.Sprintf("Invalid port: %s", portStr), "destination", "cedar")
		os.Exit(1)
	}

	fmt.Printf("🚀 HTCondor Query Demo Client\n")
	fmt.Printf("📡 Connecting to %s:%d...\n", hostname, port)

	// Establish connection using client package
	addr := fmt.Sprintf("%s:%d", hostname, port)
	htcondorClient, err := client.ConnectToAddress(context.Background(), addr)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to connect: %v", err), "destination", "cedar")
		os.Exit(1)
	}
	defer func() { _ = htcondorClient.Close() }()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// Perform security handshake for QUERY_STARTD_ADS
	fmt.Printf("🔐 Performing security handshake...\n")

	// Create security config and authenticator
	secConfig := &security.SecurityConfig{
		Command:        commands.QUERY_STARTD_ADS,
		AuthMethods:    []security.AuthMethod{security.AuthSSL, security.AuthToken},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
	}

	auth := security.NewAuthenticator(secConfig, cedarStream)
	negotiation, err := auth.ClientHandshake(context.Background())
	if err != nil {
		slog.Error(fmt.Sprintf("Security handshake failed: %v", err), "destination", "cedar")
		os.Exit(1)
	}

	fmt.Printf("✅ Security handshake completed successfully\n")
	fmt.Printf("🔐 Authentication method: %s\n", negotiation.NegotiatedAuth)
	fmt.Printf("🔍 Sending query for startd ads...\n")

	// Create query ClassAd
	queryAd := createQueryAd()

	// Create a message for sending the query using Message API
	queryMsg := message.NewMessageForStream(cedarStream)

	// Add the ClassAd to the message using Message API
	err = queryMsg.PutClassAd(context.Background(), queryAd)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to add ClassAd to message: %v", err), "destination", "cedar")
		os.Exit(1)
	}

	// Send the message using Message API (flush with End-of-Message)
	err = queryMsg.FlushFrame(context.Background(), true)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to send query message: %v", err), "destination", "cedar")
		os.Exit(1)
	}

	fmt.Printf("📨 Query sent, processing responses...\n\n")

	// Create response message reader using Message API
	responseMsg := message.NewMessageFromStream(cedarStream)

	// Process response ads
	adsReceived := 0
	for {
		// Read "more" flag
		more, err := responseMsg.GetInt32(context.Background())
		if err != nil {
			slog.Error(fmt.Sprintf("Failed to read 'more' flag: %v", err), "destination", "cedar")
			os.Exit(1)
		}

		if more == 0 {
			fmt.Printf("\n✅ Query complete! Received %d ads\n", adsReceived)
			break
		}

		// Read ClassAd
		ad, err := responseMsg.GetClassAd(context.Background())
		if err != nil {
			slog.Error(fmt.Sprintf("Failed to read ClassAd: %v", err), "destination", "cedar")
			os.Exit(1)
		}

		adsReceived++
		fmt.Printf("📄 Ad #%d:\n", adsReceived)
		printAd(ad)
		fmt.Print("\n" + strings.Repeat("-", 60) + "\n")
	}
}

// createQueryAd creates a ClassAd for querying startd ads
func createQueryAd() *classad.ClassAd {
	ad := classad.New()

	// Set MyType and TargetType as required by HTCondor query protocol
	_ = ad.Set("MyType", "Query")
	_ = ad.Set("TargetType", "Machine") // Query Machine ads (startd)

	//_ = ad.Set("Projection", "Name,Machine,State,Activity,LoadAvg,Cpus,Memory,Disk,OpSysAndVer,Arch")

	// Set Requirements - use "true" to get all ads
	// In production, you might want more specific requirements like:
	// "State == \"Unclaimed\" && Activity == \"Idle\""
	_ = ad.Set("Requirements", true)

	// Optional: Set a limit on results (uncomment if desired)
	_ = ad.Set("LimitResults", 4)

	return ad
}

// printAd prints key attributes of a ClassAd
func printAd(ad *classad.ClassAd) {
	// Key attributes to display
	keyAttrs := []string{
		"Name",          // Machine name
		"Machine",       // Machine name (alternative)
		"MyAddress",     // Network address
		"State",         // Machine state (e.g., Unclaimed, Claimed)
		"Activity",      // Machine activity (e.g., Idle, Busy)
		"LoadAvg",       // Load average
		"TotalSlots",    // Total slots on machine
		"Cpus",          // Number of CPUs
		"Memory",        // Memory in MB
		"Disk",          // Disk space in KB
		"OpSysAndVer",   // Operating system and version
		"Arch",          // Architecture
		"CondorVersion", // HTCondor version
		"MyType",        // ClassAd type
		"StartdIpAddr",  // Startd IP address
	}

	for _, attrName := range keyAttrs {
		if val, ok := ad.EvaluateAttrString(attrName); ok {
			fmt.Printf("  %-15s = %q\n", attrName, val)
		} else if val, ok := ad.EvaluateAttrNumber(attrName); ok {
			fmt.Printf("  %-15s = %.0f\n", attrName, val)
		} else if val, ok := ad.EvaluateAttrBool(attrName); ok {
			fmt.Printf("  %-15s = %t\n", attrName, val)
		}
		// If none of the simple types work, we could fall back to raw attribute lookup
		// but for the demo, we'll keep it simple
	}
}
