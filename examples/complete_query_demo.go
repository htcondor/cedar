//go:build ignore

// Complete HTCondor Query Demo Client
//
// This demonstrates the full CEDAR protocol with proper security handshake
// and shows session information from the completed handshake.
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
	"github.com/htcondor/cedar/stream"
)

// Helper function to serialize ClassAd to bytes
func serializeClassAdToBytes(ad *classad.ClassAd) ([]byte, error) {
	mockStream := &CompleteDemoMockStream{
		frames:    make([][]byte, 0),
		frameEOMs: make([]bool, 0),
		frameIdx:  0,
		encrypted: false,
	}

	msg := message.NewMessageForStream(mockStream)
	if err := msg.PutClassAd(context.Background(), ad); err != nil {
		return nil, err
	}

	if err := msg.FinishMessage(context.Background()); err != nil {
		return nil, err
	}

	var result []byte
	for _, frame := range mockStream.frames {
		result = append(result, frame...)
	}

	return result, nil
}

// Helper function to parse Message from bytes
func parseMessageFromBytes(data []byte) (*message.Message, error) {
	mockStream := &CompleteDemoMockStream{
		frames:    [][]byte{data},
		frameEOMs: []bool{true},
		frameIdx:  0,
		encrypted: false,
	}

	return message.NewMessageFromStream(mockStream), nil
}

// CompleteDemoMockStream implements StreamInterface for serialization
type CompleteDemoMockStream struct {
	frames    [][]byte
	frameEOMs []bool
	frameIdx  int
	encrypted bool
}

func (s *CompleteDemoMockStream) ReadFrame(ctx context.Context) ([]byte, bool, error) {
	if s.frameIdx >= len(s.frames) {
		return nil, false, fmt.Errorf("no more frames")
	}

	data := s.frames[s.frameIdx]
	isEOM := s.frameEOMs[s.frameIdx]
	s.frameIdx++

	return data, isEOM, nil
}

func (s *CompleteDemoMockStream) WriteFrame(ctx context.Context, data []byte, isEOM bool) error {
	s.frames = append(s.frames, data)
	s.frameEOMs = append(s.frameEOMs, isEOM)
	return nil
}

func (s *CompleteDemoMockStream) IsEncrypted() bool {
	return s.encrypted
}

func main() {
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
	}

	fmt.Printf("🚀 HTCondor Complete Query Demo Client\n")
	fmt.Printf("📡 Connecting to %s:%d...\n", hostname, port)

	// Establish connection using client package
	addr := fmt.Sprintf("%s:%d", hostname, port)
	htcondorClient, err := client.ConnectToAddress(context.Background(), addr)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to connect: %v", err), "destination", "cedar")
	}
	defer func() { _ = htcondorClient.Close() }()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	fmt.Printf("🔐 Performing security handshake...\n")

	secConfig := &security.SecurityConfig{
		Command:        commands.QUERY_STARTD_ADS,
		AuthMethods:    []security.AuthMethod{security.AuthSSL, security.AuthToken, security.AuthNone},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
	}

	auth := security.NewAuthenticator(secConfig, cedarStream)
	negotiation, err := auth.ClientHandshake(context.Background())
	if err != nil {
		slog.Error(fmt.Sprintf("Security handshake failed: %v", err), "destination", "cedar")
	}

	cedarStream.SetAuthenticated(true)

	fmt.Printf("✅ Security handshake completed successfully!\n")
	fmt.Printf("📋 Session Information:\n")
	fmt.Printf("   Session ID: %s\n", negotiation.SessionId)
	fmt.Printf("   User: %s\n", negotiation.User)
	fmt.Printf("   Valid Commands: %s\n", negotiation.ValidCommands)
	fmt.Printf("   Command %d (QUERY_STARTD_ADS) allowed: %s\n",
		commands.QUERY_STARTD_ADS,
		checkCommandAllowed(negotiation.ValidCommands, commands.QUERY_STARTD_ADS))

	// Try querying different types of ads
	queries := []struct {
		name   string
		myType string
		target string
		cmd    int
	}{
		{"Startd Ads (Machines)", "Query", "Machine", commands.QUERY_STARTD_ADS},
		{"Collector Ads", "Query", "Collector", commands.QUERY_COLLECTOR_ADS},
		{"Schedd Ads (Schedulers)", "Query", "Scheduler", commands.QUERY_SCHEDD_ADS},
	}

	for _, q := range queries {
		fmt.Printf("\n🔍 Querying %s...\n", q.name)

		allowed := checkCommandAllowed(negotiation.ValidCommands, q.cmd)
		if allowed != "✅" {
			fmt.Printf("   ❌ Command %d not allowed, skipping\n", q.cmd)
			continue
		}

		count := performQuery(cedarStream, q.myType, q.target)
		fmt.Printf("   📊 Result: %d ads received\n", count)
	}
}

func checkCommandAllowed(validCommands string, cmdCode int) string {
	if strings.Contains(validCommands, fmt.Sprintf("%d", cmdCode)) {
		return "✅"
	}
	return "❌"
}

func performQuery(cedarStream *stream.Stream, myType, targetType string) int {
	// Create query ClassAd
	queryAd := classad.New()
	queryAd.Set("MyType", myType)
	queryAd.Set("TargetType", targetType)
	queryAd.Set("Requirements", "true")

	ctx := context.Background()

	// Send query using Message API
	queryData, err := serializeClassAdToBytes(queryAd)
	if err != nil {
		fmt.Printf("   ❌ Failed to serialize query: %v\n", err)
		return 0
	}

	if err := cedarStream.SendMessage(ctx, queryData); err != nil {
		fmt.Printf("   ❌ Failed to send query: %v\n", err)
		return 0
	}

	// Process responses
	adsReceived := 0
	for {
		responseData, err := cedarStream.ReceiveCompleteMessage(ctx)
		if err != nil {
			fmt.Printf("   ❌ Failed to receive response: %v\n", err)
			break
		}

		// Parse response using Message API
		responseMsg, err := parseMessageFromBytes(responseData)
		if err != nil {
			fmt.Printf("   ❌ Failed to parse response: %v\n", err)
			break
		}

		numExprs, err := responseMsg.GetInt32(ctx)
		if err != nil {
			fmt.Printf("   ❌ Failed to read response: %v\n", err)
			break
		}

		if numExprs == 0 {
			break // End of results
		}

		// Parse the ClassAd manually
		ad := classad.New()
		for i := 0; i < int(numExprs); i++ {
			exprStr, err := responseMsg.GetString(ctx)
			if err != nil {
				fmt.Printf("   ❌ Failed to read expression %d: %v\n", i, err)
				break
			}

			// Parse "attr = value"
			if eqPos := strings.Index(exprStr, " = "); eqPos > 0 {
				attr := strings.TrimSpace(exprStr[:eqPos])
				value := strings.TrimSpace(exprStr[eqPos+3:])
				if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
					value = value[1 : len(value)-1]
				}
				ad.Set(attr, value)
			}
		}

		// Read MyType and TargetType
		if myTypeStr, err := responseMsg.GetString(ctx); err == nil && myTypeStr != "" {
			ad.Set("MyType", myTypeStr)
		}
		if targetTypeStr, err := responseMsg.GetString(ctx); err == nil && targetTypeStr != "" {
			ad.Set("TargetType", targetTypeStr)
		}

		adsReceived++

		if adsReceived <= 3 { // Show details for first few ads
			fmt.Printf("   📄 Ad #%d:\n", adsReceived)
			printAdSummary(ad)
		}

		if adsReceived >= 10 { // Limit for demo
			fmt.Printf("   ⚠️  Limited to first 10 ads for demo\n")
			break
		}
	}

	return adsReceived
}

func printAdSummary(ad *classad.ClassAd) {
	attrs := []string{"Name", "Machine", "MyType", "MyAddress", "State", "Activity"}
	for _, attr := range attrs {
		if val, ok := ad.EvaluateAttrString(attr); ok {
			fmt.Printf("     %-12s: %s\n", attr, val)
		}
	}
}
