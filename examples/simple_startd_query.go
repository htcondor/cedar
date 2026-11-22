//go:build ignore

// Simple HTCondor Startd Query Client
//
// Focuses just on QUERY_STARTD_ADS with detailed protocol debugging
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/client"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
)

// Helper function to serialize ClassAd to bytes
func serializeClassAdToBytes(ad *classad.ClassAd) ([]byte, error) {
	mockStream := &SimpleMockStream{
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
	mockStream := &SimpleMockStream{
		frames:    [][]byte{data},
		frameEOMs: []bool{true},
		frameIdx:  0,
		encrypted: false,
	}

	return message.NewMessageFromStream(mockStream), nil
}

// SimpleMockStream implements StreamInterface for serialization
type SimpleMockStream struct {
	frames    [][]byte
	frameEOMs []bool
	frameIdx  int
	encrypted bool
}

func (s *SimpleMockStream) ReadFrame(ctx context.Context) ([]byte, bool, error) {
	if s.frameIdx >= len(s.frames) {
		return nil, false, fmt.Errorf("no more frames")
	}

	data := s.frames[s.frameIdx]
	isEOM := s.frameEOMs[s.frameIdx]
	s.frameIdx++

	return data, isEOM, nil
}

func (s *SimpleMockStream) WriteFrame(ctx context.Context, data []byte, isEOM bool) error {
	s.frames = append(s.frames, data)
	s.frameEOMs = append(s.frameEOMs, isEOM)
	return nil
}

func (s *SimpleMockStream) IsEncrypted() bool {
	return s.encrypted
}

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <hostname> <port>\n", os.Args[0])
		fmt.Printf("Example: %s cm-1.ospool.osg-htc.org 9618\n", os.Args[0])
		os.Exit(1)
	}
	ctx := context.Background()

	hostname := os.Args[1]
	portStr := os.Args[2]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		slog.Error(fmt.Sprintf("Invalid port: %s", portStr), "destination", "cedar")
	}

	fmt.Printf("🚀 Simple HTCondor Startd Query\n")
	fmt.Printf("📡 Connecting to %s:%d...\n", hostname, port)

	// Establish connection using client package
	addr := fmt.Sprintf("%s:%d", hostname, port)
	htcondorClient, err := client.ConnectToAddress(ctx, addr)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to connect: %v", err), "destination", "cedar")
	}
	defer func() { _ = htcondorClient.Close() }()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	fmt.Printf("🔐 Security handshake...\n")

	secConfig := &security.SecurityConfig{
		Command:        commands.QUERY_STARTD_ADS,
		AuthMethods:    []security.AuthMethod{security.AuthNone}, // Only try unauthenticated
		Authentication: security.SecurityNever,                   // Don't require auth
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityNever, // No encryption
		Integrity:      security.SecurityNever, // No integrity
	}

	auth := security.NewAuthenticator(secConfig, cedarStream)
	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		slog.Error(fmt.Sprintf("Security handshake failed: %v", err), "destination", "cedar")
	}

	cedarStream.SetAuthenticated(true)

	fmt.Printf("✅ Handshake complete! User: %s\n", negotiation.User)

	// Send query
	fmt.Printf("📤 Sending QUERY_STARTD_ADS query...\n")

	queryAd := classad.New()
	queryAd.Set("MyType", "Query")
	queryAd.Set("TargetType", "Machine")
	queryAd.Set("Requirements", true)
	queryAd.Set("LimitResults", 10)

	fmt.Printf("📋 Query ClassAd:\n")
	fmt.Printf("   MyType = %q\n", "Query")
	fmt.Printf("   TargetType = %q\n", "Machine")
	fmt.Printf("   Requirements = %v\n", true)
	fmt.Printf("   LimitResults = %d\n", 10)

	queryData, err := serializeClassAdToBytes(queryAd)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to serialize query: %v", err), "destination", "cedar")
	}

	fmt.Printf("📏 Query message size: %d bytes\n", len(queryData))

	if err := cedarStream.SendMessage(ctx, queryData); err != nil {
		slog.Error(fmt.Sprintf("Failed to send query: %v", err), "destination", "cedar")
	}

	fmt.Printf("📨 Query sent! Waiting for response...\n")

	// Read first response
	responseData, err := cedarStream.ReceiveCompleteMessage(ctx)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to receive response: %v", err), "destination", "cedar")
	}

	fmt.Printf("📥 Received response: %d bytes\n", len(responseData))

	responseMsg, err := parseMessageFromBytes(responseData)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to parse response: %v", err), "destination", "cedar")
	}

	numExprs, err := responseMsg.GetInt32(ctx)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to read numExprs: %v", err), "destination", "cedar")
	}

	fmt.Printf("📊 Response indicates %d expressions\n", numExprs)

	if numExprs == 0 {
		fmt.Printf("❌ No startd ads available\n")
		fmt.Printf("\n💡 This might be normal if:\n")
		fmt.Printf("   - No machines are currently reporting to this collector\n")
		fmt.Printf("   - Authentication is required to see machine ads\n")
		fmt.Printf("   - The collector is configured to hide ads from unauthenticated users\n")
		return
	}

	fmt.Printf("📄 Processing ads...\n")

	adsReceived := 0
	for numExprs > 0 {
		adsReceived++

		fmt.Printf("\n📋 Ad #%d (%d expressions):\n", adsReceived, numExprs)

		// Read expressions
		for i := 0; i < int(numExprs); i++ {
			exprStr, err := responseMsg.GetString(ctx)
			if err != nil {
				slog.Error(fmt.Sprintf("Failed to read expression %d: %v", i, err), "destination", "cedar")
			}
			fmt.Printf("   Expr %d: %s\n", i+1, exprStr)
		}

		// Read MyType and TargetType
		if myType, err := responseMsg.GetString(ctx); err == nil {
			fmt.Printf("   MyType: %s\n", myType)
		}
		if targetType, err := responseMsg.GetString(ctx); err == nil {
			fmt.Printf("   TargetType: %s\n", targetType)
		}

		// Get next response
		responseData, err = cedarStream.ReceiveCompleteMessage(ctx)
		if err != nil {
			fmt.Printf("❌ Failed to receive next response: %v\n", err)
			break
		}

		responseMsg, err = parseMessageFromBytes(responseData)
		if err != nil {
			fmt.Printf("❌ Failed to parse next response: %v\n", err)
			break
		}
		numExprs, err = responseMsg.GetInt32(ctx)
		if err != nil {
			fmt.Printf("❌ Failed to read next numExprs: %v\n", err)
			break
		}

		if adsReceived >= 10 {
			fmt.Printf("⚠️  Limiting to first 10 ads for demo\n")
			break
		}
	}

	fmt.Printf("\n✅ Query complete! Received %d ads\n", adsReceived)
}
