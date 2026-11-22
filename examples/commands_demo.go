//go:build ignore

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

func main() {
	fmt.Println("HTCondor Command Example")
	fmt.Println("========================")

	// Example 1: Querying startd ads (like condor_status)
	fmt.Printf("Command for querying startd ads: %s (%d)\n",
		commands.GetCommandName(commands.QUERY_STARTD_ADS),
		commands.QUERY_STARTD_ADS)

	// Example 2: Querying job ads (like condor_q)
	fmt.Printf("Command for querying job ads: %s (%d)\n",
		commands.GetCommandName(commands.QUERY_JOB_ADS),
		commands.QUERY_JOB_ADS)

	// Example 3: Show all collector commands
	fmt.Println("\nAll Collector Commands:")
	collectorCmds := commands.GetCommandsByType(commands.CollectorCommand)
	for _, cmd := range collectorCmds {
		fmt.Printf("  %-25s (%d) - %s\n", cmd.Name, cmd.Code, cmd.Description)
	}

	// Example 4: Creating a security config with a specific command
	config := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthSSL, security.AuthToken, security.AuthNone},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Command:        commands.QUERY_STARTD_ADS, // This session will be used to query startd ads
		RemoteVersion:  "10.0.0",
	}

	fmt.Printf("\nSecurity config created for command: %s\n",
		commands.GetCommandName(config.Command))

	// Example 5: Demonstrate how this would be used in a real connection
	fmt.Println("\nSimulating connection setup...")

	// Create mock connection for demonstration
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	// Client side
	go func() {
		clientStream := stream.NewStream(client)
		auth := security.NewAuthenticator(config, clientStream)

		// This would send the DC_AUTHENTICATE command with the Command field
		// set to QUERY_STARTD_ADS in the ClassAd
		fmt.Println("[CLIENT] Starting handshake with command:",
			commands.GetCommandName(config.Command))

		_, err := auth.ClientHandshake(context.Background())
		if err != nil {
			slog.Info(fmt.Sprintf("Client handshake failed: %v", err), "destination", "cedar")
		} else {
			fmt.Println("[CLIENT] Handshake completed - ready to query startd ads")
		}
	}()

	// Server side
	serverStream := stream.NewStream(server)
	serverConfig := &security.SecurityConfig{
		AuthMethods:   []security.AuthMethod{security.AuthNone},
		CryptoMethods: []security.CryptoMethod{security.CryptoAES},
	}
	serverAuth := security.NewAuthenticator(serverConfig, serverStream)

	fmt.Println("[SERVER] Waiting for client handshake...")
	negotiation, err := serverAuth.ServerHandshake(context.Background())
	if err != nil {
		slog.Info(fmt.Sprintf("Server handshake failed: %v", err), "destination", "cedar")
	} else {
		fmt.Printf("[SERVER] Handshake completed - client wants to use command: %s\n",
			commands.GetCommandName(negotiation.ClientConfig.Command))
	}

	fmt.Println("\nExample completed successfully!")
}
