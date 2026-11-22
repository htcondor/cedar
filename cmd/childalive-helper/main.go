package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/htcondor/cedar/client/sharedport"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/security"
)

// writeResult writes the outcome to the requested path and logs to stderr on error.
func writeResult(path string, msg string) {
	if path == "" {
		return
	}
	if err := os.WriteFile(path, []byte(msg), 0644); err != nil {
		slog.Error("failed to write result file", "path", path, "error", err)
	}
}

func main() {
	outputPath := os.Getenv("CEDAR_CHILDALIVE_OUTPUT")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Ensure inherited sessions are imported
	cache := security.GetSessionCache()
	_ = cache // import side-effects

	parentAddr := security.GetInheritedParentAddr()
	if parentAddr == "" {
		writeResult(outputPath, "no_parent_addr")
		return
	}

	if os.Getenv("CEDAR_CHILDALIVE_MODE") == "query-ready-after-blowfish" {
		writeResult(outputPath, queryReadyAfterBlowfish(ctx, parentAddr))
		return
	}

	// Require that a cached inherited session exists; skip any fallback authentication.
	cmdStr := fmt.Sprintf("%d", commands.DC_CHILDALIVE)
	if _, ok := cache.LookupByCommand("", parentAddr, cmdStr); !ok {
		writeResult(outputPath, "no_cached_session")
		return
	}

	spc := sharedport.NewSharedPortClient("childalive-helper")
	stream, err := spc.ConnectToHTCondorAddress(ctx, parentAddr, 5*time.Second)
	if err != nil {
		writeResult(outputPath, fmt.Sprintf("connect_error:%v", err))
		return
	}
	defer func() {
		if cerr := stream.Close(); cerr != nil {
			slog.Warn("failed to close stream", "error", cerr)
		}
	}()
	peerAddr := stream.GetPeerAddr()
	peerName := parentAddr

	cfg := &security.SecurityConfig{
		AuthMethods:    nil,                    // Do not advertise any auth methods; force session reuse.
		Authentication: security.SecurityNever, // Never fall back to authentication if resumption fails.
		Command:        commands.DC_CHILDALIVE,
		PeerName:       peerName,
	}

	auth := security.NewAuthenticator(cfg, stream)
	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		writeResult(outputPath, fmt.Sprintf("handshake_error:%v parent=%s peer=%s peerName=%s", err, parentAddr, peerAddr, peerName))
		return
	}

	// Ensure the handshake actually resumed the inherited session.
	if negotiation == nil || (!negotiation.SessionResumed && !auth.WasSessionResumed()) {
		writeResult(outputPath, fmt.Sprintf("handshake_not_resumed parent=%s peer=%s peerName=%s", parentAddr, peerAddr, peerName))
		return
	}

	writeResult(outputPath, "ok")
}
