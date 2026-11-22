// Package sharedport provides client functionality for HTCondor's shared port protocol.
//
// The shared port protocol allows multiple HTCondor daemons to share a single
// network port by having a shared port server daemon forward connections to
// the appropriate daemon based on a shared port ID.
//
// This implementation is based on the HTCondor C++ reference implementation
// in shared_port_client.cpp and related files.
package sharedport

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

// SharedPortClient handles connections to daemons behind HTCondor's shared port
type SharedPortClient struct {
	// clientName is used for debugging purposes when talking to the shared port server
	clientName string

	// KeepAlive is applied to the TCP connection dialed to the shared-port
	// server (and, on the direct path, to the daemon). Defaults to
	// stream.DefaultKeepAliveConfig; set Enable=false to disable.
	KeepAlive stream.KeepAliveConfig

	// DialControl, if set, is installed as net.Dialer.Control on every TCP
	// connection this client dials. It is called after name resolution with
	// the concrete "ip:port" being connected to; returning an error aborts that
	// connection attempt. Callers use it to refuse destinations by IP.
	DialControl func(network, address string, c syscall.RawConn) error
}

// NewSharedPortClient creates a new shared port client
func NewSharedPortClient(clientName string) *SharedPortClient {
	if clientName == "" {
		clientName = "golang-cedar-client"
	}
	return &SharedPortClient{
		clientName: clientName,
		KeepAlive:  stream.DefaultKeepAliveConfig(),
	}
}

// ConnectViaSharedPort connects to a daemon through HTCondor's shared port mechanism
//
// It takes:
// - ctx: context for cancellation and timeouts
// - sharedPortAddr: the address of the shared port server (host:port)
// - sharedPortID: the ID of the target daemon (e.g., "startd", "schedd")
// - deadline: connection timeout
//
// Returns a stream connected directly to the target daemon
func (spc *SharedPortClient) ConnectViaSharedPort(ctx context.Context, sharedPortAddr, sharedPortID string, deadline time.Duration) (*stream.Stream, error) {
	if !addresses.IsValidSharedPortID(sharedPortID) {
		return nil, fmt.Errorf("invalid shared port ID: %s", sharedPortID)
	}

	// Connect to the shared port server
	conn, err := spc.dial(ctx, sharedPortAddr, deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to shared port server at %s: %w", sharedPortAddr, err)
	}
	// Best-effort TCP keepalives so a dead peer is detected (see stream.KeepAliveConfig).
	_ = spc.KeepAlive.Apply(conn)

	// Create a stream for the connection
	s := stream.NewStream(conn)

	// Send the shared port connection request
	err = spc.sendSharedPortRequest(ctx, s, sharedPortID, deadline)
	if err != nil {
		_ = s.Close() // Ignore error during cleanup
		return nil, fmt.Errorf("failed to send shared port request: %w", err)
	}

	// The connection is now established to the target daemon
	// However, the shared port server saw the first message but the target daemon
	// did not.  Hence, we need to recreate the stream to reset any state so the
	// message digests (if any) are correct.  This matches the behavior of the C++ implementation.
	s = stream.NewStream(conn)

	// Set peer address in HTCondor sinful string format
	peerAddr := fmt.Sprintf("<%s?sock=%s>", sharedPortAddr, sharedPortID)
	s.SetPeerAddr(peerAddr)

	return s, nil
}

// ConnectToHTCondorAddress is a convenience function that can connect to any HTCondor address,
// handling both regular TCP connections and shared port connections automatically.
//
// It takes:
// - ctx: context for cancellation and timeouts
// - address: HTCondor address (e.g., "host:port" or "host:port?sock=daemon")
// - deadline: connection timeout
//
// Returns a stream connected to the target daemon
func (spc *SharedPortClient) ConnectToHTCondorAddress(ctx context.Context, address string, deadline time.Duration) (*stream.Stream, error) {
	addrInfo := addresses.ParseHTCondorAddress(address)

	if addrInfo.IsSharedPort {
		return spc.ConnectViaSharedPort(ctx, addrInfo.ServerAddr, addrInfo.SharedPortID, deadline)
	}

	// Regular TCP connection
	conn, err := spc.dial(ctx, addrInfo.ServerAddr, deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", addrInfo.ServerAddr, err)
	}
	// Best-effort TCP keepalives so a dead peer is detected (see stream.KeepAliveConfig).
	_ = spc.KeepAlive.Apply(conn)

	s := stream.NewStream(conn)
	// Set peer address in sinful string format (preserve original format)
	s.SetPeerAddr(address)

	return s, nil
}

// dial opens a TCP connection to addr, bounded by deadline and ctx, with
// DialControl applied.
func (spc *SharedPortClient) dial(ctx context.Context, addr string, deadline time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: deadline, Control: spc.DialControl}
	return d.DialContext(ctx, "tcp", addr)
}

// sendSharedPortRequest sends the shared port connection request to the shared port server
func (spc *SharedPortClient) sendSharedPortRequest(ctx context.Context, s *stream.Stream, sharedPortID string, deadline time.Duration) error {
	// Create a message for encoding
	msg := message.NewMessageForStream(s)

	// Send SHARED_PORT_CONNECT command
	if err := msg.PutInt32(ctx, int32(commands.SHARED_PORT_CONNECT)); err != nil {
		return fmt.Errorf("failed to send SHARED_PORT_CONNECT command: %w", err)
	}

	// Send the shared port ID
	if err := msg.PutString(ctx, sharedPortID); err != nil {
		return fmt.Errorf("failed to send shared port ID: %w", err)
	}

	// Send our name for debugging purposes
	if err := msg.PutString(ctx, spc.clientName); err != nil {
		return fmt.Errorf("failed to send client name: %w", err)
	}

	// Send the deadline in seconds
	deadlineSeconds := int64(deadline.Seconds())
	if deadlineSeconds <= 0 {
		deadlineSeconds = -1 // No timeout
	}
	if err := msg.PutInt64(ctx, deadlineSeconds); err != nil {
		return fmt.Errorf("failed to send deadline: %w", err)
	}

	// Send more_args (0 for now, for possible future use)
	if err := msg.PutInt32(ctx, 0); err != nil {
		return fmt.Errorf("failed to send more_args: %w", err)
	}

	// End the message
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to end shared port request message: %w", err)
	}

	return nil
}
