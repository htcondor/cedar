// Package client provides HTCondor API client implementations
// using the CEDAR protocol.
//
// This package will eventually contain clients for various HTCondor
// operations, starting with a condor_status equivalent.
package client

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/ccb"
	"github.com/htcondor/cedar/client/sharedport"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// HTCondorClient represents a client connection to an HTCondor daemon
type HTCondorClient struct {
	stream           *stream.Stream
	config           *ClientConfig
	sharedPortClient *sharedport.SharedPortClient
	negotiation      *security.SecurityNegotiation // Security negotiation outcome (nil if no authentication performed)
}

// ClientConfig holds configuration for HTCondor client connections
type ClientConfig struct {
	// Address is the HTCondor daemon address. Can be:
	// - "host:port" for direct TCP connection
	// - "host:port?sock=daemon_id" for shared port connection
	// - "<host:port?sock=daemon_id>" for shared port connection (HTCondor format)
	Address string

	// Deprecated: Use Address field instead
	Host string
	// Deprecated: Use Address field instead
	Port int

	// Timeout for connection establishment (default: 30 seconds)
	Timeout time.Duration

	// FallbackDelay controls the IPv6/IPv4 "happy eyeballs" race
	// inside net.Dialer.DialContext when the resolved hostname has
	// both AAAA and A records. Go's default is 300 ms; we drop it
	// to 150 ms so failover off a dead IPv6 path stays snappy.
	// Pass a negative value to disable the inner race (matches
	// net.Dialer's documented contract for negative FallbackDelay).
	// Zero = use DefaultDialerFallbackDelay.
	FallbackDelay time.Duration

	// ClientName for shared port connections (for debugging)
	ClientName string

	Security *security.SecurityConfig

	// CCBReturnAddr, if set, enables streaming/proxy mode for CCB sinful
	// addresses: it is this client's own CCB sinful (carrying a ccbid), used
	// when the client is itself behind CCB and cannot accept a direct reverse
	// connection.
	CCBReturnAddr string

	// CCBRequireStreaming makes streaming mode mandatory for CCB addresses
	// (fail fast if the broker does not support it).
	CCBRequireStreaming bool

	// CCBReverseListener, when set, supplies the inbound path for a standard-mode
	// CCB dial instead of a private TCP listen socket -- see
	// ccb.DialOptions.ReverseListener. It lets a client with no port of its own
	// still accept connection reversal, by being reachable on a port it shares
	// (e.g. an in-process shared-port router, server/sharedport).
	//
	// It has no effect when CCBReturnAddr or CCBRequireStreaming select
	// streaming mode: in streaming mode the broker relays on the request socket
	// and nothing reverses. Set one or the other, not both.
	CCBReverseListener ccb.ReverseListenerFunc

	// KeepAlive controls TCP keepalive probing on the dialed connection. When
	// nil, DefaultKeepAliveConfig is used (SO_KEEPALIVE on with HTCondor's
	// idle=360s / interval=5s / count=5 defaults), so a silently-dead peer is
	// detected instead of blocking a goroutine in Read forever. Set a pointer
	// to an explicitly-configured value to override, or to a disabled config
	// (Enable=false) to turn keepalives off.
	KeepAlive *stream.KeepAliveConfig

	// DialControl, if set, is installed as net.Dialer.Control on every outbound
	// TCP connection Connect makes: the direct dial to the daemon, the dial to
	// a shared-port server, and the dials to CCB brokers. It is called after
	// name resolution with the concrete "ip:port" about to be connected to
	// (once per address tried, e.g. per family in the IPv6/IPv4 race), so a
	// caller can refuse a destination by its real IP -- an SSRF guard that a
	// check on the hostname alone cannot provide. Returning an error aborts
	// that connection attempt.
	//
	// For a CCB address the hook sees only the broker connections: the target
	// is never dialed by this client (it connects back, or the broker relays).
	DialControl func(network, address string, c syscall.RawConn) error
}

// keepAliveConfig returns the effective keepalive settings for this client,
// falling back to the HTCondor-matching defaults when none is configured.
func (c *ClientConfig) keepAliveConfig() stream.KeepAliveConfig {
	if c.KeepAlive != nil {
		return *c.KeepAlive
	}
	return stream.DefaultKeepAliveConfig()
}

// DefaultDialerFallbackDelay is the IPv6→IPv4 happy-eyeballs
// switch-over time used when ClientConfig.FallbackDelay is zero.
// 150 ms matches the typical higher-level cross-collector race
// stagger so the two failover mechanisms compose without one
// drowning the other in concurrent socket attempts.
const DefaultDialerFallbackDelay = 150 * time.Millisecond

// NewClient creates a new HTCondor client
func NewClient(config *ClientConfig) *HTCondorClient {
	// Set default values
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.ClientName == "" {
		config.ClientName = "golang-cedar-client"
	}

	// Support legacy Host:Port format
	if config.Address == "" && config.Host != "" && config.Port != 0 {
		config.Address = fmt.Sprintf("%s:%d", config.Host, config.Port)
	}

	spc := sharedport.NewSharedPortClient(config.ClientName)
	// Thread the client's keepalive policy into the shared-port dialer so the
	// shared-port path gets the same treatment as a direct dial.
	spc.KeepAlive = config.keepAliveConfig()

	return &HTCondorClient{
		config:           config,
		sharedPortClient: spc,
	}
}

// Connect establishes a connection to the HTCondor daemon
func (c *HTCondorClient) Connect(ctx context.Context) error {
	if c.config.Address == "" {
		return fmt.Errorf("no address specified in client configuration")
	}

	// Parse the address to determine its routing (CCB, shared port, direct).
	sinful, perr := addresses.ParseSinful(c.config.Address)
	if perr == nil && sinful.IsCCB() {
		conn, err := ccb.Dial(ctx, sinful.CCBContacts, ccb.DialOptions{
			Security:         c.config.Security,
			ProxyReturnAddr:  c.config.CCBReturnAddr,
			RequireStreaming: c.config.CCBRequireStreaming,
			ReverseListener:  c.config.CCBReverseListener,
			TargetDesc:       c.config.Address,
			Timeout:          c.config.Timeout,
			DialControl:      c.config.DialControl,
		})
		if err != nil {
			return fmt.Errorf("failed to reach %s via CCB: %w", c.config.Address, err)
		}
		// Best-effort keepalives on the CCB-brokered connection (no-op if the
		// broker handed back a non-TCP conn).
		_ = c.config.keepAliveConfig().Apply(conn)
		c.stream = stream.NewStream(conn)
		c.stream.SetPeerAddr(c.config.Address)
		return nil
	}

	// Parse the address to determine if it's a shared port connection
	addrInfo := addresses.ParseHTCondorAddress(c.config.Address)

	var err error
	if addrInfo.IsSharedPort {
		// Use shared port connection
		c.sharedPortClient.DialControl = c.config.DialControl
		c.stream, err = c.sharedPortClient.ConnectViaSharedPort(
			ctx,
			addrInfo.ServerAddr,
			addrInfo.SharedPortID,
			c.config.Timeout,
		)
	} else {
		// Use direct TCP connection with context-aware dialing.
		// FallbackDelay tunes Go's built-in IPv6/IPv4 happy-eyeballs:
		// a hostname with both AAAA and A records races the v6 dial
		// first, then starts the v4 dial after FallbackDelay if the
		// v6 attempt hasn't completed. Default to
		// DefaultDialerFallbackDelay (150 ms) — Go's stdlib default
		// of 300 ms is slower than ideal for HTCondor's typical
		// multi-collector deployments.
		fbDelay := c.config.FallbackDelay
		if fbDelay == 0 {
			fbDelay = DefaultDialerFallbackDelay
		}
		dialer := &net.Dialer{
			Timeout:       c.config.Timeout,
			FallbackDelay: fbDelay,
			Control:       c.config.DialControl,
		}
		conn, dialErr := dialer.DialContext(ctx, "tcp", addrInfo.ServerAddr)
		if dialErr != nil {
			return fmt.Errorf("failed to connect to %s: %w", addrInfo.ServerAddr, dialErr)
		}
		// Enable TCP keepalives (best-effort; a failure to set them must not
		// fail an otherwise-good connection, matching C++ set_keepalive which
		// only logs on failure).
		_ = c.config.keepAliveConfig().Apply(conn)
		c.stream = stream.NewStream(conn)
	}

	if err != nil {
		return fmt.Errorf("failed to establish connection: %w", err)
	}

	// Set peer address on stream using the original address format (with brackets if applicable)
	if c.stream != nil {
		c.stream.SetPeerAddr(c.config.Address)
	}

	return nil
}

// ConnectToAddress is a convenience method that creates a client and connects to the specified address
func ConnectToAddress(ctx context.Context, address string) (*HTCondorClient, error) {
	config := &ClientConfig{
		Address: address,
	}

	client := NewClient(config)
	err := client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// ConnectAndAuthenticate establishes a connection and performs authentication handshake
// with automatic retry on session resumption failures. This is the recommended method
// for establishing authenticated connections to HTCondor daemons.
//
// If session resumption fails (e.g., SID_NOT_FOUND), the function will:
// 1. Close the current connection
// 2. Establish a new connection
// 3. Retry the handshake (which will perform full authentication)
//
// This ensures that failed session resumption attempts don't leave the stream in an
// unusable state.
func ConnectAndAuthenticate(ctx context.Context, address string, securityConfig *security.SecurityConfig) (*HTCondorClient, error) {
	config := &ClientConfig{
		Address:  address,
		Security: securityConfig,
	}

	return ConnectAndAuthenticateWithConfig(ctx, config)
}

// ConnectAndAuthenticateWithConfig is like ConnectAndAuthenticate but accepts a full ClientConfig
func ConnectAndAuthenticateWithConfig(ctx context.Context, config *ClientConfig) (*HTCondorClient, error) {
	const maxRetries = 2 // Initial attempt + 1 retry on session resumption failure

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		client := NewClient(config)

		// Establish connection
		if err := client.Connect(ctx); err != nil {
			lastErr = fmt.Errorf("failed to connect to %s: %w", config.Address, err)
			continue
		}

		// Perform authentication handshake
		if config.Security != nil {
			auth := security.NewAuthenticator(config.Security, client.stream)
			negotiation, err := auth.ClientHandshake(ctx)

			// Check if this is a session resumption error
			if security.IsSessionResumptionError(err) {
				// Close the connection and retry with a fresh connection
				_ = client.Close()
				lastErr = fmt.Errorf("session resumption failed, retrying with new connection: %w", err)
				continue
			}

			if err != nil {
				_ = client.Close()
				// Propagate the underlying authentication error verbatim.
				// The inner error chain already reads "authentication phase
				// failed: all authentication methods failed: SSL: ...; TOKEN:
				// ...; FS: ..." which is informative on its own. Wrapping
				// with "authentication handshake failed:" just added a
				// redundant prefix to an already-long error chain.
				//
				// The one case worth annotating: a bare reset/EOF during the
				// handshake on a shared-port endpoint, which is otherwise an
				// opaque "connection reset by peer" that hides the fact that
				// shared_port had no daemon behind the socket name.
				return nil, annotateSharedPortReset(config.Address, client.stream.ReceivedFrame(), err)
			}

			// Store negotiation information in the client
			client.negotiation = negotiation
		}

		// Success!
		return client, nil
	}

	return nil, fmt.Errorf("failed to connect and authenticate after %d attempts: %w", maxRetries, lastErr)
}

// IsConnected returns true if the client is connected to a daemon
func (c *HTCondorClient) IsConnected() bool {
	return c.stream != nil && c.stream.IsConnected()
}

// GetStream returns the underlying CEDAR stream for advanced operations
func (c *HTCondorClient) GetStream() *stream.Stream {
	return c.stream
}

// GetSecurityNegotiation returns the security negotiation outcome from the authentication handshake.
// Returns nil if no authentication was performed.
func (c *HTCondorClient) GetSecurityNegotiation() *security.SecurityNegotiation {
	return c.negotiation
}

// SessionAttr returns one application attribute the peer advertised in its
// post-authentication ad, for a name this client asked for in
// SecurityConfig.WantSessionAttrs. A resumed session answers as the handshake
// that created it did.
//
// ok is false when the peer said nothing under that name, which a caller must
// read as the oldest behaviour it supports: a peer too old to advertise and a
// peer that chose not to are the same answer here.
func (c *HTCondorClient) SessionAttr(name string) (string, bool) {
	if c.negotiation == nil {
		return "", false
	}
	v, ok := c.negotiation.SessionAttrs[name]
	return v, ok
}

// Close closes the client connection
func (c *HTCondorClient) Close() error {
	if c.stream != nil {
		return c.stream.Close()
	}
	return nil
}
