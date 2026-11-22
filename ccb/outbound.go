package ccb

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/version"
)

// OutboundMinVersion is the minimum broker $CondorVersion$ assumed to support the
// outbound CCB_PROXY_CONNECT tunneling command. A requester version-gates the
// broker before sending command 82 so it fails fast against an old broker that
// has no handler for it, rather than tripping a confusing mid-protocol error.
// Tunneling ships alongside streaming, so this tracks StreamingMinVersion.
var OutboundMinVersion = StreamingMinVersion

// OutboundOptions configures an outbound proxy (tunnel) connect.
type OutboundOptions struct {
	// Security authenticates to the broker; its Command is overridden with
	// CCB_PROXY_CONNECT. Required. The broker enforces DAEMON authorization, so
	// this must carry a credential the broker accepts at that level.
	Security *security.SecurityConfig

	// Name is an optional debugging identity for the requester (sent as Name).
	Name string

	// Timeout bounds the whole exchange, including the broker's outbound dial to
	// the target (default 30s).
	Timeout time.Duration

	// Dial, when set, reaches the broker over a non-default carrier (see
	// BrokerDialer) instead of TCP -- used by an inside CCB that forwards the
	// proxy request to its next hop over a tunnel. nil ⇒ default TCP/shared-port.
	Dial BrokerDialer

	// TTL, when > 0, is sent to the broker as the outbound hop budget (CCBTTL).
	// The originator sets it; each forwarding broker decrements and refuses at 0,
	// bounding the chain length. 0 ⇒ omit (broker applies its own default).
	TTL int

	// DialControl, if set, is installed as net.Dialer.Control on the TCP
	// connection to the broker, including one through a shared port. It sees
	// the resolved "ip:port"; returning an error fails the connect. The
	// target is dialed by the broker, not here. Ignored when Dial is set.
	DialControl func(network, address string, c syscall.RawConn) error
}

// OutboundConnect asks a broker to dial target on the requester's behalf and
// splice, returning a net.Conn carrying an opaque byte relay to target. It is the
// client side of CCB tunneling's outbound mode: a daemon whose network forbids
// outbound TCP reaches target through its OUTBOUND_CCB_ADDRESS broker.
//
// broker is a broker Sinful ("host:port", or a shared-port "host:port?sock=name").
// target is the destination Sinful the broker should dial; the broker validates
// it against its allow-list. Unlike CCB_REQUEST there is NO CCBID -- the target is
// addressed by Sinful, which is the protocol-level distinction (§4.1).
//
// The returned conn is a raw relay: there is no reverse-connect hello and no
// ProxyMode echo. The requester IS the CEDAR connector, so the caller must run a
// normal, full CEDAR client handshake to the real target over the returned conn
// (wrapping it in a fresh stream, which resets MAC/MD state and tears down the
// broker-session crypto). That end-to-end handshake -- auth, integrity,
// encryption -- rides opaquely through the broker, which never holds its keys.
func OutboundConnect(ctx context.Context, broker, target string, opts OutboundOptions) (net.Conn, error) {
	if opts.Security == nil {
		return nil, fmt.Errorf("ccb: OutboundConnect requires a Security config for the broker")
	}
	if target == "" {
		return nil, fmt.Errorf("ccb: OutboundConnect requires a target address")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	connectID, err := GenerateConnectID()
	if err != nil {
		return nil, err
	}

	brokerConn, brokerStream, neg, err := dialBrokerAuthCmd(ctx, broker, opts.Security, CommandProxyConnect, brokerDial{carrier: opts.Dial, control: opts.DialControl})
	if err != nil {
		return nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			_ = brokerConn.Close()
		}
	}()

	// Version-gate before sending: an old broker has no handler for command 82.
	if !brokerSupportsOutbound(neg) {
		ver := ""
		if neg != nil && neg.ServerConfig != nil {
			ver = neg.ServerConfig.RemoteVersion
		}
		return nil, &OutboundUnsupportedError{Broker: broker, Version: ver}
	}

	// Request the broker dial target. ClaimId travels as the session key / shared
	// secret (and gets secret-over-the-wire treatment); MyAddress here means "the
	// address to dial", not a return address.
	req := NewAd(map[string]any{
		AttrMyAddress: target,
		AttrClaimID:   connectID,
		AttrName:      opts.Name,
	})
	if opts.TTL > 0 {
		_ = req.Set(AttrCCBTTL, opts.TTL)
	}
	if err := WriteControlAd(ctx, brokerStream, req); err != nil {
		return nil, err
	}

	// Read the {Result} reply while the broker-session crypto is still in place.
	reply, err := ReadControlAd(ctx, brokerStream)
	if err != nil {
		return nil, err
	}
	if result, _ := AdBool(reply, AttrResult); !result {
		return nil, fmt.Errorf("ccb: broker %s failed outbound connect to %s: %s",
			broker, target, AdString(reply, AttrErrorString))
	}

	// Result:true -> the very next bytes are the raw relay to the target. Hand the
	// raw conn back; the caller wraps it in a fresh stream for the end-to-end
	// handshake (no hello, no ProxyMode echo -- the requester is the connector).
	handedOff = true
	return brokerConn, nil
}

func brokerSupportsOutbound(neg *security.SecurityNegotiation) bool {
	if neg == nil || neg.ServerConfig == nil {
		return false
	}
	v, ok := version.Parse(neg.ServerConfig.RemoteVersion)
	if !ok {
		return false
	}
	return v.AtLeast(OutboundMinVersion)
}

// OutboundUnsupportedError indicates the broker cannot honor CCB_PROXY_CONNECT
// (too old, or the outbound-proxy handler is disabled).
type OutboundUnsupportedError struct {
	Broker  string
	Version string
}

func (e *OutboundUnsupportedError) Error() string {
	return fmt.Sprintf("ccb: broker %s (version %q) does not support outbound CCB proxy (tunneling)",
		e.Broker, e.Version)
}
