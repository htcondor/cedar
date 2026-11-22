// Package ccb implements the wire protocol for HTCondor's Condor Connection
// Broker (CCB). It is shared by CCB clients (requesters), CCB listeners
// (targets that register to be reachable), and CCB servers (brokers).
//
// The protocol is described in the HTCondor C++ sources src/ccb/ccb_client.cpp,
// ccb_listener.cpp and ccb_server.cpp. All control messages are a single CEDAR
// message carrying one ClassAd. The reverse-connect "hello" is a raw command
// integer followed by a ClassAd in one message (no security handshake), so it
// can be delivered to an ordinary CEDAR command socket.
package ccb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

// Command integers (mirrors condor_commands.h via the commands package).
const (
	CommandRegister         = commands.CCB_REGISTER           // 67
	CommandRequest          = commands.CCB_REQUEST            // 68
	CommandReverseConnect   = commands.CCB_REVERSE_CONNECT    // 69
	CommandProxyConnect     = commands.CCB_PROXY_CONNECT      // 82 (outbound tunneling)
	CommandGetTunnelAddress = commands.CCB_GET_TUNNEL_ADDRESS // 83 (master->CCB tunnel address)
	CommandAlive            = commands.ALIVE                  // 441
)

// ClassAd attribute names (must match condor_attributes.h exactly).
const (
	AttrCommand     = "Command"
	AttrCCBID       = "CCBID"
	AttrClaimID     = "ClaimId"
	AttrRequestID   = "RequestID"
	AttrMyAddress   = "MyAddress"
	AttrResult      = "Result"
	AttrErrorString = "ErrorString"
	AttrName        = "Name"

	// Tunneling extension (new). Attribute names are proposed by the CCB tunneling
	// design (§4.5) and must be pinned jointly with the C++ implementation, like
	// the CCB_GET_TUNNEL_ADDRESS command int.
	AttrSubsys     = "Subsys"     // master -> CCB: requesting subsystem (debugging)
	AttrCCBAddress = "CCBAddress" // CCB -> master: derived tunnel address

	// Streaming/proxy extension (new; ignored by stock HTCondor).
	AttrCCBStreaming            = "CCBStreaming"            // server -> peer: capability advertisement
	AttrCCBStreamingRequired    = "CCBStreamingRequired"    // requester -> server: this request needs proxying
	AttrProxyMode               = "ProxyMode"               // server -> requester: reply will be proxied on this socket
	AttrCCBStreamingUnsupported = "CCBStreamingUnsupported" // server -> requester: typed "not supported" failure

	// AttrCCBProxyMode tells a TARGET that the request it is being asked to serve
	// is proxied, so the reverse connection goes back to the broker this target
	// registered through rather than to the address the request names.
	//
	// In proxy mode a broker always names its own address in AttrMyAddress, so
	// that field says nothing a target does not already know -- and a target
	// reached through a relay cannot route to it at all, because the only address
	// it can dial is the one it registered through. For an incoming reversal the
	// first hop out is always the target's own broker, which is in its
	// configuration. See golang-ccb docs/SPLICE_HELPER.md.
	AttrCCBProxyMode = "CCBProxyMode"

	// Recursive inbound tunnel (Model 1) + audit. Must match the C++ wire names
	// (src/condor_includes/condor_attributes.h).
	//
	// AttrCCBRoute carries the remaining downstream CCBIDs after this hop's target
	// (space-separated; empty/absent at the final hop). When present, the target is
	// itself a downstream CCB and is asked to recurse: set up the next hop, then
	// reverse-connect and relay. AttrCCBOriginalRequester (stamped by the entry
	// broker from the *authenticated* client) and AttrCCBPriorHop (each forwarder's
	// own address) are the audit trail, forwarded for logging only.
	AttrCCBRoute             = "CCBRoute"
	AttrCCBOriginalRequester = "CCBOriginalRequester"
	AttrCCBPriorHop          = "CCBPriorHop"

	// AttrCCBTTL is the decrementing outbound-proxy time-to-live (like TCP): the
	// originator sets it, each forwarding broker decrements it and refuses at 0.
	AttrCCBTTL = "CCBTTL"
)

// maxControlAdSize caps the size of an inbound control ClassAd (DoS guard).
const maxControlAdSize = 64 * 1024

// GenerateConnectID returns a fresh connect id: 20 random bytes rendered as 40
// hex characters, matching CCBClient's connect-id generation.
func GenerateConnectID() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("ccb: generating connect id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// ContactString builds a CCB contact "<brokerAddr>#<ccbid>" (broker address
// without angle brackets), matching CCBServer::CCBIDToContactString.
func ContactString(brokerAddr string, ccbid uint64) string {
	return fmt.Sprintf("%s#%d", brokerAddr, ccbid)
}

// NewAd builds a ClassAd from a map of attribute values. Supported value types
// are string, int, int64, uint64, and bool.
func NewAd(fields map[string]any) *classad.ClassAd {
	ad := classad.New()
	for k, v := range fields {
		switch t := v.(type) {
		case uint64:
			_ = ad.Set(k, int64(t))
		default:
			_ = ad.Set(k, t)
		}
	}
	return ad
}

// WriteControlAd writes a single control message (one ClassAd terminated by
// end-of-message) on the stream. Used for CCB_REGISTER, CCB_REQUEST forwarding,
// result reports, heartbeats and replies.
func WriteControlAd(ctx context.Context, s *stream.Stream, ad *classad.ClassAd) error {
	msg := message.NewMessageForStream(s)
	// CCB control ads carry ClaimId (the connect id / reconnect cookie) as protocol
	// payload, not as a secret to hide from a peer, so opt in to sending it despite
	// the redact-by-default serialization. This is a point-to-point control channel,
	// not a query response.
	if err := msg.PutClassAdWithOptions(ctx, ad, &message.PutClassAdConfig{
		Options: message.PutClassAdIncludePrivate,
	}); err != nil {
		return fmt.Errorf("ccb: writing control ad: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("ccb: finishing control ad: %w", err)
	}
	return nil
}

// ReadControlAd reads a single control message (one ClassAd) from the stream.
func ReadControlAd(ctx context.Context, s *stream.Stream) (*classad.ClassAd, error) {
	msg := message.NewMessageFromStream(s)
	ad, err := msg.GetClassAdWithMaxSize(ctx, maxControlAdSize)
	if err != nil {
		return nil, fmt.Errorf("ccb: reading control ad: %w", err)
	}
	return ad, nil
}

// WriteReverseConnect writes the raw reverse-connect hello: the
// CCB_REVERSE_CONNECT command integer followed by a ClassAd, in one message.
// The ClassAd carries ClaimId (the connect id), RequestID and MyAddress.
func WriteReverseConnect(ctx context.Context, s *stream.Stream, connectID, requestID, myAddr string) error {
	ad := classad.New()
	_ = ad.Set(AttrClaimID, connectID)
	if requestID != "" {
		_ = ad.Set(AttrRequestID, requestID)
	}
	if myAddr != "" {
		_ = ad.Set(AttrMyAddress, myAddr)
	}
	msg := message.NewMessageForStream(s)
	if err := msg.PutInt(ctx, CommandReverseConnect); err != nil {
		return fmt.Errorf("ccb: writing reverse-connect command: %w", err)
	}
	// The connect id travels as ClaimId; it is this hello's whole purpose, so opt in
	// to sending it past the redact-by-default serialization.
	if err := msg.PutClassAdWithOptions(ctx, ad, &message.PutClassAdConfig{
		Options: message.PutClassAdIncludePrivate,
	}); err != nil {
		return fmt.Errorf("ccb: writing reverse-connect ad: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("ccb: finishing reverse-connect: %w", err)
	}
	return nil
}

// readReverseConnect reads a raw reverse-connect hello (command int + ClassAd)
// from a fresh message and validates the command. Returns the ClassAd.
func readReverseConnect(ctx context.Context, s *stream.Stream) (*classad.ClassAd, error) {
	msg := message.NewMessageFromStream(s)
	cmd, err := msg.GetInt(ctx)
	if err != nil {
		return nil, fmt.Errorf("ccb: reading reverse-connect command: %w", err)
	}
	return ReadReverseConnectAd(ctx, msg, cmd)
}

// ReadReverseConnectAd reads the ClassAd of a reverse-connect hello when the
// command integer has already been consumed from msg (e.g. by a dispatching
// server). It validates that cmd is CCB_REVERSE_CONNECT.
func ReadReverseConnectAd(ctx context.Context, msg *message.Message, cmd int) (*classad.ClassAd, error) {
	if cmd != CommandReverseConnect {
		return nil, fmt.Errorf("ccb: expected CCB_REVERSE_CONNECT (%d), got %d", CommandReverseConnect, cmd)
	}
	ad, err := msg.GetClassAdWithMaxSize(ctx, maxControlAdSize)
	if err != nil {
		return nil, fmt.Errorf("ccb: reading reverse-connect ad: %w", err)
	}
	return ad, nil
}

// AdString returns a string attribute, or "" if absent.
func AdString(ad *classad.ClassAd, name string) string {
	if ad == nil {
		return ""
	}
	v, _ := ad.EvaluateAttrString(name)
	return v
}

// AdInt returns an integer attribute and whether it was present.
func AdInt(ad *classad.ClassAd, name string) (int64, bool) {
	if ad == nil {
		return 0, false
	}
	return ad.EvaluateAttrInt(name)
}

// AdBool returns a boolean attribute and whether it was present.
func AdBool(ad *classad.ClassAd, name string) (bool, bool) {
	if ad == nil {
		return false, false
	}
	return ad.EvaluateAttrBool(name)
}
