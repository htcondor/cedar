// Package ca implements HTCondor's ClassAd-command ("CA command") protocol --
// the request/reply form used by condor_startd and friends for verbs whose
// argument is a whole ClassAd rather than a fixed list of fields.
//
// A CA command is dispatched by a string, not by its own command integer. The
// integer put on the wire is one of two entry points -- commands.CA_AUTH_CMD
// (1000) when the client forces authentication, commands.CA_CMD (1200) when it
// does not -- and the daemon then reads the Command attribute out of the
// request ad to decide which verb to run. The exchange is:
//
//	client -> daemon:  command CA_AUTH_CMD, then one request ClassAd
//	                   [ MyType = "Command"; TargetType = "Reply";
//	                     Command = "<verb>"; plus the caller's payload ]
//	daemon -> client:  one reply ClassAd
//	                   [ Result = "Success", or a failure name plus ErrorString ]
//
// Both ads are ordinary CEDAR ClassAd messages, each terminated by an
// end-of-message. This mirrors Daemon::sendCACmd in the C++ tree.
package ca

import (
	"context"
	"errors"
	"fmt"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// Attribute names of the CA protocol.
const (
	// AttrCommand carries the verb string the daemon dispatches on.
	AttrCommand = "Command"
	// AttrResult carries the outcome in the reply ad.
	AttrResult = "Result"
	// AttrErrorString carries the daemon's explanation of a failed Result.
	AttrErrorString = "ErrorString"

	attrMyType     = "MyType"
	attrTargetType = "TargetType"
)

// Ad types of the request and the reply.
const (
	CommandAdType = "Command"
	ReplyAdType   = "Reply"
)

// ResultSuccess is the only Result value that means the daemon ran the command;
// every other value is a failure (CAResult in condor_utils/command_strings.h).
const ResultSuccess = "Success"

// CmdUpdateMachineAd is the verb string for commands.CA_UPDATE_MACHINE_AD.
const CmdUpdateMachineAd = "CA_UPDATE_MACHINE_AD"

// ResultError reports a CA command that reached the daemon and was refused: the
// reply ad arrived intact but carried a Result other than ResultSuccess. It is
// distinct from a transport error, so a caller can tell "the startd said no"
// from "the startd was unreachable".
type ResultError struct {
	// Command is the verb that was sent.
	Command string
	// Result is the Result attribute from the reply ("Failure",
	// "NotAuthorized", ...).
	Result string
	// Reason is the reply's ErrorString, empty if the daemon sent none.
	Reason string
}

func (e *ResultError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("%s failed: %s: %s", e.Command, e.Result, e.Reason)
	}
	return fmt.Sprintf("%s failed: %s", e.Command, e.Result)
}

// BuildRequest returns the request ad for a CA command: the caller's payload
// plus the protocol attributes (Command, MyType, TargetType). payload may be nil
// for a verb that takes no arguments. The caller's ad is never modified; any
// Command, MyType or TargetType it already carries is overwritten in the copy.
func BuildRequest(command string, payload *classad.ClassAd) (*classad.ClassAd, error) {
	if command == "" {
		return nil, errors.New("ca: empty command string")
	}

	req := classad.New()
	if payload != nil {
		for _, attr := range payload.GetAttributes() {
			if expr, ok := payload.Lookup(attr); ok {
				req.InsertExpr(attr, expr)
			}
		}
	}

	req.InsertAttrString(attrMyType, CommandAdType)
	req.InsertAttrString(attrTargetType, ReplyAdType)
	req.InsertAttrString(AttrCommand, command)
	return req, nil
}

// Exchange runs one CA command on an already-connected, already-authenticated
// CEDAR stream whose handshake named the matching entry-point command integer,
// and returns the daemon's reply ad.
//
// A reply whose Result is not ResultSuccess is returned as a *ResultError along
// with the reply ad itself, so a caller that understands the daemon's extra
// reply attributes can still read them.
func Exchange(ctx context.Context, s *stream.Stream, command string, payload *classad.ClassAd) (*classad.ClassAd, error) {
	if s == nil {
		return nil, errors.New("ca: no stream")
	}
	req, err := BuildRequest(command, payload)
	if err != nil {
		return nil, err
	}

	msg := message.NewMessageForStream(s)
	if err := msg.PutClassAd(ctx, req); err != nil {
		return nil, fmt.Errorf("ca: failed to send %s request ad: %w", command, err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("ca: failed to send %s request: %w", command, err)
	}

	reply, err := message.NewMessageFromStream(s).GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("ca: failed to read %s reply ad: %w", command, err)
	}

	result, ok := reply.EvaluateAttrString(AttrResult)
	if !ok {
		return reply, fmt.Errorf("ca: %s reply ad has no %s attribute", command, AttrResult)
	}
	if result != ResultSuccess {
		reason, _ := reply.EvaluateAttrString(AttrErrorString)
		return reply, &ResultError{Command: command, Result: result, Reason: reason}
	}
	return reply, nil
}

// UpdateMachineAd pushes the attributes of payload into the machine ad of the
// startd at target, a sinful string or "host:port". sec supplies the security
// policy; it is not modified -- UpdateMachineAd copies it and sets the command
// and the forced authentication the protocol requires. The startd authorizes
// this at the WRITE level.
//
// Two semantics callers routinely get wrong:
//
// The startd merges payload into a single machine-wide "extras" ad, attribute by
// attribute. It is not per-slot -- every slot ad published by that startd gets
// the attributes -- and it is not a whole-ad replace: attributes already in the
// extras ad that payload does not mention are left alone. MyType and TargetType
// are dropped by the startd; every other attribute is merged, including Command.
// Attributes named Has<Universe> additionally drive the startd's
// OfflineUniverses bookkeeping.
//
// There is no delete path and no TTL: an attribute pushed this way lives until
// the startd restarts. Push absolute deadlines rather than booleans, so that a
// value left behind by a crashed pusher expires harmlessly on its own, and
// retire a value by overwriting it -- never by expecting it to be removed.
func UpdateMachineAd(ctx context.Context, target string, sec *security.SecurityConfig, payload *classad.ClassAd) error {
	return UpdateMachineAdWithConfig(ctx, &client.ClientConfig{
		Address:  target,
		Security: sec,
	}, payload)
}

// UpdateMachineAdWithConfig is UpdateMachineAd with full control over the
// connection: timeout, CCB return address, shared-port client name. The
// config's Security is used as the security policy and must not be nil; the
// config itself is not modified.
func UpdateMachineAdWithConfig(ctx context.Context, config *client.ClientConfig, payload *classad.ClassAd) error {
	_, err := SendWithConfig(ctx, config, CmdUpdateMachineAd, payload)
	return err
}

// SendWithConfig connects to the daemon named by config, authenticates, runs one
// CA command and returns the reply ad. It is the generic form behind
// UpdateMachineAd; use it for any other CA verb.
//
// The connection is always authenticated (the CA_AUTH_CMD entry point, matching
// the force_auth path of the C++ Daemon::sendCACmd) and is closed before
// returning.
func SendWithConfig(ctx context.Context, config *client.ClientConfig, command string, payload *classad.ClassAd) (*classad.ClassAd, error) {
	if config == nil {
		return nil, errors.New("ca: no client configuration")
	}
	if config.Security == nil {
		return nil, errors.New("ca: no security configuration")
	}

	// Copy both the client config and the security config: the caller's values
	// are the caller's, and a CA command dictates the command integer and
	// mandates authentication.
	connConfig := *config
	secConfig := *config.Security
	secConfig.Command = commands.CA_AUTH_CMD
	secConfig.AuthCommand = 0 // CA_AUTH_CMD carries no sub-command
	secConfig.Authentication = security.SecurityRequired
	connConfig.Security = &secConfig

	htcondorClient, err := client.ConnectAndAuthenticateWithConfig(ctx, &connConfig)
	if err != nil {
		return nil, fmt.Errorf("ca: failed to connect to %s for %s: %w", config.Address, command, err)
	}
	defer func() { _ = htcondorClient.Close() }()

	return Exchange(ctx, htcondorClient.GetStream(), command, payload)
}
