package ca

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// TestCommandNumbers pins the wire constants against condor_commands.h. The
// integer that goes on the wire for a CA command is the entry point
// CA_AUTH_CMD, NOT the per-verb CA_UPDATE_MACHINE_AD -- the verb travels as a
// string inside the ad -- so both are pinned here, as is the spelling of that
// string, which the startd compares exactly.
func TestCommandNumbers(t *testing.T) {
	if commands.CA_AUTH_CMD_BASE != 1000 {
		t.Errorf("CA_AUTH_CMD_BASE = %d, want 1000", commands.CA_AUTH_CMD_BASE)
	}
	if commands.CA_AUTH_CMD != 1000 {
		t.Errorf("CA_AUTH_CMD = %d, want 1000", commands.CA_AUTH_CMD)
	}
	if commands.CA_CMD != 1200 {
		t.Errorf("CA_CMD = %d, want 1200", commands.CA_CMD)
	}
	if commands.CA_UPDATE_MACHINE_AD != 1009 {
		t.Errorf("CA_UPDATE_MACHINE_AD = %d, want 1009", commands.CA_UPDATE_MACHINE_AD)
	}
	if got := commands.GetCommandName(commands.CA_UPDATE_MACHINE_AD); got != CmdUpdateMachineAd {
		t.Errorf("GetCommandName(CA_UPDATE_MACHINE_AD) = %q, want %q", got, CmdUpdateMachineAd)
	}
	if CmdUpdateMachineAd != "CA_UPDATE_MACHINE_AD" {
		t.Errorf("CmdUpdateMachineAd = %q", CmdUpdateMachineAd)
	}
}

func TestBuildRequest(t *testing.T) {
	payload, err := classad.ParseOld("DetectedGPUs = 4\nGPUDeadline = 1762500000")
	if err != nil {
		t.Fatal(err)
	}

	req, err := BuildRequest(CmdUpdateMachineAd, payload)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}

	if v, ok := req.EvaluateAttrString(AttrCommand); !ok || v != CmdUpdateMachineAd {
		t.Errorf("Command = %q ok=%v, want %q", v, ok, CmdUpdateMachineAd)
	}
	if v, ok := req.EvaluateAttrString("MyType"); !ok || v != CommandAdType {
		t.Errorf("MyType = %q ok=%v, want %q", v, ok, CommandAdType)
	}
	if v, ok := req.EvaluateAttrString("TargetType"); !ok || v != ReplyAdType {
		t.Errorf("TargetType = %q ok=%v, want %q", v, ok, ReplyAdType)
	}
	if v, ok := req.EvaluateAttrInt("DetectedGPUs"); !ok || v != 4 {
		t.Errorf("DetectedGPUs = %d ok=%v, want 4", v, ok)
	}
	if v, ok := req.EvaluateAttrInt("GPUDeadline"); !ok || v != 1762500000 {
		t.Errorf("GPUDeadline = %d ok=%v, want 1762500000", v, ok)
	}

	// The caller's ad is theirs: we must not have written the protocol
	// attributes into it.
	for _, attr := range []string{AttrCommand, "MyType", "TargetType"} {
		if _, ok := payload.Lookup(attr); ok {
			t.Errorf("BuildRequest wrote %s into the caller's payload", attr)
		}
	}
}

// TestBuildRequestOverwritesCallerCommand: a payload that already carries
// Command/MyType/TargetType must not be able to misdirect the command.
func TestBuildRequestOverwritesCallerCommand(t *testing.T) {
	payload, err := classad.ParseOld(`Command = "CA_SUSPEND_CLAIM"` + "\n" + `MyType = "Machine"` + "\n" + `TargetType = "Job"`)
	if err != nil {
		t.Fatal(err)
	}
	req, err := BuildRequest(CmdUpdateMachineAd, payload)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := req.EvaluateAttrString(AttrCommand); v != CmdUpdateMachineAd {
		t.Errorf("Command = %q, want %q", v, CmdUpdateMachineAd)
	}
	if v, _ := req.EvaluateAttrString("MyType"); v != CommandAdType {
		t.Errorf("MyType = %q, want %q", v, CommandAdType)
	}
	if v, _ := req.EvaluateAttrString("TargetType"); v != ReplyAdType {
		t.Errorf("TargetType = %q, want %q", v, ReplyAdType)
	}
}

func TestBuildRequestNilPayload(t *testing.T) {
	req, err := BuildRequest(CmdUpdateMachineAd, nil)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	if req.Size() != 3 {
		t.Errorf("Size = %d, want 3 (Command, MyType, TargetType): %s", req.Size(), req.MarshalOld())
	}
}

func TestBuildRequestEmptyCommand(t *testing.T) {
	if _, err := BuildRequest("", nil); err == nil {
		t.Fatal("BuildRequest(\"\") succeeded, want error")
	}
}

// fakeDaemon stands in for a startd on the far end of an in-process CEDAR
// stream: it reads exactly one request ad and answers with reply. The request
// it saw is handed back so the test can assert on the encoding.
type fakeDaemon struct {
	wg      sync.WaitGroup
	request *classad.ClassAd
	err     error
}

// startFakeDaemon wires a client stream to an in-process peer that answers one
// CA command with reply. A nil reply makes the peer hang up after reading the
// request.
func startFakeDaemon(t *testing.T, reply *classad.ClassAd) (*stream.Stream, *fakeDaemon) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	clientStream := stream.NewStream(clientConn)
	serverStream := stream.NewStream(serverConn)

	d := &fakeDaemon{}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req, err := message.NewMessageFromStream(serverStream).GetClassAd(ctx)
		if err != nil {
			d.err = err
			return
		}
		d.request = req

		if reply == nil {
			// Hang up, the way a daemon that died mid-command would.
			_ = serverConn.Close()
			return
		}
		msg := message.NewMessageForStream(serverStream)
		if err := msg.PutClassAd(ctx, reply); err != nil {
			d.err = err
			return
		}
		if err := msg.FinishMessage(ctx); err != nil {
			d.err = err
		}
	}()

	return clientStream, d
}

// testContext bounds every exchange in this file: an in-process net.Pipe has no
// deadlines of its own, so a protocol bug would otherwise hang the suite rather
// than fail it.
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func mustParse(t *testing.T, text string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.ParseOld(text)
	if err != nil {
		t.Fatal(err)
	}
	return ad
}

// TestExchangeSuccess covers the happy path end to end over a real CEDAR
// stream: the request encoding the startd will see, and a "Success" reply.
func TestExchangeSuccess(t *testing.T) {
	ctx := testContext(t)
	s, d := startFakeDaemon(t, mustParse(t, `Result = "Success"`))

	payload := mustParse(t, "WantVPN = true\nVPNLeaseExpiration = 1762500000")
	reply, err := Exchange(ctx, s, CmdUpdateMachineAd, payload)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	d.wg.Wait()
	if d.err != nil {
		t.Fatalf("fake daemon: %v", d.err)
	}

	if v, _ := reply.EvaluateAttrString(AttrResult); v != ResultSuccess {
		t.Errorf("reply Result = %q, want %q", v, ResultSuccess)
	}

	got := d.request
	if v, ok := got.EvaluateAttrString(AttrCommand); !ok || v != CmdUpdateMachineAd {
		t.Errorf("request Command = %q ok=%v, want %q", v, ok, CmdUpdateMachineAd)
	}
	if v, ok := got.EvaluateAttrString("MyType"); !ok || v != CommandAdType {
		t.Errorf("request MyType = %q ok=%v, want %q", v, ok, CommandAdType)
	}
	if v, ok := got.EvaluateAttrString("TargetType"); !ok || v != ReplyAdType {
		t.Errorf("request TargetType = %q ok=%v, want %q", v, ok, ReplyAdType)
	}
	if v, ok := got.EvaluateAttrBool("WantVPN"); !ok || !v {
		t.Errorf("request WantVPN = %v ok=%v, want true", v, ok)
	}
	if v, ok := got.EvaluateAttrInt("VPNLeaseExpiration"); !ok || v != 1762500000 {
		t.Errorf("request VPNLeaseExpiration = %d ok=%v, want 1762500000", v, ok)
	}
}

// TestExchangeFailureReply: the startd answered, and said no. That must surface
// as a *ResultError carrying the daemon's own text, not as a transport error,
// and the reply ad must still come back.
func TestExchangeFailureReply(t *testing.T) {
	ctx := testContext(t)
	s, _ := startFakeDaemon(t, mustParse(t,
		`Result = "Failure"`+"\n"+`ErrorString = "Unable to update machine ad."`))

	reply, err := Exchange(ctx, s, CmdUpdateMachineAd, nil)
	if err == nil {
		t.Fatal("Exchange succeeded, want failure")
	}
	if reply == nil {
		t.Fatal("Exchange returned no reply ad alongside the error")
	}

	var rerr *ResultError
	if !errors.As(err, &rerr) {
		t.Fatalf("error is %T (%v), want *ResultError", err, err)
	}
	if rerr.Command != CmdUpdateMachineAd {
		t.Errorf("Command = %q, want %q", rerr.Command, CmdUpdateMachineAd)
	}
	if rerr.Result != "Failure" {
		t.Errorf("Result = %q, want Failure", rerr.Result)
	}
	if rerr.Reason != "Unable to update machine ad." {
		t.Errorf("Reason = %q", rerr.Reason)
	}
	if !strings.Contains(err.Error(), "Unable to update machine ad.") {
		t.Errorf("Error() = %q, want the daemon's text in it", err.Error())
	}
}

// TestExchangeFailureWithoutErrorString: a known failure with no ErrorString is
// still an error; the Result name has to carry the message on its own.
func TestExchangeFailureWithoutErrorString(t *testing.T) {
	s, _ := startFakeDaemon(t, mustParse(t, `Result = "NotAuthorized"`))

	_, err := Exchange(testContext(t), s, CmdUpdateMachineAd, nil)
	var rerr *ResultError
	if !errors.As(err, &rerr) {
		t.Fatalf("error is %T (%v), want *ResultError", err, err)
	}
	if rerr.Result != "NotAuthorized" || rerr.Reason != "" {
		t.Errorf("got Result=%q Reason=%q, want NotAuthorized and no reason", rerr.Result, rerr.Reason)
	}
	if !strings.Contains(err.Error(), "NotAuthorized") {
		t.Errorf("Error() = %q", err.Error())
	}
}

// TestExchangeReplyWithoutResult: a reply ad with no Result is not a success.
// The C++ client treats an unrecognized Result leniently; we do not, because a
// silent "it worked" on an ad we cannot interpret is the worse failure.
func TestExchangeReplyWithoutResult(t *testing.T) {
	s, _ := startFakeDaemon(t, mustParse(t, `SomethingElse = 1`))

	_, err := Exchange(testContext(t), s, CmdUpdateMachineAd, nil)
	if err == nil {
		t.Fatal("Exchange succeeded on a reply with no Result")
	}
	var rerr *ResultError
	if errors.As(err, &rerr) {
		t.Errorf("error is a *ResultError (%v); a missing Result is a protocol error", err)
	}
	if !strings.Contains(err.Error(), AttrResult) {
		t.Errorf("Error() = %q, want it to name %s", err.Error(), AttrResult)
	}
}

// TestExchangeNoReply: the peer hangs up after reading the request. That is a
// transport error, not a ResultError.
func TestExchangeNoReply(t *testing.T) {
	s, d := startFakeDaemon(t, nil)

	_, err := Exchange(testContext(t), s, CmdUpdateMachineAd, nil)
	d.wg.Wait()
	if err == nil {
		t.Fatal("Exchange succeeded with no reply")
	}
	var rerr *ResultError
	if errors.As(err, &rerr) {
		t.Errorf("error is a *ResultError (%v), want a transport error", err)
	}
}

func TestExchangeNilStream(t *testing.T) {
	if _, err := Exchange(testContext(t), nil, CmdUpdateMachineAd, nil); err == nil {
		t.Fatal("Exchange on a nil stream succeeded")
	}
}

func TestSendWithConfigRejectsMissingConfig(t *testing.T) {
	if _, err := SendWithConfig(testContext(t), nil, CmdUpdateMachineAd, nil); err == nil {
		t.Fatal("SendWithConfig(nil config) succeeded")
	}
	if err := UpdateMachineAd(testContext(t), "startd.example.com:9618", nil, nil); err == nil {
		t.Fatal("UpdateMachineAd with no security config succeeded")
	}
}

func TestResultErrorMessage(t *testing.T) {
	withReason := (&ResultError{Command: "CA_UPDATE_MACHINE_AD", Result: "Failure", Reason: "nope"}).Error()
	if withReason != "CA_UPDATE_MACHINE_AD failed: Failure: nope" {
		t.Errorf("Error() = %q", withReason)
	}
	bare := (&ResultError{Command: "CA_UPDATE_MACHINE_AD", Result: "Failure"}).Error()
	if bare != "CA_UPDATE_MACHINE_AD failed: Failure" {
		t.Errorf("Error() = %q", bare)
	}
}
