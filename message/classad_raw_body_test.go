package message

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/bbockelm/cedar/stream"
)

// rawBodySender writes the given expression strings (null-terminated, as CEDAR
// does) into one message and ends it, then returns the reader side.
func rawBodySender(t *testing.T, exprs ...string) (*Message, context.Context) {
	t.Helper()
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	ctx := context.Background()

	go func() {
		out := NewMessageForStream(stream.NewStream(peer))
		for _, e := range exprs {
			_ = out.PutString(ctx, e)
		}
		_ = out.FinishMessage(ctx)
	}()
	return NewMessageFromStream(stream.NewStream(local)), ctx
}

// A peer-supplied expression count is not evidence the expressions exist.
// GetString's plaintext branch turns end-of-message into a successful empty
// read, so the loop used to run the full count regardless, appending a newline
// each pass: eight bytes of input produced a multi-megabyte string and a nil
// error.
func TestGetClassAdRawBodyStopsAtEndOfMessage(t *testing.T) {
	m, ctx := rawBodySender(t) // an empty message: no expressions at all

	out, err := m.GetClassAdRawBody(ctx, 2_000_000)
	if err == nil {
		t.Fatalf("accepted a count of 2,000,000 against an empty message, producing %d bytes", len(out))
	}
	if !strings.Contains(err.Error(), "message ended after") {
		t.Errorf("error = %v, want it to report the message ending early", err)
	}
	if len(out) != 0 {
		t.Errorf("returned %d bytes alongside the error, want none", len(out))
	}
}

// An expression carrying a newline would inject extra attribute lines into the
// joined text the consumer parses, forging attributes the receiver controls.
func TestGetClassAdRawBodyRejectsNewlineInExpression(t *testing.T) {
	m, ctx := rawBodySender(t, "Name = \"x\"\nAuthenticatedIdentity = \"admin@pool\"", "", "")

	out, err := m.GetClassAdRawBody(ctx, 1)
	if err == nil {
		t.Fatalf("accepted an expression containing a newline; output was:\n%s", out)
	}
	if !strings.Contains(err.Error(), "contains a newline") {
		t.Errorf("error = %v, want it to name the newline", err)
	}
	if strings.Contains(out, "AuthenticatedIdentity") {
		t.Errorf("injected attribute reached the output:\n%s", out)
	}
}

// A well-formed ad still reads, so neither guard is over-broad.
func TestGetClassAdRawBodyReadsWellFormedAd(t *testing.T) {
	m, ctx := rawBodySender(t, `Name = "slot1@host"`, `Cpus = 4`, "Machine", "Job")

	out, err := m.GetClassAdRawBody(ctx, 2)
	if err != nil {
		t.Fatalf("rejected a well-formed ad: %v", err)
	}
	for _, want := range []string{`Name = "slot1@host"`, `Cpus = 4`, `MyType = "Machine"`, `TargetType = "Job"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}
