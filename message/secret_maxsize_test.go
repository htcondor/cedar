package message

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/stream"
)

// A peer must not escape the size cap by prefixing an expression with the
// secret marker. The marker itself fits any budget, and the oversized field
// behind it used to be read by the unlimited GetString and only counted after
// it was already in memory -- so the 4 KiB caps in the security handshake and
// the 64 KiB cap on inbound CCB control ads, both read from peers that are not
// yet authenticated, gave no protection at all.
//
// On a stream with no session key PrepareCryptoForSecret is a no-op, so this
// works over a plain unauthenticated connection.
func TestSizeLimitedClassAdBoundsSecretExpression(t *testing.T) {
	const maxSize = 4096
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	ctx := context.Background()

	// One expression, sent as SecretMarker followed by a 4 MiB attribute --
	// a thousand times the cap.
	huge := `Attr = "` + strings.Repeat("A", 4<<20) + `"`

	// net.Pipe is synchronous and unbuffered, so the sender can only finish if
	// the reader actually consumed every byte. That -- not the eventual error --
	// is what distinguishes bounding the read from reading it all and only then
	// noticing the budget is blown.
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		out := NewMessageForStream(stream.NewStream(peer))
		_ = out.PutInt(ctx, 1)
		_ = out.PutString(ctx, SecretMarker)
		_ = out.PutString(ctx, huge)
		_ = out.PutString(ctx, "Machine")
		_ = out.PutString(ctx, "Job")
		_ = out.FinishMessage(ctx)
	}()

	m := NewMessageFromStream(stream.NewStream(local))
	ad, err := m.GetClassAdWithMaxSize(ctx, maxSize)
	if err == nil {
		t.Fatalf("accepted a %d-byte secret expression under a %d-byte cap; ad = %v", len(huge), maxSize, ad)
	}

	select {
	case <-sent:
		t.Errorf("the whole %d-byte secret field was consumed under a %d-byte cap: "+
			"the read was not bounded, it was merely counted afterwards (error was: %v)", len(huge), maxSize, err)
	case <-time.After(500 * time.Millisecond):
		// Sender still blocked: the reader stopped at its budget. Correct.
	}
}

// A secret expression within the budget still reads, so the cap is not applied
// so eagerly that legitimate private attributes break.
func TestSizeLimitedClassAdReadsSmallSecretExpression(t *testing.T) {
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	ctx := context.Background()

	go func() {
		out := NewMessageForStream(stream.NewStream(peer))
		_ = out.PutInt(ctx, 1)
		_ = out.PutString(ctx, SecretMarker)
		_ = out.PutString(ctx, `ClaimId = "secret-claim"`)
		_ = out.PutString(ctx, "Machine")
		_ = out.PutString(ctx, "Job")
		_ = out.FinishMessage(ctx)
	}()

	m := NewMessageFromStream(stream.NewStream(local))
	ad, err := m.GetClassAdWithMaxSize(ctx, 4096)
	if err != nil {
		t.Fatalf("rejected a secret expression well inside the cap: %v", err)
	}
	if v, ok := ad.EvaluateAttrString("ClaimId"); !ok || v != "secret-claim" {
		t.Errorf("ClaimId = %q (ok=%v), want \"secret-claim\"", v, ok)
	}
}
