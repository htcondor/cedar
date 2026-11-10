package message

import (
	"context"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestWireValuesAreOldClassAd pins the rule the CEDAR wire actually follows: a value is
// OLD-ClassAd text, so its string literals get no escape conversion at all. A backslash
// is a literal byte and \" is the only escape.
//
// The reference is unconditional about this -- getClassAd() parses every expression with
// SetOldClassAd(true) -- and reading these with new-ClassAd rules does not fail, it
// quietly returns a different value.
func TestWireValuesAreOldClassAd(t *testing.T) {
	cases := []struct {
		name string
		expr string // "Attr = value", exactly as it arrives on the wire
		attr string
		want string
	}{
		// Escapes the new syntax does not define. New-ClassAd lexing drops the
		// backslash, so these come back subtly wrong rather than rejected.
		{"agetty issue", `OSIssue = "\S"`, "OSIssue", `\S`},
		{"agetty issue, full", `OSIssue = "\S \r (\l)"`, "OSIssue", `\S \r (\l)`},
		{"regex host blocklist", `Requirements = "warlock21\.beocat\.ksu\.edu"`, "Requirements", `warlock21\.beocat\.ksu\.edu`},
		{"escaped comma and space", `TransferInput = "testing\,\ more"`, "TransferInput", `testing\,\ more`},

		// Escapes the new syntax DOES define. Old-ClassAd lexing still does not
		// interpret them: \n stays two characters and \\ stays two backslashes.
		// This is where the two syntaxes disagree most quietly.
		{"backslash-n is not a newline", `Banner = "a\nb"`, "Banner", `a\nb`},
		{"double backslash is not one", `Path = "C:\\tmp"`, "Path", `C:\\tmp`},
		{"windows path", `Scratch = "C:\temp\new"`, "Scratch", `C:\temp\new`},

		// The one escape old-ClassAd does honor.
		{"escaped quote", `Msg = "he said \"hi\""`, "Msg", `he said "hi"`},

		// No escapes: identical under either syntax.
		{"plain", `Arch = "X86_64"`, "Arch", "X86_64"},
	}
	for _, c := range cases {
		ad := classad.New()
		if err := parseAndInsertExpression(ad, c.expr); err != nil {
			t.Errorf("%s: parseAndInsertExpression(%s) errored: %v", c.name, c.expr, err)
			continue
		}
		if got, ok := ad.EvaluateAttrString(c.attr); !ok || got != c.want {
			t.Errorf("%s: %s -> %s = %q (ok=%v), want %q", c.name, c.expr, c.attr, got, ok, c.want)
		}
	}
}

// TestWireExpressionsStillParse guards the other half: most wire values are not string
// literals, and reading them as old-ClassAd must leave them as working expressions.
func TestWireExpressionsStillParse(t *testing.T) {
	ad := classad.New()
	for _, expr := range []string{
		`Requirements = (TARGET.Arch == "X86_64") && (TARGET.Memory > 1024)`,
		`Rank = 0`,
		`Cpus = 8`,
		`Load = 0.5`,
		`Ready = true`,
		`Sum = 1 + 2`,
	} {
		if err := parseAndInsertExpression(ad, expr); err != nil {
			t.Errorf("parseAndInsertExpression(%s) errored: %v", expr, err)
		}
	}
	if v, ok := ad.EvaluateAttrInt("Sum"); !ok || v != 3 {
		t.Errorf("Sum = %d (ok=%v), want 3 -- the expression was not evaluated", v, ok)
	}
	if v, ok := ad.EvaluateAttrInt("Cpus"); !ok || v != 8 {
		t.Errorf("Cpus = %d (ok=%v), want 8", v, ok)
	}
	if v, ok := ad.EvaluateAttrBool("Ready"); !ok || !v {
		t.Errorf("Ready = %v (ok=%v), want true", v, ok)
	}
}

// TestBackslashStringSurvivesRoundTrip is the guarantee the two halves have to agree on:
// a value put on the wire by this package must read back unchanged. Reading as
// old-ClassAd while writing with new-ClassAd escaping would double every backslash on
// each hop.
func TestBackslashStringSurvivesRoundTrip(t *testing.T) {
	values := []string{
		`\S`,
		`\S \r (\l)`,
		`warlock21\.beocat\.ksu\.edu`,
		`C:\temp\new`,
		`testing\,\ more`,
		`he said "hi"`,
		"X86_64",
	}
	ctx := context.Background()
	for _, want := range values {
		s := NewMockStream(false)
		send := classad.New()
		_ = send.Set("Value", want)
		enc := NewMessageForStream(s)
		if err := enc.PutClassAd(ctx, send); err != nil {
			t.Fatalf("PutClassAd(%q): %v", want, err)
		}
		if err := enc.FinishMessage(ctx); err != nil {
			t.Fatalf("FinishMessage(%q): %v", want, err)
		}
		got, err := NewMessageFromStream(s).GetClassAd(ctx)
		if err != nil {
			t.Fatalf("GetClassAd(%q): %v", want, err)
		}
		if v, ok := got.EvaluateAttrString("Value"); !ok || v != want {
			t.Errorf("round trip of %q gave %q (ok=%v)", want, v, ok)
		}
	}
}
