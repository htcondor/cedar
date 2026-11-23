package addresses

import (
	"strings"
	"testing"
)

// HTCondor's encoding, not net/url's. The two disagree about the space and
// the plus, and the disagreement is not cosmetic: QueryEscape writes a space
// as '+', and the decoder treats '+' as a literal plus, so the value comes
// back changed.
func TestEncodeParamValueMatchesHTCondor(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"ep1.example.org", "ep1.example.org"},
		{"", ""},
		{"a b", "a%20b"}, // NOT "a+b"
		{"a+b", "a+b"},   // plus passes through
		{"a&b", "a%26b"}, // the separator must never survive raw
		{"a;b", "a%3bb"},
		{"a=b", "a%3db"},
		{"<10.0.0.9:9618>", "%3c10.0.0.9:9618%3e"},
	} {
		if got := EncodeParamValue(tc.in); got != tc.want {
			t.Errorf("EncodeParamValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// What the encoder writes, the parser has to read back unchanged. This is
// the property that makes the pair safe to use on a live address.
func TestEncodedValuesRoundTripThroughTheParser(t *testing.T) {
	for _, v := range []string{"ep1.example.org", "a b", "a+b", "a&b=c;d", "<10.0.0.9:9618?sock=x>"} {
		addr := "<1.2.3.4:9618?alias=" + EncodeParamValue(v) + ">"
		parsed, err := ParseSinful(addr)
		if err != nil {
			t.Fatalf("ParseSinful(%q): %v", addr, err)
		}
		if parsed.Alias != v {
			t.Errorf("alias round-tripped %q as %q", v, parsed.Alias)
		}
	}
}

// The name HTCondor writes is CCBID. A caller asking for "ccbid" has to get
// it removed, or the failure is invisible: the parameter stays, the address
// still parses, and it goes on meaning exactly what the caller was trying to
// stop it meaning.
func TestWithoutParamFoldsKeyCase(t *testing.T) {
	for _, addr := range []string{
		"<192.0.2.9:9618?PrivNet=p&CCBID=192.0.2.1:9618%23123>",
		"<192.0.2.9:9618?PrivNet=p&ccbid=192.0.2.1:9618%23123>",
		"<192.0.2.9:9618?PrivNet=p&CcbId=192.0.2.1:9618%23123>",
	} {
		got := WithoutParam(addr, "ccbid")
		if strings.Contains(strings.ToLower(got), "ccbid") {
			t.Errorf("WithoutParam(%q) left the parameter: %q", addr, got)
		}
		parsed, err := ParseSinful(got)
		if err != nil {
			t.Fatalf("result does not parse: %q: %v", got, err)
		}
		if parsed.IsCCB() {
			t.Errorf("the address still routes through a broker: %q", got)
		}
	}
}

// Everything that stays keeps its bytes, including a parameter this package
// does not model -- which is the reason for editing rather than
// re-serializing.
func TestWithoutParamPreservesEverythingElse(t *testing.T) {
	got := WithoutParam("<1.2.3.4:9618?sock=abc&CCBID=5.6.7.8:9618%239&future=keep%20me&noUDP>", "ccbid")
	for _, want := range []string{"sock=abc", "future=keep%20me", "noUDP"} {
		if !strings.Contains(got, want) {
			t.Errorf("lost %q from %q", want, got)
		}
	}
	if !strings.HasPrefix(got, "<") || !strings.HasSuffix(got, ">") {
		t.Errorf("lost the brackets: %q", got)
	}
}

// Removing the only parameter must not leave a dangling '?'.
func TestWithoutParamDropsAnEmptyQuery(t *testing.T) {
	if got := WithoutParam("<1.2.3.4:9618?CCBID=5.6.7.8:9618%239>", "ccbid"); got != "<1.2.3.4:9618>" {
		t.Errorf("got %q, want a bare sinful", got)
	}
}

func TestWithoutParamLeavesUnrelatedAddressesAlone(t *testing.T) {
	for _, addr := range []string{"<1.2.3.4:9618>", "1.2.3.4:9618", "<1.2.3.4:9618?sock=a>"} {
		if got := WithoutParam(addr, "ccbid"); got != addr {
			t.Errorf("WithoutParam(%q) = %q, want it unchanged", addr, got)
		}
	}
}

func TestWithParamAddsAndReplaces(t *testing.T) {
	// Added to an address that had no query string at all.
	got := WithParam("<10.0.0.9:9618>", "alias", "ep1.example.org")
	parsed, err := ParseSinful(got)
	if err != nil {
		t.Fatalf("ParseSinful(%q): %v", got, err)
	}
	if parsed.Alias != "ep1.example.org" {
		t.Errorf("alias = %q in %q", parsed.Alias, got)
	}

	// Replaced rather than duplicated, and matched case-insensitively.
	twice := WithParam(WithParam("<10.0.0.9:9618>", "alias", "first"), "ALIAS", "second")
	if strings.Count(strings.ToLower(twice), "alias=") != 1 {
		t.Errorf("the parameter was duplicated: %q", twice)
	}
	parsed, err = ParseSinful(twice)
	if err != nil {
		t.Fatalf("ParseSinful(%q): %v", twice, err)
	}
	if parsed.Alias != "second" {
		t.Errorf("alias = %q, want the replacement", parsed.Alias)
	}
}

// A value carrying a separator must not be able to forge a second parameter.
func TestWithParamCannotInjectAParameter(t *testing.T) {
	got := WithParam("<10.0.0.9:9618>", "alias", "x&CCBID=evil:9618%231")
	parsed, err := ParseSinful(got)
	if err != nil {
		t.Fatalf("ParseSinful(%q): %v", got, err)
	}
	if parsed.IsCCB() {
		t.Errorf("a value smuggled in a broker contact: %q", got)
	}
	// The value comes back exactly as given -- the '%' in it is literal
	// text, escaped and restored, not an escape sequence of its own.
	const want = "x&CCBID=evil:9618%231"
	if parsed.Alias != want {
		t.Errorf("alias = %q, want %q: the whole value as one parameter", parsed.Alias, want)
	}
}

// An address with bytes after the closing '>' -- an address file's version
// line, or a peer's malformed advertisement -- must still be edited inside
// the brackets, where a parser will see the parameter. ParseSinful and
// ParseHTCondorAddress both end the body at the first '>'; the editors have
// to read it the same way, and the trailing bytes come back untouched.
func TestEditsLandInsideTheBracketsWithATrailer(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{
			name: "WithParam replaces an existing pair",
			in:   "<1.2.3.4:9618?sock=x&alias=h>\n$CondorVersion: 23.0.0$",
			want: "<1.2.3.4:9618?alias=h&sock=y>\n$CondorVersion: 23.0.0$",
		},
		{
			name: "WithParam adds to an address with no query",
			in:   "<10.0.0.1:9618>X",
			want: "<10.0.0.1:9618?sock=y>X",
		},
		{
			name: "no trailer is still the ordinary case",
			in:   "<1.2.3.4:9618?alias=h>",
			want: "<1.2.3.4:9618?alias=h&sock=y>",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := WithParam(tc.in, "sock", "y"); got != tc.want {
				t.Errorf("WithParam(%q, \"sock\", \"y\") = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	// The point of putting it inside: the edit has to survive a reparse.
	const in = "<1.2.3.4:9618?sock=x&alias=h>\n$CondorVersion: 23.0.0$"
	got := WithParam(in, "sock", "y")
	parsed, err := ParseSinful(got)
	if err != nil {
		t.Fatalf("ParseSinful(%q): %v", got, err)
	}
	if parsed.SharedPortID != "y" {
		t.Errorf("SharedPortID = %q, want %q: the edit was written outside the brackets", parsed.SharedPortID, "y")
	}
	if parsed.Alias != "h" {
		t.Errorf("Alias = %q, want %q: an untouched parameter was lost", parsed.Alias, "h")
	}

	// WithoutParam reads the body the same way and keeps the trailer.
	const withoutWant = "<1.2.3.4:9618?sock=x>\n$CondorVersion: 23.0.0$"
	if got := WithoutParam(in, "alias"); got != withoutWant {
		t.Errorf("WithoutParam(%q, \"alias\") = %q, want %q", in, got, withoutWant)
	}
}

// The privnet rewrite in golang-htcondor carries an SSL alias onto a peer's
// advertised private address, which is url-decoded and may therefore contain
// a '>'. Losing the alias there sends an SSL dial to check the certificate
// against a bare IP.
func TestWithParamKeepsAnAliasOnADecodedPrivateAddress(t *testing.T) {
	got := WithParam("<10.0.0.1:9618>X", "alias", "ep1.example.org")
	parsed, err := ParseSinful(got)
	if err != nil {
		t.Fatalf("ParseSinful(%q): %v", got, err)
	}
	if parsed.Alias != "ep1.example.org" {
		t.Errorf("Alias = %q, want %q (from %q)", parsed.Alias, "ep1.example.org", got)
	}
}
