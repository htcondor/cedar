package addresses

import (
	"fmt"
	"strings"
)

// Editing a sinful without re-serializing it.
//
// ParseSinful reads an address apart; these put one back together with a
// parameter added or removed, which is what a caller rewriting an address
// needs -- dropping a broker contact to dial a daemon directly, carrying an
// alias onto a different address.
//
// They work on the string rather than on a parsed SinfulInfo on purpose.
// Re-serializing would rewrite every parameter, including ones this package
// does not model and ones whose escaping it would spell differently, and a
// caller that only wanted to drop a broker would find the rest of the
// address subtly restated. Editing in place changes the pair that was asked
// about and leaves every other byte alone.
//
// Splitting the query string is unambiguous because HTCondor escapes the
// separators inside values: EncodeParamValue below never emits a raw '&' or
// ';', and neither does the C++ side.

// EncodeParamValue escapes a value for use in a sinful parameter.
//
// This is HTCondor's encoding, from needsUrlEncodeEscape in
// condor_sinful.cpp: alphanumerics and . _ - : # [ ] + pass through and
// everything else becomes a lower-case %xx escape.
//
// Deliberately not net/url. QueryEscape writes a space as '+', and the
// decoder on the other side treats '+' as a literal plus -- it is in the
// set above -- so a value with a space in it would come back changed. This
// is the inverse of urlDecode, which is url.PathUnescape for the same
// reason.
func EncodeParamValue(v string) string {
	if !needsAnyEscape(v) {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 8)
	for i := 0; i < len(v); i++ {
		if c := v[i]; paramByteIsSafe(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02x", c)
		}
	}
	return b.String()
}

func needsAnyEscape(v string) bool {
	for i := 0; i < len(v); i++ {
		if !paramByteIsSafe(v[i]) {
			return true
		}
	}
	return false
}

func paramByteIsSafe(c byte) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return true
	}
	switch c {
	case '.', '_', '-', ':', '#', '[', ']', '+':
		return true
	}
	return false
}

// WithoutParam returns addr with one parameter removed.
//
// The key is matched the way ParseSinful reads it: case-folded through the
// canonical names, so asking for "ccbid" removes the "CCBID" that HTCondor
// actually writes. Matching literally instead is invisible when it fails --
// the parameter stays, the address still parses, and it simply keeps meaning
// what the caller was trying to stop it meaning.
//
// An address with no such parameter, or no query string at all, comes back
// unchanged.
func WithoutParam(addr, key string) string {
	open, body, closeB, trailer, query, ok := splitSinful(addr)
	if !ok {
		return addr
	}
	want := canonicalSinfulKey(key)
	kept := make([]string, 0, 8)
	for _, pair := range splitParamPairs(query) {
		if canonicalSinfulKey(decodeParamKey(pairKey(pair))) == want {
			continue
		}
		kept = append(kept, pair)
	}
	return joinSinful(open, body, closeB, trailer, kept)
}

// WithParam returns addr with key set to value, replacing any existing one.
//
// The value is escaped with EncodeParamValue; the key is written as the
// caller spelled it, since a caller adding a parameter this package does not
// know about has to be able to choose its name.
func WithParam(addr, key, value string) string {
	open, body, closeB, trailer, query, ok := splitSinful(addr)
	pair := key + "=" + EncodeParamValue(value)
	if !ok {
		// No query string yet: append one. splitSinful has already told us
		// where the brackets are, so the new pair lands inside them.
		return joinSinful(open, body, closeB, trailer, []string{pair})
	}
	want := canonicalSinfulKey(key)
	kept := make([]string, 0, 8)
	for _, p := range splitParamPairs(query) {
		if canonicalSinfulKey(decodeParamKey(pairKey(p))) == want {
			continue
		}
		kept = append(kept, p)
	}
	kept = append(kept, pair)
	return joinSinful(open, body, closeB, trailer, kept)
}

// splitSinful breaks an address into its brackets, primary address, trailing
// remainder and query string. ok is false when there is no query string to
// edit.
//
// The bracketed body ends at the first '>', as ParseSinful and
// ParseHTCondorAddress read it; anything after that -- an address file's
// "$CondorVersion:" line, a peer's malformed advertisement -- is the trailer,
// which joinSinful puts back verbatim. Keying on the last byte instead would
// miss the brackets entirely and leave the edited parameter outside them,
// where no parser looks.
func splitSinful(addr string) (open, primary, closeB, trailer, query string, ok bool) {
	body := strings.TrimSpace(addr)
	if strings.HasPrefix(body, "<") {
		if j := strings.IndexByte(body, '>'); j >= 0 {
			open, closeB = "<", ">"
			trailer = body[j+1:]
			body = body[1:j]
		}
	}
	i := strings.IndexByte(body, '?')
	if i < 0 {
		return open, body, closeB, trailer, "", false
	}
	return open, body[:i], closeB, trailer, body[i+1:], true
}

func joinSinful(open, primary, closeB, trailer string, pairs []string) string {
	if len(pairs) == 0 {
		return open + primary + closeB + trailer
	}
	return open + primary + "?" + strings.Join(pairs, "&") + closeB + trailer
}

func splitParamPairs(query string) []string {
	return strings.FieldsFunc(query, func(r rune) bool { return r == '&' || r == ';' })
}

func pairKey(pair string) string {
	if i := strings.IndexByte(pair, '='); i >= 0 {
		return pair[:i]
	}
	return pair
}

// decodeParamKey decodes a key for comparison, tolerating a bad escape by
// falling back to the raw text: an unparseable key is not a reason to refuse
// the edit, and it simply will not match anything.
func decodeParamKey(k string) string {
	if decoded, err := urlDecode(k); err == nil {
		return decoded
	}
	return k
}
