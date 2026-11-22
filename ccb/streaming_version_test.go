package ccb

import (
	"testing"

	"github.com/htcondor/cedar/security"
)

// TestBrokerSupportsStreamingVersionGate pins the CCB streaming version gate to the
// actual C++ availability: streaming shipped on the 25.13 line (HTCONDOR-3805) and is
// NOT in the 25.12 stable series. A broker below 25.13.0 (e.g. released 25.12.2) must be
// treated as not supporting streaming, so a requester skips/falls back instead of sending
// a streaming request the older broker mishandles (it ignores the flag and does a classic
// reverse-connect).
func TestBrokerSupportsStreamingVersionGate(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"$CondorVersion: 25.12.2 2026-07-20 BuildID: x $", false}, // released stable: no streaming
		{"$CondorVersion: 25.12.9 2026-07-20 BuildID: x $", false}, // any 25.12.x patch: no streaming
		{"$CondorVersion: 25.13.0 2026-08-01 BuildID: x $", true},  // first release with streaming
		{"$CondorVersion: 25.13.4 2026-09-01 BuildID: x $", true},
		{"$CondorVersion: 26.0.0 2027-01-01 BuildID: x $", true},
		{"$CondorVersion: 25.4.0 2025-10-31 BuildID: x $", false},
	}
	for _, tc := range cases {
		neg := &security.SecurityNegotiation{
			ServerConfig: &security.SecurityConfig{RemoteVersion: tc.version},
		}
		if got := brokerSupportsStreaming(neg); got != tc.want {
			t.Errorf("brokerSupportsStreaming(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}

	// A missing/unparseable version is not assumed to support streaming.
	if brokerSupportsStreaming(nil) {
		t.Error("nil negotiation should not be treated as streaming-capable")
	}
	if brokerSupportsStreaming(&security.SecurityNegotiation{ServerConfig: &security.SecurityConfig{RemoteVersion: "garbage"}}) {
		t.Error("unparseable version should not be treated as streaming-capable")
	}
}
