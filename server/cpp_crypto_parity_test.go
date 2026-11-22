package server

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/internal/condortest"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// pingSecurity returns the Authentication, Encryption and Integrity methods
// condor_ping -verbose reports for the session it negotiated. Integrity
// without encryption is reported as MD5, whatever the key.
func pingSecurity(t *testing.T, out string) (auth, enc, integ string) {
	t.Helper()
	field := func(re string) string {
		m := regexp.MustCompile(`(?m)^(?:` + re + `):\s*(\S+)`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("condor_ping -verbose output has no %s line:\n%s", re, out)
		}
		return m[1]
	}
	// An authenticated session reports "Authenticated using", one that is
	// not "Authentication: none".
	return field("Authenticated using|Authentication"), field("Encryption"), field("Integrity")
}

// TestCppPingCryptoMatchesCpp runs the installed condor_ping -verbose against
// a C++ collector and against a cedar server configured as the collector's
// pool is, under several client policies, and requires the same
// authentication, encryption and integrity from both: the policy a C++ client
// caches for the session comes from the server's reconciliation. An
// authenticated AES session reports encryption and integrity even though both
// sides only have them OPTIONAL. Skipped when condor_master or condor_ping is
// not installed.
//
// A cedar client with the same policy is run against both as well: it must be
// told the same decisions by the C++ collector and the cedar server, and its
// stream must be keyed whenever either is enacted.
func TestCppPingCryptoMatchesCpp(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	condorPing, err := exec.LookPath("condor_ping")
	if err != nil {
		t.Skip("condor_ping not installed")
	}
	// The pool's server policy is the harness's: every level OPTIONAL.
	h := condortest.New(t)
	defer h.Shutdown(t)

	srv := New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
	})
	srv.Authorizer = func(string, string, string) bool { return true }
	srv.Handle(commands.DC_NOP_READ, func(context.Context, *Conn) error { return nil }, "READ")
	goAddr := serveTCP(t, srv)

	O, R, P, N := security.SecurityOptional, security.SecurityRequired, security.SecurityPreferred, security.SecurityNever
	for _, tc := range []struct {
		name   string
		client []string
		levels [3]security.SecurityLevel // the same client policy for cedar
		want   [3]string                 // Authentication, Encryption, Integrity
	}{
		{"authenticated", []string{"SEC_CLIENT_AUTHENTICATION = REQUIRED"}, [3]security.SecurityLevel{R, O, O}, [3]string{"FS", "AES", "AES"}},
		{"unauthenticated", []string{"SEC_CLIENT_AUTHENTICATION = NEVER"}, [3]security.SecurityLevel{N, O, O}, [3]string{"none", "none", "none"}},
		{"integrity required", []string{"SEC_CLIENT_AUTHENTICATION = OPTIONAL", "SEC_CLIENT_INTEGRITY = REQUIRED"}, [3]security.SecurityLevel{O, O, R}, [3]string{"none", "none", "MD5"}},
		{"encryption preferred", []string{"SEC_CLIENT_AUTHENTICATION = OPTIONAL", "SEC_CLIENT_ENCRYPTION = PREFERRED"}, [3]security.SecurityLevel{O, P, O}, [3]string{"none", "AES", "none"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := filepath.Join(t.TempDir(), "condor_config")
			lines := append([]string{
				"include : " + filepath.Join(h.ConfigDir(), "condor_config"),
				"SEC_CLIENT_AUTHENTICATION_METHODS = FS",
				"TOOL_DEBUG = D_SECURITY:2",
			}, tc.client...)
			if err := os.WriteFile(config, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			got := map[string][3]string{}
			for name, addr := range map[string]string{"C++ collector": h.GetCollectorAddr(), "cedar": goAddr} {
				stdout, stderr, err := runTool(t, config, condorPing, "-addr", addr, "-verbose", "READ")
				if err != nil {
					t.Fatalf("condor_ping %s: %v\nstdout:\n%s\nstderr:\n%s", name, err, stdout, stderr)
				}
				a, e, i := pingSecurity(t, stdout)
				got[name] = [3]string{a, e, i}
			}
			if got["C++ collector"] != tc.want {
				t.Errorf("C++ collector negotiated %v, want %v (has HTCondor's reconciliation changed?)", got["C++ collector"], tc.want)
			}
			if got["cedar"] != got["C++ collector"] {
				t.Errorf("cedar negotiated %v, C++ collector %v", got["cedar"], got["C++ collector"])
			}

			// The same policy from a cedar client.
			told := map[string][2]security.SecurityLevel{}
			for name, addr := range map[string]string{"C++ collector": h.GetCollectorAddr(), "cedar": goAddr} {
				hostPort := strings.TrimPrefix(strings.SplitN(strings.SplitN(addr, "?", 2)[0], ">", 2)[0], "<")
				conn, err := net.DialTimeout("tcp", hostPort, 10*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				// The shared port hands a plain connection to the collector.
				st := stream.NewStream(conn)
				neg, err := security.NewAuthenticator(&security.SecurityConfig{
					AuthMethods:    []security.AuthMethod{security.AuthFS},
					Authentication: tc.levels[0],
					CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
					Encryption:     tc.levels[1],
					Integrity:      tc.levels[2],
					Command:        commands.DC_NOP_READ,
				}, st).ClientHandshake(context.Background())
				_ = conn.Close()
				if err != nil {
					t.Fatalf("cedar client to %s: %v", name, err)
				}
				told[name] = [2]security.SecurityLevel{neg.ServerConfig.Encryption, neg.ServerConfig.Integrity}
				if (told[name][0] == "YES" || told[name][1] == "YES") && !st.IsEncrypted() {
					t.Errorf("cedar client to %s was told Encryption=%s Integrity=%s but its stream is not keyed", name, told[name][0], told[name][1])
				}
			}
			if told["cedar"] != told["C++ collector"] {
				t.Errorf("cedar client was told %v by cedar, %v by the C++ collector", told["cedar"], told["C++ collector"])
			}
		})
	}
}
