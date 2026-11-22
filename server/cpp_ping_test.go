package server

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/htcondor/cedar/commands"
)

// TestCppPing runs the installed condor_ping, which sends DC_SEC_QUERY for the
// level's DC_NOP_* command, against a cedar server whose Authorizer allows the
// peer at READ only. READ is reported authorized for the identity the server
// mapped the peer to; WRITE is reported failed with the server's DENIED, and a
// command the server does not serve with CMD_NOT_FOUND. No handler runs.
// Skipped when condor_ping is not installed.
func TestCppPing(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	condorPing, err := exec.LookPath("condor_ping")
	if err != nil {
		t.Skip("condor_ping not installed")
	}

	const identity = "pinger@cedar.test"
	srv := newFSServer("READ")
	srv.FQUMapper = func(string, string) string { return identity }
	nop := func(_ context.Context, c *Conn) error {
		t.Errorf("handler for command %d ran", c.Command)
		return nil
	}
	srv.Handle(commands.DC_NOP_READ, nop, "READ")
	srv.Handle(commands.DC_NOP_WRITE, nop, "WRITE")
	sinful := serveTCP(t, srv)
	config := cppToolConfig(t, "SEC_CLIENT_AUTHENTICATION_METHODS = FS")
	ping := func(t *testing.T, args ...string) (string, error) {
		t.Helper()
		stdout, stderr, err := runTool(t, config, condorPing, append([]string{"-addr", sinful}, args...)...)
		t.Logf("condor_ping %s: %v\nstdout:\n%s", strings.Join(args, " "), err, stdout)
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("condor_ping %s stderr:\n%s", strings.Join(args, " "), stderr)
			}
		})
		return stdout, err
	}

	t.Run("READ", func(t *testing.T) {
		out, err := ping(t, "READ")
		if err != nil || !strings.Contains(out, "succeeded as "+identity) {
			t.Errorf("condor_ping READ: %v, want it to succeed as %s", err, identity)
		}
	})

	t.Run("verbose", func(t *testing.T) {
		out, err := ping(t, "-verbose", "READ")
		if err != nil || !regexp.MustCompile(`Remote Mapping:\s+`+regexp.QuoteMeta(identity)+`\n`).MatchString(out) ||
			!regexp.MustCompile(`Authorized:\s+TRUE`).MatchString(out) {
			t.Errorf("condor_ping -verbose READ: %v, want Authorized TRUE for %s", err, identity)
		}
		out, err = ping(t, "-verbose", "WRITE")
		if err == nil || !strings.Contains(out, `Received "DENIED" from server for user `+identity) {
			t.Errorf("condor_ping -verbose WRITE: %v, want it refused with DENIED", err)
		}
		out, err = ping(t, "-verbose", "DAEMON")
		if err == nil || !strings.Contains(out, `Received "CMD_NOT_FOUND"`) {
			t.Errorf("condor_ping -verbose DAEMON: %v, want it refused with CMD_NOT_FOUND", err)
		}
	})

	t.Run("table", func(t *testing.T) {
		out, err := ping(t, "-table", "READ", "WRITE")
		if err == nil {
			t.Error("condor_ping -table READ WRITE exited 0 although WRITE was refused")
		}
		if !regexp.MustCompile(`(?m)^\s*READ\s+FS\s.*\sALLOW\s+` + regexp.QuoteMeta(identity) + `$`).MatchString(out) {
			t.Errorf("READ row does not allow %s", identity)
		}
		if !regexp.MustCompile(`(?m)^\s*WRITE\s+FAIL\s`).MatchString(out) {
			t.Error("WRITE row does not report the refusal")
		}
	})
}
