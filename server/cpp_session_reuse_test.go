package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
)

// cppToolConfig writes a client configuration for the installed HTCondor tools
// that authenticates by FS only and returns its path.
func cppToolConfig(t *testing.T, extra ...string) string {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, "condor_config")
	lines := append([]string{
		"LOG = " + dir,
		"SEC_CLIENT_AUTHENTICATION = REQUIRED",
		"TOOL_DEBUG = D_SECURITY:2",
	}, extra...)
	if err := os.WriteFile(config, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return config
}

// newFSServer returns a server requiring FS authentication whose Authorizer
// allows every authenticated identity at the levels in allow (all levels if
// allow is empty).
func newFSServer(allow ...string) *Server {
	srv := New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
	})
	srv.Authorizer = func(perm, _, user string) bool {
		return user != UnauthenticatedFQU && (len(allow) == 0 || strings.Contains(strings.Join(allow, ","), perm))
	}
	return srv
}

// serveTCP serves srv on a loopback listener until the test ends and returns
// its sinful string.
func serveTCP(t *testing.T, srv *Server) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, l) }()
	return "<" + l.Addr().String() + ">"
}

// runTool runs an installed HTCondor tool under config and returns its stdout,
// stderr and exit error.
func runTool(t *testing.T, config, tool string, args ...string) (string, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+config)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// TestCppClientResumesSessionAcrossCommands runs the installed condor_rm, which
// sends ACT_ON_JOBS twice (once for a job id, once for a cluster) from one
// process, against a cedar server. The second command resumes the first one's
// session, and ACT_ON_JOBS forces authentication on the client
// (Daemon::forceAuthentication), which a C++ client skips on a resumed session
// only if the server's post-auth reply said TriedAuthentication. Without it the
// client re-authenticates mid-command, which a cedar server does not serve.
// The client's method list is in lower case, which HTCondor accepts. Skipped
// when condor_rm is not installed.
func TestCppClientResumesSessionAcrossCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	condorRm, err := exec.LookPath("condor_rm")
	if err != nil {
		t.Skip("condor_rm not installed")
	}

	srv := newFSServer()
	resumed := make(chan bool, 2)
	srv.Handle(commands.ACT_ON_JOBS, func(ctx context.Context, c *Conn) error {
		if _, err := message.NewMessageFromStream(c.Stream).GetClassAd(ctx); err != nil {
			return fmt.Errorf("read request: %w", err)
		}
		reply := message.NewMessageForStream(c.Stream)
		if err := reply.PutClassAdRaw(ctx, []string{"ActionResult = 1"}, "", ""); err != nil {
			return err
		}
		if err := reply.FinishMessage(ctx); err != nil {
			return err
		}
		if _, err := message.NewMessageFromStream(c.Stream).GetInt(ctx); err != nil {
			return fmt.Errorf("read client's answer: %w", err)
		}
		done := message.NewMessageForStream(c.Stream)
		if err := done.PutInt(ctx, 1); err != nil {
			return err
		}
		if err := done.FinishMessage(ctx); err != nil {
			return err
		}
		resumed <- c.Negotiation.SessionResumed
		return nil
	}, "WRITE")
	sinful := serveTCP(t, srv)

	config := cppToolConfig(t, "SEC_CLIENT_AUTHENTICATION_METHODS = fs")
	stdout, stderr, runErr := runTool(t, config, condorRm, "-debug", "-addr", sinful, "1.0", "2")
	if runErr != nil {
		t.Fatalf("condor_rm -addr %s 1.0 2: %v\nstdout:\n%s\nstderr:\n%s", sinful, runErr, stdout, stderr)
	}
	var got []bool
	for range 2 {
		select {
		case r := <-resumed:
			got = append(got, r)
		case <-time.After(10 * time.Second):
			t.Fatalf("ACT_ON_JOBS ran %d times, want 2\nstderr:\n%s", len(got), stderr)
		}
	}
	if got[0] || !got[1] {
		t.Errorf("SessionResumed = %v, want the second command on the first one's session", got)
	}
}

// TestCppAdvertiseReportsDenial runs the installed condor_advertise against a
// cedar server whose Authorizer refuses the update: the post-auth reply says
// DENIED, so condor_advertise reports the refusal rather than a sent update.
// An update the server permits is sent. Skipped when condor_advertise is not
// installed.
func TestCppAdvertiseReportsDenial(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	condorAdvertise, err := exec.LookPath("condor_advertise")
	if err != nil {
		t.Skip("condor_advertise not installed")
	}
	adFile := filepath.Join(t.TempDir(), "startd.ad")
	if err := os.WriteFile(adFile, []byte("MyType = \"Machine\"\nName = \"cedar-denied-test\"\nMachine = \"cedar-denied-test\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := cppToolConfig(t, "SEC_CLIENT_AUTHENTICATION_METHODS = FS")

	for _, tc := range []struct {
		allow   string
		wantRan bool
	}{{"READ", false}, {"ADVERTISE_STARTD", true}} {
		t.Run(tc.allow, func(t *testing.T) {
			srv := newFSServer(tc.allow)
			ran := make(chan struct{}, 1)
			srv.Handle(commands.UPDATE_STARTD_AD, func(ctx context.Context, c *Conn) error {
				if _, err := message.NewMessageFromStream(c.Stream).GetClassAd(ctx); err != nil {
					return fmt.Errorf("read ad: %w", err)
				}
				ran <- struct{}{}
				return nil
			}, "ADVERTISE_STARTD")
			sinful := serveTCP(t, srv)

			stdout, stderr, runErr := runTool(t, config, condorAdvertise, "-debug", "-tcp", "-pool", sinful, "UPDATE_STARTD_AD", adFile)
			out := stdout + stderr
			if !tc.wantRan {
				if runErr == nil || strings.Contains(out, "Sent 1 of 1") || !strings.Contains(out, `Received "DENIED"`) {
					t.Errorf("condor_advertise: %v, want the update refused with DENIED\nstdout:\n%s\nstderr:\n%s", runErr, stdout, stderr)
				}
				select {
				case <-ran:
					t.Error("refused update ran")
				default:
				}
				return
			}
			if runErr != nil || !strings.Contains(out, "Sent 1 of 1") {
				t.Fatalf("condor_advertise: %v, want the update sent\nstdout:\n%s\nstderr:\n%s", runErr, stdout, stderr)
			}
			select {
			case <-ran:
			case <-time.After(10 * time.Second):
				t.Error("permitted update did not run")
			}
		})
	}
}
