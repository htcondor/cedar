package server

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/server/sharedport"
)

// TestCppFSClientThroughSharedPort runs the installed HTCondor condor_status
// against a cedar server reached through cedar's shared-port router, with FS as
// the only authentication method. An HTCondor 25.14+ client that dialed a
// "?sock=" address reports that id in its FS channel-binding extension
// (HTCONDOR-3883), which the server must accept; older clients report a bare
// ip:port. The server is told its shared-port id, so a 25.14+ client's id is
// checked, not just tolerated. Skipped when condor_status is not installed.
func TestCppFSClientThroughSharedPort(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	condorStatus, err := exec.LookPath("condor_status")
	if err != nil {
		t.Skip("condor_status not installed")
	}

	const sockID = "cedar_fs_test"
	router, err := sharedport.Listen("127.0.0.1:0", sharedport.Options{})
	if err != nil {
		t.Fatalf("shared-port listen: %v", err)
	}
	defer func() { _ = router.Close() }()
	route, err := router.Register(sockID)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	srv := New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		SharedPortID:   sockID,
	})
	type seen struct {
		user   string
		method security.AuthMethod
	}
	handled := make(chan seen, 1)
	srv.Handle(commands.QUERY_STARTD_ADS, func(ctx context.Context, c *Conn) error {
		if _, err := message.NewMessageFromStream(c.Stream).GetClassAd(ctx); err != nil {
			return fmt.Errorf("read query: %w", err)
		}
		reply := message.NewMessageForStream(c.Stream)
		if err := reply.PutInt(ctx, 1); err != nil {
			return err
		}
		if err := reply.PutClassAdRaw(ctx, []string{`Name = "cedar-fs-test"`}, "Machine", "Job"); err != nil {
			return err
		}
		if err := reply.PutInt(ctx, 0); err != nil {
			return err
		}
		if err := reply.FinishMessage(ctx); err != nil {
			return err
		}
		handled <- seen{user: c.Negotiation.User, method: c.Negotiation.NegotiatedAuth}
		return nil
	}, "READ")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	go func() { _ = srv.Serve(ctx, route) }()

	dir := t.TempDir()
	config := filepath.Join(dir, "condor_config")
	if err := os.WriteFile(config, []byte(strings.Join([]string{
		"LOG = " + dir,
		"SEC_CLIENT_AUTHENTICATION = REQUIRED",
		"SEC_CLIENT_AUTHENTICATION_METHODS = FS",
		"SEC_FS_ENFORCE_CHANNEL_BINDING = TRUE",
		"TOOL_DEBUG = D_SECURITY:2",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.CommandContext(ctx, condorStatus, "-debug", "-pool", route.Sinful(), "-af", "Name")
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+config)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	if runErr != nil || strings.TrimSpace(stdout.String()) != "cedar-fs-test" {
		t.Fatalf("condor_status -pool %s: %v\nstdout:\n%s\nstderr:\n%s", route.Sinful(), runErr, stdout.String(), stderr.String())
	}

	select {
	case s := <-handled:
		if s.method != security.AuthFS {
			t.Errorf("negotiated %q, want FS", s.method)
		}
		if s.user == "" {
			t.Error("server recorded no authenticated user")
		}
	case <-ctx.Done():
		t.Fatal("query handler did not run")
	}
}
