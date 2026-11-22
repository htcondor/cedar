package server

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
)

// TestCppClientResumesEncryptedSession runs the installed condor_rm against a
// cedar server that requires encryption. Its second ACT_ON_JOBS resumes the
// first one's session, so the command runs over a resumed, AES-GCM-encrypted
// connection whose AAD binds both peers' resume nonces: the server decrypts
// the client's request and the client the server's replies only if both
// computed the handshake digest the same way. Skipped when condor_rm is not
// installed.
func TestCppClientResumesEncryptedSession(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	condorRm, err := exec.LookPath("condor_rm")
	if err != nil {
		t.Skip("condor_rm not installed")
	}

	srv := New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityRequired,
	})
	srv.Authorizer = func(_, _, user string) bool { return user != UnauthenticatedFQU }
	type run struct{ resumed, encrypted bool }
	runs := make(chan run, 2)
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
		runs <- run{resumed: c.Negotiation.SessionResumed, encrypted: c.Stream.IsEncrypted()}
		return nil
	}, "WRITE")
	sinful := serveTCP(t, srv)

	config := cppToolConfig(t,
		"SEC_CLIENT_AUTHENTICATION_METHODS = FS",
		"SEC_CLIENT_ENCRYPTION = REQUIRED",
		"SEC_CLIENT_INTEGRITY = REQUIRED",
		"SEC_CLIENT_CRYPTO_METHODS = AES",
	)
	stdout, stderr, runErr := runTool(t, config, condorRm, "-debug", "-addr", sinful, "1.0", "2")
	if runErr != nil {
		t.Fatalf("condor_rm -addr %s 1.0 2: %v\nstdout:\n%s\nstderr:\n%s", sinful, runErr, stdout, stderr)
	}
	var got []run
	for range 2 {
		select {
		case r := <-runs:
			got = append(got, r)
		case <-time.After(10 * time.Second):
			t.Fatalf("ACT_ON_JOBS completed %d times, want 2\nstderr:\n%s", len(got), stderr)
		}
	}
	if got[0].resumed || !got[1].resumed || !got[0].encrypted || !got[1].encrypted {
		t.Errorf("runs = %+v, want two encrypted commands, the second on the first one's session", got)
	}
}
