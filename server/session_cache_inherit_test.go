package server

import (
	"testing"

	"github.com/htcondor/cedar/security"
)

// TestPerCommandConfigInheritsSessionCache: a per-command config that names
// no session cache stores its sessions in the server's, which is where a
// resumption looks them up. Otherwise a server with its own cache negotiates
// sessions it can never resume: they go to the global cache, and resumption
// only falls back to that for inherited sessions.
func TestPerCommandConfigInheritsSessionCache(t *testing.T) {
	ran := make(chan limitsDispatch, 2)
	srv := newClaimToBeServer(ran)
	perCommand := *srv.SecurityConfig
	perCommand.SessionCache = nil
	srv.SecurityConfigForCommand = func(int) *security.SecurityConfig {
		c := perCommand
		return &c
	}
	clientCache := security.NewSessionCache()

	first := dispatchLimits(t, srv, ran, claimToBeClientConfig(readCmd, clientCache), 0)[0]
	if first.clientErr != nil || first.serveErr != nil || !first.ran {
		t.Fatalf("first command: ran=%t client err=%v err=%v", first.ran, first.clientErr, first.serveErr)
	}
	cfg := claimToBeClientConfig(readCmd, clientCache)
	cfg.SessionID = first.client.SessionId
	second := dispatchLimits(t, srv, ran, cfg, 0)[0]
	if second.clientErr != nil || !second.client.SessionResumed {
		t.Fatalf("second command did not resume the session: resumed=%t err=%v", second.client != nil && second.client.SessionResumed, second.clientErr)
	}
}
