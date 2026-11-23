package server

import (
	"context"
	"strings"
	"testing"

	"github.com/htcondor/cedar/security"
)

// noPermsCmd is registered through Handle with no authorization levels.
const noPermsCmd = 81015

// TestEmptyPermsCommandIsNotGated: Handle with no perms "applies no
// authorization table", so an Authorizer that refuses every level it is asked
// about must not refuse such a command -- it is never asked. A command
// registered WITH a level keeps being refused.
func TestEmptyPermsCommandIsNotGated(t *testing.T) {
	ran := make(chan limitsDispatch, 2)
	handler := func(_ context.Context, c *Conn) error {
		ran <- limitsDispatch{ran: true, limits: c.AuthorizationLimits()}
		return nil
	}

	newServer := func() *Server {
		srv := New(&security.SecurityConfig{
			AuthMethods:    []security.AuthMethod{security.AuthClaimToBe},
			Authentication: security.SecurityRequired,
			Encryption:     security.SecurityRequired,
			Integrity:      security.SecurityRequired,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			UIDDomain:      "pool",
			SessionCache:   security.NewSessionCache(),
		})
		// Refuses every level: the only way this command runs is by not
		// consulting the Authorizer at all.
		srv.Authorizer = func(string, string, string) bool { return false }
		srv.Handle(noPermsCmd, handler)
		srv.Handle(adminCmd, handler, "ADMINISTRATOR")
		return srv
	}

	t.Run("no_perms_runs", func(t *testing.T) {
		srv := newServer()
		res := dispatchLimits(t, srv, ran, claimToBeClientConfig(noPermsCmd, security.NewSessionCache()), 0)[0]
		if res.clientErr != nil {
			t.Errorf("client handshake: %v", res.clientErr)
		}
		if !res.ran {
			t.Errorf("handler for a command registered with no perms did not run; ServeConn err = %v", res.serveErr)
		}
	})

	t.Run("non_empty_perms_still_refused", func(t *testing.T) {
		srv := newServer()
		res := dispatchLimits(t, srv, ran, claimToBeClientConfig(adminCmd, security.NewSessionCache()), 0)[0]
		if res.ran {
			t.Error("a command whose level the Authorizer refuses ran")
		}
		denial(t, res.clientErr, "DENIED")
		if res.serveErr == nil || !strings.Contains(res.serveErr.Error(), "authorization levels [ADMINISTRATOR]") {
			t.Errorf("ServeConn error = %v, want it to name the command's authorization levels", res.serveErr)
		}
	})
}
