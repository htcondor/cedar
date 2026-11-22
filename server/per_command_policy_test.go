package server

import (
	"slices"
	"testing"

	"github.com/htcondor/cedar/security"
)

// advertiseLevelConfig is a per-level policy for ADVERTISE_STARTD, built on its
// own rather than copied from the server's SecurityConfig, as a daemon builds
// one from its SEC_ADVERTISE_STARTD_* settings.
func advertiseLevelConfig() *security.SecurityConfig {
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthClaimToBe},
		Authentication: security.SecurityRequired,
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		UIDDomain:      "pool",
	}
}

// TestPerCommandConfigInheritsPolicyHooks: a session negotiated under a
// per-command config from SecurityConfigForCommand gets the server's post-auth
// policy and command levels: its identity is mapped by FQUMapper, it is
// advertised every command it is authorized for, and its CLAIMTOBE session is
// limited to the command's level. A per-command config's own PostAuthPolicy
// is kept.
func TestPerCommandConfigInheritsPolicyHooks(t *testing.T) {
	ran := make(chan limitsDispatch, 2)
	srv := newClaimToBeServer(ran)
	user := uniqueUser(t)
	srv.FQUMapper = func(string, string) string { return user }
	srv.SecurityConfigForCommand = func(command int) *security.SecurityConfig {
		if command == advertiseStartdCmd {
			return advertiseLevelConfig()
		}
		return nil
	}

	res := dispatchLimits(t, srv, ran, claimToBeClientConfig(advertiseStartdCmd, security.NewSessionCache()), 0)[0]
	if res.clientErr != nil || res.serveErr != nil || !res.ran {
		t.Fatalf("ran=%t client err=%v err=%v", res.ran, res.clientErr, res.serveErr)
	}
	if res.client.User != user {
		t.Errorf("User = %q, want the mapped %q", res.client.User, user)
	}
	valid := validCommands(res.client)
	for _, c := range []int{advertiseStartdCmd, readCmd, allowCmd, daemonOrStartdCmd} {
		if !slices.Contains(valid, c) {
			t.Errorf("ValidCommands %v lacks authorized command %d", valid, c)
		}
	}
	for _, c := range []int{adminCmd, negotiatorCmd} {
		if slices.Contains(valid, c) {
			t.Errorf("ValidCommands %v includes command %d above the session's level", valid, c)
		}
	}
	if !slices.Equal(res.limits, []string{"ADVERTISE_STARTD", "READ"}) {
		t.Errorf("Conn.AuthorizationLimits() = %q, want [ADVERTISE_STARTD READ]", res.limits)
	}

	t.Run("own policy", func(t *testing.T) {
		srv.SecurityConfigForCommand = func(command int) *security.SecurityConfig {
			c := advertiseLevelConfig()
			c.PostAuthPolicy = func(string, string, bool, bool) (string, []int) {
				return "own@pool", []int{advertiseStartdCmd}
			}
			return c
		}
		res := dispatchLimits(t, srv, ran, claimToBeClientConfig(advertiseStartdCmd, security.NewSessionCache()), 0)[0]
		if res.clientErr != nil || res.serveErr != nil {
			t.Fatalf("client err=%v err=%v", res.clientErr, res.serveErr)
		}
		if res.client.User != "own@pool" || !slices.Equal(validCommands(res.client), []int{advertiseStartdCmd}) {
			t.Errorf("User = %q, ValidCommands = %v, want the per-command policy's own@pool and [%d]", res.client.User, validCommands(res.client), advertiseStartdCmd)
		}
	})
}
