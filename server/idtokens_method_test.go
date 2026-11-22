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
	"github.com/htcondor/cedar/stream"
)

// tokenMethodSeen is what the server handler observed for one connection.
type tokenMethodSeen struct {
	user   string
	method security.AuthMethod
}

// newTokenMethodServer returns a server requiring token authentication under
// the given method names, verifying tokens signed with the POOL key in keyDir.
func newTokenMethodServer(keyDir string, methods []security.AuthMethod, seen chan<- tokenMethodSeen) *Server {
	srv := New(&security.SecurityConfig{
		AuthMethods:             methods,
		Authentication:          security.SecurityRequired,
		Encryption:              security.SecurityRequired,
		Integrity:               security.SecurityRequired,
		CryptoMethods:           []security.CryptoMethod{security.CryptoAES},
		TrustDomain:             limitsTrustDomain,
		TokenPoolSigningKeyFile: filepath.Join(keyDir, "POOL"),
		TokenSigningKeyDir:      keyDir,
		SessionCache:            security.NewSessionCache(),
	})
	srv.Authorizer = func(_, _, user string) bool { return user != UnauthenticatedFQU }
	srv.Handle(readCmd, func(_ context.Context, c *Conn) error {
		seen <- tokenMethodSeen{user: c.Negotiation.User, method: c.Negotiation.NegotiatedAuth}
		return nil
	}, "READ")
	return srv
}

// TestIDTokensIsToken: IDTOKENS and TOKEN name the same method, as in
// HTCondor (SecMan::sec_char_to_auth_method). A client configured with either
// name authenticates with a token to a server configured with either or both,
// within a short deadline rather than hanging, and each side reports the
// method under the name it configured.
func TestIDTokensIsToken(t *testing.T) {
	keyDir := tokenKeyDir(t)
	token := idToken(t, keyDir, nil)
	idt, tok := security.AuthIDTokens, security.AuthToken

	cases := []struct {
		name   string
		client []security.AuthMethod
		server []security.AuthMethod
	}{
		{"IDTOKENS client, TOKEN server", []security.AuthMethod{idt}, []security.AuthMethod{tok}},
		{"IDTOKENS client, IDTOKENS server", []security.AuthMethod{idt}, []security.AuthMethod{idt}},
		{"IDTOKENS client, IDTOKENS+TOKEN server", []security.AuthMethod{idt}, []security.AuthMethod{idt, tok}},
		{"IDTOKENS client, TOKEN+IDTOKENS server", []security.AuthMethod{idt}, []security.AuthMethod{tok, idt}},
		{"TOKEN client, IDTOKENS server", []security.AuthMethod{tok}, []security.AuthMethod{idt}},
		{"IDTOKENS+TOKEN client, IDTOKENS server", []security.AuthMethod{idt, tok}, []security.AuthMethod{idt}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan tokenMethodSeen, 1)
			srv := newTokenMethodServer(keyDir, tc.server, seen)
			cliCfg := limitsClientConfig(token, readCmd, security.NewSessionCache())
			cliCfg.AuthMethods = tc.client

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			serverConn, clientConn := net.Pipe()
			// A method mismatch can leave both sides reading; closing the pipe at
			// the deadline guarantees the test ends.
			go func() {
				<-ctx.Done()
				_ = serverConn.Close()
				_ = clientConn.Close()
			}()
			done := make(chan error, 1)
			go func() { done <- srv.ServeConn(ctx, serverConn) }()

			st := stream.NewStream(clientConn)
			st.SetPeerAddr(limitsServerAddr)
			neg, err := security.NewAuthenticator(cliCfg, st).ClientHandshake(ctx)
			if err != nil {
				t.Fatalf("client handshake: %v (ctx: %v)", err, ctx.Err())
			}
			if neg.NegotiatedAuth != tc.client[0] {
				t.Errorf("client NegotiatedAuth = %q, want %q", neg.NegotiatedAuth, tc.client[0])
			}
			_ = clientConn.Close()
			if err := <-done; err != nil {
				t.Fatalf("ServeConn: %v", err)
			}
			select {
			case s := <-seen:
				if s.user != "alice@"+limitsTrustDomain {
					t.Errorf("server user = %q, want alice@%s", s.user, limitsTrustDomain)
				}
				if s.method != tc.server[0] {
					t.Errorf("server NegotiatedAuth = %q, want %q", s.method, tc.server[0])
				}
			default:
				t.Fatal("handler did not run")
			}
		})
	}
}

// TestCppIDTokensClient runs the installed HTCondor condor_status, configured
// with IDTOKENS (which HTCondor offers as TOKEN), against a cedar server
// configured with IDTOKENS only. Skipped when condor_status is not installed.
func TestCppIDTokensClient(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	condorStatus, err := exec.LookPath("condor_status")
	if err != nil {
		t.Skip("condor_status not installed")
	}

	keyDir := tokenKeyDir(t)
	srv := New(&security.SecurityConfig{
		AuthMethods:             []security.AuthMethod{security.AuthIDTokens},
		Authentication:          security.SecurityRequired,
		CryptoMethods:           []security.CryptoMethod{security.CryptoAES},
		Encryption:              security.SecurityOptional,
		Integrity:               security.SecurityOptional,
		TrustDomain:             limitsTrustDomain,
		TokenPoolSigningKeyFile: filepath.Join(keyDir, "POOL"),
		TokenSigningKeyDir:      keyDir,
	})
	seen := make(chan tokenMethodSeen, 1)
	srv.Handle(commands.QUERY_STARTD_ADS, func(ctx context.Context, c *Conn) error {
		if _, err := message.NewMessageFromStream(c.Stream).GetClassAd(ctx); err != nil {
			return fmt.Errorf("read query: %w", err)
		}
		reply := message.NewMessageForStream(c.Stream)
		if err := reply.PutInt(ctx, 1); err != nil {
			return err
		}
		if err := reply.PutClassAdRaw(ctx, []string{`Name = "cedar-idtokens-test"`}, "Machine", "Job"); err != nil {
			return err
		}
		if err := reply.PutInt(ctx, 0); err != nil {
			return err
		}
		if err := reply.FinishMessage(ctx); err != nil {
			return err
		}
		seen <- tokenMethodSeen{user: c.Negotiation.User, method: c.Negotiation.NegotiatedAuth}
		return nil
	}, "READ")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens.d")
	if err := os.Mkdir(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tokenDir, "alice"), []byte(idToken(t, keyDir, nil)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "condor_config")
	if err := os.WriteFile(config, []byte(strings.Join([]string{
		"LOG = " + dir,
		"SEC_CLIENT_AUTHENTICATION = REQUIRED",
		"SEC_CLIENT_AUTHENTICATION_METHODS = IDTOKENS",
		"SEC_TOKEN_DIRECTORY = " + tokenDir,
		"TOOL_DEBUG = D_SECURITY:2",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	pool := "<" + ln.Addr().String() + ">"
	cmd := exec.CommandContext(ctx, condorStatus, "-debug", "-pool", pool, "-af", "Name")
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+config)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	if runErr != nil || strings.TrimSpace(stdout.String()) != "cedar-idtokens-test" {
		t.Fatalf("condor_status -pool %s: %v\nstdout:\n%s\nstderr:\n%s", pool, runErr, stdout.String(), stderr.String())
	}

	select {
	case s := <-seen:
		if s.method != security.AuthIDTokens {
			t.Errorf("negotiated %q, want IDTOKENS", s.method)
		}
		if s.user != "alice@"+limitsTrustDomain {
			t.Errorf("server user = %q, want alice@%s", s.user, limitsTrustDomain)
		}
	case <-ctx.Done():
		t.Fatal("query handler did not run")
	}
}
