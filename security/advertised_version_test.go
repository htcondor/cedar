package security

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

const (
	serverVersion = "$CondorVersion: 25.14.0 2026-10-01 BuildID: server $"
	clientVersion = "$CondorVersion: 25.15.0 2026-10-02 BuildID: client $"
	otherVersion  = "$CondorVersion: 25.16.0 2026-10-03 BuildID: other $"
)

// TestResumedSessionKeepsConfiguredVersions makes two connections between a
// cedar client and server that each configure a RemoteVersion; the second
// resumes the first one's session. Each side must see the other's configured
// version on both connections. A server that answered a resumption with
// DefaultRemoteVersion instead made the client see 25.4.0 on every resumed
// connection, so features gated on the peer version (CCB streaming and
// outbound tunneling) were refused from the second connection on.
func TestResumedSessionKeepsConfiguredVersions(t *testing.T) {
	GetSessionCache().Clear()
	defer GetSessionCache().Clear()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	serverNegs := make(chan *SecurityNegotiation, 2)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				cfg := resumeReplayConfig("")
				cfg.RemoteVersion = serverVersion
				neg, err := NewAuthenticator(cfg, stream.NewStream(conn)).ServerHandshake(context.Background())
				if err != nil {
					t.Errorf("server handshake: %v", err)
				}
				serverNegs <- neg
			}()
		}
	}()

	for _, tc := range []struct {
		label       string
		wantResumed bool
	}{{"negotiated", false}, {"resumed", true}} {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("%s: dial: %v", tc.label, err)
		}
		cfg := resumeReplayConfig("version-server")
		cfg.RemoteVersion = clientVersion
		neg, err := NewAuthenticator(cfg, stream.NewStream(conn)).ClientHandshake(context.Background())
		_ = conn.Close()
		if err != nil {
			t.Fatalf("%s: client handshake: %v", tc.label, err)
		}
		if neg.SessionResumed != tc.wantResumed {
			t.Fatalf("%s: SessionResumed = %v, want %v", tc.label, neg.SessionResumed, tc.wantResumed)
		}
		if got := neg.ServerConfig.RemoteVersion; got != serverVersion {
			t.Errorf("%s: client sees server version %q, want %q", tc.label, got, serverVersion)
		}
		var sneg *SecurityNegotiation
		select {
		case sneg = <-serverNegs:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: server produced no result", tc.label)
		}
		if sneg == nil {
			t.Fatalf("%s: server handshake failed", tc.label)
		}
		if got := sneg.ClientConfig.RemoteVersion; got != clientVersion {
			t.Errorf("%s: server sees client version %q, want %q", tc.label, got, clientVersion)
		}
	}
}

// TestServerResumeReplyAdvertisesConfiguredVersion resumes a session against
// a cedar server and reads the version its reply carries: the one a full
// handshake for the same command would advertise. That is the per-command
// config's when ServerConfigForCommand selects one (for DC_SEC_QUERY, the one
// for the command it asks about), else the server's own, else
// DefaultRemoteVersion.
func TestServerResumeReplyAdvertisesConfiguredVersion(t *testing.T) {
	perCommand := func(command int) *SecurityConfig {
		if command == commands.CCB_REQUEST {
			return &SecurityConfig{RemoteVersion: otherVersion}
		}
		return nil
	}
	for _, tc := range []struct {
		name        string
		base        string
		perCommand  func(int) *SecurityConfig
		command     int
		authCommand int
		want        string
	}{
		{"configured", serverVersion, nil, commands.CCB_REQUEST, 0, serverVersion},
		{"unset", "", nil, commands.CCB_REQUEST, 0, DefaultRemoteVersion},
		{"per-command", serverVersion, perCommand, commands.CCB_REQUEST, 0, otherVersion},
		{"per-command sec query", serverVersion, perCommand, commands.DC_SEC_QUERY, commands.CCB_REQUEST, otherVersion},
		{"no per-command config", serverVersion, perCommand, commands.DC_NOP, 0, serverVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, entry := importFamilySession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			serverConn, clientConn := net.Pipe()
			defer func() { _ = serverConn.Close() }()
			defer func() { _ = clientConn.Close() }()

			done := make(chan *SecurityNegotiation, 1)
			go func() {
				a := NewAuthenticator(&SecurityConfig{SessionCache: cache, RemoteVersion: tc.base}, stream.NewStream(serverConn))
				a.ServerConfigForCommand = tc.perCommand
				neg, err := a.ServerHandshake(ctx)
				if err != nil {
					t.Errorf("server handshake: %v", err)
				}
				done <- neg
			}()

			cs := stream.NewStream(clientConn)
			msg := message.NewMessageForStream(cs)
			resumeAd := classad.New()
			_ = resumeAd.Set("Command", tc.command)
			if tc.authCommand != 0 {
				_ = resumeAd.Set("AuthCommand", tc.authCommand)
			}
			_ = resumeAd.Set("UseSession", "YES")
			_ = resumeAd.Set("Sid", entry.ID())
			_ = resumeAd.Set("ResumeResponse", true)
			_ = resumeAd.Set("RemoteVersion", clientVersion)
			if err := msg.PutInt(ctx, commands.DC_AUTHENTICATE); err != nil {
				t.Fatal(err)
			}
			if err := msg.PutClassAd(ctx, resumeAd); err != nil {
				t.Fatal(err)
			}
			if err := msg.FinishMessage(ctx); err != nil {
				t.Fatal(err)
			}
			resp, err := message.NewMessageFromStream(cs).GetClassAd(ctx)
			if err != nil {
				t.Fatalf("reading resume response: %v", err)
			}
			if rc, _ := resp.EvaluateAttrString("ReturnCode"); rc != "AUTHORIZED" {
				t.Fatalf("ReturnCode = %q, want AUTHORIZED", rc)
			}
			if got, _ := resp.EvaluateAttrString("RemoteVersion"); got != tc.want {
				t.Errorf("resume reply RemoteVersion = %q, want %q", got, tc.want)
			}
			// The server takes the client's version from its resume request.
			if neg := <-done; neg == nil || neg.ClientConfig.RemoteVersion != clientVersion {
				t.Errorf("server did not record the client's version %q from the resume request", clientVersion)
			}
		})
	}
}

// resumeAgainst resumes an imported session that recorded cachedVersion as
// the peer's ("" = none) with a stub server that answers AUTHORIZED with
// replyVersion as its RemoteVersion ("" = none). It returns the resume request
// the server read and the client's negotiation.
func resumeAgainst(t *testing.T, cfg *SecurityConfig, cachedVersion, replyVersion string) (*classad.ClassAd, *SecurityNegotiation) {
	t.Helper()
	cache, entry := importFamilySession(t)
	if cachedVersion != "" {
		if entry.Policy() == nil {
			t.Fatal("imported session has no policy")
		}
		_ = entry.Policy().Set("RemoteVersion", cachedVersion)
	}
	cfg.SessionCache = cache
	cfg.SessionID = entry.ID()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	got := make(chan *classad.ClassAd, 1)
	go func() {
		defer close(got)
		ss := stream.NewStream(serverConn)
		in := message.NewMessageFromStream(ss)
		if _, err := in.GetInt(ctx); err != nil {
			return
		}
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return
		}
		got <- ad
		resp := classad.New()
		_ = resp.Set("ReturnCode", "AUTHORIZED")
		if replyVersion != "" {
			_ = resp.Set("RemoteVersion", replyVersion)
		}
		out := message.NewMessageForStream(ss)
		if out.PutClassAd(ctx, resp) == nil {
			_ = out.FinishMessage(ctx)
		}
	}()

	neg, err := NewAuthenticator(cfg, stream.NewStream(clientConn)).ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	ad := <-got
	if ad == nil {
		t.Fatal("server did not receive a resume ad")
	}
	return ad, neg
}

// TestClientResumeRequestAdvertisesConfiguredVersion pins the version a cedar
// client puts in its resume request: its configured one, else the default.
func TestClientResumeRequestAdvertisesConfiguredVersion(t *testing.T) {
	for _, tc := range []struct {
		name, configured, want string
	}{
		{"configured", clientVersion, clientVersion},
		{"unset", "", DefaultRemoteVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad, _ := resumeAgainst(t, &SecurityConfig{Command: commands.DC_NOP, RemoteVersion: tc.configured}, "", "")
			if got, _ := ad.EvaluateAttrString("RemoteVersion"); got != tc.want {
				t.Errorf("resume request RemoteVersion = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClientResumeTakesPeerVersionFromReply checks which peer version a
// client keeps after resuming a session: a version in the reply replaces the
// one the session recorded, as in HTCondor, except cedar's own default, which
// a cedar v0.7.9 server sent in every resumption reply whatever version it
// advertised otherwise. With none recorded, the default is still taken.
func TestClientResumeTakesPeerVersionFromReply(t *testing.T) {
	for _, tc := range []struct {
		name, cached, reply, want string
	}{
		{"real version", serverVersion, otherVersion, otherVersion},
		{"no version", serverVersion, "", serverVersion},
		{"cedar default", serverVersion, DefaultRemoteVersion, serverVersion},
		{"cedar default, none recorded", "", DefaultRemoteVersion, DefaultRemoteVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, neg := resumeAgainst(t, &SecurityConfig{Command: commands.DC_NOP}, tc.cached, tc.reply)
			if !neg.SessionResumed {
				t.Fatal("session not resumed")
			}
			if got := neg.ServerConfig.RemoteVersion; got != tc.want {
				t.Errorf("peer version after resume = %q, want %q", got, tc.want)
			}
		})
	}
}
