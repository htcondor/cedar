package security

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/htcondor/cedar/stream"
)

// attrPair runs one client connection against a server configured with
// serverAttrs, returning what the client captured for wantAttrs and whether
// the session was resumed. The caller clears the session cache to control
// which of those it gets.
func attrPair(t *testing.T, serverAttrs map[string]string, wantAttrs []string, peer string) (map[string]string, bool) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		cfg := resumeReplayConfig("")
		cfg.SessionAttrs = serverAttrs
		if _, err := NewAuthenticator(cfg, stream.NewStream(conn)).ServerHandshake(context.Background()); err != nil {
			t.Errorf("server handshake: %v", err)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cfg := resumeReplayConfig(peer)
	cfg.WantSessionAttrs = wantAttrs
	neg, err := NewAuthenticator(cfg, stream.NewStream(conn)).ClientHandshake(context.Background())
	_ = conn.Close()
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	<-done
	return neg.SessionAttrs, neg.SessionResumed
}

// TestSessionAttrsSurviveResumption is the property the mechanism exists for.
//
// A resumed session exchanges no post-authentication ad, and all but the first
// connection to a peer resumes. If the attributes were read off the wire and
// not kept with the session, a capability would be visible on the first
// connection and invisible on every one after it -- which is worse than not
// advertising it at all, because the client would conclude the server had been
// downgraded and fall back for the life of the session.
func TestSessionAttrsSurviveResumption(t *testing.T) {
	GetSessionCache().Clear()
	defer GetSessionCache().Clear()

	advertised := map[string]string{"DBProtocolVersion": "3"}
	want := []string{"DBProtocolVersion"}

	for _, tc := range []struct {
		label       string
		wantResumed bool
	}{{"negotiated", false}, {"resumed", true}} {
		got, resumed := attrPair(t, advertised, want, "attr-server")
		if resumed != tc.wantResumed {
			t.Fatalf("%s: SessionResumed = %v, want %v", tc.label, resumed, tc.wantResumed)
		}
		if got["DBProtocolVersion"] != "3" {
			t.Errorf("%s: DBProtocolVersion = %q, want \"3\"", tc.label, got["DBProtocolVersion"])
		}
	}
}

// TestSessionAttrsCaptureOnlyWhatWasAskedFor pins capture to the client's
// named list. The ad also carries attributes cedar and C++ HTCondor own, and a
// client that collected everything it did not recognise would present those to
// the application as its protocol's own claims.
func TestSessionAttrsCaptureOnlyWhatWasAskedFor(t *testing.T) {
	GetSessionCache().Clear()
	defer GetSessionCache().Clear()

	got, _ := attrPair(t,
		map[string]string{"DBProtocolVersion": "3", "SomethingElse": "yes"},
		[]string{"DBProtocolVersion"}, "attr-subset")

	if got["DBProtocolVersion"] != "3" {
		t.Errorf("DBProtocolVersion = %q, want \"3\"", got["DBProtocolVersion"])
	}
	if v, ok := got["SomethingElse"]; ok {
		t.Errorf("captured SomethingElse = %q, which the client never asked for", v)
	}
	if _, ok := got["Sid"]; ok {
		t.Error("captured Sid, a handshake attribute, as an application one")
	}
}

// TestSessionAttrsCannotOverrideTheHandshake proves an application cannot
// rewrite the session's identity or authorization through this door. Sid and
// User are the handshake's; an application that set them would be restating
// who authenticated.
func TestSessionAttrsCannotOverrideTheHandshake(t *testing.T) {
	GetSessionCache().Clear()
	defer GetSessionCache().Clear()

	got, _ := attrPair(t,
		map[string]string{"Sid": "forged", "User": "root@forged", "DBProtocolVersion": "3"},
		[]string{"Sid", "User", "DBProtocolVersion"}, "attr-reserved")

	for _, name := range []string{"Sid", "User"} {
		if v, ok := got[name]; ok {
			t.Errorf("application set the reserved attribute %s = %q", name, v)
		}
	}
	if got["DBProtocolVersion"] != "3" {
		t.Errorf("the unreserved attribute was dropped too: %q", got["DBProtocolVersion"])
	}
}

// TestSessionAttrsAbsentFromASilentPeer is the old-server case, which is the
// one that has to keep working: a peer that advertises nothing must read as
// absent, never as a zero value a caller could mistake for an answer.
func TestSessionAttrsAbsentFromASilentPeer(t *testing.T) {
	GetSessionCache().Clear()
	defer GetSessionCache().Clear()

	got, _ := attrPair(t, nil, []string{"DBProtocolVersion"}, "attr-silent")
	if v, ok := got["DBProtocolVersion"]; ok {
		t.Errorf("DBProtocolVersion = %q from a peer that advertised nothing", v)
	}
}

// TestReservedSessionAttr checks the name test itself, case-insensitively as
// ClassAd attribute names compare.
func TestReservedSessionAttr(t *testing.T) {
	for _, name := range []string{"Sid", "sid", "USER", "ValidCommands", "RemoteVersion", AttrLimitAuthorization} {
		if !ReservedSessionAttr(name) {
			t.Errorf("%q should be reserved", name)
		}
	}
	for _, name := range []string{"DBProtocolVersion", "SidekickVersion", ""} {
		if ReservedSessionAttr(name) {
			t.Errorf("%q should not be reserved", name)
		}
	}
}
