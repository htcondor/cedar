package security

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/stream"
)

// tagTestServer accepts connections and runs a server handshake on each,
// issuing a resumable session. It returns the listener address.
func tagTestServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				auth := NewAuthenticator(tagTestConfig("", "", ""), stream.NewStream(conn))
				_, _ = auth.ServerHandshake(context.Background())
			}()
		}
	}()
	return ln.Addr().String()
}

func tagTestConfig(peerName, tag, token string) *SecurityConfig {
	return &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthNone},
		Authentication: SecurityOptional,
		CryptoMethods:  []CryptoMethod{CryptoAES},
		Encryption:     SecurityRequired,
		Integrity:      SecurityRequired,
		Command:        commands.DC_NOP,
		PeerName:       peerName,
		SecurityTag:    tag,
		Token:          token,
	}
}

// tagTestDial runs one client handshake with the global session cache and
// returns the negotiated session id and whether it was resumed.
func tagTestDial(t *testing.T, addr, tag, token string) (string, bool) {
	t.Helper()
	return tagTestDialCache(t, addr, tag, token, nil)
}

// tagTestDialCache is tagTestDial with cache as the config's SessionCache
// (nil: the global cache).
func tagTestDialCache(t *testing.T, addr, tag, token string, cache *SessionCache) (string, bool) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// A fixed PeerName keys every dial to the same {addr,cmd} slot.
	cfg := tagTestConfig("tag-test-server", tag, token)
	cfg.SessionCache = cache
	auth := NewAuthenticator(cfg, stream.NewStream(conn))
	neg, err := auth.ClientHandshake(context.Background())
	if err != nil {
		t.Fatalf("client handshake (tag=%q token=%q): %v", tag, token, err)
	}
	if neg.SessionId == "" {
		t.Fatalf("client handshake (tag=%q token=%q): no session id", tag, token)
	}
	return neg.SessionId, neg.SessionResumed
}

// TestClientSessionTagIsolation checks that client sessions in the global
// cache are resumed only by a config with the same tag: the store used to map
// every session untagged while the lookup used the config's tag, so tagged
// configs never resumed their own sessions and left them in the untagged slot.
func TestClientSessionTagIsolation(t *testing.T) {
	GetSessionCache().Clear()
	t.Cleanup(func() { GetSessionCache().Clear() })
	addr := tagTestServer(t)

	idA, resumed := tagTestDial(t, addr, "tag-a", "")
	if resumed {
		t.Fatal("first tag-a dial resumed a session; want a full handshake")
	}

	idB, resumed := tagTestDial(t, addr, "tag-b", "")
	if resumed || idB == idA {
		t.Fatalf("tag-b resumed tag-a's session (resumed=%v, id equal=%v)", resumed, idB == idA)
	}

	idU, resumed := tagTestDial(t, addr, "", "")
	if resumed || idU == idA || idU == idB {
		t.Fatalf("untagged config resumed a tagged session (resumed=%v)", resumed)
	}

	if id, resumed := tagTestDial(t, addr, "tag-a", ""); !resumed || id != idA {
		t.Fatalf("tag-a did not resume its own session: resumed=%v id==idA %v", resumed, id == idA)
	}
	if id, resumed := tagTestDial(t, addr, "tag-b", ""); !resumed || id != idB {
		t.Fatalf("tag-b did not resume its own session: resumed=%v id==idB %v", resumed, id == idB)
	}
	if id, resumed := tagTestDial(t, addr, "", ""); !resumed || id != idU {
		t.Fatalf("untagged config did not resume its own session: resumed=%v id==idU %v", resumed, id == idU)
	}
	if _, resumed := tagTestDial(t, addr, "tag-c", ""); resumed {
		t.Fatal("tag-c resumed another config's session")
	}
}

// TestClientSessionTokenDerivedTag checks that a config carrying a token but
// no SecurityTag is isolated by the token: it neither resumes nor exposes the
// untagged slot, and a different token does not resume its session.
func TestClientSessionTokenDerivedTag(t *testing.T) {
	GetSessionCache().Clear()
	t.Cleanup(func() { GetSessionCache().Clear() })
	addr := tagTestServer(t)

	idU, _ := tagTestDial(t, addr, "", "")

	idA, resumed := tagTestDial(t, addr, "", "token-a")
	if resumed || idA == idU {
		t.Fatalf("token config resumed the untagged session (resumed=%v)", resumed)
	}
	idB, resumed := tagTestDial(t, addr, "", "token-b")
	if resumed || idB == idA {
		t.Fatalf("token-b resumed token-a's session (resumed=%v)", resumed)
	}

	if id, resumed := tagTestDial(t, addr, "", "token-a"); !resumed || id != idA {
		t.Fatalf("token-a did not resume its own session: resumed=%v", resumed)
	}
	if id, resumed := tagTestDial(t, addr, "", ""); !resumed || id != idU {
		t.Fatalf("untagged config did not resume its own session: resumed=%v", resumed)
	}

	// The session is stored under the derived tag, never the untagged key.
	entry, ok := GetSessionCache().Lookup(idA)
	if !ok {
		t.Fatal("token-a session not in the global cache")
	}
	if !strings.HasPrefix(entry.Tag(), tokenSessionTagPrefix) || strings.Contains(entry.Tag(), "token-a") {
		t.Fatalf("token-a session tag = %q, want a %s digest", entry.Tag(), tokenSessionTagPrefix)
	}
	if got, ok := GetSessionCache().LookupByCommand("", "tag-test-server", strconv.Itoa(commands.DC_NOP)); !ok || got.ID() != idU {
		t.Fatal("untagged {addr,cmd} slot does not hold the untagged session")
	}
}

// TestClientSessionPrivateCacheUntagged checks that the token-derived tag
// applies only to the global cache. A cache the caller supplies is its own
// partition: there an untagged token config keeps the untagged slot, so
// requests for one user whose token is minted afresh each time still resume
// each other's sessions -- and none of it reaches the global cache.
func TestClientSessionPrivateCacheUntagged(t *testing.T) {
	GetSessionCache().Clear()
	t.Cleanup(func() { GetSessionCache().Clear() })
	addr := tagTestServer(t)
	private := NewSessionCache()

	id1, resumed := tagTestDialCache(t, addr, "", "minted-1", private)
	if resumed {
		t.Fatal("first dial resumed a session")
	}
	if id, resumed := tagTestDialCache(t, addr, "", "minted-2", private); !resumed || id != id1 {
		t.Fatalf("private-cache config did not resume the session in its cache: resumed=%v", resumed)
	}
	if entry, ok := private.Lookup(id1); !ok || entry.Tag() != "" {
		t.Fatalf("private-cache session stored with tag %q, want untagged", entry.Tag())
	}
	// (The global cache does hold id1 as this process's server-side entry,
	// so look at the client command map, not the session table.)
	if _, ok := GetSessionCache().LookupByCommand("", "tag-test-server", strconv.Itoa(commands.DC_NOP)); ok {
		t.Fatal("private-cache session was mapped in the global cache")
	}
	if _, resumed := tagTestDial(t, addr, "", ""); resumed {
		t.Fatal("untagged global-cache config resumed a private-cache session")
	}
}

func TestClientSessionTag(t *testing.T) {
	global := GetSessionCache()
	private := NewSessionCache()
	if got := (&SecurityConfig{}).clientSessionTag(global); got != "" {
		t.Errorf("no tag, no token: got %q, want empty", got)
	}
	if got := (&SecurityConfig{SecurityTag: "x", Token: "t"}).clientSessionTag(global); got != "x" {
		t.Errorf("explicit tag: got %q, want %q", got, "x")
	}
	a := (&SecurityConfig{Token: "t1"}).clientSessionTag(global)
	b := (&SecurityConfig{Token: "t2"}).clientSessionTag(global)
	if a == "" || a == b || a != (&SecurityConfig{Token: "t1"}).clientSessionTag(global) {
		t.Errorf("derived tags: t1=%q t2=%q; want non-empty, distinct and stable", a, b)
	}
	if got := (&SecurityConfig{Token: "t1"}).clientSessionTag(private); got != "" {
		t.Errorf("token with a private cache: got %q, want empty", got)
	}
	if got := (&SecurityConfig{SecurityTag: "x", Token: "t1"}).clientSessionTag(private); got != "x" {
		t.Errorf("explicit tag with a private cache: got %q, want %q", got, "x")
	}
}

// authTestServer is tagTestServer with FS authentication offered at
// OPTIONAL, so whether a session is authenticated is the client's choice.
func authTestServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				cfg := tagTestConfig("", "", "")
				cfg.AuthMethods = []AuthMethod{AuthFS}
				auth := NewAuthenticator(cfg, stream.NewStream(conn))
				_, _ = auth.ServerHandshake(context.Background())
			}()
		}
	}()
	return ln.Addr().String()
}

// authTestDial runs one client handshake offering FS at authLevel, under a
// fixed tag and peer name, against the global cache.
func authTestDial(t *testing.T, addr string, authLevel SecurityLevel) *SecurityNegotiation {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	cfg := tagTestConfig("auth-test-server", "auth-test", "")
	cfg.AuthMethods = []AuthMethod{AuthFS}
	cfg.Authentication = authLevel
	neg, err := NewAuthenticator(cfg, stream.NewStream(conn)).ClientHandshake(context.Background())
	if err != nil {
		t.Fatalf("client handshake (%s): %v", authLevel, err)
	}
	return neg
}

// TestClientRequiredDoesNotResumeUnauthenticated checks that a session
// negotiated without authentication is recorded as such -- with no method
// name -- and that a config requiring authentication does not resume it but
// authenticates afresh, while configs that do not require it still resume.
func TestClientRequiredDoesNotResumeUnauthenticated(t *testing.T) {
	GetSessionCache().Clear()
	t.Cleanup(func() { GetSessionCache().Clear() })
	addr := authTestServer(t)

	optional := authTestDial(t, addr, SecurityOptional)
	if optional.SessionResumed || optional.Authentication {
		t.Fatalf("OPTIONAL/OPTIONAL handshake: resumed=%v authenticated=%v; want a fresh unauthenticated session",
			optional.SessionResumed, optional.Authentication)
	}
	entry, ok := GetSessionCache().LookupByCommand("auth-test", "auth-test-server", strconv.Itoa(commands.DC_NOP))
	if !ok || entry.ID() != optional.SessionId {
		t.Fatal("unauthenticated session not cached under its tag")
	}
	if m, _ := entry.Policy().EvaluateAttrString("AuthMethods"); m != string(AuthNone) {
		t.Errorf("unauthenticated session cached with AuthMethods=%q, want NONE", m)
	}
	if authed, ok := entry.Policy().EvaluateAttrBool(clientAuthenticatedAttr); !ok || authed {
		t.Errorf("unauthenticated session cached with %s=%v (present=%v), want false", clientAuthenticatedAttr, authed, ok)
	}

	resumed := authTestDial(t, addr, SecurityOptional)
	if !resumed.SessionResumed || resumed.SessionId != optional.SessionId {
		t.Fatal("OPTIONAL config did not resume the unauthenticated session")
	}
	if resumed.Authentication || resumed.NegotiatedAuth != AuthNone {
		t.Errorf("resumed unauthenticated session reports authenticated=%v method=%q, want false and NONE",
			resumed.Authentication, resumed.NegotiatedAuth)
	}

	required := authTestDial(t, addr, SecurityRequired)
	if required.SessionResumed || required.SessionId == optional.SessionId {
		t.Fatal("REQUIRED config resumed an unauthenticated session")
	}
	if required.NegotiatedAuth != AuthFS {
		t.Fatalf("REQUIRED handshake: method=%q, want FS", required.NegotiatedAuth)
	}
	if e, ok := GetSessionCache().LookupByCommand("auth-test", "auth-test-server", strconv.Itoa(commands.DC_NOP)); !ok || e.ID() != required.SessionId {
		t.Fatal("authenticated session did not replace the unauthenticated one under the tag")
	} else if authed, _ := e.Policy().EvaluateAttrBool(clientAuthenticatedAttr); !authed {
		t.Fatalf("authenticated session cached with %s=false", clientAuthenticatedAttr)
	} else if _, present := e.Policy().EvaluateAttrBool("Authenticated"); present {
		// The server side resumes by id from the same cache and trusts
		// "Authenticated"; a client session must not carry it.
		t.Fatal("client session carries the server-side Authenticated attribute")
	}

	again := authTestDial(t, addr, SecurityRequired)
	if !again.SessionResumed || again.SessionId != required.SessionId {
		t.Fatal("REQUIRED config did not resume its own authenticated session")
	}
	if !again.Authentication || again.NegotiatedAuth != AuthFS {
		t.Errorf("resumed authenticated session reports authenticated=%v method=%q, want true and FS",
			again.Authentication, again.NegotiatedAuth)
	}
}

// TestResumedSessionWithoutOutcomeReportsNoMethod checks that resuming a
// cached session that names a method but does not record that it was
// authenticated (as entries cached before the outcome was recorded do)
// reports no method rather than the recorded one.
func TestResumedSessionWithoutOutcomeReportsNoMethod(t *testing.T) {
	GetSessionCache().Clear()
	t.Cleanup(func() { GetSessionCache().Clear() })
	addr := tagTestServer(t)

	key := []byte("0123456789abcdef0123456789abcdef") // AES-256
	policy := classad.New()
	_ = policy.Set("AuthMethods", string(AuthToken))
	_ = policy.Set("CryptoMethods", string(CryptoAES))
	const sid = "legacy-session-no-outcome"
	// Global cache: the in-process server resumes it by id from there.
	GetSessionCache().Store(NewSessionEntry(sid, "tag-test-server",
		&KeyInfo{Data: key, Protocol: string(CryptoAES)}, policy, time.Now().Add(time.Hour), 0, ""))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	cfg := tagTestConfig("tag-test-server", "", "")
	cfg.SessionID = sid
	neg, err := NewAuthenticator(cfg, stream.NewStream(conn)).ClientHandshake(context.Background())
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !neg.SessionResumed {
		t.Fatal("session was not resumed")
	}
	if neg.Authentication || neg.NegotiatedAuth != AuthNone {
		t.Errorf("resumed session reports authenticated=%v method=%q, want false and NONE",
			neg.Authentication, neg.NegotiatedAuth)
	}
}

func TestMayResume(t *testing.T) {
	entry := func(authed *bool, key *KeyInfo) *SessionEntry {
		pol := classad.New()
		if authed != nil {
			_ = pol.Set(clientAuthenticatedAttr, *authed)
		}
		return NewSessionEntry("s", "peer", key, pol, time.Now().Add(time.Hour), 0, "")
	}
	// keyed is a claim / inherited / minted session: authenticated by key
	// possession, recorded as "Authenticated" (optionally alongside a
	// client-side record, which then decides).
	keyed := func(client *bool) *SessionEntry {
		pol := classad.New()
		_ = pol.Set("Authenticated", true)
		if client != nil {
			_ = pol.Set(clientAuthenticatedAttr, *client)
		}
		return NewSessionEntry("k", "peer", nil, pol, time.Now().Add(time.Hour), 0, "")
	}
	yes, no := true, false
	aes := &KeyInfo{Data: []byte("0123456789abcdef0123456789abcdef"), Protocol: string(CryptoAES)}

	cases := []struct {
		name  string
		cfg   SecurityConfig
		entry *SessionEntry
		want  bool
	}{
		{"optional accepts unauthenticated", SecurityConfig{Authentication: SecurityOptional}, entry(&no, aes), true},
		{"required refuses unauthenticated", SecurityConfig{Authentication: SecurityRequired}, entry(&no, aes), false},
		{"required refuses unrecorded outcome", SecurityConfig{Authentication: SecurityRequired}, entry(nil, aes), false},
		{"required accepts authenticated", SecurityConfig{Authentication: SecurityRequired}, entry(&yes, aes), true},
		{"encryption required refuses keyless", SecurityConfig{Encryption: SecurityRequired}, entry(&yes, nil), false},
		{"integrity required refuses keyless", SecurityConfig{Integrity: SecurityRequired}, entry(&yes, nil), false},
		{"encryption required accepts AES", SecurityConfig{Encryption: SecurityRequired}, entry(&yes, aes), true},
		{"encryption optional accepts keyless", SecurityConfig{Encryption: SecurityOptional}, entry(&yes, nil), true},
		{"required accepts a key-possession session", SecurityConfig{Authentication: SecurityRequired}, keyed(nil), true},
		{"client record overrides Authenticated", SecurityConfig{Authentication: SecurityRequired}, keyed(&no), false},
	}
	for _, tc := range cases {
		if got := tc.cfg.mayResume(tc.entry); got != tc.want {
			t.Errorf("%s: mayResume = %v, want %v", tc.name, got, tc.want)
		}
	}
}
