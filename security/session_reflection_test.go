package security

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/stream"
)

// reflectionConfig is an encrypted, authentication-optional policy, the
// shape of a daemon's READ-level command policy.
func reflectionConfig(peerName string) *SecurityConfig {
	return &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthNone},
		Authentication: SecurityOptional,
		CryptoMethods:  []CryptoMethod{CryptoAES},
		Encryption:     SecurityRequired,
		Integrity:      SecurityRequired,
		Command:        commands.DC_NOP,
		PeerName:       peerName,
	}
}

// serveOnce accepts one connection on a fresh listener, runs the server
// handshake with cfg, and delivers the resulting negotiation.
func serveOnce(t *testing.T, cfg *SecurityConfig) (string, <-chan *SecurityNegotiation) {
	t.Helper()
	return serveOnceWith(t, cfg, nil)
}

// serveOnceWith is serveOnce with a hook to adjust the server's stream.
func serveOnceWith(t *testing.T, cfg *SecurityConfig, setup func(*stream.Stream)) (string, <-chan *SecurityNegotiation) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	out := make(chan *SecurityNegotiation, 1)
	go func() {
		defer close(out)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		st := stream.NewStream(conn)
		if setup != nil {
			setup(st)
		}
		neg, err := NewAuthenticator(cfg, st).ServerHandshake(context.Background())
		if err != nil {
			t.Logf("server handshake: %v", err)
			return
		}
		out <- neg
	}()
	return ln.Addr().String(), out
}

func recvNeg(t *testing.T, ch <-chan *SecurityNegotiation) *SecurityNegotiation {
	t.Helper()
	select {
	case neg := <-ch:
		return neg
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for server handshake")
		return nil
	}
}

// TestClientSessionNotReflectedAsOwnIdentity: a session this process
// negotiated as a client is known to the peer (it chose the id and holds the
// key). If the peer resumes it against this process's server, the server
// must not attribute the connection to the identity the peer reported for
// us; a client-side entry records no authenticated peer, so the reversed
// session is unauthenticated.
func TestClientSessionNotReflectedAsOwnIdentity(t *testing.T) {
	GetSessionCache().Clear()
	t.Cleanup(func() { GetSessionCache().Clear() })

	const reported = "condor@pool"
	const peerName = "reflection-peer"

	// The peer's server: no authentication, but its post-auth ad tells the
	// client it is "condor@pool".
	peerCfg := reflectionConfig("")
	peerCfg.PostAuthPolicy = func(string, string, bool, bool) (string, []int) {
		return reported, []int{commands.DC_NOP}
	}
	// The peer is another process: with no peer address its server side
	// skips caching the session, so only our client side is in our cache.
	peerAddr, peerNegCh := serveOnceWith(t, peerCfg, func(st *stream.Stream) { st.SetPeerAddr("") })

	conn, err := net.Dial("tcp", peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	clientNeg, err := NewAuthenticator(reflectionConfig(peerName), stream.NewStream(conn)).ClientHandshake(context.Background())
	_ = conn.Close()
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if clientNeg.User != reported {
		t.Fatalf("client User = %q, want the identity the peer reported (%q)", clientNeg.User, reported)
	}
	peerNeg := recvNeg(t, peerNegCh)
	sid := clientNeg.SessionId

	entry, ok := GetSessionCache().Lookup(sid)
	if !ok || entry.Addr() != peerName {
		t.Fatalf("global cache entry for the session is not the client-side one (ok=%v)", ok)
	}

	// Our own server, resuming from the global cache.
	ownAddr, ownNegCh := serveOnce(t, reflectionConfig(""))

	// The peer resumes the session against our server with the id and key it
	// holds from its side of the handshake.
	peerCache := NewSessionCache()
	pol := classad.New()
	_ = pol.Set("CryptoMethods", string(peerNeg.NegotiatedCrypto))
	peerCache.Store(NewSessionEntry(sid, ownAddr, &KeyInfo{
		Data:     peerNeg.GetSharedSecret(),
		Protocol: string(peerNeg.NegotiatedCrypto),
	}, pol, time.Now().Add(time.Hour), time.Hour, ""))
	rcfg := reflectionConfig(ownAddr)
	rcfg.SessionCache = peerCache
	rcfg.SessionID = sid
	rconn, err := net.Dial("tcp", ownAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rconn.Close() }()
	if _, err := NewAuthenticator(rcfg, stream.NewStream(rconn)).ClientHandshake(context.Background()); err != nil {
		t.Fatalf("reversed resume: %v", err)
	}
	ownNeg := recvNeg(t, ownNegCh)

	if !ownNeg.SessionResumed || ownNeg.SessionId != sid {
		t.Fatalf("server did not resume the session (resumed=%v)", ownNeg.SessionResumed)
	}
	t.Logf("reversed resume: server assigned User=%q Authentication=%v", ownNeg.User, ownNeg.Authentication)
	if ownNeg.User != "" || ownNeg.Authentication {
		t.Fatalf("reversed resume of a client-side session: User=%q Authentication=%v, want unauthenticated", ownNeg.User, ownNeg.Authentication)
	}

	// Our own reuse of the session as a client still reports our identity.
	ownCfg := reflectionConfig(peerName)
	if got, ok := GetSessionCache().LookupByCommand("", peerName, strconv.Itoa(commands.DC_NOP)); !ok || got.ID() != sid {
		t.Fatal("client session not mapped for resumption")
	}
	resumeAddr, _ := serveOnce(t, reflectionConfig(""))
	c2, err := net.Dial("tcp", resumeAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	resumed, err := NewAuthenticator(ownCfg, stream.NewStream(c2)).ClientHandshake(context.Background())
	if err != nil {
		t.Fatalf("client resume: %v", err)
	}
	if !resumed.SessionResumed || resumed.User != reported {
		t.Fatalf("client resume: resumed=%v User=%q, want %q", resumed.SessionResumed, resumed.User, reported)
	}
}

// TestResumeAuthenticatedRequiresUser: an entry flagged Authenticated but
// naming no peer resumes unauthenticated on the server.
func TestResumeAuthenticatedRequiresUser(t *testing.T) {
	GetSessionCache().Clear()
	t.Cleanup(func() { GetSessionCache().Clear() })

	const sid = "authenticated-without-user"
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	pol := classad.New()
	_ = pol.Set("Authenticated", true)
	_ = pol.Set("AuthMethods", string(AuthToken))
	_ = pol.Set("CryptoMethods", string(CryptoAES))
	GetSessionCache().Store(NewSessionEntry(sid, "somewhere", &KeyInfo{Data: key, Protocol: string(CryptoAES)},
		pol, time.Now().Add(time.Hour), time.Hour, ""))

	addr, negCh := serveOnce(t, reflectionConfig(""))
	cache := NewSessionCache()
	cpol := classad.New()
	_ = cpol.Set("CryptoMethods", string(CryptoAES))
	cache.Store(NewSessionEntry(sid, addr, &KeyInfo{Data: key, Protocol: string(CryptoAES)},
		cpol, time.Now().Add(time.Hour), time.Hour, ""))
	cfg := reflectionConfig(addr)
	cfg.SessionCache = cache
	cfg.SessionID = sid
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := NewAuthenticator(cfg, stream.NewStream(conn)).ClientHandshake(context.Background()); err != nil {
		t.Fatalf("resume: %v", err)
	}
	neg := recvNeg(t, negCh)
	if !neg.SessionResumed {
		t.Fatal("server did not resume the session")
	}
	if neg.Authentication {
		t.Fatal("entry with no User resumed as authenticated")
	}

	// Control: the same entry naming a peer resumes authenticated.
	pol2 := classad.New()
	_ = pol2.Set("Authenticated", true)
	_ = pol2.Set("User", "alice@domain")
	_ = pol2.Set("CryptoMethods", string(CryptoAES))
	GetSessionCache().Store(NewSessionEntry(sid, "somewhere", &KeyInfo{Data: key, Protocol: string(CryptoAES)},
		pol2, time.Now().Add(time.Hour), time.Hour, ""))
	addr2, negCh2 := serveOnce(t, reflectionConfig(""))
	cache.Store(NewSessionEntry(sid, addr2, &KeyInfo{Data: key, Protocol: string(CryptoAES)},
		cpol, time.Now().Add(time.Hour), time.Hour, ""))
	cfg2 := reflectionConfig(addr2)
	cfg2.SessionCache = cache
	cfg2.SessionID = sid
	conn2, err := net.Dial("tcp", addr2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn2.Close() }()
	if _, err := NewAuthenticator(cfg2, stream.NewStream(conn2)).ClientHandshake(context.Background()); err != nil {
		t.Fatalf("resume: %v", err)
	}
	neg2 := recvNeg(t, negCh2)
	if !neg2.Authentication || neg2.User != "alice@domain" {
		t.Fatalf("entry naming a peer: Authentication=%v User=%q, want true alice@domain", neg2.Authentication, neg2.User)
	}
}
