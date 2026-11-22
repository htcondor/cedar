package security

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/stream"
)

// onWriteConn runs fn once, before the first Write after arm is set.
type onWriteConn struct {
	net.Conn
	arm  *atomic.Bool
	once sync.Once
	fn   func()
}

func (c *onWriteConn) Write(b []byte) (int, error) {
	if c.arm.Load() {
		c.once.Do(c.fn)
	}
	return c.Conn.Write(b)
}

// TestClientSessionIDCollisionKeepsExisting: a server we dial as a client
// picks the session id. When it names the id of a session already in our
// cache (here a server session for client A), our client must not replace
// that entry: A keeps its key and identity and can still resume, and the
// new client session is simply not cached.
func TestClientSessionIDCollisionKeepsExisting(t *testing.T) {
	GetSessionCache().Clear()
	t.Cleanup(func() { GetSessionCache().Clear() })

	const marker = "collision-peer-side"
	const peerName = "collision-peer"
	keyA := bytes.Repeat([]byte{0xA5}, 32)
	var sid string
	var victim *SessionEntry

	// The peer's server. Running in this process, it caches its own side of
	// the session under the id it generated; just before it sends that id to
	// us, put A's session under the same id in its place, as if A held it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var arm atomic.Bool
	peerCfg := reflectionConfig("")
	peerCfg.PostAuthPolicy = func(string, string, bool, bool) (string, []int) {
		arm.Store(true)
		return "", []int{commands.DC_NOP}
	}
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		wc := &onWriteConn{Conn: conn, arm: &arm, fn: func() {
			for _, e := range GetSessionCache().Snapshot() {
				if e.Addr() == marker {
					sid = e.ID()
				}
			}
			pol := classad.New()
			_ = pol.Set("Authenticated", true)
			_ = pol.Set("User", "alice@domain")
			_ = pol.Set("AuthMethods", string(AuthToken))
			_ = pol.Set("CryptoMethods", string(CryptoAES))
			victim = NewSessionEntry(sid, "client-a", &KeyInfo{Data: keyA, Protocol: string(CryptoAES)},
				pol, time.Now().Add(time.Hour), time.Hour, "")
			GetSessionCache().Store(victim)
		}}
		st := stream.NewStream(wc)
		st.SetPeerAddr(marker)
		_, _ = NewAuthenticator(peerCfg, st).ServerHandshake(context.Background())
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientNeg, err := NewAuthenticator(reflectionConfig(peerName), stream.NewStream(conn)).ClientHandshake(context.Background())
	_ = conn.Close()
	<-peerDone
	if err != nil {
		t.Fatalf("client handshake with a colliding session id: %v", err)
	}
	if sid == "" || clientNeg.SessionId != sid {
		t.Fatalf("peer did not hand back the colliding id (sid set=%v)", sid != "")
	}

	got, ok := GetSessionCache().Lookup(sid)
	if !ok || got != victim {
		t.Fatal("client replaced the existing session under the colliding id")
	}
	if !bytes.Equal(got.KeyInfo().Data, keyA) {
		t.Fatal("existing session's key changed")
	}
	if u, _ := got.Policy().EvaluateAttrString("User"); u != "alice@domain" {
		t.Fatalf("existing session's User = %q, want alice@domain", u)
	}
	if _, ok := GetSessionCache().LookupByCommand("", peerName, strconv.Itoa(commands.DC_NOP)); ok {
		t.Fatal("uncached client session was mapped for resumption")
	}

	// A resumes its session against our server.
	addr, negCh := serveOnce(t, reflectionConfig(""))
	cache := NewSessionCache()
	cpol := classad.New()
	_ = cpol.Set("CryptoMethods", string(CryptoAES))
	cache.Store(NewSessionEntry(sid, addr, &KeyInfo{Data: keyA, Protocol: string(CryptoAES)},
		cpol, time.Now().Add(time.Hour), time.Hour, ""))
	cfg := reflectionConfig(addr)
	cfg.SessionCache = cache
	cfg.SessionID = sid
	aconn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = aconn.Close() }()
	if _, err := NewAuthenticator(cfg, stream.NewStream(aconn)).ClientHandshake(context.Background()); err != nil {
		t.Fatalf("A's resume: %v", err)
	}
	neg := recvNeg(t, negCh)
	if !neg.SessionResumed || neg.User != "alice@domain" || !neg.Authentication {
		t.Fatalf("A's resume: resumed=%v User=%q Authentication=%v, want alice@domain authenticated",
			neg.SessionResumed, neg.User, neg.Authentication)
	}
}

// TestImportClaimSessionKeepsExisting: a claim id, and so its session id,
// comes from the peer. Importing one whose id is already held by a session
// with a different key is refused and leaves that session alone; importing
// the same claim again succeeds.
func TestImportClaimSessionKeepsExisting(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	info := `[Encryption="YES";Integrity="YES";CryptoMethods="AES";]`
	claimID := buildStartdClaimID("<127.0.0.1:9618>", "1700000000", "7", info, key)
	const sesid = "<127.0.0.1:9618>#1700000000#7"
	const ftID = fileTransferSessionPrefix + sesid

	for _, tc := range []struct {
		name     string
		id       string
		doImport func(*SessionCache) (string, error)
	}{
		{"claim", sesid, func(c *SessionCache) (string, error) {
			return ImportClaimSession(c, claimID, ClaimSessionOptions{})
		}},
		{"filetrans", ftID, func(c *SessionCache) (string, error) {
			return ImportFileTransferSession(c, claimID, ClaimSessionOptions{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := NewSessionCache()
			other := bytes.Repeat([]byte{0x5A}, 32)
			pol := classad.New()
			_ = pol.Set("User", "alice@domain")
			existing := NewSessionEntry(tc.id, "client-a", &KeyInfo{Data: other, Protocol: "AESGCM"},
				pol, time.Now().Add(time.Hour), time.Hour, "")
			cache.Store(existing)

			if _, err := tc.doImport(cache); err == nil {
				t.Fatal("import over an existing session with a different key succeeded")
			}
			if got, ok := cache.Lookup(tc.id); !ok || got != existing || !bytes.Equal(got.KeyInfo().Data, other) {
				t.Fatal("import replaced the existing session")
			}

			fresh := NewSessionCache()
			if _, err := tc.doImport(fresh); err != nil {
				t.Fatalf("first import: %v", err)
			}
			first, _ := fresh.Lookup(tc.id)
			if _, err := tc.doImport(fresh); err != nil {
				t.Fatalf("re-import of the same claim: %v", err)
			}
			if got, ok := fresh.Lookup(tc.id); !ok || got != first {
				t.Fatal("re-import did not keep the existing session")
			}
		})
	}
}
