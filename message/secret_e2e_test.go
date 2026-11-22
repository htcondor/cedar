package message

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"sync"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/stream"
)

// recordingConn tees everything read from the wrapped connection, so a test can
// inspect the actual bytes that crossed the wire.
type recordingConn struct {
	net.Conn
	mu  sync.Mutex
	log bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.log.Write(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordingConn) wire() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.log.Bytes()...)
}

// TestE2EPrivateAdSecretRoundTrip is the end-to-end coverage for the SECRET_MARKER
// path over REAL streams: a Go sender serializes an ad carrying a private attribute
// (a claim id) and a Go receiver reads it back, on a channel that has a session key
// but is not currently encrypting normal traffic -- exactly the condition where
// HTCondor wraps the private attribute in SECRET_MARKER + put_secret.
//
// It asserts three things end to end: the claim id round-trips intact (marker
// written and consumed, no desync), the claim id is NOT on the wire in cleartext
// (it was put_secret-encrypted), and the SECRET_MARKER itself is on the wire (the
// marker path actually ran). Before the fix, the receiver desynced on the marker
// and the claim id surfaced mangled in the MyType slot.
func TestE2EPrivateAdSecretRoundTrip(t *testing.T) {
	ctx := context.Background()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	rec := &recordingConn{Conn: server}
	cs := stream.NewStream(client)
	ss := stream.NewStream(rec)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := cs.SetSymmetricKey(key); err != nil {
		t.Fatal(err)
	}
	if err := ss.SetSymmetricKey(key); err != nil {
		t.Fatal(err)
	}
	// Session key present, but normal traffic is NOT encrypted -> the marker path.
	cs.SetEncrypted(false)
	ss.SetEncrypted(false)

	const secret = "abc123deadbeefclaimidsecret789"
	ad, err := classad.ParseOld(`Name = "slot1@h"` + "\n" + `MyType = "Machine"` + "\n" + `ClaimId = "` + secret + `"`)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		m := NewMessageForStream(cs)
		if werr := m.PutClassAdWithOptions(ctx, ad, &PutClassAdConfig{Options: PutClassAdIncludePrivate}); werr != nil {
			t.Errorf("write: %v", werr)
			return
		}
		if werr := m.FinishMessage(ctx); werr != nil {
			t.Errorf("finish: %v", werr)
		}
	}()

	got, err := NewMessageFromStream(ss).GetClassAd(ctx)
	if err != nil {
		t.Fatalf("GetClassAd: %v", err)
	}
	wg.Wait()

	// 1. Round-trip: the claim id survives intact.
	if cid, ok := got.EvaluateAttrString("ClaimId"); !ok || cid != secret {
		t.Fatalf("ClaimId = %q ok=%v, want %q", cid, ok, secret)
	}
	if v, _ := got.EvaluateAttrString("Name"); v != "slot1@h" {
		t.Errorf("Name = %q, want slot1@h", v)
	}
	if v, _ := got.EvaluateAttrString("MyType"); v != "Machine" {
		t.Errorf("MyType = %q, want Machine", v)
	}

	// 2. Secrecy: the claim id must NOT be on the wire in the clear.
	wire := rec.wire()
	if bytes.Contains(wire, []byte(secret)) {
		t.Errorf("claim id leaked in cleartext on the wire")
	}
	// 3. The marker path actually ran (marker itself is cleartext).
	if !bytes.Contains(wire, []byte(SecretMarker)) {
		t.Errorf("SECRET_MARKER not on the wire; the marker path did not run")
	}
}

// TestE2EPrivateAdPlaintextChannel is the companion: with NO session key the
// channel cannot encrypt, so HTCondor sends private attributes in the clear (no
// marker). The ad must still round-trip -- proving the sender only takes the marker
// path when crypto is actually available.
func TestE2EPrivateAdPlaintextChannel(t *testing.T) {
	ctx := context.Background()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	cs := stream.NewStream(client) // no key -> gcm nil -> CryptoForSecretIsNoop
	ss := stream.NewStream(server)

	ad, err := classad.ParseOld(`Name = "slot1@h"` + "\n" + `ClaimId = "plainclaim42"`)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		m := NewMessageForStream(cs)
		if werr := m.PutClassAdWithOptions(ctx, ad, &PutClassAdConfig{Options: PutClassAdIncludePrivate}); werr != nil {
			t.Errorf("write: %v", werr)
			return
		}
		if werr := m.FinishMessage(ctx); werr != nil {
			t.Errorf("finish: %v", werr)
		}
	}()

	got, err := NewMessageFromStream(ss).GetClassAd(ctx)
	if err != nil {
		t.Fatalf("GetClassAd: %v", err)
	}
	wg.Wait()

	if cid, ok := got.EvaluateAttrString("ClaimId"); !ok || cid != "plainclaim42" {
		t.Fatalf("ClaimId = %q ok=%v, want plainclaim42", cid, ok)
	}
}
