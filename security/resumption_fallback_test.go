package security

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/htcondor/cedar/stream"
)

// TestResumptionExchangeFailureIsResumptionError reproduces the restart race a
// collector hits against a database that keeps no session store: the client
// holds a cached (persisted) session, sends a resumption request, and the peer
// drops the connection instead of answering. That failure must be classified a
// SessionResumptionError -- so ConnectAndAuthenticate falls back to a fresh
// connection with full authentication -- and the doomed session must leave the
// cache, so the fallback (and every later dial) does not re-attempt it.
func TestResumptionExchangeFailureIsResumptionError(t *testing.T) {
	cconn, sconn := net.Pipe()

	cache := NewSessionCache()
	entry := NewSessionEntry("test-session-id", "127.0.0.1:9618", nil, nil,
		time.Now().Add(time.Hour), time.Hour, "")
	cache.Store(entry)

	cfg := &SecurityConfig{Command: 1234}
	auth := NewAuthenticator(cfg, stream.NewStream(cconn))

	// Peer: read a little of the request, then hang up without a response --
	// the mid-restart shape (reset/EOF on the client side).
	go func() {
		buf := make([]byte, 64)
		_, _ = sconn.Read(buf)
		_ = sconn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := auth.resumeSession(ctx, entry, cache)
	if err == nil {
		t.Fatal("resumeSession succeeded against a peer that hung up")
	}
	if !IsSessionResumptionError(err) {
		t.Fatalf("exchange failure not classified as SessionResumptionError: %v", err)
	}
	if _, still := cache.Lookup("test-session-id"); still {
		t.Fatal("failed resumption left the stale session cached; every reconnect would re-attempt it")
	}
}

// TestPinnedResumptionFailureKeepsSession covers the other kind of session: one
// the caller named outright with SecurityConfig.SessionID. That is a credential
// handed to this dial -- a schedd-minted starter claim, say -- and not a cache
// entry that can be re-derived by authenticating again. A failed exchange must
// leave it in place, or ConnectAndAuthenticate's retry has nothing to offer.
func TestPinnedResumptionFailureKeepsSession(t *testing.T) {
	cconn, sconn := net.Pipe()

	cache := NewSessionCache()
	entry := NewSessionEntry("pinned-session-id", "127.0.0.1:9618", nil, nil,
		time.Now().Add(time.Hour), time.Hour, "")
	cache.Store(entry)

	cfg := &SecurityConfig{Command: 1234, SessionID: "pinned-session-id", SessionCache: cache}
	auth := NewAuthenticator(cfg, stream.NewStream(cconn))

	go func() {
		buf := make([]byte, 64)
		_, _ = sconn.Read(buf)
		_ = sconn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := auth.resumeSession(ctx, entry, cache)
	if err == nil {
		t.Fatal("resumeSession succeeded against a peer that hung up")
	}
	if !IsSessionResumptionError(err) {
		t.Fatalf("exchange failure not classified as SessionResumptionError: %v", err)
	}
	if _, still := cache.Lookup("pinned-session-id"); !still {
		t.Fatal("a failed exchange dropped the caller's pinned session; the retry has no credential left")
	}
}

// TestPinnedRetryReportsTheRealFailure is the symptom this was found as: an
// exec on a job behind CCB failed with "pre-registered session not found in
// cache", which named the cache rather than anything that had gone wrong. The
// first attempt's failure had evicted the one session the second attempt
// needed, so the second attempt reported the eviction and the real reason was
// never logged. The retry must fail the way the first attempt did.
func TestPinnedRetryReportsTheRealFailure(t *testing.T) {
	cache := NewSessionCache()
	entry := NewSessionEntry("pinned-session-id", "127.0.0.1:9618", nil, nil,
		time.Now().Add(time.Hour), time.Hour, "")
	cache.Store(entry)
	cfg := &SecurityConfig{Command: 1234, SessionID: "pinned-session-id", SessionCache: cache}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Each attempt gets its own connection, as ConnectAndAuthenticate's retry
	// does; both peers hang up mid-exchange.
	var last error
	for attempt := range 2 {
		cconn, sconn := net.Pipe()
		go func() {
			buf := make([]byte, 64)
			_, _ = sconn.Read(buf)
			_ = sconn.Close()
		}()
		_, err := NewAuthenticator(cfg, stream.NewStream(cconn)).ClientHandshake(ctx)
		if err == nil {
			t.Fatalf("attempt %d: handshake succeeded against a peer that hung up", attempt)
		}
		last = err
	}

	var sre *SessionResumptionError
	if !errors.As(last, &sre) {
		t.Fatalf("retry failure not a SessionResumptionError: %v", last)
	}
	if sre.Reason == "pre-registered session not found in cache" {
		t.Fatalf("retry blamed the cache instead of the failure that caused it: %v", last)
	}
	if sre.Cause == nil {
		t.Fatalf("retry failure carries no underlying cause, so the real reason is still unreported: %v", last)
	}
}
