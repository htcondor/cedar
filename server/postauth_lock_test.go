package server

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"
)

// TestPostAuthPolicyCallsCallbacksWithoutHoldingLock pins the rule that
// postAuthPolicy must release s.mu before running any application-supplied
// callback. CommandPerms' own documentation tells a caller enforcing
// per-command authorization to consult it, so an Authorizer (or a
// SecurityConfigForCommand hook, which commandLevelSatisfied calls) that does
// exactly that re-enters s.mu.RLock. sync.RWMutex is not reentrant: with a
// Handle queued on the write lock, the recursive read lock blocks behind the
// writer and both goroutines wedge forever, taking every later handshake with
// them.
//
// The test drives that interleaving deliberately: it lets postAuthPolicy reach
// the Authorizer, then starts a Handle, then has the Authorizer call
// CommandPerms. Everything is bounded, because the failure mode under test is
// a hang rather than a wrong answer.
func TestPostAuthPolicyCallsCallbacksWithoutHoldingLock(t *testing.T) {
	const (
		advertisedCmd = 60001
		laterCmd      = 60002

		// How long the Authorizer waits for the Handle it expects to be queued
		// on the write lock. When the lock is already released, Handle returns
		// first and this is not waited out at all.
		writerQueueWait = 250 * time.Millisecond

		// Overall bound. postAuthPolicy here does a handful of map reads and
		// one callback, so anything near this is a deadlock, not slowness.
		deadlockAfter = 10 * time.Second
	)

	noopHandler := func(ctx context.Context, c *Conn) error { return nil }

	srv := New(nil)
	srv.Handle(advertisedCmd, noopHandler, "READ")

	var (
		enteredOnce sync.Once
		entered     = make(chan struct{})
		handleDone  = make(chan struct{})
		permsSeen   = make(chan []string, 4)
	)

	srv.Authorizer = func(perm, peerAddr, user string) bool {
		enteredOnce.Do(func() { close(entered) })
		// Give the test a window to queue a writer behind us.
		select {
		case <-handleDone:
		case <-time.After(writerQueueWait):
		}
		// The callback a consumer is invited to write: back into the server,
		// which takes s.mu.RLock again.
		permsSeen <- srv.CommandPerms(advertisedCmd)
		return true
	}

	type result struct {
		fqu   string
		valid []int
	}
	policyDone := make(chan result, 1)
	go func() {
		fqu, valid := srv.postAuthPolicy("alice@example.com", "127.0.0.1:5000", true, true)
		policyDone <- result{fqu, valid}
	}()

	select {
	case <-entered:
	case <-time.After(deadlockAfter):
		t.Fatalf("Authorizer was never reached within %s", deadlockAfter)
	}

	// Queue a writer while postAuthPolicy is mid-flight. Go's RWMutex blocks
	// new readers once a writer is waiting, so this is what turns a recursive
	// read lock into a deadlock.
	go func() {
		srv.Handle(laterCmd, noopHandler, "WRITE")
		close(handleDone)
	}()

	select {
	case got := <-policyDone:
		if got.fqu != "alice@example.com" {
			t.Errorf("fqu = %q, want %q", got.fqu, "alice@example.com")
		}
		if !slices.Contains(got.valid, advertisedCmd) {
			t.Errorf("valid = %v, want it to contain %d", got.valid, advertisedCmd)
		}
	case <-time.After(deadlockAfter):
		t.Fatalf("deadlock: postAuthPolicy did not return within %s; the Authorizer re-entered s.mu.RLock behind a queued Handle", deadlockAfter)
	}

	select {
	case perms := <-permsSeen:
		if !slices.Equal(perms, []string{"READ"}) {
			t.Errorf("CommandPerms from the Authorizer = %v, want [READ]", perms)
		}
	default:
		t.Error("the Authorizer never completed its CommandPerms call")
	}

	select {
	case <-handleDone:
	case <-time.After(deadlockAfter):
		t.Fatalf("deadlock: Handle did not return within %s while postAuthPolicy held s.mu.RLock", deadlockAfter)
	}
}
