package security

import (
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

func expiredEntry(id string) *SessionEntry {
	return NewSessionEntry(id, "<127.0.0.1:9618>", nil, classad.New(),
		time.Now().Add(-time.Hour), 0, "")
}

// A server mints a fresh session id for every handshake and stores it with a
// one-hour duration, so a peer that never resumes leaves an entry unreachable
// by id. Nothing else collects those: Invalidate is reached only on a
// client-side resumption failure, and LookupNonExpired drops just the id it
// was asked for. Without a sweep on the growth path the map grew for the life
// of the process.
func TestStoreSweepsExpiredSessions(t *testing.T) {
	cache := NewSessionCache()

	// Within the first interval the cache is a plain map: storing does not
	// evict, so InvalidateExpired stays the only sweeper for callers that
	// depend on that.
	for _, id := range []string{"a", "b", "c"} {
		cache.Store(expiredEntry(id))
	}
	if got := cache.Size(); got != 3 {
		t.Fatalf("cache size = %d, want 3 before any sweep is due", got)
	}

	// Once the interval has passed, the next store sweeps.
	cache.mu.Lock()
	cache.lastSweep = time.Now().Add(-2 * sessionSweepInterval)
	cache.mu.Unlock()

	live := NewSessionEntry("live", "<127.0.0.1:9618>", nil, classad.New(),
		time.Now().Add(time.Hour), time.Hour, "")
	cache.Store(live)

	if got := cache.Size(); got != 1 {
		t.Errorf("cache size = %d, want 1: the three expired entries were not swept", got)
	}
	if _, ok := cache.LookupNonExpired("live"); !ok {
		t.Error("the sweep dropped the unexpired entry it was storing")
	}
}

// The sweeper reads each entry's expiration, which RenewLease writes. Reading
// the field directly raced; go test -race fails this if it regresses.
func TestSweepDoesNotRaceLeaseRenewal(t *testing.T) {
	cache := NewSessionCache()
	entries := make([]*SessionEntry, 0, 16)
	for i := 0; i < 16; i++ {
		e := NewSessionEntry(string(rune('a'+i)), "<127.0.0.1:9618>", nil, classad.New(),
			time.Now().Add(time.Hour), time.Hour, "")
		entries = append(entries, e)
		cache.Store(e)
	}

	var wg sync.WaitGroup
	for _, e := range entries {
		wg.Add(1)
		go func(e *SessionEntry) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				e.RenewLease()
			}
		}(e)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			cache.InvalidateExpired()
		}
	}()
	wg.Wait()
}
