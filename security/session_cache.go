package security

import (
	"crypto/subtle"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// KeyInfo represents a cryptographic key with metadata
type KeyInfo struct {
	Data     []byte
	Protocol string // "AESGCM", "BLOWFISH", "3DES", etc.
}

// SessionEntry represents a cached security session. One entry is shared by every
// connection that resumes the session, so its mutable fields (expiration,
// lastPeerVersion, inherited) are guarded by mu; the rest are immutable after
// construction. A concurrent collector/CCB resuming one session from many
// connections would otherwise race on these (caught by TestConcurrentServerHandshakes).
type SessionEntry struct {
	mu              sync.Mutex
	id              string
	addr            string // Remote address this session is for (empty for incoming sessions)
	keyInfo         *KeyInfo
	policy          *classad.ClassAd
	expiration      time.Time // guarded by mu
	lease           time.Duration
	lastPeerVersion string // guarded by mu
	tag             string // Security context tag
	createdAt       time.Time
	inherited       bool // guarded by mu; true for sessions imported from the parent daemon
}

// NewSessionEntry creates a new session cache entry
func NewSessionEntry(id, addr string, keyInfo *KeyInfo, policy *classad.ClassAd, expiration time.Time, lease time.Duration, tag string) *SessionEntry {
	return &SessionEntry{
		id:         id,
		addr:       addr,
		keyInfo:    keyInfo,
		policy:     policy,
		expiration: expiration,
		lease:      lease,
		tag:        tag,
		createdAt:  time.Now(),
	}
}

// ID returns the session ID
func (s *SessionEntry) ID() string {
	return s.id
}

// Addr returns the remote address
func (s *SessionEntry) Addr() string {
	return s.addr
}

// KeyInfo returns the session key
func (s *SessionEntry) KeyInfo() *KeyInfo {
	return s.keyInfo
}

// Policy returns the security policy
func (s *SessionEntry) Policy() *classad.ClassAd {
	return s.policy
}

// Expiration returns the expiration time
func (s *SessionEntry) Expiration() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiration
}

// Lease returns the lease duration
func (s *SessionEntry) Lease() time.Duration {
	return s.lease
}

// Tag returns the security context tag
func (s *SessionEntry) Tag() string {
	return s.tag
}

// LastPeerVersion returns the last known peer version
func (s *SessionEntry) LastPeerVersion() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastPeerVersion
}

// SetLastPeerVersion sets the last peer version
func (s *SessionEntry) SetLastPeerVersion(version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastPeerVersion = version
}

// IsInherited reports whether this session was imported from the parent daemon
// (via CONDOR_PRIVATE_INHERIT). Inherited sessions are re-imported from the
// environment on every start and must not be persisted to disk.
func (s *SessionEntry) IsInherited() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inherited
}

// SetInherited marks this session as imported from the parent daemon.
func (s *SessionEntry) SetInherited(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inherited = v
}

// IsExpired checks if the session has expired
func (s *SessionEntry) IsExpired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expiration.IsZero() {
		return false
	}
	return time.Now().After(s.expiration)
}

// RenewLease renews the session lease
func (s *SessionEntry) RenewLease() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lease.Seconds() != 0 {
		s.expiration = time.Now().Add(s.lease)
	}
}

// SessionCache manages cached security sessions
type SessionCache struct {
	mu         sync.RWMutex
	sessions   map[string]*SessionEntry
	commandMap map[string]string // Maps {tag,addr,<cmd>} to session ID
	lastSweep  time.Time         // when expired entries were last dropped
}

// sessionSweepInterval bounds how often storing a session sweeps expired ones.
// Entries last an hour by default, so sweeping on every store would be pure
// overhead; sweeping never let the map grow for the life of the process.
const sessionSweepInterval = time.Minute

// NewSessionCache creates a new session cache
func NewSessionCache() *SessionCache {
	return &SessionCache{
		sessions:   make(map[string]*SessionEntry),
		commandMap: make(map[string]string),
		// Start the clock now, so a fresh cache behaves as a plain map for the
		// first interval: Store stays a plain insert and InvalidateExpired is
		// the only sweeper until then.
		lastSweep: time.Now(),
	}
}

// Store adds or updates a session in the cache
func (c *SessionCache) Store(entry *SessionEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions[entry.id] = entry
	c.sweepExpiredLocked()
}

// sweepExpiredLocked drops expired entries, at most once per
// sessionSweepInterval. The caller holds c.mu.
//
// Storing is the growth path, so it is also where the sweep belongs: a server
// mints a fresh id for every handshake and stores it with a one-hour duration,
// and a peer that never resumes leaves an entry unreachable by id. Nothing
// else collects those -- Invalidate is reached only on a client-side
// resumption failure, and LookupNonExpired drops just the one id it was asked
// for -- so the map grew for the life of the process.
func (c *SessionCache) sweepExpiredLocked() {
	now := time.Now()
	if !c.lastSweep.IsZero() && now.Sub(c.lastSweep) < sessionSweepInterval {
		return
	}
	c.lastSweep = now
	c.invalidateExpiredLocked()
}

// storeNew adds entry unless an unexpired session already holds its id, in
// which case the cache is left unchanged and the existing entry is returned
// with false. Use it wherever the id was chosen by a peer, so a peer cannot
// replace another session by naming its id. HTCondor's session cache behaves
// the same way (KeyCache::emplace).
func (c *SessionCache) storeNew(entry *SessionEntry) (*SessionEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.sessions[entry.id]; ok && !old.IsExpired() {
		return old, false
	}
	c.sessions[entry.id] = entry
	return entry, true
}

// sameSessionKey reports whether two entries hold the same session key, i.e.
// are the same session (for example both ends of a connection this process
// made to itself). Only a holder of the key can produce a match.
func sameSessionKey(a, b *SessionEntry) bool {
	ak, bk := a.KeyInfo(), b.KeyInfo()
	return ak != nil && bk != nil && len(ak.Data) > 0 &&
		subtle.ConstantTimeCompare(ak.Data, bk.Data) == 1
}

// Snapshot returns a copy of the current session entries. The returned slice is
// independent of the cache's internal map (callers may iterate it without
// holding the lock), though the *SessionEntry pointers are shared. It is used by
// persistence layers to enumerate sessions; callers typically skip expired and
// inherited entries (see IsExpired / IsInherited).
func (c *SessionCache) Snapshot() []*SessionEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*SessionEntry, 0, len(c.sessions))
	for _, e := range c.sessions {
		out = append(out, e)
	}
	return out
}

// Lookup retrieves a session by ID
func (c *SessionCache) Lookup(id string) (*SessionEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.sessions[id]
	if !ok {
		return nil, false
	}

	// Check if expired
	if entry.IsExpired() {
		return nil, false
	}

	return entry, true
}

// LookupNonExpired retrieves a non-expired session by ID
func (c *SessionCache) LookupNonExpired(id string) (*SessionEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.sessions[id]
	if !ok {
		return nil, false
	}

	// Check if expired
	if entry.IsExpired() {
		// Remove expired session
		delete(c.sessions, id)
		return nil, false
	}

	return entry, true
}

// LookupByCommand finds a session for a specific command to an address
func (c *SessionCache) LookupByCommand(tag, addr, command string) (*SessionEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var key string
	if tag != "" {
		key = fmt.Sprintf("{%s,%s,<%s>}", tag, addr, command)
	} else {
		key = fmt.Sprintf("{%s,<%s>}", addr, command)
	}

	sessionID, ok := c.commandMap[key]
	if !ok {
		return nil, false
	}

	entry, ok := c.sessions[sessionID]
	if !ok {
		return nil, false
	}

	if entry.IsExpired() {
		return nil, false
	}

	return entry, true
}

// MapCommand maps a command to a session ID
func (c *SessionCache) MapCommand(tag, addr, command, sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var key string
	if tag != "" {
		key = fmt.Sprintf("{%s,%s,<%s>}", tag, addr, command)
	} else {
		key = fmt.Sprintf("{%s,<%s>}", addr, command)
	}

	c.commandMap[key] = sessionID
}

// Invalidate removes a session from the cache
func (c *SessionCache) Invalidate(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.sessions[id]
	if !ok {
		return false
	}

	delete(c.sessions, id)

	// Remove all command mappings to this session
	for key, sessID := range c.commandMap {
		if sessID == id {
			delete(c.commandMap, key)
		}
	}

	return true
}

// InvalidateExpired removes all expired sessions from the cache
func (c *SessionCache) InvalidateExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.invalidateExpiredLocked()
}

// invalidateExpiredLocked is InvalidateExpired with c.mu already held.
func (c *SessionCache) invalidateExpiredLocked() int {
	count := 0

	for id, entry := range c.sessions {
		// IsExpired reads the expiration under the entry's own lock; reading
		// entry.expiration directly here raced RenewLease, which writes it.
		if entry.IsExpired() {
			delete(c.sessions, id)
			count++
		}
	}

	// Clean up command mappings for deleted sessions
	for key, sessID := range c.commandMap {
		if _, ok := c.sessions[sessID]; !ok {
			delete(c.commandMap, key)
		}
	}

	return count
}

// Clear removes all sessions from the cache
func (c *SessionCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sessions = make(map[string]*SessionEntry)
	c.commandMap = make(map[string]string)
}

// DebugDump returns a human-readable snapshot of the session cache for troubleshooting.
func (c *SessionCache) DebugDump() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var b strings.Builder
	b.WriteString("sessions:\n")
	for id, entry := range c.sessions {
		exp := "never"
		if !entry.expiration.IsZero() {
			exp = entry.expiration.Format(time.RFC3339Nano)
		}
		fmt.Fprintf(&b, "- id=%s addr=%s tag=%s lease=%s exp=%s\n", id, entry.addr, entry.tag, entry.lease, exp)
	}

	b.WriteString("command_map:\n")
	for key, sid := range c.commandMap {
		fmt.Fprintf(&b, "- %s -> %s\n", key, sid)
	}

	return b.String()
}

// Size returns the number of sessions in the cache
func (c *SessionCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}

// GenerateSessionID generates a unique session ID
// Format: hostname:pid:timestamp:counter
func GenerateSessionID(counter int) string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	pid := os.Getpid()
	timestamp := time.Now().Unix()

	return fmt.Sprintf("%s:%d:%d:%d", hostname, pid, timestamp, counter)
}
