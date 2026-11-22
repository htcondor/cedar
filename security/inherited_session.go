// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package security provides authentication and encryption protocols
// for CEDAR streams.
//
// This file implements support for inherited security sessions passed
// from a parent daemon (e.g., condor_master) via environment variables.

package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/commands"
	"golang.org/x/crypto/hkdf"
)

// Environment variable names used by HTCondor for passing session information
const (
	// ENV_CONDOR_INHERIT contains parent process information and inherited sockets
	EnvCondorInherit = "CONDOR_INHERIT"
	// ENV_CONDOR_PRIVATE_INHERIT contains security session keys
	EnvCondorPrivateInherit = "CONDOR_PRIVATE_INHERIT"
	// ENV_CONDOR_PARENT_ID contains the parent's unique ID
	EnvCondorParentID = "CONDOR_PARENT_ID"
)

// InheritedSessionType indicates the type of inherited session
type InheritedSessionType int

const (
	// SessionTypeNormal is a regular session for parent-child communication
	SessionTypeNormal InheritedSessionType = iota
	// SessionTypeFamily is a "family" session for sibling daemon communication
	SessionTypeFamily
)

// InheritedSession represents a security session passed from a parent daemon
type InheritedSession struct {
	// Type indicates whether this is a normal or family session
	Type InheritedSessionType

	// SessionID is the unique identifier for this session
	SessionID string

	// SessionInfo contains exported session attributes (ClassAd format)
	SessionInfo string

	// SessionKey is the raw key material for this session
	SessionKey string

	// ParentAddr is the sinful string of the parent daemon (from CONDOR_INHERIT)
	ParentAddr string

	// ParentPID is the process ID of the parent daemon
	ParentPID int
}

// ClaimID represents a parsed HTCondor claim ID
// Format: session_id#session_info#session_key
type ClaimID struct {
	raw         string
	sessionID   string
	sessionInfo string
	sessionKey  string
}

// ParseClaimID parses an HTCondor claim ID string
// Format: session_id#session_info#session_key
func ParseClaimID(claimID string) *ClaimID {
	c := &ClaimID{raw: claimID}

	// Split into at most three parts to avoid losing extra # characters in the key
	parts := strings.SplitN(claimID, "#", 3)

	if len(parts) >= 1 {
		c.sessionID = parts[0]
	}
	if len(parts) >= 2 {
		c.sessionInfo = parts[1]
	}
	if len(parts) >= 3 {
		c.sessionKey = parts[2]
	}

	// Some HTCondor exports omit the second # and instead append the key directly
	// after the closing ']' of the session info. Detect and split that form so we
	// can still populate sessionInfo and sessionKey.
	if c.sessionKey == "" && c.sessionInfo != "" {
		if idx := strings.LastIndex(c.sessionInfo, "]"); idx != -1 && idx+1 < len(c.sessionInfo) {
			c.sessionKey = c.sessionInfo[idx+1:]
			c.sessionInfo = c.sessionInfo[:idx+1]
		}
	}

	return c
}

// Raw returns the original claim ID string
func (c *ClaimID) Raw() string {
	return c.raw
}

// SecSessionID returns the session ID
// This matches ClaimIdParser::secSessionId() in HTCondor
func (c *ClaimID) SecSessionID() string {
	// If there's no session info, there's no security session
	if c.sessionInfo == "" {
		return ""
	}
	return c.sessionID
}

// SecSessionInfo returns the session info (exported attributes)
func (c *ClaimID) SecSessionInfo() string {
	return c.sessionInfo
}

// SecSessionKey returns the session key
func (c *ClaimID) SecSessionKey() string {
	return c.sessionKey
}

// PublicClaimID returns a version of the claim ID safe for logging (without the key)
func (c *ClaimID) PublicClaimID() string {
	if c.sessionID == "" {
		return ""
	}
	return c.sessionID + "#..."
}

// inheritedSessions holds sessions imported from the environment
var (
	inheritedSessions     []*InheritedSession
	inheritedSessionsOnce sync.Once
	inheritedParentAddr   string
	inheritedParentPID    int
)

// getEnvAny returns the first non-empty environment variable value from the provided keys.
func getEnvAny(keys ...string) string {
	for _, key := range keys {
		if val := os.Getenv(key); val != "" {
			return val
		}
	}
	return ""
}

// ParseCondorInherit parses the CONDOR_INHERIT environment variable
// Format: ppid psinful [socket_info...] [remaining_items...]
func ParseCondorInherit(inherit string) (ppid int, parentAddr string, remaining []string) {
	parts := strings.Fields(inherit)

	if len(parts) >= 1 {
		ppid, _ = strconv.Atoi(parts[0])
	}
	if len(parts) >= 2 {
		parentAddr = parts[1]
	}
	if len(parts) > 2 {
		remaining = parts[2:]
	}

	return ppid, parentAddr, remaining
}

// ParseCondorPrivateInherit parses the CONDOR_PRIVATE_INHERIT environment variable
// Format: space-separated items like "SessionKey:<claim_id>" and "FamilySessionKey:<claim_id>"
func ParseCondorPrivateInherit(privateInherit string) (sessions []*InheritedSession) {
	for _, item := range strings.Fields(privateInherit) {
		if strings.HasPrefix(item, "SessionKey:") {
			claimIDStr := strings.TrimPrefix(item, "SessionKey:")
			claimID := ParseClaimID(claimIDStr)
			if claimID.SecSessionID() != "" {
				sessions = append(sessions, &InheritedSession{
					Type:        SessionTypeNormal,
					SessionID:   claimID.SecSessionID(),
					SessionInfo: claimID.SecSessionInfo(),
					SessionKey:  claimID.SecSessionKey(),
				})
			}
		} else if strings.HasPrefix(item, "FamilySessionKey:") {
			claimIDStr := strings.TrimPrefix(item, "FamilySessionKey:")
			claimID := ParseClaimID(claimIDStr)
			if claimID.SecSessionID() != "" {
				sessions = append(sessions, &InheritedSession{
					Type:        SessionTypeFamily,
					SessionID:   claimID.SecSessionID(),
					SessionInfo: claimID.SecSessionInfo(),
					SessionKey:  claimID.SecSessionKey(),
				})
			}
		}
	}

	return sessions
}

// ImportInheritedSessions imports security sessions from environment variables
// This should be called early in daemon initialization
func ImportInheritedSessions() ([]*InheritedSession, error) {
	inheritedSessionsOnce.Do(func() {
		// Parse CONDOR_INHERIT for parent info (try both plain and _CONDOR_ prefixed variants)
		if inherit := getEnvAny(EnvCondorInherit, "_"+EnvCondorInherit); inherit != "" {
			inheritedParentPID, inheritedParentAddr, _ = ParseCondorInherit(inherit)
			slog.Debug("Parsed CONDOR_INHERIT",
				"parent_pid", inheritedParentPID,
				"parent_addr", inheritedParentAddr)
		}

		// Parse CONDOR_PRIVATE_INHERIT for session keys
		if privateInherit := getEnvAny(EnvCondorPrivateInherit, "_"+EnvCondorPrivateInherit); privateInherit != "" {
			sessions := ParseCondorPrivateInherit(privateInherit)
			for _, sess := range sessions {
				sess.ParentAddr = inheritedParentAddr
				sess.ParentPID = inheritedParentPID
				inheritedSessions = append(inheritedSessions, sess)

				sessionTypeStr := "normal"
				if sess.Type == SessionTypeFamily {
					sessionTypeStr = "family"
				}
				slog.Debug("Imported inherited session",
					"type", sessionTypeStr,
					"session_id", redactSessionID(sess.SessionID))
			}

			// Clear the environment variable to prevent it from being passed to children
			// (similar to HTCondor's behavior)
			if err := os.Unsetenv(EnvCondorPrivateInherit); err != nil {
				slog.Warn("Failed to clear inherited session env", "var", EnvCondorPrivateInherit, "error", err)
			}
			if err := os.Unsetenv("_" + EnvCondorPrivateInherit); err != nil {
				slog.Warn("Failed to clear inherited session env", "var", "_"+EnvCondorPrivateInherit, "error", err)
			}
		}
	})

	return inheritedSessions, nil
}

// GetInheritedSessions returns the list of imported inherited sessions
func GetInheritedSessions() []*InheritedSession {
	if _, err := ImportInheritedSessions(); err != nil {
		slog.Warn("Failed to import inherited sessions", "error", err)
	}
	return inheritedSessions
}

// GetInheritedParentAddr returns the parent daemon's address from CONDOR_INHERIT
func GetInheritedParentAddr() string {
	if _, err := ImportInheritedSessions(); err != nil {
		slog.Warn("Failed to import inherited sessions", "error", err)
	}
	return inheritedParentAddr
}

// GetInheritedParentPID returns the parent daemon's PID from CONDOR_INHERIT
func GetInheritedParentPID() int {
	if _, err := ImportInheritedSessions(); err != nil {
		slog.Warn("Failed to import inherited sessions", "error", err)
	}
	return inheritedParentPID
}

// ImportSessionInfoAttributes parses session info string and extracts attributes
// Session info format: [Attr1="value1";Attr2="value2";...]
func ImportSessionInfoAttributes(sessionInfo string) (map[string]string, error) {
	attrs := make(map[string]string)

	if sessionInfo == "" {
		return attrs, nil
	}

	// Remove brackets if present
	sessionInfo = strings.TrimPrefix(sessionInfo, "[")
	sessionInfo = strings.TrimSuffix(sessionInfo, "]")

	// Parse ClassAd-style attributes
	for _, item := range strings.Split(sessionInfo, ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		eqPos := strings.Index(item, "=")
		if eqPos <= 0 {
			continue
		}

		attrName := strings.TrimSpace(item[:eqPos])
		attrValue := strings.TrimSpace(item[eqPos+1:])

		// Remove quotes from string values
		if strings.HasPrefix(attrValue, "\"") && strings.HasSuffix(attrValue, "\"") {
			attrValue = attrValue[1 : len(attrValue)-1]
		}

		attrs[attrName] = attrValue
	}

	return attrs, nil
}

// deriveSessionKey derives an encryption key from the session key material
// This matches HTCondor's key derivation using HKDF
func deriveSessionKey(sessionKey string, keyLen int) ([]byte, error) {
	if sessionKey == "" {
		return nil, fmt.Errorf("empty session key")
	}

	// Use HKDF to derive the key, matching HTCondor's Condor_Crypt_Base::hkdf
	// exactly: salt "htcondor", info "keygen" (see condor_crypt.cpp). Without the
	// same salt/info the derived key differs from the C++ peer's and every
	// message on an inherited/family session decrypts to garbage.
	hash := sha256.New
	hkdfReader := hkdf.New(hash, []byte(sessionKey), []byte("htcondor"), []byte("keygen"))

	derivedKey := make([]byte, keyLen)
	if _, err := hkdfReader.Read(derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return derivedKey, nil
}

// CreateNonNegotiatedSession creates a session entry from inherited session data
// This is equivalent to SecMan::CreateNonNegotiatedSecuritySession in HTCondor
func CreateNonNegotiatedSession(session *InheritedSession, peerAddr string) (*SessionEntry, error) {
	if session == nil {
		return nil, fmt.Errorf("nil session")
	}

	if session.SessionID == "" {
		return nil, fmt.Errorf("empty session ID")
	}

	// Parse session info attributes
	attrs, err := ImportSessionInfoAttributes(session.SessionInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse session info: %w", err)
	}

	// Determine the crypto method the peer keyed this session on.  HTCondor's
	// importer (ImportSecSessionInfo) overrides the single, legacy CryptoMethods
	// attribute with the full CryptoMethodsList and keys the session on the
	// FIRST method of that list -- the KeyCacheEntry's preferred protocol.  The
	// legacy CryptoMethods field, by contrast, carries an "old-crypto-preferred"
	// value (typically BLOWFISH, via getPreferredOldCryptProtocol) for pre-9.9
	// peers and does NOT reflect the cipher a modern daemon actually uses: those
	// negotiate the first entry of CryptoMethodsList, which is AES by default.
	// So read CryptoMethodsList first (dot-delimited), fall back to the legacy
	// CryptoMethods field (comma-delimited), and take the first entry.
	cryptoMethod := "AESGCM"
	methodStr, sep := attrs["CryptoMethodsList"], "."
	if methodStr == "" {
		methodStr, sep = attrs["CryptoMethods"], ","
	}
	if methodStr != "" {
		if parts := strings.Split(methodStr, sep); len(parts) > 0 {
			cryptoMethod = strings.TrimSpace(parts[0])
		}
	}

	// cedar implements only AES-GCM.  If the session is keyed on a legacy cipher
	// -- e.g. the pool lists a non-AES method first, or the peer predates AES --
	// we cannot join it; fail clearly rather than deriving an unusable key.
	if cryptoMethod != "AES" && cryptoMethod != "AESGCM" {
		return nil, fmt.Errorf("inherited session is keyed on crypto method %q, but cedar only implements AES-GCM; ensure the pool's SEC_*_CRYPTO_METHODS lists AES first", cryptoMethod)
	}
	cryptoMethod = "AESGCM"
	keyLen := 32

	// Derive the encryption key
	derivedKey, err := deriveSessionKey(session.SessionKey, keyLen)
	if err != nil {
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	// Create KeyInfo
	keyInfo := &KeyInfo{
		Data:     derivedKey,
		Protocol: cryptoMethod,
	}

	// Create policy ClassAd from session info
	policy := classad.New()
	if err := policy.Set("SecUseSession", "YES"); err != nil {
		return nil, fmt.Errorf("failed to set SecUseSession: %w", err)
	}
	if err := policy.Set("SecSid", session.SessionID); err != nil {
		return nil, fmt.Errorf("failed to set SecSid: %w", err)
	}
	if err := policy.Set("SecEnact", "YES"); err != nil {
		return nil, fmt.Errorf("failed to set SecEnact: %w", err)
	}
	if err := policy.Set("SecNegotiatedSession", false); err != nil {
		return nil, fmt.Errorf("failed to set SecNegotiatedSession: %w", err)
	}

	// Copy attributes from session info
	for attr, value := range attrs {
		if err := policy.Set(attr, value); err != nil {
			return nil, fmt.Errorf("failed to set policy attribute %s: %w", attr, err)
		}
	}

	// The session key was derived for AES-GCM (cryptoMethod above), so the
	// policy must advertise that cipher. HTCondor's ExportSecSessionInfo emits a
	// legacy back-compat CryptoMethods (an old-preferred cipher such as BLOWFISH
	// via getPreferredOldCryptProtocol) alongside the modern CryptoMethodsList
	// whose head is AES; the copy loop above brought that legacy value in.
	// Leaving it would tell a resumed peer the wrong cipher -- the first
	// encrypted frame is then keyed AES-GCM but announced as BLOWFISH, and the
	// peer fails to decrypt it. Override with the method we actually keyed on.
	if err := policy.Set("CryptoMethods", cryptoMethod); err != nil {
		return nil, fmt.Errorf("failed to set CryptoMethods: %w", err)
	}

	// Set authentication method and identity for inherited sessions. A family or
	// parent session is a pre-shared key the master minted and handed only to its
	// own children over a private channel (CONDOR_INHERIT); possessing it proves a
	// trusted identity, so HTCondor treats these sessions as fully authenticated
	// (condor@family / condor@parent) with no auth handshake. Record that as both
	// the Sec-prefixed policy attributes (used elsewhere) AND the non-prefixed
	// "Authenticated"/"User"/"AuthMethods" that handleSessionResumption reads back
	// (matching what storeSession writes for a negotiated session). Without the
	// "Authenticated" flag a resumed family session comes back authenticated=false
	// and the per-command security-level check refuses every auth-required command
	// (e.g. UPDATE_STARTD_AD) -- so sibling daemons cannot advertise at all.
	user := "condor@parent"
	if session.Type == SessionTypeFamily {
		user = "condor@family"
	}
	if err := policy.Set("SecAuthenticationMethods", "FAMILY"); err != nil {
		return nil, fmt.Errorf("failed to set SecAuthenticationMethods: %w", err)
	}
	if err := policy.Set("SecUser", user); err != nil {
		return nil, fmt.Errorf("failed to set SecUser: %w", err)
	}
	// Non-prefixed mirrors read by handleSessionResumption.
	if err := policy.Set("Authenticated", true); err != nil {
		return nil, fmt.Errorf("failed to set Authenticated: %w", err)
	}
	if err := policy.Set("User", user); err != nil {
		return nil, fmt.Errorf("failed to set User: %w", err)
	}
	if err := policy.Set("AuthMethods", "FAMILY"); err != nil {
		return nil, fmt.Errorf("failed to set AuthMethods: %w", err)
	}

	// Determine expiration.  The exported attribute is "SessionExpires" (see
	// ATTR_SEC_SESSION_EXPIRES in HTCondor); a zero/absent value means the
	// session does not auto-expire.
	var expiration time.Time
	if expiresStr, ok := attrs["SessionExpires"]; ok {
		if expires, err := strconv.ParseInt(expiresStr, 10, 64); err == nil && expires > 0 {
			expiration = time.Unix(expires, 0)
		}
	}

	// Create the session entry
	entry := NewSessionEntry(
		session.SessionID,
		peerAddr,
		keyInfo,
		policy,
		expiration,
		0,  // No lease for inherited sessions
		"", // No tag
	)

	return entry, nil
}

// registerInheritedSessions imports inherited sessions and registers them in the provided session cache
// Returns the number of sessions registered
func registerInheritedSessions(cache *SessionCache) (int, error) {
	if cache == nil {
		return 0, fmt.Errorf("nil session cache")
	}

	sessions, err := ImportInheritedSessions()
	if err != nil {
		return 0, err
	}

	registered := 0

	parentAddr := GetInheritedParentAddr()
	addrInfo := addresses.ParseHTCondorAddress(parentAddr)

	// Build a normalized shared-port address (what clients actually use when connecting)
	normalizedAddrs := []string{parentAddr}
	if addrInfo.IsSharedPort {
		normalized := fmt.Sprintf("<%s?sock=%s>", addrInfo.ServerAddr, addrInfo.SharedPortID)
		if normalized != "" {
			normalizedAddrs = append(normalizedAddrs, normalized)
		}
	}

	for _, sess := range sessions {
		entry, err := CreateNonNegotiatedSession(sess, parentAddr)
		if err != nil {
			slog.Warn("Failed to create session from inherited data",
				"session_id", sess.SessionID,
				"error", err)
			continue
		}

		entry.SetInherited(true) // re-imported from env each start; never persist
		cache.Store(entry)

		// Map commands to this session so the client handshake can attempt session
		// resumption for those commands (e.g., DC_CHILDALIVE from child daemons).
		// Add mappings for both the raw inherited address and the normalized
		// shared-port address the client uses to connect.
		cmds := []string{}
		if attrs, err := ImportSessionInfoAttributes(sess.SessionInfo); err == nil {
			if cmdList, ok := attrs["ValidCommands"]; ok {
				for _, cmd := range strings.Split(cmdList, ",") {
					cmd = strings.TrimSpace(cmd)
					if cmd != "" {
						cmds = append(cmds, cmd)
					}
				}
			}
		}

		// If no ValidCommands were provided (common for inherited family sessions),
		// fall back to mapping DC_CHILDALIVE so child daemons can resume the session
		// instead of performing a full handshake and getting denied.
		if len(cmds) == 0 {
			cmds = append(cmds, fmt.Sprintf("%d", commands.DC_CHILDALIVE))
		}

		for _, cmd := range cmds {
			for _, addr := range normalizedAddrs {
				cache.MapCommand("", addr, cmd, sess.SessionID)
			}
		}
		registered++

		sessionTypeStr := "normal"
		if sess.Type == SessionTypeFamily {
			sessionTypeStr = "family"
		}
		slog.Info("Registered inherited session",
			"type", sessionTypeStr,
			"session_id", redactSessionID(sess.SessionID),
			"parent_addr", parentAddr)
	}

	return registered, nil
}

// GetFamilySessionID returns the session ID of the family session, if one was inherited
func GetFamilySessionID() string {
	sessions := GetInheritedSessions()
	for _, sess := range sessions {
		if sess.Type == SessionTypeFamily {
			return sess.SessionID
		}
	}
	return ""
}

// GetParentSessionID returns the session ID of the parent session, if one was inherited
func GetParentSessionID() string {
	sessions := GetInheritedSessions()
	for _, sess := range sessions {
		if sess.Type == SessionTypeNormal {
			return sess.SessionID
		}
	}
	return ""
}

// LookupInheritedSession looks up an inherited session by ID
func LookupInheritedSession(sessionID string) *InheritedSession {
	sessions := GetInheritedSessions()
	for _, sess := range sessions {
		if sess.SessionID == sessionID {
			return sess
		}
	}
	return nil
}

// ExportClaimID creates a claim ID string from session components
// This is the inverse of ParseClaimID
func ExportClaimID(sessionID, sessionInfo, sessionKey string) string {
	return fmt.Sprintf("%s#%s#%s", sessionID, sessionInfo, sessionKey)
}

// GenerateSecuritySessionKey generates a random session key suitable for use in a claim ID
func GenerateSecuritySessionKey() (string, error) {
	key := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}
	return hex.EncodeToString(key), nil
}
