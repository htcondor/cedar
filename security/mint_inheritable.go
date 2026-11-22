package security

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// MintInheritableSession mints a standalone, non-negotiated security session for a child
// process to inherit, registers it in the process-global session cache (which the local
// server resumes connections from), and returns the session id plus the CONDOR_PRIVATE_INHERIT
// token to place in the child's environment.
//
// The child imports the token via GetSessionCache()/GetParentSessionID() and resumes the
// session (SecurityConfig.SessionID) instead of running an authentication handshake; the local
// server accepts it from the global cache and maps it to the identity condor@parent.
//
// The session is:
//   - a normal (condor@parent) session, deliberately DISTINCT from any inherited family
//     (condor@family) session, so a child gets its own dedicated credential rather than the
//     daemon's family key;
//   - NOT persisted (SetInherited: re-minted on each launch, never written to a session file);
//   - NON-expiring (no SessionExpires): it lives as long as the child, since the parent supervises
//     the child's lifetime.
//
// validCommands is NOT a security boundary. It is advertised in the session policy and mapped
// on peerAddr so a server-side command_map lookup can find the session, but dispatch does not
// consult it: the server re-evaluates authorization against the current Authorizer instead
// (Server.sessionSatisfies), deliberately, because an advertised command set goes stale across a
// reconfig. A child handed a session minted with one command id can therefore run anything the
// Authorizer allows condor@parent, which for a parent identity is usually DAEMON or better.
//
// To actually bound what the child may do, use MintInheritableSessionWithLimits: the
// authorization bounding set IS enforced, ahead of the Authorizer, for resumed sessions too.
//
// Pass a single command; a claim id cannot carry ',' in some fields, so a one-command
// advertisement is the safe, common case.
func MintInheritableSession(peerAddr string, validCommands ...int) (sessionID, inheritToken string, err error) {
	return MintInheritableSessionWithLimits(peerAddr, nil, validCommands...)
}

// MintInheritableSessionWithLimits is MintInheritableSession with an authorization bounding set
// -- the levels ("READ", "WRITE", "DAEMON", ...) the minted session may ever be used for. Unlike
// validCommands this is enforced: it is carried in the session policy as LimitAuthorization, and
// Server.sessionSatisfies refuses a command whose registered levels fall outside it before it
// ever consults the Authorizer, on a resumed session as much as a fresh one.
//
// The limits are chosen by the parent and never read back off the wire, so a child cannot widen
// them; a peer-supplied set could only ever narrow its own authorization.
//
// A nil or empty set means no bounding set, which is what a minted session carried before this
// existed: the child is then limited only by what the Authorizer grants condor@parent.
func MintInheritableSessionWithLimits(peerAddr string, authorizationLimits []string, validCommands ...int) (sessionID, inheritToken string, err error) {
	key, err := GenerateSecuritySessionKey()
	if err != nil {
		return "", "", fmt.Errorf("mint session: generating key: %w", err)
	}
	sessionID = GenerateSessionID(GetNextSessionCounter())

	policy := classad.New()
	_ = policy.Set("Encryption", "YES")
	_ = policy.Set("Integrity", "YES")
	_ = policy.Set("CryptoMethods", "AES") // cedar keys sessions on AES-GCM
	if len(validCommands) > 0 {
		cmds := make([]string, len(validCommands))
		for i, c := range validCommands {
			cmds[i] = strconv.Itoa(c)
		}
		_ = policy.Set("ValidCommands", strings.Join(cmds, ","))
	}
	// No SessionExpires -> the session never auto-expires.
	sessionInfo, err := ExportSecSessionInfo(policy)
	if err != nil {
		return "", "", fmt.Errorf("mint session: exporting session info: %w", err)
	}

	entry, err := CreateNonNegotiatedSession(&InheritedSession{
		Type:        SessionTypeNormal,
		SessionID:   sessionID,
		SessionInfo: sessionInfo,
		SessionKey:  key,
	}, peerAddr)
	if err != nil {
		return "", "", fmt.Errorf("mint session: %w", err)
	}
	entry.SetInherited(true) // never persist; re-minted each child launch

	// Record the bounding set on the stored entry, which is where the server reads it
	// (handleSessionResumption). It is deliberately not routed through the session_info:
	// the claim-id round trip copies a fixed attribute list that excludes
	// LimitAuthorization, and adding it there would change every startd claim as well.
	// The child does not need it -- the limits bind the parent's server, not the child.
	if len(authorizationLimits) > 0 {
		if pol := entry.Policy(); pol != nil {
			_ = pol.Set(AttrLimitAuthorization, strings.Join(authorizationLimits, ","))
		}
	}

	cache := GetSessionCache()
	cache.Store(entry)
	// Map the command(s) to this session on the peer address so a server-side command_map
	// lookup can also resume it (the child resumes by explicit SessionID, but this makes the
	// mapping symmetric with an inherited family session).
	for _, c := range validCommands {
		cache.MapCommand("", peerAddr, strconv.Itoa(c), sessionID)
	}

	inheritToken = "SessionKey:" + ExportClaimID(sessionID, sessionInfo, key)
	return sessionID, inheritToken, nil
}
