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
// This package implements HTCondor's security methods including
// SSL, SCITOKENS, and IDTOKENS authentication.
package security

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// AuthMethod represents different authentication methods supported by HTCondor
type AuthMethod string

const (
	AuthSSL       AuthMethod = "SSL"
	AuthSciTokens AuthMethod = "SCITOKENS"
	AuthIDTokens  AuthMethod = "IDTOKENS"
	AuthToken     AuthMethod = "TOKEN"
	AuthFS        AuthMethod = "FS"
	AuthClaimToBe AuthMethod = "CLAIMTOBE"
	AuthPassword  AuthMethod = "PASSWORD"
	AuthKerberos  AuthMethod = "KERBEROS"
	AuthNone      AuthMethod = "NONE"
)

// Implemented reports whether this build of cedar has a working authentication handshake
// for the method. It is the source of truth for "what can we actually negotiate": offering
// a method whose handshake is unimplemented would just make negotiation fail. Kept in sync
// with performAuthentication -- PASSWORD is declared but its handshake still returns "not
// yet implemented", so it reports false until implemented.
func (m AuthMethod) Implemented() bool {
	switch canonicalAuthMethod(m) {
	case AuthFS, AuthIDTokens, AuthToken, AuthSciTokens, AuthSSL, AuthKerberos, AuthClaimToBe, AuthNone:
		return true
	default: // AuthPassword (stub) and any unknown value
		return false
	}
}

// canonicalAuthMethod returns method spelled as HTCondor's method names are,
// in upper case. HTCondor ignores case in method names, from configuration and
// from the peer alike (SecMan::sec_char_to_auth_method and
// SecMan::ReconcileMethodLists, condor_secman.cpp), so cedar compares and
// dispatches on this form.
func canonicalAuthMethod(method AuthMethod) AuthMethod {
	return AuthMethod(strings.ToUpper(strings.TrimSpace(string(method))))
}

// canonicalCryptoMethod is canonicalAuthMethod for crypto method names, which
// HTCondor also matches ignoring case (SecMan::getCryptProtocolNameToEnum).
func canonicalCryptoMethod(method CryptoMethod) CryptoMethod {
	return CryptoMethod(strings.ToUpper(strings.TrimSpace(string(method))))
}

// stdAuthMethodOrder mirrors C++ HTCondor's SEC_STD_AUTH_METHOD_NAMES precedence
// (condor_utils/param_info.cpp): FS, IDTOKENS, PASSWORD, KERBEROS, SCITOKENS, SSL.
var stdAuthMethodOrder = []AuthMethod{
	AuthFS, AuthIDTokens, AuthPassword, AuthKerberos, AuthSciTokens, AuthSSL,
}

// DefaultAuthMethods returns the standard HTCondor authentication methods this build of
// cedar can actually perform, in precedence order. It is the Go analogue of C++ building
// SEC_STD_AUTH_METHOD_NAMES from compile-time HAVE_EXT_* flags: the standard order filtered
// by Implemented(). Callers use it to bootstrap SEC_*_AUTHENTICATION_METHODS defaults
// without offering a method cedar cannot negotiate. Today: FS, IDTOKENS, KERBEROS, SCITOKENS, SSL.
func DefaultAuthMethods() []AuthMethod {
	out := make([]AuthMethod, 0, len(stdAuthMethodOrder))
	for _, m := range stdAuthMethodOrder {
		if m.Implemented() {
			out = append(out, m)
		}
	}
	return out
}

// Authentication method bitmasks for the authentication handshake
// These values must match HTCondor's condor_auth.h CAUTH_* constants
const (
	AuthBitmaskNone      = 0    // CAUTH_NONE
	AuthBitmaskAny       = 1    // CAUTH_ANY
	AuthBitmaskClaimToBe = 2    // CAUTH_CLAIMTOBE
	AuthBitmaskFS        = 4    // CAUTH_FILESYSTEM
	AuthBitmaskFSRemote  = 8    // CAUTH_FILESYSTEM_REMOTE
	AuthBitmaskNTSSPI    = 16   // CAUTH_NTSSPI
	AuthBitmaskGSI       = 32   // CAUTH_GSI
	AuthBitmaskKerberos  = 64   // CAUTH_KERBEROS
	AuthBitmaskAnonymous = 128  // CAUTH_ANONYMOUS
	AuthBitmaskSSL       = 256  // CAUTH_SSL
	AuthBitmaskPassword  = 512  // CAUTH_PASSWORD
	AuthBitmaskMunge     = 1024 // CAUTH_MUNGE
	AuthBitmaskToken     = 2048 // CAUTH_TOKEN
	AuthBitmaskSciTokens = 4096 // CAUTH_SCITOKENS
)

// CryptoMethod represents different encryption methods supported by HTCondor
type CryptoMethod string

const (
	CryptoAES      CryptoMethod = "AES"
	CryptoBlowfish CryptoMethod = "BLOWFISH"
	Crypto3DES     CryptoMethod = "3DES"
)

// isAESGCM reports whether a negotiated crypto name denotes AES-256-GCM. A
// freshly-negotiated session records it as "AES" (CryptoAES) while inherited /
// family sessions record it as "AESGCM"; both are the same cipher.
func isAESGCM(m CryptoMethod) bool {
	m = canonicalCryptoMethod(m)
	return m == CryptoAES || m == "AESGCM"
}

// cryptoMethodFromWire resolves a crypto method name list as HTCondor's
// SecMan::getCryptProtocolNameToEnum does: the first token naming a cipher it
// knows wins, other tokens are skipped, and "" means none was named.
func cryptoMethodFromWire(list string) CryptoMethod {
	for _, tok := range strings.FieldsFunc(list, func(r rune) bool { return strings.ContainsRune(", \t\r\n", r) }) {
		switch m := canonicalCryptoMethod(CryptoMethod(tok)); m {
		case CryptoAES, CryptoBlowfish:
			return m
		case Crypto3DES, "TRIPLEDES":
			return Crypto3DES
		}
	}
	return ""
}

// SecurityLevel represents security requirement levels
type SecurityLevel string

const (
	SecurityRequired  SecurityLevel = "REQUIRED"
	SecurityPreferred SecurityLevel = "PREFERRED"
	SecurityOptional  SecurityLevel = "OPTIONAL"
	SecurityNever     SecurityLevel = "NEVER"
)

// SessionResumptionError represents an error that occurs when attempting to resume a session
// This error type can be used with errors.Is and errors.As to detect when a session resumption
// fails and a new connection should be established
type SessionResumptionError struct {
	SessionID string
	Reason    string
	Cause     error // underlying I/O error for a failed exchange, if any
}

func (e *SessionResumptionError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("session resumption failed for session %s: %s: %v", redactSessionID(e.SessionID), e.Reason, e.Cause)
	}
	return fmt.Sprintf("session resumption failed for session %s: %s", redactSessionID(e.SessionID), e.Reason)
}

func (e *SessionResumptionError) Unwrap() error { return e.Cause }

// redactSessionID returns a short, log-safe rendering of a cedar
// session identifier. Session IDs are the lookup key for cached
// SessionEntry records (which hold the actual HMAC session key);
// HTCondor's daemon logs are world-readable on stock installs (mode
// 0644), so logging the full ID risks exposing it to unprivileged
// users sharing the host. The first 8 hex chars (32 bits) are kept
// so consecutive log lines can be correlated for the same session
// during debugging — the remaining 40 chars (160 bits) are dropped
// behind an ASCII "...".
// Returns "<empty>" for the empty string so a missing-ID code
// path is still distinguishable from a present secret.
//
// All slog log sites in this package go through this helper. The
// SessionResumptionError above also redacts: errors get logged at
// Warn/Error which are not silenced by destination-level filtering.
func redactSessionID(id string) string {
	if id == "" {
		return "<empty>"
	}
	if len(id) <= 8 {
		return id + "..."
	}
	return id[:8] + "..."
}

// IsSessionResumptionError checks if an error is a SessionResumptionError
func IsSessionResumptionError(err error) bool {
	var sre *SessionResumptionError
	return errors.As(err, &sre)
}

// AuthMethodAttempt records one auth method tried during negotiation
// and the error that caused it to fail. Stored in the order attempts
// happened so the operator can see which method was preferred.
type AuthMethodAttempt struct {
	Method AuthMethod
	Err    error
}

// AuthMethodsExhaustedError is returned by ClientHandshake (and the
// underlying handleClientAuthentication) when negotiation runs out of
// methods to try. It carries every method that was attempted along
// with the specific error that caused it to be removed from the
// candidate set, so callers can render an actionable failure message
// without having to enable cedar DEBUG logging and replay the
// connection.
//
// The wrapped errors are also reachable via errors.Is / errors.As — a
// caller checking for SessionResumptionError, x509 verification
// errors, or net.OpError (e.g. handshake timeouts) will match against
// the per-method error that produced them.
type AuthMethodsExhaustedError struct {
	// Attempts is in negotiation order: the first entry is the
	// method the server preferred first, etc.
	Attempts []AuthMethodAttempt
}

// Error renders all attempts in a single line so the failure shows up
// usefully even from a non-structured logger. Format:
//
//	all authentication methods failed: SSL: <err>; TOKEN: <err>
//
// When Attempts is empty (no method even started — e.g., the server
// rejected the initial bitmask outright), the message degrades
// gracefully to the historical "all authentication methods failed".
func (e *AuthMethodsExhaustedError) Error() string {
	if len(e.Attempts) == 0 {
		return "all authentication methods failed"
	}
	parts := make([]string, 0, len(e.Attempts))
	for _, a := range e.Attempts {
		parts = append(parts, fmt.Sprintf("%s: %v", a.Method, a.Err))
	}
	return "all authentication methods failed: " + strings.Join(parts, "; ")
}

// Unwrap returns the per-attempt errors so errors.Is / errors.As can
// match against any of them. A caller probing for an x509 cert
// mismatch on a multi-method handshake will get a hit even when SSL
// was just one of the methods that failed.
func (e *AuthMethodsExhaustedError) Unwrap() []error {
	out := make([]error, len(e.Attempts))
	for i, a := range e.Attempts {
		out[i] = a.Err
	}
	return out
}

// NoCommand marks a SecurityConfig that carries no command (an auth-only /
// session-establishment handshake). It is distinct from command 0
// (UPDATE_STARTD_AD), which is a legitimate command; on the wire a NoCommand
// handshake advertises DC_AUTHENTICATE instead.
const NoCommand = -1

// SecurityConfig holds configuration for stream security
type SecurityConfig struct {
	// Peer name; used by client to recall the server name
	PeerName string

	// Authentication settings
	AuthMethods    []AuthMethod
	Authentication SecurityLevel

	// Encryption settings
	CryptoMethods []CryptoMethod
	Encryption    SecurityLevel
	Integrity     SecurityLevel

	// FSLocalDir / FSRemoteDir are HTCondor's FS_LOCAL_DIR / FS_REMOTE_DIR: the base
	// directory the FS / FS_REMOTE authentication methods create their proof directory
	// under. Empty means the on-the-wire default, "/tmp". The server roots its temp
	// directory here, and the client accepts a server-supplied path ONLY when its parent
	// equals this base (from the client's OWN local config -- never the peer's -- so a
	// hostile server cannot direct the client to mkdir elsewhere). Both ends share the
	// same host and config in an FS handshake, so they agree on the base.
	FSLocalDir  string
	FSRemoteDir string

	// SharedPortID is the shared-port id (the "sock" value of its sinful) a server
	// is reached through when it sits behind a shared port, or empty. An HTCondor
	// 25.14+ FS client that dialed through a shared port reports the id it dialed
	// in its channel-binding extension ("ip:port?sock=ID"); when this is set the
	// server requires that id to match, as C++ checks it against its own command
	// sinful. When empty, a reported id is accepted on the ip:port check alone --
	// the same binding a client that reports no id gets.
	SharedPortID string

	// AuthRequired mirrors HTCondor's ATTR_SEC_AUTH_REQUIRED on a server
	// response: when authentication is enacted (Authentication="YES"), it records
	// whether authentication is mandatory. nil means the attribute was absent,
	// which HTCondor treats as required (condor_secman.cpp: the client defaults
	// auth_required=true). A non-nil false lets the client proceed with an
	// unauthenticated session if all enacted auth methods fail.
	AuthRequired *bool

	// PostAuthPolicy, if set, is invoked by the server side after a successful
	// authentication to supply the authorization result the security layer does
	// not itself own. authUser is the authenticated identity and peerAddr is the
	// peer's "host:port"; authenticated and encrypted report the session's actual
	// negotiated properties so the policy can exclude commands the session could
	// not immediately run (e.g. a command that mandates encryption on a plaintext
	// session). It returns the identity to advertise to the peer (the mapped FQU;
	// empty keeps authUser) and the command integers this session is authorized
	// for. Those commands are reported in the post-auth ValidCommands so an
	// HTCondor peer can reuse the session for any of them -- so the returned set
	// must not be broader than what current policy would permit right now.
	PostAuthPolicy func(authUser, peerAddr string, authenticated, encrypted bool) (fqu string, validCommands []int)

	// SessionAttrs are application attributes this SERVER advertises in its
	// post-authentication ad and keeps with the cached session, so a protocol
	// layered on cedar can tell its peer what it supports without the peer
	// having to probe for it. Names the handshake owns are ignored; see
	// ReservedSessionAttr and the commentary in session_attrs.go.
	SessionAttrs map[string]string

	// WantSessionAttrs are the attribute names this CLIENT captures from a
	// peer's post-authentication ad, reported as SecurityNegotiation.SessionAttrs
	// and restored when a cached session is resumed. Capture is by name so an
	// attribute this build does not understand -- from a C++ peer, or a newer
	// cedar -- is never mistaken for the application's own.
	WantSessionAttrs []string

	// CommandPerms, if set, returns the authorization levels a command is
	// registered at. The server side uses it to drop from PostAuthPolicy's
	// commands any that the session's AuthorizationLimits do not permit, so the
	// post-auth ValidCommands stays inside the bounding set.
	CommandPerms func(command int) []string

	// Certificate/Key files for SSL, mirroring HTCondor's
	// AUTH_SSL_{CLIENT,SERVER}_{CERTFILE,KEYFILE,CAFILE}. All three are
	// comma-separated candidate lists, interpreted as C++ condor_auth_ssl does:
	//
	//   - CertFile/KeyFile are paired index-wise. A pair either of whose files
	//     cannot be read is skipped; every readable pair is loaded, a readable
	//     pair that does not load is an error, and the LAST readable pair is the
	//     one used. A client with no readable pair authenticates anonymously.
	//   - CAFile: the LAST readable candidate is loaded, and only that one.
	CertFile string
	KeyFile  string
	CAFile   string
	// CADir is AUTH_SSL_{CLIENT,SERVER}_CADIR: a directory of CA certificates
	// (OpenSSL's CApath; several may be given separated by os.PathListSeparator,
	// as OpenSSL allows). Every regular file in it (symlinks followed) that
	// holds PEM certificates contributes them as trust anchors; anything else
	// (CRLs, signing_policy, namespaces, ...) is ignored. A directory that does
	// not exist or cannot be listed contributes nothing, as in OpenSSL.
	CADir string
	// UseDefaultCAs is AUTH_SSL_{CLIENT,SERVER}_USE_DEFAULT_CAS: whether the
	// system's default trust store is trusted in addition to CAFile/CADir. Nil
	// means true, HTCondor's default; set to false to trust only CAFile/CADir.
	UseDefaultCAs *bool
	// Server name for SSL certificate verification (optional, defaults to hostname)
	ServerName string

	// Credentials, if set, reads credential files (SSL key/cert, token signing
	// keys, token files) on cedar's behalf. A daemon running as an unprivileged
	// service account supplies a reader that re-elevates to root for root-owned
	// 0600 credentials and supports reload-on-reconfig. Nil means plain
	// a plain read. See CredentialReader.
	Credentials CredentialReader

	// Token content for TOKEN authentication (JWT string)
	Token string

	// DelegatedCredential says Token belongs to somebody other than
	// this host, so it is the only credential this connection may
	// present.
	//
	// Token discovery exists for a daemon authenticating as itself: if
	// the configured token will not do, read another from TokenFile or
	// TokenDir. That is right for the daemon's own work and dangerous
	// for a request made on somebody's behalf -- a server that cannot
	// use a caller's token then authenticates to the peer as itself,
	// and the peer sees a privileged daemon identity where it should
	// have seen a user. It is not a hypothetical: it presents as a
	// request that succeeds with more authority than the caller has,
	// or, when the daemon identity happens not to be allowed either,
	// as a denial naming an identity nobody involved recognises.
	//
	// With this set, a token that is missing, unusable or expired is
	// an error that says so, and no file on this host is offered in
	// its place.
	DelegatedCredential bool
	// Token file for TOKEN authentication
	TokenFile string
	// Token directory for discovering multiple tokens (default: ~/.condor/tokens.d)
	TokenDir string

	// Token signing key configuration (server-side)
	// Path to pool signing key file (SEC_TOKEN_POOL_SIGNING_KEY_FILE)
	TokenPoolSigningKeyFile string
	// Directory containing named signing keys (SEC_PASSWORD_DIRECTORY)
	TokenSigningKeyDir string
	// Maximum token age in seconds (SEC_TOKEN_MAX_AGE)
	TokenMaxAge int
	// List of issuer key names accepted by server (from IssuerKeys ClassAd attribute)
	IssuerKeys []string

	// CondorUsername is the service account HTCondor daemons run as (the "condor"
	// user). When set, FS authentication mirrors C++ condor_auth_fs: the client, when
	// running as root, creates its marker owned by this account, and the server maps a
	// root-owned marker to it -- so a tool run as root authenticates as condor, not
	// root. Empty disables both behaviors.
	CondorUsername string
	// FSRootToCondor gates the server-side root->CondorUsername mapping. Nil means
	// enabled, matching HTCondor's FS_ROOT_TO_CONDOR default of true; set to false to
	// disable. Ignored when CondorUsername is empty.
	FSRootToCondor *bool
	// CondorPrivRunner, when set, runs the FS-auth client's marker mkdir as the condor
	// service account (mirroring C++ set_condor_priv), so a root daemon's marker is owned
	// by condor. golang-htcondor supplies a droppriv-backed implementation; nil means the
	// marker is created under the current identity (the normal non-root case).
	CondorPrivRunner CondorPrivRunner

	// UIDDomain is HTCondor's UID_DOMAIN: the domain of the fully-qualified user
	// an FS or FS_REMOTE peer authenticates as (user@UIDDomain), of a CLAIMTOBE
	// name sent without one, and of a mapped name without an '@'. Empty means no
	// UID domain is known, and those identities stay bare for a map file or
	// server.FQUMapper to qualify; cedar does not stand in a guess of its own
	// (see LocalUIDDomain). Set it from UID_DOMAIN, whose own default is
	// $(FULL_HOSTNAME) -- a wrong domain authorizes as a different peer than a
	// missing one does, so applying that default is the config layer's job.
	UIDDomain string

	// SciTokensMapper is the SCITOKENS entries of HTCondor's map file
	// (CERTIFICATE_MAPFILE): given a SciToken's authenticated name,
	// "issuer,subject", it returns the canonical user, or false when no entry
	// maps it. The server accepts a SciToken only when it is mapped, and the
	// peer authenticates as the mapped user (with UIDDomain when it has no
	// '@'). It is consulted before anything is fetched from the issuer, so an
	// issuer no entry can match is never contacted. Nil, like HTCondor with
	// no map file, refuses every SciToken.
	SciTokensMapper func(authName string) (canonicalUser string, ok bool)
	// SciTokensServerAudience is SCITOKENS_SERVER_AUDIENCE: the audiences a
	// SciToken may name. Empty (HTCondor's default) accepts only tokens that
	// name no audience, or the profile's "any" audience. See
	// SciTokenVerifyOptions.Audiences.
	SciTokensServerAudience []string
	// SciTokensForeignTokenIssuers is SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS when
	// SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES is true, nil when it is false.
	// See SciTokenVerifyOptions.ForeignTokenIssuers.
	SciTokensForeignTokenIssuers []string
	// SciTokensHTTPClient fetches SciToken issuers' metadata and keys; nil
	// uses a client trusting the system roots. Only https is ever fetched.
	SciTokensHTTPClient *http.Client

	// Other settings
	RemoteVersion   string
	TrustDomain     string
	Subsystem       string
	ServerPid       int
	SessionDuration int
	SessionLease    int

	// Command for this session (what the client intends to do). This is a real
	// HTCondor command int, which may legitimately be 0 (UPDATE_STARTD_AD). Use
	// NoCommand (-1) for an auth-only handshake that carries no command.
	Command int

	// AuthCommand specifies a sub-command for the security handshake (optional)
	// For example, when Command is DC_SEC_QUERY (60040), AuthCommand might be
	// DC_NOP_WRITE (60021) to specify the actual operation being authorized.
	// If not set (0), only Command will be sent in the handshake.
	AuthCommand int

	// ECDH key exchange
	ECDHPublicKey string

	// SecurityTag partitions the client session cache: a session negotiated
	// under one tag is stored, and resumed, only under that tag, so configs
	// presenting different credentials to the same peer do not ride each
	// other's sessions. The tag must change whenever the authority of the
	// presented credential does. When it is empty, Token is set and the
	// global cache is in use, a tag derived from the token is used instead
	// (see clientSessionTag), so a token never shares the untagged slot the
	// process uses for its own identity.
	SecurityTag string

	// Session cache (optional, if provided will be used instead of global cache)
	SessionCache *SessionCache

	// SessionID, if set, forces the client handshake to resume this exact
	// pre-registered session (e.g. one installed by ImportClaimSession),
	// bypassing both negotiation and the command_map lookup. This mirrors
	// CEDAR's setSecSessionId() for non-negotiated / claim sessions, where the
	// caller explicitly names the session to ride rather than relying on a
	// command-to-session mapping. It is an error if the id is not in the cache.
	SessionID string
}

// AuthorizedCommand returns the command a handshake for Command is authorized
// as: AuthCommand when Command is DC_AUTHENTICATE or DC_SEC_QUERY, which run no
// handler of their own, else Command. DaemonCore picks the command whose
// security policy, authorization and ValidCommands the handshake uses the same
// way (daemon_command.cpp, m_auth_cmd).
func (c *SecurityConfig) AuthorizedCommand() int {
	if c.Command == commands.DC_AUTHENTICATE || c.Command == commands.DC_SEC_QUERY {
		return c.AuthCommand
	}
	return c.Command
}

// SecurityNegotiation represents the security negotiation state
type SecurityNegotiation struct {
	Command          int
	ClientConfig     *SecurityConfig
	ServerConfig     *SecurityConfig
	NegotiatedAuth   AuthMethod
	NegotiatedCrypto CryptoMethod
	sharedSecret     []byte // Private: only accessible through getter, set during ECDH or session resumption
	Enact            bool
	Authentication   bool
	Encryption       bool
	// Integrity is the server's integrity decision. cedar's only cipher,
	// AES-GCM, integrity-checks whatever it encrypts, so a session with
	// Integrity has Encryption's key on the stream as well.
	Integrity      bool
	IsClient       bool
	SessionResumed bool // Indicates if this session was resumed from cache
	// Session information from post-auth ClassAd
	SessionId string
	// User is the peer's fully-qualified user, "user@domain" as C++ reports it
	// (getRemoteFQU) -- the identity ALLOW/DENY lists match. On the client it is
	// our own identity as the server reported it. Take UserName() where HTCondor
	// stores a bare user name, such as a job's Owner.
	User          string
	ValidCommands string
	// SessionAttrs are the peer's application attributes, as named by
	// SecurityConfig.WantSessionAttrs. An absent attribute is absent from the
	// map: a peer that set nothing and a peer too old to set anything look the
	// same, so absence must be read as the oldest behaviour.
	SessionAttrs map[string]string
	// AuthorizationLimits is the server's record of the authorization levels
	// the peer's credential was limited to (HTCondor's LimitAuthorization), as
	// the credential named them, before implied levels are added: the
	// "condor:/<LEVEL>" scopes of a TOKEN/IDTOKENS or SCITOKENS credential. nil
	// means the session has no bounding set; a non-nil set that names no level
	// permits only ALLOW commands. See AuthorizationLimitsPermit.
	AuthorizationLimits []string
}

// GetSharedSecret returns the shared secret (read-only access)
func (sn *SecurityNegotiation) GetSharedSecret() []byte {
	return sn.sharedSecret
}

// setSharedSecret sets the shared secret (internal use only)
func (sn *SecurityNegotiation) setSharedSecret(secret []byte) {
	sn.sharedSecret = secret
}

// Authenticator handles the security handshake for a stream
type Authenticator struct {
	config         *SecurityConfig
	stream         *stream.Stream
	ecdhPrivKey    *ecdh.PrivateKey // ECDH private key for key exchange
	sessionResumed bool             // Indicates if the current session was resumed

	// ServerConfigForCommand, if set, lets the server pick a per-command security
	// policy: after the client's handshake reveals which command it wants to run,
	// the returned SecurityConfig replaces the default for negotiation. This is how
	// a daemon serves different commands at different HTCondor authorization levels
	// (e.g. a collector negotiating a QUERY at READ but an UPDATE at ADVERTISE).
	// Returning nil keeps the default config. Server-side only.
	ServerConfigForCommand func(command int) *SecurityConfig

	// AuthorizeCommand, if set, decides whether the command a full handshake
	// negotiated may run, before the post-auth reply is sent, as DaemonCore
	// decides it (daemon_command.cpp, VerifyCommand and SendResponse). It is
	// called once the peer has authenticated, PostAuthPolicy has mapped its
	// identity into negotiation.User, and the session's AuthorizationLimits are
	// set. A non-nil error refuses the command: the post-auth reply carries
	// ReturnCode DENIED (CMD_NOT_FOUND if the error wraps ErrCommandNotFound),
	// the session is not cached, and the handshake returns a
	// *CommandRefusedError. A resumed session gets no post-auth reply, so the
	// caller authorizes its command after the handshake, as DaemonCore does.
	// Server-side only.
	AuthorizeCommand func(negotiation *SecurityNegotiation) error
}

// WasSessionResumed returns true if the session was resumed from cache
func (a *Authenticator) WasSessionResumed() bool {
	return a.sessionResumed
}

// SecurityManager provides a high-level interface for security operations
type SecurityManager struct {
	config *SecurityConfig
}

// NewAuthenticator creates a new authenticator with the given config and stream
func NewAuthenticator(config *SecurityConfig, s *stream.Stream) *Authenticator {
	// Generate ECDH key pair for the handshake
	ecdhPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		slog.Info(fmt.Sprintf("Warning: Failed to generate ECDH key pair: %v", err), "destination", "cedar")
		return &Authenticator{
			config: config,
			stream: s,
		}
	}

	// Get the raw ECDH public key bytes (65 bytes starting with 0x04)
	ecdhPubKey := ecdhPrivKey.PublicKey()
	pubKeyBytes := ecdhPubKey.Bytes()

	if len(pubKeyBytes) != 65 || pubKeyBytes[0] != 0x04 {
		slog.Info("Warning: Invalid ECDH public key format", "destination", "cedar")
		return &Authenticator{
			config: config,
			stream: s,
		}
	}

	// Store the base64-encoded raw public key in config (HTCondor raw format)
	config.ECDHPublicKey = base64.StdEncoding.EncodeToString(pubKeyBytes)

	return &Authenticator{
		config:      config,
		stream:      s,
		ecdhPrivKey: ecdhPrivKey,
	}
}

// NewSecurityManager creates a new security manager with default configuration
func NewSecurityManager() *SecurityManager {
	return &SecurityManager{
		config: &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthSSL, AuthToken, AuthNone},
			Authentication: SecurityOptional,
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Encryption:     SecurityOptional,
			Integrity:      SecurityOptional,
			Command:        NoCommand, // default manager does auth-only handshakes
		},
	}
}

// ClientHandshake performs a client-side security handshake on the given stream
func (sm *SecurityManager) ClientHandshake(ctx context.Context, s *stream.Stream) error {
	auth := NewAuthenticator(sm.config, s)
	_, err := auth.ClientHandshake(ctx)
	if err != nil {
		return err
	}

	s.SetAuthenticated(true)
	return nil
}

// ServerHandshake performs a server-side security handshake on the given stream
func (sm *SecurityManager) ServerHandshake(ctx context.Context, s *stream.Stream) error {
	auth := NewAuthenticator(sm.config, s)
	_, err := auth.ServerHandshake(ctx)
	if err != nil {
		return err
	}

	s.SetAuthenticated(true)
	return nil
}

// ClientHandshake performs the client-side security handshake
// This sends a single message with DC_AUTHENTICATE command followed by client security ClassAd
func (a *Authenticator) ClientHandshake(ctx context.Context) (*SecurityNegotiation, error) {
	// Determine which session cache to use - prefer context-provided cache
	cache := a.config.SessionCache
	if cache == nil {
		cache = GetSessionCache()
	}

	// Explicitly-named pre-registered session (mirrors CEDAR setSecSessionId
	// for non-negotiated / claim sessions): resume this exact session id,
	// skipping negotiation and the command_map lookup entirely.
	if a.config.SessionID != "" {
		entry, ok := cache.LookupNonExpired(a.config.SessionID)
		if !ok {
			return nil, &SessionResumptionError{
				SessionID: a.config.SessionID,
				Reason:    "pre-registered session not found in cache",
			}
		}
		slog.Info(fmt.Sprintf("🔐 CLIENT: Using pre-registered session %s (explicit SessionID)",
			redactSessionID(entry.ID())), "destination", "cedar")
		return a.resumeSession(ctx, entry, cache)
	}

	// Check for existing session to resume
	// Priority order: PeerName > Stream's peer address
	serverAddr := a.config.PeerName
	if serverAddr == "" && a.stream != nil {
		serverAddr = a.stream.GetPeerAddr()
	}

	if serverAddr != "" && a.config.Command >= 0 {
		cmdStr := fmt.Sprintf("%d", a.config.Command)
		entry, ok := cache.LookupByCommand(a.config.clientSessionTag(cache), serverAddr, cmdStr)
		if ok && !a.config.mayResume(entry) {
			// Left cached for the configs it does satisfy.
			slog.Info(fmt.Sprintf("🔐 CLIENT: Cached session %s for %s does not meet this config's security requirements; authenticating afresh",
				redactSessionID(entry.ID()), serverAddr), "destination", "cedar")
			ok = false
		}
		if ok {
			slog.Info(fmt.Sprintf("🔐 CLIENT: Found cached session %s for %s, attempting to resume...",
				redactSessionID(entry.ID()), serverAddr), "destination", "cedar")

			// Try to resume the session
			negotiation, err := a.resumeSession(ctx, entry, cache)
			if err != nil {
				// Session resumption failed - return the error so the caller can retry with a new connection
				// Do NOT fall back to full authentication on the same stream as it's in an unusable state
				slog.Info(fmt.Sprintf("🔐 CLIENT: Session resumption failed: %v", err), "destination", "cedar")
				return nil, err
			}
			slog.Info(fmt.Sprintf("🔐 CLIENT: Successfully resumed session %s", redactSessionID(entry.ID())), "destination", "cedar")
			return negotiation, nil
		}
	}

	// No cached session, perform full authentication
	return a.performFullAuthentication(ctx, cache)
}

// performFullAuthentication performs a full authentication handshake (original ClientHandshake logic)
func (a *Authenticator) performFullAuthentication(ctx context.Context, cache *SessionCache) (*SecurityNegotiation, error) {
	// Create message for outgoing data
	msg := message.NewMessageForStream(a.stream)

	// First put the command integer
	if err := msg.PutInt(ctx, commands.DC_AUTHENTICATE); err != nil {
		return nil, fmt.Errorf("failed to put authenticate command: %w", err)
	}

	// Then put the client security ClassAd
	clientAd := a.createClientSecurityAd()
	if err := msg.PutClassAd(ctx, clientAd); err != nil {
		return nil, fmt.Errorf("failed to serialize client security ad: %w", err)
	} // Finish and send the complete message
	slog.Info("🔐 CLIENT: Sending authentication message...", "destination", "cedar")
	if err := msg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to send authenticate message: %w", err)
	}

	// Create message for incoming data
	slog.Info("🔐 CLIENT: Waiting for server response...", "destination", "cedar")
	responseMsg := message.NewMessageFromStream(a.stream)
	// Limit ClassAd size to 4KB to prevent DoS attacks
	serverAd, err := responseMsg.GetClassAdWithMaxSize(ctx, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server response: %w", err)
	}
	slog.Info("🔐 CLIENT: Received server security ClassAd:", "destination", "cedar")
	slog.Info(fmt.Sprintf("    %s", serverAd.String()), "destination", "cedar")

	// The server may gracefully reject the negotiation instead of proceeding
	// (see sendNegotiationFailureResponse): a ReturnCode other than "AUTHORIZED"
	// in the negotiation response means the policies could not be reconciled.
	// Surface the server's reason rather than pressing on into an auth/encryption
	// phase that cannot succeed (and would fail with a vaguer error).
	if rc, ok := serverAd.EvaluateAttrString("ReturnCode"); ok && rc != "" && rc != "AUTHORIZED" {
		reason, _ := serverAd.EvaluateAttrString("ErrorString")
		if reason == "" {
			reason = "server rejected security negotiation"
		}
		return nil, fmt.Errorf("security negotiation rejected by server (%s): %s", rc, reason)
	}

	// Process negotiation result
	negotiation := &SecurityNegotiation{
		Command:      commands.DC_AUTHENTICATE,
		ClientConfig: a.config,
		ServerConfig: a.parseServerSecurityAd(serverAd),
		IsClient:     true,
	}

	slog.Info("🔐 CLIENT: Negotiating security parameters...", "destination", "cedar")
	if err := a.negotiateSecurity(negotiation); err != nil {
		return nil, fmt.Errorf("security negotiation failed: %w", err)
	}
	slog.Info("🔐 CLIENT: Security negotiation completed", "destination", "cedar")
	slog.Info(fmt.Sprintf("    Negotiated Auth: %s", negotiation.NegotiatedAuth), "destination", "cedar")
	slog.Info(fmt.Sprintf("    Negotiated Crypto: %s", negotiation.NegotiatedCrypto), "destination", "cedar")

	// Handle authentication phase FIRST (without encryption). The
	// inner error from handleClientAuthentication is typically an
	// AuthMethodsExhaustedError whose own message already begins
	// "all authentication methods failed: …" — wrapping it with
	// "authentication phase failed:" just adds one more vague prefix
	// in front of an already-informative chain.
	if err := a.handleClientAuthentication(ctx, negotiation); err != nil {
		return nil, err
	}

	// NOW set up stream encryption AFTER authentication is complete
	if err := a.setupStreamEncryption(negotiation); err != nil {
		return nil, fmt.Errorf("failed to setup stream encryption: %w", err)
	}
	// A session has enacted crypto if EITHER end settled on it, so both sources
	// have to be consulted. ServerConfig holds the server's reply verbatim
	// ("YES"/"NO", parseServerSecurityAd casts the string straight to
	// SecurityLevel), which is why it is compared as a literal and not as a
	// level. Checking only that let a rogue or rewritten reply of
	// Encryption="NO" satisfy a client configured Encryption=REQUIRED, which
	// then sent its command in cleartext; checking only our own reconciled
	// value would miss a server enacting encryption we were merely optional
	// about.
	encryptionEnacted := negotiation.Encryption || negotiation.ServerConfig.Encryption == "YES"
	integrityEnacted := negotiation.Integrity || negotiation.ServerConfig.Integrity == "YES"
	if err := a.requireEnactedKey(encryptionEnacted, integrityEnacted); err != nil {
		return nil, err
	}

	slog.Info(fmt.Sprintf("Stream encryption: %t", a.stream.IsEncrypted()), "destination", "cedar")

	// Parse post-auth message as ClassAd directly from the stream
	slog.Info("🔐 CLIENT: Waiting for post-auth response...", "destination", "cedar")
	postAuthMsg := message.NewMessageFromStream(a.stream)
	// Limit ClassAd size to 4KB to prevent DoS attacks
	postAuthAd, err := postAuthMsg.GetClassAdWithMaxSize(ctx, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to parse post-auth ClassAd: %w", err)
	}

	slog.Info("🔐 CLIENT: Received post-auth ClassAd:", "destination", "cedar")
	slog.Info(fmt.Sprintf("    %s", postAuthAd.String()), "destination", "cedar")

	// Extract session information from post-auth ClassAd
	var sessionDuration, sessionLease int
	if sid, ok := postAuthAd.EvaluateAttrString("Sid"); ok {
		negotiation.SessionId = sid
	}
	if user, ok := postAuthAd.EvaluateAttrString("User"); ok {
		negotiation.User = user
	}
	if validCmds, ok := postAuthAd.EvaluateAttrString("ValidCommands"); ok {
		negotiation.ValidCommands = validCmds
	}
	negotiation.SessionAttrs = captureSessionAttrs(postAuthAd, a.config.WantSessionAttrs)
	if returnCode, ok := postAuthAd.EvaluateAttrString("ReturnCode"); ok {
		if returnCode != "AUTHORIZED" {
			// The handshake got this far, so the peer knows who we are and
			// is refusing the command; say so, with everything it told us
			// in the same reply. Read after ValidCommands above, which is
			// part of the explanation rather than a detail to collect only
			// on success.
			peer := a.config.PeerName
			if peer == "" && a.stream != nil {
				peer = a.stream.GetPeerAddr()
			}
			tried, triedKnown := postAuthAd.EvaluateAttrBool("TriedAuthentication")
			return nil, &AuthorizationError{
				ReturnCode:          returnCode,
				Command:             a.config.Command,
				Peer:                peer,
				User:                negotiation.User,
				Method:              string(negotiation.NegotiatedAuth),
				Encrypted:           negotiation.Encryption,
				TriedAuthentication: tried,
				TriedAuthKnown:      triedKnown,
				ValidCommands:       negotiation.ValidCommands,
			}
		}
	}
	if dur, ok := postAuthAd.EvaluateAttrInt("SessionDuration"); ok {
		sessionDuration = int(dur)
	}
	if lease, ok := postAuthAd.EvaluateAttrInt("SessionLease"); ok {
		sessionLease = int(lease)
	}

	// Store session on client side (with remote address)
	// Priority order: PeerName > Stream's peer address
	serverAddr := a.config.PeerName
	if serverAddr == "" && a.stream != nil {
		serverAddr = a.stream.GetPeerAddr()
	}
	if negotiation.SessionId != "" && serverAddr != "" {
		a.storeClientSession(negotiation, sessionDuration, sessionLease, cache)
	}

	return negotiation, nil
}

// handleSessionResumption handles a session resumption request from the client
func (a *Authenticator) handleSessionResumption(ctx context.Context, sessionID string, clientAd *classad.ClassAd, command int) (*SecurityNegotiation, error) {
	// Prefer the per-connection cache (set on the server's SecurityConfig) so a
	// server configured with an isolated cache resumes from it -- including
	// sessions registered programmatically via ImportClaimSession rather than
	// created by a prior handshake. Fall back to the global cache otherwise.
	cache := a.config.SessionCache
	if cache == nil {
		cache = GetSessionCache()
	}

	// Look up the session. When a custom cache is set but the session is not
	// there, fall back to the global cache: freshly handshake-negotiated
	// server sessions are stored there (see storeSession), so a server with a
	// custom cache must still resume them.
	entry, ok := cache.LookupNonExpired(sessionID)
	if !ok {
		if global := GetSessionCache(); global != cache {
			if e, found := global.LookupNonExpired(sessionID); found {
				entry, ok, cache = e, true, global
			}
		}
	}

	// Check if client wants a response
	wantResponse := false
	if val, ok := clientAd.EvaluateAttrBool("ResumeResponse"); ok {
		wantResponse = val
	}

	// rejectSession refuses the resumption as an unknown session.
	rejectSession := func() error {
		if !wantResponse {
			return nil
		}
		// Send SID_NOT_FOUND response
		responseAd := classad.New()
		_ = responseAd.Set("ReturnCode", "SID_NOT_FOUND")

		responseMsg := message.NewMessageForStream(a.stream)
		if err := responseMsg.PutClassAd(ctx, responseAd); err != nil {
			return fmt.Errorf("failed to send session not found response: %w", err)
		}
		if err := responseMsg.FinishMessage(ctx); err != nil {
			return fmt.Errorf("failed to finish session not found response: %w", err)
		}

		slog.Info("🔐 SERVER: Sent SID_NOT_FOUND response", "destination", "cedar")
		return nil
	}

	if !ok {
		slog.Info(fmt.Sprintf("🔐 SERVER: Session %s not found or expired", redactSessionID(sessionID)), "destination", "cedar")
		if err := rejectSession(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("session %s not found", redactSessionID(sessionID))
	}

	// The client names the cipher it keyed this connection with. In HTCondor
	// a session imported from a claim id or CONDOR_PRIVATE_INHERIT holds a key
	// per method, and a C++ client uses the one its session prefers
	// (SecManStartCommand::sendAuthInfo_inner announces it). A UDP command
	// resumed with BLOWFISH, which UDP forces, makes BLOWFISH the preferred
	// method of the receiver's session (DaemonCommandProtocol::ReadCommand), so
	// that daemon's later TCP commands over the session use BLOWFISH too.
	// cedar holds only the AES-GCM key and cannot read such a connection, so
	// refuse it as an unknown session: a C++ client then stops using a family
	// session with this address and negotiates a new session, which uses AES.
	clientMethods, _ := clientAd.EvaluateAttrString("CryptoMethods")
	if clientCrypto := cryptoMethodFromWire(clientMethods); clientCrypto != "" && !isAESGCM(clientCrypto) {
		slog.Warn(fmt.Sprintf("🔐 SERVER: Client resumed session %s with crypto method %s; cedar implements only AES-GCM, refusing the session", redactSessionID(sessionID), clientCrypto), "destination", "cedar")
		if err := rejectSession(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("session %s resumed with unsupported crypto method %s", redactSessionID(sessionID), clientCrypto)
	}

	slog.Info(fmt.Sprintf("🔐 SERVER: Found session %s, resuming...", redactSessionID(sessionID)), "destination", "cedar")

	// Renew the session lease
	entry.RenewLease()
	cache.Store(entry)

	// The wire command is always DC_AUTHENTICATE; the command actually being
	// invoked over the resumed session is carried in the client's ad (see the
	// client resume path, which sets "Command"). Extract it and expose it via
	// ClientConfig so a dispatching server can route the resumed command instead
	// of seeing command 0 and dropping the connection.
	resumedCommand := command
	if c, ok := clientAd.EvaluateAttrInt("Command"); ok {
		resumedCommand = int(c)
	}
	// A resumed DC_SEC_QUERY names the command it asks about, as on a full
	// handshake.
	authCommand := 0
	if c, ok := clientAd.EvaluateAttrInt("AuthCommand"); ok {
		authCommand = int(c)
	}
	clientConfig := &SecurityConfig{Command: resumedCommand, AuthCommand: authCommand}
	// The resume request carries the client's version, which HTCondor takes
	// as the peer's (DaemonCommandProtocol::ReadCommand).
	if rv, ok := clientAd.EvaluateAttrString("RemoteVersion"); ok {
		clientConfig.RemoteVersion = rv
	}

	if wantResponse {
		// Advertise the version a full handshake for this command would: the
		// per-command config's when one is selected, else the server's own.
		versionConfig := a.config
		if a.ServerConfigForCommand != nil {
			if perCmd := a.ServerConfigForCommand(clientConfig.AuthorizedCommand()); perCmd != nil {
				versionConfig = perCmd
			}
		}

		// Send success response
		responseAd := classad.New()
		_ = responseAd.Set("ReturnCode", "AUTHORIZED")
		_ = responseAd.Set("Sid", sessionID)
		// As in HTCondor (DaemonCommandProtocol::ReadCommand), the reply
		// carries our version and a fresh nonce. The nonce enters the
		// handshake digest bound into the AES-GCM AAD, so the client's
		// encrypted frames verify only on this connection.
		nonce, err := resumeNonce()
		if err != nil {
			return nil, err
		}
		_ = responseAd.Set("RemoteVersion", versionConfig.advertisedVersion())
		_ = responseAd.Set("Nonce", nonce)

		responseMsg := message.NewMessageForStream(a.stream)
		if err := responseMsg.PutClassAd(ctx, responseAd); err != nil {
			return nil, fmt.Errorf("failed to send session resumption response: %w", err)
		}
		if err := responseMsg.FinishMessage(ctx); err != nil {
			return nil, fmt.Errorf("failed to finish session resumption response: %w", err)
		}

		slog.Info("🔐 SERVER: Sent session resumption success response", "destination", "cedar")
	}

	// Create negotiation result from cached session
	negotiation := &SecurityNegotiation{
		Command:      resumedCommand,
		ClientConfig: clientConfig,
		ServerConfig: a.config,
		IsClient:     false,
		SessionId:    sessionID,
	}

	// Restore session information and mark as resumed
	if entry.KeyInfo() != nil {
		negotiation.setSharedSecret(entry.KeyInfo().Data)
		negotiation.NegotiatedCrypto = CryptoMethod(entry.KeyInfo().Protocol)
		negotiation.SessionResumed = true
		negotiation.Encryption = isAESGCM(negotiation.NegotiatedCrypto)
		a.sessionResumed = true
	}

	if entry.Policy() != nil {
		if authMethod, ok := entry.Policy().EvaluateAttrString("AuthMethods"); ok {
			negotiation.NegotiatedAuth = AuthMethod(authMethod)
		}
		// Restore User information from cached policy
		if user, ok := entry.Policy().EvaluateAttrString("User"); ok {
			negotiation.User = user
		}
		// Restore the session's actual authentication outcome and authorized command
		// set so a resumed session is judged by what it really was, not left at the
		// zero value (which would wrongly deny an authenticated session, or -- with
		// ValidCommands empty -- every command under an Authorizer).
		//
		// The cache is shared with sessions this process negotiated as a
		// client, which the peer can also resume here. Those name no peer, so
		// a session counts as authenticated only when it names who was.
		if authed, ok := entry.Policy().EvaluateAttrBool("Authenticated"); ok {
			negotiation.Authentication = authed && negotiation.User != ""
		}
		// Re-advertise what this session was created advertising (see
		// storeSession), so the server's own view of a resumed session matches
		// the fresh one.
		if a.config != nil {
			negotiation.SessionAttrs = sessionAttrsFromPolicy(entry.Policy(), sortedAttrNames(a.config.SessionAttrs))
		}
		if valid, ok := entry.Policy().EvaluateAttrString("ValidCommands"); ok {
			negotiation.ValidCommands = valid
		}
		// storeSession records the bounding set of the credential the peer
		// authenticated with. Client, claim and minted sessions have none, as
		// in HTCondor; nothing the peer sends when resuming can set it.
		if limits, ok := entry.Policy().EvaluateAttrString(AttrLimitAuthorization); ok {
			negotiation.AuthorizationLimits = parseLimitAuthorization(limits)
		}
	}

	// Set up encryption with cached key (only for session resumption)
	if len(negotiation.GetSharedSecret()) > 0 {
		if err := a.setupStreamEncryption(negotiation); err != nil {
			return nil, fmt.Errorf("failed to setup stream encryption: %w", err)
		}
	}

	slog.Info(fmt.Sprintf("🔐 SERVER: Successfully resumed session %s", redactSessionID(sessionID)), "destination", "cedar")

	return negotiation, nil
}

// ServerHandshake performs the server-side security handshake
// This receives a single message with DC_AUTHENTICATE command and client ClassAd, then responds
func (a *Authenticator) ServerHandshake(ctx context.Context) (*SecurityNegotiation, error) {
	// Parse message directly from stream using Message API
	msg := message.NewMessageFromStream(a.stream)

	// First get the command integer
	command, err := msg.GetInt(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authenticate command: %w", err)
	}

	return a.ServerHandshakeWithMessage(ctx, msg, command)
}

// ServerHandshakeWithMessage performs the server-side security handshake when
// the caller has already created the inbound Message and consumed the leading
// command integer. This lets a dispatching server peek the command to
// distinguish an authenticated command (DC_AUTHENTICATE) from a "raw" command
// (e.g. CCB_REVERSE_CONNECT) before deciding to authenticate. The provided
// message MUST be the one the command int was read from, so the client
// security ClassAd is read from the same message.
func (a *Authenticator) ServerHandshakeWithMessage(ctx context.Context, msg *message.Message, command int) (*SecurityNegotiation, error) {
	if command != commands.DC_AUTHENTICATE {
		return nil, fmt.Errorf("expected DC_AUTHENTICATE command (%d), got %d", commands.DC_AUTHENTICATE, command)
	}

	// Then get the client security ClassAd
	// Limit ClassAd size to 4KB to prevent DoS attacks
	clientAd, err := msg.GetClassAdWithMaxSize(ctx, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client security ad: %w", err)
	}

	// Check if this is a session resumption request
	if useSession, ok := clientAd.EvaluateAttrString("UseSession"); ok && useSession == "YES" {
		if sid, ok := clientAd.EvaluateAttrString("Sid"); ok {
			slog.Info(fmt.Sprintf("🔐 SERVER: Received session resumption request for %s", redactSessionID(sid)), "destination", "cedar")
			return a.handleSessionResumption(ctx, sid, clientAd, command)
		}
	}

	// Regular authentication flow (no session resumption)
	// Process client configuration and create negotiation
	clientConfig := a.parseClientSecurityAd(clientAd)

	// Now that the client's requested command is known, let the server swap in a
	// per-command security policy (e.g. serve a QUERY at READ but an UPDATE at
	// ADVERTISE). Do this before negotiation so the negotiated methods, auth
	// requirement, and the advertised response all reflect the command's level.
	// A DC_SEC_QUERY is negotiated at the level of the command it asks about.
	if a.ServerConfigForCommand != nil {
		if perCmd := a.ServerConfigForCommand(clientConfig.AuthorizedCommand()); perCmd != nil {
			// The per-command config carries only policy (auth/encryption/
			// integrity requirements and methods); it does not have this
			// connection's ephemeral ECDH keypair. NewAuthenticator generated
			// that keypair and stored the matching public key in the original
			// a.config while keeping the private half in a.ecdhPrivKey, so
			// a.config.ECDHPublicKey <-> a.ecdhPrivKey is an invariant the key
			// derivation relies on. Carry the public key across the swap so the
			// server still advertises the pubkey that matches a.ecdhPrivKey.
			// Without this the server would advertise perCmd's empty (or
			// foreign) ECDHPublicKey: the client then either receives no server
			// pubkey and fails encryption outright ("enable_enc no key to use")
			// or derives a mismatched key and every encrypted frame is garbage.
			perCmd.ECDHPublicKey = a.config.ECDHPublicKey
			a.config = perCmd
		}
	}

	negotiation := &SecurityNegotiation{
		Command:      command,
		ClientConfig: clientConfig,
		// Filtered so the server neither advertises nor negotiates a TLS method it
		// cannot back (no readable configured cert). See serverOfferedAuthMethods.
		ServerConfig: a.serverNegotiationConfig(),
		IsClient:     false,
	}

	// Negotiate security settings
	if err := a.negotiateSecurity(negotiation); err != nil {
		// Graceful failure: send a response ClassAd describing the failed
		// reconciliation before returning (the caller then closes the socket).
		// Without this the peer reads nothing and reports a bare closed socket --
		// HTCondor surfaces it as SECMAN:2011 "Connection closed during command
		// authorization. Probably due to an unknown command." -- which is
		// misleading when the real cause is a security-policy mismatch. The
		// response reflects the demanded levels (see negotiateSecurity) so the
		// peer's own policy checks fire, and carries an explicit reason for peers
		// (and cedar's own client) that inspect it.
		a.sendNegotiationFailureResponse(ctx, negotiation, err)
		return nil, fmt.Errorf("security negotiation failed: %w", err)
	}

	// Send server response using Message API
	serverAd := a.createServerSecurityAd(negotiation)
	responseMsg := message.NewMessageForStream(a.stream)
	if err := responseMsg.PutClassAd(ctx, serverAd); err != nil {
		return nil, fmt.Errorf("failed to serialize server response: %w", err)
	}
	if err := responseMsg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to send server response: %w", err)
	}

	// Handle authentication phase FIRST (without encryption). Whether it is
	// attempted at all is reported to the peer as TriedAuthentication.
	triedAuthentication := negotiation.Authentication
	if err := a.handleServerAuthentication(ctx, negotiation); err != nil {
		return nil, fmt.Errorf("server authentication phase failed: %w", err)
	}

	// NOW set up stream encryption AFTER authentication is complete
	if err := a.setupStreamEncryption(negotiation); err != nil {
		return nil, fmt.Errorf("failed to setup stream encryption: %w", err)
	}
	if err := a.requireEnactedKey(negotiation.Encryption, negotiation.Integrity); err != nil {
		return nil, err
	}

	// Send post-authentication session info using Message API
	postAuthAd, refusal := a.createPostAuthAd(negotiation, triedAuthentication)
	postAuthMsg := message.NewMessageForStream(a.stream)
	if err := postAuthMsg.PutClassAd(ctx, postAuthAd); err != nil {
		return nil, fmt.Errorf("failed to serialize post-auth response: %w", err)
	}
	if err := postAuthMsg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to send post-auth response: %w", err)
	}
	if refusal != nil {
		return nil, refusal
	}

	return negotiation, nil
}

// DefaultRemoteVersion is the CondorVersion a cedar peer advertises (as the
// RemoteVersion handshake attribute) when the caller set none. It MUST parse as
// >= 9.9.0: a C++ peer keys putClassAd behavior on the version we advertise
// (Sock::get_peer_version). Advertise nothing (or < 9.9.0) and C++ takes the
// legacy private-attribute path -- wrapping each private attribute in a
// SECRET_MARKER ("ZKM") + put_secret sub-message -- even under AES-GCM
// (classad_oldnew.cpp exclude_private_v2). Advertising a modern version makes C++
// send private attributes inline under normal full-session encryption, avoiding
// the marker entirely. Build metadata is irrelevant; only major.minor gates this.
const DefaultRemoteVersion = "$CondorVersion: 25.4.0 2025-10-31 BuildID: 847437 PackageID: 25.4.0-0.847437 GitSHA: a6507f91 RC $"

// advertisedVersion is the RemoteVersion this side sends its peer: the
// configured one, else DefaultRemoteVersion. Every ad that carries our version
// -- handshake request and reply, resumption request and reply -- uses it, so a
// peer sees the same version whether the session was negotiated or resumed.
func (c *SecurityConfig) advertisedVersion() string {
	if c.RemoteVersion != "" {
		return c.RemoteVersion
	}
	return DefaultRemoteVersion
}

// createClientSecurityAd creates the client security ClassAd for handshake
func (a *Authenticator) createClientSecurityAd() *classad.ClassAd {
	ad := classad.New()

	// Authentication methods - comma separated string
	_ = ad.Set("AuthMethods", wireAuthMethodList(a.config.AuthMethods))

	// Crypto methods - comma separated string
	cryptoMethods := ""
	for i, method := range a.config.CryptoMethods {
		if i > 0 {
			cryptoMethods += ","
		}
		cryptoMethods += string(method)
	}
	_ = ad.Set("CryptoMethods", cryptoMethods)

	// Security levels
	_ = ad.Set("Authentication", string(a.config.Authentication))
	// AuthenticationNew (HTCondor 23.10+) carries the same authentication
	// preference but tells the peer we do NOT couple authentication to
	// encryption/integrity. Without it the server treats us as a pre-9.0 client
	// and forces authentication whenever encryption/integrity are required.
	_ = ad.Set("AuthenticationNew", string(a.config.Authentication))
	// An unset level is HTCondor's default, OPTIONAL, as FillInSecurityPolicyAd
	// always sends one: a server reads a missing one as NEVER.
	_ = ad.Set("Encryption", string(ownSecurityLevel(a.config.Encryption)))
	_ = ad.Set("Integrity", string(ownSecurityLevel(a.config.Integrity)))

	// Advertise the session command. Only an auth-only handshake (NoCommand)
	// falls back to DC_AUTHENTICATE; a real command -- including 0
	// (UPDATE_STARTD_AD) -- is sent as-is so the server can dispatch it.
	sessionCommand := a.config.Command
	if sessionCommand < 0 {
		sessionCommand = commands.DC_AUTHENTICATE
	}
	_ = ad.Set("Command", sessionCommand)

	// Include AuthCommand if specified (sub-command for the handshake)
	if a.config.AuthCommand != 0 {
		_ = ad.Set("AuthCommand", a.config.AuthCommand)
	}
	_ = ad.Set("RemoteVersion", a.config.advertisedVersion())
	if a.config.TrustDomain != "" {
		_ = ad.Set("TrustDomain", a.config.TrustDomain)
	}
	if a.config.Subsystem != "" {
		_ = ad.Set("Subsystem", a.config.Subsystem)
	}
	if a.config.ServerPid > 0 {
		_ = ad.Set("ServerPid", a.config.ServerPid)
	}
	if a.config.SessionDuration > 0 {
		_ = ad.Set("SessionDuration", a.config.SessionDuration)
	}
	if a.config.SessionLease > 0 {
		_ = ad.Set("SessionLease", a.config.SessionLease)
	}
	if a.config.ECDHPublicKey != "" {
		_ = ad.Set("ECDHPublicKey", a.config.ECDHPublicKey)
	}

	// Negotiation settings
	_ = ad.Set("NegotiatedSession", true)
	_ = ad.Set("NewSession", "YES")
	_ = ad.Set("OutgoingNegotiation", "PREFERRED")
	_ = ad.Set("Enact", "NO")

	slog.Info(fmt.Sprintf("🔐 CLIENT: Created client security ClassAd: %v", ad), "destination", "cedar")
	return ad
}

// parseServerSecurityAd parses server security ClassAd into config.
// Also used (via parseClientSecurityAd) to parse a client request on
// the server side; the two ClassAd shapes overlap enough to share
// parsing.
//
// AuthMethods vs AuthMethodsList: a server response carries TWO
// fields. `AuthMethods` is the SINGLE negotiated method (set by
// createServerSecurityAd at the bottom of negotiation). `AuthMethodsList`
// is the FULL list of methods the server supports — that's what the
// client needs in order to drive the bitmask-exchange retry loop in
// handleClientAuthentication: when the first method fails, the client
// strips it from the bitmask and tries the next one, but only methods
// in `AuthMethods` (the parsed config field) are considered candidates.
//
// Reading the singular `AuthMethods` here meant `availableMethods`
// later in handleClientAuthentication had exactly one entry — once
// that method failed, retry had nothing to try and the handshake
// died with "all authentication methods failed: FS: server
// verification failed", even when the server had advertised
// `AuthMethodsList = "FS,SSL"` and SSL would have worked.
//
// We prefer `AuthMethodsList` when present, falling back to
// `AuthMethods` when not. The fallback covers two cases:
//
//   - The server-side parse of a client request (createClientSecurityAd
//     only sets `AuthMethods` — it's the client's full list, no need
//     to duplicate into a separate field).
//   - Older peers that predate `AuthMethodsList` in the response.
//
// Same treatment for CryptoMethods / CryptoMethodsList.
func (a *Authenticator) parseServerSecurityAd(ad *classad.ClassAd) *SecurityConfig {
	config := &SecurityConfig{}

	// Parse authentication methods. Prefer AuthMethodsList (the full
	// set) over AuthMethods (the single negotiated outcome on a server
	// response).
	if list, ok := ad.EvaluateAttrString("AuthMethodsList"); ok && list != "" {
		config.AuthMethods = parseMethodsList(list)
	} else if authMethods, ok := ad.EvaluateAttrString("AuthMethods"); ok {
		config.AuthMethods = parseMethodsList(authMethods)
	}

	// Parse crypto methods. Same precedence: full list first, single
	// negotiated value as fallback.
	if list, ok := ad.EvaluateAttrString("CryptoMethodsList"); ok && list != "" {
		config.CryptoMethods = parseCryptoMethodsList(list)
	} else if cryptoMethods, ok := ad.EvaluateAttrString("CryptoMethods"); ok {
		config.CryptoMethods = parseCryptoMethodsList(cryptoMethods)
	}

	// Parse command fields
	if command, ok := ad.EvaluateAttrInt("Command"); ok {
		config.Command = int(command)
	}
	if authCommand, ok := ad.EvaluateAttrInt("AuthCommand"); ok {
		config.AuthCommand = int(authCommand)
	}

	// Parse security levels
	if auth, ok := ad.EvaluateAttrString("Authentication"); ok {
		config.Authentication = SecurityLevel(auth)
	}
	// HTCondor 23.10+ peers also send AuthenticationNew: the authentication
	// preference decoupled from encryption/integrity. Prefer it when present so a
	// required-encryption policy does not force authentication on. This mirrors
	// condor_secman.cpp ReconcileSecurityAttribute, which reconciles
	// AuthenticationNew as the primary attribute and falls back to Authentication
	// only for pre-9.0 peers. A peer sends Authentication coupled up to the
	// encryption requirement, but AuthenticationNew carries its real preference.
	if authNew, ok := ad.EvaluateAttrString("AuthenticationNew"); ok && authNew != "" {
		config.Authentication = SecurityLevel(authNew)
	}
	// ATTR_SEC_AUTH_REQUIRED: a server sets this false when authentication is
	// enacted but not mandatory, so the client may proceed unauthenticated if the
	// enacted method fails. Absent leaves it nil (treated as required).
	if req, ok := ad.EvaluateAttrBool("AuthRequired"); ok {
		config.AuthRequired = &req
	}
	if enc, ok := ad.EvaluateAttrString("Encryption"); ok {
		config.Encryption = SecurityLevel(enc)
	}
	if integrity, ok := ad.EvaluateAttrString("Integrity"); ok {
		config.Integrity = SecurityLevel(integrity)
	}

	// Parse other attributes
	if version, ok := ad.EvaluateAttrString("RemoteVersion"); ok {
		config.RemoteVersion = version
	}
	if domain, ok := ad.EvaluateAttrString("TrustDomain"); ok {
		config.TrustDomain = domain
	}
	if duration, ok := ad.EvaluateAttrInt("SessionDuration"); ok {
		config.SessionDuration = int(duration)
	}
	if lease, ok := ad.EvaluateAttrInt("SessionLease"); ok {
		config.SessionLease = int(lease)
	}
	if key, ok := ad.EvaluateAttrString("ECDHPublicKey"); ok {
		config.ECDHPublicKey = key
	}
	if issuerKeys, ok := ad.EvaluateAttrString("IssuerKeys"); ok {
		config.IssuerKeys = parseIssuerKeysList(issuerKeys)
	}

	return config
}

// parseClientSecurityAd parses client security ClassAd into config
func (a *Authenticator) parseClientSecurityAd(ad *classad.ClassAd) *SecurityConfig {
	return a.parseServerSecurityAd(ad) // Same parsing logic
}

// createServerSecurityAd creates server response ClassAd based on negotiation
func (a *Authenticator) createServerSecurityAd(negotiation *SecurityNegotiation) *classad.ClassAd {
	ad := classad.New()

	// Negotiated methods
	_ = ad.Set("AuthMethods", string(wireAuthMethod(negotiation.NegotiatedAuth)))
	_ = ad.Set("CryptoMethods", string(negotiation.NegotiatedCrypto))

	// AuthMethodsList advertises the methods the client may attempt. Start from the
	// negotiation's server methods (filtered to drop TLS methods the server cannot
	// back, so a vetoed SSL/SCITOKENS is never advertised) rather than the raw
	// config, then restrict to the intersection with what the client offered (in
	// server preference order). Some clients try every method in this list without
	// re-checking it against their own offer, so a full list would let a peer
	// attempt a method it never offered. When the client offered nothing usable we
	// fall back to the server's (vetoed) list -- there is no client set to intersect
	// with, and authentication will fail on the empty overlap anyway.
	serverAuthMethods := a.config.AuthMethods
	if negotiation.ServerConfig != nil {
		serverAuthMethods = negotiation.ServerConfig.AuthMethods
	}
	if negotiation.ClientConfig != nil && len(negotiation.ClientConfig.AuthMethods) > 0 {
		clientOffered := make(map[AuthMethod]bool, len(negotiation.ClientConfig.AuthMethods))
		for _, m := range negotiation.ClientConfig.AuthMethods {
			clientOffered[wireAuthMethod(m)] = true
		}
		intersected := make([]AuthMethod, 0, len(serverAuthMethods))
		for _, m := range serverAuthMethods {
			if clientOffered[wireAuthMethod(m)] {
				intersected = append(intersected, m)
			}
		}
		serverAuthMethods = intersected
	}
	_ = ad.Set("AuthMethodsList", wireAuthMethodList(serverAuthMethods))

	cryptoMethodsList := ""
	for i, method := range a.config.CryptoMethods {
		if i > 0 {
			cryptoMethodsList += ","
		}
		cryptoMethodsList += string(method)
	}
	_ = ad.Set("CryptoMethodsList", cryptoMethodsList)

	// Security decisions
	if negotiation.Authentication {
		_ = ad.Set("Authentication", "YES")
		// Tell the client whether authentication is MANDATORY. The
		// server enacts auth whenever methods match and either side
		// prefers it, but "enacted" is not "required": a server whose
		// own policy only prefers auth still authorizes an
		// unauthenticated peer (an htcondordb with anonymous ALLOW_READ,
		// say). Without this attribute the client assumes auth is
		// required -- the documented default, matching HTCondor's C++
		// secman -- so when its enacted methods all fail it errors with
		// "all authentication methods failed" instead of falling through
		// to the unauthenticated session the server would have granted.
		// That is exactly the client-side mayProceedUnauthenticated
		// fallback, which is dead code until the server advertises this.
		//
		// Only the not-required case is emitted, because absent already
		// means required (ATTR_SEC_AUTH_REQUIRED, condor_secman.cpp).
		// Required means required by EITHER side: a client whose own
		// policy is REQUIRED must not be told it may go without.
		if !eitherSideRequiresAuth(a.config.Authentication, negotiation.ClientConfig) {
			_ = ad.Set("AuthRequired", false)
		}
	} else {
		_ = ad.Set("Authentication", "NO")
	}

	if negotiation.Encryption {
		_ = ad.Set("Encryption", "YES")
	} else {
		_ = ad.Set("Encryption", "NO")
	}

	if negotiation.Integrity {
		_ = ad.Set("Integrity", "YES")
	} else {
		_ = ad.Set("Integrity", "NO")
	}

	// Server configuration. Always advertise a version (default >= 9.9.0) so a
	// connecting C++ peer sees a modern RemoteVersion and sends private attributes
	// inline under full-session encryption, instead of the legacy SECRET_MARKER +
	// put_secret path that a missing peer version triggers. See DefaultRemoteVersion.
	_ = ad.Set("RemoteVersion", a.config.advertisedVersion())
	if a.config.TrustDomain != "" {
		_ = ad.Set("TrustDomain", a.config.TrustDomain)
	}
	if a.config.SessionDuration > 0 {
		_ = ad.Set("SessionDuration", a.config.SessionDuration)
	}
	if a.config.SessionLease > 0 {
		_ = ad.Set("SessionLease", a.config.SessionLease)
	}
	if a.config.ECDHPublicKey != "" {
		_ = ad.Set("ECDHPublicKey", a.config.ECDHPublicKey)
	}

	// Negotiation result
	_ = ad.Set("NegotiatedSession", true)
	if negotiation.Enact {
		_ = ad.Set("Enact", "YES")
	} else {
		_ = ad.Set("Enact", "NO")
	}

	return ad
}

// negotiationFailureReturnCode is the ATTR_SEC_RETURN_CODE value sent in a
// graceful negotiation-failure response. HTCondor's client treats any ReturnCode
// other than "AUTHORIZED" as a rejection.
const negotiationFailureReturnCode = "DENIED"

// sendNegotiationFailureResponse sends a best-effort response ClassAd after
// security negotiation fails, so the peer gets a specific reason instead of a
// silently closed socket (which HTCondor reports as the misleading SECMAN:2011
// "Connection closed during command authorization. Probably due to an unknown
// command."). The ad reflects the security levels the server was demanding --
// Authentication/Encryption = "YES" with the negotiated method left empty --
// which is what drives a peer's own policy checks (e.g. HTCondor's "requires
// encryption but provided no crypto method to use; potentially there were no
// mutually-compatible methods enabled"), and it carries ReturnCode="DENIED" plus
// a human-readable ErrorString that cedar's own client surfaces verbatim.
//
// Errors here are ignored: the connection is already failing and the caller
// closes it next; this is a best-effort courtesy to the peer.
func (a *Authenticator) sendNegotiationFailureResponse(ctx context.Context, negotiation *SecurityNegotiation, negErr error) {
	if a.stream == nil {
		return
	}
	ad := a.createServerSecurityAd(negotiation)
	_ = ad.Set("ReturnCode", negotiationFailureReturnCode)
	if negErr != nil {
		_ = ad.Set("ErrorString", negErr.Error())
	}
	// A failed negotiation never enacts a session.
	_ = ad.Set("Enact", "NO")

	msg := message.NewMessageForStream(a.stream)
	if err := msg.PutClassAd(ctx, ad); err != nil {
		slog.Debug(fmt.Sprintf("🔐 SERVER: failed to send negotiation-failure response: %v", err), "destination", "cedar")
		return
	}
	if err := msg.FinishMessage(ctx); err != nil {
		slog.Debug(fmt.Sprintf("🔐 SERVER: failed to flush negotiation-failure response: %v", err), "destination", "cedar")
	}
}

// createPostAuthAd creates the post-authentication ClassAd with session
// information and, unless AuthorizeCommand refuses the negotiated command,
// caches the session. triedAuthentication reports whether the server attempted
// to authenticate the peer. A refusal is returned as a *CommandRefusedError,
// with the ad carrying its ReturnCode.
func (a *Authenticator) createPostAuthAd(negotiation *SecurityNegotiation, triedAuthentication bool) (*classad.ClassAd, error) {
	ad := classad.New()

	// Generate unique session ID
	sessionID := GenerateSessionID(GetNextSessionCounter())
	negotiation.SessionId = sessionID

	// Session information
	_ = ad.Set("Sid", sessionID)
	// A C++ client copies TriedAuthentication into its cached session and, on
	// resuming it for a later command, sets the socket's triedAuthentication from
	// it (condor_secman.cpp). A command that forces authentication
	// (Daemon::forceAuthentication) then re-authenticates mid-command unless it
	// is set. DaemonCore sends it only when true (daemon_command.cpp,
	// SendResponse).
	if triedAuthentication {
		_ = ad.Set("TriedAuthentication", true)
	}
	// Report the authenticated identity the peer mapped to, so the client's
	// post-auth "current FQU" is its real identity rather than unmapped, and the
	// set of commands this session is authorized for. HTCondor's SECMAN reads
	// ValidCommands as a *string* (LookupString) and aborts if it is empty, so it
	// must be a non-empty comma-separated command list, not an integer.
	//
	// The security layer does not own the authorization policy, so when the
	// application supplies a PostAuthPolicy we use it to map the identity and
	// enumerate the authorized commands; otherwise we fall back to reporting the
	// authenticated identity and just the command that was negotiated.
	user := negotiation.User
	if user == "" {
		user = "unauthenticated@unmapped"
	}
	// Report the command the client actually authenticated for
	// (ClientConfig.AuthorizedCommand()), not the outer DC_AUTHENTICATE that
	// framed the handshake (negotiation.Command). The client caches the session
	// under this command and resumes by it, so reporting the outer command here
	// would keep every session from ever resuming. For a DC_SEC_QUERY it is the
	// command queried, under which a C++ client looks the session up.
	sessionCommand := negotiation.Command
	if negotiation.ClientConfig != nil {
		sessionCommand = negotiation.ClientConfig.AuthorizedCommand()
	}
	validCommands := fmt.Sprintf("%d", sessionCommand)
	if a.config != nil && a.config.PostAuthPolicy != nil {
		peerAddr := a.config.PeerName
		if a.stream != nil {
			peerAddr = a.stream.GetPeerAddr()
		}
		fqu, cmds := a.config.PostAuthPolicy(negotiation.User, peerAddr, negotiation.Authentication, negotiation.Encryption)
		if fqu != "" {
			user = fqu
		}
		cmds = a.withinAuthorizationLimits(negotiation, cmds)
		if len(cmds) > 0 {
			strs := make([]string, len(cmds))
			for i, c := range cmds {
				strs[i] = fmt.Sprintf("%d", c)
			}
			validCommands = strings.Join(strs, ",")
		}
	}
	// Reflect the mapped identity back into the session state so the server's
	// own authorization probes and per-session identity checks see the same
	// fully-qualified user that was advertised to the peer -- not the pre-mapping
	// identity. Only for an authenticated peer: an anonymous session keeps User=""
	// (the advertised "unauthenticated@unmapped" fallback is display-only) so the
	// application still recognizes it as unauthenticated.
	if negotiation.User != "" {
		negotiation.User = user
	}
	_ = ad.Set("User", user)
	_ = ad.Set("ValidCommands", validCommands)

	// Session duration and lease (in seconds)
	sessionDuration := 3600 // 1 hour default
	sessionLease := 1800    // 30 minutes default
	if negotiation.ServerConfig != nil {
		if negotiation.ServerConfig.SessionDuration > 0 {
			sessionDuration = negotiation.ServerConfig.SessionDuration
		}
		if negotiation.ServerConfig.SessionLease > 0 {
			sessionLease = negotiation.ServerConfig.SessionLease
		}
	}
	_ = ad.Set("SessionDuration", sessionDuration)
	_ = ad.Set("SessionLease", sessionLease)

	// Authorize the command now, so the reply says whether it may run. A
	// refused command's session is not cached, so it cannot be resumed.
	if a.AuthorizeCommand != nil {
		if err := a.AuthorizeCommand(negotiation); err != nil {
			returnCode := "DENIED"
			if errors.Is(err, ErrCommandNotFound) {
				returnCode = "CMD_NOT_FOUND"
			}
			_ = ad.Set("ReturnCode", returnCode)
			return ad, &CommandRefusedError{ReturnCode: returnCode, Command: sessionCommand, Err: err}
		}
	}
	_ = ad.Set("ReturnCode", "AUTHORIZED")

	// Advertise the application's own attributes, and keep them on the
	// negotiation so storeSession persists them with the session: a resumed
	// session exchanges no post-auth ad, and a capability the peer can only
	// learn on its first connection is one it mostly cannot use.
	if a.config != nil && len(a.config.SessionAttrs) > 0 {
		setSessionAttrs(ad, a.config.SessionAttrs)
		negotiation.SessionAttrs = a.config.SessionAttrs
	}

	// Store session in cache
	a.storeSession(negotiation, sessionID, sessionDuration, sessionLease)

	return ad, nil
}

// withinAuthorizationLimits returns the commands in cmds that the session's
// AuthorizationLimits permit, judged by the levels SecurityConfig.CommandPerms
// reports for each. A session with no bounding set, or a config with no
// CommandPerms, keeps them all.
func (a *Authenticator) withinAuthorizationLimits(negotiation *SecurityNegotiation, cmds []int) []int {
	if negotiation.AuthorizationLimits == nil || a.config.CommandPerms == nil {
		return cmds
	}
	var kept []int
	for _, c := range cmds {
		if AuthorizationLimitsPermit(negotiation.AuthorizationLimits, a.config.CommandPerms(c)) {
			kept = append(kept, c)
		}
	}
	return kept
}

// storeSession stores the negotiated session in the global session cache
func (a *Authenticator) storeSession(negotiation *SecurityNegotiation, sessionID string, durationSecs, leaseSecs int) {
	cache := GetSessionCache()

	// Create key info from the shared secret
	var keyInfo *KeyInfo
	if len(negotiation.GetSharedSecret()) > 0 {
		keyInfo = &KeyInfo{
			Data:     negotiation.GetSharedSecret(),
			Protocol: string(negotiation.NegotiatedCrypto),
		}
	}

	// Create security policy ad
	policy := classad.New()
	_ = policy.Set("Authentication", string(negotiation.ServerConfig.Authentication))
	_ = policy.Set("Encryption", string(negotiation.ServerConfig.Encryption))
	_ = policy.Set("Integrity", string(negotiation.ServerConfig.Integrity))
	_ = policy.Set("AuthMethods", string(negotiation.NegotiatedAuth))
	_ = policy.Set("CryptoMethods", string(negotiation.NegotiatedCrypto))
	// Record the actual outcome (not just the configured policy) so a resumed
	// session reports whether it was authenticated and which commands it is
	// authorized for -- a reused session must be re-checked against each command's
	// required level (see server.sessionSatisfies).
	_ = policy.Set("Authenticated", negotiation.Authentication)
	if negotiation.ValidCommands != "" {
		_ = policy.Set("ValidCommands", negotiation.ValidCommands)
	}
	// Store User information for session resumption
	if negotiation.User != "" {
		_ = policy.Set("User", negotiation.User)
	}
	// Keep the credential's bounding set with the session, as HTCondor keeps
	// it in the session policy (daemon_command.cpp), so every command run on
	// the session resumed or kept alive is bounded by it too.
	if negotiation.AuthorizationLimits != nil {
		_ = policy.Set(AttrLimitAuthorization, strings.Join(negotiation.AuthorizationLimits, ","))
	}
	// Keep the application's advertised attributes with the session, so
	// resuming it advertises what the first handshake did.
	storeSessionAttrs(policy, negotiation.SessionAttrs)

	// Calculate expiration time
	expiration := time.Now().Add(time.Duration(durationSecs) * time.Second)
	lease := time.Duration(leaseSecs) * time.Second

	// Get client address from stream (server sees the client's address)
	clientAddr := a.config.PeerName
	if a.stream != nil {
		clientAddr = a.stream.GetPeerAddr()
	}
	if clientAddr == "" {
		slog.Info(fmt.Sprintf("🔐 SERVER: Cannot store session %s, client address unknown", redactSessionID(sessionID)), "destination", "cedar")
		return
	}

	// Create session entry with client address (for incoming sessions from clients)
	entry := NewSessionEntry(sessionID, clientAddr, keyInfo, policy, expiration, lease, a.config.SecurityTag)

	// Store in cache. The id was generated here, so it replaces anything a
	// peer may have placed under it (see storeClientSession).
	cache.Store(entry)

	slog.Info(fmt.Sprintf("🔐 SERVER: Created and cached session %s (duration: %ds, lease: %ds)",
		redactSessionID(sessionID), durationSecs, leaseSecs), "destination", "cedar")
}

// storeClientSession stores the session on the client side with the remote address
// storeClientSession stores the session on the client side with the remote address
func (a *Authenticator) storeClientSession(negotiation *SecurityNegotiation, durationSecs, leaseSecs int, cache *SessionCache) {
	// Create key info from the shared secret
	var keyInfo *KeyInfo
	if len(negotiation.GetSharedSecret()) > 0 {
		keyInfo = &KeyInfo{
			Data:     negotiation.GetSharedSecret(),
			Protocol: string(negotiation.NegotiatedCrypto),
		}
	}

	// Create security policy ad
	policy := classad.New()
	if negotiation.ClientConfig != nil {
		_ = policy.Set("Authentication", string(negotiation.ClientConfig.Authentication))
		_ = policy.Set("Encryption", string(negotiation.ClientConfig.Encryption))
		_ = policy.Set("Integrity", string(negotiation.ClientConfig.Integrity))
	}
	// Record what happened rather than what was negotiated: unless a method
	// actually ran, NegotiatedAuth still names the one negotiateSecurity
	// picked. Whether WE authenticated to the peer decides which client
	// configs may resume the session (see mayResume). It is recorded under
	// its own name, never "Authenticated": that attribute is the server's
	// statement that the peer authenticated to us, and the server resumes
	// sessions by id from the same cache.
	authed := clientAuthenticated(negotiation)
	authMethod := negotiation.NegotiatedAuth
	if !authed {
		authMethod = AuthNone
	}
	_ = policy.Set("AuthMethods", string(authMethod))
	_ = policy.Set("CryptoMethods", string(negotiation.NegotiatedCrypto))
	_ = policy.Set(clientAuthenticatedAttr, authed)
	// negotiation.User is our own identity as the server reported it, not the
	// server's. Record it as MyRemoteUserName and leave "User" -- the peer's
	// identity, which handleSessionResumption assigns if the peer resumes this
	// session against our own server -- unset, since the client side does not
	// learn who the server is. HTCondor does the same (condor_secman.cpp).
	if negotiation.User != "" {
		_ = policy.Set("MyRemoteUserName", negotiation.User)
	}
	// Keep the peer's application attributes with the session, for the same
	// reason as its version: a resumed session must answer as the fresh one did.
	storeSessionAttrs(policy, negotiation.SessionAttrs)

	// Store the peer (server) version so a resumed session exposes it just like
	// a freshly-negotiated one (callers such as CCB streaming gate on it).
	if negotiation.ServerConfig != nil && negotiation.ServerConfig.RemoteVersion != "" {
		_ = policy.Set("RemoteVersion", negotiation.ServerConfig.RemoteVersion)
	}

	// Use defaults if not provided
	if durationSecs == 0 {
		durationSecs = 3600 // 1 hour
	}
	if leaseSecs == 0 {
		leaseSecs = 1800 // 30 minutes
	}

	// Calculate expiration time
	expiration := time.Now().Add(time.Duration(durationSecs) * time.Second)
	lease := time.Duration(leaseSecs) * time.Second

	// Priority order: PeerName > Stream's peer address
	serverAddr := a.config.PeerName
	if serverAddr == "" && a.stream != nil {
		serverAddr = a.stream.GetPeerAddr()
	}

	// Store and map under the same tag the lookup in ClientHandshake uses, so
	// a session is resumed only by a config presenting the same credential.
	tag := a.config.clientSessionTag(cache)

	// Create session entry with remote address (using sinful string)
	entry := NewSessionEntry(negotiation.SessionId, serverAddr, keyInfo, policy, expiration, lease, tag)

	// The server chose the session id. If a live session already has it, keep
	// that one, as HTCondor's client does: this session is not cached, and the
	// connection proceeds without resumption. An entry with the same key is
	// this session's other end, cached by our own server when we connected to
	// ourselves; record the client's view over it as before.
	if old, stored := cache.storeNew(entry); !stored {
		if !sameSessionKey(old, entry) {
			slog.Warn(fmt.Sprintf("🔐 CLIENT: Not caching session %s from %s: the id is already in use",
				redactSessionID(negotiation.SessionId), serverAddr), "destination", "cedar")
			return
		}
		cache.Store(entry)
	}

	// Map commands to this session (using sinful string as key)
	if negotiation.ValidCommands != "" {
		commands := strings.Split(negotiation.ValidCommands, ",")
		for _, cmd := range commands {
			cmd = strings.TrimSpace(cmd)
			if cmd != "" {
				cache.MapCommand(tag, serverAddr, cmd, negotiation.SessionId)
			}
		}
	}

	slog.Info(fmt.Sprintf("🔐 CLIENT: Cached session %s for %s (duration: %ds, lease: %ds)",
		redactSessionID(negotiation.SessionId), serverAddr, durationSecs, leaseSecs), "destination", "cedar")
}

// resumeNonce returns the "Nonce" value both peers of a session resumption
// send: 33 random bytes, base64-encoded, as HTCondor generates it.
func resumeNonce() (string, error) {
	var b [33]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed to generate resumption nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// resumeSession attempts to resume an existing session
func (a *Authenticator) resumeSession(ctx context.Context, entry *SessionEntry, cache *SessionCache) (*SecurityNegotiation, error) {
	// Create message for session resumption request
	msg := message.NewMessageForStream(a.stream)

	// A session the caller named outright, with SecurityConfig.SessionID, is
	// not a cached optimization: it is the credential for this dial, and
	// nothing stands behind it. ClientHandshake's explicit branch resumes it
	// or fails, so dropping it on a failed exchange leaves the retry with no
	// credential at all -- it reports "pre-registered session not found in
	// cache" and the reason the first attempt failed is gone. Keep it, and the
	// retry either works or names what actually went wrong.
	pinned := a.config.SessionID != ""

	// Send DC_AUTHENTICATE command
	// A failure anywhere in the resumption exchange leaves this connection
	// unusable and a *cached* session suspect: the peer may have restarted
	// without a session store (SID unknown), be mid-restart (reset/EOF), or have
	// expired the session. Treat every such failure as a resumption failure --
	// drop the cached session and report a SessionResumptionError so
	// ConnectAndAuthenticate retries on a fresh connection with full
	// authentication, exactly as it does for an explicit SID_NOT_FOUND. (Without
	// this, an EOF while reading the response surfaced as a hard error AND left
	// the stale session cached, so every reconnect re-attempted the doomed
	// resumption.)
	fail := func(reason string, err error) (*SecurityNegotiation, error) {
		if !pinned {
			cache.Invalidate(entry.ID())
		}
		return nil, &SessionResumptionError{SessionID: entry.ID(), Reason: reason, Cause: err}
	}

	if err := msg.PutInt(ctx, commands.DC_AUTHENTICATE); err != nil {
		return fail("failed to put authenticate command", err)
	}

	// Create resumption request ad
	resumeAd := classad.New()
	_ = resumeAd.Set("Command", a.config.Command)
	if a.config.AuthCommand != 0 {
		_ = resumeAd.Set("AuthCommand", a.config.AuthCommand)
	}
	_ = resumeAd.Set("UseSession", "YES")
	_ = resumeAd.Set("Sid", entry.ID())
	// A fresh nonce, as SecManStartCommand::sendAuthInfo_inner sends, makes
	// the handshake digest bound into the AES-GCM AAD unique to this
	// connection, so the server's encrypted frames verify only here.
	nonce, err := resumeNonce()
	if err != nil {
		return fail("failed to generate resumption nonce", err)
	}
	_ = resumeAd.Set("Nonce", nonce)
	_ = resumeAd.Set("ResumeResponse", true) // Request response for modern protocol
	_ = resumeAd.Set("RemoteVersion", a.config.advertisedVersion())

	// Name the cipher this connection is keyed with, spelled as HTCondor
	// spells it, as SecManStartCommand::sendAuthInfo_inner does. A C++ server
	// holding a key per method for the session uses the one named here
	// (DaemonCommandProtocol::ReadCommand); a name it does not know ("AESGCM")
	// leaves it on its preferred key, which need not be AES.
	// A session without a key names none.
	if key := entry.KeyInfo(); key != nil && key.Protocol != "" {
		method := CryptoMethod(key.Protocol)
		if isAESGCM(method) {
			method = CryptoAES
		}
		_ = resumeAd.Set("CryptoMethods", string(method))
	}

	// Send the resumption request
	if err := msg.PutClassAd(ctx, resumeAd); err != nil {
		return fail("failed to send resumption request", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fail("failed to finish resumption message", err)
	}

	slog.Info(fmt.Sprintf("🔐 CLIENT: Sent session resumption request for %s", redactSessionID(entry.ID())), "destination", "cedar")

	// Wait for server response
	responseMsg := message.NewMessageFromStream(a.stream)
	responseAd, err := responseMsg.GetClassAdWithMaxSize(ctx, 4096)
	if err != nil {
		return fail("failed to receive resumption response", err)
	}

	slog.Info("🔐 CLIENT: Received resumption response:", "destination", "cedar")
	slog.Info(fmt.Sprintf("    %s", responseAd.String()), "destination", "cedar")

	// Check if session was accepted
	if returnCode, ok := responseAd.EvaluateAttrString("ReturnCode"); ok {
		if returnCode == "SID_NOT_FOUND" {
			// Session not found on server, invalidate locally and return specific error
			if !pinned {
				cache.Invalidate(entry.ID())
			}
			return nil, &SessionResumptionError{
				SessionID: entry.ID(),
				Reason:    "session not found on server",
			}
		} else if returnCode != "AUTHORIZED" {
			return nil, &SessionResumptionError{
				SessionID: entry.ID(),
				Reason:    fmt.Sprintf("unexpected return code: %s", returnCode),
			}
		}
	}

	// Session resumed successfully, create negotiation result
	negotiation := &SecurityNegotiation{
		Command:      a.config.Command,
		ClientConfig: a.config,
		ServerConfig: &SecurityConfig{}, // Initialize to avoid nil pointer dereference
		IsClient:     true,
		SessionId:    entry.ID(),
	}

	// Restore session information from cached entry and mark as resumed
	if entry.KeyInfo() != nil {
		negotiation.setSharedSecret(entry.KeyInfo().Data)
		negotiation.NegotiatedCrypto = CryptoMethod(entry.KeyInfo().Protocol)
		negotiation.SessionResumed = true
		// The cached session carried an AES key, so it was encrypted; restore
		// that on the resumed negotiation (setupStreamEncryption re-applies the
		// key, but the flag must also be set so callers know the transport is
		// encrypted).
		negotiation.Encryption = isAESGCM(negotiation.NegotiatedCrypto)
		a.sessionResumed = true
	}

	if entry.Policy() != nil {
		if authMethod, ok := entry.Policy().EvaluateAttrString("AuthMethods"); ok {
			negotiation.NegotiatedAuth = AuthMethod(authMethod)
		}
		negotiation.SessionAttrs = sessionAttrsFromPolicy(entry.Policy(), a.config.WantSessionAttrs)
		// An unauthenticated session reports no method, whatever was recorded.
		negotiation.Authentication = clientSessionAuthenticated(entry)
		if !negotiation.Authentication {
			negotiation.NegotiatedAuth = AuthNone
		}
		// Restore our identity as the server knows it (see storeClientSession).
		// Imported sessions record only the peer's "User".
		if user, ok := entry.Policy().EvaluateAttrString("MyRemoteUserName"); ok {
			negotiation.User = user
		} else if user, ok := entry.Policy().EvaluateAttrString("User"); ok {
			negotiation.User = user
		}
		// Restore the peer (server) version so version-dependent logic works on
		// a resumed session (see storeClientSession).
		if rv, ok := entry.Policy().EvaluateAttrString("RemoteVersion"); ok {
			negotiation.ServerConfig.RemoteVersion = rv
		}
	}
	// A version in the reply is the peer's current one, as HTCondor takes it
	// (SecManStartCommand::receiveAuthInfo_inner). The exception is cedar's
	// own default when the session already recorded a version: cedar v0.7.9
	// servers sent the default in every resumption reply, whatever version
	// they were configured to advertise, and taking it would downgrade a
	// peer version that features such as CCB streaming are gated on.
	if rv, ok := responseAd.EvaluateAttrString("RemoteVersion"); ok && rv != "" {
		if rv != DefaultRemoteVersion || negotiation.ServerConfig.RemoteVersion == "" {
			negotiation.ServerConfig.RemoteVersion = rv
		}
	}

	// Renew the session lease
	entry.RenewLease()
	cache.Store(entry)

	// Set up encryption with cached key (only for session resumption)
	if len(negotiation.GetSharedSecret()) > 0 {
		if err := a.setupStreamEncryption(negotiation); err != nil {
			return nil, fmt.Errorf("failed to setup stream encryption: %w", err)
		}
	}

	return negotiation, nil
}

// negotiateSecurity performs security negotiation between client and server
func (a *Authenticator) negotiateSecurity(negotiation *SecurityNegotiation) error {
	// Find compatible authentication method - server preference order
	negotiation.NegotiatedAuth = AuthNone
	for _, serverAuth := range negotiation.ServerConfig.AuthMethods {
		for _, clientAuth := range negotiation.ClientConfig.AuthMethods {
			if wireAuthMethod(serverAuth) == wireAuthMethod(clientAuth) {
				negotiation.NegotiatedAuth = canonicalAuthMethod(serverAuth)
				break
			}
		}
		if negotiation.NegotiatedAuth != AuthNone {
			break
		}
	}

	// Find compatible crypto method - server preference order. Only a method
	// cedar can key (AES-GCM) is chosen, as HTCondor drops the methods its
	// build cannot do (SecMan::filterCryptoMethods): a BLOWFISH or 3DES
	// "agreement" would leave the session without the protection it reports.
	for _, serverCrypto := range negotiation.ServerConfig.CryptoMethods {
		if !isAESGCM(serverCrypto) {
			continue
		}
		for _, clientCrypto := range negotiation.ClientConfig.CryptoMethods {
			if canonicalCryptoMethod(serverCrypto) == canonicalCryptoMethod(clientCrypto) {
				negotiation.NegotiatedCrypto = canonicalCryptoMethod(serverCrypto)
				break
			}
		}
		if negotiation.NegotiatedCrypto != "" {
			break
		}
	}

	// Combine server and client authentication settings to determine if authentication should be performed
	serverAuth := negotiation.ServerConfig.Authentication
	clientAuth := negotiation.ClientConfig.Authentication

	// Check for incompatible authentication requirements. Reflect the server's
	// demand on the negotiation so a graceful-failure response advertises it.
	if serverAuth == SecurityRequired && clientAuth == SecurityNever {
		negotiation.Authentication = true
		return fmt.Errorf("authentication incompatibility: server requires authentication but client has it set to never")
	}
	if serverAuth == SecurityNever && clientAuth == SecurityRequired {
		return fmt.Errorf("authentication incompatibility: client requires authentication but server has it set to never")
	}

	// Determine if authentication should be performed based on combined settings
	slog.Debug(fmt.Sprintf("🔐 NEGOTIATION: Server auth: %s, Client auth: %s", serverAuth, clientAuth), "destination", "cedar")
	shouldAuthenticate := false
	switch {
	case serverAuth == SecurityRequired || clientAuth == SecurityRequired:
		// If either side requires authentication, it must be performed
		shouldAuthenticate = true
	case serverAuth == SecurityNever || clientAuth == SecurityNever:
		// If either side has authentication set to never, don't authenticate
		shouldAuthenticate = false
	case serverAuth == SecurityPreferred || clientAuth == SecurityPreferred:
		// If either side prefers authentication and we have compatible methods, authenticate
		shouldAuthenticate = (negotiation.NegotiatedAuth != AuthNone)
	case serverAuth == SecurityOptional && clientAuth == SecurityOptional:
		// Both sides are optional - authenticate if we have compatible methods
		shouldAuthenticate = false
	}

	// Determine if we need to encrypt the session based on combined client and server settings
	serverEncryption := negotiation.ServerConfig.Encryption
	clientEncryption := negotiation.ClientConfig.Encryption
	slog.Debug(fmt.Sprintf("🔐 NEGOTIATION: Server encryption: %s, Client encryption: %s", serverEncryption, clientEncryption), "destination", "cedar")

	var shouldEncrypt, shouldIntegrity bool
	if negotiation.IsClient {
		// The client reads the server's decisions back (Encryption and
		// Integrity are YES or NO); it only refines them with its own levels.
		shouldEncrypt = clientWantsEncryption(serverEncryption, clientEncryption, negotiation.NegotiatedCrypto)
		shouldIntegrity = clientWantsIntegrity(negotiation.ServerConfig.Integrity, negotiation.ClientConfig.Integrity, negotiation.NegotiatedCrypto)
		// AES-GCM encrypts and integrity-checks every frame, so an authenticated
		// AES session has enacted both regardless of how the levels reconciled.
		// The server records it the same way, so both ends agree.
		if shouldAuthenticate && negotiation.NegotiatedCrypto == CryptoAES {
			shouldEncrypt = true
			shouldIntegrity = true
		}
	} else {
		// The server decides, as DaemonCore does with
		// SecMan::ReconcileSecurityPolicyAds (condor_secman.cpp): each feature
		// from the client's and server's levels by ReconcileSecurityAttribute.
		encryption := reconcileSecurityAttribute(peerSecurityLevel(clientEncryption), ownSecurityLevel(serverEncryption))
		integrity := reconcileSecurityAttribute(peerSecurityLevel(negotiation.ClientConfig.Integrity), ownSecurityLevel(negotiation.ServerConfig.Integrity))
		// Reflect the server's demand on the negotiation so a graceful-failure
		// response advertises it.
		if encryption == featureFail {
			if ownSecurityLevel(serverEncryption) == SecurityRequired {
				negotiation.Encryption = true
				return fmt.Errorf("encryption incompatibility: server requires encryption but client has it set to %s", peerSecurityLevel(clientEncryption))
			}
			return fmt.Errorf("encryption incompatibility: client requires encryption but server has it set to never")
		}
		if integrity == featureFail {
			if ownSecurityLevel(negotiation.ServerConfig.Integrity) == SecurityRequired {
				negotiation.Integrity = true
				return fmt.Errorf("integrity incompatibility: server requires integrity but client has it set to %s", peerSecurityLevel(negotiation.ClientConfig.Integrity))
			}
			return fmt.Errorf("integrity incompatibility: client requires integrity but server has it set to never")
		}
		shouldEncrypt = encryption == featureYes
		shouldIntegrity = integrity == featureYes
		// AES-GCM always encrypts and integrity-checks the stream, so when the
		// session authenticates and AES is the method, HTCondor reports both on
		// whatever the levels reconciled to (ReconcileSecurityPolicyAds). A C++
		// peer caches the session's policy from this response.
		if shouldAuthenticate && negotiation.NegotiatedCrypto == CryptoAES {
			shouldEncrypt = true
			shouldIntegrity = true
		}
	}

	// Record the intended outcome on the negotiation BEFORE the compatibility
	// checks below, so that if one fails the negotiation still reflects the level
	// the server was demanding. The server's graceful-failure response is built
	// from these fields (see sendNegotiationFailureResponse): advertising
	// Authentication/Encryption = "YES" with an empty negotiated method is exactly
	// what makes a peer report a specific policy error (e.g. HTCondor's "requires
	// encryption but provided no crypto method") instead of a bare closed socket.
	negotiation.Enact = shouldAuthenticate || shouldEncrypt || shouldIntegrity
	negotiation.Authentication = shouldAuthenticate
	negotiation.Encryption = shouldEncrypt
	negotiation.Integrity = shouldIntegrity

	// If encryption or integrity is required but no compatible method was found, return error
	if (shouldEncrypt || shouldIntegrity) && negotiation.NegotiatedCrypto == "" {
		return fmt.Errorf("encryption required but no compatible encryption methods found between client (%v) and server (%v)",
			negotiation.ClientConfig.CryptoMethods, negotiation.ServerConfig.CryptoMethods)
	}

	// If authentication is required but no compatible method was found, return error
	if shouldAuthenticate && negotiation.NegotiatedAuth == AuthNone {
		return fmt.Errorf("authentication required but no compatible authentication methods found between client (%v) and server (%v)",
			negotiation.ClientConfig.AuthMethods, negotiation.ServerConfig.AuthMethods)
	}

	return nil
}

// clientWantsEncryption is the client's encryption decision from the server's
// reply (serverEncryption is its YES or NO) and the client's own level.
func clientWantsEncryption(serverEncryption, clientEncryption SecurityLevel, negotiatedCrypto CryptoMethod) bool {
	switch {
	case serverEncryption == SecurityRequired || clientEncryption == SecurityRequired:
		return true
	case serverEncryption == SecurityNever || clientEncryption == SecurityNever:
		return false
	case serverEncryption == SecurityPreferred || clientEncryption == SecurityPreferred:
		return negotiatedCrypto != ""
	}
	return false
}

// clientWantsIntegrity is the integrity twin of clientWantsEncryption, and
// keeps its shape: either side requiring it settles it, either side refusing it
// settles it, and a preference needs a negotiated method. Note that a server
// reply carries a decision ("YES"/"NO"), not a level, so in practice it is the
// client's own level that decides here; the server's declaration is enforced
// separately where requireEnactedKey is called.
func clientWantsIntegrity(serverIntegrity, clientIntegrity SecurityLevel, negotiatedCrypto CryptoMethod) bool {
	switch {
	case serverIntegrity == SecurityRequired || clientIntegrity == SecurityRequired:
		return true
	case serverIntegrity == SecurityNever || clientIntegrity == SecurityNever:
		return false
	case serverIntegrity == SecurityPreferred || clientIntegrity == SecurityPreferred:
		return negotiatedCrypto != ""
	}
	return false
}

// Helper functions for parsing method lists
func parseMethodsList(methods string) []AuthMethod {
	if methods == "" {
		return nil
	}

	var result []AuthMethod
	for _, method := range splitCommaList(methods) {
		result = append(result, canonicalAuthMethod(AuthMethod(method)))
	}
	return result
}

func parseCryptoMethodsList(methods string) []CryptoMethod {
	if methods == "" {
		return nil
	}

	var result []CryptoMethod
	for _, method := range splitCommaList(methods) {
		result = append(result, canonicalCryptoMethod(CryptoMethod(method)))
	}
	return result
}

// parseIssuerKeysList parses a comma and/or space separated list of key IDs (kid values)
// that the server accepts for token authentication
func parseIssuerKeysList(keys string) []string {
	if keys == "" {
		return nil
	}

	var result []string
	// Split by both comma and space to handle formats like "key1,key2" or "key1 key2" or "key1, key2"
	for _, item := range strings.FieldsFunc(keys, func(r rune) bool {
		return r == ',' || r == ' '
	}) {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func splitCommaList(s string) []string {
	if s == "" {
		return nil
	}

	var result []string
	for _, item := range strings.Split(s, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// setupStreamEncryption configures AES-GCM encryption on the stream using ECDH-derived keys
func (a *Authenticator) setupStreamEncryption(negotiation *SecurityNegotiation) error {
	slog.Debug("🔐 CRYPTO: Setting up stream encryption...", "destination", "cedar")
	slog.Debug(fmt.Sprintf("    Negotiated crypto: %s", negotiation.NegotiatedCrypto), "destination", "cedar")
	slog.Debug(fmt.Sprintf("    Existing shared secret: %t (%d bytes)", len(negotiation.GetSharedSecret()) > 0, len(negotiation.GetSharedSecret())), "destination", "cedar")

	// If we have a shared secret from session resumption, set it on the stream.
	// Accept both "AES" and "AESGCM" as the crypto name: they denote the same
	// AES-256-GCM cipher, but inherited/family sessions record "AESGCM" while a
	// freshly-negotiated session records "AES". Without this, a resumed family
	// session's key is never applied and encrypted payloads read as garbage.
	if len(negotiation.GetSharedSecret()) > 0 && isAESGCM(negotiation.NegotiatedCrypto) && negotiation.SessionResumed {
		// Set the symmetric key on the stream for encryption
		err := a.stream.SetSymmetricKey(negotiation.GetSharedSecret())
		if err != nil {
			return fmt.Errorf("failed to set symmetric key on stream: %w", err)
		}
		// The stream is now encrypting. Reconcile the negotiated outcome with reality so
		// downstream consumers (post-auth advertisement, session cache, and the server's
		// per-command security-level check) see that the session IS encrypted. See the
		// ECDH path below for why this matters under OPTIONAL encryption.
		negotiation.Encryption = a.stream.IsEncrypted()
		slog.Debug("✅ CRYPTO: Stream encryption enabled with AES-256-GCM (from cached session)", "destination", "cedar")
		return nil
	}

	// Check if we have ECDH public keys to derive a shared secret. Both configs
	// may be nil on the server side of a resumed session (no fresh ECDH), so
	// guard both before dereferencing.
	clientKey := ""
	if negotiation.ClientConfig != nil {
		clientKey = negotiation.ClientConfig.ECDHPublicKey
	}
	serverKey := ""
	if negotiation.ServerConfig != nil {
		serverKey = negotiation.ServerConfig.ECDHPublicKey
	}

	slog.Debug(fmt.Sprintf("    Client has ECDH key: %t", clientKey != ""), "destination", "cedar")
	slog.Debug(fmt.Sprintf("    Server has ECDH key: %t", serverKey != ""), "destination", "cedar")

	if clientKey != "" && serverKey != "" && negotiation.NegotiatedCrypto == CryptoAES {
		slog.Debug("🔐 CRYPTO: Performing ECDH key exchange...", "destination", "cedar")
		// Parse the peer's public key and perform ECDH key exchange
		sharedSecret, err := a.performECDHKeyExchange(clientKey, serverKey, negotiation.IsClient)
		if err != nil {
			// If ECDH fails, log but don't fail the entire handshake
			// This allows tests with placeholder keys to work
			slog.Debug(fmt.Sprintf("⚠️  CRYPTO: ECDH key exchange failed (continuing without encryption): %v", err), "destination", "cedar")
			return nil
		}

		slog.Debug("🔐 CRYPTO: ECDH successful, deriving AES key...", "destination", "cedar")
		// Derive AES-256-GCM key from shared secret using HKDF
		derivedKey, err := a.deriveAESKey(sharedSecret)
		if err != nil {
			return fmt.Errorf("key derivation failed: %w", err)
		}
		slog.Debug(fmt.Sprintf("🔐 CRYPTO: AES key derived, length: %d bytes", len(derivedKey)), "destination", "cedar")

		// Store the derived key for session caching (not for stream encryption yet)
		negotiation.setSharedSecret(derivedKey)

		slog.Debug("🔐 CRYPTO: Setting symmetric key on stream...", "destination", "cedar")
		// Set the symmetric key on the stream for encryption
		err = a.stream.SetSymmetricKey(derivedKey)
		if err != nil {
			return fmt.Errorf("failed to set symmetric key on stream: %w", err)
		}

		// Reconcile the negotiated outcome with reality: ECDH succeeded and the stream is
		// now AES-GCM encrypted, so record Encryption=true even though the negotiated
		// *level* was only OPTIONAL/PREFERRED (which left negotiation.Encryption=false at
		// the decision stage). Without this, a session that is genuinely encrypted still
		// reports Encryption=false, and a server enforcing a required encryption/integrity
		// level for a command (SEC_*_INTEGRITY=REQUIRED with AES-GCM authenticated
		// encryption) wrongly rejects it -- the bug that made SEC_DEFAULT_ENCRYPTION=OPTIONAL
		// unusable for request/response commands.
		negotiation.Encryption = a.stream.IsEncrypted()

		slog.Debug("✅ CRYPTO: Stream encryption enabled with AES-256-GCM", "destination", "cedar")
		return nil
	}

	slog.Debug("ℹ️  CRYPTO: No encryption configured", "destination", "cedar")
	// If no ECDH keys are available, encryption is not enabled
	// A plaintext session never installs an encryption key, so it would otherwise
	// keep running its handshake digest over every application frame for a value it
	// never uses (an encrypted session freezes the digest when the key is installed).
	// Freeze it now so the application phase -- e.g. a large collector query stream --
	// skips the per-frame SHA256. Idempotent on an already-frozen (resumed) session.
	a.stream.FinalizeDigests()
	return nil
}

// requireEnactedKey fails a handshake that enacted encryption or integrity
// but did not key the stream, as HTCondor does (DaemonCommandProtocol::
// EnableCrypto on the server, SecManStartCommand::authenticate_inner_finish on
// the client), rather than carrying the session's traffic in the clear.
func (a *Authenticator) requireEnactedKey(encryption, integrity bool) error {
	if (encryption || integrity) && !a.stream.IsEncrypted() {
		return fmt.Errorf("session enacted encryption=%t integrity=%t but no session key was established", encryption, integrity)
	}
	return nil
}

// performECDHKeyExchange performs ECDH key exchange using P-256 curve
func (a *Authenticator) performECDHKeyExchange(clientKeyB64, serverKeyB64 string, isClient bool) ([]byte, error) {
	// Determine which key is ours and which is the peer's
	var peerKeyB64 string
	if isClient {
		peerKeyB64 = serverKeyB64
	} else {
		peerKeyB64 = clientKeyB64
	}

	// Decode the peer's base64-encoded public key
	peerKeyBytes, err := base64.StdEncoding.DecodeString(peerKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode peer public key: %w", err)
	}

	var peerECDHKey *ecdh.PublicKey

	// Try to parse as raw ECDH format first (65 bytes starting with 0x04)
	if len(peerKeyBytes) == 65 && peerKeyBytes[0] == 0x04 {
		// Raw uncompressed P-256 public key format
		peerECDHKey, err = ecdh.P256().NewPublicKey(peerKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse raw ECDH public key: %w", err)
		}
	} else {
		// Try to parse as DER-encoded public key
		peerPubKey, err := x509.ParsePKIXPublicKey(peerKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DER public key: %w", err)
		}

		// Ensure it's an ECDSA public key on P-256
		ecdsaPubKey, ok := peerPubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("peer key is not an ECDSA public key")
		}

		if ecdsaPubKey.Curve != elliptic.P256() {
			return nil, fmt.Errorf("peer key is not on P-256 curve")
		}

		// Convert ECDSA public key to ECDH public key
		peerECDHKey, err = ecdsaPubKey.ECDH()
		if err != nil {
			return nil, fmt.Errorf("failed to convert peer key to ECDH: %w", err)
		}
	}

	// Use our stored ECDH private key
	if a.ecdhPrivKey == nil {
		return nil, fmt.Errorf("no ECDH private key available")
	}
	ourPrivateKey := a.ecdhPrivKey

	// Perform ECDH to compute shared secret
	sharedSecret, err := ourPrivateKey.ECDH(peerECDHKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation failed: %w", err)
	}

	return sharedSecret, nil
}

// deriveAESKey derives an AES-256-GCM key from the ECDH shared secret using HKDF
// This matches HTCondor's implementation with "htcondor" salt and "keygen" info
func (a *Authenticator) deriveAESKey(sharedSecret []byte) ([]byte, error) {
	// HTCondor uses HKDF with SHA-256, "htcondor" as salt, and "keygen" as info
	salt := []byte("htcondor")
	info := []byte("keygen")

	// Create HKDF reader
	hkdf := hkdf.New(sha256.New, sharedSecret, salt, info)

	// Derive 32 bytes for AES-256
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}

	return derivedKey, nil
}

// authMethodToBitmask converts an AuthMethod to its bitmask value
func authMethodToBitmask(method AuthMethod) int {
	switch canonicalAuthMethod(method) {
	case AuthNone:
		return AuthBitmaskNone
	case AuthClaimToBe:
		return AuthBitmaskClaimToBe
	case AuthFS:
		return AuthBitmaskFS
	case AuthKerberos:
		return AuthBitmaskKerberos
	case AuthPassword:
		return AuthBitmaskPassword
	case AuthSSL:
		return AuthBitmaskSSL
	case AuthToken:
		return AuthBitmaskToken
	case AuthSciTokens:
		return AuthBitmaskSciTokens
	case AuthIDTokens:
		// HTCondor's SecMan::sec_char_to_auth_method maps IDTOKENS (and
		// IDTOKEN, TOKENS) to CAUTH_TOKEN: it is the same method.
		return AuthBitmaskToken
	default:
		return 0
	}
}

// wireAuthMethod returns the name HTCondor uses for method in negotiation ads,
// for comparing method names. HTCondor treats IDTOKENS, IDTOKEN and TOKENS as
// TOKEN and sends TOKEN on the wire (SecMan::filterAuthenticationMethods); a C++
// peer does not recognize a client that offers IDTOKENS.
func wireAuthMethod(method AuthMethod) AuthMethod {
	method = canonicalAuthMethod(method)
	switch method {
	case AuthIDTokens, "IDTOKEN", "TOKENS":
		return AuthToken
	default:
		return method
	}
}

// wireAuthMethodList joins methods by their wire names, dropping repeats (a
// config listing both TOKEN and IDTOKENS offers TOKEN once).
func wireAuthMethodList(methods []AuthMethod) string {
	names := make([]string, 0, len(methods))
	for _, m := range methods {
		name := string(wireAuthMethod(m))
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return strings.Join(names, ",")
}

// methodForBitmask returns the first of methods whose bit is bitmask, falling
// back to bitmaskToAuthMethod when none is.
func methodForBitmask(methods []AuthMethod, bitmask int) AuthMethod {
	for _, m := range methods {
		if authMethodToBitmask(m) == bitmask {
			return m
		}
	}
	return bitmaskToAuthMethod(bitmask)
}

// bitmaskToAuthMethod converts a bitmask value to an AuthMethod
func bitmaskToAuthMethod(bitmask int) AuthMethod {
	switch bitmask {
	case AuthBitmaskNone:
		return AuthNone
	case AuthBitmaskClaimToBe:
		return AuthClaimToBe
	case AuthBitmaskFS:
		return AuthFS
	case AuthBitmaskKerberos:
		return AuthKerberos
	case AuthBitmaskPassword:
		return AuthPassword
	case AuthBitmaskSSL:
		return AuthSSL
	case AuthBitmaskToken:
		return AuthToken
	case AuthBitmaskSciTokens:
		return AuthSciTokens
	default:
		return ""
	}
}

// isTokenMethod checks if an authentication method is a token-based method
func isTokenMethod(method AuthMethod) bool {
	method = canonicalAuthMethod(method)
	return method == AuthToken || method == AuthSciTokens || method == AuthIDTokens
}

// createClientAuthBitmask creates a bitmask of authentication methods the client supports
func createClientAuthBitmask(methods []AuthMethod) int {
	bitmask := 0
	for _, method := range methods {
		bitmask |= authMethodToBitmask(method)
	}
	return bitmask
}

// performSSLAuthentication performs SSL certificate-based authentication
func (a *Authenticator) performSSLAuthentication(ctx context.Context, negotiation *SecurityNegotiation) error {
	slog.Debug("🔐 SSL: Starting SSL authentication...", "destination", "cedar")

	// Create SSL authenticator
	sslAuth := NewSSLAuthenticator(a)
	defer sslAuth.close()

	// Perform SSL handshake following HTCondor's protocol
	err := sslAuth.PerformSSLHandshake(ctx, negotiation)
	if err != nil {
		return fmt.Errorf("SSL authentication failed: %w", err)
	}

	if !negotiation.IsClient && sslAuth.tlsConn != nil {
		negotiation.User = sslPeerFQU(sslAuth.tlsConn.ConnectionState())
	}

	slog.Debug("✅ SSL: SSL authentication completed successfully", "destination", "cedar")
	return nil
}

// sslPeerFQU returns the FQU C++ gives an SSL client before any map file
// (Condor_Auth_SSL::authenticate_finish): ssl@unmapped for a client that
// presented a certificate, unauthenticated@unmapped for one that did not.
func sslPeerFQU(state tls.ConnectionState) string {
	if len(state.PeerCertificates) > 0 {
		return joinFQU("ssl", UnmappedDomain)
	}
	return joinFQU("unauthenticated", UnmappedDomain)
}

// performSciTokenAuthentication performs SCITOKENS authentication (SSL + SciToken exchange)
func (a *Authenticator) performSciTokenAuthentication(ctx context.Context, negotiation *SecurityNegotiation) error {
	slog.Debug("🔐 SCITOKENS: Starting SCITOKENS authentication...", "destination", "cedar")

	// Create SSL authenticator
	sslAuth := NewSSLAuthenticator(a)
	sslAuth.sciTokensMode = true
	defer sslAuth.close()

	// The client finds its token first, as C++ does: without one it reports
	// failure in the initial SSL status exchange rather than leaving the
	// server waiting for a token that never comes.
	var tokenStr string
	if negotiation.IsClient {
		var err error
		tokenStr, err = a.discoverSciToken(negotiation.ClientConfig)
		if err != nil {
			return sslAuth.signalSetupFailure(ctx, negotiation, fmt.Errorf("failed to discover SciToken: %w", err))
		}
	}

	// Perform SSL handshake first
	err := sslAuth.PerformSSLHandshake(ctx, negotiation)
	if err != nil {
		return fmt.Errorf("SSL handshake failed during SCITOKENS authentication: %w", err)
	}

	// Now exchange SciToken over the established TLS connection
	if negotiation.IsClient {
		_, err = sslAuth.exchangeSciToken(ctx, negotiation, tokenStr)
		if err != nil {
			return fmt.Errorf("SciToken exchange failed: %w", err)
		}

		slog.Debug("✅ SCITOKENS: Client successfully sent SciToken", "destination", "cedar")
	} else {
		// Server: receive and verify SciToken
		authenticatedUser, err := sslAuth.exchangeSciToken(ctx, negotiation, "")
		if err != nil {
			return fmt.Errorf("SciToken verification failed: %w", err)
		}

		// C++ refuses a SciToken whose "issuer,subject" the map file does not
		// map, and otherwise authenticates the peer as the mapped user
		// (condor_auth_ssl.cpp, authentication.cpp).
		slog.Debug("✅ SCITOKENS: Server authenticated user", "user", authenticatedUser, "destination", "cedar")
		negotiation.User = authenticatedUser
	}

	slog.Debug("✅ SCITOKENS: SCITOKENS authentication completed successfully", "destination", "cedar")
	return nil
}

// discoverSciToken discovers a SciToken from the configured sources
func (a *Authenticator) discoverSciToken(config *SecurityConfig) (string, error) {
	// Try config.Token first if specified directly
	if config.Token != "" {
		if IsSciToken(config.Token) {
			return config.Token, nil
		}
	}

	// A credential held on somebody else's behalf has one source, and
	// it is not a file on this host. Guarded here rather than at each
	// caller, so a caller added later inherits it.
	if config.DelegatedCredential {
		return "", &DelegatedCredentialError{Reason: "no delegated SciToken to present"}
	}

	// Try TokenFile next
	if config.TokenFile != "" {
		tokenStr, err := a.findSciTokenInFile(config.TokenFile)
		if err == nil {
			return tokenStr, nil
		}
	}

	// Try TokenDir
	if config.TokenDir != "" {
		tokenPaths := a.scanTokenDirectory(config.TokenDir)
		for _, tokenPath := range tokenPaths {
			tokenStr, err := a.findSciTokenInFile(tokenPath)
			if err == nil {
				return tokenStr, nil
			}
		}
	}

	return "", fmt.Errorf("no SciToken found (check Token, TokenFile, or TokenDir configuration)")
}

// findSciTokenInFile reads a token file and returns the first SciToken found
func (a *Authenticator) findSciTokenInFile(tokenPath string) (string, error) {
	// Read token file
	tokenData, err := a.config.readCredential(tokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read token file %s: %w", tokenPath, err)
	}

	// Process file line by line
	lines := strings.Split(string(tokenData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if this is a SciToken
		if IsSciToken(line) {
			return line, nil
		}
	}

	return "", fmt.Errorf("no SciToken found in %s", tokenPath)
}

// performPasswordAuthentication performs password-based authentication
func (a *Authenticator) performPasswordAuthentication(ctx context.Context, negotiation *SecurityNegotiation) error {
	// TODO: Implement password authentication
	return fmt.Errorf("password authentication not yet implemented")
}

// performKerberosAuthentication performs Kerberos-based authentication,
// wire-compatible with HTCondor's condor_auth_kerberos (see kerberos_auth.go).
func (a *Authenticator) performKerberosAuthentication(ctx context.Context, negotiation *SecurityNegotiation) error {
	if negotiation.IsClient {
		return a.kerberosClient(ctx, negotiation)
	}
	return a.kerberosServer(ctx, negotiation)
}

// eitherSideRequiresAuth reports whether enacted authentication must succeed
// for the connection to proceed: true when EITHER side's policy is REQUIRED.
// This is the `required` result of condor_secman.cpp
// ReconcileSecurityAttribute, which ReconcileSecurityPolicyAds records as
// ATTR_SEC_AUTH_REQUIRED (omitted, meaning true, unless neither side requires
// it) and which both ends consult when authentication fails. own is this end's
// configured level; peer is the other end's parsed config (may be nil).
func eitherSideRequiresAuth(own SecurityLevel, peer *SecurityConfig) bool {
	return own == SecurityRequired || (peer != nil && peer.Authentication == SecurityRequired)
}

// mayProceedUnauthenticated reports whether a client whose enacted auth
// methods all failed may still proceed with an unauthenticated session --
// matching condor_secman.cpp authenticate_inner, which continues (rather than
// aborting the command) when authentication fails but was not required. That
// needs the server to have signalled ATTR_SEC_AUTH_REQUIRED = false AND this
// client's own policy not to be REQUIRED: the server's flag never overrides
// the client's REQUIRED (a C++ server folds the client's level into the flag;
// a server that does not must not be able to downgrade the client).
func (a *Authenticator) mayProceedUnauthenticated(negotiation *SecurityNegotiation) bool {
	if eitherSideRequiresAuth(a.config.Authentication, negotiation.ServerConfig) {
		return false
	}
	return negotiation.ServerConfig != nil &&
		negotiation.ServerConfig.AuthRequired != nil &&
		!*negotiation.ServerConfig.AuthRequired
}

// clientRequiredAuthError annotates a client-side authentication failure
// with the client's own REQUIRED policy, which is why there was no
// unauthenticated fallback.
func (a *Authenticator) clientRequiredAuthError(err error) error {
	if a.config.Authentication == SecurityRequired {
		return fmt.Errorf("authentication is required by client policy and did not succeed: %w", err)
	}
	return err
}

// handleClientAuthentication performs the client-side authentication handshake
func (a *Authenticator) handleClientAuthentication(ctx context.Context, negotiation *SecurityNegotiation) error {
	// Check if authentication is required based on server's Authentication response
	authRequired := negotiation.ServerConfig.Authentication == "YES"

	// The server config Authentication field should have been set from server's ClassAd
	// Check if it's "YES" or if the negotiated auth method is not NONE

	if !authRequired {
		// A server reconciling with a REQUIRED client enacts authentication
		// or rejects the negotiation; it never answers NO. Proceeding
		// would leave a REQUIRED client unauthenticated.
		if a.config.Authentication == SecurityRequired {
			return a.clientRequiredAuthError(fmt.Errorf("server did not enact authentication (Authentication=%q)",
				negotiation.ServerConfig.Authentication))
		}
		slog.Debug("🔐 CLIENT: No authentication required", "destination", "cedar")
		return nil
	}

	slog.Debug("🔐 CLIENT: Authentication required, starting handshake...", "destination", "cedar")

	// Get available authentication methods from server's negotiated auth methods
	availableMethods := negotiation.ServerConfig.AuthMethods
	if len(availableMethods) == 0 {
		return fmt.Errorf("server requires authentication but provides no methods")
	}

	// Create bitmask of methods we support that the server also supports
	clientMethods := []AuthMethod{}
	for _, clientMethod := range a.config.AuthMethods {
		for _, serverMethod := range availableMethods {
			if wireAuthMethod(clientMethod) == wireAuthMethod(serverMethod) {
				// For TOKEN authentication, check if we have compatible tokens
				// Only offer TOKEN if we have at least one token that matches
				// the server's TrustDomain and IssuerKeys requirements
				if isTokenMethod(clientMethod) {
					if !a.hasCompatibleToken(negotiation.ClientConfig, negotiation.ServerConfig) {
						slog.Info(fmt.Sprintf("🔐 CLIENT: Skipping %s - no compatible tokens available; %s",
							clientMethod, a.tokenSearchSummary(negotiation.ClientConfig, negotiation.ServerConfig)), "destination", "cedar")
						continue
					}
				}
				clientMethods = append(clientMethods, canonicalAuthMethod(clientMethod))
				break
			}
		}
	}

	if len(clientMethods) == 0 {
		// Surface enough context for the operator to figure out *why* nothing
		// matched. Without these lists, the only way to debug is to enable
		// debug logging and replay the connection — far too much friction
		// for a routine misconfiguration. We log the same fields cedar's
		// negotiateSecurity error at line ~1182 includes, plus a hint about
		// the most common cause (token filtering by trust domain / IssuerKeys).
		serverMethodStrings := make([]string, 0, len(availableMethods))
		for _, m := range availableMethods {
			serverMethodStrings = append(serverMethodStrings, string(m))
		}
		clientMethodStrings := make([]string, 0, len(a.config.AuthMethods))
		for _, m := range a.config.AuthMethods {
			clientMethodStrings = append(clientMethodStrings, string(m))
		}
		// No method in common, but if authentication is optional on both sides
		// we may still proceed unauthenticated. Tell the server we have nothing
		// to offer (0 bitmask), then continue, rather than failing the command.
		if a.mayProceedUnauthenticated(negotiation) {
			giveUp := message.NewMessageForStream(a.stream)
			if err := giveUp.PutInt(ctx, 0); err == nil {
				_ = giveUp.FinishMessage(ctx)
			}
			negotiation.Authentication = false
			negotiation.NegotiatedAuth = AuthNone
			slog.Info("🔐 CLIENT: no compatible auth methods, but authentication was not required; continuing unauthenticated", "destination", "cedar")
			return nil
		}
		return a.clientRequiredAuthError(fmt.Errorf(
			"no compatible authentication methods found: client offered %v, server offered %v "+
				"(if methods overlap, all matching token methods were filtered out — check that the client's tokens "+
				"have iss matching server TrustDomain=%q and kid in IssuerKeys=%v)",
			clientMethodStrings, serverMethodStrings,
			negotiation.ServerConfig.TrustDomain, negotiation.ServerConfig.IssuerKeys))
	}

	// Create bitmask of all supported authentication methods
	availableBitmask := createClientAuthBitmask(clientMethods)
	slog.Debug(fmt.Sprintf("🔐 CLIENT: Available auth methods bitmask: 0x%x", availableBitmask), "destination", "cedar")

	// Accumulate per-method failures so the caller can see *why* each
	// method was eliminated, not just "all methods failed". Sized to
	// the number of bits in availableBitmask as a generous upper bound.
	var attempts []AuthMethodAttempt

	// Iterate until we succeed or run out of methods
	for availableBitmask != 0 {
		// Send current bitmask to server
		authMsg := message.NewMessageForStream(a.stream)
		if err := authMsg.PutInt(ctx, availableBitmask); err != nil {
			return fmt.Errorf("failed to send auth method bitmask: %w", err)
		}
		if err := authMsg.FinishMessage(ctx); err != nil {
			return fmt.Errorf("failed to send auth method message: %w", err)
		}
		slog.Debug(fmt.Sprintf("🔐 CLIENT: Sent auth bitmask: 0x%x", availableBitmask), "destination", "cedar")

		// Receive server response
		responseMsg := message.NewMessageFromStream(a.stream)
		serverResponse, err := responseMsg.GetInt(ctx)
		if err != nil {
			return fmt.Errorf("failed to receive server auth response: %w", err)
		}
		slog.Debug(fmt.Sprintf("🔐 CLIENT: Server selected method bitmask: 0x%x", serverResponse), "destination", "cedar")

		// Check if server rejected all methods (sent back 0)
		if serverResponse == 0 {
			slog.Debug("🔐 CLIENT: Server rejected all remaining methods", "destination", "cedar")
			break
		}

		// Convert server response to method, naming it as we configured it
		// (TOKEN and IDTOKENS share one bit).
		selectedMethod := methodForBitmask(clientMethods, serverResponse)
		if selectedMethod == "" {
			slog.Debug(fmt.Sprintf("🔐 CLIENT: Invalid method bitmask from server: 0x%x", serverResponse), "destination", "cedar")
			// Remove this invalid method and continue
			availableBitmask &= ^serverResponse
			continue
		}

		slog.Debug(fmt.Sprintf("🔐 CLIENT: Attempting authentication method: %s", selectedMethod), "destination", "cedar")

		// Perform the specific authentication method
		err = a.performAuthentication(ctx, selectedMethod, negotiation)
		if err != nil {
			slog.Debug(fmt.Sprintf("🔐 CLIENT: Authentication method %s failed: %v", selectedMethod, err), "destination", "cedar")
			attempts = append(attempts, AuthMethodAttempt{Method: selectedMethod, Err: err})
			// Remove this failed method from available bitmask and try again
			failedBitmask := authMethodToBitmask(selectedMethod)
			availableBitmask &= ^failedBitmask
			slog.Debug(fmt.Sprintf("🔐 CLIENT: Removed failed method %s, remaining bitmask: 0x%x", selectedMethod, availableBitmask), "destination", "cedar")
			continue
		}

		slog.Debug(fmt.Sprintf("✅ CLIENT: Authentication successful with method: %s", selectedMethod), "destination", "cedar")
		negotiation.NegotiatedAuth = selectedMethod

		// After successful authentication, perform key exchange as in HTCondor's Authentication::exchangeKey
		// For modern HTCondor with AESGCM crypto, the server always sends an empty key
		if err := a.exchangeKey(ctx, negotiation); err != nil {
			return fmt.Errorf("key exchange failed: %w", err)
		}

		return nil
	}

	// Send final 0 bitmask to tell server we're giving up
	if availableBitmask == 0 {
		slog.Debug("🔐 CLIENT: Sending final 0 bitmask to server (no methods left)", "destination", "cedar")
		authMsg := message.NewMessageForStream(a.stream)
		if err := authMsg.PutInt(ctx, 0); err != nil {
			slog.Debug(fmt.Sprintf("⚠️  CLIENT: Failed to send final 0 bitmask: %v", err), "destination", "cedar")
		} else if err := authMsg.FinishMessage(ctx); err != nil {
			slog.Debug(fmt.Sprintf("⚠️  CLIENT: Failed to send final 0 bitmask message: %v", err), "destination", "cedar")
		}
	}

	// Every enacted method failed. If the server marked authentication optional
	// (AuthRequired=false) and this client does not require it, proceed with an
	// unauthenticated session rather than failing the command -- the final 0
	// bitmask above told the server we gave up, and it will serve the command
	// unauthenticated (matching condor_status).
	if a.mayProceedUnauthenticated(negotiation) {
		negotiation.Authentication = false
		negotiation.NegotiatedAuth = AuthNone
		slog.Info("🔐 CLIENT: authentication failed but was not required by the server; continuing unauthenticated", "destination", "cedar")
		return nil
	}

	return a.clientRequiredAuthError(&AuthMethodsExhaustedError{Attempts: attempts})
}

// serverNegotiationConfig returns the server's SecurityConfig for a handshake,
// with SSL/SCITOKENS removed when a certificate is configured but unreadable (see
// serverOfferedAuthMethods). a.config is shared across connections, so when the
// method set changes this returns a shallow copy rather than mutating it.
func (a *Authenticator) serverNegotiationConfig() *SecurityConfig {
	usable := a.serverOfferedAuthMethods()
	if len(usable) == len(a.config.AuthMethods) {
		return a.config
	}
	cfg := *a.config
	cfg.AuthMethods = usable
	return &cfg
}

// serverOfferedAuthMethods returns the server's configured auth methods, dropping
// SSL/SCITOKENS when a certificate location IS configured (CertFile/KeyFile
// non-empty) but no candidate cert/key pair is readable. Such a server cannot
// perform a TLS handshake, so advertising or selecting a TLS method would only
// make the peer choose one that fails -- or, before the SSL status exchange,
// hang. Mirrors how the client filters TOKEN it cannot satisfy before offering
// it. Only file readability is checked here; the certificate is not parsed (a
// present-but-malformed cert is caught later in the handshake). An empty cert
// config is left untouched -- that path fails cleanly rather than hanging.
func (a *Authenticator) serverOfferedAuthMethods() []AuthMethod {
	methods := a.config.AuthMethods
	hasTLS := false
	for _, m := range methods {
		if m := canonicalAuthMethod(m); m == AuthSSL || m == AuthSciTokens {
			hasTLS = true
			break
		}
	}
	if !hasTLS {
		return methods
	}
	if a.config.CertFile == "" && a.config.KeyFile == "" {
		return methods
	}
	if a.serverHasReadableCertKey() {
		return methods
	}
	filtered := make([]AuthMethod, 0, len(methods))
	for _, m := range methods {
		if m := canonicalAuthMethod(m); m == AuthSSL || m == AuthSciTokens {
			continue
		}
		filtered = append(filtered, m)
	}
	slog.Info("🔐 SERVER: configured TLS certificate/key is unreadable; not offering SSL/SCITOKENS", "destination", "cedar")
	return filtered
}

// serverHasReadableCertKey reports whether at least one CertFile/KeyFile candidate
// pair is readable. CertFile/KeyFile are comma-separated candidate lists (like
// HTCondor); the pair is tried index-wise. Readability is checked via
// readCredential (which honors the root-elevation path); the certificate is not
// parsed.
func (a *Authenticator) serverHasReadableCertKey() bool {
	certPaths := splitCommaList(a.config.CertFile)
	keyPaths := splitCommaList(a.config.KeyFile)
	n := len(certPaths)
	if len(keyPaths) < n {
		n = len(keyPaths)
	}
	for i := 0; i < n; i++ {
		if _, err := a.config.readCredential(certPaths[i]); err != nil {
			continue
		}
		if _, err := a.config.readCredential(keyPaths[i]); err != nil {
			continue
		}
		return true
	}
	return false
}

// handleServerAuthentication performs the server-side authentication handshake
func (a *Authenticator) handleServerAuthentication(ctx context.Context, negotiation *SecurityNegotiation) error {
	// Check if authentication is required based on our negotiated auth method
	if !negotiation.Authentication {
		slog.Info("🔐 SERVER: No authentication required", "destination", "cedar")
		return nil
	}

	slog.Info("🔐 SERVER: Authentication required, waiting for client method selection...", "destination", "cedar")

	// Keep handling client authentication attempts until one succeeds
	for {
		// Wait for client to send authentication method bitmask
		authMsg := message.NewMessageFromStream(a.stream)
		clientBitmask, err := authMsg.GetInt(ctx)
		if err != nil {
			return fmt.Errorf("failed to receive client auth method bitmask: %w", err)
		}

		slog.Info(fmt.Sprintf("🔐 SERVER: Client sent auth bitmask: 0x%x", clientBitmask), "destination", "cedar")

		// If client sends 0, they've given up. Whether that ends the command
		// depends on both sides' policies, exactly as createServerSecurityAd
		// decided when it advertised AuthRequired: a server that only PREFERS
		// auth told an OPTIONAL/PREFERRED client (AuthRequired=false) it may
		// proceed unauthenticated, so we must honor that here and serve the
		// command with an anonymous session rather than dropping the socket.
		// Erroring instead leaves the client -- which already fell through to
		// reading the post-auth ClassAd via its mayProceedUnauthenticated
		// fallback -- staring at a closed connection and reporting a bare EOF.
		// Give-up is fatal when either side is REQUIRED (daemon_command.cpp
		// consults the reconciled ATTR_SEC_AUTH_REQUIRED). This is the server
		// half of that client fallback; without it the AuthRequired=false
		// advertisement is a promise the server breaks.
		if clientBitmask == 0 {
			if !eitherSideRequiresAuth(a.config.Authentication, negotiation.ClientConfig) {
				// Record the session as what it actually is -- unauthenticated --
				// so the post-auth ad, session cache, and per-command authz do not
				// see a stale NegotiatedAuth from the method that just failed and
				// mistake this peer for an authenticated one. The client zeroes the
				// same fields on its half of the fallback.
				negotiation.Authentication = false
				negotiation.NegotiatedAuth = AuthNone
				slog.Info("🔐 SERVER: client offered no usable authentication method; authentication was not required, continuing unauthenticated", "destination", "cedar")
				return nil
			}
			return fmt.Errorf("client has no more authentication methods to try")
		}

		// Find a compatible method from the bitmask (prefer our order). Use the
		// negotiation's (filtered) server methods so a vetoed TLS method is never
		// selected even if a peer requests it in its bitmask.
		serverMethods := a.config.AuthMethods
		if negotiation.ServerConfig != nil {
			serverMethods = negotiation.ServerConfig.AuthMethods
		}
		selectedMethod := AuthNone
		selectedBitmask := 0

		for _, method := range serverMethods {
			methodBitmask := authMethodToBitmask(method)
			if clientBitmask&methodBitmask != 0 {
				selectedMethod = canonicalAuthMethod(method)
				selectedBitmask = methodBitmask
				break
			}
		}

		// Send response to client
		responseMsg := message.NewMessageForStream(a.stream)
		if err := responseMsg.PutInt(ctx, selectedBitmask); err != nil {
			return fmt.Errorf("failed to send server auth response: %w", err)
		}
		if err := responseMsg.FinishMessage(ctx); err != nil {
			return fmt.Errorf("failed to send server auth response message: %w", err)
		}

		if selectedBitmask == 0 {
			slog.Info("🔐 SERVER: No compatible authentication method found, client will retry", "destination", "cedar")
			continue
		}

		slog.Info(fmt.Sprintf("🔐 SERVER: Selected authentication method: %s", selectedMethod), "destination", "cedar")

		// Perform the specific authentication method
		err = a.performAuthentication(ctx, selectedMethod, negotiation)
		if err != nil {
			slog.Info(fmt.Sprintf("🔐 SERVER: Authentication method %s failed: %v", selectedMethod, err), "destination", "cedar")
			// Continue the loop to wait for the client's next attempt. A failed
			// method leaves the stream back at the bitmask handshake in sync with
			// the peer: even an SSL/SCITOKENS TLS-setup failure signals the peer
			// in-band through the SSL status exchange (see PerformSSLHandshake),
			// so the client returns to the handshake and can try another method
			// rather than hanging.
			continue
		}

		slog.Info(fmt.Sprintf("✅ SERVER: Authentication successful with method: %s", selectedMethod), "destination", "cedar")
		negotiation.NegotiatedAuth = selectedMethod
		if selectedMethod == AuthClaimToBe {
			a.limitClaimToBe(negotiation)
		}

		// After successful authentication, perform key exchange as in HTCondor's Authentication::exchangeKey
		// For modern HTCondor with AESGCM crypto, the server always sends an empty key
		if err := a.exchangeKey(ctx, negotiation); err != nil {
			return fmt.Errorf("key exchange failed: %w", err)
		}

		return nil
	}
}

// limitClaimToBe bounds a CLAIMTOBE session to the authorization level of the
// command it was negotiated for and the levels that level implies, as DaemonCore
// does (daemon_command.cpp, AuthenticateFinish): the peer only claimed its
// name, so the session must not be resumed for a command at a higher level.
// The level is the first one CommandPerms reports, as DaemonCore uses the
// command's primary permission and not its alternates. A command registered at
// no level leaves the session unbounded.
func (a *Authenticator) limitClaimToBe(negotiation *SecurityNegotiation) {
	if a.config.CommandPerms == nil || negotiation.ClientConfig == nil {
		return
	}
	perms := a.config.CommandPerms(negotiation.ClientConfig.AuthorizedCommand())
	if len(perms) == 0 {
		return
	}
	limits := ImpliedPermissions(perms[0])
	if limits == nil {
		// Not a level: the bounding set permits ALLOW commands alone.
		limits = []string{}
	}
	negotiation.AuthorizationLimits = limits
}

// performAuthentication performs the specific authentication method handshake
func (a *Authenticator) performAuthentication(ctx context.Context, method AuthMethod, negotiation *SecurityNegotiation) error {
	method = canonicalAuthMethod(method)
	switch method {
	case AuthNone:
		// No additional handshake required for NONE
		return nil
	case AuthSSL:
		return a.performSSLAuthentication(ctx, negotiation)
	case AuthSciTokens:
		// SCITOKENS uses SSL + SciToken exchange
		return a.performSciTokenAuthentication(ctx, negotiation)
	case AuthToken, AuthIDTokens:
		return a.performTokenAuthentication(ctx, method, negotiation)
	case AuthFS:
		// FS uses local filesystem
		return a.performFSAuthentication(ctx, negotiation, false)
	case AuthClaimToBe:
		return a.performClaimToBeAuthentication(ctx, negotiation)
	case AuthPassword:
		return a.performPasswordAuthentication(ctx, negotiation)
	case AuthKerberos:
		return a.performKerberosAuthentication(ctx, negotiation)
	default:
		return fmt.Errorf("unsupported authentication method: %s", method)
	}
}

// PerformTokenAuthenticationDemo is a simple wrapper for demonstration purposes
func (a *Authenticator) PerformTokenAuthenticationDemo(method AuthMethod, negotiation *SecurityNegotiation) error {
	return a.performTokenAuthentication(context.Background(), method, negotiation)
}

// exchangeKey performs the key exchange step following HTCondor's Authentication::exchangeKey
// For modern HTCondor with AESGCM crypto, the server always sends an empty key
func (a *Authenticator) exchangeKey(ctx context.Context, negotiation *SecurityNegotiation) error {
	slog.Info("🔑 Starting key exchange...", "destination", "cedar")

	if negotiation.IsClient {
		// Client side: receive key from server
		slog.Info("🔑 CLIENT: Receiving key from server...", "destination", "cedar")

		msg := message.NewMessageFromStream(a.stream)

		// Receive hasKey flag
		hasKey, err := msg.GetInt(ctx)
		if err != nil {
			return fmt.Errorf("failed to receive hasKey flag: %w", err)
		}

		slog.Info(fmt.Sprintf("🔑 CLIENT: Server hasKey flag: %d", hasKey), "destination", "cedar")

		if hasKey == 0 {
			// Server has no key - this is expected for AESGCM crypto
			slog.Info("🔑 CLIENT: Server sent empty key (expected for AESGCM)", "destination", "cedar")
			return nil
		} else {
			// Server has a key to send (not expected for AESGCM but handle anyway)
			keyLength, err := msg.GetInt(ctx)
			if err != nil {
				return fmt.Errorf("failed to receive key length: %w", err)
			}

			protocol, err := msg.GetInt(ctx)
			if err != nil {
				return fmt.Errorf("failed to receive protocol: %w", err)
			}

			duration, err := msg.GetInt(ctx)
			if err != nil {
				return fmt.Errorf("failed to receive duration: %w", err)
			}

			inputLen, err := msg.GetInt(ctx)
			if err != nil {
				return fmt.Errorf("failed to receive input length: %w", err)
			}

			slog.Info(fmt.Sprintf("🔑 CLIENT: Receiving key - length: %d, protocol: %d, duration: %d, inputLen: %d",
				keyLength, protocol, duration, inputLen), "destination", "cedar")

			// Read encrypted key data
			encryptedKey := make([]byte, inputLen)
			for i := 0; i < inputLen; i++ {
				b, err := msg.GetChar(ctx)
				if err != nil {
					return fmt.Errorf("failed to get encrypted key byte %d: %w", i, err)
				}
				encryptedKey[i] = b
			}

			// TODO: Unwrap the key using the authenticator
			slog.Info(fmt.Sprintf("🔑 CLIENT: Received encrypted key (%d bytes)", len(encryptedKey)), "destination", "cedar")
		}
	} else {
		// Server side: send key to client
		slog.Info("🔑 SERVER: Sending key to client...", "destination", "cedar")

		msg := message.NewMessageForStream(a.stream)

		// For AESGCM crypto, always send empty key (hasKey = 0)
		hasKey := 0
		if err := msg.PutInt(ctx, hasKey); err != nil {
			return fmt.Errorf("failed to send hasKey flag: %w", err)
		}

		if err := msg.FinishMessage(ctx); err != nil {
			return fmt.Errorf("failed to finish key exchange message: %w", err)
		}

		slog.Info(fmt.Sprintf("🔑 SERVER: Sent empty key (hasKey = %d) for AESGCM crypto", hasKey), "destination", "cedar")
	}

	slog.Info("✅ Key exchange completed successfully", "destination", "cedar")
	return nil
}
