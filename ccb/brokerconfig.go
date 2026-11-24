package ccb

import (
	"github.com/htcondor/cedar/security"
)

// brokerDisposition is what brokerConfig does with one SecurityConfig field on
// the broker leg. Every field is classified: see brokerFieldDispositions.
type brokerDisposition int

const (
	// dispositionCarried: the field describes this HOST -- its credentials,
	// its trust anchors, its policy -- so it means the same thing to a broker
	// as to the target.
	dispositionCarried brokerDisposition = iota
	// dispositionReAimed: the field names the peer or the work, and
	// brokerConfig replaces it with the broker's.
	dispositionReAimed
	// dispositionCleared: the field is meaningful only for the target's
	// handshake, and brokerConfig zeroes it.
	dispositionCleared
	// dispositionRefused: the field makes a broker leg impermissible, and
	// dialBrokerAuthOnce refuses before dialling rather than re-aiming it.
	dispositionRefused
)

// brokerFieldDispositions classifies every exported field of
// security.SecurityConfig. The broker leg starts from the caller's config for
// the TARGET -- client.Connect hands c.config.Security straight to Dial -- so a
// field that names the target, or that grants the target's handshake something,
// has to be dealt with explicitly or it travels to a party the caller never
// chose. ServerName and DelegatedCredential were each that mistake, found
// separately; this table is so the next one is a test failure rather than a
// review finding.
//
// TestBrokerFieldDispositionsAreExhaustive fails when SecurityConfig gains a
// field that is not listed here.
var brokerFieldDispositions = map[string]brokerDisposition{
	// Re-aimed at the broker.
	"PeerName": dispositionReAimed, // keys the client session cache, in preference to the stream's peer address
	"Command":  dispositionReAimed, // the CCB command this leg carries, not the target's

	// Cleared: target-only.
	"SessionID":     dispositionCleared, // names a pre-registered session to resume; the target's, typically a schedd-minted claim
	"ServerName":    dispositionCleared, // the name SSL verifies the peer cert against; cleared so the handshake derives the broker's from the peer address
	"AuthCommand":   dispositionCleared, // a sub-command OF Command, which is re-aimed, so the target's is incoherent here
	"ECDHPublicKey": dispositionCleared, // per-handshake, not config: NewAuthenticator writes a fresh one, and a stale value must not be what is advertised

	// Refused: see the guard at the top of dialBrokerAuthOnce.
	"DelegatedCredential": dispositionRefused,

	// Carried: this host's own credentials, trust anchors and policy.
	"AuthMethods":                  dispositionCarried,
	"Authentication":               dispositionCarried,
	"CryptoMethods":                dispositionCarried,
	"Encryption":                   dispositionCarried,
	"Integrity":                    dispositionCarried,
	"FSLocalDir":                   dispositionCarried,
	"FSRemoteDir":                  dispositionCarried,
	"SharedPortID":                 dispositionCarried, // read only by verifyServerChannelBindingExt, server-side; inert on a client leg
	"AuthRequired":                 dispositionCarried,
	"PostAuthPolicy":               dispositionCarried, // server-side hook; inert on a client leg
	"SessionAttrs":                 dispositionCarried, // server-side; inert on a client leg
	"WantSessionAttrs":             dispositionCarried,
	"CommandPerms":                 dispositionCarried, // server-side; inert on a client leg
	"CertFile":                     dispositionCarried,
	"KeyFile":                      dispositionCarried,
	"CAFile":                       dispositionCarried,
	"CADir":                        dispositionCarried,
	"UseDefaultCAs":                dispositionCarried,
	"Credentials":                  dispositionCarried,
	"Token":                        dispositionCarried, // this host's own token; a delegated one is refused above
	"TokenFile":                    dispositionCarried,
	"TokenDir":                     dispositionCarried,
	"TokenPoolSigningKeyFile":      dispositionCarried,
	"TokenSigningKeyDir":           dispositionCarried,
	"TokenMaxAge":                  dispositionCarried,
	"IssuerKeys":                   dispositionCarried,
	"CondorUsername":               dispositionCarried,
	"FSRootToCondor":               dispositionCarried,
	"CondorPrivRunner":             dispositionCarried,
	"UIDDomain":                    dispositionCarried,
	"SciTokensMapper":              dispositionCarried, // server-side; inert on a client leg
	"SciTokensServerAudience":      dispositionCarried, // server-side; inert on a client leg
	"SciTokensForeignTokenIssuers": dispositionCarried, // server-side; inert on a client leg
	"SciTokensHTTPClient":          dispositionCarried,
	"RemoteVersion":                dispositionCarried,
	"TrustDomain":                  dispositionCarried,
	"Subsystem":                    dispositionCarried,
	"ServerPid":                    dispositionCarried,
	"SessionDuration":              dispositionCarried,
	"SessionLease":                 dispositionCarried,
	"SecurityTag":                  dispositionCarried, // same credential as the target leg, so the same cache partition is right; PeerName separates the entries
	"SessionCache":                 dispositionCarried, // the same process cache serves both legs
}

// brokerConfig derives the security config for a leg to brokerAddr carrying
// command, from the caller's config for the TARGET. The caller has already
// refused a config whose disposition is dispositionRefused.
//
// Why each re-aimed or cleared field has to be:
//
//	PeerName is what ClientHandshake keys the session cache on, in preference
//	to the stream's peer address. Left as the target, every broker in the
//	target's CCBID shares one cache entry: a session minted with one broker is
//	then offered to the next, which has never heard of it, and the dial fails
//	with "session not found on server" -- repeatedly, because the entry keeps
//	being re-created under that same shared key.
//
//	Command is the CCB command this leg carries (CCB_REQUEST and friends), not
//	whatever the caller means to do once it reaches the target.
//
//	SessionID names a pre-registered session to resume outright, skipping
//	negotiation. On this path it is the target's, typically a schedd-minted
//	claim; offering it to a broker asks the broker to resume a session it never
//	issued.
//
//	ServerName is the name SSL verifies the peer certificate against, and an
//	explicit one beats the name the handshake would otherwise derive from the
//	stream's peer address. Left as the target, the broker's certificate is
//	checked against the target's hostname and the dial fails with "certificate
//	is valid for <broker>, not <target>". Clearing it hands the derivation back
//	to the SSL handshake, which takes the name from the peer address --
//	brokerAddr, set by dialBrokerWith.
//
//	AuthCommand is a sub-command of Command (AuthorizedCommand returns it when
//	Command is DC_AUTHENTICATE or DC_SEC_QUERY). Command is re-aimed, so the
//	target's sub-command no longer describes anything; condor_ping sets it
//	(golang-htcondor ping.go) and it would otherwise be advertised to the broker.
//
//	ECDHPublicKey is per-handshake state kept in the config rather than
//	configuration. NewAuthenticator writes a fresh one, so clearing it only
//	removes the window in which a stale key is what this leg would advertise.
//
// The disposition of a field and the code below have to agree, which
// TestBrokerConfigMatchesItsDispositions checks.
func brokerConfig(sec *security.SecurityConfig, brokerAddr string, command int) *security.SecurityConfig {
	cfg := *sec

	cfg.PeerName = brokerAddr
	cfg.Command = command

	cfg.SessionID = ""
	cfg.ServerName = ""
	cfg.AuthCommand = 0
	cfg.ECDHPublicKey = ""

	return &cfg
}
