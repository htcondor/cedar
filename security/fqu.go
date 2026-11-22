package security

import "strings"

// HTCondor names an authenticated peer by its fully-qualified user,
// "user@domain" (Condor_Auth_Base::getRemoteFQU, condor_auth.cpp). Each
// authentication method sets the user and the domain; setRemoteDomain
// lowercases the domain, and a method that sets no domain leaves the FQU as the
// bare user. ALLOW_*/DENY_* lists are matched against the whole FQU, while the
// user part alone is what C++ calls the owner (Sock::getOwner), e.g. a job's
// Owner attribute.

// UnmappedDomain is the domain C++ gives an SSL or SCITOKENS identity that no
// map file renamed (UNMAPPED_DOMAIN, authentication.cpp).
const UnmappedDomain = "unmapped"

// SplitFQU splits a fully-qualified user at its last '@' into the user and
// domain parts, as Authentication::split_canonical_name does. A name with no
// '@' is all user, with an empty domain.
func SplitFQU(fqu string) (user, domain string) {
	if i := strings.LastIndexByte(fqu, '@'); i >= 0 {
		return fqu[:i], fqu[i+1:]
	}
	return fqu, ""
}

// UserName returns the user part of User, the name before its last '@' -- what
// C++ calls the owner (Sock::getOwner). Use it, not User, wherever HTCondor
// stores a bare user name, such as a job's Owner; User is the identity to
// authorize.
func (sn *SecurityNegotiation) UserName() string {
	user, _ := SplitFQU(sn.User)
	return user
}

// UserDomain returns the domain part of User, the name after its last '@', or
// "" when User has no domain.
func (sn *SecurityNegotiation) UserDomain() string {
	_, domain := SplitFQU(sn.User)
	return domain
}

// joinFQU builds the FQU for a method that set user and domain, as getRemoteFQU
// does: "user@domain" with the domain lowercased, or user alone when there is no
// domain.
func joinFQU(user, domain string) string {
	if domain == "" {
		return user
	}
	return user + "@" + strings.ToLower(domain)
}

// canonicalFQU returns the FQU for a "user@domain" name, splitting it at the
// last '@' and lowercasing the domain. A name with no '@' takes defaultDomain
// (Authentication::split_canonical_name gives a mapped name UID_DOMAIN), or
// stays bare when defaultDomain is "" (an IDTOKENS subject with no '@').
func canonicalFQU(name, defaultDomain string) string {
	if i := strings.LastIndexByte(name, '@'); i >= 0 {
		return name[:i+1] + strings.ToLower(name[i+1:])
	}
	return joinFQU(name, defaultDomain)
}

// CanonicalUser returns the FQU HTCondor records for a canonical user name, the
// result of a map file: a name with an '@' keeps its domain (lowercased), and a
// name without one takes the UID domain (see LocalUIDDomain).
func (c *SecurityConfig) CanonicalUser(name string) string {
	return canonicalFQU(name, c.LocalUIDDomain())
}

// LocalUIDDomain returns UIDDomain: the domain the methods that authenticate a
// peer by a bare user name -- FS and FS_REMOTE above all, whose identity is the
// owner of a marker file and so carries no domain of its own -- qualify it
// with. It is "" when nothing configured one, and those methods then leave the
// identity bare rather than invent a domain for it.
//
// Guessing is worse than having nothing to go on. A guessed domain is
// indistinguishable downstream from a configured one, so the caller that does
// know the real UID_DOMAIN -- a map file, or server.FQUMapper, which qualifies
// a name that arrives without an '@' -- sees an identity that is already
// qualified and leaves it alone. The peer is then authorized as user@<guess>,
// which matches no ALLOW_<PERM> rule written for the pool's UID domain and
// which the daemon cannot tell apart from a genuinely foreign identity. A bare
// name is at least true, and the layer above can still complete it.
//
// UID_DOMAIN's own default, $(FULL_HOSTNAME), belongs to the configuration that
// reads UID_DOMAIN -- it is a parameter's default, not something to synthesize
// here out of whatever name this host happens to answer to. os.Hostname is not
// even that default: it is as often the short name.
func (c *SecurityConfig) LocalUIDDomain() string {
	if c == nil {
		return ""
	}
	return c.UIDDomain
}

// IsUnauthenticatedFQU reports whether user is the identity an authentication
// method yields when it completed without identifying the peer -- an SSL peer
// that presented no client certificate reaches this. A session carrying it has
// not authenticated anyone, so it must not satisfy a policy that requires
// authentication, and it must not be authorized under that literal name as
// though it were a real identity.
func IsUnauthenticatedFQU(user string) bool {
	return user == joinFQU("unauthenticated", UnmappedDomain)
}
