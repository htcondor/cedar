// Copyright ...
//
// KERBEROS authentication method, wire-compatible with HTCondor's C++
// condor_auth_kerberos.cpp. Pure Go: the krb5 ticket handling uses
// jcmturner/gokrb5 rather than cgo bindings to libkrb5, so the daemon keeps
// building with CGO_ENABLED=0.
//
// It implements both halves of the handshake (client AP_REQ, server keytab
// verify + AP_REP); performKerberosAuthentication dispatches by role.

package security

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/message"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Kerberos CEDAR handshake result codes. These are the KERBEROS_* #defines in
// HTCondor's condor_auth_kerberos.cpp and must not change.
const (
	kerberosABORT   = -1
	kerberosDENY    = 0
	kerberosGRANT   = 1
	kerberosMUTUAL  = 3
	kerberosPROCEED = 4
)

// defaultKerberosService is HTCondor's STR_DEFAULT_CONDOR_SERVICE — the service
// component of the server principal (service/host@REALM) when KERBEROS_SERVER_SERVICE
// is unset. HTCondor defaults this to "host".
const defaultKerberosService = "host"

// defaultKerberosUser is HTCondor's STR_DEFAULT_CONDOR_USER, the user a client
// authenticating with the condor service principal maps to when
// KERBEROS_SERVER_USER is unset.
const defaultKerberosUser = "condor"

// kerberosClient runs the client half of the HTCondor Kerberos CEDAR handshake:
//
//	-> PROCEED                              (readiness)
//	-> PROCEED, len(AP_REQ), AP_REQ bytes   (send_request)
//	<- MUTUAL                               (server accepted the ticket)
//	<- PROCEED, len(AP_REP), AP_REP bytes   (server's mutual-auth reply)
//	-> GRANT
//	<- reply
//
// then the krb5 ticket session key becomes the CEDAR session key.
func (a *Authenticator) kerberosClient(ctx context.Context, negotiation *SecurityNegotiation) error {
	cl, err := newKerberosClientFromCCache()
	if err != nil {
		_ = a.kerberosSendInt(ctx, kerberosABORT)
		return fmt.Errorf("kerberos: init client: %w", err)
	}
	defer cl.Destroy()

	spn, err := a.kerberosServerSPN(negotiation)
	if err != nil {
		_ = a.kerberosSendInt(ctx, kerberosABORT)
		return err
	}

	tkt, sessionKey, err := cl.GetServiceTicket(spn)
	if err != nil {
		_ = a.kerberosSendInt(ctx, kerberosABORT)
		return fmt.Errorf("kerberos: get service ticket for %q: %w", spn, err)
	}

	// Build the authenticator ourselves and keep it: the server's AP_REP echoes
	// this timestamp back (encrypted under the session key), which is how mutual
	// auth proves the server holds the service key.
	authenticator, err := types.NewAuthenticator(cl.Credentials.Realm(), cl.Credentials.CName())
	if err != nil {
		_ = a.kerberosSendInt(ctx, kerberosABORT)
		return fmt.Errorf("kerberos: build authenticator: %w", err)
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, authenticator)
	if err != nil {
		_ = a.kerberosSendInt(ctx, kerberosABORT)
		return fmt.Errorf("kerberos: build AP_REQ: %w", err)
	}
	// Request mutual authentication so the server proves it holds the service key
	// (matches the C++ client, which always does mutual auth).
	types.SetFlag(&apReq.APOptions, flags.APOptionMutualRequired)
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		_ = a.kerberosSendInt(ctx, kerberosABORT)
		return fmt.Errorf("kerberos: marshal AP_REQ: %w", err)
	}

	// Readiness (C++ authenticate()).
	if err := a.kerberosSendInt(ctx, kerberosPROCEED); err != nil {
		return fmt.Errorf("kerberos: send readiness: %w", err)
	}

	// send_request: PROCEED, length, AP_REQ bytes.
	if err := a.kerberosSendRequest(ctx, apReqBytes); err != nil {
		return fmt.Errorf("kerberos: send AP_REQ: %w", err)
	}

	// Expect MUTUAL from the server.
	reply, err := a.kerberosRecvInt(ctx)
	if err != nil {
		return fmt.Errorf("kerberos: recv reply: %w", err)
	}
	if reply != kerberosMUTUAL {
		return fmt.Errorf("kerberos: server declined the ticket (reply=%d)", reply)
	}

	// client_mutual_authenticate: read the server's AP_REP and validate it.
	apRepBytes, err := a.kerberosReadRequest(ctx)
	if err != nil {
		return fmt.Errorf("kerberos: read AP_REP: %w", err)
	}
	// Validate the AP_REP (krb5_rd_rep): decrypt it with the session key and
	// confirm it echoes our authenticator's timestamp — the server's proof that it
	// holds the service key. Without this, a MUTUAL reply is unauthenticated.
	if err := validateKerberosAPRep(apRepBytes, sessionKey, authenticator); err != nil {
		return fmt.Errorf("kerberos: %w", err)
	}

	if err := a.kerberosSendInt(ctx, kerberosGRANT); err != nil {
		return fmt.Errorf("kerberos: send GRANT: %w", err)
	}
	if _, err := a.kerberosRecvInt(ctx); err != nil {
		return fmt.Errorf("kerberos: recv final reply: %w", err)
	}

	// KERBEROS only proves identity; it does not set the CEDAR session key. Modern
	// HTCondor derives the AES-256-GCM key from the ECDH exchange carried in the
	// security-policy ClassAds (setupStreamEncryption), independent of the auth
	// method — so, like TOKEN/SSL, we leave the key to the framework. (The legacy
	// krb5_c_encrypt key-wrap, condor_auth_kerberos.cpp usage 1024, is only used
	// for the obsolete Blowfish/3DES ciphers, which CEDAR does not implement.)
	if cl.Credentials != nil {
		negotiation.User = cl.Credentials.UserName() + "@" + cl.Credentials.Realm()
	}
	return nil
}

// --- CEDAR wire helpers (match condor_auth_kerberos.cpp framing) ---

// kerberosSendInt sends a single CEDAR int as its own message + end_of_message.
func (a *Authenticator) kerberosSendInt(ctx context.Context, v int) error {
	msg := message.NewMessageForStream(a.stream)
	if err := msg.PutInt(ctx, v); err != nil {
		return err
	}
	return msg.FinishMessage(ctx)
}

// kerberosRecvInt reads a single CEDAR int message.
func (a *Authenticator) kerberosRecvInt(ctx context.Context) (int, error) {
	return message.NewMessageFromStream(a.stream).GetInt(ctx)
}

// kerberosSendRequest sends an AP_REQ/AP_REP blob using HTCondor's send_request
// framing: int(PROCEED), int(length), raw bytes, end_of_message.
func (a *Authenticator) kerberosSendRequest(ctx context.Context, data []byte) error {
	msg := message.NewMessageForStream(a.stream)
	if err := msg.PutInt(ctx, kerberosPROCEED); err != nil {
		return err
	}
	if err := msg.PutInt(ctx, len(data)); err != nil {
		return err
	}
	if err := msg.PutBytes(ctx, data); err != nil {
		return err
	}
	return msg.FinishMessage(ctx)
}

// kerberosReadRequest reads a blob written with the send_request framing:
// int(message), int(length), then length raw bytes.
func (a *Authenticator) kerberosReadRequest(ctx context.Context) ([]byte, error) {
	msg := message.NewMessageFromStream(a.stream)
	if _, err := msg.GetInt(ctx); err != nil { // leading message code (PROCEED)
		return nil, err
	}
	length, err := msg.GetInt(ctx)
	if err != nil {
		return nil, err
	}
	if length < 0 {
		return nil, fmt.Errorf("kerberos: negative request length %d", length)
	}
	return msg.GetBytes(ctx, length)
}

// --- gokrb5 helpers ---

// newKerberosClientFromCCache builds a gokrb5 client from the credential cache
// named by KRB5CCNAME (or the default /tmp/krb5cc_<uid>), configured from
// /etc/krb5.conf (or KRB5_CONFIG).
func newKerberosClientFromCCache() (*client.Client, error) {
	ccName := os.Getenv("KRB5CCNAME")
	ccName = strings.TrimPrefix(ccName, "FILE:")
	if ccName == "" {
		ccName = fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
	}
	ccache, err := credentials.LoadCCache(ccName)
	if err != nil {
		return nil, fmt.Errorf("load ccache %q: %w", ccName, err)
	}

	cfgPath := os.Getenv("KRB5_CONFIG")
	if cfgPath == "" {
		cfgPath = "/etc/krb5.conf"
	}
	cfg, err := krb5config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("load krb5.conf %q: %w", cfgPath, err)
	}

	cl, err := client.NewFromCCache(ccache, cfg, client.DisablePAFXFAST(true))
	if err != nil {
		return nil, fmt.Errorf("new client from ccache: %w", err)
	}
	return cl, nil
}

// validateKerberosAPRep performs the client side of krb5_rd_rep: it decrypts the
// server's AP_REP with the ticket session key and checks that the sealed
// timestamp matches the authenticator we sent. A matching timestamp proves the
// server could decrypt our AP_REQ — i.e. it holds the service key — completing
// mutual authentication.
func validateKerberosAPRep(b []byte, key types.EncryptionKey, sent types.Authenticator) error {
	var apRep messages.APRep
	if err := apRep.Unmarshal(b); err != nil {
		return fmt.Errorf("unmarshal AP_REP: %w", err)
	}
	decrypted, err := crypto.DecryptEncPart(apRep.EncPart, key, keyusage.AP_REP_ENCPART)
	if err != nil {
		return fmt.Errorf("decrypt AP_REP: %w", err)
	}
	var enc messages.EncAPRepPart
	if err := enc.Unmarshal(decrypted); err != nil {
		return fmt.Errorf("unmarshal EncAPRepPart: %w", err)
	}
	// Compare at second granularity: the AP_REP ctime is a GeneralizedTime (no
	// sub-second), with the microseconds carried separately in cusec.
	if enc.CTime.Unix() != sent.CTime.Unix() || enc.Cusec != sent.Cusec {
		return fmt.Errorf("AP_REP timestamp mismatch: server did not prove the service key")
	}
	return nil
}

// kerberosClockSkew bounds AP_REQ timestamp acceptance (krb5 default ~5m).
const kerberosClockSkew = 5 * time.Minute

// kerberosServer runs the server half of the handshake: read the client's
// AP_REQ, validate it against the service keytab (krb5_rd_req), prove we hold the
// service key with a matching AP_REP, then adopt the ticket session key.
//
//	<- PROCEED                              (client readiness)
//	<- PROCEED, len(AP_REQ), AP_REQ bytes
//	-> MUTUAL
//	-> PROCEED, len(AP_REP), AP_REP bytes
//	<- GRANT
//	-> GRANT
func (a *Authenticator) kerberosServer(ctx context.Context, negotiation *SecurityNegotiation) error {
	ready, err := a.kerberosRecvInt(ctx)
	if err != nil {
		return fmt.Errorf("kerberos: recv readiness: %w", err)
	}
	if ready != kerberosPROCEED {
		return fmt.Errorf("kerberos: client aborted (readiness=%d)", ready)
	}

	apReqBytes, err := a.kerberosReadRequest(ctx)
	if err != nil {
		return fmt.Errorf("kerberos: read AP_REQ: %w", err)
	}

	kt, err := loadKerberosServerKeytab()
	if err != nil {
		_ = a.kerberosSendInt(ctx, kerberosDENY)
		return fmt.Errorf("kerberos: %w", err)
	}
	var apReq messages.APReq
	if err := apReq.Unmarshal(apReqBytes); err != nil {
		_ = a.kerberosSendInt(ctx, kerberosDENY)
		return fmt.Errorf("kerberos: unmarshal AP_REQ: %w", err)
	}
	// Verify through the service layer, which adds the replay cache RFC 4120
	// section 3.2.3 requires. APReq.Verify on its own decrypts the ticket,
	// checks its validity and the clock skew and matches the CName, but keeps
	// no record of the authenticators it has already seen -- so a captured
	// AP_REQ replayed inside the skew window verified a second time. KERBEROS
	// contributes nothing to the CEDAR session key (it comes from the
	// framework's ECDH, which a replaying peer performs itself) and the server
	// asks the peer for nothing but a GRANT integer after the AP_REP, so the
	// replay yielded a fully working session under the victim's principal.
	//
	// The remaining Settings defaults match what was passed before -- zero
	// ClientAddress, nil KeytabPrincipal, RequireHostAddr off. MaxClockSkew is
	// passed explicitly to keep our own value rather than the package default.
	//
	// PAC decoding is off because gokrb5's decoder expects an Active Directory
	// PAC: an MIT KDC issues a ticket whose PAC carries no KerbValidationInfo,
	// which makes GetPACType return isPAC with an error and fails the whole
	// verification ("PAC Info Buffers does not contain a KerbValidationInfo").
	// Nothing here reads PAC data; identity comes from the ticket's CName.
	ktSettings := service.NewSettings(kt,
		service.MaxClockSkew(kerberosClockSkew),
		service.DecodePAC(false),
	)
	if ok, _, verr := service.VerifyAPREQ(&apReq, ktSettings); verr != nil || !ok {
		_ = a.kerberosSendInt(ctx, kerberosDENY)
		return fmt.Errorf("kerberos: AP_REQ verification failed: %v", verr)
	}

	// Accept and enter mutual auth.
	if err := a.kerberosSendInt(ctx, kerberosMUTUAL); err != nil {
		return fmt.Errorf("kerberos: send MUTUAL: %w", err)
	}

	// AP_REP echoing the client's authenticator timestamp (krb5_mk_rep).
	sessionKey := apReq.Ticket.DecryptedEncPart.Key
	apRep, err := buildKerberosAPRep(apReq.Authenticator.CTime, apReq.Authenticator.Cusec, sessionKey)
	if err != nil {
		return fmt.Errorf("kerberos: build AP_REP: %w", err)
	}
	if err := a.kerberosSendRequest(ctx, apRep); err != nil {
		return fmt.Errorf("kerberos: send AP_REP: %w", err)
	}

	if grant, err := a.kerberosRecvInt(ctx); err != nil || grant != kerberosGRANT {
		return fmt.Errorf("kerberos: client did not grant (reply=%d, err=%v)", grant, err)
	}
	if err := a.kerberosSendInt(ctx, kerberosGRANT); err != nil {
		return fmt.Errorf("kerberos: send final reply: %w", err)
	}

	// As on the client, KERBEROS proves identity only; the AES session key comes
	// from the framework's ECDH exchange (see kerberosClient for the details).
	ep := apReq.Ticket.DecryptedEncPart
	negotiation.User = kerberosFQU(ep.CName.NameString, ep.CRealm)
	return nil
}

// kerberosFQU returns the FQU C++ gives a Kerberos client principal
// (Condor_Auth_Kerberos::map_kerberos_name): the principal's first component --
// the name up to the first '/' -- with the condor service ("host") mapped to the
// condor user, at the realm.
func kerberosFQU(nameString []string, realm string) string {
	user := ""
	if len(nameString) > 0 {
		user = nameString[0]
	}
	if user == defaultKerberosService {
		user = defaultKerberosUser
	}
	return joinFQU(user, realm)
}

// buildKerberosAPRep produces a wire AP_REP whose encrypted part echoes
// (ctime, cusec) sealed under key — the krb5_mk_rep the server returns for mutual
// auth, and exactly what validateKerberosAPRep checks on the client.
func buildKerberosAPRep(ctime time.Time, cusec int, key types.EncryptionKey) ([]byte, error) {
	enc := messages.EncAPRepPart{CTime: ctime, Cusec: cusec}
	encBytes, err := asn1.Marshal(enc)
	if err != nil {
		return nil, fmt.Errorf("marshal EncAPRepPart: %w", err)
	}
	encBytes = asn1tools.AddASNAppTag(encBytes, asnAppTag.EncAPRepPart)
	ed, err := crypto.GetEncryptedData(encBytes, key, keyusage.AP_REP_ENCPART, 1)
	if err != nil {
		return nil, fmt.Errorf("encrypt EncAPRepPart: %w", err)
	}
	apRep := messages.APRep{PVNO: 5, MsgType: 15, EncPart: ed} // KRB_AP_REP
	b, err := asn1.Marshal(apRep)
	if err != nil {
		return nil, fmt.Errorf("marshal APRep: %w", err)
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.APREP), nil
}

// loadKerberosServerKeytab loads the service keytab named by KRB5_KTNAME (or the
// system default). TODO: wire to HTCondor's KERBEROS_SERVER_KEYTAB via SecurityConfig.
func loadKerberosServerKeytab() (*keytab.Keytab, error) {
	path := strings.TrimPrefix(os.Getenv("KRB5_KTNAME"), "FILE:")
	if path == "" {
		path = "/etc/krb5.keytab"
	}
	kt, err := keytab.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load keytab %q: %w", path, err)
	}
	return kt, nil
}

// kerberosServerSPN derives the server service principal (service/host) the
// client must obtain a ticket for, from the CEDAR peer address. The service
// component defaults to "host" and is overridden by KERBEROS_SERVER_SERVICE; the
// host comes from the sinful string's alias= (no DNS) — see the body.
func (a *Authenticator) kerberosServerSPN(negotiation *SecurityNegotiation) (string, error) {
	service := defaultKerberosService

	peer := a.stream.GetPeerAddr()
	if peer == "" {
		return "", fmt.Errorf("kerberos: no peer address to derive the server principal")
	}
	// Prefer the canonical hostname from the sinful string's alias= parameter.
	// HTCondor records the daemon's canonical name there (it's in the collector's
	// advertised address), so the client gets the right host/<name> without a DNS
	// lookup.
	if si, err := addresses.ParseSinful(peer); err == nil && si.Alias != "" {
		return service + "/" + si.Alias, nil
	}
	// Otherwise fall back to the connected host — but only if it is a hostname. A
	// bare IP won't match the service's host/<name> keytab principal, and we
	// deliberately do not reverse-resolve.
	host := strings.Trim(peer, "<>")
	if h, _, err := net.SplitHostPort(strings.SplitN(host, "?", 2)[0]); err == nil {
		host = h
	}
	if host == "" || net.ParseIP(host) != nil {
		return "", fmt.Errorf("kerberos: cannot determine the server hostname for the service principal from %q; connect via a sinful address with alias= (HTCondor's collector address) or a hostname", peer)
	}
	return service + "/" + host, nil
}
