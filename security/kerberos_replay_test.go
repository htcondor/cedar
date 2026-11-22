package security_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/internal/condortest"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// CEDAR kerberos framing, mirroring kerberosSendInt/kerberosSendRequest (those
// are unexported and condortest cannot be imported from inside the package).
const (
	kerbDeny    = 0
	kerbMutual  = 3
	kerbProceed = 4
)

func kerbSendInt(ctx context.Context, s *stream.Stream, v int) error {
	m := message.NewMessageForStream(s)
	if err := m.PutInt(ctx, v); err != nil {
		return err
	}
	return m.FinishMessage(ctx)
}

func kerbRecvInt(ctx context.Context, s *stream.Stream) (int, error) {
	return message.NewMessageFromStream(s).GetInt(ctx)
}

func kerbSendRequest(ctx context.Context, s *stream.Stream, data []byte) error {
	m := message.NewMessageForStream(s)
	if err := m.PutInt(ctx, kerbProceed); err != nil {
		return err
	}
	if err := m.PutInt(ctx, len(data)); err != nil {
		return err
	}
	if err := m.PutBytes(ctx, data); err != nil {
		return err
	}
	return m.FinishMessage(ctx)
}

func kerbReadRequest(ctx context.Context, s *stream.Stream) ([]byte, error) {
	m := message.NewMessageFromStream(s)
	if _, err := m.GetInt(ctx); err != nil {
		return nil, err
	}
	n, err := m.GetInt(ctx)
	if err != nil {
		return nil, err
	}
	if n < 0 {
		return nil, fmt.Errorf("negative request length %d", n)
	}
	return m.GetBytes(ctx, n)
}

// TestKerberosAPReqReplayRejected captures the AP_REQ a real client produces and
// presents it to two fresh servers. RFC 4120 section 3.2.3 requires the second
// to be refused: the ticket still decrypts and the clock skew is still inside
// the window, so a replay cache is the only thing that can tell the two apart.
//
// It matters more here than the five-minute window suggests. KERBEROS
// contributes nothing to the CEDAR session key -- that comes from the
// framework's ECDH, which a replaying peer performs itself -- and after the
// AP_REP the server asks the peer for nothing but a plaintext GRANT integer. So
// a verified replay yields a working session under the victim's principal.
//
// Skips unless the MIT krb5 tools are installed.
func TestKerberosAPReqReplayRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Kerberos replay test in short mode")
	}

	host, err := os.Hostname()
	if err != nil {
		t.Fatalf("hostname: %v", err)
	}
	kfix := condortest.SetupKerberos(t, host) // skips if krb5 tools are absent

	t.Setenv("KRB5_CONFIG", kfix.Krb5Conf)
	t.Setenv("KRB5CCNAME", "FILE:"+kfix.CCacheFile)
	t.Setenv("KRB5_KTNAME", "FILE:"+kfix.KeytabFile)

	serverCfg := func() *security.SecurityConfig {
		return &security.SecurityConfig{
			AuthMethods:    []security.AuthMethod{security.AuthKerberos},
			Authentication: security.SecurityRequired,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			Encryption:     security.SecurityOptional,
			Integrity:      security.SecurityOptional,
			Command:        commands.DC_NOP,
		}
	}

	// A minimal peer: negotiate, offer KERBEROS, then hand over apReq (or
	// capture the real client's, when apReq is nil). Returns the server's reply
	// to the AP_REQ and, on capture, the bytes it saw.
	peer := func(ctx context.Context, s *stream.Stream, apReq []byte) (int, []byte, error) {
		ad := classad.New()
		for k, v := range map[string]string{
			"Authentication": "REQUIRED", "AuthenticationNew": "REQUIRED",
			"AuthMethods": "KERBEROS", "CryptoMethods": "AES",
			"Encryption": "NO", "Integrity": "NO", "Enact": "NO",
			"NewSession": "YES", "OutgoingNegotiation": "PREFERRED",
		} {
			_ = ad.Set(k, v)
		}
		_ = ad.Set("Command", int(commands.DC_NOP))
		m := message.NewMessageForStream(s)
		if err := m.PutInt(ctx, commands.DC_AUTHENTICATE); err != nil {
			return 0, nil, err
		}
		if err := m.PutClassAd(ctx, ad); err != nil {
			return 0, nil, err
		}
		if err := m.FinishMessage(ctx); err != nil {
			return 0, nil, err
		}
		if _, err := message.NewMessageFromStream(s).GetClassAd(ctx); err != nil {
			return 0, nil, fmt.Errorf("reading server policy: %w", err)
		}
		// Offer KERBEROS (CAUTH_KERBEROS) and read the server's selection.
		if err := kerbSendInt(ctx, s, security.AuthBitmaskKerberos); err != nil {
			return 0, nil, err
		}
		if _, err := kerbRecvInt(ctx, s); err != nil {
			return 0, nil, fmt.Errorf("reading method selection: %w", err)
		}
		if err := kerbSendInt(ctx, s, kerbProceed); err != nil {
			return 0, nil, err
		}
		if err := kerbSendRequest(ctx, s, apReq); err != nil {
			return 0, nil, err
		}
		code, err := kerbRecvInt(ctx, s)
		if err != nil {
			// A closed stream is a refusal, which is what we are measuring.
			return kerbDeny, apReq, nil
		}
		return code, apReq, nil
	}

	// Capture a genuine AP_REQ by letting the real client build one and
	// standing in for the server just long enough to read it off the wire.
	capture := func() []byte {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		clientConn, srvConn := net.Pipe()
		defer func() { _ = clientConn.Close() }()
		defer func() { _ = srvConn.Close() }()

		cs := stream.NewStream(clientConn)
		cs.SetPeerAddr(fmt.Sprintf("<127.0.0.1:0?alias=%s>", host))
		clientCfg := serverCfg()
		go func() {
			_, _ = security.NewAuthenticator(clientCfg, cs).ClientHandshake(ctx)
		}()

		ss := stream.NewStream(srvConn)
		// Read the client's command + negotiation ad, answer with a policy ad
		// selecting KERBEROS, then read its bitmask and its AP_REQ.
		req := message.NewMessageFromStream(ss)
		if _, err := req.GetInt(ctx); err != nil {
			t.Fatalf("reading client command: %v", err)
		}
		if _, err := req.GetClassAd(ctx); err != nil {
			t.Fatalf("reading client negotiation ad: %v", err)
		}
		pol := classad.New()
		for k, v := range map[string]string{
			"Authentication": "YES", "AuthMethods": "KERBEROS", "AuthMethodsList": "KERBEROS",
			"CryptoMethods": "AES", "CryptoMethodsList": "AES",
			"Encryption": "NO", "Integrity": "NO", "Enact": "YES",
		} {
			_ = pol.Set(k, v)
		}
		pm := message.NewMessageForStream(ss)
		if err := pm.PutClassAd(ctx, pol); err != nil {
			t.Fatalf("sending policy: %v", err)
		}
		if err := pm.FinishMessage(ctx); err != nil {
			t.Fatalf("finishing policy: %v", err)
		}
		if _, err := kerbRecvInt(ctx, ss); err != nil {
			t.Fatalf("reading client bitmask: %v", err)
		}
		if err := kerbSendInt(ctx, ss, security.AuthBitmaskKerberos); err != nil {
			t.Fatalf("selecting KERBEROS: %v", err)
		}
		if _, err := kerbRecvInt(ctx, ss); err != nil {
			t.Fatalf("reading client readiness: %v", err)
		}
		blob, err := kerbReadRequest(ctx, ss)
		if err != nil {
			t.Fatalf("capturing AP_REQ: %v", err)
		}
		if len(blob) == 0 {
			t.Fatal("captured an empty AP_REQ")
		}
		return blob
	}

	apReq := capture()
	t.Logf("captured AP_REQ: %d bytes", len(apReq))

	present := func() int {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		srvConn, peerConn := net.Pipe()
		defer func() { _ = srvConn.Close() }()
		defer func() { _ = peerConn.Close() }()

		go func() {
			_, _ = security.NewAuthenticator(serverCfg(), stream.NewStream(srvConn)).ServerHandshake(ctx)
		}()
		code, _, err := peer(ctx, stream.NewStream(peerConn), apReq)
		if err != nil {
			t.Fatalf("presenting AP_REQ: %v", err)
		}
		return code
	}

	if code := present(); code != kerbMutual {
		t.Fatalf("first presentation refused (reply=%d); the capture or fixture is wrong, so the replay half would prove nothing", code)
	}
	if code := present(); code == kerbMutual {
		t.Error("server entered mutual auth for a replayed AP_REQ: the same authenticator verified twice")
	}
}
