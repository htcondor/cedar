package security

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

// TestReconcileSecurityAttributeMatchesCpp pins reconcileSecurityAttribute to
// the chart in condor_secman.cpp SecMan::ReconcileSecurityAttribute.
func TestReconcileSecurityAttributeMatchesCpp(t *testing.T) {
	R, P, O, N := SecurityRequired, SecurityPreferred, SecurityOptional, SecurityNever
	yes, no, fail := featureYes, featureNo, featureFail
	chart := []struct {
		cli, srv SecurityLevel
		want     featureAction
	}{
		{R, R, yes}, {R, P, yes}, {R, O, yes}, {R, N, fail},
		{P, R, yes}, {P, P, yes}, {P, O, yes}, {P, N, no},
		{O, R, yes}, {O, P, yes}, {O, O, no}, {O, N, no},
		{N, R, fail}, {N, P, no}, {N, O, no}, {N, N, no},
		// "cli_req is not in {REQUIRED, PREFERRED, OPTIONAL, NEVER}"
		{"", O, fail},
	}
	for _, c := range chart {
		if got := reconcileSecurityAttribute(c.cli, c.srv); got != c.want {
			t.Errorf("reconcileSecurityAttribute(client %q, server %q) = %v, want %v", c.cli, c.srv, got, c.want)
		}
	}
}

// TestPeerSecurityLevelMatchesCpp pins peerSecurityLevel to
// SecMan::sec_alpha_to_sec_req (first letter) plus ReconcileSecurityAttribute's
// treatment of a missing attribute as NEVER, and ownSecurityLevel's unset
// default to OPTIONAL.
func TestPeerSecurityLevelMatchesCpp(t *testing.T) {
	for in, want := range map[SecurityLevel]SecurityLevel{
		"REQUIRED": SecurityRequired, "yes": SecurityRequired, "True": SecurityRequired,
		"PREFERRED": SecurityPreferred, "optional": SecurityOptional,
		"NEVER": SecurityNever, "NO": SecurityNever, "false": SecurityNever,
		"": SecurityNever, "maybe": "",
	} {
		if got := peerSecurityLevel(in); got != want {
			t.Errorf("peerSecurityLevel(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ownSecurityLevel(""); got != SecurityOptional {
		t.Errorf("ownSecurityLevel(\"\") = %q, want OPTIONAL", got)
	}
}

// pipeHandshake is the outcome of handshakePipe on both ends.
type pipeHandshake struct {
	cNeg, sNeg *SecurityNegotiation
	cErr, sErr error
	cs, ss     *stream.Stream
}

// handshakePipe runs a cedar client and server handshake over a pipe.
func handshakePipe(t *testing.T, client, server *SecurityConfig) pipeHandshake {
	t.Helper()
	var (
		cNeg, sNeg *SecurityNegotiation
		cErr, sErr error
		cs, ss     *stream.Stream
	)
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close(); _ = clientConn.Close() })
	cs, ss = stream.NewStream(clientConn), stream.NewStream(serverConn)
	type res struct {
		neg *SecurityNegotiation
		err error
	}
	sCh := make(chan res, 1)
	go func() {
		neg, err := NewAuthenticator(server, ss).ServerHandshake(context.Background())
		if err != nil {
			_ = serverConn.Close()
		}
		sCh <- res{neg, err}
	}()
	cNeg, cErr = NewAuthenticator(client, cs).ClientHandshake(context.Background())
	if cErr != nil {
		_ = clientConn.Close()
	}
	select {
	case r := <-sCh:
		sNeg, sErr = r.neg, r.err
	case <-time.After(10 * time.Second):
		t.Fatal("server handshake did not return")
	}
	return pipeHandshake{cNeg, sNeg, cErr, sErr, cs, ss}
}

// TestServerReconcilesCryptoAsCpp runs cedar handshakes whose policies HTCondor
// reconciles to known Encryption/Integrity decisions
// (SecMan::ReconcileSecurityPolicyAds) and requires the cedar server to reach,
// and report to the client, the same ones: an authenticated session whose
// method is AES has both whatever the levels, integrity is reconciled at all,
// and an irreconcilable integrity policy fails.
func TestServerReconcilesCryptoAsCpp(t *testing.T) {
	cfg := func(auth, enc, integ SecurityLevel) *SecurityConfig {
		return &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthClaimToBe},
			Authentication: auth,
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Encryption:     enc,
			Integrity:      integ,
			Command:        60020,
		}
	}
	O, R, N := SecurityOptional, SecurityRequired, SecurityNever
	for _, tc := range []struct {
		name           string
		client, server *SecurityConfig
		enc, integ     bool
		fail           string
	}{
		{"authenticated AES", cfg(R, O, O), cfg(O, O, O), true, true, ""},
		{"integrity required by server", cfg(N, O, O), cfg(O, O, R), false, true, ""},
		{"integrity required by client", cfg(N, O, R), cfg(O, O, O), false, true, ""},
		{"unauthenticated optional", cfg(N, O, O), cfg(O, O, O), false, false, ""},
		// An unset client level is sent as HTCondor's default, OPTIONAL.
		{"unset client integrity", cfg(N, O, ""), cfg(O, O, R), false, true, ""},
		{"integrity required, never", cfg(N, O, N), cfg(O, O, R), false, false, "integrity incompatibility"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			GetSessionCache().Clear()
			r := handshakePipe(t, tc.client, tc.server)
			cNeg, sNeg, cErr, sErr, cs, ss := r.cNeg, r.sNeg, r.cErr, r.sErr, r.cs, r.ss
			if tc.fail != "" {
				if sErr == nil || !strings.Contains(sErr.Error(), tc.fail) {
					t.Fatalf("server handshake: %v, want an error containing %q", sErr, tc.fail)
				}
				if cErr == nil {
					t.Fatal("client handshake succeeded against a server that refused the policy")
				}
				return
			}
			if cErr != nil || sErr != nil {
				t.Fatalf("handshake: client %v, server %v", cErr, sErr)
			}
			// sNeg.Encryption records whether the stream ended up keyed
			// (ECDH runs whenever both sides offer AES); the decision is what
			// the server reported.
			if sNeg.Integrity != tc.integ {
				t.Errorf("server decided integrity=%t, want %t", sNeg.Integrity, tc.integ)
			}
			yesNo := func(b bool) SecurityLevel {
				if b {
					return "YES"
				}
				return "NO"
			}
			if cNeg.ServerConfig.Encryption != yesNo(tc.enc) || cNeg.ServerConfig.Integrity != yesNo(tc.integ) {
				t.Errorf("server reported Encryption=%q Integrity=%q, want %q %q",
					cNeg.ServerConfig.Encryption, cNeg.ServerConfig.Integrity, yesNo(tc.enc), yesNo(tc.integ))
			}
			if (tc.enc || tc.integ) && (!cs.IsEncrypted() || !ss.IsEncrypted()) {
				t.Errorf("stream not keyed: client %t server %t", cs.IsEncrypted(), ss.IsEncrypted())
			}
		})
	}
}

// TestCryptoNegotiationSkipsUnimplementedMethods: a cedar server whose policy
// requires encryption must not settle on a method it cannot key (BLOWFISH),
// which left the session in the clear while it reported encryption.
func TestCryptoNegotiationSkipsUnimplementedMethods(t *testing.T) {
	GetSessionCache().Clear()
	client := &SecurityConfig{
		AuthMethods: []AuthMethod{AuthClaimToBe}, Authentication: SecurityNever,
		CryptoMethods: []CryptoMethod{CryptoBlowfish}, Encryption: SecurityOptional, Integrity: SecurityOptional, Command: 60020,
	}
	server := &SecurityConfig{
		AuthMethods: []AuthMethod{AuthClaimToBe}, Authentication: SecurityOptional,
		CryptoMethods: []CryptoMethod{CryptoBlowfish, CryptoAES}, Encryption: SecurityRequired, Integrity: SecurityOptional,
	}
	r := handshakePipe(t, client, server)
	cErr, sErr := r.cErr, r.sErr
	if sErr == nil || !strings.Contains(sErr.Error(), "no compatible encryption methods") {
		t.Errorf("server handshake: %v, want no compatible encryption methods", sErr)
	}
	if cErr == nil {
		t.Error("client handshake succeeded with encryption required and only BLOWFISH in common")
	}
}

// TestClientRefusesEnactedCryptoWithoutKey: a server that enacts encryption
// but offers no key exchange must not get the session in the clear. HTCondor's
// client fails it ("enable_enc no key to use").
func TestClientRefusesEnactedCryptoWithoutKey(t *testing.T) {
	GetSessionCache().Clear()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	// A server that reads the request, answers Encryption=YES with no
	// ECDHPublicKey, and authorizes the command.
	go func() {
		ctx := context.Background()
		st := stream.NewStream(serverConn)
		req := message.NewMessageFromStream(st)
		if _, err := req.GetInt(ctx); err != nil {
			return
		}
		if _, err := req.GetClassAd(ctx); err != nil {
			return
		}
		reply := func(attrs map[string]string) {
			ad := classad.New()
			for k, v := range attrs {
				_ = ad.Set(k, v)
			}
			m := message.NewMessageForStream(st)
			_ = m.PutClassAd(ctx, ad)
			_ = m.FinishMessage(ctx)
		}
		reply(map[string]string{
			"Authentication": "NO", "Encryption": "YES", "Integrity": "YES",
			"CryptoMethods": "AES", "CryptoMethodsList": "AES", "Enact": "YES",
		})
		reply(map[string]string{"Sid": "fake:1", "User": "unauthenticated@unmapped", "ValidCommands": "60020", "ReturnCode": "AUTHORIZED"})
	}()

	client := &SecurityConfig{
		AuthMethods: []AuthMethod{AuthClaimToBe}, Authentication: SecurityOptional,
		CryptoMethods: []CryptoMethod{CryptoAES}, Encryption: SecurityOptional, Integrity: SecurityOptional, Command: 60020,
	}
	cs := stream.NewStream(clientConn)
	_, err := NewAuthenticator(client, cs).ClientHandshake(context.Background())
	if err == nil {
		t.Fatalf("client accepted a session the server enacted encryption on without a key (stream encrypted: %t)", cs.IsEncrypted())
	}
	if !strings.Contains(err.Error(), "no session key") {
		t.Errorf("client error = %v, want it to name the missing session key", err)
	}
}

// TestServerRefusesEnactedCryptoWithoutKey: a client that offers no key
// exchange cannot get a session the server enacted integrity on in the clear.
// HTCondor's server fails it (EnableCrypto has no key).
func TestServerRefusesEnactedCryptoWithoutKey(t *testing.T) {
	GetSessionCache().Clear()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	// A client that requires integrity but sends no ECDHPublicKey, then reads
	// whatever the server sends.
	go func() {
		ctx := context.Background()
		st := stream.NewStream(clientConn)
		ad := classad.New()
		for k, v := range map[string]string{
			"AuthMethods": "CLAIMTOBE", "Authentication": "NEVER", "AuthenticationNew": "NEVER",
			"CryptoMethods": "AES", "Encryption": "OPTIONAL", "Integrity": "REQUIRED",
			"NewSession": "YES", "Enact": "NO",
		} {
			_ = ad.Set(k, v)
		}
		_ = ad.Set("Command", commands.DC_NOP_READ)
		m := message.NewMessageForStream(st)
		_ = m.PutInt(ctx, commands.DC_AUTHENTICATE)
		_ = m.PutClassAd(ctx, ad)
		_ = m.FinishMessage(ctx)
		for {
			if _, err := message.NewMessageFromStream(st).GetClassAd(ctx); err != nil {
				return
			}
		}
	}()

	server := &SecurityConfig{
		AuthMethods: []AuthMethod{AuthClaimToBe}, Authentication: SecurityOptional,
		CryptoMethods: []CryptoMethod{CryptoAES}, Encryption: SecurityOptional, Integrity: SecurityOptional,
	}
	ss := stream.NewStream(serverConn)
	_, err := NewAuthenticator(server, ss).ServerHandshake(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no session key") {
		t.Fatalf("server handshake: %v, want it refused for want of a session key (stream encrypted: %t)", err, ss.IsEncrypted())
	}
}
