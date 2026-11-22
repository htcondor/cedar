package security

import (
	"context"
	"net"
	"testing"

	"github.com/htcondor/cedar/stream"
)

// TestOptionalEncryptionRecordedWhenActive is a regression test for the bug that made
// SEC_DEFAULT_ENCRYPTION=OPTIONAL unusable: when the negotiated encryption LEVEL is only
// OPTIONAL/PREFERRED, the decision flag (negotiation.Encryption) starts false, but ECDH
// still runs and the stream ends up AES-GCM encrypted. The negotiation must then RECORD
// Encryption=true so a server enforcing a required encryption/integrity level for a command
// does not reject a session that is genuinely encrypted.
//
// Run over a real TCP socket (the transport the daemon uses) with Integrity=REQUIRED, which
// is exactly the htcondordb default that triggered the rejection.
func TestOptionalEncryptionRecordedWhenActive(t *testing.T) {
	GetSessionCache().Clear()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	cfg := func() *SecurityConfig {
		return &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthFS},
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Authentication: SecurityRequired,
			Encryption:     SecurityOptional, // the level under test
			Integrity:      SecurityRequired, // htcondordb default; needs authenticated encryption
			TrustDomain:    "repro.local",
		}
	}

	type res struct {
		neg *SecurityNegotiation
		st  *stream.Stream
		err error
	}
	sCh := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			sCh <- res{err: err}
			return
		}
		ss := stream.NewStream(c)
		neg, err := NewAuthenticator(cfg(), ss).ServerHandshake(context.Background())
		sCh <- res{neg: neg, st: ss, err: err}
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cs := stream.NewStream(cc)
	cNeg, err := NewAuthenticator(cfg(), cs).ClientHandshake(context.Background())
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	sr := <-sCh
	if sr.err != nil {
		t.Fatalf("server handshake: %v", sr.err)
	}

	// The stream must actually be encrypted on both ends...
	if !cs.IsEncrypted() || !sr.st.IsEncrypted() {
		t.Fatalf("stream not encrypted: client=%v server=%v", cs.IsEncrypted(), sr.st.IsEncrypted())
	}
	// ...and the negotiated outcome must RECORD that (the fix). Before the fix these were
	// false under OPTIONAL, which made the server reject required-encryption/integrity
	// commands on a genuinely-encrypted session.
	if !cNeg.Encryption {
		t.Error("client negotiation.Encryption=false but the stream is encrypted (OPTIONAL bug)")
	}
	if !sr.neg.Encryption {
		t.Error("server negotiation.Encryption=false but the stream is encrypted (OPTIONAL bug)")
	}
}
