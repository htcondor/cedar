package security

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

// TestEncryptedSessionResumptionDataFlow establishes an AES-encrypted CEDAR
// session, then reconnects and resumes it, and after each handshake exchanges an
// encrypted application message. This exercises the real fast path (session
// resumption over encrypted transport) that the collector's daemons rely on --
// not just that the handshake doesn't panic, but that data actually flows.
func TestEncryptedSessionResumptionDataFlow(t *testing.T) {
	GetSessionCache().Clear()
	defer GetSessionCache().Clear()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// The client keys its session cache by PeerName, so a stable PeerName makes
	// the second dial find (and resume) the first dial's session -- matching how
	// the htcondor client resumes against a fixed collector address.
	cfg := func(peerName string) *SecurityConfig {
		return &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthNone},
			Authentication: SecurityOptional,
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Encryption:     SecurityRequired,
			Integrity:      SecurityRequired,
			Command:        commands.DC_NOP,
			PeerName:       peerName,
		}
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				st := stream.NewStream(conn)
				auth := NewAuthenticator(cfg(""), st)
				neg, err := auth.ServerHandshake(context.Background())
				if err != nil {
					t.Errorf("server handshake: %v", err)
					return
				}
				if !neg.Encryption {
					t.Errorf("server: session is not encrypted")
				}
				// Send one encrypted application message.
				ad := classad.New()
				_ = ad.Set("Hello", "world")
				msg := message.NewMessageForStream(st)
				if err := msg.PutClassAd(context.Background(), ad); err != nil {
					t.Errorf("server put: %v", err)
					return
				}
				if err := msg.FinishMessage(context.Background()); err != nil {
					t.Errorf("server finish: %v", err)
				}
				time.Sleep(50 * time.Millisecond)
			}()
		}
	}()

	dial := func(label string, wantResumed bool) {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("%s: dial: %v", label, err)
		}
		defer func() { _ = conn.Close() }()
		st := stream.NewStream(conn)
		auth := NewAuthenticator(cfg("bench-server"), st)
		neg, err := auth.ClientHandshake(context.Background())
		if err != nil {
			t.Fatalf("%s: client handshake: %v", label, err)
		}
		if !neg.Encryption || !st.IsEncrypted() {
			t.Fatalf("%s: transport not encrypted", label)
		}
		if neg.SessionResumed != wantResumed {
			t.Fatalf("%s: SessionResumed=%v, want %v", label, neg.SessionResumed, wantResumed)
		}
		// Read the server's encrypted application message.
		rmsg := message.NewMessageFromStream(st)
		ad, err := rmsg.GetClassAd(context.Background())
		if err != nil {
			t.Fatalf("%s: read encrypted ad: %v", label, err)
		}
		if v, _ := ad.EvaluateAttrString("Hello"); v != "world" {
			t.Fatalf("%s: decrypted ad = %q, want Hello=world", label, v)
		}
	}

	dial("first (full handshake)", false)
	time.Sleep(100 * time.Millisecond)
	dial("second (resumed)", true)
}
