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

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/htcondor/cedar/ccb"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// TestClaimSessionLoopback exercises the Stage-2 keystone end to end: a startd
// hands out a claim id embedding a pre-shared security session; both the
// "schedd" (client) and the "startd" (server) import that claim into their own
// caches (deriving the SAME AES key from the SAME secret); the client then
// sends a claim command using the session with NO DC_AUTHENTICATE full
// handshake, and the payload rides the session's AES-GCM key.
//
// It asserts: (1) the session was resumed rather than freshly authenticated,
// (2) the stream is encrypted, (3) the server handler sees the match-session
// identity carried by the claim (not a fresh FS/SSL identity), and (4) a
// ClassAd request/reply round-trips over the encrypted stream.
func TestClaimSessionLoopback(t *testing.T) {
	const (
		serverAddr = "<127.0.0.1:9618>"
		claimCmd   = commands.REQUEST_CLAIM
		// A startd claim id: <sinful>#startd_bday#seq#[session_info]secret_key.
		sessionInfo = `[Encryption="YES";Integrity="YES";CryptoMethods="AES";]`
		secretKey   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	claimID := serverAddr + "#1700000000#7#" + sessionInfo + secretKey

	// Two independent caches, one per "daemon" -- proving the key is derived
	// (not shared in memory) and interoperates.
	clientCache := security.NewSessionCache()
	serverCache := security.NewSessionCache()

	// Schedd (client) imports the claim: its peer is the startd (execute side).
	sesid, err := security.ImportClaimSession(clientCache, claimID, security.ClaimSessionOptions{
		PeerAddr:           serverAddr,
		PeerFQU:            security.ExecuteSideMatchSessionFQU,
		ExtraValidCommands: []int{claimCmd},
	})
	if err != nil {
		t.Fatalf("client ImportClaimSession: %v", err)
	}

	// Startd (server) imports the same claim: its peer is the schedd (submit side).
	srvSesid, err := security.ImportClaimSession(serverCache, claimID, security.ClaimSessionOptions{
		PeerAddr: serverAddr,
		PeerFQU:  security.SubmitSideMatchSessionFQU,
	})
	if err != nil {
		t.Fatalf("server ImportClaimSession: %v", err)
	}
	if sesid != srvSesid {
		t.Fatalf("session ids differ: client %q, server %q", sesid, srvSesid)
	}

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   serverCache,
	})

	type seen struct {
		user     string
		cmd      int
		resumed  bool
		encField bool
		hi       string
	}
	handlerDone := make(chan seen, 1)
	handlerErr := make(chan error, 1)
	srv.Handle(claimCmd, func(ctx context.Context, c *Conn) error {
		req, err := ccb.ReadControlAd(ctx, c.Stream)
		if err != nil {
			handlerErr <- err
			return err
		}
		reply := ccb.NewAd(map[string]any{"AuthenticatedUser": c.Negotiation.User})
		if err := ccb.WriteControlAd(ctx, c.Stream, reply); err != nil {
			handlerErr <- err
			return err
		}
		handlerDone <- seen{
			user:     c.Negotiation.User,
			cmd:      c.Command,
			resumed:  c.Negotiation.SessionResumed,
			encField: c.Stream.IsEncrypted(),
			hi:       ccb.AdString(req, "Hello"),
		}
		return nil
	}, "DAEMON")

	go func() { _ = srv.ServeConn(ctx, serverConn) }()

	// Client resumes the pre-registered claim session by naming it explicitly
	// (mirrors CEDAR setSecSessionId). No full authentication is performed.
	cliStream := stream.NewStream(clientConn)
	cliStream.SetPeerAddr(serverAddr)
	auth := security.NewAuthenticator(&security.SecurityConfig{
		Command:      claimCmd,
		PeerName:     serverAddr,
		SessionCache: clientCache,
		SessionID:    sesid,
	}, cliStream)
	neg, err := auth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("client handshake (claim session resume): %v", err)
	}

	// (1) The client resumed the session rather than authenticating fresh.
	if !neg.SessionResumed {
		t.Error("client negotiation not marked as resumed (a full handshake occurred)")
	}
	if !auth.WasSessionResumed() {
		t.Error("authenticator reports no session resumption")
	}
	if neg.NegotiatedAuth != security.AuthMethod(security.AuthMethodMatch) {
		t.Errorf("negotiated auth = %q, want MATCH (claim session)", neg.NegotiatedAuth)
	}
	// (2) The stream is encrypted with the claim's AES key.
	if !cliStream.IsEncrypted() {
		t.Error("client stream is not encrypted")
	}

	// (4) Round-trip a command over the encrypted session.
	if err := ccb.WriteControlAd(ctx, cliStream, ccb.NewAd(map[string]any{"Hello": "world"})); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply, err := ccb.ReadControlAd(ctx, cliStream)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}

	select {
	case err := <-handlerErr:
		t.Fatalf("handler error: %v", err)
	case s := <-handlerDone:
		if s.cmd != claimCmd {
			t.Errorf("handler dispatched cmd=%d, want %d", s.cmd, claimCmd)
		}
		if !s.resumed {
			t.Error("server did not resume the session (full handshake occurred)")
		}
		if !s.encField {
			t.Error("server stream not encrypted")
		}
		// (3) The server sees the match-session identity carried by the claim.
		if s.user != security.SubmitSideMatchSessionFQU {
			t.Errorf("server saw user %q, want %q", s.user, security.SubmitSideMatchSessionFQU)
		}
		if s.hi != "world" {
			t.Errorf("server saw request Hello=%q, want world", s.hi)
		}
	case <-ctx.Done():
		t.Fatalf("handler did not complete: %v", ctx.Err())
	}

	if got := ccb.AdString(reply, "AuthenticatedUser"); got != security.SubmitSideMatchSessionFQU {
		t.Errorf("reply AuthenticatedUser = %q, want %q", got, security.SubmitSideMatchSessionFQU)
	}
}
