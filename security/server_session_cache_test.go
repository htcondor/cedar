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

// SecurityConfig.SessionCache is documented as a replacement for the global
// cache, and ClientHandshake, storeClientSession and handleSessionResumption
// all honour it. The server's own store must too, or a session negotiated
// under an isolated cache is resumable by every other server in the process
// and the embedder's own Invalidate never reaches its own sessions.
func TestStoreSessionHonoursTheConfiguredCache(t *testing.T) {
	GetSessionCache().Clear()
	t.Cleanup(func() { GetSessionCache().Clear() })

	cache := NewSessionCache()
	cfg := &SecurityConfig{
		Authentication: SecurityRequired,
		Encryption:     SecurityRequired,
		Integrity:      SecurityRequired,
		SessionCache:   cache,
	}
	s := stream.NewStream(nil)
	s.SetPeerAddr("<10.0.0.7:9618>")

	neg := &SecurityNegotiation{
		ServerConfig:     cfg,
		NegotiatedAuth:   AuthFS,
		NegotiatedCrypto: CryptoAES,
		SessionId:        "configured-cache-session",
		Authentication:   true,
		User:             "someone@example.com",
	}
	neg.setSharedSecret(make([]byte, 32))

	NewAuthenticator(cfg, s).storeSession(neg, neg.SessionId, 3600, 3600)

	if _, ok := cache.LookupNonExpired(neg.SessionId); !ok {
		t.Errorf("session %q is not in the configured cache", neg.SessionId)
	}
	if _, ok := GetSessionCache().LookupNonExpired(neg.SessionId); ok {
		t.Errorf("session %q was written to the process-global cache", neg.SessionId)
	}
}

// resumeAgainstIsolatedServer runs one session-resumption attempt against a
// server whose SessionCache holds nothing, and reports the ReturnCode the
// server answered with and the identity it granted.
func resumeAgainstIsolatedServer(t *testing.T, sessionID string) (returnCode, user string, serverErr error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	type result struct {
		err  error
		user string
	}
	done := make(chan result, 1)
	go func() {
		ss := stream.NewStream(serverConn)
		neg, err := NewAuthenticator(&SecurityConfig{SessionCache: NewSessionCache()}, ss).ServerHandshake(ctx)
		if err != nil {
			_ = serverConn.Close()
			done <- result{err: err}
			return
		}
		done <- result{user: neg.User}
	}()

	cs := stream.NewStream(clientConn)
	msg := message.NewMessageForStream(cs)
	resumeAd := classad.New()
	_ = resumeAd.Set("Command", 60020)
	_ = resumeAd.Set("UseSession", "YES")
	_ = resumeAd.Set("Sid", sessionID)
	_ = resumeAd.Set("ResumeResponse", true)
	if err := msg.PutInt(ctx, commands.DC_AUTHENTICATE); err != nil {
		t.Fatal(err)
	}
	if err := msg.PutClassAd(ctx, resumeAd); err != nil {
		t.Fatal(err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		t.Fatal(err)
	}

	resp, err := message.NewMessageFromStream(cs).GetClassAd(ctx)
	if err != nil {
		t.Fatalf("reading resume response: %v", err)
	}
	rc, _ := resp.EvaluateAttrString("ReturnCode")
	r := <-done
	return rc, r.user, r.err
}

// A server given its own cache must not resume a session out of the global
// one -- that is the isolation the field buys. The exception is a session
// inherited from condor_master, or minted for a child: those are registered
// in the global cache and nowhere else, so refusing them would break the
// family session a daemon under the master depends on.
func TestServerResumesOnlyInheritedSessionsFromTheGlobalCache(t *testing.T) {
	for _, tc := range []struct {
		name       string
		inherited  bool
		wantResume bool
	}{
		{"negotiated by another server", false, false},
		{"inherited from the parent daemon", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			GetSessionCache().Clear()
			t.Cleanup(func() { GetSessionCache().Clear() })

			entry := NewSessionEntry(
				"global:0123abcd", "<10.0.0.5:9618>",
				&KeyInfo{Data: make([]byte, 32), Protocol: "AESGCM"},
				authenticatedPolicy(t), time.Now().Add(time.Hour), time.Hour, "",
			)
			entry.SetInherited(tc.inherited)
			GetSessionCache().Store(entry)

			rc, user, serverErr := resumeAgainstIsolatedServer(t, entry.ID())

			if !tc.wantResume {
				if rc != "SID_NOT_FOUND" {
					t.Errorf("ReturnCode = %q, want SID_NOT_FOUND", rc)
				}
				if serverErr == nil {
					t.Fatalf("server resumed another cache's session as %q", user)
				}
				if user == "victim@example.com" {
					t.Fatalf("server conferred %q from a session its own cache never held", user)
				}
				return
			}

			if serverErr != nil {
				t.Fatalf("server refused the inherited session: %v", serverErr)
			}
			if user != "victim@example.com" {
				t.Errorf("resumed user = %q, want the inherited session's identity", user)
			}
		})
	}
}
