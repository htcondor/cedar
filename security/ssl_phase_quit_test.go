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
	"errors"
	"strings"
	"testing"
	"time"
)

// TestSSLPhaseOpFailureTellsPeer: when this side's TLS operation fails on a
// round in which it receives rather than sends, it has carried no status to
// the peer, so it must say QUITTING before it returns -- the invariant every
// other failure exit in runPhase keeps. Without it the peer blocks until its
// own handshake deadline, and so does this side's caller, which goes back to
// waiting for the peer's next authentication attempt.
func TestSSLPhaseOpFailureTellsPeer(t *testing.T) {
	ssl, peer := phasePair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Receive-first phase (the server handshake, the client session key, the
	// server SciToken exchange) whose operation fails on round 0.
	boom := errors.New("tls: bad record MAC")
	done := make(chan error, 1)
	go func() { done <- ssl.runPhase(ctx, "probe", false, false, func() error { return boom }) }()

	if err := peer.sendMessage(ctx, AuthSSLReceiving, nil); err != nil {
		t.Fatalf("peer send: %v", err)
	}

	// Bounded: before the fix nothing is ever sent, and an unbounded read
	// here would hang the test rather than fail it.
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcancel()
	status, data, err := peer.receiveMessage(rctx)
	if err != nil {
		t.Fatalf("peer receive after this side's TLS failure: %v; want AUTH_SSL_QUITTING", err)
	}
	if status != AuthSSLQuitting {
		t.Errorf("peer saw status %d, want AuthSSLQuitting (%d)", status, AuthSSLQuitting)
	}
	if len(data) != 0 {
		t.Errorf("QUITTING carried %d bytes, want none", len(data))
	}

	if err := <-done; err == nil || !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("runPhase = %v, want the operation's own failure", err)
	}
}

// TestSSLPhaseOpFailureOnSendRoundDoesNotDoubleSend: on a send round the
// round's own message already carried QUITTING, so the peer must not be told
// twice -- a second message would leave the stream one message ahead of a
// peer that has already stopped reading this phase.
func TestSSLPhaseOpFailureOnSendRoundDoesNotDoubleSend(t *testing.T) {
	ssl, peer := phasePair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- ssl.runPhase(ctx, "probe", true, true, func() error { return errors.New("boom") })
	}()

	status, _, err := peer.receiveMessage(ctx)
	if err != nil {
		t.Fatalf("peer receive: %v", err)
	}
	if status != AuthSSLQuitting {
		t.Fatalf("peer saw status %d on the send round, want AuthSSLQuitting (%d)", status, AuthSSLQuitting)
	}
	if err := <-done; err == nil {
		t.Fatal("runPhase = nil, want the operation's failure")
	}

	// Nothing more may follow on the stream for this phase.
	rctx, rcancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer rcancel()
	if status, _, err := peer.receiveMessage(rctx); err == nil {
		t.Errorf("a second message (status %d) followed the send round's QUITTING", status)
	}
}
