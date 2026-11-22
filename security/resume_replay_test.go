package security

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

// recordingConn copies every byte written through it.
type recordingConn struct {
	net.Conn
	mu  sync.Mutex
	out bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.out.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recordingConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.out.Bytes()...)
}

func resumeReplayConfig(peerName string) *SecurityConfig {
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

// putAd sends one ClassAd message.
func putAd(st *stream.Stream, attr, val string) error {
	ad := classad.New()
	_ = ad.Set(attr, val)
	msg := message.NewMessageForStream(st)
	if err := msg.PutClassAd(context.Background(), ad); err != nil {
		return err
	}
	return msg.FinishMessage(context.Background())
}

// getAd reads one ClassAd message and returns attr's value.
func getAd(st *stream.Stream, attr string) (string, error) {
	ad, err := message.NewMessageFromStream(st).GetClassAd(context.Background())
	if err != nil {
		return "", err
	}
	v, _ := ad.EvaluateAttrString(attr)
	return v, nil
}

// TestResumedSessionReplayRejectedByServer records the bytes a client sends
// on a resumed, AES-GCM-encrypted connection (the resume request and an
// encrypted command payload) and replays them verbatim on a new connection.
// The server must not accept the replayed payload: its resume reply carries a
// fresh nonce, which enters the handshake digest bound into the AES-GCM AAD.
func TestResumedSessionReplayRejectedByServer(t *testing.T) {
	GetSessionCache().Clear()
	defer GetSessionCache().Clear()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// One result per accepted connection: the payload the server decrypted,
	// or the error that stopped it and whether the resume handshake succeeded.
	type result struct {
		resumed bool
		payload string
		err     error
	}
	results := make(chan result, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				st := stream.NewStream(conn)
				neg, err := NewAuthenticator(resumeReplayConfig(""), st).ServerHandshake(context.Background())
				if err != nil {
					results <- result{err: err}
					return
				}
				v, err := getAd(st, "Payload")
				results <- result{resumed: neg.SessionResumed, payload: v, err: err}
			}()
		}
	}()

	waitResult := func(label string) result {
		select {
		case r := <-results:
			return r
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: server produced no result", label)
			return result{}
		}
	}

	dial := func(label string, wantResumed bool) []byte {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("%s: dial: %v", label, err)
		}
		defer func() { _ = raw.Close() }()
		conn := &recordingConn{Conn: raw}
		st := stream.NewStream(conn)
		neg, err := NewAuthenticator(resumeReplayConfig("replay-server"), st).ClientHandshake(context.Background())
		if err != nil {
			t.Fatalf("%s: client handshake: %v", label, err)
		}
		if neg.SessionResumed != wantResumed || !st.IsEncrypted() {
			t.Fatalf("%s: SessionResumed=%v encrypted=%v, want resumed=%v and encrypted", label, neg.SessionResumed, st.IsEncrypted(), wantResumed)
		}
		if err := putAd(st, "Payload", label); err != nil {
			t.Fatalf("%s: send payload: %v", label, err)
		}
		if r := waitResult(label); r.err != nil || r.payload != label {
			t.Fatalf("%s: server got payload %q, err %v", label, r.payload, r.err)
		}
		return conn.written()
	}

	dial("first", false)
	recorded := dial("resumed", true)

	// Replay the resumed conversation's client bytes on a fresh connection.
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	go func() { _, _ = io.Copy(io.Discard, raw) }()
	if _, err := raw.Write(recorded); err != nil {
		t.Fatalf("replay write: %v", err)
	}
	// The replayed resume request itself is still accepted (the session id
	// is valid); what must fail is the encrypted payload that follows.
	r := waitResult("replay")
	if !r.resumed {
		t.Fatalf("replayed resume request did not resume the session: %v", r.err)
	}
	if r.err == nil {
		t.Fatalf("server accepted a replayed resumed-session payload %q", r.payload)
	}
	t.Logf("replay rejected: %v", r.err)
}

// TestResumedSessionReplayRejectedByClient is the reverse direction: the
// bytes a server sent on a resumed connection are replayed to a client that
// resumes the same session for the same command. The client must not accept
// the replayed encrypted reply: its resume request carries a fresh nonce.
func TestResumedSessionReplayRejectedByClient(t *testing.T) {
	GetSessionCache().Clear()
	defer GetSessionCache().Clear()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	recordings := make(chan []byte, 8)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = raw.Close() }()
				_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
				conn := &recordingConn{Conn: raw}
				st := stream.NewStream(conn)
				if _, err := NewAuthenticator(resumeReplayConfig(""), st).ServerHandshake(context.Background()); err != nil {
					t.Errorf("server handshake: %v", err)
					return
				}
				if err := putAd(st, "Reply", "fresh"); err != nil {
					t.Errorf("server reply: %v", err)
					return
				}
				recordings <- conn.written()
			}()
		}
	}()

	resume := func(label, addr string, wantResumed bool) (string, error) {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("%s: dial: %v", label, err)
		}
		defer func() { _ = raw.Close() }()
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		st := stream.NewStream(raw)
		neg, err := NewAuthenticator(resumeReplayConfig("replay-server"), st).ClientHandshake(context.Background())
		if err != nil {
			t.Fatalf("%s: client handshake: %v", label, err)
		}
		if neg.SessionResumed != wantResumed {
			t.Fatalf("%s: SessionResumed=%v, want %v", label, neg.SessionResumed, wantResumed)
		}
		return getAd(st, "Reply")
	}
	nextRecording := func(label string) []byte {
		select {
		case b := <-recordings:
			return b
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: no server recording", label)
			return nil
		}
	}

	for _, step := range []struct {
		label   string
		resumed bool
	}{{"first", false}, {"resumed", true}} {
		if v, err := resume(step.label, ln.Addr().String(), step.resumed); err != nil || v != "fresh" {
			t.Fatalf("%s: reply %q, err %v", step.label, v, err)
		}
	}
	_ = nextRecording("first")
	recorded := nextRecording("resumed")

	// A second listener answers every connection with the recorded server
	// bytes. The client resumes the same session (same PeerName) against it.
	replayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replayLn.Close() }()
	go func() {
		conn, err := replayLn.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write(recorded)
		_, _ = io.Copy(io.Discard, conn) // until the client hangs up
	}()

	v, err := resume("replay", replayLn.Addr().String(), true)
	if err == nil {
		t.Fatalf("client accepted a replayed resumed-session reply %q", v)
	}
	t.Logf("replay rejected: %v", err)
}
