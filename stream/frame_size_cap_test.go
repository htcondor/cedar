package stream

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// readFrameHeader returns the end flag and declared length of the next frame
// the stream puts on the wire.
func readFrameHeader(t *testing.T, conn net.Conn) (byte, uint32) {
	t.Helper()
	hdr := make([]byte, NormalHeaderSize)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	return hdr[0], binary.BigEndian.Uint32(hdr[1:5])
}

// An encrypted frame must not be emitted with an on-wire length above
// MaxMessageSize. The declared length in the header is the post-encryption
// size, and that is the number the receiver checks, so a plaintext payload at
// exactly the cap used to go out 32 bytes over it and be killed by the peer.
func TestSendRejectsOversizeOnWireLengthWhenEncrypted(t *testing.T) {
	peer, s := encryptedStreamPair(t)

	// Capture the header, then keep draining. net.Pipe is unbuffered, so a
	// reader that stops after the header would leave a wrongly-emitted frame
	// blocked mid-write and turn this test into a hang instead of a failure.
	wire := make(chan uint32, 1)
	go func() {
		buf := make([]byte, NormalHeaderSize)
		if _, err := io.ReadFull(peer, buf); err != nil {
			close(wire)
			return
		}
		wire <- binary.BigEndian.Uint32(buf[1:5])
		_, _ = io.Copy(io.Discard, peer)
	}()

	err := s.SendMessage(context.Background(), make([]byte, MaxMessageSize))
	if err == nil {
		if n, ok := <-wire; ok {
			t.Fatalf("sent an oversize encrypted frame: on-wire length %d, cap %d", n, MaxMessageSize)
		}
		t.Fatal("SendMessage accepted a plaintext payload whose encrypted frame exceeds the cap")
	}
	if !strings.Contains(err.Error(), "message too large") {
		t.Errorf("error = %q, want it to report the message as too large", err)
	}
}

// The largest plaintext that still fits under the cap once encrypted must
// still be sendable, and must declare a length at or below the cap. This is
// the test that catches "fix the asymmetry by rejecting everything near it".
func TestSendAcceptsLargestEncryptableFrame(t *testing.T) {
	peer, s := encryptedStreamPair(t)

	// First frame of the stream carries the IV as well as the GCM tag.
	plaintext := MaxMessageSize - 32

	type hdrResult struct {
		end byte
		n   uint32
	}
	got := make(chan hdrResult, 1)
	go func() {
		end, n := readFrameHeader(t, peer)
		got <- hdrResult{end, n}
		_, _ = io.CopyN(io.Discard, peer, int64(n))
	}()

	if err := s.SendMessage(context.Background(), make([]byte, plaintext)); err != nil {
		t.Fatalf("a %d-byte plaintext should fit under the %d-byte cap once encrypted: %v",
			plaintext, MaxMessageSize, err)
	}

	select {
	case h := <-got:
		if h.n > MaxMessageSize {
			t.Errorf("on-wire length %d exceeds the cap %d", h.n, MaxMessageSize)
		}
		if h.end != EndFlagComplete {
			t.Errorf("end flag = %d, want %d", h.end, EndFlagComplete)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no frame reached the wire")
	}
}

// Without encryption the on-wire length is the plaintext length, so the cap is
// unchanged: a full MaxMessageSize payload is still legal.
func TestSendAcceptsMaxMessageSizeWhenPlaintext(t *testing.T) {
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	s := NewStream(local)

	got := make(chan uint32, 1)
	go func() {
		_, n := readFrameHeader(t, peer)
		got <- n
		_, _ = io.CopyN(io.Discard, peer, int64(n))
	}()

	if err := s.SendMessage(context.Background(), make([]byte, MaxMessageSize)); err != nil {
		t.Fatalf("a full-size plaintext frame must still be legal: %v", err)
	}

	select {
	case n := <-got:
		if n != MaxMessageSize {
			t.Errorf("on-wire length = %d, want %d", n, MaxMessageSize)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no frame reached the wire")
	}
}
