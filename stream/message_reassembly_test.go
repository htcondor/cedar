package stream

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// writePartialFrames writes n plaintext partial frames of payload bytes each
// and then closes the connection. The close is what keeps a missing cap from
// turning these tests into a hang: the reader runs out of input and reports a
// read error, which is a different error than the one being asserted.
func writePartialFrames(conn net.Conn, n, payload int) {
	frame := make([]byte, NormalHeaderSize+payload)
	frame[0] = EndFlagPartial
	binary.BigEndian.PutUint32(frame[1:5], uint32(payload))
	for i := 0; i < n; i++ {
		if _, err := conn.Write(frame); err != nil {
			break
		}
	}
	_ = conn.Close()
}

// A peer that never sets the end flag must not be able to grow the reassembly
// buffer without bound. Every frame here is a legal MaxMessageSize frame; it is
// their sum that has to be refused.
func TestStartMessageReadRejectsEndlessPartialFrames(t *testing.T) {
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	s := NewStream(local)

	go writePartialFrames(peer, MaxTotalMessageSize/MaxMessageSize+4, MaxMessageSize)

	err := s.StartMessageRead(context.Background())
	if err == nil {
		t.Fatalf("accepted an unterminated message: buffered %d bytes, cap is %d",
			len(s.receiveBuffer), MaxTotalMessageSize)
	}
	if !strings.Contains(err.Error(), "message too large") {
		t.Fatalf("error = %q, want the reassembly cap to stop the read (the peer running out of frames stopped it instead)", err)
	}
	if len(s.receiveBuffer) > MaxTotalMessageSize {
		t.Errorf("buffered %d bytes past the %d-byte cap", len(s.receiveBuffer), MaxTotalMessageSize)
	}
}

// The same bound applies to readNextFrame's working twin.
func TestReceiveCompleteMessageRejectsEndlessPartialFrames(t *testing.T) {
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	s := NewStream(local)

	go writePartialFrames(peer, MaxTotalMessageSize/MaxMessageSize+4, MaxMessageSize)

	data, err := s.ReceiveCompleteMessage(context.Background())
	if err == nil {
		t.Fatalf("accepted an unterminated message of %d bytes, cap is %d", len(data), MaxTotalMessageSize)
	}
	if !strings.Contains(err.Error(), "message too large") {
		t.Fatalf("error = %q, want the reassembly cap to stop the read (the peer running out of frames stopped it instead)", err)
	}
}

// A multi-frame message that stays under the cap must still reassemble: the
// cap must not be mistaken for "refuse anything that spans frames".
func TestMultiFrameMessageUnderCapStillReassembles(t *testing.T) {
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	sender, receiver := NewStream(peer), NewStream(local)
	ctx := context.Background()

	payload := []byte("the quick brown fox")
	sent := make(chan error, 1)
	go func() {
		if err := sender.SendPartialMessage(ctx, payload); err != nil {
			sent <- err
			return
		}
		sent <- sender.SendMessage(ctx, payload)
	}()

	got, err := receiver.ReceiveCompleteMessage(ctx)
	if err != nil {
		t.Fatalf("ReceiveCompleteMessage: %v", err)
	}
	if want := string(payload) + string(payload); string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if err := <-sent; err != nil {
		t.Fatalf("send: %v", err)
	}
}
