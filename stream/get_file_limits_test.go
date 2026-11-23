package stream

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// writeFrame puts one complete plaintext frame on the wire. Errors are
// ignored: the tests below deliberately leave the last frame unread, and
// net.Pipe is unbuffered, so that write only unblocks when the cleanup
// closes the connection.
func writeFrame(conn net.Conn, payload []byte) {
	frame := make([]byte, NormalHeaderSize+len(payload))
	frame[0] = EndFlagComplete
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[NormalHeaderSize:], payload)
	_, _ = conn.Write(frame)
}

func fileSizeFrame(size uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, size)
	return b
}

func eofMarkerFrame() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, 666)
	return b
}

// Nothing ties a frame's length to the size the sender declared, so a peer
// that declares a small file and then sends a large frame must not get that
// frame written to disk in full.
func TestGetFileClampsChunksToDeclaredSize(t *testing.T) {
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	s := NewStream(local)

	const declared = 10
	oversize := bytes.Repeat([]byte("A"), 100)

	go func() {
		writeFrame(peer, fileSizeFrame(declared))
		writeFrame(peer, oversize)
		writeFrame(peer, eofMarkerFrame())
	}()

	path := filepath.Join(t.TempDir(), "clamped.dat")
	n, err := s.GetFile(context.Background(), path)
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if n != declared {
		t.Errorf("GetFile reported %d bytes for a %d-byte file", n, declared)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(got) != declared {
		t.Errorf("wrote %d bytes to disk for a %d-byte declared file", len(got), declared)
	}
}

// A declared size above 2^63 arrives as a negative int64. Left alone it skips
// the receive loop entirely and reports success over an empty file.
func TestGetFileRejectsNegativeDeclaredSize(t *testing.T) {
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	s := NewStream(local)

	go func() {
		writeFrame(peer, fileSizeFrame(1<<63))
		// So an unenforced size reaches a clean end instead of blocking here.
		writeFrame(peer, eofMarkerFrame())
	}()

	path := filepath.Join(t.TempDir(), "negative.dat")
	n, err := s.GetFile(context.Background(), path)
	if err == nil {
		t.Fatalf("accepted a declared size of 2^63 bytes, returned %d", n)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("created %s for a size that was refused (stat: %v)", path, statErr)
	}
}

// The ordinary case must be unaffected: a file whose frames add up to exactly
// the declared size still transfers whole.
func TestGetFileAcceptsExactlyDeclaredSize(t *testing.T) {
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	s := NewStream(local)

	payload := bytes.Repeat([]byte("cedar"), 2000)

	go func() {
		writeFrame(peer, fileSizeFrame(uint64(len(payload))))
		writeFrame(peer, payload[:len(payload)/2])
		writeFrame(peer, payload[len(payload)/2:])
		writeFrame(peer, eofMarkerFrame())
	}()

	path := filepath.Join(t.TempDir(), "exact.dat")
	n, err := s.GetFile(context.Background(), path)
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if n != int64(len(payload)) {
		t.Errorf("GetFile reported %d bytes, want %d", n, len(payload))
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("file contents differ from what was sent (%d bytes on disk, %d sent)", len(got), len(payload))
	}
}
