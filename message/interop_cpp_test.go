package message

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/htcondor/cedar/stream"
)

// bytesConn is a read-only net.Conn backed by a fixed byte slice, so a golden
// wire vector can be fed to a real stream.Stream (which decrypts) without a socket.
type bytesConn struct{ r *byteReader }

func (c bytesConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c bytesConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c bytesConn) Close() error                     { return nil }
func (c bytesConn) LocalAddr() net.Addr              { return nil }
func (c bytesConn) RemoteAddr() net.Addr             { return nil }
func (c bytesConn) SetDeadline(time.Time) error      { return nil }
func (c bytesConn) SetReadDeadline(time.Time) error  { return nil }
func (c bytesConn) SetWriteDeadline(time.Time) error { return nil }

type byteReader struct {
	b []byte
	i int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

// TestInteropReadCppPrivateAd is a C++ <-> Go interop test. testdata/
// cpp_private_ad.wire.b64 is the exact byte stream produced by REAL HTCondor C++
// putClassAd() (see testdata/gen_cpp_private_ad.cpp) for an ad carrying a private
// attribute: an AES-256-GCM message whose private attribute (a claim id) is wrapped
// in a SECRET_MARKER ("ZKM") + put_secret, because the peer version is unknown.
//
// This is the shape that desynced the Go collector in production. The test proves
// two things end to end against genuine C++ output: cedar's AES-GCM decryption is
// wire-compatible with C++, and the SECRET_MARKER handling recovers the claim id
// instead of surfacing a bare "ZKM" + a mangled MyType. (On a cedar without the
// SECRET_MARKER fix, this test fails with `expression contents 'ZKM'`.)
func TestInteropReadCppPrivateAd(t *testing.T) {
	b64, err := os.ReadFile("testdata/cpp_private_ad.wire.b64")
	if err != nil {
		t.Fatalf("read golden vector: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		t.Fatalf("decode golden vector: %v", err)
	}

	s := stream.NewStream(bytesConn{r: &byteReader{b: raw}})
	key := make([]byte, 32) // the generator used an all-zero AES-256 key
	if err := s.SetSymmetricKey(key); err != nil {
		t.Fatal(err)
	}

	ad, err := NewMessageFromStream(s).GetClassAd(context.Background())
	if err != nil {
		t.Fatalf("read C++ ad: %v", err)
	}
	for k, want := range map[string]string{
		"Name":    "slot1@interop",
		"MyType":  "Machine",
		"ClaimId": "interop-secret-claimid-deadbeef",
	} {
		if got, _ := ad.EvaluateAttrString(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}
