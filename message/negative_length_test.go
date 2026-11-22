package message

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/bbockelm/cedar/stream"
)

// encryptedPair returns a keyed stream pair: the encrypted string path is the
// one that carries an explicit length prefix.
func encryptedPair(t *testing.T) (*stream.Stream, *stream.Stream) {
	t.Helper()
	peer, local := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	ls, ps := stream.NewStream(local), stream.NewStream(peer)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := ls.SetSymmetricKey(key); err != nil {
		t.Fatal(err)
	}
	if err := ps.SetSymmetricKey(key); err != nil {
		t.Fatal(err)
	}
	return ls, ps
}

// A negative length prefix must be rejected, not handed to make([]byte, n).
// ensureData cannot catch it -- both of its comparisons are false for a
// negative need, so it returns nil without reading -- and the allocation then
// panicked with "makeslice: len out of range". A panic here is not contained
// everywhere: the per-connection recover in server.Serve covers inbound server
// connections, while client-side readers (the CCB control-ad path, the security
// handshake) run outside it, so the process would die.
func TestEncryptedStringRejectsNegativeLength(t *testing.T) {
	// 8-byte CEDAR int whose low 32 bits make int32 negative.
	for _, wire := range []uint64{0x00000000FFFFFFFF, 0x0000000080000000} {
		for _, bounded := range []bool{false, true} {
			name := "GetString"
			if bounded {
				name = "GetStringWithMaxSize"
			}
			t.Run(name, func(t *testing.T) {
				ls, ps := encryptedPair(t)
				ctx := context.Background()

				body := make([]byte, 8)
				binary.BigEndian.PutUint64(body, wire)
				go func() {
					out := NewMessageForStream(ps)
					_ = out.PutBytes(ctx, body)
					_ = out.FinishMessage(ctx)
				}()

				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panicked on a negative length instead of erroring: %v", r)
					}
				}()

				in := NewMessageFromStream(ls)
				var err error
				if bounded {
					_, err = in.GetStringWithMaxSize(ctx, 4096)
				} else {
					_, err = in.GetString(ctx)
				}
				if err == nil {
					t.Fatal("accepted a negative string length")
				}
				if !strings.Contains(err.Error(), "negative string length") {
					t.Errorf("error = %v, want it to name the negative length", err)
				}
			})
		}
	}
}
