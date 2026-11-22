package security

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// A server must pick an authentication method from the set the client offered.
// Answering with a different bit used to make the client run that method anyway
// -- a KDC round trip for KERBEROS it never advertised -- and then spin forever,
// because the failure path cleared a bit that was never set in availableBitmask
// so the identical offer went back out on every iteration.
func TestClientRejectsAuthMethodItDidNotOffer(t *testing.T) {
	GetSessionCache().Clear()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	go func() {
		ctx := context.Background()
		st := stream.NewStream(serverConn)
		req := message.NewMessageFromStream(st)
		if _, err := req.GetInt(ctx); err != nil {
			return
		}
		if _, err := req.GetClassAd(ctx); err != nil {
			return
		}
		ad := classad.New()
		for k, v := range map[string]string{
			"Authentication": "YES", "Encryption": "NO", "Integrity": "NO",
			"AuthMethods": "CLAIMTOBE", "AuthMethodsList": "CLAIMTOBE",
			"CryptoMethods": "AES", "CryptoMethodsList": "AES", "Enact": "YES",
		} {
			_ = ad.Set(k, v)
		}
		m := message.NewMessageForStream(st)
		_ = m.PutClassAd(ctx, ad)
		_ = m.FinishMessage(ctx)

		// However many times the client offers, answer with KERBEROS, which it
		// never offered. Before the fix this fed an unbounded loop.
		for {
			bm := message.NewMessageFromStream(st)
			if _, err := bm.GetInt(ctx); err != nil {
				return
			}
			reply := message.NewMessageForStream(st)
			if err := reply.PutInt(ctx, AuthBitmaskKerberos); err != nil {
				return
			}
			if err := reply.FinishMessage(ctx); err != nil {
				return
			}
		}
	}()

	client := &SecurityConfig{
		AuthMethods: []AuthMethod{AuthClaimToBe}, Authentication: SecurityRequired,
		CryptoMethods: []CryptoMethod{CryptoAES},
		Encryption:    SecurityOptional, Integrity: SecurityOptional, Command: 60020,
	}

	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		_, err := NewAuthenticator(client, stream.NewStream(clientConn)).ClientHandshake(context.Background())
		done <- result{err}
	}()

	select {
	case r := <-done:
		if r.err == nil {
			t.Fatal("handshake succeeded using a method the client never offered")
		}
		if !strings.Contains(r.err.Error(), "not among those offered") {
			t.Errorf("error = %v, want it to name the unoffered method bitmask", r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handshake did not return: the method-negotiation loop is not making progress")
	}
}
