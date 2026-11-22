package security

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// replyingServer answers one negotiation request with the given policy
// attributes, then a post-auth ad authorizing the command.
func replyingServer(t *testing.T, conn net.Conn, policy map[string]string) {
	t.Helper()
	go func() {
		ctx := context.Background()
		st := stream.NewStream(conn)
		req := message.NewMessageFromStream(st)
		if _, err := req.GetInt(ctx); err != nil {
			return
		}
		if _, err := req.GetClassAd(ctx); err != nil {
			return
		}
		reply := func(attrs map[string]string) {
			ad := classad.New()
			for k, v := range attrs {
				_ = ad.Set(k, v)
			}
			m := message.NewMessageForStream(st)
			_ = m.PutClassAd(ctx, ad)
			_ = m.FinishMessage(ctx)
		}
		reply(policy)
		reply(map[string]string{
			"Sid": "fake:1", "User": "unauthenticated@unmapped",
			"ValidCommands": "60020", "ReturnCode": "AUTHORIZED",
		})
	}()
}

// A client configured Encryption=REQUIRED must not complete a handshake in the
// clear just because the peer answered Encryption="NO". The client's own
// requirement is not the peer's to waive, so this must fail even though the
// server advertises AES (which keeps the no-compatible-method check from firing)
// and sends no ECDHPublicKey.
func TestClientRequiringEncryptionRefusesPeerSayingNo(t *testing.T) {
	GetSessionCache().Clear()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	replyingServer(t, serverConn, map[string]string{
		"Authentication": "NO", "Encryption": "NO", "Integrity": "NO",
		"CryptoMethods": "AES", "CryptoMethodsList": "AES", "Enact": "NO",
	})

	client := &SecurityConfig{
		AuthMethods: []AuthMethod{AuthClaimToBe}, Authentication: SecurityOptional,
		CryptoMethods: []CryptoMethod{CryptoAES},
		Encryption:    SecurityRequired, Integrity: SecurityOptional, Command: 60020,
	}
	cs := stream.NewStream(clientConn)
	_, err := NewAuthenticator(client, cs).ClientHandshake(context.Background())
	if err == nil {
		t.Fatalf("handshake succeeded with Encryption=REQUIRED and no key (stream encrypted: %t)", cs.IsEncrypted())
	}
	if !strings.Contains(err.Error(), "no session key") {
		t.Errorf("error = %v, want it to name the missing session key", err)
	}
}

// Same for integrity: before this, the client never computed an integrity
// requirement at all, so Integrity=REQUIRED was silently unenforced.
func TestClientRequiringIntegrityRefusesPeerSayingNo(t *testing.T) {
	GetSessionCache().Clear()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	replyingServer(t, serverConn, map[string]string{
		"Authentication": "NO", "Encryption": "NO", "Integrity": "NO",
		"CryptoMethods": "AES", "CryptoMethodsList": "AES", "Enact": "NO",
	})

	client := &SecurityConfig{
		AuthMethods: []AuthMethod{AuthClaimToBe}, Authentication: SecurityOptional,
		CryptoMethods: []CryptoMethod{CryptoAES},
		Encryption:    SecurityOptional, Integrity: SecurityRequired, Command: 60020,
	}
	cs := stream.NewStream(clientConn)
	_, err := NewAuthenticator(client, cs).ClientHandshake(context.Background())
	if err == nil {
		t.Fatalf("handshake succeeded with Integrity=REQUIRED and no key (stream encrypted: %t)", cs.IsEncrypted())
	}
	if !strings.Contains(err.Error(), "no session key") {
		t.Errorf("error = %v, want it to name the missing session key", err)
	}
}
