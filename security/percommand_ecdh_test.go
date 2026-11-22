package security

import (
	"context"
	"testing"
	"time"

	"github.com/htcondor/cedar/stream"

	"net"
)

// TestPerCommandSwapPreservesECDHKey reproduces the IDTOKENS+encryption failure:
// when the server swaps in a per-command SecurityConfig (via ServerConfigForCommand)
// that carries only policy and no ECDH public key, the server must still advertise
// the ephemeral public key that matches its private key (a.ecdhPrivKey). Otherwise
// the client receives no server pubkey, cannot derive the session key, and any
// command whose level requires encryption fails with "enable_enc no key to use".
//
// The command's level here requires encryption, so a dropped key is fatal (unlike a
// READ query where encryption is optional and the missing key goes unnoticed).
func TestPerCommandSwapPreservesECDHKey(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	clientStream := stream.NewStream(client)
	serverStream := stream.NewStream(server)

	// Client asks for command 42 with encryption required.
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthNone},
		Authentication: SecurityOptional,
		CryptoMethods:  []CryptoMethod{CryptoAES},
		Encryption:     SecurityRequired,
		Integrity:      SecurityOptional,
		Command:        42,
	}

	// The server's base config; NewAuthenticator will stamp its ECDH pubkey here.
	serverConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthNone},
		Authentication: SecurityOptional,
		CryptoMethods:  []CryptoMethod{CryptoAES},
		Encryption:     SecurityRequired,
		Integrity:      SecurityOptional,
	}

	clientAuth := NewAuthenticator(clientConfig, clientStream)
	serverAuth := NewAuthenticator(serverConfig, serverStream)

	// Per-command policy carries NO ECDH public key -- exactly like the collector's
	// SecurityForLevel entries, which never pass through NewAuthenticator. This is
	// the config the swap installs; the fix must preserve the connection's own
	// ephemeral pubkey across the swap.
	serverAuth.ServerConfigForCommand = func(command int) *SecurityConfig {
		return &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthNone},
			Authentication: SecurityOptional,
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Encryption:     SecurityRequired,
			Integrity:      SecurityOptional,
			// ECDHPublicKey intentionally empty.
		}
	}

	serverResultChan := make(chan *SecurityNegotiation, 1)
	serverErrChan := make(chan error, 1)
	go func() {
		result, err := serverAuth.ServerHandshake(context.Background())
		if err != nil {
			serverErrChan <- err
		} else {
			serverResultChan <- result
		}
	}()

	time.Sleep(10 * time.Millisecond)

	clientNeg, err := clientAuth.ClientHandshake(context.Background())
	if err != nil {
		t.Fatalf("Client handshake failed: %v", err)
	}

	var serverNeg *SecurityNegotiation
	select {
	case result := <-serverResultChan:
		serverNeg = result
	case err := <-serverErrChan:
		t.Fatalf("Server handshake failed: %v", err)
	case <-time.After(1 * time.Second):
		t.Fatal("Server handshake timed out")
	}

	// The client must have derived a session key (this is what the C++ client's
	// "enable_enc no key to use" guard checks).
	if len(clientNeg.GetSharedSecret()) != 32 {
		t.Fatalf("client derived no/short session key: got %d bytes, want 32 (server dropped its ECDH pubkey across the per-command swap)", len(clientNeg.GetSharedSecret()))
	}
	if len(serverNeg.GetSharedSecret()) != 32 {
		t.Fatalf("server derived no/short session key: got %d bytes, want 32", len(serverNeg.GetSharedSecret()))
	}

	// Both sides must derive the SAME key, or encrypted frames are garbage.
	if !equalBytes(clientNeg.GetSharedSecret(), serverNeg.GetSharedSecret()) {
		t.Fatalf("client and server derived different session keys:\n client=%x\n server=%x\n(server advertised a pubkey that does not match its private key)",
			clientNeg.GetSharedSecret(), serverNeg.GetSharedSecret())
	}

	if !clientStream.IsEncrypted() {
		t.Error("client stream should be encrypted")
	}
	if !serverStream.IsEncrypted() {
		t.Error("server stream should be encrypted")
	}
}
