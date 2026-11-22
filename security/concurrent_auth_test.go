package security

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

// TestConcurrentEncryptedHandshakes hammers the encrypted (ECDH + AES) handshake
// path from many goroutines at once, with per-connection data round-trips and
// concurrent session resumption against the shared session cache. Run under
// -race, it is designed to surface cedar concurrency bugs beyond the shared-
// config ECDH race the CCB tree test found -- e.g. shared state in key
// derivation, the AES stream, or the global session cache. Each connection must
// come up encrypted AND correctly echo its own sequence number (crossed crypto
// state between connections would corrupt or fail the echo).
func TestConcurrentEncryptedHandshakes(t *testing.T) {
	GetSessionCache().Clear()
	defer GetSessionCache().Clear()

	encCfg := func(peerName string) *SecurityConfig {
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

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// Server: per connection, a fresh handshake (encrypted), then echo one ad.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				st := stream.NewStream(conn)
				auth := NewAuthenticator(encCfg(""), st)
				neg, err := auth.ServerHandshake(ctx)
				if err != nil {
					return // client may have closed; client side records the failure
				}
				if !neg.Encryption {
					t.Errorf("server: session not encrypted")
					return
				}
				ad, err := message.NewMessageFromStream(st).GetClassAd(ctx)
				if err != nil {
					return
				}
				out := message.NewMessageForStream(st)
				if err := out.PutClassAd(ctx, ad); err != nil {
					return
				}
				_ = out.FinishMessage(ctx)
			}()
		}
	}()

	const clients = 16
	const iters = 25
	var wg sync.WaitGroup
	errCh := make(chan error, clients*iters)
	addr := ln.Addr().String()

	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			peer := fmt.Sprintf("cli-%d", c) // stable per client => iter 0 creates, rest resume
			for i := 0; i < iters; i++ {
				seq := int64(c*1000 + i)
				if err := oneEncryptedExchange(addr, encCfg(peer), seq); err != nil {
					errCh <- fmt.Errorf("client %d iter %d: %w", c, i, err)
					return
				}
			}
		}(c)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// oneEncryptedExchange dials, runs an encrypted client handshake, sends {Seq:seq},
// and verifies the server echoes it back over the encrypted session.
func oneEncryptedExchange(addr string, cfg *SecurityConfig, seq int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	st := stream.NewStream(conn)
	auth := NewAuthenticator(cfg, st)
	neg, err := auth.ClientHandshake(ctx)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if !neg.Encryption {
		return fmt.Errorf("session not encrypted")
	}

	ad := classad.New()
	_ = ad.Set("Seq", seq)
	out := message.NewMessageForStream(st)
	if err := out.PutClassAd(ctx, ad); err != nil {
		return fmt.Errorf("put: %w", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish: %w", err)
	}
	echo, err := message.NewMessageFromStream(st).GetClassAd(ctx)
	if err != nil {
		return fmt.Errorf("get echo: %w", err)
	}
	if got, _ := echo.EvaluateAttrInt("Seq"); got != seq {
		return fmt.Errorf("echo Seq=%d, want %d (crossed/corrupted encrypted stream)", got, seq)
	}
	return nil
}
