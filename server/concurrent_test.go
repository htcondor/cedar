package server_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/htcondor/cedar/client"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/server"
)

// TestConcurrentServerHandshakes drives many concurrent authenticated+encrypted
// connections against ONE cedar server sharing a single SecurityConfig -- the
// real daemon pattern (collector, CCB, ...). With encryption REQUIRED, each
// connection's ephemeral ECDH key matters, so a server that leaked per-connection
// handshake state into its shared config (as it once did) would corrupt keys and
// fail handshakes under load. Run under -race, this guards that isolation
// directly in cedar (the CCB tree test caught it only indirectly).
func TestConcurrentServerHandshakes(t *testing.T) {
	security.GetSessionCache().Clear()
	defer security.GetSessionCache().Clear()

	serverCfg := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthNone},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityRequired,
	}
	srv := server.New(serverCfg)
	srv.Handle(commands.DC_NOP, func(context.Context, *server.Conn) error { return nil })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()
	addr := ln.Addr().String()

	const clients = 24
	const iters = 15
	var wg sync.WaitGroup
	errCh := make(chan error, clients*iters)
	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				cfg := &security.SecurityConfig{
					AuthMethods:    []security.AuthMethod{security.AuthNone},
					Authentication: security.SecurityOptional,
					CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
					Encryption:     security.SecurityRequired,
					Integrity:      security.SecurityRequired,
					Command:        commands.DC_NOP,
				}
				dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
				cl, err := client.ConnectAndAuthenticate(dctx, addr, cfg)
				if err != nil {
					errCh <- err
					dcancel()
					return
				}
				if neg := cl.GetSecurityNegotiation(); neg == nil || !neg.Encryption {
					errCh <- fmt.Errorf("session not encrypted")
				}
				_ = cl.Close()
				dcancel()
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
