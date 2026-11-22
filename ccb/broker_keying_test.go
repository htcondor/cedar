package ccb

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	cedarserver "github.com/htcondor/cedar/server"

	"github.com/htcondor/cedar/security"
)

// TestBrokerSessionIsKeyedByTheBroker: the security config handed to a CCB
// dial is the caller's config for the TARGET -- client.Connect passes
// c.config.Security straight into ccb.Dial -- so it arrives carrying
// PeerName set to the target's sinful. ClientHandshake keys the session
// cache on PeerName in preference to the stream's peer address, so every
// broker session gets cached under the TARGET's address.
//
// That makes two brokers share one cache entry. A session minted with
// broker A is then offered to broker B, which has never heard of it, and
// the dial fails with "session not found on server" -- repeatedly, for as
// long as the entry keeps being re-created.
func TestBrokerSessionIsKeyedByTheBroker(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	srv := cedarserver.New(plaintextSec())
	srv.Handle(CommandRequest, func(_ context.Context, _ *cedarserver.Conn) error { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() { _ = srv.ServeConn(ctx, conn) }()
		}
	}()

	brokerAddr := ln.Addr().String()
	const targetSinful = "<10.0.0.5:41339?CCBID=broker-a%2367#broker-b%2312&noUDP>"

	cache := security.NewSessionCache()
	sec := plaintextSec()
	sec.SessionCache = cache
	// What a caller dialling a target behind CCB actually passes.
	sec.PeerName = targetSinful

	if _, _, _, err := dialBrokerAuthCmd(ctx, brokerAddr, sec, CommandRequest, brokerDial{}); err != nil {
		t.Fatalf("dialing the broker: %v", err)
	}

	cmd := strconv.Itoa(CommandRequest)
	if _, ok := cache.LookupByCommand("", targetSinful, cmd); ok {
		t.Error("the broker session was cached under the TARGET's address: " +
			"every broker in the target's CCBID now shares one entry, and a session " +
			"minted with one is offered to the others")
	}
	if _, ok := cache.LookupByCommand("", brokerAddr, cmd); !ok {
		t.Errorf("the broker session was not cached under the broker's address %q", brokerAddr)
	}
}
