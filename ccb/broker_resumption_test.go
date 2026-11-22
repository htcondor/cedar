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

// TestBrokerDialRecoversFromAStaleSession reproduces what an access point
// sees when the CCB broker it has a cached session with no longer has that
// session -- the broker restarted, failed over between the collectors in its
// sinful, or evicted the entry:
//
//	ccb: authenticating to broker 128.105.82.148:9618?...: session resumption
//	failed for session ospool-c...: session not found on server
//
// The client half already handles this correctly: the handshake sees
// SID_NOT_FOUND, drops the cache entry and returns a SessionResumptionError.
// What was missing is the other half. client.ConnectAndAuthenticate answers
// that error by redialing with full authentication, but the CCB broker paths
// do their own dial and handshake, so the invalidation only ever helped some
// LATER caller while this one failed -- a one-shot error on a healthy pool,
// surfaced to whatever was trying to reach a job.
func TestBrokerDialRecoversFromAStaleSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// A broker that knows nothing about our session: it has its own empty
	// store, so a resumption attempt gets SID_NOT_FOUND and a full
	// authentication succeeds.
	srv := cedarserver.New(plaintextSec())
	srv.Handle(CommandRequest, func(_ context.Context, _ *cedarserver.Conn) error {
		return nil
	})
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

	addr := ln.Addr().String()

	// Prime the client with a session the broker has never heard of, keyed
	// the way ClientHandshake looks one up: (tag, address, command).
	cache := security.NewSessionCache()
	stale := security.NewSessionEntry("stale-broker-session", addr, nil, nil,
		time.Now().Add(time.Hour), time.Hour, "")
	cache.Store(stale)
	cache.MapCommand("", addr, strconv.Itoa(CommandRequest), stale.ID())

	sec := plaintextSec()
	sec.SessionCache = cache

	conn, s, _, err := dialBrokerAuthCmd(ctx, addr, sec, CommandRequest, brokerDial{})
	if err != nil {
		t.Fatalf("dialing the broker did not recover from a stale session: %v", err)
	}
	if conn != nil {
		defer func() { _ = conn.Close() }()
	}
	if s == nil {
		t.Fatal("no stream returned")
	}

	// And the dead session is gone, so the next dial does not re-attempt it.
	if _, still := cache.Lookup("stale-broker-session"); still {
		t.Error("the stale session is still cached; every later dial would retry it")
	}
}
