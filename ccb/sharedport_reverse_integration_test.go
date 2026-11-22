package ccb_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/ccb"
	"github.com/htcondor/cedar/internal/condortest"
	sharedportserver "github.com/htcondor/cedar/server/sharedport"
	"github.com/htcondor/cedar/stream"
)

// TestCCBReverseConnectThroughInProcessSharedPort exercises the combination
// this exists for: a requester that has no inbound socket of its own accepts
// CCB connection reversal on a port it shares, by advertising
// "<host:port?sock=NAME>" for an in-process shared-port router.
//
// The broker is the real C++ CCB server (the harness collector), so the test
// also covers the thing a Go-only test could not: that a C++ CCB target
// honors a shared-port id on the reverse-connect address it is handed. It
// does, via Sock::special_connect, but that is a claim about someone else's
// code and worth proving rather than assuming.
//
// Routed > 0 at the end is what distinguishes this from an ordinary
// reverse-connect dial: without it, a regression that quietly fell back to a
// private TCP listener would still echo successfully and the test would pass
// while testing nothing.
func TestCCBReverseConnectThroughInProcessSharedPort(t *testing.T) {
	extra := "ALLOW_DAEMON = *\n" +
		"ALLOW_ADVERTISE_STARTD = *\n" +
		"ALLOW_ADVERTISE_SCHEDD = *\n" +
		"ALLOW_ADVERTISE_MASTER = *\n"
	h := condortest.NewWithConfig(t, extra)
	defer h.Shutdown(t)

	broker := net.JoinHostPort(h.GetCollectorHost(), strconv.Itoa(h.GetCollectorPort()))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The router: one loopback port, no condor_shared_port, no fd passing.
	router, err := sharedportserver.Listen("127.0.0.1:0", sharedportserver.Options{})
	if err != nil {
		t.Fatalf("starting shared-port router: %v", err)
	}
	defer func() { _ = router.Close() }()
	t.Logf("shared-port router listening at %s", router.AdvertisedAddr())

	// The target: a Go CCB listener registered with the C++ broker.
	gotConn := make(chan net.Conn, 1)
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        broker,
		Name:              "go-ccb-sharedport-target",
		Security:          ccbTestSecurity(),
		HeartbeatInterval: 30 * time.Second,
		Handler:           func(conn net.Conn, _ ccb.InboundMeta) { gotConn <- conn },
	})
	go func() { _ = lis.Run(ctx) }()

	deadline := time.Now().Add(30 * time.Second)
	for lis.NumRegistered() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("listener did not register with the C++ CCB server within 30s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, ccbid, ok := addresses.SplitCCBContact(lis.Contact())
	if !ok {
		t.Fatalf("could not parse registered contact %q", lis.Contact())
	}

	srvErr := make(chan error, 1)
	go func() {
		select {
		case conn := <-gotConn:
			defer func() { _ = conn.Close() }()
			s := stream.NewStream(conn)
			req, err := ccb.ReadControlAd(ctx, s)
			if err != nil {
				srvErr <- err
				return
			}
			srvErr <- ccb.WriteControlAd(ctx, s,
				ccb.NewAd(map[string]any{"Echo": ccb.AdString(req, "Ping")}))
		case <-ctx.Done():
			srvErr <- ctx.Err()
		}
	}()

	// The requester registers a route per dial and advertises its sinful. Note
	// there is no ListenAddr: this dial opens no socket of its own.
	var routeSinful string
	contacts := []addresses.CCBContact{{BrokerAddr: broker, CCBID: ccbid}}
	conn, err := ccb.Dial(ctx, contacts, ccb.DialOptions{
		Security:   ccbTestSecurity(),
		TargetDesc: "go-ccb-sharedport-target",
		ReverseListener: func() (net.Listener, string, error) {
			route, err := router.Register("")
			if err != nil {
				return nil, "", err
			}
			routeSinful = route.Sinful()
			return route, route.Sinful(), nil
		},
	})
	if err != nil {
		t.Fatalf("ccb.Dial with a shared-port reverse listener failed (advertised %s): %v", routeSinful, err)
	}
	defer func() { _ = conn.Close() }()
	t.Logf("reverse connection arrived on %s", routeSinful)

	s := stream.NewStream(conn)
	if err := ccb.WriteControlAd(ctx, s, ccb.NewAd(map[string]any{"Ping": "hello-sharedport"})); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	reply, err := ccb.ReadControlAd(ctx, s)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if got := ccb.AdString(reply, "Echo"); got != "hello-sharedport" {
		t.Errorf("echo = %q, want %q", got, "hello-sharedport")
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("target-side exchange failed: %v", err)
	}

	if stats := router.Stats(); stats.Routed == 0 {
		t.Errorf("the reverse connection did not go through the shared-port router: %+v", stats)
	} else {
		t.Logf("router stats: %+v", stats)
	}
}
