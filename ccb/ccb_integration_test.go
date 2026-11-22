package ccb_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/ccb"
	"github.com/htcondor/cedar/internal/condortest"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// ccbTestSecurity returns a permissive client/daemon security config matching
// the harness pool (FS auth as the current user, everything optional).
func ccbTestSecurity() *security.SecurityConfig {
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS, security.AuthClaimToBe},
		Authentication: security.SecurityOptional,
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
	}
}

// TestCCBInteropWithCppBroker stands up a real C++ HTCondor pool whose collector
// acts as the CCB server (ENABLE_CCB_SERVER defaults to true), registers a Go
// ccb.Listener with it, and dials that listener from a Go ccb requester. The
// CCB control plane (REGISTER, REQUEST, forward to the registered target) is
// exercised against the real C++ CCB server; the reverse-connect data plane is
// Go<->Go on loopback so there is no fragile cross-language dial-back.
//
// Two broker addresses are tested: the collector's direct command port, and the
// collector's advertised sinful. Under USE_SHARED_PORT (which the harness sets)
// the advertised sinful carries a sock= parameter, so that subtest exercises
// dialBroker's shared-port path against the real C++ shared_port + collector.
func TestCCBInteropWithCppBroker(t *testing.T) {
	// CCB_REGISTER is a DAEMON-level command (CCB_REQUEST is READ, already
	// allowed). Open DAEMON/ADVERTISE authorization so the Go listener may
	// register with the collector's CCB server.
	extra := "ALLOW_DAEMON = *\n" +
		"ALLOW_ADVERTISE_STARTD = *\n" +
		"ALLOW_ADVERTISE_SCHEDD = *\n" +
		"ALLOW_ADVERTISE_MASTER = *\n"
	h := condortest.NewWithConfig(t, extra)
	defer h.Shutdown(t)

	directBroker := net.JoinHostPort(h.GetCollectorHost(), strconv.Itoa(h.GetCollectorPort()))
	advertised := h.GetCollectorAddr()
	t.Logf("collector direct=%s advertised=%s", directBroker, advertised)

	for _, tc := range []struct {
		name   string
		broker string
	}{
		{"DirectPort", directBroker},
		{"AdvertisedSinful", advertised},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runCCBInterop(t, tc.broker)
		})
	}
}

// TestCCBProxyStreamingThroughCppBroker verifies the shared_port + CCB proxy
// (streaming) combination against the real C++ CCB streaming server. The
// requester dials in proxy mode (ProxyReturnAddr set), so the collector splices
// the requester's socket to the target rather than having the target dial the
// requester. Because the collector is behind shared_port (USE_SHARED_PORT), it
// tells the target to reverse-connect to its shared-port address -- so this
// exercises the Go listener dialing the broker's reverse-connect endpoint
// through shared_port, the combination that a plain TCP dial could not handle.
func TestCCBProxyStreamingThroughCppBroker(t *testing.T) {
	extra := "ALLOW_DAEMON = *\n" +
		"ALLOW_ADVERTISE_STARTD = *\n" +
		"ALLOW_ADVERTISE_SCHEDD = *\n" +
		"ALLOW_ADVERTISE_MASTER = *\n"
	h := condortest.NewWithConfig(t, extra)
	defer h.Shutdown(t)

	broker := net.JoinHostPort(h.GetCollectorHost(), strconv.Itoa(h.GetCollectorPort()))
	t.Logf("collector direct=%s advertised=%s", broker, h.GetCollectorAddr())

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	gotConn := make(chan net.Conn, 1)
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        broker,
		Name:              "go-ccb-proxy-listener",
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
	t.Logf("registered contact: %s", lis.Contact())

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
			reply := ccb.NewAd(map[string]any{"Echo": ccb.AdString(req, "Ping")})
			srvErr <- ccb.WriteControlAd(ctx, s, reply)
		case <-ctx.Done():
			srvErr <- ctx.Err()
		}
	}()

	contacts := []addresses.CCBContact{{BrokerAddr: broker, CCBID: ccbid}}
	conn, err := ccb.Dial(ctx, contacts, ccb.DialOptions{
		Security:         ccbTestSecurity(),
		ProxyReturnAddr:  "<127.0.0.1:0?ccbid=127.0.0.1:0%231>", // CCB-routed; not dialed by the broker in proxy mode
		RequireStreaming: true,
		TargetDesc:       "go-ccb-proxy-target",
	})
	if err != nil {
		// Streaming requires a broker at or above StreamingMinVersion. A released
		// CI image may ship an older collector that lacks the feature; that is an
		// environment limitation, not a test failure.
		var unsup *ccb.StreamingUnsupportedError
		if errors.As(err, &unsup) {
			t.Skipf("C++ CCB broker does not support streaming (need >= %s): %v", ccb.StreamingMinVersion, err)
		}
		t.Fatalf("ccb.Dial (proxy/streaming) through C++ broker failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	s := stream.NewStream(conn)
	if err := ccb.WriteControlAd(ctx, s, ccb.NewAd(map[string]any{"Ping": "hello-proxy"})); err != nil {
		t.Fatalf("write ping over proxied connection: %v", err)
	}
	reply, err := ccb.ReadControlAd(ctx, s)
	if err != nil {
		t.Fatalf("read echo over proxied connection: %v", err)
	}
	if got := ccb.AdString(reply, "Echo"); got != "hello-proxy" {
		t.Errorf("echo over proxy = %q, want %q", got, "hello-proxy")
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("listener-side exchange failed: %v", err)
	}
}

// TestCCBRequesterViaSharedPortEndpoint verifies that a requester can accept the
// target's reverse connection through a shared-port endpoint instead of its own
// TCP listen socket. The requester registers an endpoint in the pool's
// DAEMON_SOCKET_DIR and advertises a "<host:port?sock=NAME>" return address; the
// Go target (registered with the C++ collector's CCB) then reverse-connects to
// it through the real C++ shared_port daemon. Both a named and an anonymous
// endpoint socket are covered.
func TestCCBRequesterViaSharedPortEndpoint(t *testing.T) {
	extra := "ALLOW_DAEMON = *\n" +
		"ALLOW_ADVERTISE_STARTD = *\n" +
		"ALLOW_ADVERTISE_SCHEDD = *\n" +
		"ALLOW_ADVERTISE_MASTER = *\n"
	h := condortest.NewWithConfig(t, extra)
	defer h.Shutdown(t)

	broker := net.JoinHostPort(h.GetCollectorHost(), strconv.Itoa(h.GetCollectorPort()))
	// The collector is behind shared_port, so its port is the shared_port
	// daemon's TCP port -- the address through which forwarded connections enter.
	spAddr := broker
	socketDir := h.SocketDir()
	t.Logf("broker=%s sharedPortAddr=%s socketDir=%s", broker, spAddr, socketDir)

	for _, tc := range []struct {
		name string
		sock string
	}{
		{"NamedSocket", "ccb-itest-req"},
		{"AnonymousSocket", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runCCBSharedPortEndpoint(t, broker, spAddr, socketDir, tc.sock)
		})
	}
}

func runCCBSharedPortEndpoint(t *testing.T, broker, spAddr, socketDir, sockName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	gotConn := make(chan net.Conn, 1)
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        broker,
		Name:              "go-ccb-sp-listener",
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
			reply := ccb.NewAd(map[string]any{"Echo": ccb.AdString(req, "Ping")})
			srvErr <- ccb.WriteControlAd(ctx, s, reply)
		case <-ctx.Done():
			srvErr <- ctx.Err()
		}
	}()

	contacts := []addresses.CCBContact{{BrokerAddr: broker, CCBID: ccbid}}
	conn, err := ccb.Dial(ctx, contacts, ccb.DialOptions{
		Security: ccbTestSecurity(),
		SharedPortEndpoint: &ccb.SharedPortEndpointConfig{
			SharedPortAddr: spAddr,
			SocketDir:      socketDir,
			SocketName:     sockName,
		},
		TargetDesc: "go-ccb-sp-target",
	})
	if err != nil {
		t.Fatalf("ccb.Dial via shared-port endpoint failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	s := stream.NewStream(conn)
	if err := ccb.WriteControlAd(ctx, s, ccb.NewAd(map[string]any{"Ping": "hello-sp"})); err != nil {
		t.Fatalf("write ping over shared-port-endpoint connection: %v", err)
	}
	reply, err := ccb.ReadControlAd(ctx, s)
	if err != nil {
		t.Fatalf("read echo over shared-port-endpoint connection: %v", err)
	}
	if got := ccb.AdString(reply, "Echo"); got != "hello-sp" {
		t.Errorf("echo = %q, want %q", got, "hello-sp")
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("listener-side exchange failed: %v", err)
	}
}

func runCCBInterop(t *testing.T, broker string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	gotConn := make(chan net.Conn, 1)
	lis := ccb.NewListener(ccb.ListenerConfig{
		BrokerAddr:        broker,
		Name:              "go-ccb-itest-listener",
		Security:          ccbTestSecurity(),
		HeartbeatInterval: 30 * time.Second,
		Handler:           func(conn net.Conn, _ ccb.InboundMeta) { gotConn <- conn },
	})
	go func() { _ = lis.Run(ctx) }()

	// Wait for the listener to register with the C++ CCB server.
	deadline := time.Now().Add(30 * time.Second)
	for lis.NumRegistered() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("listener did not register with the C++ CCB server within 30s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	contact := lis.Contact()
	t.Logf("registered contact: %s", contact)
	_, ccbid, ok := addresses.SplitCCBContact(contact)
	if !ok {
		t.Fatalf("could not parse registered contact %q", contact)
	}

	// Listener-side application exchange: act as the CEDAR server end of the
	// reverse-connected socket.
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
			reply := ccb.NewAd(map[string]any{"Echo": ccb.AdString(req, "Ping")})
			srvErr <- ccb.WriteControlAd(ctx, s, reply)
		case <-ctx.Done():
			srvErr <- ctx.Err()
		}
	}()

	// Requester side: reach the listener through the C++ CCB broker.
	contacts := []addresses.CCBContact{{BrokerAddr: broker, CCBID: ccbid}}
	conn, err := ccb.Dial(ctx, contacts, ccb.DialOptions{
		Security:   ccbTestSecurity(),
		ListenAddr: "127.0.0.1:0", // loopback so the Go listener can dial us back
		TargetDesc: "go-ccb-itest-target",
	})
	if err != nil {
		t.Fatalf("ccb.Dial through C++ broker failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	s := stream.NewStream(conn)
	if err := ccb.WriteControlAd(ctx, s, ccb.NewAd(map[string]any{"Ping": "hello-ccb"})); err != nil {
		t.Fatalf("write ping over CCB connection: %v", err)
	}
	reply, err := ccb.ReadControlAd(ctx, s)
	if err != nil {
		t.Fatalf("read echo over CCB connection: %v", err)
	}
	if got := ccb.AdString(reply, "Echo"); got != "hello-ccb" {
		t.Errorf("echo over CCB = %q, want %q", got, "hello-ccb")
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("listener-side exchange failed: %v", err)
	}
}
