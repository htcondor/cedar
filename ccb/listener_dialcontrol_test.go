package ccb

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/htcondor/cedar/stream"
)

// TestListenerDialControl checks ListenerConfig.DialControl is applied to the
// reverse-connect dial a CCB_REQUEST asks for: it is shown the requester's
// MyAddress, allowing it lets the connection through to the handler, and
// refusing it fails the request -- reported to the broker -- before the
// address is reached.
func TestListenerDialControl(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()

	var mu sync.Mutex
	var seen []string
	var refuse error
	cfg := &ListenerConfig{
		DialTimeout: 5 * time.Second,
		Handler:     func(conn net.Conn, _ InboundMeta) { _ = conn.Close() },
		DialControl: func(network, address string, _ syscall.RawConn) error {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, address)
			return refuse
		},
	}

	// The broker side of the registration: handleRequest reports its result
	// there.
	brokerEnd, listenerEnd := net.Pipe()
	defer func() { _ = brokerEnd.Close() }()
	defer func() { _ = listenerEnd.Close() }()
	r := &brokerReg{addr: "broker", cfg: cfg, stream: stream.NewStream(listenerEnd)}
	broker := stream.NewStream(brokerEnd)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request := func() (bool, string) {
		t.Helper()
		go r.handleRequest(ctx, NewAd(map[string]any{
			AttrCommand:   CommandRequest,
			AttrMyAddress: "<" + target.Addr().String() + ">",
			AttrClaimID:   "connect-id",
			AttrRequestID: "1",
		}))
		result, err := ReadControlAd(ctx, broker)
		if err != nil {
			t.Fatalf("reading the request result: %v", err)
		}
		ok, _ := AdBool(result, AttrResult)
		return ok, AdString(result, AttrErrorString)
	}

	if ok, msg := request(); !ok {
		t.Fatalf("allowed request failed: %s", msg)
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("allowed request never reached the requester")
	}
	mu.Lock()
	if len(seen) != 1 || seen[0] != target.Addr().String() {
		t.Errorf("DialControl saw %v, want [%s]", seen, target.Addr())
	}
	seen = nil
	refuse = errors.New("refused by test")
	mu.Unlock()

	ok, msg := request()
	if ok {
		t.Fatal("request succeeded although DialControl refused the requester")
	}
	if !strings.Contains(msg, "refused by test") {
		t.Errorf("result error %q does not carry DialControl's refusal", msg)
	}
	select {
	case <-accepted:
		t.Error("requester was reached although DialControl refused it")
	case <-time.After(200 * time.Millisecond):
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != target.Addr().String() {
		t.Errorf("DialControl saw %v, want [%s]", seen, target.Addr())
	}
}

// TestOutboundConnectDialControl checks OutboundOptions.DialControl is applied
// to the broker connection: refusing the broker's address fails the connect
// before the broker is reached.
func TestOutboundConnectDialControl(t *testing.T) {
	broker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = broker.Close() }()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := broker.Accept(); err == nil {
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()

	var seen []string
	_, err = OutboundConnect(context.Background(), broker.Addr().String(), "<10.0.0.9:9618>", OutboundOptions{
		Security: plaintextSec(),
		Timeout:  5 * time.Second,
		DialControl: func(network, address string, _ syscall.RawConn) error {
			seen = append(seen, address)
			return errors.New("refused by test")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "refused by test") {
		t.Fatalf("OutboundConnect = %v, want DialControl's refusal", err)
	}
	if len(seen) != 1 || seen[0] != broker.Addr().String() {
		t.Errorf("DialControl saw %v, want [%s]", seen, broker.Addr())
	}
	select {
	case <-accepted:
		t.Error("broker was reached although DialControl refused it")
	case <-time.After(200 * time.Millisecond):
	}
}
