package ccb

import (
	"context"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/stream"
)

// TestProxyModeReverseConnectsToOwnBroker checks that a request marked
// CCBProxyMode sends the reverse connection to the broker this registrant
// registered through, not to the address the request names.
//
// In proxy mode a broker always names its OWN address in MyAddress, so the
// field carries nothing the target does not already know. It matters when the
// two differ: a registrant reached through a relay can dial only the address it
// registered through, and the broker's own address is unroutable from there.
func TestProxyModeReverseConnectsToOwnBroker(t *testing.T) {
	// Stands in for the address the registrant reached its broker through --
	// the only one it can dial.
	broker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = broker.Close() }()
	reached := make(chan struct{}, 4)
	go func() {
		for {
			c, err := broker.Accept()
			if err != nil {
				return
			}
			reached <- struct{}{}
			_ = c.Close()
		}
	}()

	// A different, unrelated listener. The broker will name this one, standing
	// in for its own address on the far side of a carrier.
	elsewhere, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = elsewhere.Close() }()
	elsewhereReached := make(chan struct{}, 4)
	go func() {
		for {
			c, err := elsewhere.Accept()
			if err != nil {
				return
			}
			elsewhereReached <- struct{}{}
			_ = c.Close()
		}
	}()

	var mu sync.Mutex
	var dialed []string
	cfg := &ListenerConfig{
		DialTimeout: 5 * time.Second,
		Handler:     func(conn net.Conn, _ InboundMeta) { _ = conn.Close() },
		DialControl: func(_, address string, _ syscall.RawConn) error {
			mu.Lock()
			defer mu.Unlock()
			dialed = append(dialed, address)
			return nil
		},
	}

	brokerEnd, listenerEnd := net.Pipe()
	defer func() { _ = brokerEnd.Close() }()
	defer func() { _ = listenerEnd.Close() }()
	// addr is what this registrant registered through.
	r := &brokerReg{addr: broker.Addr().String(), cfg: cfg, stream: stream.NewStream(listenerEnd)}
	brokerStream := stream.NewStream(brokerEnd)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request := func(ad *classad.ClassAd) (bool, string) {
		t.Helper()
		go r.handleRequest(ctx, ad)
		result, err := ReadControlAd(ctx, brokerStream)
		if err != nil {
			t.Fatalf("reading the request result: %v", err)
		}
		ok, _ := AdBool(result, AttrResult)
		return ok, AdString(result, AttrErrorString)
	}

	// Proxy mode: MyAddress names "elsewhere", which must be ignored.
	if ok, msg := request(NewAd(map[string]any{
		AttrCommand:      CommandRequest,
		AttrCCBProxyMode: true,
		AttrMyAddress:    "<" + elsewhere.Addr().String() + ">",
		AttrClaimID:      "connect-id",
		AttrRequestID:    "1",
	})); !ok {
		t.Fatalf("proxy-mode request failed: %s", msg)
	}
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the reverse connection did not go to the broker this registrant registered through")
	}
	select {
	case <-elsewhereReached:
		t.Fatal("the reverse connection went to the address the request named; in proxy mode it must go to our own broker")
	case <-time.After(200 * time.Millisecond):
	}
	mu.Lock()
	if len(dialed) != 1 || dialed[0] != broker.Addr().String() {
		t.Errorf("dialed %v, want [%s] (our broker), not the named address %s",
			dialed, broker.Addr(), elsewhere.Addr())
	}
	dialed = nil
	mu.Unlock()

	// Without the flag, the named address is still honoured: a standard request
	// reverse-connects to the requester, which is the whole point of that mode.
	if ok, msg := request(NewAd(map[string]any{
		AttrCommand:   CommandRequest,
		AttrMyAddress: "<" + elsewhere.Addr().String() + ">",
		AttrClaimID:   "connect-id-2",
		AttrRequestID: "2",
	})); !ok {
		t.Fatalf("standard request failed: %s", msg)
	}
	select {
	case <-elsewhereReached:
	case <-time.After(5 * time.Second):
		t.Fatal("a standard request must still reverse-connect to the address it names")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 1 || dialed[0] != elsewhere.Addr().String() {
		t.Errorf("standard request dialed %v, want [%s]", dialed, elsewhere.Addr())
	}
}
