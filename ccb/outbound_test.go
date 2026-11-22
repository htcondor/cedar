package ccb

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	cedarserver "github.com/htcondor/cedar/server"
)

// TestOutboundConnectWire pins the normative CCB_PROXY_CONNECT request wire format
// (§4.1) from the client side and verifies the raw relay handoff: the requester
// sends command 82 with MyAddress=<target>, a 40-hex ClaimId, and NO CCBID; after
// {Result:true} the socket is a raw byte relay (no reverse-connect hello), so an
// application payload round-trips opaquely.
func TestOutboundConnectWire(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var mu sync.Mutex
	var gotTarget, gotClaim, gotCCBID string
	sawRequest := make(chan struct{}, 1)

	srv := cedarserver.New(plaintextSec())
	srv.Handle(CommandProxyConnect, func(ctx context.Context, c *cedarserver.Conn) error {
		ad, err := ReadControlAd(ctx, c.Stream)
		if err != nil {
			return err
		}
		mu.Lock()
		gotTarget = AdString(ad, AttrMyAddress)
		gotClaim = AdString(ad, AttrClaimID)
		gotCCBID = AdString(ad, AttrCCBID)
		mu.Unlock()
		select {
		case sawRequest <- struct{}{}:
		default:
		}
		// Reply {Result:true} on the (broker-session) stream, then relay raw bytes
		// -- here, echo them back, standing in for the spliced target.
		if err := WriteControlAd(ctx, c.Stream, NewAd(map[string]any{AttrResult: true})); err != nil {
			return err
		}
		conn := c.Stream.GetConnection()
		_, _ = io.Copy(conn, conn) // raw echo until the requester closes
		return cedarserver.KeepOpen()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = srv.ServeConn(ctx, conn) }()
		}
	}()

	const target = "<10.1.2.3:9618>"
	dctx, dcancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer dcancel()
	conn, err := OutboundConnect(dctx, ln.Addr().String(), target, OutboundOptions{
		Security: plaintextSec(),
		Name:     "wire-test",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("OutboundConnect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case <-sawRequest:
	case <-time.After(3 * time.Second):
		t.Fatal("broker never received the proxy-connect request")
	}

	mu.Lock()
	target0, claim0, ccbid0 := gotTarget, gotClaim, gotCCBID
	mu.Unlock()
	if target0 != target {
		t.Errorf("MyAddress = %q, want %q (the target to dial)", target0, target)
	}
	if len(claim0) != 40 {
		t.Errorf("ClaimId = %q (len %d), want a 40-hex connect id", claim0, len(claim0))
	}
	if ccbid0 != "" {
		t.Errorf("CCBID = %q, want empty (outbound addresses the target by Sinful, not CCBID)", ccbid0)
	}

	// Raw relay: no hello, bytes flow opaquely.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q, want %q", buf, "ping")
	}
}

// TestOutboundConnectFailureReply verifies a {Result:false} reply surfaces as an
// error carrying the broker's ErrorString.
func TestOutboundConnectFailureReply(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	srv := cedarserver.New(plaintextSec())
	srv.Handle(CommandProxyConnect, func(ctx context.Context, c *cedarserver.Conn) error {
		if _, err := ReadControlAd(ctx, c.Stream); err != nil {
			return err
		}
		return WriteControlAd(ctx, c.Stream, NewAd(map[string]any{
			AttrResult:      false,
			AttrErrorString: "target not allowed",
		}))
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = srv.ServeConn(ctx, conn) }()
		}
	}()

	dctx, dcancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer dcancel()
	_, err = OutboundConnect(dctx, ln.Addr().String(), "<10.1.2.3:9618>", OutboundOptions{
		Security: plaintextSec(),
		Timeout:  5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected an error for a {Result:false} reply")
	}
}
