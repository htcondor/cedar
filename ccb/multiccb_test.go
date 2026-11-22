package ccb

import (
	"context"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/security"
	cedarserver "github.com/htcondor/cedar/server"
	"github.com/htcondor/cedar/stream"
)

// plaintextSec returns an un-authenticated, un-encrypted security config so the
// in-process broker handshake completes without credentials.
func plaintextSec() *security.SecurityConfig {
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{},
		Authentication: security.SecurityNever,
		Encryption:     security.SecurityNever,
		Integrity:      security.SecurityNever,
		RemoteVersion:  "$CondorVersion: 25.13.0 2026-06-21 BuildID: test $",
	}
}

func TestSplitBrokerList(t *testing.T) {
	tests := map[string][]string{
		"":                  {},
		"a:1":               {"a:1"},
		"a:1,b:2":           {"a:1", "b:2"},
		"a:1 b:2":           {"a:1", "b:2"},
		"a:1, b:2,  c:3":    {"a:1", "b:2", "c:3"},
		" a:1 ,b:2\t c:3\n": {"a:1", "b:2", "c:3"},
		"host.example:9618": {"host.example:9618"},
	}
	for in, want := range tests {
		got := SplitBrokerList(in)
		if len(got) == 0 && len(want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("SplitBrokerList(%q) = %v, want %v", in, got, want)
		}
	}
}

// fakeBroker is a minimal CCB broker for requester tests. For a CCB_REQUEST it
// plays the target as well: it reverse-connects to the requester's listen
// address and sends the reverse-connect hello, which is enough for ccb.Dial to
// complete in standard mode. The broker socket is kept open so the requester's
// failure-reply reader stays blocked and the accepted reverse connection wins.
type fakeBroker struct {
	addr   string
	ln     net.Listener
	srv    *cedarserver.Server
	cancel context.CancelFunc

	mu    sync.Mutex
	conns []net.Conn // everything we opened/kept, closed on stop
	reqs  int        // CCB_REQUESTs received
}

func startFakeBroker(t *testing.T) *fakeBroker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBroker{addr: ln.Addr().String(), ln: ln, srv: cedarserver.New(plaintextSec())}
	b.srv.Handle(CommandRequest, func(ctx context.Context, c *cedarserver.Conn) error {
		ad, err := ReadControlAd(ctx, c.Stream)
		if err != nil {
			return err
		}
		b.mu.Lock()
		b.reqs++
		b.conns = append(b.conns, c.Stream.GetConnection()) // keep broker socket open
		b.mu.Unlock()

		connectID := AdString(ad, AttrClaimID)
		myAddr := strings.Trim(AdString(ad, AttrMyAddress), "<>")
		rc, err := net.Dial("tcp", myAddr)
		if err != nil {
			return err
		}
		b.mu.Lock()
		b.conns = append(b.conns, rc)
		b.mu.Unlock()
		if err := WriteReverseConnect(ctx, stream.NewStream(rc), connectID, "1", myAddr); err != nil {
			return err
		}
		// Keep both sockets open; the requester accepts rc as the target conn.
		return cedarserver.KeepOpen()
	})
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	go func() { _ = b.srv.Serve(ctx, ln) }()
	return b
}

func (b *fakeBroker) contact() addresses.CCBContact {
	return addresses.CCBContact{BrokerAddr: b.addr, CCBID: "1", Raw: b.addr + "#1"}
}

func (b *fakeBroker) stop() {
	b.cancel()
	_ = b.ln.Close()
	b.mu.Lock()
	for _, c := range b.conns {
		_ = c.Close()
	}
	b.mu.Unlock()
}

// deadBroker accepts TCP connections but never responds, so the security
// handshake blocks until the dial's context is cancelled.
type deadBroker struct {
	addr   string
	ln     net.Listener
	cancel context.CancelFunc
}

func startDeadBroker(t *testing.T) *deadBroker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &deadBroker{addr: ln.Addr().String(), ln: ln, cancel: cancel}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { <-ctx.Done(); _ = conn.Close() }() // hold open, never respond
		}
	}()
	return d
}

func (d *deadBroker) contact() addresses.CCBContact {
	return addresses.CCBContact{BrokerAddr: d.addr, CCBID: "1", Raw: d.addr + "#1"}
}
func (d *deadBroker) stop() { d.cancel(); _ = d.ln.Close() }

// TestDialHappyEyeballsSkipsDeadBroker verifies that with one dead broker and
// one working broker, Dial succeeds quickly regardless of the (randomized)
// order, because the staggered second attempt wins well before the dead
// broker's handshake would time out.
func TestDialHappyEyeballsSkipsDeadBroker(t *testing.T) {
	work := startFakeBroker(t)
	defer work.stop()
	dead := startDeadBroker(t)
	defer dead.stop()

	// Run several times so both shuffle orders (dead-first, work-first) are hit.
	for i := 0; i < 8; i++ {
		ctx := context.Background()
		start := time.Now()
		conn, err := Dial(ctx, []addresses.CCBContact{dead.contact(), work.contact()}, DialOptions{
			Security:   plaintextSec(),
			ListenAddr: "127.0.0.1:0",
			Stagger:    50 * time.Millisecond,
			Timeout:    10 * time.Second, // generous; success must be far faster
		})
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("iter %d: Dial failed: %v", i, err)
		}
		_ = conn.Close()
		// The dead broker would only fail at the 10s timeout; happy-eyeballs
		// must win via the working broker in well under that.
		if elapsed > 3*time.Second {
			t.Fatalf("iter %d: Dial took %v; happy-eyeballs did not bypass the dead broker", i, elapsed)
		}
	}
}

// TestDialSequentialStillWorks verifies a single working broker dials fine
// (degenerate happy-eyeballs with one contact).
func TestDialSingleBroker(t *testing.T) {
	work := startFakeBroker(t)
	defer work.stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dial(ctx, []addresses.CCBContact{work.contact()}, DialOptions{
		Security:   plaintextSec(),
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close()
	if work.reqs == 0 {
		t.Errorf("broker received no CCB_REQUEST")
	}
}
