package ccb

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/htcondor/cedar/addresses"
)

// TestDialControlSeesBroker checks DialOptions.DialControl is applied to the
// broker connection: it is shown the broker's ip:port, allowing it lets the
// dial complete, and refusing it fails the dial before the broker is reached.
func TestDialControlSeesBroker(t *testing.T) {
	work := startFakeBroker(t)
	defer work.stop()

	var mu sync.Mutex
	var seen []string
	var refuse error
	control := func(network, address string, _ syscall.RawConn) error {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, address)
		return refuse
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dial(ctx, []addresses.CCBContact{work.contact()}, DialOptions{
		Security:    plaintextSec(),
		ListenAddr:  "127.0.0.1:0",
		DialControl: control,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close()
	mu.Lock()
	if len(seen) != 1 || seen[0] != work.addr {
		t.Errorf("DialControl saw %v, want [%s]", seen, work.addr)
	}
	seen = nil
	refuse = errors.New("refused by test")
	mu.Unlock()

	work.mu.Lock()
	before := work.reqs
	work.mu.Unlock()
	if _, err := Dial(ctx, []addresses.CCBContact{work.contact()}, DialOptions{
		Security:    plaintextSec(),
		ListenAddr:  "127.0.0.1:0",
		DialControl: control,
	}); err == nil {
		t.Fatal("Dial succeeded although DialControl refused the broker")
	}
	work.mu.Lock()
	after := work.reqs
	work.mu.Unlock()
	if after != before {
		t.Errorf("broker received a request after DialControl refused it")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 || seen[0] != work.addr {
		t.Errorf("DialControl saw %v, want [%s]", seen, work.addr)
	}
}
