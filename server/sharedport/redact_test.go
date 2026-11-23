package sharedport

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
)

func TestRedactID(t *testing.T) {
	const generated = "cedar-0123456789abcdef0123456789abcdef"
	cases := []struct {
		name string
		id   string
		want string
	}{
		{"empty", "", "<empty>"},
		{"generated", generated, "cedar-01234567..."},
		{"caller named", "collector-inbound-route", "collecto..."},
		{"short", "abc", "abc..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactID(tc.id)
			if got != tc.want {
				t.Errorf("redactID(%q) = %q, want %q", tc.id, got, tc.want)
			}
			if tc.id != "" && len(tc.id) > 8 && strings.Contains(got, tc.id) {
				t.Errorf("redactID(%q) = %q, which still carries the whole id", tc.id, got)
			}
		})
	}
}

// syncBuffer is a bytes.Buffer safe to read while the router's goroutines are
// still logging into it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestLogsRedactSharedPortID is the point of redactID: a shared-port id is an
// unguessable capability — the router authenticates nothing, so whoever reads
// an id out of a log can claim the connections addressed to it — and HTCondor
// daemon logs are world-readable on stock installs. No log line may carry one
// whole, least of all the Warn, which is emitted at the default level.
//
// It drives all three id-logging sites in handle(): the unregistered-id
// rejection, the successful queue, and the delivery timeout.
func TestLogsRedactSharedPortID(t *testing.T) {
	logs := &syncBuffer{}
	srv := newTestServer(t, Options{
		DeliveryTimeout: 250 * time.Millisecond,
		Logger:          slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})

	route, err := srv.Register("")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer func() { _ = route.Close() }()
	secret := route.ID()

	unregistered, err := randomID()
	if err != nil {
		t.Fatalf("randomID: %v", err)
	}
	conn := dialRouter(t, srv)
	sendRequest(t, conn, int32(commands.SHARED_PORT_CONNECT), unregistered, "scanner", 30, nil)

	// Nothing ever accepts: the first routeQueueDepth requests are queued and
	// logged at Debug, and the one past the queue times out and is logged at
	// Warn.
	for i := 0; i < routeQueueDepth+1; i++ {
		c := dialRouter(t, srv)
		sendRequest(t, c, int32(commands.SHARED_PORT_CONNECT), secret, "legit-peer", 30, nil)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		stats := srv.Stats()
		if stats.Undelivered > 0 && stats.UnknownID > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("router never reached the undelivered and unknown-id paths (stats: %+v)", stats)
		}
		time.Sleep(5 * time.Millisecond)
	}

	out := logs.String()
	for _, msg := range []string{
		"shared-port request for an unregistered id",
		"shared-port connection queued",
		"shared-port connection went unaccepted",
	} {
		if !strings.Contains(out, msg) {
			t.Fatalf("log does not contain %q, so that site was never exercised:\n%s", msg, out)
		}
	}
	for _, id := range []string{secret, unregistered} {
		if strings.Contains(out, id) {
			t.Errorf("log leaks the whole shared-port id %q:\n%s", id, out)
		}
		if !strings.Contains(out, redactID(id)) {
			t.Errorf("log does not carry the redacted id %q, so the lines cannot be correlated:\n%s", redactID(id), out)
		}
	}
}

// TestDuplicateRegistrationErrorRedactsID covers the other way an id escapes:
// an error the caller logs.
func TestDuplicateRegistrationErrorRedactsID(t *testing.T) {
	srv := newTestServer(t, Options{})
	route, err := srv.Register("")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer func() { _ = route.Close() }()

	_, err = srv.Register(route.ID())
	if !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("duplicate Register = %v, want ErrDuplicateID", err)
	}
	if strings.Contains(err.Error(), route.ID()) {
		t.Errorf("duplicate-registration error leaks the whole id: %v", err)
	}
	if !strings.Contains(err.Error(), redactID(route.ID())) {
		t.Errorf("duplicate-registration error = %v, want it to name the redacted id %q", err, redactID(route.ID()))
	}
}
