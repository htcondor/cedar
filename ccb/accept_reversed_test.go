package ccb

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/htcondor/cedar/stream"
)

// scriptedListener hands out conns from a channel in order, and reports a
// closed listener once the channel is drained and closed.
type scriptedListener struct{ conns chan net.Conn }

func (l *scriptedListener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, errors.New("scripted listener exhausted")
	}
	return c, nil
}

func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return nil }

// TestAcceptReversedSkipsSilentPeer: a connection that opens and never sends
// its hello must not hold the serial accept loop. It is dropped after
// reverseConnectHelloTimeout and the target's real connection is accepted,
// even under a context with no deadline of its own.
func TestAcceptReversedSkipsSilentPeer(t *testing.T) {
	saved := reverseConnectHelloTimeout
	reverseConnectHelloTimeout = 100 * time.Millisecond
	defer func() { reverseConnectHelloTimeout = saved }()

	const connectID = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	ctx := context.Background()

	// A peer that connects and says nothing at all.
	silent, silentPeer := net.Pipe()
	defer func() { _ = silentPeer.Close() }()

	// The real target: hello, then a sentinel byte the caller reads back off
	// the returned conn.
	good, goodPeer := net.Pipe()
	defer func() { _ = goodPeer.Close() }()
	writeErr := make(chan error, 1)
	go func() {
		s := stream.NewStream(goodPeer)
		if err := WriteReverseConnect(ctx, s, connectID, "1", "<10.0.0.1:9618>"); err != nil {
			writeErr <- err
			return
		}
		_, err := goodPeer.Write([]byte{0x2a})
		writeErr <- err
	}()

	ln := &scriptedListener{conns: make(chan net.Conn, 2)}
	ln.conns <- silent
	ln.conns <- good

	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := acceptReversed(ctx, ln, connectID)
		done <- result{conn: conn, err: err}
	}()

	var res result
	select {
	case res = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("acceptReversed did not return: a silent peer wedged the accept loop")
	}
	if res.err != nil {
		t.Fatalf("acceptReversed: %v", res.err)
	}
	if res.conn != net.Conn(good) {
		t.Fatalf("acceptReversed returned %p, want the connection that sent the hello", res.conn)
	}

	// The hello deadline must not outlive the hello: the caller runs a full
	// CEDAR handshake on this conn, long after reverseConnectHelloTimeout.
	time.Sleep(2 * reverseConnectHelloTimeout)
	buf := make([]byte, 1)
	if _, err := res.conn.Read(buf); err != nil {
		t.Fatalf("reading from the accepted conn: %v (hello read deadline not cleared?)", err)
	}
	if buf[0] != 0x2a {
		t.Errorf("read %#x from the accepted conn, want 0x2a", buf[0])
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("target write: %v", err)
	}
}
