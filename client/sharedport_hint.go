package client

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"

	"github.com/htcondor/cedar/addresses"
)

// isConnResetOrEOF reports whether err is the wire symptom of the peer dropping the
// connection abruptly with no orderly protocol reply: a TCP reset, a broken pipe, or an
// EOF / unexpected EOF while a read was still expecting data. It deliberately does NOT
// match protocol- or auth-level rejections (which carry a message from the daemon) --
// only the "the other end simply went away" cases.
func isConnResetOrEOF(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, net.ErrClosed) {
		return true
	}
	// Some platforms surface the OS error only in the message (not as a typed errno
	// reachable through errors.Is), so fall back to the canonical wording.
	s := err.Error()
	return strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "forcibly closed") // Windows wording for a reset
}

// annotateSharedPortReset improves the error from a shared-port connection that failed
// with an abrupt reset/EOF during the initial handshake.
//
// HTCondor's shared_port server accepts the TCP connection on the shared port and then
// splices it to the target daemon's named unix socket. The client sends its
// SHARED_PORT_CONNECT request fire-and-forget (shared_port sends no reply) and proceeds
// straight into the CEDAR handshake with whatever is on the other side. When no daemon is
// registered under that socket name -- it is still starting up, has exited, or was just
// restarted -- shared_port resets the connection, and the only symptom the client sees is
// a bare "connection reset by peer" on its first read, with nothing to say shared_port
// routing was even involved. Wrap that into something an operator can act on.
//
// Non-shared-port addresses, and shared-port failures that carry a real protocol/auth
// message (not a bare reset), are returned unchanged.
//
// daemonResponded must be true when the peer already sent at least one frame on
// this connection (see Stream.ReceivedFrame). A reset/EOF after the daemon has
// answered -- e.g. a post-authentication EOF once the security handshake is well
// underway -- is a mid-conversation failure, and calling it "the daemon did not
// respond / is not registered" is actively misleading. Only a reset before any
// response earns that hint.
func annotateSharedPortReset(address string, daemonResponded bool, err error) error {
	if err == nil {
		return nil
	}
	if daemonResponded {
		return err
	}
	addrInfo := addresses.ParseHTCondorAddress(address)
	if !addrInfo.IsSharedPort || !isConnResetOrEOF(err) {
		return err
	}
	return fmt.Errorf("shared_port at %s accepted the connection but the target daemon "+
		"(sock=%s) did not respond -- it may be starting up, or is not currently registered "+
		"with shared_port: %w", addrInfo.ServerAddr, addrInfo.SharedPortID, err)
}
