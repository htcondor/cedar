package sharedport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/htcondor/cedar/commands"
)

// The shared-port endpoint handshake.
//
// A condor_shared_port daemon multiplexes many daemons onto a single
// network port. When it decides a connection belongs to a particular
// endpoint, it hands the connected client fd off to that endpoint over
// a Unix-domain socket. This is the general shared-port endpoint
// mechanism; it is not specific to any application protocol carried on
// the forwarded connection.
//
// Wire protocol on the UDS, per shared_port_server / shared_port_endpoint:
//
//  1. The server sends a single CEDAR-framed message containing the
//     int command SHARED_PORT_PASS_SOCK terminated by an
//     end-of-message marker.
//  2. The server then sendmsg(2)s a 1-byte iov plus an SCM_RIGHTS
//     ancillary record carrying the connected client fd.
//  3. No application-level ack is sent in either direction; the UDS
//     connection is then closed by the server.
//
// The forwarded fd is modeled as a net.Conn value produced by the
// Listener's net.Listener implementation, so callers can treat it like
// any other accepted connection.

// CEDAR's framed wire format on a connection:
//
//	[1 byte: end flag] [4 bytes: payload length, big-endian] [payload]
//
// PutInt encodes its value as 8 bytes big-endian (uint64), so a single
// "PutInt; FinishMessage" is one frame whose payload length is 8.
const (
	cedarHeaderSize    = 5  // 1-byte end flag + 4-byte length
	cedarIntPayloadLen = 8  // PutInt encodes int64
	maxHeaderPayload   = 64 // sanity bound; the only valid command here is 8 bytes
)

// readPassSockHeader consumes the CEDAR-framed header sent by shared_port
// over the UDS, validates that it carries SHARED_PORT_PASS_SOCK, and
// returns nil on success. Anything else (short read, bad length, wrong
// command) returns a descriptive error so the caller can drop the
// connection without engaging recvmsg.
func readPassSockHeader(r io.Reader) error {
	var hdr [cedarHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("read CEDAR frame header: %w", err)
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length == 0 || length > maxHeaderPayload {
		return fmt.Errorf("unexpected CEDAR frame length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("read CEDAR frame payload: %w", err)
	}
	if len(payload) != cedarIntPayloadLen {
		return fmt.Errorf("expected %d-byte int payload, got %d", cedarIntPayloadLen, len(payload))
	}
	//nolint:gosec // CEDAR ints are 8 bytes; we compare against a small constant
	cmd := int64(binary.BigEndian.Uint64(payload))
	if cmd != int64(commands.SHARED_PORT_PASS_SOCK) {
		return fmt.Errorf("unexpected command %d; want SHARED_PORT_PASS_SOCK (%d)", cmd, commands.SHARED_PORT_PASS_SOCK)
	}
	return nil
}

// writePassSockHeader is the producer side of the CEDAR-framed header.
// Used by tests (and in principle by any client that wants to emulate
// shared_port's handshake) so we can exercise the receiver in-process
// without standing up condor_shared_port.
//
// We pick endFlag = 1 ("complete message in single frame") to match
// the value cedar's stream.SendMessage emits.
func writePassSockHeader(w io.Writer) error {
	var frame [cedarHeaderSize + cedarIntPayloadLen]byte
	frame[0] = 1 // EndFlagComplete
	binary.BigEndian.PutUint32(frame[1:5], cedarIntPayloadLen)
	binary.BigEndian.PutUint64(frame[5:13], uint64(commands.SHARED_PORT_PASS_SOCK))
	_, err := w.Write(frame[:])
	return err
}

// errClosed signals that the listener has been Close()'d. Returned via
// Accept() so http.Server.Serve recognises shutdown rather than tight-
// looping on the failure.
var errClosed = errors.New("sharedport: listener closed")
