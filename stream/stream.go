// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package stream provides low-level TCP socket stream management
// and message framing for the CEDAR protocol.
//
// This package implements the binary framing protocol that wraps
// messages before sending them over TCP sockets, based on HTCondor's
// reli_sock.cpp implementation.
package stream

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// Stream represents a CEDAR protocol stream over a TCP connection
type Stream struct {
	conn   net.Conn
	reader io.Reader
	writer io.Writer

	// Connection information
	peerAddr string // Remote address of the connection (in HTCondor sinful string format if possible)

	// receivedFrame records whether the peer has ever sent us a complete
	// frame header. It distinguishes "the daemon never responded" (a
	// shared_port splice to a socket with no daemon resets on our first
	// read, so this stays false) from "the daemon responded and then the
	// connection failed later" -- which must NOT be reported as a daemon
	// that never answered. See annotateSharedPortReset.
	receivedFrame bool

	// Security settings
	encrypted     bool
	authenticated bool

	// AES-GCM encryption
	gcm        cipher.AEAD
	encryptKey []byte

	// Nonce/IV state tracking (matches HTCondor's approach)
	encryptIV      [16]byte // Base IV for encryption (16 bytes for GCM)
	decryptIV      [16]byte // Base IV for decryption (16 bytes for GCM)
	encryptCounter uint32   // Message counter for encryption
	decryptCounter uint32   // Message counter for decryption

	// AAD (Additional Authenticated Data) support for HTCondor compatibility
	sendDigest hash.Hash // SHA-256 digest of all sent data
	recvDigest hash.Hash // SHA-256 digest of all received data
	// sendDigestWritten/recvDigestWritten record whether ANY pre-encryption
	// bytes were fed to the corresponding handshake digest. HTCondor's AES-GCM
	// AAD uses a 32-byte all-zero placeholder (not SHA256 of the empty string)
	// for a direction in which no plaintext was exchanged before encryption --
	// its md_ctx is created lazily on first use, so an unused direction yields
	// zeros (reli_sock.cpp: "Setting ... digest in AAD to N 0's"). This happens
	// on a resumed session with ResumeResponse=false, where the server sends no
	// plaintext handshake reply. Track usage so we can reproduce that zero digest.
	sendDigestWritten bool
	recvDigestWritten bool
	finishedSendAAD   bool   // True after first encrypted frame is sent
	finishedRecvAAD   bool   // True after first encrypted frame is received
	finalSendDigest   []byte // Final digest of all sent data (32 bytes)
	finalRecvDigest   []byte // Final digest of all received data (32 bytes)

	// frameBuf is a reusable scratch buffer for assembling an outbound frame
	// (header + [encrypted] data) in sendMessageWithEnd. Streams are written
	// serially, and writeWithContext returns only after its write has completed
	// (the cancellation path Close()s and waits on the goroutine before returning),
	// so the previous send never still holds this buffer when the next one starts.
	frameBuf []byte

	// EOM (End of Message) handling
	sendBuffer    []byte // Buffer for building messages across multiple writes
	sendEOM       bool   // True if EOM has been indicated for current message
	receiveBuffer []byte // Buffer for accumulating partial frames
	bytesRead     int    // Bytes consumed from current message during decoding
	totalMsgBytes int    // Total bytes in current message being decoded
	inMessage     bool   // True if currently decoding a multi-frame message

	// Timeout settings (matches HTCondor's Stream timeout behavior)
	timeout            time.Duration // Socket timeout duration (0 = no timeout)
	cryptoBeforeSecret bool          // Saved encryption state before sending/receiving secret

	// closed records that Close() has run on this side. net.Conn provides no
	// way to ask whether it is still open, so this is the only thing that makes
	// IsConnected() report false after a close. It is atomic because Close may
	// be called from a goroutine other than the one reading IsConnected.
	closed atomic.Bool
}

// CEDAR protocol constants based on HTCondor's reli_sock.cpp
const (
	// Header sizes from HTCondor reli_sock.cpp
	NormalHeaderSize = 5
	MaxHeaderSize    = NormalHeaderSize // TODO: Add MAC_SIZE when implementing MD

	// Maximum message size from HTCondor (1MB)
	MaxMessageSize = 1024 * 1024

	// MaxTotalMessageSize bounds one logical message reassembled from several
	// frames. MaxMessageSize caps a single frame, but a peer may send an
	// unlimited run of partial frames (end flag 0) and never set the end flag,
	// so without a cumulative bound the reassembly buffer grows until the
	// process dies. Sixteen full frames is far above anything HTCondor sends
	// as one message and still bounds what a hostile peer can make us hold.
	MaxTotalMessageSize = 16 * MaxMessageSize

	// Frame size threshold - send frame when message reaches this size
	DefaultFrameThreshold = 4096 // 4KB default threshold

	// End flag values
	EndFlagPartial  = 0 // More frames follow
	EndFlagComplete = 1 // Last frame in message
)

// NewStream creates a new CEDAR stream from a TCP connection
func NewStream(conn net.Conn) *Stream {
	// Try to get the remote address from the connection
	peerAddr := ""
	if conn != nil && conn.RemoteAddr() != nil {
		// Format as HTCondor sinful string: <ip:port>
		peerAddr = fmt.Sprintf("<%s>", conn.RemoteAddr().String())
	}

	return &Stream{
		conn:       conn,
		reader:     conn,
		writer:     conn,
		peerAddr:   peerAddr,
		sendDigest: sha256.New(),
		recvDigest: sha256.New(),
	}
}

// writeWithContext performs a write operation with context cancellation support.
// It runs the write in a goroutine and monitors the context for cancellation.
// If the context is cancelled, it closes the connection to interrupt the write.
func (s *Stream) writeWithContext(ctx context.Context, data []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Fast path: a context that can never be cancelled -- context.Background()/
	// TODO(), whose Done() channel is nil -- needs no cancellation watcher. Write
	// directly. This is the common case for bulk/streaming paths (e.g. the
	// collector streaming query results) and skips all per-frame overhead.
	if ctx.Done() == nil {
		n, err := s.writer.Write(data)
		if err != nil {
			return err
		}
		if n != len(data) {
			return fmt.Errorf("short write: wrote %d of %d bytes", n, len(data))
		}
		return nil
	}

	// Cancellable context (a deadline and/or an explicit cancel): closing the
	// connection interrupts a blocked Write. context.AfterFunc registers that on
	// the context's existing cancellation machinery -- it starts a goroutine only
	// if cancellation actually fires, so a write that completes in time (the norm)
	// costs no goroutine and no channel, just the AfterFunc node. stop() reports
	// whether it beat the cancellation: true means it prevented the close (clean
	// completion), false means ctx was cancelled and the conn was closed.
	stop := context.AfterFunc(ctx, func() { _ = s.conn.Close() })
	n, err := s.writer.Write(data)
	if !stop() {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	if n != len(data) {
		return fmt.Errorf("short write: wrote %d of %d bytes", n, len(data))
	}
	return nil
}

// readWithContext performs a read operation with context cancellation support.
// If the context is cancelled it closes the connection to interrupt the read.
func (s *Stream) readWithContext(ctx context.Context, data []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Fast path: a non-cancellable context (Done() == nil) needs no watcher; read
	// directly. See writeWithContext for the rationale.
	if ctx.Done() == nil {
		_, err := io.ReadFull(s.reader, data)
		return err
	}

	// Cancellable context: closing the connection interrupts a blocked read.
	// AfterFunc spawns a goroutine only if cancellation fires; a read that
	// completes in time costs none. See writeWithContext.
	stop := context.AfterFunc(ctx, func() { _ = s.conn.Close() })
	_, err := io.ReadFull(s.reader, data)
	if !stop() {
		return ctx.Err()
	}
	return err
}

// SendMessage sends a framed message over the stream
// Uses HTCondor CEDAR protocol format:
// [1 byte: end flag] [4 bytes: message length in network order] [message data]
func (s *Stream) SendMessage(ctx context.Context, data []byte) error {
	return s.sendMessageWithEnd(ctx, data, EndFlagComplete) // Complete message in single frame
}

// grabFrame returns s.frameBuf resized to n bytes, growing it only when the
// current capacity is too small. The returned slice is valid until the next
// grabFrame call on this Stream.
func (s *Stream) grabFrame(n int) []byte {
	if cap(s.frameBuf) < n {
		s.frameBuf = make([]byte, n)
	}
	return s.frameBuf[:n]
}

// sendMessageWithEnd sends a message with specified end flag
func (s *Stream) sendMessageWithEnd(ctx context.Context, data []byte, end byte) error {
	// Bound the ON-WIRE length, not the plaintext. The frame header carries
	// the post-encryption size, and that is the number every receiver checks
	// against MaxMessageSize -- ReceiveFrame below, and HTCondor's
	// ReliSock::rcv_packet. AES-GCM adds its 16-byte tag, plus a 16-byte IV on
	// the first frame of a stream, so capping the plaintext here let an
	// encrypted maximum-size frame go out at 1048608 bytes against a 1048576
	// cap, and the peer killed the frame as oversized. The plaintext a frame
	// can carry is correspondingly smaller once encryption is on.
	if onWire := s.calculateEncryptedSize(len(data)); onWire > MaxMessageSize {
		return fmt.Errorf("message too large: %d bytes on the wire (max %d)", onWire, MaxMessageSize)
	}

	var frame []byte
	var finalHeader [NormalHeaderSize]byte // Use array to avoid heap allocation

	if s.gcm != nil && s.encrypted {
		// Calculate the size overhead from encryption
		encryptedSize := s.calculateEncryptedSize(len(data))

		// Construct header with encrypted data length
		finalHeader[0] = end // End flag
		binary.BigEndian.PutUint32(finalHeader[1:5], uint32(encryptedSize))

		// Single reused buffer for header + encrypted data (see Stream.frameBuf).
		frame = s.grabFrame(NormalHeaderSize + encryptedSize)
		copy(frame[:NormalHeaderSize], finalHeader[:])

		// Encrypt directly into the frame buffer (after header)
		encryptedData, err := s.encryptDataWithAAD(data, finalHeader[:])
		if err != nil {
			return fmt.Errorf("failed to encrypt message: %w", err)
		}
		copy(frame[NormalHeaderSize:], encryptedData)
	} else {
		// No encryption - construct header with plain data length
		finalHeader[0] = end // End flag
		binary.BigEndian.PutUint32(finalHeader[1:5], uint32(len(data)))

		// Single reused buffer for header + data (see Stream.frameBuf).
		frame = s.grabFrame(NormalHeaderSize + len(data))
		copy(frame[:NormalHeaderSize], finalHeader[:])
		copy(frame[NormalHeaderSize:], data)
	}

	// Track cleartext data for AAD digest calculation BEFORE sending
	if s.sendDigest != nil && s.finalSendDigest == nil {
		// Track header (always cleartext for digest purposes)
		s.sendDigest.Write(finalHeader[:])
		// Track original data (cleartext, not encrypted)
		if len(data) > 0 {
			s.sendDigest.Write(data)
		}
		s.sendDigestWritten = true
	}

	// Send complete frame (header + data) in a single write
	if err := s.writeWithContext(ctx, frame); err != nil {
		return fmt.Errorf("failed to write frame: %w", err)
	}

	return nil
}

// SendPartialMessage sends a message frame (end flag = 0)
func (s *Stream) SendPartialMessage(ctx context.Context, data []byte) error {
	return s.sendMessageWithEnd(ctx, data, EndFlagPartial) // More frames follow
}

// ReceiveFrame receives and deframes a message from the stream
// Uses HTCondor CEDAR protocol format:
// [1 byte: end flag] [4 bytes: message length in network order] [message data]
func (s *Stream) ReceiveFrame(ctx context.Context) ([]byte, error) {
	// Read HTCondor-style header (5 bytes)
	header := make([]byte, NormalHeaderSize)
	if err := s.readWithContext(ctx, header); err != nil {
		return nil, fmt.Errorf("failed to read frame header: %w", err)
	}
	// A full header means the peer answered; a later failure is no longer
	// "the daemon never responded".
	s.receivedFrame = true

	// Extract end flag and message length
	endFlag := header[0]
	messageLength := binary.BigEndian.Uint32(header[1:5])

	// Validate message size
	if messageLength > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", messageLength, MaxMessageSize)
	}

	// Validate end flag (HTCondor uses values 0-10)
	if endFlag > 10 {
		return nil, fmt.Errorf("invalid end flag: %d", endFlag)
	}

	// Handle zero-length messages
	if messageLength == 0 {
		// See ReceiveFrameWithEnd: unverifiable on an encrypted stream.
		if s.gcm != nil {
			return nil, fmt.Errorf("zero-length frame on encrypted stream")
		}
		return []byte{}, nil
	}

	// Read message data
	messageData := make([]byte, messageLength)
	if err := s.readWithContext(ctx, messageData); err != nil {
		return nil, fmt.Errorf("failed to read message data: %w", err)
	}

	// Decrypt data if encryption is enabled using AAD
	var clearData []byte
	if s.gcm != nil && s.encrypted {
		decryptedData, err := s.decryptDataWithAAD(messageData, header)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt message: %w", err)
		}
		clearData = decryptedData
	} else {
		clearData = messageData
	}

	// Track cleartext data for AAD digest calculation AFTER decryption
	if s.recvDigest != nil && s.finalRecvDigest == nil {
		s.recvDigest.Write(header)
		s.recvDigest.Write(clearData)
		s.recvDigestWritten = true
	}

	return clearData, nil
}

// ReceiveFrameWithEnd receives a message and returns both data and end flag
func (s *Stream) ReceiveFrameWithEnd(ctx context.Context) ([]byte, byte, error) {
	// Read HTCondor-style header (5 bytes)
	header := make([]byte, NormalHeaderSize)
	if err := s.readWithContext(ctx, header); err != nil {
		return nil, 0, fmt.Errorf("failed to read frame header: %w", err)
	}
	// A full header means the peer answered; a later failure is no longer
	// "the daemon never responded".
	s.receivedFrame = true

	// Extract end flag and message length
	endFlag := header[0]
	messageLength := binary.BigEndian.Uint32(header[1:5])

	// Validate message size
	if messageLength > MaxMessageSize {
		return nil, 0, fmt.Errorf("message too large: %d bytes (max %d)", messageLength, MaxMessageSize)
	}

	// Validate end flag (HTCondor uses values 0-10)
	if endFlag > 10 {
		return nil, 0, fmt.Errorf("invalid end flag: %d", endFlag)
	}

	// Handle zero-length messages
	if messageLength == 0 {
		// An encrypted stream can never legitimately produce one: every frame
		// carries the 16-byte GCM tag (plus the IV on the first), so
		// calculateEncryptedSize never yields 0. Accepting it would return an
		// end-of-message flag that never passed AEAD verification, letting an
		// on-path peer splice message boundaries into the session without the key.
		if s.gcm != nil {
			return nil, 0, fmt.Errorf("zero-length frame on encrypted stream")
		}
		// Track header for AAD digest calculation
		if s.recvDigest != nil && s.finalRecvDigest == nil {
			s.recvDigest.Write(header)
			s.recvDigestWritten = true
		}
		return []byte{}, endFlag, nil
	}

	// Read message data
	messageData := make([]byte, messageLength)
	if err := s.readWithContext(ctx, messageData); err != nil {
		return nil, 0, fmt.Errorf("failed to read message data: %w", err)
	}

	// Decrypt data if encryption is enabled using AAD
	var clearData []byte
	if s.gcm != nil && len(messageData) > 0 {
		decryptedData, err := s.decryptDataWithAAD(messageData, header)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to decrypt message: %w", err)
		}
		clearData = decryptedData
	} else {
		clearData = messageData
	}

	// Track cleartext data for AAD digest calculation AFTER decryption
	if s.recvDigest != nil && s.finalRecvDigest == nil {
		s.recvDigest.Write(header)
		s.recvDigest.Write(clearData)
		s.recvDigestWritten = true
	}

	return clearData, endFlag, nil
}

// IsConnected reports whether this side of the stream is still usable: it has
// a connection and Close() has not been called. It says nothing about whether
// the peer is still reachable -- a peer-side drop is only discoverable by
// doing I/O, and this method does none.
func (s *Stream) IsConnected() bool {
	return s.conn != nil && !s.closed.Load()
}

// Close closes the underlying connection. It is idempotent; a second call is a
// no-op and returns nil.
func (s *Stream) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// GetConnection returns the underlying connection for TLS upgrade
func (s *Stream) GetConnection() net.Conn {
	return s.conn
}

// SetConnection replaces the underlying connection (e.g., with TLS connection)
func (s *Stream) SetConnection(conn net.Conn) {
	s.conn = conn
	s.reader = conn
	s.writer = conn

	// Update peer address if the connection changed
	if conn != nil && conn.RemoteAddr() != nil {
		s.peerAddr = fmt.Sprintf("<%s>", conn.RemoteAddr().String())
	}
}

// GetPeerAddr returns the remote address of the connection in HTCondor sinful string format
func (s *Stream) GetPeerAddr() string {
	return s.peerAddr
}

// SetPeerAddr sets the remote address (useful when the address should be in a specific format)
func (s *Stream) SetPeerAddr(addr string) {
	s.peerAddr = addr
}

// ReceivedFrame reports whether the peer has ever sent a complete frame header
// on this stream. It is false only when nothing was ever read back -- e.g. a
// shared_port splice to a socket with no daemon behind it, which resets on the
// first read. Once true, a subsequent reset/EOF is a mid-conversation failure,
// not an unregistered daemon.
func (s *Stream) ReceivedFrame() bool {
	return s.receivedFrame
}

// WriteMessage writes data to the message buffer
// Data is accumulated until EndMessage() is called or frame threshold is reached
func (s *Stream) WriteMessage(ctx context.Context, data []byte) error {
	if s.sendEOM {
		return fmt.Errorf("cannot write to message after EndMessage() has been called")
	}

	// Append to send buffer
	s.sendBuffer = append(s.sendBuffer, data...)

	// If buffer exceeds threshold, send a partial frame
	if len(s.sendBuffer) >= DefaultFrameThreshold {
		return s.flushPartialFrame(ctx)
	}

	return nil
}

// StartMessage resets EOM state to allow writing a new message
func (s *Stream) StartMessage() {
	s.sendEOM = false
	s.sendBuffer = nil
}

// EndMessage indicates end of message and sends any remaining buffered data
func (s *Stream) EndMessage(ctx context.Context) error {
	if s.sendEOM {
		return fmt.Errorf("EndMessage() already called for this message")
	}

	s.sendEOM = true

	// Send remaining buffer as final frame
	err := s.sendMessageWithEnd(ctx, s.sendBuffer, EndFlagComplete)
	if err != nil {
		return err
	}

	// Reset buffer but keep sendEOM flag true until next message starts
	s.sendBuffer = nil

	return nil
}

// flushPartialFrame sends a partial frame and clears the buffer
func (s *Stream) flushPartialFrame(ctx context.Context) error {
	if len(s.sendBuffer) == 0 {
		return nil
	}

	err := s.sendMessageWithEnd(ctx, s.sendBuffer, EndFlagPartial)
	if err != nil {
		return err
	}

	// Clear buffer for next chunk
	s.sendBuffer = nil
	return nil
}

// ReadMessageBytes reads up to n bytes from the current message
// Returns error if trying to read more bytes than available in current message
func (s *Stream) ReadMessageBytes(ctx context.Context, data []byte) (int, error) {
	if !s.inMessage {
		return 0, fmt.Errorf("no message currently being read")
	}

	available := len(s.receiveBuffer) - s.bytesRead
	if available == 0 {
		// Need to read more frames
		err := s.readNextFrame(ctx)
		if err != nil {
			return 0, err
		}
		available = len(s.receiveBuffer) - s.bytesRead
	}

	// Read up to requested amount or available amount
	toRead := len(data)
	if toRead > available {
		toRead = available
	}

	copy(data[:toRead], s.receiveBuffer[s.bytesRead:s.bytesRead+toRead])
	s.bytesRead += toRead

	return toRead, nil
}

// EndMessageRead indicates that message reading is complete
// Returns error if not all bytes have been consumed
func (s *Stream) EndMessageRead() error {
	if !s.inMessage {
		return fmt.Errorf("no message currently being read")
	}

	if s.bytesRead < s.totalMsgBytes {
		return fmt.Errorf("message not fully consumed: read %d of %d bytes", s.bytesRead, s.totalMsgBytes)
	}

	// Reset for next message
	s.inMessage = false
	s.receiveBuffer = nil
	s.bytesRead = 0
	s.totalMsgBytes = 0

	return nil
}

// StartMessageRead begins reading a complete message (potentially across multiple frames)
func (s *Stream) StartMessageRead(ctx context.Context) error {
	if s.inMessage {
		return fmt.Errorf("already reading a message")
	}

	// Read first frame
	err := s.readNextFrame(ctx)
	if err != nil {
		return err
	}

	s.inMessage = true
	s.bytesRead = 0
	return nil
}

// readNextFrame reads frames until the end of the current message, appending
// each frame's data to the receive buffer.
//
// This iterates rather than recursing: one stack frame per partial frame meant
// a peer that never set the end flag drove the goroutine stack to the runtime's
// "stack exceeds" fatal error, which no caller can recover from. The reassembled
// total is also capped at MaxTotalMessageSize so the same peer cannot grow the
// buffer without bound instead.
func (s *Stream) readNextFrame(ctx context.Context) error {
	for {
		frameData, endFlag, err := s.ReceiveFrameWithEnd(ctx)
		if err != nil {
			return err
		}

		if len(s.receiveBuffer)+len(frameData) > MaxTotalMessageSize {
			return fmt.Errorf("message too large: reassembly exceeds %d bytes", MaxTotalMessageSize)
		}

		// Append frame data to receive buffer
		s.receiveBuffer = append(s.receiveBuffer, frameData...)
		s.totalMsgBytes = len(s.receiveBuffer)

		// If this is the final frame, the message is complete
		if endFlag != EndFlagPartial {
			return nil
		}
	}
}

// ReceiveCompleteMessage receives a complete message, reading multiple frames if necessary
// This is the main method for reading complete messages that may span multiple frames
func (s *Stream) ReceiveCompleteMessage(ctx context.Context) ([]byte, error) {
	var completeMessage []byte

	for {
		frameData, endFlag, err := s.ReceiveFrameWithEnd(ctx)
		if err != nil {
			return nil, err
		}

		// Append this frame's data to the complete message, bounding what a
		// peer that never sets the end flag can make us accumulate.
		if len(completeMessage)+len(frameData) > MaxTotalMessageSize {
			return nil, fmt.Errorf("message too large: reassembly exceeds %d bytes", MaxTotalMessageSize)
		}
		completeMessage = append(completeMessage, frameData...)

		// Check if message is complete
		if endFlag == EndFlagComplete {
			break // This was the final frame
		} else if endFlag == EndFlagPartial {
			// More frames to come, continue reading
			continue
		} else {
			return nil, fmt.Errorf("unexpected end flag: %d", endFlag)
		}
	}

	return completeMessage, nil
}

// finalizeSendDigest freezes the send-side handshake digest for AAD use. If no
// pre-encryption bytes were ever fed to it, the digest is a 32-byte zero block,
// matching HTCondor's lazily-created md_ctx (an unused direction contributes
// zeros, not SHA256 of the empty string). See sendDigestWritten.
func (s *Stream) finalizeSendDigest() {
	if s.finalSendDigest != nil {
		return
	}
	if s.sendDigest != nil && s.sendDigestWritten {
		s.finalSendDigest = s.sendDigest.Sum(nil)
	} else {
		s.finalSendDigest = make([]byte, sha256.Size)
	}
}

// FinalizeDigests freezes both handshake digests. Enabling encryption already does
// this (the digests feed the AAD), but a PLAINTEXT session never enables encryption,
// so without this its per-frame digest would keep running for the life of the
// connection -- hashing every byte of every response for a value that is never used.
// The security layer calls this once a session is established without encryption so
// the application phase (e.g. a large collector query stream) skips the SHA256 work.
// Idempotent and safe to call at any point after the handshake.
func (s *Stream) FinalizeDigests() {
	s.finalizeSendDigest()
	s.finalizeRecvDigest()
}

// finalizeRecvDigest is the receive-side counterpart of finalizeSendDigest.
func (s *Stream) finalizeRecvDigest() {
	if s.finalRecvDigest != nil {
		return
	}
	if s.recvDigest != nil && s.recvDigestWritten {
		s.finalRecvDigest = s.recvDigest.Sum(nil)
	} else {
		s.finalRecvDigest = make([]byte, sha256.Size)
	}
}

// SetSymmetricKey configures AES-GCM encryption with the provided key
func (s *Stream) SetSymmetricKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("AES-256-GCM requires a 32-byte key, got %d bytes", len(key))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return fmt.Errorf("failed to create GCM mode: %w", err)
	}

	s.gcm = gcm
	s.encryptKey = make([]byte, len(key))
	copy(s.encryptKey, key)

	// Initialize IV state following HTCondor's approach
	// Generate random base IV for encryption
	if _, err := rand.Read(s.encryptIV[:]); err != nil {
		return fmt.Errorf("failed to generate encryption IV: %w", err)
	}

	// Reset counters
	s.encryptCounter = 0
	s.decryptCounter = 0

	// Finalize AAD digest state for HTCondor compatibility
	// The digests should contain all data sent/received before encryption was enabled
	s.finishedSendAAD = false
	s.finishedRecvAAD = false

	// Finalize the digests if not already done
	s.finalizeSendDigest()
	s.finalizeRecvDigest()

	// Decrypt IV will be initialized from first received message

	// Automatically enable encryption when key is set
	s.encrypted = true
	return nil
}

// ---------------------------------------------------------------------------
// Live crypto-state export / import (mid-stream resume across an fd handoff)
// ---------------------------------------------------------------------------
//
// These two methods let a live AES-256-GCM CEDAR session be handed to a
// separate process together with its raw connection fd (passed via SCM_RIGHTS).
// The fd alone is insufficient: an established session is mid-flight -- IVs have
// already been exchanged and per-direction message counters are >= 1 -- and the
// only other public crypto entry point, SetSymmetricKey, RESETS to a fresh
// random IV and zero counters, which cannot resume. ExportCryptoState serializes
// the full live crypto+framing state; NewStreamWithCryptoState rebuilds an
// equivalent Stream around a different connection that continues the session
// byte-exactly. This mirrors C++ HTCondor's ReliSock::serialize / CONDOR_INHERIT.
//
// SECURITY / TRUST ASSUMPTION: the exported blob contains the raw 32-byte AES
// session key (and IVs/counters). It is only ever meant to travel over a LOCAL,
// same-user unix socket alongside the fd it describes -- exactly the trust
// domain of C++ CONDOR_INHERIT. Do NOT transmit it over any untrusted channel.

const (
	// cryptoStateMagic identifies an ExportCryptoState blob.
	cryptoStateMagic = "CDRX" // CeDaR eXport
	// cryptoStateVersion is bumped whenever the blob layout changes so a
	// mismatched consumer fails loudly instead of misparsing.
	cryptoStateVersion uint16 = 1

	// cryptoStateFixedLen is the length of the fixed-layout prefix that
	// precedes the variable-length (length-prefixed) trailing fields.
	//   magic(4) + version(2) + flags(1) + encryptKey(32) +
	//   encryptIV(16) + decryptIV(16) + encryptCounter(4) + decryptCounter(4)
	cryptoStateFixedLen = 4 + 2 + 1 + 32 + 16 + 16 + 4 + 4

	// Flag bits packed into the single flags byte.
	csFlagEncrypted         = 1 << 0
	csFlagAuthenticated     = 1 << 1
	csFlagFinishedSendAAD   = 1 << 2
	csFlagFinishedRecvAAD   = 1 << 3
	csFlagSendDigestWritten = 1 << 4
	csFlagRecvDigestWritten = 1 << 5
)

// ExportCryptoState serializes the full live AES-256-GCM crypto and framing
// state required to resume this session byte-exactly on a different connection.
//
// It returns an error unless the stream is at a CLEAN MESSAGE BOUNDARY of an
// established, encrypted session. The clean-boundary check is the core safety
// guarantee: exporting mid-frame would strand buffered plaintext/ciphertext that
// the rebuilt stream could never account for, silently desynchronizing the GCM
// counter/IV stream (the "buffered-bytes hazard"). Each rejection names the
// offending condition so the caller fails loudly rather than corrupting data.
//
// The exported fields and WHY each is needed for byte-exact continuation:
//   - encryptKey (32B): rebuilds the AEAD on the far side. Same key -> same GCM.
//   - encryptIV[16] / decryptIV[16]: the per-direction BASE IVs. The low 4 bytes
//     hold a base counter to which the message counter is added for every frame;
//     the base IV is transmitted inline only on the counter==0 frame. Resuming
//     with counters >= 1 means NO IV is re-sent, so both sides must already agree
//     on these base IVs or every subsequent GCM nonce diverges.
//   - encryptCounter / decryptCounter: the per-direction message counters (>= 1
//     on an established session). They select the GCM nonce for the next frame;
//     off-by-one here is an immediate auth-tag failure.
//   - finishedSendAAD / finishedRecvAAD: mark that each direction's first
//     encrypted frame (which carries the 64-byte handshake-digest AAD) is already
//     past. Restored as true so the rebuilt stream uses header-only AAD for all
//     further frames -- matching the peer, which is likewise past its first frame.
//   - finalSendDigest / finalRecvDigest: the frozen 32-byte handshake digests
//     that formed the first-frame AAD. Not consulted again once the finished
//     flags are true, but exported for completeness and forward compatibility.
//   - sendDigestWritten / recvDigestWritten: whether any pre-encryption bytes
//     fed the handshake digests; preserved so a re-finalization would reproduce
//     the same digest. Inert post-handshake but kept for a faithful restore.
//   - encrypted / authenticated flags and peerAddr: session status + identity.
//
// The blob is a versioned, self-describing binary layout (magic + version) so a
// future field addition is detectable rather than silently misread.
func (s *Stream) ExportCryptoState() ([]byte, error) {
	// --- Established-encrypted-session assertions ---
	if !s.encrypted {
		return nil, fmt.Errorf("ExportCryptoState: stream is not encrypted (encrypted=false)")
	}
	if s.gcm == nil || len(s.encryptKey) != 32 {
		return nil, fmt.Errorf("ExportCryptoState: no AES-256-GCM key established (gcm/encryptKey unset)")
	}
	if !s.finishedSendAAD || !s.finishedRecvAAD {
		return nil, fmt.Errorf("ExportCryptoState: session not past handshake (finishedSendAAD=%v finishedRecvAAD=%v); both directions must have exchanged at least one encrypted frame",
			s.finishedSendAAD, s.finishedRecvAAD)
	}

	// --- Clean-message-boundary assertions (buffered-bytes hazard guard) ---
	if s.inMessage {
		return nil, fmt.Errorf("ExportCryptoState: not at a clean boundary (inMessage set: a multi-frame receive is in progress)")
	}
	if s.bytesRead != 0 {
		return nil, fmt.Errorf("ExportCryptoState: not at a clean boundary (bytesRead=%d: inbound message partially consumed)", s.bytesRead)
	}
	if len(s.receiveBuffer) != 0 {
		return nil, fmt.Errorf("ExportCryptoState: not at a clean boundary (receiveBuffer=%d bytes: buffered inbound frame not yet consumed)", len(s.receiveBuffer))
	}
	if len(s.sendBuffer) != 0 {
		return nil, fmt.Errorf("ExportCryptoState: not at a clean boundary (sendBuffer=%d bytes: partial outbound message)", len(s.sendBuffer))
	}
	if s.sendEOM {
		return nil, fmt.Errorf("ExportCryptoState: not at a clean boundary (sendEOM set: outbound message end-of-message pending StartMessage)")
	}

	var flags byte
	if s.encrypted {
		flags |= csFlagEncrypted
	}
	if s.authenticated {
		flags |= csFlagAuthenticated
	}
	if s.finishedSendAAD {
		flags |= csFlagFinishedSendAAD
	}
	if s.finishedRecvAAD {
		flags |= csFlagFinishedRecvAAD
	}
	if s.sendDigestWritten {
		flags |= csFlagSendDigestWritten
	}
	if s.recvDigestWritten {
		flags |= csFlagRecvDigestWritten
	}

	buf := bytes.NewBuffer(make([]byte, 0, cryptoStateFixedLen+96))
	buf.WriteString(cryptoStateMagic)
	_ = binary.Write(buf, binary.BigEndian, cryptoStateVersion)
	buf.WriteByte(flags)
	buf.Write(s.encryptKey)   // exactly 32 bytes (checked above)
	buf.Write(s.encryptIV[:]) // 16 bytes
	buf.Write(s.decryptIV[:]) // 16 bytes
	_ = binary.Write(buf, binary.BigEndian, s.encryptCounter)
	_ = binary.Write(buf, binary.BigEndian, s.decryptCounter)

	writeVar := func(b []byte) {
		_ = binary.Write(buf, binary.BigEndian, uint16(len(b)))
		buf.Write(b)
	}
	writeVar(s.finalSendDigest)
	writeVar(s.finalRecvDigest)
	writeVar([]byte(s.peerAddr))

	return buf.Bytes(), nil
}

// NewStreamWithCryptoState builds a Stream around conn (as NewStream does) and
// then restores the live crypto+framing state previously produced by
// ExportCryptoState, so the returned stream continues the same AES-256-GCM
// session byte-exactly. The AEAD is rebuilt from the exported key exactly as
// SetSymmetricKey constructs it, but WITHOUT regenerating the IV or zeroing the
// counters -- the exported IVs/counters/digests/flags are restored verbatim.
//
// It rejects a version mismatch, a truncated blob, or a bad magic so a stale or
// corrupt blob fails loudly. conn is typically the SCM_RIGHTS-passed fd wrapped
// as a net.Conn; the blob describes the session that fd is carrying.
func NewStreamWithCryptoState(conn net.Conn, blob []byte) (*Stream, error) {
	if len(blob) < cryptoStateFixedLen {
		return nil, fmt.Errorf("NewStreamWithCryptoState: blob too short: %d bytes (need at least %d)", len(blob), cryptoStateFixedLen)
	}
	if string(blob[:4]) != cryptoStateMagic {
		return nil, fmt.Errorf("NewStreamWithCryptoState: bad magic %q (expected %q)", blob[:4], cryptoStateMagic)
	}
	off := 4
	version := binary.BigEndian.Uint16(blob[off : off+2])
	off += 2
	if version != cryptoStateVersion {
		return nil, fmt.Errorf("NewStreamWithCryptoState: unsupported crypto-state version %d (expected %d)", version, cryptoStateVersion)
	}

	flags := blob[off]
	off++

	encryptKey := make([]byte, 32)
	copy(encryptKey, blob[off:off+32])
	off += 32

	var encryptIV, decryptIV [16]byte
	copy(encryptIV[:], blob[off:off+16])
	off += 16
	copy(decryptIV[:], blob[off:off+16])
	off += 16

	encryptCounter := binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	decryptCounter := binary.BigEndian.Uint32(blob[off : off+4])
	off += 4

	// Variable-length trailer: three uint16-length-prefixed byte fields.
	readVar := func(name string) ([]byte, error) {
		if off+2 > len(blob) {
			return nil, fmt.Errorf("NewStreamWithCryptoState: truncated blob reading %s length", name)
		}
		n := int(binary.BigEndian.Uint16(blob[off : off+2]))
		off += 2
		if off+n > len(blob) {
			return nil, fmt.Errorf("NewStreamWithCryptoState: truncated blob reading %s (%d bytes)", name, n)
		}
		out := make([]byte, n)
		copy(out, blob[off:off+n])
		off += n
		return out, nil
	}
	finalSendDigest, err := readVar("finalSendDigest")
	if err != nil {
		return nil, err
	}
	finalRecvDigest, err := readVar("finalRecvDigest")
	if err != nil {
		return nil, err
	}
	peerAddrBytes, err := readVar("peerAddr")
	if err != nil {
		return nil, err
	}

	// Rebuild the AEAD exactly as SetSymmetricKey does (AES-256 + 16-byte-nonce
	// GCM), but leave IVs/counters as restored below rather than regenerating.
	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return nil, fmt.Errorf("NewStreamWithCryptoState: failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, fmt.Errorf("NewStreamWithCryptoState: failed to create GCM mode: %w", err)
	}

	s := NewStream(conn)
	s.gcm = gcm
	s.encryptKey = encryptKey
	s.encryptIV = encryptIV
	s.decryptIV = decryptIV
	s.encryptCounter = encryptCounter
	s.decryptCounter = decryptCounter
	if len(finalSendDigest) > 0 {
		s.finalSendDigest = finalSendDigest
	}
	if len(finalRecvDigest) > 0 {
		s.finalRecvDigest = finalRecvDigest
	}
	s.finishedSendAAD = flags&csFlagFinishedSendAAD != 0
	s.finishedRecvAAD = flags&csFlagFinishedRecvAAD != 0
	s.sendDigestWritten = flags&csFlagSendDigestWritten != 0
	s.recvDigestWritten = flags&csFlagRecvDigestWritten != 0
	s.encrypted = flags&csFlagEncrypted != 0
	s.authenticated = flags&csFlagAuthenticated != 0

	// The blob's peerAddr describes the ORIGINAL peer of the handed-off session;
	// prefer it over the local address of the (possibly unix-socket) conn.
	if len(peerAddrBytes) > 0 {
		s.peerAddr = string(peerAddrBytes)
	}

	return s, nil
}

// calculateEncryptedSize returns the size of data after AES-GCM encryption
func (s *Stream) calculateEncryptedSize(plainSize int) int {
	if !s.encrypted || s.gcm == nil {
		return plainSize
	}

	// AES-GCM adds 16 bytes for authentication tag
	result := plainSize + 16

	// First packet also includes 16-byte IV
	if s.encryptCounter == 0 {
		result += 16
	}

	return result
}

// encryptDataWithAAD encrypts data using AES-GCM with HTCondor-compatible AAD
func (s *Stream) encryptDataWithAAD(data []byte, frameHeader []byte) ([]byte, error) {
	if !s.encrypted || s.gcm == nil {
		return data, nil // No encryption
	}

	// Check if we've hit the maximum counter (HTCondor safety check)
	if s.encryptCounter == 0xffffffff {
		return nil, fmt.Errorf("hit maximum number of packets per connection")
	}

	// Determine if we need to send the IV (only on first message)
	sendingIV := (s.encryptCounter == 0)

	// Construct IV following HTCondor's approach:
	// Take base IV, replace first 4 bytes with (base_counter + message_counter)
	var iv [16]byte
	copy(iv[:], s.encryptIV[:])

	// Extract base counter from first 4 bytes of base IV (network byte order)
	baseCounter := binary.BigEndian.Uint32(s.encryptIV[:4])

	// Add message counter to base counter
	finalCounter := baseCounter + s.encryptCounter

	// Put final counter back into first 4 bytes of IV (network byte order)
	binary.BigEndian.PutUint32(iv[:4], finalCounter)

	// Construct AAD according to HTCondor specification
	var aad []byte
	if !s.finishedSendAAD {
		// First frame: AAD = SHA256(sent_data) + SHA256(recv_data) + frame_header
		s.finishedSendAAD = true

		// Finalize digests if not already done
		s.finalizeSendDigest()
		s.finalizeRecvDigest()

		// Construct AAD: sent_digest(32) + recv_digest(32) + frame_header(5) = 69 bytes
		aad = make([]byte, 32+32+len(frameHeader))
		copy(aad[0:32], s.finalSendDigest)
		copy(aad[32:64], s.finalRecvDigest)
		copy(aad[64:], frameHeader)
	} else {
		// Subsequent frames: AAD = frame_header only (5 bytes)
		aad = make([]byte, len(frameHeader))
		copy(aad, frameHeader)
	}

	// Encrypt data with the constructed IV and AAD (use full 16 bytes for GCM)
	ciphertext := s.gcm.Seal(nil, iv[:], data, aad)

	// Calculate output size: ciphertext + optional IV
	outputSize := len(ciphertext)
	if sendingIV {
		outputSize += 16 // Add IV size for first packet
	}

	// Build result: [IV (first packet only)] + [encrypted data + auth tag]
	result := make([]byte, outputSize)
	offset := 0

	if sendingIV {
		// Include base IV in first packet (HTCondor sends the base IV)
		copy(result[offset:], s.encryptIV[:])
		offset += 16
	}

	// Add encrypted data + authentication tag
	copy(result[offset:], ciphertext)

	// Increment counter only after successful encryption
	s.encryptCounter++

	return result, nil
}

// decryptDataWithAAD decrypts data using AES-GCM with HTCondor-compatible AAD
func (s *Stream) decryptDataWithAAD(data []byte, frameHeader []byte) ([]byte, error) {
	if !s.encrypted || s.gcm == nil {
		return data, nil // No decryption
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("empty encrypted data")
	}

	var iv [16]byte
	var encryptedData []byte
	offset := 0

	// Check if IV is included (first packet)
	expectIV := (s.decryptCounter == 0)

	if expectIV {
		if len(data) < 16 {
			return nil, fmt.Errorf("encrypted data too short to contain IV")
		}
		// Extract IV from data
		copy(s.decryptIV[:], data[:16])
		offset = 16
	}

	// Prepare IV for decryption: base IV with counter
	copy(iv[:], s.decryptIV[:])

	// Extract base counter and add message counter
	baseCounter := binary.BigEndian.Uint32(s.decryptIV[:4])
	finalCounter := baseCounter + s.decryptCounter
	binary.BigEndian.PutUint32(iv[:4], finalCounter)

	// Extract encrypted data (remaining bytes after optional IV)
	encryptedData = data[offset:]

	if len(encryptedData) < 16 { // Need at least auth tag
		return nil, fmt.Errorf("encrypted data too short for auth tag")
	}

	// Construct AAD according to HTCondor specification
	var aad []byte
	if !s.finishedRecvAAD {
		// First frame: AAD = SHA256(sent_data) + SHA256(recv_data) + frame_header
		s.finishedRecvAAD = true

		// Finalize digests if not already done
		s.finalizeSendDigest()
		s.finalizeRecvDigest()

		// Construct AAD: sent_digest(32) + recv_digest(32) + frame_header(5) = 69 bytes
		// NOTE: Order is different for decryption - recv first, then send
		aad = make([]byte, 32+32+len(frameHeader))
		copy(aad[0:32], s.finalRecvDigest)
		copy(aad[32:64], s.finalSendDigest)
		copy(aad[64:], frameHeader)
	} else {
		// Subsequent frames: AAD = frame_header only (5 bytes)
		aad = make([]byte, len(frameHeader))
		copy(aad, frameHeader)
	}

	// Decrypt data with the constructed IV and AAD (use full 16 bytes for GCM)
	plaintext, err := s.gcm.Open(nil, iv[:], encryptedData, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %v", err)
	}

	// Increment counter only after successful decryption
	s.decryptCounter++

	return plaintext, nil
}

// IsAuthenticated returns true if the stream has completed authentication
func (s *Stream) IsAuthenticated() bool {
	return s.authenticated
}

// IsEncrypted returns true if the stream is using encryption
func (s *Stream) IsEncrypted() bool {
	return s.encrypted
}

// SetAuthenticated sets the authentication status of the stream
func (s *Stream) SetAuthenticated(authenticated bool) {
	s.authenticated = authenticated
}

// SetEncrypted sets the encryption status of the stream
func (s *Stream) SetEncrypted(encrypted bool) {
	s.encrypted = encrypted
}

//
// STREAMINTERFACE IMPLEMENTATION
//

// ReadFrame reads a single frame from the stream and returns the data and EOM flag
func (s *Stream) ReadFrame(ctx context.Context) ([]byte, bool, error) {
	data, endByte, err := s.ReceiveFrameWithEnd(ctx)
	if err != nil {
		return nil, false, err
	}
	// EOM is indicated by endByte != 0 in CEDAR protocol
	isEOM := endByte != 0
	return data, isEOM, nil
}

// WriteFrame writes a single frame to the stream with the EOM flag
func (s *Stream) WriteFrame(ctx context.Context, data []byte, isEOM bool) error {
	if isEOM {
		return s.SendMessage(ctx, data)
	} else {
		return s.SendPartialMessage(ctx, data)
	}
}

//
// SOCKET OPERATION APIS
//

// SetTimeout sets the socket timeout duration
// Based on HTCondor's Stream::timeout() from stream.cpp
// A timeout of 0 means no timeout (blocking indefinitely)
func (s *Stream) SetTimeout(duration time.Duration) error {
	s.timeout = duration

	// Apply timeout to the underlying TCP connection if available
	if tcpConn, ok := s.conn.(*net.TCPConn); ok {
		if duration > 0 {
			deadline := time.Now().Add(duration)
			return tcpConn.SetDeadline(deadline)
		} else {
			// Clear deadline
			return tcpConn.SetDeadline(time.Time{})
		}
	}
	return nil
}

// GetTimeout returns the current socket timeout duration
func (s *Stream) GetTimeout() time.Duration {
	return s.timeout
}

// GetEncryption returns true if encryption is currently enabled
// Based on HTCondor's Stream::get_encryption() from stream.cpp
func (s *Stream) GetEncryption() bool {
	return s.encrypted
}

// SetCryptoMode enables or disables encryption on the stream
// Based on HTCondor's Stream::set_crypto_mode() from stream.cpp
// Returns false if encryption cannot be enabled (e.g., no key exchanged)
func (s *Stream) SetCryptoMode(enabled bool) bool {
	if enabled {
		// Can only enable if we have encryption set up
		if s.gcm != nil {
			s.encrypted = true
			return true
		}
		return false
	}

	// Disable encryption
	s.encrypted = false
	return true
}

// prepareCryptoForSecret prepares encryption state before sending/receiving a secret
// Based on HTCondor's Stream::prepare_crypto_for_secret() from stream.cpp
func (s *Stream) prepareCryptoForSecret() {
	s.cryptoBeforeSecret = s.encrypted
	// Enable encryption if available
	if s.gcm != nil && !s.encrypted {
		s.encrypted = true
	}
}

// restoreCryptoAfterSecret restores encryption state after sending/receiving a secret
// Based on HTCondor's Stream::restore_crypto_after_secret() from stream.cpp
func (s *Stream) restoreCryptoAfterSecret() {
	s.encrypted = s.cryptoBeforeSecret
}

// PrepareCryptoForSecret / RestoreCryptoAfterSecret expose the crypto-for-secret
// toggle to the message layer. A ClassAd on the wire may carry a private attribute
// inline as a SECRET_MARKER followed by a put_secret field (see message
// GetClassAdRaw); reading that field requires the same temporary crypto state the
// sender used, but the read happens through the buffered Message API rather than a
// single Stream.GetSecret call.
func (s *Stream) PrepareCryptoForSecret()   { s.prepareCryptoForSecret() }
func (s *Stream) RestoreCryptoAfterSecret() { s.restoreCryptoAfterSecret() }

// CryptoForSecretIsNoop reports whether toggling crypto for a secret would change
// nothing: either the channel is already encrypted (so a secret is no different
// from any other field) or no session key exists (so a secret cannot be encrypted
// and must go in the clear). It mirrors C++ Stream::prepare_crypto_for_secret_is_noop.
// A sender uses it to decide whether to wrap a private attribute in a SECRET_MARKER
// + put_secret (only worthwhile when crypto is available but not currently on).
func (s *Stream) CryptoForSecretIsNoop() bool { return s.gcm == nil || s.encrypted }

// PutSecret sends a secret string with automatic encryption
// Based on HTCondor's Stream::put_secret() from stream.cpp
// Temporarily enables encryption if possible, then restores previous state
func (s *Stream) PutSecret(ctx context.Context, secret string) error {
	s.prepareCryptoForSecret()
	defer s.restoreCryptoAfterSecret()

	// Use standard string sending mechanism
	return s.SendMessage(ctx, []byte(secret+"\x00")) // Null-terminated
}

// GetSecret receives a secret string with automatic encryption
// Based on HTCondor's Stream::get_secret() from stream.cpp
// Temporarily enables encryption if possible, then restores previous state
func (s *Stream) GetSecret(ctx context.Context) (string, error) {
	s.prepareCryptoForSecret()
	defer s.restoreCryptoAfterSecret()

	// Receive the message
	data, err := s.ReceiveFrame(ctx)
	if err != nil {
		return "", err
	}

	// Remove null terminator if present
	if len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}

	return string(data), nil
}

// PutFile sends a file over the stream
// Based on HTCondor's ReliSock::put_file() from reli_sock.cpp
// Returns the number of bytes sent
func (s *Stream) PutFile(ctx context.Context, filename string) (int64, error) {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return 0, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer func() { _ = file.Close() }()

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("failed to stat file %s: %w", filename, err)
	}
	fileSize := fileInfo.Size()

	// Send file size first (as 8-byte big-endian)
	sizeData := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeData, uint64(fileSize))
	if err := s.SendMessage(ctx, sizeData); err != nil {
		return 0, fmt.Errorf("failed to send file size: %w", err)
	}

	// Send file data in chunks
	const bufSize = 65536 // 64KB buffer
	buffer := make([]byte, bufSize)
	var totalSent int64

	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return totalSent, fmt.Errorf("failed to read file: %w", err)
		}
		if n == 0 {
			break
		}

		// Send this chunk
		if err := s.SendMessage(ctx, buffer[:n]); err != nil {
			return totalSent, fmt.Errorf("failed to send file chunk: %w", err)
		}
		totalSent += int64(n)

		if err == io.EOF {
			break
		}
	}

	// Send end-of-file marker (666 as 4-byte big-endian, per HTCondor)
	eofMarker := make([]byte, 4)
	binary.BigEndian.PutUint32(eofMarker, 666)
	if err := s.SendMessage(ctx, eofMarker); err != nil {
		return totalSent, fmt.Errorf("failed to send EOF marker: %w", err)
	}

	return totalSent, nil
}

// GetFile receives a file from the stream
// Based on HTCondor's ReliSock::get_file() from reli_sock.cpp
// Returns the number of bytes received
func (s *Stream) GetFile(ctx context.Context, filename string) (int64, error) {
	// Receive file size first (8-byte big-endian)
	sizeData, err := s.ReceiveFrame(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to receive file size: %w", err)
	}
	if len(sizeData) != 8 {
		return 0, fmt.Errorf("invalid file size data: got %d bytes, expected 8", len(sizeData))
	}
	fileSize := int64(binary.BigEndian.Uint64(sizeData))

	// Create the output file
	file, err := os.Create(filename)
	if err != nil {
		return 0, fmt.Errorf("failed to create file %s: %w", filename, err)
	}
	defer func() { _ = file.Close() }()

	// Receive file data in chunks
	var totalReceived int64
	for totalReceived < fileSize {
		chunk, err := s.ReceiveFrame(ctx)
		if err != nil {
			return totalReceived, fmt.Errorf("failed to receive file chunk: %w", err)
		}

		n, err := file.Write(chunk)
		if err != nil {
			return totalReceived, fmt.Errorf("failed to write to file: %w", err)
		}
		totalReceived += int64(n)
	}

	// Receive and verify EOF marker (666 as 4-byte big-endian)
	eofData, err := s.ReceiveFrame(ctx)
	if err != nil {
		return totalReceived, fmt.Errorf("failed to receive EOF marker: %w", err)
	}
	if len(eofData) != 4 {
		return totalReceived, fmt.Errorf("invalid EOF marker: got %d bytes, expected 4", len(eofData))
	}
	eofMarker := binary.BigEndian.Uint32(eofData)
	if eofMarker != 666 {
		return totalReceived, fmt.Errorf("invalid EOF marker: got %d, expected 666", eofMarker)
	}

	return totalReceived, nil
}
