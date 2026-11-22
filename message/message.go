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

// Package message provides serialization and deserialization
// of CEDAR protocol messages and frames.
//
// This package implements the type serialization system used by
// HTCondor's CEDAR protocol, based on stream.cpp implementation.
//
// Key concepts:
// - Frame: A single CEDAR protocol frame with fixed maximum size
// - Message: A logical message that may span multiple frames
// - Stream: Handles frame-level protocol and encryption
//
// The type serialization follows HTCondor's exact binary format:
// - Integers: 64-bit values in network (big-endian) byte order
// - Doubles: Split into fractional and exponential parts for portability
// - Strings: Null-terminated with optional encryption length prefix
// - All types support bidirectional encoding/decoding
package message

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/PelicanPlatform/classad/classad"
)

// ErrStringSizeExceeded is returned when a string exceeds the maximum allowed size
// The error includes the actual length and the maximum size limit
type ErrStringSizeExceeded struct {
	Length  int
	MaxSize int
}

func (e *ErrStringSizeExceeded) Error() string {
	return fmt.Sprintf("string length (%d bytes) exceeds maximum allowed size (%d bytes)", e.Length, e.MaxSize)
}

// Constants from HTCondor stream.cpp
const (
	// FRAC_CONST used for double encoding - must match HTCondor's value
	FracConst = 2147483647 // 2^31 - 1
	// BinNullChar used to represent NULL strings
	BinNullChar = '\255'
	// IntSize is the number of bytes for integers on the wire
	IntSize = 8 // HTCondor sends 64-bit integers
	// MaxFrameSize maximum size for a single frame payload
	MaxFrameSize = 1024 * 1024 // 1MB frames
	// TargetFrameSize optimal frame size for network efficiency
	TargetFrameSize = 16 * 1024 // 16KB frames
)

// CodingDirection represents the stream direction (encode vs decode)
type CodingDirection int

const (
	CodingEncode CodingDirection = iota
	CodingDecode
	CodingUnknown
)

// StreamInterface defines the interface needed from Stream to read/write frames
type StreamInterface interface {
	ReadFrame(ctx context.Context) ([]byte, bool, error) // data, isEOM, error
	WriteFrame(ctx context.Context, data []byte, isEOM bool) error
	IsEncrypted() bool
}

// Frame represents a single CEDAR protocol frame containing raw bytes only
// Use Message for data serialization operations
type Frame struct {
	buffer *bytes.Buffer
}

// NewFrame creates a new empty frame for writing
func NewFrame() *Frame {
	return &Frame{
		buffer: &bytes.Buffer{},
	}
}

// NewFrameFromBytes creates a frame from existing bytes for reading
func NewFrameFromBytes(data []byte) *Frame {
	return &Frame{
		buffer: bytes.NewBuffer(data),
	}
}

// PutBytes writes raw bytes to the message
func (f *Frame) PutBytes(data []byte) (int, error) {
	return f.buffer.Write(data)
}

// GetBytes reads raw bytes from the message
func (f *Frame) GetBytes(data []byte) (int, error) {
	return f.buffer.Read(data)
}

//
// UTILITY METHODS
//

// Bytes returns the message content as bytes
func (f *Frame) Bytes() []byte {
	return f.buffer.Bytes()
}

// Len returns the current message length
func (f *Frame) Len() int {
	return f.buffer.Len()
}

// Reset clears the message buffer
func (f *Frame) Reset() {
	f.buffer.Reset()
}

// WriteTo writes the frame content to a writer
func (f *Frame) WriteTo(w io.Writer) (int64, error) {
	return f.buffer.WriteTo(w)
}

//
// NEW STREAMING MESSAGE IMPLEMENTATION
//

// Message represents a streaming CEDAR protocol message that may span multiple frames
// Messages automatically read additional frames from the Stream as needed
type Message struct {
	stream    StreamInterface
	buffer    *bytes.Buffer // Current frame data buffer
	direction CodingDirection
	isEOM     bool // End of Message flag from last frame read
	finished  bool // Message has been completely read
}

// NewMessageFromStream creates a new message for reading from a stream
func NewMessageFromStream(stream StreamInterface) *Message {
	return &Message{
		stream:    stream,
		buffer:    &bytes.Buffer{},
		direction: CodingDecode,
		isEOM:     false,
		finished:  false,
	}
}

// NewMessageForStream creates a new message for writing to a stream
func NewMessageForStream(stream StreamInterface) *Message {
	return &Message{
		stream:    stream,
		buffer:    &bytes.Buffer{},
		direction: CodingEncode,
		isEOM:     false,
		finished:  false,
	}
}

// ensureData ensures there's enough data in the buffer for the requested read
// If not enough data is available, it reads additional frames from the stream
func (m *Message) ensureData(ctx context.Context, needed int) error {
	// Keep reading frames until we have enough data or reach EOM
	for m.buffer.Len() < needed && !m.isEOM {
		frameData, isEOM, err := m.stream.ReadFrame(ctx)
		if err != nil {
			return err
		}

		// Append frame data to our buffer
		if len(frameData) > 0 {
			m.buffer.Write(frameData)
		}

		m.isEOM = isEOM
	}

	// Check if we have enough data
	if m.buffer.Len() < needed {
		if m.isEOM {
			// We've reached end of message but don't have enough data
			m.finished = true
			return io.EOF
		}
		// This shouldn't happen - we should have either gotten more data or EOM
		return fmt.Errorf("unexpected state: no more frames but not at EOM")
	}

	return nil
}

// IsEncode returns true if in encode mode
func (m *Message) IsEncode() bool {
	return m.direction == CodingEncode
}

// IsDecode returns true if in decode mode
func (m *Message) IsDecode() bool {
	return m.direction == CodingDecode
}

// Finished returns true if the message has been completely read
func (m *Message) Finished() bool {
	return m.finished && m.buffer.Len() == 0
}

// PeekEndOfMessage reports whether the message is exhausted -- i.e. no more
// fields remain before end-of-message -- without consuming any field. It pulls
// in pending frames the same way ensureData does, so the answer is reliable even
// when the message is fragmented across frames. Use it to read an optional
// trailing field: peek, and only Get the field when this returns false. Mirrors
// CEDAR's ReliSock::peek_end_of_message().
func (m *Message) PeekEndOfMessage(ctx context.Context) (bool, error) {
	if m.direction != CodingDecode {
		return false, fmt.Errorf("can only peek in decode mode")
	}
	// Read frames until a byte is buffered (more data remains) or EOM is
	// reached with nothing buffered (the message is done).
	for m.buffer.Len() == 0 && !m.isEOM {
		frameData, isEOM, err := m.stream.ReadFrame(ctx)
		if err != nil {
			return false, err
		}
		if len(frameData) > 0 {
			m.buffer.Write(frameData)
		}
		m.isEOM = isEOM
	}
	return m.buffer.Len() == 0 && m.isEOM, nil
}

// FlushFrame sends the current buffer as a frame (for encoding)
func (m *Message) FlushFrame(ctx context.Context, isEOM bool) error {
	if m.direction != CodingEncode {
		return fmt.Errorf("can only flush frames in encode mode")
	}

	data := m.buffer.Bytes()

	err := m.stream.WriteFrame(ctx, data, isEOM)
	if err != nil {
		return err
	}

	m.buffer.Reset()
	return nil
}

//
// STREAMING READ OPERATIONS
//

// GetChar reads a single byte, possibly across frame boundaries
func (m *Message) GetChar(ctx context.Context) (byte, error) {
	if err := m.ensureData(ctx, 1); err != nil {
		return 0, err
	}
	return m.buffer.ReadByte()
}

// GetInt reads an int from 64-bit value, possibly across frame boundaries
func (m *Message) GetInt(ctx context.Context) (int, error) {
	if err := m.ensureData(ctx, 8); err != nil {
		return 0, err
	}

	buf := make([]byte, 8)
	if _, err := io.ReadFull(m.buffer, buf); err != nil {
		return 0, err
	}
	networkValue := binary.BigEndian.Uint64(buf)
	result := int(int64(networkValue))
	return result, nil
}

// GetInt32 reads an int32 from 64-bit value, possibly across frame boundaries
func (m *Message) GetInt32(ctx context.Context) (int32, error) {
	val, err := m.GetInt(ctx)
	return int32(val), err
}

// GetInt64 reads an int64, possibly across frame boundaries
func (m *Message) GetInt64(ctx context.Context) (int64, error) {
	val, err := m.GetInt(ctx)
	return int64(val), err
}

// GetUint32 reads a uint32 from 64-bit value, possibly across frame boundaries
func (m *Message) GetUint32(ctx context.Context) (uint32, error) {
	val, err := m.GetInt(ctx)
	return uint32(val), err
}

// GetFloat reads a float, possibly across frame boundaries
func (m *Message) GetFloat(ctx context.Context) (float32, error) {
	val, err := m.GetDouble(ctx)
	return float32(val), err
}

// GetDouble reads a double using HTCondor's frexp/ldexp decoding, possibly across frame boundaries
func (m *Message) GetDouble(ctx context.Context) (float64, error) {
	// Read fractional part and exponent (each is int32, so 8 bytes total for each)
	fracInt, err := m.GetInt32(ctx)
	if err != nil {
		return 0, err
	}

	exp, err := m.GetInt32(ctx)
	if err != nil {
		return 0, err
	}

	// Convert back using ldexp (matches HTCondor exactly)
	frac := float64(fracInt) / float64(FracConst)
	return math.Ldexp(frac, int(exp)), nil
}

// GetString reads a null-terminated string, possibly across frame boundaries
func (m *Message) GetString(ctx context.Context) (string, error) {
	isEncrypted := m.stream.IsEncrypted()
	if isEncrypted {
		// For encrypted strings, read length first then exact number of bytes
		length, err := m.GetInt32(ctx)
		if err != nil {
			return "", err
		}

		// A negative length is malformed and cannot be left to ensureData:
		// both of its comparisons are false for a negative need, so it returns
		// nil without reading, and make([]byte, length) below then panicked
		// with "makeslice: len out of range". GetBytes already rejects this.
		if length < 0 {
			return "", fmt.Errorf("negative string length %d", length)
		}

		if err := m.ensureData(ctx, int(length)); err != nil {
			return "", err
		}

		data := make([]byte, length)
		if _, err := io.ReadFull(m.buffer, data); err != nil {
			return "", err
		}

		// Check for HTCondor's null string marker
		if len(data) > 0 && data[0] == BinNullChar {
			return "", nil // NULL string in HTCondor
		}

		// Remove trailing null terminator if present
		if len(data) > 0 && data[len(data)-1] == 0 {
			data = data[:len(data)-1]
		}

		// For encrypted mode, null characters are preserved (not truncated)
		return string(data), nil
	} else {
		// For unencrypted strings, read until null terminator
		// Null characters terminate the string
		var result []byte
		for {
			// Ensure we have at least one byte to read
			if err := m.ensureData(ctx, 1); err != nil {
				if err == io.EOF {
					// End of message, return what we have
					break
				}
				return "", err
			}

			b, err := m.buffer.ReadByte()
			if err != nil {
				// This shouldn't happen since we just ensured data is available
				return "", err
			}
			if b == 0 {
				break // Found null terminator
			}
			result = append(result, b)
		}
		return string(result), nil
	}
}

// GetStringWithMaxSize reads a null-terminated string with a maximum size limit
// If the string exceeds maxSize, returns the truncated string (up to maxSize-1 bytes)
// along with an ErrStringSizeExceeded error to allow the caller to detect size violations
// For encrypted mode: null characters are preserved in the returned string

// GetStringWithMaxSize reads a null-terminated string with a maximum size limit
// If the string exceeds maxSize, returns the truncated string (up to maxSize-1 bytes)
// along with an ErrStringSizeExceeded error to allow the caller to detect size violations
// For encrypted mode: null characters are preserved in the returned string
// For unencrypted mode: null characters terminate the string (as per protocol)
// If maxSize is 0 or negative, returns an empty string without reading any data
// SECURITY: Never buffers more than maxSize bytes to prevent DoS attacks
func (m *Message) GetStringWithMaxSize(ctx context.Context, maxSize int) (string, error) {
	if maxSize <= 0 {
		return "", nil // Return empty string for maxSize <= 0 without reading
	}

	isEncrypted := m.stream.IsEncrypted()
	if isEncrypted {
		// For encrypted strings, read length first
		length, err := m.GetInt32(ctx)
		if err != nil {
			return "", err
		}

		// Same malformed case as GetString. The clamp below is no guard: for a
		// negative value bytesToRead > maxSize is false, so it stayed negative
		// and reached make([]byte, bytesToRead).
		if length < 0 {
			return "", fmt.Errorf("negative string length %d", length)
		}

		// Check if length exceeds maxSize - if so, only read maxSize bytes
		bytesToRead := int(length)
		exceeds := false
		if bytesToRead > maxSize {
			bytesToRead = maxSize
			exceeds = true
		}

		// Only read up to maxSize bytes to prevent DoS
		if err := m.ensureData(ctx, bytesToRead); err != nil {
			return "", err
		}

		data := make([]byte, bytesToRead)
		if _, err := io.ReadFull(m.buffer, data); err != nil {
			return "", err
		}

		// Check for HTCondor's null string marker
		if len(data) > 0 && data[0] == BinNullChar {
			if exceeds {
				// String was truncated, return error
				return "", &ErrStringSizeExceeded{Length: int(length), MaxSize: maxSize}
			}
			return "", nil // NULL string in HTCondor
		}

		// Remove trailing null terminator if present
		if len(data) > 0 && data[len(data)-1] == 0 {
			data = data[:len(data)-1]
		}

		// For encrypted mode, null characters within the string are preserved
		// Check if we truncated the string
		if exceeds {
			// Return exactly maxSize bytes (truncated string)
			if len(data) > maxSize {
				data = data[:maxSize]
			}
			return string(data), &ErrStringSizeExceeded{Length: int(length), MaxSize: maxSize}
		}

		return string(data), nil
	} else {
		// For unencrypted strings, read byte-by-byte up to maxSize
		// Null characters terminate the string
		var result []byte
		bytesRead := 0
		foundNull := false

		for bytesRead < maxSize {
			// Ensure we have at least one byte to read
			if err := m.ensureData(ctx, 1); err != nil {
				if err == io.EOF {
					// End of message before finding null terminator
					if bytesRead > 0 {
						return string(result), &ErrStringSizeExceeded{Length: bytesRead, MaxSize: maxSize}
					}
					break
				}
				return "", err
			}

			b, err := m.buffer.ReadByte()
			if err != nil {
				return "", err
			}

			bytesRead++

			if b == 0 {
				// Found null terminator within size limit
				foundNull = true
				break
			}

			result = append(result, b)
		}

		// If we reached maxSize without finding null terminator
		if bytesRead >= maxSize && !foundNull {
			// SECURITY: Do NOT read more data - return immediately with error
			// This leaves the stream in an inconsistent state, but prevents DoS
			// Return exactly maxSize bytes of data (truncated string)
			if len(result) > maxSize {
				result = result[:maxSize]
			}
			return string(result), &ErrStringSizeExceeded{Length: -1, MaxSize: maxSize}
		}

		return string(result), nil
	}
}

//
// STREAMING WRITE OPERATIONS
//

// PutChar writes a single byte
func (m *Message) PutChar(ctx context.Context, c byte) error {
	if m.buffer.Len() >= TargetFrameSize {
		// Flush current frame if it's getting too large
		if err := m.FlushFrame(ctx, false); err != nil {
			return err
		}
	}
	return m.buffer.WriteByte(c)
}

// PutInt writes an int as 64-bit value
func (m *Message) PutInt(ctx context.Context, value int) error {
	if m.buffer.Len()+8 > TargetFrameSize {
		if err := m.FlushFrame(ctx, false); err != nil {
			return err
		}
	}

	networkValue := uint64(int64(value))
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, networkValue)
	_, err := m.buffer.Write(buf)
	return err
}

// PutInt32 writes an int32 as 64-bit value
func (m *Message) PutInt32(ctx context.Context, value int32) error {
	return m.PutInt(ctx, int(value))
}

// PutInt64 writes an int64
func (m *Message) PutInt64(ctx context.Context, value int64) error {
	return m.PutInt(ctx, int(value))
}

// PutUint32 writes a uint32 as 64-bit value
func (m *Message) PutUint32(ctx context.Context, value uint32) error {
	return m.PutInt(ctx, int(value))
}

// PutFloat writes a float as double
func (m *Message) PutFloat(ctx context.Context, value float32) error {
	return m.PutDouble(ctx, float64(value))
}

// PutDouble writes a double using HTCondor's frexp/ldexp encoding
func (m *Message) PutDouble(ctx context.Context, value float64) error {
	// HTCondor uses frexp to split double into fraction and exponent
	frac, exp := math.Frexp(value)

	// Convert fraction to integer (multiply by FracConst)
	fracInt := int32(frac * float64(FracConst))

	// Write fractional part as int32, then exponent as int32
	if err := m.PutInt32(ctx, fracInt); err != nil {
		return err
	}
	return m.PutInt32(ctx, int32(exp))
}

// PutString writes a string with null terminator
// If the string contains a null character, it is truncated at the first null
// and a null terminator is still appended
func (m *Message) PutString(ctx context.Context, s string) error {
	isEncrypted := m.stream.IsEncrypted()

	// Truncate at first null character if present
	truncated := s
	if nullIndex := bytes.IndexByte([]byte(s), 0); nullIndex >= 0 {
		truncated = s[:nullIndex]
	}

	data := []byte(truncated + "\x00")
	length := len(data)

	// Ensure we have space for the data (plus length prefix if encrypted)
	needed := length
	if isEncrypted {
		needed += 8 // int32 length prefix (stored as int64)
	}

	// For very large strings that exceed MaxFrameSize, handle specially
	if needed > MaxFrameSize {
		// Flush current frame if it has data
		if m.buffer.Len() > 0 {
			if err := m.FlushFrame(ctx, false); err != nil {
				return err
			}
		}

		// If encryption enabled, write length first
		if isEncrypted {
			if err := m.PutInt32(ctx, int32(length)); err != nil {
				return err
			}
		}

		// Use PutBytes to handle the large data splitting
		return m.PutBytes(ctx, data)
	}

	// For normal-sized strings, use TargetFrameSize
	if m.buffer.Len()+needed > TargetFrameSize {
		if err := m.FlushFrame(ctx, false); err != nil {
			return err
		}
	}

	// If encryption enabled, write length first
	if isEncrypted {
		if err := m.PutInt32(ctx, int32(length)); err != nil {
			return err
		}
	}

	// Write string data with null terminator
	_, err := m.buffer.Write(data)
	return err
}

// PutStringBytes writes a byte slice as a CEDAR string (the wire form is
// identical to PutString(string(b))), but without allocating a string from b. It
// lets a caller stream many strings out of one reused scratch buffer -- e.g. a
// collector rendering each ad's "Attr = Value" expressions into a shared buffer --
// with no per-string allocation. b is not modified.
func (m *Message) PutStringBytes(ctx context.Context, b []byte) error {
	isEncrypted := m.stream.IsEncrypted()

	// Truncate at first null character if present (CEDAR strings are null-terminated).
	if nullIndex := bytes.IndexByte(b, 0); nullIndex >= 0 {
		b = b[:nullIndex]
	}
	length := len(b) + 1 // + null terminator

	needed := length
	if isEncrypted {
		needed += 8
	}

	// Large strings: flush, write the (encrypted) length prefix, then stream b and
	// the null terminator via PutBytes (which splits across frames).
	if needed > MaxFrameSize {
		if m.buffer.Len() > 0 {
			if err := m.FlushFrame(ctx, false); err != nil {
				return err
			}
		}
		if isEncrypted {
			if err := m.PutInt32(ctx, int32(length)); err != nil {
				return err
			}
		}
		if err := m.PutBytes(ctx, b); err != nil {
			return err
		}
		return m.PutBytes(ctx, []byte{0})
	}

	if m.buffer.Len()+needed > TargetFrameSize {
		if err := m.FlushFrame(ctx, false); err != nil {
			return err
		}
	}
	if isEncrypted {
		if err := m.PutInt32(ctx, int32(length)); err != nil {
			return err
		}
	}
	if _, err := m.buffer.Write(b); err != nil {
		return err
	}
	return m.buffer.WriteByte(0)
}

// PutBytes writes raw bytes to the message without length prefix
// Flushes frame if needed to accommodate the data
// For data larger than MaxFrameSize, splits across multiple frames
func (m *Message) PutBytes(ctx context.Context, data []byte) error {
	if m.direction != CodingEncode {
		return fmt.Errorf("can only put bytes in encode mode")
	}

	length := len(data)
	if length == 0 {
		return nil // No data to write
	}

	// If the data is larger than MaxFrameSize, we need to split it
	if length > MaxFrameSize {
		// Split large data across multiple frames
		offset := 0
		for offset < length {
			// Flush current frame if it has any data
			if m.buffer.Len() > 0 {
				if err := m.FlushFrame(ctx, false); err != nil {
					return err
				}
			}

			// Determine how much to write in this frame
			remaining := length - offset
			chunkSize := MaxFrameSize
			if remaining < chunkSize {
				chunkSize = remaining
			}

			// Write chunk directly to buffer
			chunk := data[offset : offset+chunkSize]
			if _, err := m.buffer.Write(chunk); err != nil {
				return err
			}

			offset += chunkSize
		}
		return nil
	}

	// For normal-sized data, check if we need to flush the current frame
	if m.buffer.Len()+length > TargetFrameSize {
		if err := m.FlushFrame(ctx, false); err != nil {
			return err
		}
	}

	// Write byte data directly
	_, err := m.buffer.Write(data)
	return err
}

// GetBytes reads the specified number of raw bytes from the message
// Reads across frame boundaries as needed
func (m *Message) GetBytes(ctx context.Context, numBytes int) ([]byte, error) {
	if m.direction != CodingDecode {
		return nil, fmt.Errorf("can only get bytes in decode mode")
	}

	if numBytes <= 0 {
		return []byte{}, nil // Return empty slice for zero or negative length
	}

	// Ensure we have enough data in the buffer
	if err := m.ensureData(ctx, numBytes); err != nil {
		return nil, err
	}

	// Read the requested number of bytes
	data := make([]byte, numBytes)
	n, err := io.ReadFull(m.buffer, data)
	if err != nil {
		return nil, err
	}
	if n != numBytes {
		return nil, fmt.Errorf("expected to read %d bytes, but only read %d", numBytes, n)
	}

	return data, nil
}

// GetRemainingBytes drains and returns every remaining byte of the message,
// reading frames until end-of-message. It is used by receivers whose payload is
// an opaque, length-unprefixed byte stream terminated only by EOM (e.g. the
// QMGMT SendMaterializeData itemdata stream, which the C++ schedd reads with
// repeated sock->get_bytes(...) until end_of_message). Returns an empty slice
// (nil error) when nothing remains.
func (m *Message) GetRemainingBytes(ctx context.Context) ([]byte, error) {
	if m.direction != CodingDecode {
		return nil, fmt.Errorf("can only get bytes in decode mode")
	}
	// Pull in every remaining frame. ensureData stops growing the buffer once
	// EOM is seen; asking for one more byte than we have forces it to read all
	// remaining frames (and returns io.EOF at EOM, which is the expected end).
	for !m.isEOM {
		if err := m.ensureData(ctx, m.buffer.Len()+1); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	out := make([]byte, m.buffer.Len())
	copy(out, m.buffer.Bytes())
	m.buffer.Reset()
	m.finished = true
	return out, nil
}

// Code methods for the streaming Message

func (m *Message) CodeChar(ctx context.Context, c *byte) error {
	switch m.direction {
	case CodingEncode:
		return m.PutChar(ctx, *c)
	case CodingDecode:
		var err error
		*c, err = m.GetChar(ctx)
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

func (m *Message) CodeInt(ctx context.Context, value *int) error {
	switch m.direction {
	case CodingEncode:
		return m.PutInt(ctx, *value)
	case CodingDecode:
		var err error
		*value, err = m.GetInt(ctx)
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

func (m *Message) CodeInt32(ctx context.Context, value *int32) error {
	switch m.direction {
	case CodingEncode:
		return m.PutInt32(ctx, *value)
	case CodingDecode:
		var err error
		*value, err = m.GetInt32(ctx)
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

func (m *Message) CodeInt64(ctx context.Context, value *int64) error {
	switch m.direction {
	case CodingEncode:
		return m.PutInt64(ctx, *value)
	case CodingDecode:
		var err error
		*value, err = m.GetInt64(ctx)
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

func (m *Message) CodeFloat(ctx context.Context, value *float32) error {
	switch m.direction {
	case CodingEncode:
		return m.PutFloat(ctx, *value)
	case CodingDecode:
		var err error
		*value, err = m.GetFloat(ctx)
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

func (m *Message) CodeDouble(ctx context.Context, value *float64) error {
	switch m.direction {
	case CodingEncode:
		return m.PutDouble(ctx, *value)
	case CodingDecode:
		var err error
		*value, err = m.GetDouble(ctx)
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

func (m *Message) CodeString(ctx context.Context, s *string) error {
	switch m.direction {
	case CodingEncode:
		return m.PutString(ctx, *s)
	case CodingDecode:
		var err error
		*s, err = m.GetString(ctx)
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

// FinishMessage completes the message by sending any remaining data with EOM flag
func (m *Message) FinishMessage(ctx context.Context) error {
	if m.direction != CodingEncode {
		return fmt.Errorf("can only finish messages in encode mode")
	}
	return m.FlushFrame(ctx, true)
}

//
// CLASSAD OPERATIONS FOR STREAMING MESSAGES
//

// PutClassAd writes a ClassAd to the streaming message
func (m *Message) PutClassAd(ctx context.Context, ad *classad.ClassAd) error {
	return m.PutClassAdWithOptions(ctx, ad, nil)
}

// PutClassAdWithOptions writes a ClassAd with options to the streaming message
func (m *Message) PutClassAdWithOptions(ctx context.Context, ad *classad.ClassAd, config *PutClassAdConfig) error {
	return putClassAdToMessageWithOptions(m, ad, config, ctx)
}

// GetClassAd reads a ClassAd from the streaming message
func (m *Message) GetClassAd(ctx context.Context) (*classad.ClassAd, error) {
	return getClassAdFromMessage(m, ctx)
}

// GetClassAdWithMaxSize reads a ClassAd from the streaming message with size limits
// maxSize limits the total bytes read for the entire ClassAd
func (m *Message) GetClassAdWithMaxSize(ctx context.Context, maxSize int) (*classad.ClassAd, error) {
	return getClassAdFromMessageWithMaxSize(m, maxSize, ctx)
}
