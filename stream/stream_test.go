package stream

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
)

func TestMessageFraming(t *testing.T) {
	ctx := context.Background()

	// Create a buffer to simulate a network connection
	var buf bytes.Buffer

	// Create a stream using the buffer
	stream := &Stream{
		reader: &buf,
		writer: &buf,
	}

	// Test data
	testFrame := []byte("Hello, CEDAR!")

	// Send the message
	err := stream.SendMessage(ctx, testFrame)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Receive the message
	receivedFrame, err := stream.ReceiveFrame(ctx)
	if err != nil {
		t.Fatalf("Failed to receive message: %v", err)
	}

	// Verify the message content
	if !bytes.Equal(testFrame, receivedFrame) {
		t.Errorf("Message mismatch: sent %q, received %q", testFrame, receivedFrame)
	}
}

func TestEmptyMessage(t *testing.T) {
	ctx := context.Background()

	var buf bytes.Buffer
	stream := &Stream{
		reader: &buf,
		writer: &buf,
	}

	// Test empty message
	testMessage := []byte{}

	err := stream.SendMessage(ctx, testMessage)
	if err != nil {
		t.Fatalf("Failed to send empty message: %v", err)
	}

	receivedFrame, err := stream.ReceiveFrame(ctx)
	if err != nil {
		t.Fatalf("Failed to receive empty message: %v", err)
	}

	if len(receivedFrame) != 0 {
		t.Errorf("Expected empty message, got %d bytes", len(receivedFrame))
	}
}

func TestLargeMessage(t *testing.T) {
	ctx := context.Background()

	var buf bytes.Buffer
	stream := &Stream{
		reader: &buf,
		writer: &buf,
	}

	// Test large message (1MB)
	testMessage := make([]byte, 1024*1024)
	for i := range testMessage {
		testMessage[i] = byte(i % 256)
	}

	err := stream.SendMessage(ctx, testMessage)
	if err != nil {
		t.Fatalf("Failed to send large message: %v", err)
	}

	receivedFrame, err := stream.ReceiveFrame(ctx)
	if err != nil {
		t.Fatalf("Failed to receive large frame: %v", err)
	}

	if !bytes.Equal(testMessage, receivedFrame) {
		t.Errorf("Large message mismatch: lengths sent=%d, received=%d", len(testMessage), len(receivedFrame))
	}
}

func TestMessageTooLarge(t *testing.T) {
	var buf bytes.Buffer
	stream := &Stream{
		reader: &buf,
		writer: &buf,
	}

	// Test message that's too large
	testMessage := make([]byte, MaxMessageSize+1)

	err := stream.SendMessage(context.Background(), testMessage)
	if err == nil {
		t.Fatal("Expected error for message that's too large")
	}
}

func TestPartialMessage(t *testing.T) {
	var buf bytes.Buffer
	stream := &Stream{
		reader: &buf,
		writer: &buf,
	}

	// Test partial message (end flag = 0)
	testMessage := []byte("Partial frame")

	err := stream.SendPartialMessage(context.Background(), testMessage)
	if err != nil {
		t.Fatalf("Failed to send partial frame: %v", err)
	}

	receivedFrame, endFlag, err := stream.ReceiveFrameWithEnd(context.Background())
	if err != nil {
		t.Fatalf("Failed to receive partial frame: %v", err)
	}

	if endFlag != 0 {
		t.Errorf("Expected end flag 0 for partial frame, got %d", endFlag)
	}

	if !bytes.Equal(testMessage, receivedFrame) {
		t.Errorf("Frame mismatch: sent %q, received %q", testMessage, receivedFrame)
	}
}

func TestCompleteMessage(t *testing.T) {
	var buf bytes.Buffer
	stream := &Stream{
		reader: &buf,
		writer: &buf,
	}

	// Test complete message (end flag = 1)
	testMessage := []byte("Complete message")

	err := stream.SendMessage(context.Background(), testMessage) // SendMessage uses end flag = 1
	if err != nil {
		t.Fatalf("Failed to send complete message: %v", err)
	}

	receivedFrame, endFlag, err := stream.ReceiveFrameWithEnd(context.Background())
	if err != nil {
		t.Fatalf("Failed to receive complete message: %v", err)
	}

	if endFlag != 1 {
		t.Errorf("Expected end flag 1 for complete message, got %d", endFlag)
	}

	if !bytes.Equal(testMessage, receivedFrame) {
		t.Errorf("Frame mismatch: sent %q, received %q", testMessage, receivedFrame)
	}
}

func TestEchoServer(t *testing.T) {
	// Start echo server on a random port
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	// Get the actual port assigned
	addr := listener.Addr().(*net.TCPAddr)
	port := addr.Port
	t.Logf("Echo server listening on port %d", port)

	// Start the echo server in a goroutine
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runEchoServer(t, listener)
	}()

	// Give the server a moment to start
	// Connect as client
	clientConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		t.Fatalf("Failed to connect to echo server: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	// Create client stream
	clientStream := NewStream(clientConn)

	// Test messages
	testFrames := []string{
		"Hello, Echo Server!",
		"This is a test message",
		"Unicode test: 🔥💻🚀",
		"", // Empty message
		"A very long message: " + string(make([]byte, 1000)), // Long message
	}

	for i, testMsg := range testFrames {
		t.Run(fmt.Sprintf("Frame_%d", i), func(t *testing.T) {
			// Send message to server
			err := clientStream.SendMessage(context.Background(), []byte(testMsg))
			if err != nil {
				t.Fatalf("Failed to send message: %v", err)
			}

			// Receive echo response
			response, err := clientStream.ReceiveFrame(context.Background())
			if err != nil {
				t.Fatalf("Failed to receive response: %v", err)
			}

			// Verify echo
			if string(response) != testMsg {
				t.Errorf("Echo mismatch: sent %q, received %q", testMsg, string(response))
			}
		})
	}

	// Close client connection to signal server to stop
	_ = clientConn.Close() // Ignore error during cleanup

	// Close the listener to stop the server
	_ = listener.Close() // Ignore error during cleanup

	// Wait for server to finish or timeout
	select {
	case err := <-serverDone:
		if err != nil && err.Error() != "accept tcp 127.0.0.1:57787: use of closed network connection" {
			t.Logf("Server finished with error: %v", err)
		}
	default:
		// Server might still be running, that's ok for this test
		t.Logf("Server still running (expected)")
	}
}

// runEchoServer implements a simple echo server
// It reads a length followed by that exact number of bytes into a string,
// then sends the same frame back to the client
func runEchoServer(t *testing.T, listener net.Listener) error {
	for {
		// Accept connection
		conn, err := listener.Accept()
		if err != nil {
			// Listener was closed, normal shutdown
			return nil
		}

		// Handle this client in a separate goroutine
		go func(clientConn net.Conn) {
			defer func() { _ = clientConn.Close() }()

			// Create stream for this client
			stream := NewStream(clientConn)

			// NOTE: do not call t.Log* from this goroutine. It can outlive the
			// test function -- the listener is closed during teardown while a
			// client handler may still be running -- and logging after the test
			// has returned is a data race on the testing.common state (caught by
			// -race).
			for {
				// Read frame using CEDAR protocol
				frameData, endFlag, err := stream.ReceiveFrameWithEnd(context.Background())
				if err != nil {
					// Client disconnected (normal shutdown).
					return
				}

				// Echo the frame back
				if err := stream.sendMessageWithEnd(context.Background(), frameData, endFlag); err != nil {
					return
				}
			}
		}(conn)
	}
}

// TestEOMWriteMode tests End of Message handling in write mode
func TestEOMWriteMode(t *testing.T) {
	var buf bytes.Buffer
	stream := &Stream{
		reader: &buf,
		writer: &buf,
	}

	t.Run("BasicWriteAndEnd", func(t *testing.T) {
		ctx := context.Background()

		// Reset the buffer
		buf.Reset()
		stream.StartMessage()

		// Write some data
		data1 := []byte("Hello, ")
		data2 := []byte("World!")

		err := stream.WriteMessage(ctx, data1)
		if err != nil {
			t.Fatalf("Failed to write first chunk: %v", err)
		}

		err = stream.WriteMessage(ctx, data2)
		if err != nil {
			t.Fatalf("Failed to write second chunk: %v", err)
		}

		// End the message
		err = stream.EndMessage(ctx)
		if err != nil {
			t.Fatalf("Failed to end message: %v", err)
		}

		// Receive and verify the complete message
		received, err := stream.ReceiveFrame(ctx)
		if err != nil {
			t.Fatalf("Failed to receive message: %v", err)
		}

		expected := append(data1, data2...)
		if !bytes.Equal(received, expected) {
			t.Errorf("Message mismatch: expected %q, got %q", expected, received)
		}
	})

	t.Run("WriteAfterEOMError", func(t *testing.T) {
		ctx := context.Background()

		// Reset the buffer
		buf.Reset()
		stream.StartMessage()

		// Write and end message
		err := stream.WriteMessage(ctx, []byte("test"))
		if err != nil {
			t.Fatalf("Failed to write data: %v", err)
		}

		err = stream.EndMessage(ctx)
		if err != nil {
			t.Fatalf("Failed to end message: %v", err)
		}

		// Try to write after EOM - should fail
		err = stream.WriteMessage(ctx, []byte("should fail"))
		if err == nil {
			t.Fatal("Expected error when writing after EndMessage()")
		}

		expected := "cannot write to message after EndMessage() has been called"
		if err.Error() != expected {
			t.Errorf("Wrong error message: expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("DoubleEndMessageError", func(t *testing.T) {
		ctx := context.Background()

		// Reset the buffer
		buf.Reset()
		stream.StartMessage()

		// Write and end message
		err := stream.WriteMessage(ctx, []byte("test"))
		if err != nil {
			t.Fatalf("Failed to write data: %v", err)
		}

		err = stream.EndMessage(ctx)
		if err != nil {
			t.Fatalf("Failed to end message: %v", err)
		}

		// Try to end message again - should fail
		err = stream.EndMessage(ctx)
		if err == nil {
			t.Fatal("Expected error when calling EndMessage() twice")
		}

		expected := "EndMessage() already called for this message"
		if err.Error() != expected {
			t.Errorf("Wrong error message: expected %q, got %q", expected, err.Error())
		}
	})
}

// TestEOMReadMode tests End of Message handling in read mode
func TestEOMReadMode(t *testing.T) {
	var buf bytes.Buffer
	stream := &Stream{
		reader: &buf,
		writer: &buf,
	}

	t.Run("ReadCompleteMessage", func(t *testing.T) {
		ctx := context.Background()

		// Reset the buffer
		buf.Reset()
		stream.inMessage = false
		stream.receiveBuffer = nil
		stream.bytesRead = 0
		stream.totalMsgBytes = 0

		// Send a test message
		testMessage := []byte("Hello, World!")
		err := stream.SendMessage(ctx, testMessage)
		if err != nil {
			t.Fatalf("Failed to send message: %v", err)
		}

		// Start reading the message
		err = stream.StartMessageRead(ctx)
		if err != nil {
			t.Fatalf("Failed to start message read: %v", err)
		}

		// Read the message in chunks
		chunk1 := make([]byte, 7)
		n1, err := stream.ReadMessageBytes(ctx, chunk1)
		if err != nil {
			t.Fatalf("Failed to read first chunk: %v", err)
		}
		if n1 != 7 || string(chunk1) != "Hello, " {
			t.Errorf("First chunk mismatch: expected 'Hello, ' (7 bytes), got %q (%d bytes)", chunk1[:n1], n1)
		}

		chunk2 := make([]byte, 6)
		n2, err := stream.ReadMessageBytes(ctx, chunk2)
		if err != nil {
			t.Fatalf("Failed to read second chunk: %v", err)
		}
		if n2 != 6 || string(chunk2) != "World!" {
			t.Errorf("Second chunk mismatch: expected 'World!' (6 bytes), got %q (%d bytes)", chunk2[:n2], n2)
		}

		// End message read
		err = stream.EndMessageRead()
		if err != nil {
			t.Fatalf("Failed to end message read: %v", err)
		}
	})

	t.Run("IncompleteReadError", func(t *testing.T) {
		ctx := context.Background()

		// Reset the buffer
		buf.Reset()
		stream.inMessage = false
		stream.receiveBuffer = nil
		stream.bytesRead = 0
		stream.totalMsgBytes = 0

		// Send a test message
		testMessage := []byte("Hello, World!")
		err := stream.SendMessage(ctx, testMessage)
		if err != nil {
			t.Fatalf("Failed to send message: %v", err)
		}

		// Start reading the message
		err = stream.StartMessageRead(ctx)
		if err != nil {
			t.Fatalf("Failed to start message read: %v", err)
		}

		// Read only part of the message
		chunk := make([]byte, 5)
		_, err = stream.ReadMessageBytes(ctx, chunk)
		if err != nil {
			t.Fatalf("Failed to read chunk: %v", err)
		}

		// Try to end without reading all bytes - should fail
		err = stream.EndMessageRead()
		if err == nil {
			t.Fatal("Expected error when ending message read with unread bytes")
		}

		if !bytes.Contains([]byte(err.Error()), []byte("message not fully consumed")) {
			t.Errorf("Wrong error message: %v", err)
		}
	})
}

// TestMultiFrameMessages tests messages that span multiple frames
func TestMultiFrameMessages(t *testing.T) {
	var buf bytes.Buffer
	stream := &Stream{
		reader: &buf,
		writer: &buf,
	}

	t.Run("AutoFrameSplitting", func(t *testing.T) {
		// Reset the buffer
		buf.Reset()
		stream.sendBuffer = nil
		stream.sendEOM = false

		ctx := context.Background()

		// Create a large message that will exceed frame threshold
		largeMessage := make([]byte, DefaultFrameThreshold+1000)
		for i := range largeMessage {
			largeMessage[i] = byte(i % 256)
		}

		// Write the large message - should auto-split into frames
		err := stream.WriteMessage(ctx, largeMessage)
		if err != nil {
			t.Fatalf("Failed to write large message: %v", err)
		}

		// End the message
		err = stream.EndMessage(ctx)
		if err != nil {
			t.Fatalf("Failed to end message: %v", err)
		}

		// Receive the complete message
		received, err := stream.ReceiveCompleteMessage(ctx)
		if err != nil {
			t.Fatalf("Failed to receive complete message: %v", err)
		}

		// Verify the message
		if !bytes.Equal(largeMessage, received) {
			t.Errorf("Large message mismatch: lengths expected=%d, got=%d", len(largeMessage), len(received))
		}
	})

	t.Run("ManualPartialFrames", func(t *testing.T) {
		ctx := context.Background()

		// Reset the buffer
		buf.Reset()

		// Manually send partial frames
		frame1 := []byte("First frame, ")
		frame2 := []byte("Second frame, ")
		frame3 := []byte("Final frame!")

		err := stream.SendPartialMessage(ctx, frame1)
		if err != nil {
			t.Fatalf("Failed to send first frame: %v", err)
		}

		err = stream.SendPartialMessage(ctx, frame2)
		if err != nil {
			t.Fatalf("Failed to send second frame: %v", err)
		}

		err = stream.SendMessage(ctx, frame3) // Final frame with end flag
		if err != nil {
			t.Fatalf("Failed to send final frame: %v", err)
		}

		// Receive the complete message
		received, err := stream.ReceiveCompleteMessage(ctx)
		if err != nil {
			t.Fatalf("Failed to receive complete message: %v", err)
		}

		expected := append(append(frame1, frame2...), frame3...)
		if !bytes.Equal(expected, received) {
			t.Errorf("Multi-frame message mismatch: expected %q, got %q", expected, received)
		}
	})
}

// TestIsConnectedAfterClose covers the local half of the connection
// predicate: Close() on this side must make IsConnected() report false.
// Detecting a peer-side drop is out of scope -- that needs I/O.
func TestIsConnectedAfterClose(t *testing.T) {
	// A real TCP conn, not net.Pipe: net.Pipe's own Close is already
	// idempotent, which would make the second-Close assertion below vacuous.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	s := NewStream(conn)

	if !s.IsConnected() {
		t.Fatal("Expected a fresh stream to report connected")
	}

	if err = s.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if s.IsConnected() {
		t.Error("Expected a closed stream to report not connected")
	}

	// Close is idempotent: a second call is a no-op returning nil, not the
	// "use of closed network connection" error the conn would give.
	if err = s.Close(); err != nil {
		t.Errorf("Second Close returned %v, want nil", err)
	}

	if s.IsConnected() {
		t.Error("Expected a closed stream to still report not connected")
	}
}
