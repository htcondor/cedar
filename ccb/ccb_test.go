package ccb

import (
	"context"
	"net"
	"testing"

	"github.com/htcondor/cedar/stream"
)

func TestGenerateConnectID(t *testing.T) {
	id, err := GenerateConnectID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 40 {
		t.Errorf("connect id len = %d, want 40", len(id))
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("connect id has non-hex char %q", c)
		}
	}
	id2, _ := GenerateConnectID()
	if id == id2 {
		t.Errorf("two connect ids collided")
	}
}

func TestContactString(t *testing.T) {
	if got := ContactString("192.168.1.1:9618", 42); got != "192.168.1.1:9618#42" {
		t.Errorf("ContactString = %q", got)
	}
}

func TestReverseConnectRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	ctx := context.Background()

	const connectID = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	const reqID = "7"
	const myAddr = "<10.0.0.1:9618>"

	writeErr := make(chan error, 1)
	go func() {
		s := stream.NewStream(c1)
		writeErr <- WriteReverseConnect(ctx, s, connectID, reqID, myAddr)
	}()

	s := stream.NewStream(c2)
	ad, err := readReverseConnect(ctx, s)
	if err != nil {
		t.Fatalf("readReverseConnect: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("WriteReverseConnect: %v", err)
	}

	if got := AdString(ad, AttrClaimID); got != connectID {
		t.Errorf("ClaimId = %q, want %q", got, connectID)
	}
	if got := AdString(ad, AttrRequestID); got != reqID {
		t.Errorf("RequestID = %q, want %q", got, reqID)
	}
	if got := AdString(ad, AttrMyAddress); got != myAddr {
		t.Errorf("MyAddress = %q, want %q", got, myAddr)
	}
}

func TestControlAdRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	ctx := context.Background()

	writeErr := make(chan error, 1)
	go func() {
		s := stream.NewStream(c1)
		ad := NewAd(map[string]any{
			AttrCommand: CommandRegister,
			AttrName:    "schedd 10.0.0.5",
		})
		writeErr <- WriteControlAd(ctx, s, ad)
	}()

	s := stream.NewStream(c2)
	ad, err := ReadControlAd(ctx, s)
	if err != nil {
		t.Fatalf("ReadControlAd: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("WriteControlAd: %v", err)
	}
	if cmd, _ := AdInt(ad, AttrCommand); cmd != int64(CommandRegister) {
		t.Errorf("Command = %d, want %d", cmd, CommandRegister)
	}
	if got := AdString(ad, AttrName); got != "schedd 10.0.0.5" {
		t.Errorf("Name = %q", got)
	}
}
