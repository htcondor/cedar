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

package security

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

// fakeAddr is a net.Addr whose String() we control, for unit-testing
// fsChannelBindingExt without a real socket.
type fakeAddr struct{ s string }

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return f.s }

func TestFSChannelBindingExt(t *testing.T) {
	cases := []struct {
		name    string
		addr    net.Addr
		want    string
		wantErr bool
	}{
		{"ipv4", fakeAddr{"127.0.0.1:39945"}, "127.0.0.1:39945", false},
		{"ipv6", fakeAddr{"[::1]:39945"}, "[::1]:39945", false},
		{"nil addr", nil, "", true},
		{"no port", fakeAddr{"127.0.0.1"}, "", true},
		{"host not ip", fakeAddr{"example.com:80"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fsChannelBindingExt(tc.addr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateFSChannelBoundPath(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		ext      string
		remote   bool
		wantLeaf string
		wantErr  bool
	}{
		{
			name:     "address-qualified local",
			base:     "/tmp/FS_127.0.0.1_39945_XXXR2qLuV_",
			ext:      "127.0.0.1:39945",
			wantLeaf: "FS_127.0.0.1_39945_XXXR2qLuV_127.0.0.1:39945",
		},
		{
			// The server's embedded view (10.0.0.5) differs from our view of it
			// (127.0.0.1): that NAT divergence is exactly what channel binding
			// covers, and it must be accepted, not rejected.
			name:     "embedded endpoint differs from ext (NAT)",
			base:     "/tmp/FS_10.0.0.5_39945_XXXR2qLuV_",
			ext:      "127.0.0.1:39945",
			wantLeaf: "FS_10.0.0.5_39945_XXXR2qLuV_127.0.0.1:39945",
		},
		{
			name:     "historical local core",
			base:     "/tmp/FS_abcd1234_",
			ext:      "127.0.0.1:39945",
			wantLeaf: "FS_abcd1234_127.0.0.1:39945",
		},
		{
			name:     "address-qualified remote",
			base:     "/tmp/FS_REMOTE_127.0.0.1_39945_XXXR2qLuV_",
			ext:      "127.0.0.1:39945",
			remote:   true,
			wantLeaf: "FS_REMOTE_127.0.0.1_39945_XXXR2qLuV_127.0.0.1:39945",
		},
		{"missing trailing underscore", "/tmp/FS_127.0.0.1_39945_XXXR2qLuV", "127.0.0.1:39945", false, "", true},
		{"not absolute", "FS_127.0.0.1_39945_XXXR2qLuV_", "127.0.0.1:39945", false, "", true},
		{"wrong parent", "/var/tmp/FS_127.0.0.1_39945_XXXR2qLuV_", "127.0.0.1:39945", false, "", true},
		{"core traversal", "/tmp/../etc/FS_x_", "127.0.0.1:39945", false, "", true},
		{"bad core shape", "/tmp/EVIL_", "127.0.0.1:39945", false, "", true},
		{"ext not ip:port", "/tmp/FS_127.0.0.1_39945_XXXR2qLuV_", "not-an-addr", false, "", true},
		{"ext with slash", "/tmp/FS_127.0.0.1_39945_XXXR2qLuV_", "1.2.3.4:5/../x", false, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf, err := validateFSChannelBoundPath(tc.base, tc.ext, fsAuthBaseDir, tc.remote)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got leaf %q", leaf)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if leaf != tc.wantLeaf {
				t.Fatalf("got leaf %q, want %q", leaf, tc.wantLeaf)
			}
			if strings.ContainsAny(leaf, "/\x00") {
				t.Fatalf("leaf %q contains a path separator", leaf)
			}
		})
	}
}

// TestFSAuthClientChannelBinding exercises performFSAuthenticationClient against
// a mock server over a real loopback TCP connection (so RemoteAddr/LocalAddr are
// genuine, unlike net.Pipe). The mock server speaks the C++ condor_auth_fs wire
// protocol with SEC_FS_ENFORCE_CHANNEL_BINDING on: it sends a directory name
// ending in '_', then verifies the client (a) created the directory with our
// channel-binding extension appended and (b) reported that extension back.
// Runs without condor_master, unlike the integration test.
func TestFSAuthClientChannelBinding(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	serverPort := ln.Addr().(*net.TCPAddr).Port
	// The server-supplied name is address-qualified with the server's own view
	// of its endpoint and ends in '_' to invite channel binding.
	dirPath := fmt.Sprintf("/tmp/FS_127.0.0.1_%d_XXXR2qLuV_", serverPort)
	expectedExt := fmt.Sprintf("127.0.0.1:%d", serverPort)
	expectedDir := dirPath + expectedExt

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- func() error {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return fmt.Errorf("accept: %w", aerr)
			}
			defer func() { _ = conn.Close() }()
			s := stream.NewStream(conn)

			// 1. Send the channel-binding directory name.
			m := message.NewMessageForStream(s)
			if e := m.PutString(ctx, dirPath); e != nil {
				return e
			}
			if e := m.FinishMessage(ctx); e != nil {
				return e
			}

			// 2. Read client result and the channel-binding extension.
			r := message.NewMessageFromStream(s)
			clientResult, e := r.GetInt(ctx)
			if e != nil {
				return fmt.Errorf("read client result: %w", e)
			}
			if clientResult != 0 {
				return fmt.Errorf("client reported failure %d", clientResult)
			}
			gotExt, e := r.GetStringWithMaxSize(ctx, MaxDirPathSize)
			if e != nil {
				return fmt.Errorf("read client ext: %w", e)
			}
			if _, e := r.GetChar(ctx); e != io.EOF {
				return fmt.Errorf("expected EOM after ext, got %v", e)
			}
			if gotExt != expectedExt {
				return fmt.Errorf("client ext = %q, want %q", gotExt, expectedExt)
			}

			// 3. Verify the client created exactly the bound directory.
			fi, e := os.Lstat(expectedDir)
			if e != nil {
				return fmt.Errorf("bound dir not created: %w", e)
			}
			if !fi.IsDir() || fi.Mode().Perm() != 0700 {
				return fmt.Errorf("bound dir wrong type/mode: %v", fi.Mode())
			}
			_ = os.Remove(expectedDir)

			// 4. Report success.
			v := message.NewMessageForStream(s)
			if e := v.PutInt(ctx, 0); e != nil {
				return e
			}
			return v.FinishMessage(ctx)
		}()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	cfg := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		Authentication: SecurityRequired,
		Command:        commands.DC_AUTHENTICATE,
	}
	auth := NewAuthenticator(cfg, stream.NewStream(conn))
	neg := &SecurityNegotiation{
		Command:      commands.DC_AUTHENTICATE,
		ClientConfig: cfg,
		IsClient:     true,
	}

	if err := auth.performFSAuthenticationClient(ctx, neg, false); err != nil {
		t.Fatalf("client FS authentication failed: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("mock server: %v", err)
	}

	// Client's deferred cleanup should have removed the bound directory.
	if _, err := os.Lstat(expectedDir); !os.IsNotExist(err) {
		_ = os.Remove(expectedDir)
		t.Errorf("bound directory %s not cleaned up by client", filepath.Base(expectedDir))
	}
}
