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
	"net"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/stream"
)

// dialLoopbackPair returns a connected (client, server) TCP pair on loopback so
// both ends have real addresses (unlike net.Pipe), which is what engages FS-auth
// channel binding.
func dialLoopbackPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type res struct {
		c   net.Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- res{c, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-accepted
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	return client, r.c
}

// TestFSAuthChannelBindingRoundTrip runs cedar's own FS-auth client and server
// against each other over a real loopback connection. Because both ends have
// real addresses, the server emits an address-qualified name ending in '_', the
// client appends its view of the server and reports it, and the server verifies
// the binding and stats the bound directory -- exercising both new code paths.
func TestFSAuthChannelBindingRoundTrip(t *testing.T) {
	clientConn, serverConn := dialLoopbackPair(t)
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		Authentication: SecurityRequired,
		TrustDomain:    "test.domain",
		Command:        commands.DC_AUTHENTICATE,
	}
	serverConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		Authentication: SecurityRequired,
		TrustDomain:    "test.domain",
		UIDDomain:      "UID.Example",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverNeg := &SecurityNegotiation{Command: commands.DC_AUTHENTICATE, ServerConfig: serverConfig, IsClient: false}
	clientNeg := &SecurityNegotiation{Command: commands.DC_AUTHENTICATE, ClientConfig: clientConfig, IsClient: true}

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- NewAuthenticator(serverConfig, stream.NewStream(serverConn)).
			performFSAuthenticationServer(ctx, serverNeg, false)
	}()

	if err := NewAuthenticator(clientConfig, stream.NewStream(clientConn)).
		performFSAuthenticationClient(ctx, clientNeg, false); err != nil {
		t.Fatalf("client FS auth failed: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server FS auth failed: %v", err)
	}

	cur, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	// FS names the marker's owner at the server's UID_DOMAIN.
	if want := cur.Username + "@uid.example"; serverNeg.User != want {
		t.Errorf("authenticated user = %q, want %q", serverNeg.User, want)
	}
}

// TestVerifyServerChannelBindingExt checks the server-side extension validation
// against a real connection whose local endpoint is known.
func TestVerifyServerChannelBindingExt(t *testing.T) {
	clientConn, serverConn := dialLoopbackPair(t)
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	a := NewAuthenticator(&SecurityConfig{}, stream.NewStream(serverConn))
	local := serverConn.LocalAddr().(*net.TCPAddr)
	matching := fmt.Sprintf("%s:%d", local.IP.String(), local.Port)

	if err := a.verifyServerChannelBindingExt(matching); err != nil {
		t.Errorf("matching endpoint %q rejected: %v", matching, err)
	}

	bad := []string{
		fmt.Sprintf("%s:%d", local.IP.String(), local.Port+1), // wrong port
		fmt.Sprintf("10.99.99.99:%d", local.Port),             // wrong ip
		"not-an-addr",
		"1.2.3.4:5/../etc", // path separator
		"",
	}
	for _, ext := range bad {
		if err := a.verifyServerChannelBindingExt(ext); err == nil {
			t.Errorf("extension %q accepted, want rejected", ext)
		}
	}
}

// TestVerifyServerChannelBindingExtSharedPort covers the "ip:port?sock=ID" form
// an HTCondor 25.14+ client reports when it dialed through a shared port
// (HTCONDOR-3883).
func TestVerifyServerChannelBindingExtSharedPort(t *testing.T) {
	clientConn, serverConn := dialLoopbackPair(t)
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	local := serverConn.LocalAddr().(*net.TCPAddr)
	hostPort := fmt.Sprintf("%s:%d", local.IP.String(), local.Port)
	otherPort := fmt.Sprintf("%s:%d", local.IP.String(), local.Port+1)

	cases := []struct {
		name   string
		ourID  string
		ext    string
		accept bool
	}{
		{"id unknown, client id accepted on ip:port", "", hostPort + "?sock=collector", true},
		{"id matches", "collector", hostPort + "?sock=collector", true},
		{"id mismatch", "collector", hostPort + "?sock=schedd_123_abcd", false},
		{"bare ip:port with id known", "collector", hostPort, true},
		{"wrong port with id", "collector", otherPort + "?sock=collector", false},
		{"wrong port, id unknown", "", otherPort + "?sock=collector", false},
		{"empty id", "", hostPort + "?sock=", false},
		{"id with extra params", "", hostPort + "?sock=collector&noUDP", false},
		{"id with path separator", "", hostPort + "?sock=a/../b", false},
		{"id without ip:port", "collector", "?sock=collector", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAuthenticator(&SecurityConfig{SharedPortID: tc.ourID}, stream.NewStream(serverConn))
			err := a.verifyServerChannelBindingExt(tc.ext)
			if tc.accept && err != nil {
				t.Errorf("extension %q rejected: %v", tc.ext, err)
			}
			if !tc.accept && err == nil {
				t.Errorf("extension %q accepted, want rejected", tc.ext)
			}
		})
	}
}

// cppFSClient plays the client side of FS authentication the way HTCondor's
// condor_auth_fs.cpp does: receive the server's directory name, and when it
// ends in '_' create it with ext appended and report ext after the result.
// Returns the server's verdict (0 = authenticated).
func cppFSClient(ctx context.Context, t *testing.T, conn net.Conn, ext string) int {
	t.Helper()
	s := stream.NewStream(conn)
	in := message.NewMessageFromStream(s)
	dir, err := in.GetString(ctx)
	if err != nil {
		t.Fatalf("client: read directory: %v", err)
	}
	if !strings.HasSuffix(dir, "_") {
		t.Fatalf("client: server directory %q does not invite channel binding", dir)
	}
	bound := dir + ext
	result := 0
	if err := os.Mkdir(bound, 0700); err != nil {
		t.Errorf("client: mkdir %s: %v", bound, err)
		result = -1
	}
	defer func() { _ = os.Remove(bound) }()

	out := message.NewMessageForStream(s)
	if err := out.PutInt(ctx, result); err != nil {
		t.Fatalf("client: send result: %v", err)
	}
	if err := out.PutString(ctx, ext); err != nil {
		t.Fatalf("client: send extension: %v", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		t.Fatalf("client: finish: %v", err)
	}

	verdict, err := message.NewMessageFromStream(s).GetInt(ctx)
	if err != nil {
		t.Fatalf("client: read server result: %v", err)
	}
	return verdict
}

// TestFSAuthServerCppSharedPortClient runs cedar's FS server against the
// wire exchange of an HTCondor 25.14+ client that dialed through a shared port
// and so reports "ip:port?sock=ID" as its channel-binding extension.
func TestFSAuthServerCppSharedPortClient(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	cases := []struct {
		name   string
		ourID  string
		sockID string // "" = 25.13-style bare ip:port
		accept bool
	}{
		{"25.14 client, our id unknown", "", "collector", true},
		{"25.14 client, our id matches", "collector", "collector", true},
		{"25.14 client, our id differs", "collector", "schedd_1_ab", false},
		{"25.13 client, our id known", "collector", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := dialLoopbackPair(t)
			defer func() { _ = clientConn.Close() }()
			defer func() { _ = serverConn.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			serverConfig := &SecurityConfig{
				AuthMethods:    []AuthMethod{AuthFS},
				Authentication: SecurityRequired,
				SharedPortID:   tc.ourID,
				UIDDomain:      "UID.Example",
			}
			serverNeg := &SecurityNegotiation{Command: commands.DC_AUTHENTICATE, ServerConfig: serverConfig}
			srvErr := make(chan error, 1)
			go func() {
				srvErr <- NewAuthenticator(serverConfig, stream.NewStream(serverConn)).
					performFSAuthenticationServer(ctx, serverNeg, false)
			}()

			// The C++ client appends its view of the server: the address it
			// dialed, which is the server connection's local address.
			ext := serverConn.LocalAddr().String()
			if tc.sockID != "" {
				ext += "?sock=" + tc.sockID
			}
			verdict := cppFSClient(ctx, t, clientConn, ext)
			err := <-srvErr

			if tc.accept {
				if verdict != 0 || err != nil {
					t.Fatalf("extension %q: verdict %d, server error %v; want authenticated", ext, verdict, err)
				}
				if want := cur.Username + "@uid.example"; serverNeg.User != want {
					t.Errorf("authenticated user = %q, want %q", serverNeg.User, want)
				}
				return
			}
			if verdict == 0 || err == nil {
				t.Fatalf("extension %q: verdict %d, server error %v; want rejected", ext, verdict, err)
			}
			if serverNeg.User != "" {
				t.Errorf("rejected handshake still set user %q", serverNeg.User)
			}
		})
	}
}
