package ccb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSharedPortEndpointRequiresSocketDir: a shared-port endpoint with no
// SocketDir used to bind its socket at a bare relative path, so it landed in
// whatever directory the process happened to be in. That cannot work. The
// address we advertise is "<host:port?sock=NAME>", and the shared_port daemon
// resolves NAME inside its own DAEMON_SOCKET_DIR -- so the socket is
// unreachable, and the dial fails as a reverse-connect timeout pointing at
// nothing. Refuse the configuration instead of binding somewhere useless.
func TestSharedPortEndpointRequiresSocketDir(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)

	ln, addr, err := newReverseListener(DialOptions{
		SharedPortEndpoint: &SharedPortEndpointConfig{
			SharedPortAddr: "10.0.0.2:9618",
			SocketName:     "spsock",
		},
	})
	if err == nil {
		_ = ln.Close()
		t.Fatalf("a shared-port endpoint with no SocketDir was accepted, advertising %q", addr)
	}
	if !strings.Contains(err.Error(), "SocketDir") {
		t.Errorf("error does not name the missing field: %v", err)
	}

	entries, rerr := os.ReadDir(cwd)
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, e := range entries {
		t.Errorf("the endpoint socket was created in the process working directory: %s", e.Name())
	}
}

// TestSharedPortEndpointUsesSocketDir is the other half: with SocketDir set
// the socket is created there, the advertised sinful names it, and closing
// the listener removes it.
func TestSharedPortEndpointUsesSocketDir(t *testing.T) {
	dir, err := os.MkdirTemp("", "ccbsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	ln, addr, err := newReverseListener(DialOptions{
		SharedPortEndpoint: &SharedPortEndpointConfig{
			SharedPortAddr: "10.0.0.2:9618",
			SocketDir:      dir,
			SocketName:     "spsock",
		},
	})
	if err != nil {
		t.Fatalf("newReverseListener: %v", err)
	}
	if want := "<10.0.0.2:9618?sock=spsock>"; addr != want {
		t.Errorf("advertised %q, want %q", addr, want)
	}
	sockPath := filepath.Join(dir, "spsock")
	if _, err := os.Stat(sockPath); err != nil {
		t.Errorf("socket not created in SocketDir: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("closing the listener: %v", err)
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("socket left behind after Close: stat err = %v", err)
	}
}
