package condortest

import (
	"os"
	"strings"
	"testing"
)

// TestNewSocketDirRemovedWithoutHarness pins the ordering that makes the socket
// directory safe: the removal is registered by newSocketDir itself, so it runs
// even when the caller never gets as far as building a Harness — which is what
// happens on every t.Fatalf in setup. It also covers the double removal, since
// Shutdown removes the same directory before this cleanup runs.
func TestNewSocketDirRemovedWithoutHarness(t *testing.T) {
	var dir string

	// The subtest does nothing but create the directory. Anything it would have
	// done afterwards is exactly the part that a t.Fatalf skips.
	t.Run("create", func(t *testing.T) {
		dir = newSocketDir(t)

		if !strings.HasPrefix(dir, "/tmp/htc_sock_") {
			t.Fatalf("unexpected socket directory %q", dir)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("socket directory not created: %v", err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", dir)
		}
	})

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("socket directory %s outlived its creator: stat error = %v", dir, err)
	}

	// Shutdown's own os.RemoveAll of the same path must stay harmless.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("second removal of %s failed: %v", dir, err)
	}
}
