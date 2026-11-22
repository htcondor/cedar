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

// Package condortest provides a reusable in-process HTCondor test harness.
//
// It stands up a real, ephemeral HTCondor pool (master, collector, shared
// port, and schedd) via condor_master so that integration tests in any
// package can exercise CEDAR against a live pool. Tests that use this package
// are skipped automatically when condor_master is not available in PATH.
//
// Although this is a regular (non _test.go) source file, it intentionally
// imports the testing package: this is the idiomatic way to share a test
// harness across multiple Go packages.
package condortest

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/commands"
	"github.com/htcondor/cedar/message"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"

	"github.com/PelicanPlatform/classad/classad"
)

// Harness manages a mini HTCondor instance for integration testing.
type Harness struct {
	tmpDir        string
	configFile    string
	logDir        string
	passwordDir   string
	socketDir     string
	mapFile       string
	masterCmd     *exec.Cmd
	collectorAddr string
	collectorHost string
	collectorPort int
	caCertFile    string
	caKeyFile     string
	hostCertFile  string
	hostKeyFile   string
	tokenKeyFile  string
	t             *testing.T
}

// New creates and starts a mini HTCondor instance via condor_master.
func New(t *testing.T) *Harness {
	return NewWithConfig(t, "")
}

// NewWithConfig allows injecting extra HTCondor config lines (e.g., extra daemons).
func NewWithConfig(t *testing.T, extraConfig string) *Harness {
	t.Helper()

	// Check if condor_master is available
	masterPath, err := exec.LookPath("condor_master")
	if err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Determine LIBEXEC directory by looking for condor_shared_port
	var libexecDir string
	sharedPortPath, err := exec.LookPath("condor_shared_port")
	if err == nil {
		// Found condor_shared_port, use its parent directory
		libexecDir = filepath.Dir(sharedPortPath)
		t.Logf("Found condor_shared_port at %s, using LIBEXEC=%s", sharedPortPath, libexecDir)
	} else {
		// Not found in PATH, try deriving from condor_master location
		// condor_master is in sbin directory, so libexec is ../libexec relative to sbin
		sbinDir := filepath.Dir(masterPath)
		derivedLibexec := filepath.Join(filepath.Dir(sbinDir), "libexec")

		// Check if the derived path exists
		if _, err := os.Stat(filepath.Join(derivedLibexec, "condor_shared_port")); err == nil {
			libexecDir = derivedLibexec
			t.Logf("Using derived LIBEXEC=%s (from condor_master location)", libexecDir)
		} else {
			// Try standard location /usr/libexec/condor
			stdLibexec := "/usr/libexec/condor"
			if _, err := os.Stat(filepath.Join(stdLibexec, "condor_shared_port")); err == nil {
				libexecDir = stdLibexec
				t.Logf("Using standard LIBEXEC=%s", libexecDir)
			}
			// If not found, leave libexecDir empty and don't set LIBEXEC in config
			// HTCondor will use its default
		}
	}

	// Compute SBIN path from condor_master location
	sbinDir := filepath.Dir(masterPath)

	// Create temporary directory structure
	tmpDir := t.TempDir()

	// Create secure socket directory in /tmp to avoid path length issues
	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		t.Fatalf("Failed to create secure socket directory: %v", err)
	}

	h := &Harness{
		tmpDir:      tmpDir,
		configFile:  filepath.Join(tmpDir, "condor_config"),
		logDir:      filepath.Join(tmpDir, "log"),
		passwordDir: filepath.Join(tmpDir, "passwords"),
		socketDir:   socketDir,
		mapFile:     filepath.Join(tmpDir, "condor_mapfile"),
		t:           t,
	}

	// Create directories
	for _, dir := range []string{h.logDir, h.passwordDir} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	// Create condor mapfile for SciTokens
	mapContent := `# HTCondor mapfile for SciTokens authentication
# Map SciToken identities to local users
# Format: issuer,subject -> extract username from subject (before @)
SCITOKENS .*,([^@]+)@.* \1
`
	if err := os.WriteFile(h.mapFile, []byte(mapContent), 0644); err != nil {
		t.Fatalf("Failed to write mapfile: %v", err)
	}

	// Generate SSL certificates
	h.caCertFile = filepath.Join(tmpDir, "ca-cert.pem")
	h.caKeyFile = filepath.Join(tmpDir, "ca-key.pem")
	h.hostCertFile = filepath.Join(tmpDir, "host-cert.pem")
	h.hostKeyFile = filepath.Join(tmpDir, "host-key.pem")

	if err := security.GenerateTestCA(h.caCertFile, h.caKeyFile); err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	if err := security.GenerateTestHostCert(h.hostCertFile, h.hostKeyFile, h.caCertFile, h.caKeyFile, "localhost"); err != nil {
		t.Fatalf("Failed to generate host certificate: %v", err)
	}

	// Generate TOKEN signing key
	h.tokenKeyFile = filepath.Join(h.passwordDir, "POOL")
	if err := security.GeneratePoolSigningKey(h.tokenKeyFile); err != nil {
		t.Fatalf("Failed to generate token signing key: %v", err)
	}

	// Generate HTCondor configuration
	h.collectorHost = "127.0.0.1"
	h.collectorPort = 0 // Use dynamic port

	// Build LIBEXEC line if we found a valid directory
	libexecLine := ""
	if libexecDir != "" {
		libexecLine = fmt.Sprintf("LIBEXEC = %s\n", libexecDir)
	}
	configContent := fmt.Sprintf(`
# Mini HTCondor collector configuration for integration testing
CONDOR_HOST = 127.0.0.1

# Use local directory structure
LOCAL_DIR = %s
LOG = $(LOCAL_DIR)/log

# Set paths for HTCondor binaries
SBIN = %s
%s
# Collector configuration
COLLECTOR_NAME = test_collector
COLLECTOR_HOST = 127.0.0.1:0
CONDOR_VIEW_HOST = $(COLLECTOR_HOST)

# Network settings
BIND_ALL_INTERFACES = False
NETWORK_INTERFACE = 127.0.0.1

# Enable shared port with proper configuration
USE_SHARED_PORT = True
SHARED_PORT_DEBUG = D_FULLDEBUG
DAEMON_SOCKET_DIR = %s

# Security settings - enable all authentication methods
SEC_DEFAULT_AUTHENTICATION = OPTIONAL
SEC_DEFAULT_AUTHENTICATION_METHODS = FS,CLAIMTOBE,PASSWORD,SSL,IDTOKENS,TOKEN,SCITOKENS
SEC_DEFAULT_ENCRYPTION = OPTIONAL
SEC_DEFAULT_INTEGRITY = OPTIONAL
SEC_CLIENT_AUTHENTICATION_METHODS = FS,CLAIMTOBE,PASSWORD,SSL,IDTOKENS,TOKEN,SCITOKENS

# Allow all access for testing
ALLOW_READ = *
ALLOW_WRITE = *
ALLOW_NEGOTIATOR = *
ALLOW_ADMINISTRATOR = *
ALLOW_OWNER = *
ALLOW_CLIENT = *

# SSL configuration
AUTH_SSL_SERVER_CERTFILE = %s
AUTH_SSL_SERVER_KEYFILE = %s
AUTH_SSL_SERVER_CAFILE = %s
AUTH_SSL_CLIENT_CERTFILE = %s
AUTH_SSL_CLIENT_KEYFILE = %s
AUTH_SSL_CLIENT_CAFILE = %s

# TOKEN configuration
SEC_PASSWORD_DIRECTORY = %s
SEC_TOKEN_POOL_SIGNING_KEY_FILE = %s
SEC_TOKEN_ISSUER_KEY = POOL
TRUST_DOMAIN = test.domain

# SciTokens cache configuration
SEC_SCITOKENS_CACHE = %s

# Mapfile for authentication
CERTIFICATE_MAPFILE = %s

# Schedd configuration - enable a schedd daemon for testing
DAEMON_LIST = MASTER, COLLECTOR, SHARED_PORT, SCHEDD
SCHEDD_NAME = test_schedd
SCHEDD_LOG = $(LOG)/SchedLog
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address
MAX_SCHEDD_LOG = 10000000
SCHEDD_DEBUG = D_FULLDEBUG D_SECURITY

# Logging
MAX_COLLECTOR_LOG = 10000000
COLLECTOR_DEBUG = D_FULLDEBUG D_SECURITY
SHARED_PORT_DEBUG = D_FULLDEBUG D_SECURITY D_NETWORK:2 D_COMMAND
MAX_SHARED_PORT_LOG = 10000000
MAX_MASTER_LOG = 10000000
MASTER_DEBUG = D_FULLDEBUG D_SECURITY

# Disable unwanted features for testing
ENABLE_SOAP = False
ENABLE_WEB_SERVER = False
`, h.tmpDir, sbinDir, libexecLine, h.socketDir, h.hostCertFile, h.hostKeyFile, h.caCertFile,
		h.hostCertFile, h.hostKeyFile, h.caCertFile,
		h.passwordDir, h.tokenKeyFile, h.getSciTokensCacheDir(), h.mapFile)

	if extraConfig != "" {
		configContent += "\n" + extraConfig + "\n"
	}

	if err := os.WriteFile(h.configFile, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Start condor_master (which will start collector, shared_port, and schedd)
	h.masterCmd = exec.Command(masterPath, "-f")
	h.masterCmd.Env = append(os.Environ(),
		"CONDOR_CONFIG="+h.configFile,
		"_CONDOR_LOCAL_DIR="+h.tmpDir,
	)
	// Add XDG_CACHE_HOME if set in the environment (for SciTokens cache)
	if cacheHome := os.Getenv("XDG_CACHE_HOME"); cacheHome != "" {
		h.masterCmd.Env = append(h.masterCmd.Env, "XDG_CACHE_HOME="+cacheHome)
		h.t.Logf("🔑 Setting XDG_CACHE_HOME for HTCondor: %s", cacheHome)
	}
	h.masterCmd.Dir = h.tmpDir

	// Capture output for debugging
	h.masterCmd.Stdout = os.Stdout
	h.masterCmd.Stderr = os.Stderr

	if err := h.masterCmd.Start(); err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}

	// Register cleanup
	t.Cleanup(func() {
		h.Shutdown(t)
	})

	// Wait for collector and schedd to start
	if err := h.waitForCondor(); err != nil {
		t.Fatalf("Failed to wait for HTCondor daemons: %v", err)
	}

	return h
}

// waitForCondor waits for both collector and schedd to start and become responsive
func (h *Harness) waitForCondor() error {
	// Wait for collector to write its address file
	collectorAddressFile := filepath.Join(h.logDir, ".collector_address")
	scheddAddressFile := filepath.Join(h.logDir, ".schedd_address")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	collectorReady := false
	scheddReady := false

	for {
		select {
		case <-ctx.Done():
			// List files in log directory for debugging
			if entries, err := os.ReadDir(h.logDir); err == nil {
				h.t.Logf("Files in log directory: ")
				for _, entry := range entries {
					h.t.Logf("  %s", entry.Name())
				}
			}
			h.printAllLogs()

			if !collectorReady {
				return fmt.Errorf("timeout waiting for collector to start")
			}
			if !scheddReady {
				return fmt.Errorf("timeout waiting for schedd to start")
			}
			return fmt.Errorf("timeout waiting for HTCondor daemons to start")

		case <-ticker.C:
			// Check collector if not ready
			if !collectorReady {
				if data, err := os.ReadFile(collectorAddressFile); err == nil {
					// Parse address from file
					lines := strings.Split(string(data), "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "$") {
							h.collectorAddr = line
							break
						}
					}

					if h.collectorAddr != "" {
						// Check for invalid address
						if strings.Contains(h.collectorAddr, "(null)") {
							h.printCollectorLog()
							return fmt.Errorf("collector address file contains '(null)' - daemon failed to start")
						}

						// Parse address using addresses package
						addrInfo := addresses.ParseHTCondorAddress(h.collectorAddr)

						// Split host and port
						host, portStr, err := net.SplitHostPort(addrInfo.ServerAddr)
						if err != nil {
							h.t.Logf("Failed to parse collector address %q: %v", addrInfo.ServerAddr, err)
							continue
						}

						port := 0
						if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
							h.t.Logf("Failed to parse collector port: %v", err)
							continue
						}

						h.collectorHost = host
						h.collectorPort = port
						collectorReady = true

						h.t.Logf("✅ Collector started at: %s (host=%s, port=%d)", h.collectorAddr, host, port)
					}
				}
			}

			// Check schedd if not ready
			if !scheddReady {
				if data, err := os.ReadFile(scheddAddressFile); err == nil {
					// Just check that the file exists and has content
					content := strings.TrimSpace(string(data))
					if content != "" && !strings.Contains(content, "(null)") {
						scheddReady = true
						h.t.Logf("✅ Schedd started (address file present)")
					} else if strings.Contains(content, "(null)") {
						h.printSchedLog()
						return fmt.Errorf("schedd address file contains '(null)' - daemon failed to start")
					}
				}
			}

			// If both are ready, we're done
			if collectorReady && scheddReady {
				h.t.Logf("✅ All HTCondor daemons ready")
				// Give a bit more time for daemons to fully initialize
				time.Sleep(1 * time.Second)
				return nil
			}
		}
	}
}

// printCollectorLog prints the collector log for debugging
func (h *Harness) printCollectorLog() {
	// First try to print master log
	masterLog := filepath.Join(h.logDir, "MasterLog")
	if data, err := os.ReadFile(masterLog); err == nil {
		h.t.Logf("=== MasterLog contents ===\n%s\n=== End MasterLog ===", string(data))
	} else {
		h.t.Logf("Failed to read MasterLog: %v", err)
	}

	// Then try collector log
	collectorLog := filepath.Join(h.logDir, "CollectorLog")
	if data, err := os.ReadFile(collectorLog); err == nil {
		h.t.Logf("=== CollectorLog contents ===\n%s\n=== End CollectorLog ===", string(data))
	} else {
		h.t.Logf("Failed to read CollectorLog: %v", err)
	}
}

// printSchedLog prints the schedd log for debugging
func (h *Harness) printSchedLog() {
	schedLog := filepath.Join(h.logDir, "SchedLog")
	data, err := os.ReadFile(schedLog)
	if err != nil {
		h.t.Logf("Failed to read SchedLog: %v", err)
		return
	}

	h.t.Logf("=== SchedLog contents ===\n%s\n=== End SchedLog ===", string(data))
}

// printMasterLog prints the master log for debugging
func (h *Harness) printMasterLog() {
	masterLog := filepath.Join(h.logDir, "MasterLog")
	data, err := os.ReadFile(masterLog)
	if err != nil {
		h.t.Logf("Failed to read MasterLog: %v", err)
		return
	}

	h.t.Logf("=== MasterLog contents ===\n%s\n=== End MasterLog ===", string(data))
}

// printSharedPortLog prints the shared port log for debugging
func (h *Harness) printSharedPortLog() {
	sharedPortLog := filepath.Join(h.logDir, "SharedPortLog")
	data, err := os.ReadFile(sharedPortLog)
	if err != nil {
		h.t.Logf("Failed to read SharedPortLog: %v", err)
		return
	}

	h.t.Logf("=== SharedPortLog contents ===\n%s\n=== End SharedPortLog ===", string(data))
}

// PrintAllLogs prints all HTCondor logs for debugging.
func (h *Harness) PrintAllLogs() {
	h.printAllLogs()
}

// printAllLogs prints all HTCondor logs for debugging
func (h *Harness) printAllLogs() {
	h.t.Logf("=== Printing All HTCondor Logs ===")
	h.printCollectorLog()
	h.printSchedLog()
	h.printMasterLog()
	h.printSharedPortLog()
	h.t.Logf("=== End of HTCondor Logs ===")
}

// QuerySchedAds queries the collector for schedd ads and returns the count and any found address.
func (h *Harness) QuerySchedAds(t *testing.T) (int, string, error) {
	// Connect to collector to query for schedd
	addr := net.JoinHostPort(h.GetCollectorHost(), fmt.Sprintf("%d", h.GetCollectorPort()))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return 0, "", fmt.Errorf("failed to connect to collector: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}()

	// Create stream for collector query
	cedarStream := stream.NewStream(conn)

	// Perform security handshake with collector first
	clientConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		Command:        commands.QUERY_SCHEDD_ADS,
	}

	auth := security.NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = auth.ClientHandshake(ctx)
	if err != nil {
		return 0, "", fmt.Errorf("security handshake with collector failed: %v", err)
	}

	// Create query ClassAd for schedd ads
	queryAd := classad.New()
	_ = queryAd.Set("MyType", "Query")
	_ = queryAd.Set("TargetType", "Scheduler") // Query Scheduler ads (schedd)
	_ = queryAd.Set("Requirements", true)      // Get all schedd ads
	_ = queryAd.Set("LimitResults", 10)        // Limit to 10 results

	// Send the query ClassAd using the Message API
	queryMsg := message.NewMessageForStream(cedarStream)
	if err := queryMsg.PutClassAd(ctx, queryAd); err != nil {
		return 0, "", fmt.Errorf("failed to send query ClassAd: %v", err)
	}

	// Send the message with End-of-Message
	if err := queryMsg.FlushFrame(ctx, true); err != nil {
		return 0, "", fmt.Errorf("failed to send query message: %v", err)
	}

	// Read response using the correct HTCondor protocol
	respMsg := message.NewMessageFromStream(cedarStream)

	var scheddAddress string
	adsReceived := 0

	// Process response ads with the correct protocol
	for {
		// Read "more" flag
		more, err := respMsg.GetInt32(ctx)
		if err != nil {
			return 0, "", fmt.Errorf("failed to read 'more' flag: %v", err)
		}

		if more == 0 {
			break
		}

		// Read ClassAd
		ad, err := respMsg.GetClassAd(ctx)
		if err != nil {
			return 0, "", fmt.Errorf("failed to read schedd ad %d: %v", adsReceived+1, err)
		}

		adsReceived++

		// Extract MyAddress from the ClassAd
		if myAddr, ok := ad.EvaluateAttrString("MyAddress"); ok {
			scheddAddress = myAddr
			t.Logf("Found schedd MyAddress: %s", scheddAddress)
		}
	}

	return adsReceived, scheddAddress, nil
}

// Shutdown stops the HTCondor master instance.
func (h *Harness) Shutdown(t *testing.T) {
	if h.masterCmd != nil && h.masterCmd.Process != nil {
		h.t.Log("Shutting down HTCondor master")

		// Try graceful shutdown first
		if err := h.masterCmd.Process.Signal(syscall.SIGTERM); err != nil {
			h.t.Logf("Failed to send interrupt to master: %v", err)
		}

		// Wait for graceful shutdown
		done := make(chan error, 1)
		go func() {
			done <- h.masterCmd.Wait()
		}()

		select {
		case <-time.After(5 * time.Second):
			// Force kill if graceful shutdown times out
			if err := h.masterCmd.Process.Kill(); err != nil {
				h.t.Logf("Failed to kill master: %v", err)
			}
			if err := <-done; err != nil {
				h.t.Logf("Master exited after kill: %v", err)
			}
		case err := <-done:
			// Graceful shutdown succeeded
			if err != nil {
				h.t.Logf("Master exited: %v", err)
			}
		}
	}

	if t.Failed() {
		t.Logf("Test failed, printing all logs for debugging...")
		h.printAllLogs()
	}

	// Clean up socket directory
	if h.socketDir != "" {
		if err := os.RemoveAll(h.socketDir); err != nil {
			h.t.Logf("Failed to remove socket directory %s: %v", h.socketDir, err)
		}
	}
}

// GetCollectorAddr returns the collector address.
func (h *Harness) GetCollectorAddr() string {
	return h.collectorAddr
}

// GetCollectorHost returns the collector host.
func (h *Harness) GetCollectorHost() string {
	return h.collectorHost
}

// GetCollectorPort returns the collector port.
func (h *Harness) GetCollectorPort() int {
	return h.collectorPort
}

// GetCollectorAlias extracts the alias from the collector sinful string.
// Sinful string format: <127.0.0.1:52504?addrs=127.0.0.1-52504&alias=f4hp7ql65f-2.local>
func (h *Harness) GetCollectorAlias() string {
	// Parse the alias from the sinful string
	if strings.Contains(h.collectorAddr, "alias=") {
		// Extract everything after "alias="
		parts := strings.Split(h.collectorAddr, "alias=")
		if len(parts) >= 2 {
			// Get the alias value (everything after alias= until & or >)
			alias := parts[1]
			// Trim any trailing characters
			if idx := strings.IndexAny(alias, "&>"); idx >= 0 {
				alias = alias[:idx]
			}
			return alias
		}
	}
	// Fallback to host if no alias found
	return h.collectorHost
}

// getSciTokensCacheDir returns the SciTokens cache directory from XDG_CACHE_HOME
func (h *Harness) getSciTokensCacheDir() string {
	if cacheHome := os.Getenv("XDG_CACHE_HOME"); cacheHome != "" {
		return cacheHome
	}
	// Fallback to system default
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".cache")
}

// TmpDir returns the harness temporary directory. Tests can place generated
// tokens and other scratch files here.
func (h *Harness) TmpDir() string {
	return h.tmpDir
}

// PasswordDir returns the directory containing the pool signing key(s).
func (h *Harness) PasswordDir() string {
	return h.passwordDir
}

// ConfigDir returns the directory containing the generated condor_config.
func (h *Harness) ConfigDir() string {
	return h.tmpDir
}

// CACertFile returns the path to the generated CA certificate.
func (h *Harness) CACertFile() string {
	return h.caCertFile
}

// SocketDir returns the pool's DAEMON_SOCKET_DIR, the directory the
// condor_shared_port daemon watches for endpoint sockets.
func (h *Harness) SocketDir() string {
	return h.socketDir
}

// HostCertFile returns the path to the generated host certificate.
func (h *Harness) HostCertFile() string {
	return h.hostCertFile
}

// HostKeyFile returns the path to the generated host private key.
func (h *Harness) HostKeyFile() string {
	return h.hostKeyFile
}

// SupportsAuthMethod checks if HTCondor supports a specific authentication method
// by querying the collector's capabilities.
func (h *Harness) SupportsAuthMethod(method string) bool {
	// For now, we'll assume SCITOKENS is not supported in older HTCondor versions
	// This can be enhanced to actually query the collector for supported methods
	// by examining the SEC_DEFAULT_AUTHENTICATION_METHODS or similar config

	// SCITOKENS was added in HTCondor 8.9.2+, so we'll check for that
	// For testing purposes, we'll just return true if we have SSL certs
	// (which indicates a reasonably modern HTCondor setup)
	if method == "SCITOKENS" {
		return h.caCertFile != "" && h.hostCertFile != "" && h.hostKeyFile != ""
	}
	return true
}
