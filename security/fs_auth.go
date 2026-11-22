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

// Package security provides FS and CLAIMTOBE authentication implementation
// for CEDAR streams.
//
// This file implements HTCondor's FS (filesystem) and CLAIMTOBE authentication
// methods as documented in condor_auth_fs.cpp and condor_auth_claim.cpp.
package security

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/htcondor/cedar/addresses"
	"github.com/htcondor/cedar/message"
)

const (
	// Maximum sizes for DoS protection
	MaxDirPathSize  = 4096 // 4KB max for directory paths
	MaxUsernameSize = 1024 // 1KB max for usernames

	// fsAuthBaseDir is the on-the-wire DEFAULT base directory for FS auth, used when
	// neither FS_LOCAL_DIR (FS) nor FS_REMOTE_DIR (FS_REMOTE) is configured. When one
	// IS configured, both the server's generateLocalFSPath/generateRemoteFSPath and the
	// client's path validation use that instead (SecurityConfig.FSLocalDir/FSRemoteDir,
	// resolved from this side's OWN config via fsAuthBase). A site running e.g.
	// FS_LOCAL_DIR=/dev/shm thus authenticates without the client rejecting the path.
	fsAuthBaseDir = "/tmp"
)

// fsAuthLocalLeafRE matches the exact leaf shape an FS-auth server
// emits, covering both implementations a real client may meet:
//
//   - Cedar's generateLocalFSPath uses os.MkdirTemp(baseDir, "FS_*"),
//     which replaces "*" with decimal digits from runtime random
//     (uint32, ≤10 digits).
//   - HTCondor's C++ condor_auth_fs.cpp uses condor_mkstemp on
//     template "FS_XXXXXXXXX" (9 X's). The X-replacement pulls from
//     mkstemp's alphanumeric character set, and not all positions
//     are guaranteed to be filled — we've observed leaves like
//     "FS_XXXjlv9Zj" where the first three X's stayed literal.
//     "X" is a perfectly valid alphanumeric character, so we don't
//     need a special case for it; the bound of 16 just gives some
//     headroom over HTCondor's 9-char template.
//
// The regex anchors both ends and requires at least one alphanumeric
// after the "FS_" prefix. Anything else — embedded "..", slashes,
// dots, dashes, well-known leaves like ".X11-unix" — is rejected so
// a malicious server can't pick its own leaf name even after passing
// the base-dir check.
var fsAuthLocalLeafRE = regexp.MustCompile(`^FS_[A-Za-z0-9]{1,16}$`)

// fsAuthRemoteLeafRE matches generateRemoteFSPath's pattern:
// "FS_REMOTE_<hostname>_<pid>_<rand>". Hostname allows the
// RFC-1123-friendly character set plus underscore (some sites use
// underscores in /etc/hostname even though RFC 1123 frowns on it),
// PID is 1+ decimal digits, random suffix is up to 16 alphanumeric
// characters (covers Go's decimal-uint32 output and HTCondor's
// 9-char mkstemp output). The regex backtracks correctly when the
// hostname itself contains underscores: greedy hostname consumption
// gives way to the trailing "_<pid>_<rand>$" anchor.
var fsAuthRemoteLeafRE = regexp.MustCompile(`^FS_REMOTE_[A-Za-z0-9._\-]+_[0-9]+_[A-Za-z0-9]{1,16}$`)

// performFSAuthentication performs filesystem-based authentication
// Implements the CAUTH_FILESYSTEM protocol from condor_auth_fs.cpp
func (a *Authenticator) performFSAuthentication(ctx context.Context, negotiation *SecurityNegotiation, remote bool) error {
	if negotiation.IsClient {
		return a.performFSAuthenticationClient(ctx, negotiation, remote)
	}
	return a.performFSAuthenticationServer(ctx, negotiation, remote)
}

// performFSAuthenticationClient handles client side of FS authentication.
//
// Security note: the path the client mkdirs is supplied by the server.
// A malicious server could otherwise direct the client to create
// directories anywhere the client process has write permission —
// useful for "defeat existence-based locking" or "drop attacker-named
// directory under $HOME" classes of confused-deputy attack. We mitigate
// in two layers:
//
//  1. validateFSAuthPath rejects anything whose absolute parent isn't
//     fsAuthBaseDir or whose leaf doesn't match the expected
//     FS_ / FS_REMOTE_ prefix the server's MkdirTemp emits. That stops
//     path traversal, base-directory escape, and "leaf collides with
//     a known lockdir name" before any filesystem call.
//
//  2. The actual mkdir/remove go through *os.Root opened on
//     fsAuthBaseDir. os.Root.Mkdir refuses any name that escapes the
//     root via "..", absolute paths, or symlinks pointing outside —
//     so even if validateFSAuthPath had a bug, the kernel-enforced
//     root would block escape. Belt-and-suspenders.
func (a *Authenticator) performFSAuthenticationClient(ctx context.Context, negotiation *SecurityNegotiation, remote bool) error {
	// Receive directory name to create from server
	msg := message.NewMessageFromStream(a.stream)

	// Use WithMaxSize to limit directory path size and prevent DoS
	dirPath, err := msg.GetStringWithMaxSize(ctx, MaxDirPathSize)
	if err != nil {
		return fmt.Errorf("failed to receive directory path: %w", err)
	}

	// Verify we've received the complete message with EOM marker
	_, err = msg.GetChar(ctx)
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("protocol error: error checking for message completion: %w", err)
		}
		return fmt.Errorf("protocol error: expected EOM but more data available")
	}

	// Initialize result as failure
	clientResult := -1
	// leafName is the validated, single-component name passed to
	// root.Mkdir / root.Remove. Set only after validateFSAuthPath
	// accepts the server-supplied path.
	var leafName string
	var root *os.Root
	// base is the FS-auth base directory (this client's own FS_LOCAL_DIR/FS_REMOTE_DIR,
	// else /tmp); declared here so the cleanup defer below can name it in its log.
	var base string
	// boundExt is the channel-binding extension we appended to the server's
	// path (empty when the server didn't request channel binding). When
	// non-empty it is reported back to the server in the reply so it can
	// stat the same connection-bound directory name.
	var boundExt string

	// Try to create the directory if server provided a valid path
	if dirPath != "" {
		// The peer address (the server we dialed) is the endpoint an address-qualified
		// path is checked against.
		var peerAddr net.Addr
		if c := a.stream.GetConnection(); c != nil {
			peerAddr = c.RemoteAddr()
		}

		// Expected base from the CLIENT's own config (FS_LOCAL_DIR / FS_REMOTE_DIR),
		// defaulting to /tmp. Never the peer's, so a hostile server cannot direct the
		// client to create a directory outside the configured base.
		base = a.fsAuthBase(remote)

		// Channel binding (SEC_FS_ENFORCE_CHANNEL_BINDING, on by default in
		// modern HTCondor): a server-supplied name ending in '_' is an
		// invitation to append our own view of the server's ip:port and
		// report it back, binding the marker to this specific connection even
		// under NAT / TCP_FORWARDING_HOST. Mirrors condor_auth_fs.cpp, except
		// that we never append the "?sock=ID" an HTCondor 25.14+ client adds
		// when it dialed through a shared port: 25.14+ servers accept a bare
		// ip:port, while older servers (and cedar before it) reject the suffix.
		createPath := dirPath
		if strings.HasSuffix(dirPath, "_") {
			ext, extErr := fsChannelBindingExt(peerAddr)
			if extErr != nil {
				// Can't determine our view of the peer, so we can't honor the
				// binding request. Leave createPath ending in '_' -- validation
				// below rejects it and we report failure rather than creating a
				// marker the server won't be able to find.
				slog.Warn(fmt.Sprintf("FS: cannot compute channel binding for %q: %v", dirPath, extErr), "destination", "cedar")
			} else {
				boundExt = ext
				createPath = dirPath + ext
			}
		}

		var leaf string
		var err error
		if boundExt != "" {
			leaf, err = validateFSChannelBoundPath(dirPath, boundExt, base, remote)
		} else {
			leaf, err = validateFSAuthPath(createPath, base, remote, peerAddr)
		}
		if err != nil {
			// Refuse to mkdir at the server's request. We still send
			// the failure code through the wire so the server gets a
			// clean negative response rather than a hang; the actual
			// validation error is logged so the operator can tell
			// "server paid an attempted attack" apart from "FS auth
			// just didn't work".
			slog.Warn(fmt.Sprintf("FS: rejected server-supplied path %q: %v", dirPath, err), "destination", "cedar")
		} else {
			// Open an os.Root scoped to the FS-auth base dir, then
			// mkdir the validated leaf inside it. os.Root enforces no
			// escape via .., absolute paths, or symlinks at the
			// kernel level — even if validateFSAuthPath had a logic
			// bug, this would block the actual directory creation.
			r, openErr := os.OpenRoot(base)
			if openErr != nil {
				slog.Warn(fmt.Sprintf("FS: open root %s: %v", base, openErr), "destination", "cedar")
			} else {
				// Mode 0700 — same as the original; other users must
				// not be able to access this dir between mkdir and
				// the server's stat-based ownership check.
				if mkErr := a.mkdirFSMarker(r, leaf); mkErr == nil {
					clientResult = 0
					leafName = leaf
					root = r
				} else {
					slog.Warn(fmt.Sprintf("FS: failed to create directory %s/%s: %v", base, leaf, mkErr), "destination", "cedar")
					_ = r.Close()
				}
			}
		}
	} else {
		// Server had an error generating the path
		slog.Warn("FS: server error - received empty directory path", "destination", "cedar")
	}

	// Send result back to server, followed by the channel-binding extension
	// we appended (if any). The server reads the extension only when the
	// message isn't already at EOM, so a client that added nothing stays
	// wire-compatible with servers that don't expect an extension.
	responseMsg := message.NewMessageForStream(a.stream)
	if err := responseMsg.PutInt(ctx, clientResult); err != nil {
		if root != nil {
			_ = root.Close()
		}
		return fmt.Errorf("failed to send client result: %w", err)
	}
	if boundExt != "" {
		if err := responseMsg.PutString(ctx, boundExt); err != nil {
			if root != nil {
				_ = root.Close()
			}
			return fmt.Errorf("failed to send channel-binding extension: %w", err)
		}
	}
	if err := responseMsg.FinishMessage(ctx); err != nil {
		if root != nil {
			_ = root.Close()
		}
		return fmt.Errorf("failed to finish message: %w", err)
	}

	// Clean up directory if we created it
	defer func() {
		if root == nil {
			return
		}
		defer func() { _ = root.Close() }()
		if clientResult == 0 && leafName != "" {
			// The server also removes this directory after it stats it, so a "does not
			// exist" here just means the server won the cleanup race -- expected, not a
			// problem. Only a different error is worth surfacing.
			if err := root.Remove(leafName); err != nil && !errors.Is(err, fs.ErrNotExist) {
				slog.Warn(fmt.Sprintf("FS: failed to remove directory %s/%s: %v", base, leafName, err), "destination", "cedar")
			}
		}
	}()

	// Receive server verification result
	verifyMsg := message.NewMessageFromStream(a.stream)
	serverResult, err := verifyMsg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive server result: %w", err)
	}

	// Verify we've received the complete message with EOM marker
	_, err = verifyMsg.GetChar(ctx)
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("protocol error: error checking for verification message completion: %w", err)
		}
		return fmt.Errorf("protocol error: expected EOM but more data available")
	}

	if serverResult != 0 {
		return fmt.Errorf("FS authentication failed: client and server uid/filesystem do not match")
	}

	return nil
}

// performFSAuthenticationServer handles server side of FS authentication
func (a *Authenticator) performFSAuthenticationServer(ctx context.Context, negotiation *SecurityNegotiation, remote bool) error {
	// Generate unique directory name
	var dirPath string
	var err error

	if remote {
		// FS_REMOTE: use FS_REMOTE_DIR from config
		dirPath, err = a.generateRemoteFSPath(negotiation.ServerConfig)
	} else {
		// FS: use FS_LOCAL_DIR from config or /tmp
		dirPath, err = a.generateLocalFSPath(negotiation.ServerConfig)
	}

	if err != nil {
		// Send empty string to indicate error
		dirPath = ""
	}

	// Send directory path to client
	msg := message.NewMessageForStream(a.stream)
	if err := msg.PutString(ctx, dirPath); err != nil {
		return fmt.Errorf("failed to send directory path: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish message: %w", err)
	}

	// If we failed to generate a path, still need to continue the protocol
	if dirPath == "" {
		// Receive client result (will be failure)
		responseMsg := message.NewMessageFromStream(a.stream)
		_, _ = responseMsg.GetInt(ctx)
		// Try to read EOM marker (ignoring errors since this is error path)
		_, _ = responseMsg.GetChar(ctx)

		// Send failure result
		verifyMsg := message.NewMessageForStream(a.stream)
		_ = verifyMsg.PutInt(ctx, -1)
		_ = verifyMsg.FinishMessage(ctx)

		return fmt.Errorf("FS authentication failed: could not generate temp directory")
	}

	// Receive client result, optionally followed by the client's
	// channel-binding extension.
	responseMsg := message.NewMessageFromStream(a.stream)
	clientResult, err := responseMsg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive client result: %w", err)
	}

	// Channel binding: when we invited it (name ends in '_'), the client may
	// append its own view of our ip:port (plus "?sock=ID" from an HTCondor 25.14+
	// client that dialed through a shared port) as a trailing string, which we must
	// concatenate onto the marker name before stat'ing it. A client that added
	// nothing (an older peer that created the literal name) leaves the message
	// at EOM here, so the read stays backward compatible.
	statPath := dirPath
	channelBinding := strings.HasSuffix(dirPath, "_")
	if channelBinding {
		atEnd, perr := responseMsg.PeekEndOfMessage(ctx)
		if perr != nil {
			return fmt.Errorf("protocol error: error checking for channel-binding extension: %w", perr)
		}
		if !atEnd {
			clientExt, cerr := responseMsg.GetStringWithMaxSize(ctx, MaxDirPathSize)
			if cerr != nil {
				return fmt.Errorf("failed to receive channel-binding extension: %w", cerr)
			}
			if verr := a.verifyServerChannelBindingExt(clientExt); verr != nil {
				// The client bound the marker to an endpoint that isn't ours:
				// refuse rather than stat an unbound name. Fail after draining
				// the message so the wire stays in sync.
				slog.Warn(fmt.Sprintf("FS: rejecting channel-binding extension %q: %v", clientExt, verr), "destination", "cedar")
				clientResult = -1
			} else {
				statPath = dirPath + clientExt
			}
		}
	}

	// Verify we've received the complete message with EOM marker
	_, err = responseMsg.GetChar(ctx)
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("protocol error: error checking for response message completion: %w", err)
		}
		return fmt.Errorf("protocol error: expected EOM but more data available")
	}

	serverResult := -1 // Assume failure

	// Verify the directory was created correctly if client succeeded
	if clientResult == 0 && dirPath != "" {
		// For remote FS, sync NFS by creating a temp file
		if remote {
			a.syncNFS(negotiation.ServerConfig)
		}

		// Stat the directory to verify ownership and permissions
		fileInfo, err := os.Lstat(statPath)
		if err == nil {
			// Verify it's a directory with correct permissions (0700)
			// and not a symlink
			stat, ok := fileInfo.Sys().(*syscall.Stat_t)
			if ok {
				mode := fileInfo.Mode()

				// Check all security requirements:
				// 1. Must be a directory
				// 2. Must not be a symlink
				// 3. Must have mode 0700 (owner only)
				// 4. Link count must be 1 or 2 (btrfs compatibility)
				if mode.IsDir() &&
					(mode&os.ModeSymlink) == 0 &&
					(mode.Perm() == 0700) &&
					(stat.Nlink == 1 || stat.Nlink == 2) {

					// Get username from UID
					u, err := user.LookupId(fmt.Sprintf("%d", stat.Uid))
					if err == nil {
						// Authentication successful
						serverResult = 0
						// The marker's owner at UID_DOMAIN (condor_auth_fs.cpp),
						// or bare when no UID domain is configured, for a map
						// file or server.FQUMapper to qualify. See
						// LocalUIDDomain on why we do not guess one.
						negotiation.User = joinFQU(fsMapOwner(u.Username, a.config), a.config.LocalUIDDomain())
					}
				}
			}
		}

		// Clean up the directory. The client also removes it, so a "does not exist"
		// here just means the client won the cleanup race -- expected, not a problem.
		if err := os.Remove(statPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn(fmt.Sprintf("FS: failed to remove directory %s: %v", statPath, err), "destination", "cedar")
		}
	}

	// Send server verification result
	verifyMsg := message.NewMessageForStream(a.stream)
	if err := verifyMsg.PutInt(ctx, serverResult); err != nil {
		return fmt.Errorf("failed to send server result: %w", err)
	}
	if err := verifyMsg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish verification message: %w", err)
	}

	if serverResult != 0 {
		return fmt.Errorf("FS authentication failed: directory verification failed")
	}

	return nil
}

// fsRootToCondorEnabled reports whether the server-side root->condor FS mapping is on.
// Nil (unset) means enabled, matching HTCondor's FS_ROOT_TO_CONDOR default of true.
func (c *SecurityConfig) fsRootToCondorEnabled() bool {
	return c.FSRootToCondor == nil || *c.FSRootToCondor
}

// fsMapOwner applies HTCondor's FS_ROOT_TO_CONDOR mapping: a marker owned by root maps to
// the configured condor service account (when the mapping is enabled and a condor account
// is configured), so a tool run as root authenticates as condor. Any other owner is
// returned unchanged.
func fsMapOwner(owner string, cfg *SecurityConfig) string {
	if owner == "root" && cfg != nil && cfg.CondorUsername != "" && cfg.fsRootToCondorEnabled() {
		return cfg.CondorUsername
	}
	return owner
}

// CondorPrivRunner runs a filesystem operation as the condor service account. cedar's
// FS-auth client uses it (via SecurityConfig.CondorPrivRunner) to create its marker
// directory owned by condor when running as a root daemon, mirroring C++
// set_condor_priv() so a tool run as root authenticates as condor. It is the FS-auth
// analogue of CredentialReader: cedar defines the hook and golang-htcondor implements it
// with its droppriv package -- cedar cannot import droppriv directly without an import
// cycle. When nil, the marker is created under the process's current identity, which is
// correct for the normal non-root case.
type CondorPrivRunner interface {
	// RunAsCondor runs fn (an FS-auth marker mkdir) with the effective identity of the
	// condor service account, restoring the prior identity afterward.
	RunAsCondor(fn func() error) error
}

// mkdirFSMarker creates the FS-auth marker directory. When a CondorPrivRunner is
// configured (a root daemon), the mkdir runs as the condor service account so the marker
// is owned by condor -- mirroring C++ set_condor_priv() so a root tool authenticates as
// condor. Without one, it is created under the process's current identity (the normal
// non-root case). The os.Root scoping applies inside the runner too, so the no-escape
// guarantee holds regardless of identity.
func (a *Authenticator) mkdirFSMarker(root *os.Root, leaf string) error {
	mkdir := func() error { return root.Mkdir(leaf, 0700) }
	if a.config != nil && a.config.CondorPrivRunner != nil {
		return a.config.CondorPrivRunner.RunAsCondor(mkdir)
	}
	return mkdir()
}

// validateFSAuthPath checks that a server-supplied FS-auth directory
// path is something the client should be willing to mkdir. Returns
// the validated leaf name (the directory's basename) on success, or
// an error describing why the path was rejected.
//
// Rules, all of which must hold:
//
//  1. Non-empty.
//
//  2. Absolute path. (Relative paths could be interpreted against the
//     client's CWD, which is attacker-controlled territory once
//     `condor_history` or similar is run from a writable directory.)
//
//  3. filepath.Clean(path) == path — no embedded "..", no doubled
//     slashes, no trailing slash. This rules out the simplest
//     traversal attacks before they reach the os.Root layer.
//
//  4. The parent directory equals fsAuthBaseDir exactly. We don't
//     allow nested subdirs of the base; the server's MkdirTemp emits
//     a flat path, and accepting nesting would let a server pick a
//     leaf that collides with attacker-controlled state in some
//     subdirectory.
//
//  5. The leaf matches the exact name shape the server's
//     os.MkdirTemp call produces:
//
//     - FS: fsAuthLocalLeafRE → ^FS_[0-9]{1,10}$
//     - FS_REMOTE: fsAuthRemoteLeafRE
//     → ^FS_REMOTE_<host>_<pid>_<rand>$
//
//     The earlier version of this check just required the leaf to
//     *start with* "FS_" / "FS_REMOTE_". That left wiggle room: a
//     malicious server could pick "FS_../../etc" — we'd already
//     reject that on the canonical-form rule, but the prefix-only
//     check is loose enough that other wedge cases ("FS_anything-I-want")
//     would slip through if any of the earlier rules were
//     accidentally relaxed. Pinning to the actual MkdirTemp output
//     shape eliminates that wedge entirely.
//
// The returned leaf is safe to pass to (*os.Root).Mkdir on a Root
// rooted at fsAuthBaseDir.
func validateFSAuthPath(dirPath, expectedBase string, remote bool, peerAddr net.Addr) (string, error) {
	if dirPath == "" {
		return "", fmt.Errorf("empty path")
	}
	if !filepath.IsAbs(dirPath) {
		return "", fmt.Errorf("not an absolute path: %q", dirPath)
	}
	if filepath.Clean(dirPath) != dirPath {
		return "", fmt.Errorf("path %q is not in canonical form (Clean)", dirPath)
	}
	parent := filepath.Dir(dirPath)
	if parent != expectedBase {
		return "", fmt.Errorf("parent %q is not the expected base directory %q", parent, expectedBase)
	}
	leaf := filepath.Base(dirPath)

	// Belt-and-suspenders: leaf shouldn't contain a slash, NUL, or be a dot component.
	// filepath.Base + filepath.Clean already guarantee this; the explicit check pins the
	// invariant against future refactors that loosen the matching below.
	if strings.ContainsAny(leaf, "/\x00") || leaf == "." || leaf == ".." {
		return "", fmt.Errorf("leaf %q contains an unsafe component", leaf)
	}

	// Address-qualified form some HTCondor peers use: FS[_REMOTE]_<ip>_<port>_<rand>,
	// where <ip>:<port> is the peer's own endpoint. When a name is in this form, require
	// it to be consistent with the endpoint this connection is actually talking to; a
	// name that parses as address-qualified but names a different endpoint is rejected
	// rather than falling through to the looser historical match.
	if ip, port, ok := fsAddrLeaf(leaf, remote); ok {
		if err := verifyFSPathEndpoint(ip, port, peerAddr); err != nil {
			return "", err
		}
		return leaf, nil
	}

	// Historical forms (FS_REMOTE_<hostname>_<pid>_<rand> or local FS_<rand>), accepted
	// for compatibility with peers that use them.
	if !fsHistoricalLeafOK(leaf, remote) {
		return "", fmt.Errorf("leaf %q does not match any accepted FS-auth directory-name pattern", leaf)
	}
	return leaf, nil
}

// fsHistoricalLeafOK reports whether leaf matches the historical (non
// address-qualified) FS-auth directory-name shape: local FS_<rand> or
// remote FS_REMOTE_<hostname>_<pid>_<rand>.
func fsHistoricalLeafOK(leaf string, remote bool) bool {
	leafRE := fsAuthLocalLeafRE
	if remote {
		leafRE = fsAuthRemoteLeafRE
	}
	return leafRE.MatchString(leaf)
}

// fsChannelBindingExt returns this connection's view of the peer's ip:port in
// HTCondor's to_ip_and_port_string() form (IPv4 "a.b.c.d:port", IPv6
// "[x::y]:port"), for appending to a channel-binding FS-auth directory name.
// It errors when no addressable peer is available (e.g. a non-TCP transport),
// so the caller can decline the binding rather than fabricate one.
func fsChannelBindingExt(peerAddr net.Addr) (string, error) {
	if peerAddr == nil {
		return "", fmt.Errorf("no connection peer address available")
	}
	host, port, err := net.SplitHostPort(peerAddr.String())
	if err != nil {
		return "", fmt.Errorf("cannot parse peer address %q: %w", peerAddr.String(), err)
	}
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf("peer address host %q is not an IP", host)
	}
	return net.JoinHostPort(host, port), nil
}

// fsSharedPortSuffix separates the ip:port of a channel-binding extension from
// the shared-port id an HTCondor 25.14+ client appends when it dialed through a
// shared port (HTCONDOR-3883): "ip:port?sock=ID".
const fsSharedPortSuffix = "?sock="

// verifyServerChannelBindingExt checks a client-supplied channel-binding
// extension on the server side: it must be an ip:port (no path separators)
// naming this server's own endpoint -- the client's view of where it connected
// must match our local address -- optionally followed by "?sock=ID", the
// shared-port id the client dialed. This is what makes the marker name binding
// meaningful: an attacker relaying the auth to a different endpoint can't
// reproduce our address. Mirrors condor_auth_fs.cpp's client_ext checks
// (basename guard, from_ip_and_port_string, client_peer == my_addr, and the
// shared-port id against our own when we know it; see SecurityConfig.SharedPortID).
//
// cedar has no TCP_FORWARDING_HOST/sinful machinery, so a cedar server that sits
// behind NAT (its local address differs from the client's view of it) cannot
// verify the binding and will reject; the common case -- direct connection or a
// NAT'd client reaching a publicly-addressed server -- verifies cleanly.
func (a *Authenticator) verifyServerChannelBindingExt(ext string) error {
	if strings.ContainsAny(ext, "/\x00") {
		return fmt.Errorf("extension contains a path separator")
	}
	hostPort, sockID, hasSock := strings.Cut(ext, fsSharedPortSuffix)
	if hasSock {
		if !addresses.IsValidSharedPortID(sockID) {
			return fmt.Errorf("extension %q carries an invalid shared-port id", ext)
		}
		if a.config != nil && a.config.SharedPortID != "" && sockID != a.config.SharedPortID {
			return fmt.Errorf("extension shared-port id %q does not match ours %q", sockID, a.config.SharedPortID)
		}
	}
	eh, ep, err := net.SplitHostPort(hostPort)
	if err != nil {
		return fmt.Errorf("extension %q is not a valid ip:port: %w", ext, err)
	}
	eip := net.ParseIP(eh)
	if eip == nil {
		return fmt.Errorf("extension host %q is not an IP", eh)
	}
	lip, lport, ok := a.fsLocalEndpoint()
	if !ok {
		return fmt.Errorf("cannot determine local endpoint to verify channel binding")
	}
	if ep != lport || !eip.Equal(net.ParseIP(lip)) {
		return fmt.Errorf("extension %s does not match our endpoint %s:%s", ext, lip, lport)
	}
	return nil
}

// validateFSChannelBoundPath validates a channel-binding FS-auth directory: the
// server-supplied base (which ended in '_') with our channel-binding extension
// ext appended, and returns the single leaf component to create.
//
// Unlike validateFSAuthPath's address-qualified branch, the ip:port embedded in
// the base is deliberately NOT checked against the peer: under channel binding
// the base carries the server's own view of its address, which may legitimately
// differ from ours under NAT / TCP_FORWARDING_HOST -- that divergence is exactly
// why the server asked us to bind. It is our appended ext -- our own view of the
// live connection -- that is authoritative. Safety still holds: the result stays
// a single component under fsAuthBaseDir (checked here and again by os.Root), and
// ext is a value we computed ourselves, not one the server supplied.
func validateFSChannelBoundPath(path, ext, expectedBase string, remote bool) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("not an absolute path: %q", path)
	}
	if !strings.HasSuffix(path, "_") {
		return "", fmt.Errorf("channel-binding path %q does not end in '_'", path)
	}
	// Recover the core name (drop the trailing '_') and check it is a well
	// formed FS-auth name under the base directory. The core may be either the
	// address-qualified form or a historical one; we accept either shape but do
	// not verify its embedded endpoint (see the doc comment).
	core := strings.TrimSuffix(path, "_")
	if filepath.Clean(core) != core {
		return "", fmt.Errorf("path %q is not in canonical form (Clean)", path)
	}
	if parent := filepath.Dir(core); parent != expectedBase {
		return "", fmt.Errorf("parent %q is not the expected base directory %q", parent, expectedBase)
	}
	coreLeaf := filepath.Base(core)
	if _, _, ok := fsAddrLeaf(coreLeaf, remote); !ok && !fsHistoricalLeafOK(coreLeaf, remote) {
		return "", fmt.Errorf("leaf %q does not match any accepted FS-auth directory-name pattern", coreLeaf)
	}
	// Defense in depth: ext must be a bare ip:port (no path separators). We
	// produced it in fsChannelBindingExt, but re-check before it becomes part
	// of a filesystem name.
	if h, _, err := net.SplitHostPort(ext); err != nil || net.ParseIP(h) == nil {
		return "", fmt.Errorf("channel-binding extension %q is not a valid ip:port", ext)
	}
	leaf := filepath.Base(path) + ext
	if strings.ContainsAny(leaf, "/\x00") || leaf == "." || leaf == ".." {
		return "", fmt.Errorf("leaf %q contains an unsafe component", leaf)
	}
	return leaf, nil
}

// fsSuffixRE matches the random suffix of an FS-auth directory name (a short
// alphanumeric mkstemp field). 16 gives headroom over the templates in use.
var fsSuffixRE = regexp.MustCompile(`^[A-Za-z0-9]{1,16}$`)

// fsAddrLeaf reports whether leaf is the address-qualified form
// FS[_REMOTE]_<ip>_<port>_<suffix> and, if so, returns the embedded ip and port. It is
// distinguished from the historical FS_REMOTE_<hostname>_<pid>_<suffix> by the first
// field parsing as an IP address -- a hostname never does -- so the two never collide.
func fsAddrLeaf(leaf string, remote bool) (ip, port string, ok bool) {
	prefix := "FS_"
	if remote {
		prefix = "FS_REMOTE_"
	}
	rest, hit := strings.CutPrefix(leaf, prefix)
	if !hit {
		return "", "", false
	}
	// A local FS_ name must not actually be the FS_REMOTE_ form.
	if !remote && strings.HasPrefix(rest, "REMOTE_") {
		return "", "", false
	}
	// Exactly <ip>_<port>_<suffix>. The ip (IPv4 dotted-quad or IPv6) contains dots or
	// colons, never '_', so it stays a single field under this split.
	fields := strings.Split(rest, "_")
	if len(fields) != 3 {
		return "", "", false
	}
	if net.ParseIP(fields[0]) == nil || !fsSuffixRE.MatchString(fields[2]) {
		return "", "", false
	}
	if n := len(fields[1]); n < 1 || n > 5 {
		return "", "", false
	}
	for _, c := range fields[1] {
		if c < '0' || c > '9' {
			return "", "", false
		}
	}
	return fields[0], fields[1], true
}

// verifyFSPathEndpoint checks that the ip:port embedded in an address-qualified FS-auth
// path names the endpoint this connection is talking to (peerAddr). Returns an error if
// the address is unavailable, so an address-qualified name is never accepted without the
// consistency check.
func verifyFSPathEndpoint(nameIP, namePort string, peerAddr net.Addr) error {
	if peerAddr == nil {
		return fmt.Errorf("cannot check FS path against connection: no connection address available")
	}
	ph, pp, err := net.SplitHostPort(peerAddr.String())
	if err != nil {
		return fmt.Errorf("cannot parse connection peer address %q: %w", peerAddr.String(), err)
	}
	if namePort != pp {
		return fmt.Errorf("FS path %s:%s is inconsistent with the connection endpoint (%s:%s)", nameIP, namePort, ph, pp)
	}
	ni, pi := net.ParseIP(nameIP), net.ParseIP(ph)
	if ni == nil || pi == nil || !ni.Equal(pi) {
		return fmt.Errorf("FS path %s:%s is inconsistent with the connection endpoint (%s:%s)", nameIP, namePort, ph, pp)
	}
	return nil
}

// fsLocalEndpoint returns the ip and port of this connection's local address -- the
// address the peer dialed -- for qualifying an FS-auth path name. ok is false when there
// is no addressable connection (e.g. a non-TCP transport), in which case the caller falls
// back to the historical hostname/pid name.
func (a *Authenticator) fsLocalEndpoint() (ip, port string, ok bool) {
	if a.stream == nil {
		return "", "", false
	}
	c := a.stream.GetConnection()
	if c == nil || c.LocalAddr() == nil {
		return "", "", false
	}
	h, p, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil || net.ParseIP(h) == nil {
		return "", "", false
	}
	return h, p, true
}

// generateLocalFSPath generates a unique temporary directory path for local FS auth.
// When the connection's local address is known it qualifies the name with that address
// (FS_<ip>_<port>_<rand>); otherwise it falls back to the historical FS_<rand>.
// fsAuthBase returns the base directory the FS (or FS_REMOTE, when remote) handshake
// uses, from this authenticator's OWN config: FS_LOCAL_DIR / FS_REMOTE_DIR when set,
// else the on-the-wire default fsAuthBaseDir ("/tmp"). The client validates a
// server-supplied path against this, and the server roots its temp directory here.
func (a *Authenticator) fsAuthBase(remote bool) string {
	if a.config != nil {
		if remote {
			if a.config.FSRemoteDir != "" {
				return a.config.FSRemoteDir
			}
		} else if a.config.FSLocalDir != "" {
			return a.config.FSLocalDir
		}
	}
	return fsAuthBaseDir
}

func (a *Authenticator) generateLocalFSPath(config *SecurityConfig) (string, error) {
	baseDir := fsAuthBaseDir
	if config != nil && config.FSLocalDir != "" {
		baseDir = config.FSLocalDir
	}
	pattern := "FS_*"
	addrQualified := false
	if ip, port, ok := a.fsLocalEndpoint(); ok {
		pattern = fmt.Sprintf("FS_%s_%s_*", ip, port)
		addrQualified = true
	}

	// os.MkdirTemp creates the directory; we remove it and let the client create it.
	tempDir, err := os.MkdirTemp(baseDir, pattern)
	if err != nil {
		return "", fmt.Errorf("failed to generate temp directory path: %w", err)
	}
	if err := os.Remove(tempDir); err != nil {
		return "", fmt.Errorf("failed to remove temp directory: %w", err)
	}
	// Channel binding: an address-qualified name ends in '_' to invite the client
	// to append its own view of our ip:port (see performFSAuthenticationServer and
	// condor_auth_fs.cpp). The historical, non-address-qualified name never opts in.
	if addrQualified {
		tempDir += "_"
	}
	return tempDir, nil
}

// generateRemoteFSPath generates a unique temporary directory path for remote FS auth
func (a *Authenticator) generateRemoteFSPath(config *SecurityConfig) (string, error) {
	// FS_REMOTE_DIR from config, else the on-the-wire default /tmp.
	baseDir := fsAuthBaseDir
	if config != nil && config.FSRemoteDir != "" {
		baseDir = config.FSRemoteDir
	}

	// Address-qualified name FS_REMOTE_<ip>_<port>_<rand> when the local address is
	// known; else fall back to the historical FS_REMOTE_<hostname>_<pid>_<rand>.
	var pattern string
	addrQualified := false
	if ip, port, ok := a.fsLocalEndpoint(); ok {
		pattern = fmt.Sprintf("FS_REMOTE_%s_%s_*", ip, port)
		addrQualified = true
	} else {
		hostname, herr := os.Hostname()
		if herr != nil {
			hostname = "unknown"
		}
		pattern = fmt.Sprintf("FS_REMOTE_%s_%d_*", hostname, os.Getpid())
	}

	// Create unique temp directory
	tempDir, err := os.MkdirTemp(baseDir, pattern)
	if err != nil {
		return "", fmt.Errorf("failed to generate temp directory path: %w", err)
	}

	// Remove the directory - client needs to create it
	if err := os.Remove(tempDir); err != nil {
		return "", fmt.Errorf("failed to remove temp directory: %w", err)
	}

	// Channel binding: an address-qualified name ends in '_' to invite the
	// client to append its view of our ip:port (see condor_auth_fs.cpp).
	if addrQualified {
		tempDir += "_"
	}

	return tempDir, nil
}

// syncNFS attempts to sync NFS by creating and deleting a temp file
// This forces NFS client to sync with server before checking for client's directory
func (a *Authenticator) syncNFS(config *SecurityConfig) {
	baseDir := "/tmp"
	hostname, _ := os.Hostname()
	pid := os.Getpid()

	pattern := fmt.Sprintf("FS_REMOTE_%s_%d_sync_*", hostname, pid)

	// Create temp file to force NFS sync
	tempFile, err := os.CreateTemp(baseDir, pattern)
	if err == nil {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
	}
}

// performClaimToBeAuthentication performs CLAIMTOBE authentication
// Implements the CAUTH_CLAIMTOBE protocol from condor_auth_claim.cpp
func (a *Authenticator) performClaimToBeAuthentication(ctx context.Context, negotiation *SecurityNegotiation) error {
	if negotiation.IsClient {
		return a.performClaimToBeAuthenticationClient(ctx, negotiation)
	}
	return a.performClaimToBeAuthenticationServer(ctx, negotiation)
}

// performClaimToBeAuthenticationClient handles client side of CLAIMTOBE authentication
func (a *Authenticator) performClaimToBeAuthenticationClient(ctx context.Context, negotiation *SecurityNegotiation) error {
	// Get username - prefer configured user, otherwise use current user
	username, err := a.getClaimUsername(negotiation.ClientConfig)
	if err != nil {
		// Send error indicator (0) followed by end of message
		msg := message.NewMessageForStream(a.stream)
		_ = msg.PutInt(ctx, 0)
		_ = msg.FinishMessage(ctx)
		return fmt.Errorf("failed to get username: %w", err)
	}

	// Check if we should include domain
	includeDomain := true // Default to true like HTCondor
	// Could support SEC_CLAIMTOBE_INCLUDE_DOMAIN config here
	// if config.ClaimToBeIncludeDomain != nil {
	//     includeDomain = *config.ClaimToBeIncludeDomain
	// }

	// Append domain if configured. joinFQU, not concatenation: with no UID
	// domain configured there is nothing to append, and "bob@" is not a name.
	if includeDomain {
		username = joinFQU(username, negotiation.ClientConfig.LocalUIDDomain())
	}

	// Send success indicator (1) followed by username
	msg := message.NewMessageForStream(a.stream)
	if err := msg.PutInt(ctx, 1); err != nil {
		return fmt.Errorf("failed to send success indicator: %w", err)
	}
	if err := msg.PutString(ctx, username); err != nil {
		return fmt.Errorf("failed to send username: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish message: %w", err)
	}

	// Receive server acknowledgment
	responseMsg := message.NewMessageFromStream(a.stream)
	result, err := responseMsg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive server acknowledgment: %w", err)
	}

	// Verify we've received the complete message with EOM marker
	_, err = responseMsg.GetChar(ctx)
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("protocol error: error checking for acknowledgment completion: %w", err)
		}
		return fmt.Errorf("protocol error: expected EOM but more data available")
	}

	if result != 1 {
		return fmt.Errorf("CLAIMTOBE authentication failed: server rejected claim")
	}

	return nil
}

// performClaimToBeAuthenticationServer handles server side of CLAIMTOBE authentication
func (a *Authenticator) performClaimToBeAuthenticationServer(ctx context.Context, negotiation *SecurityNegotiation) error {
	// Receive client status indicator
	msg := message.NewMessageFromStream(a.stream)
	status, err := msg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive client status: %w", err)
	}

	if status != 1 {
		// Client had an error
		// Verify we've received the complete message with EOM marker
		_, err := msg.GetChar(ctx)
		if err != io.EOF {
			if err != nil {
				return fmt.Errorf("protocol error: error checking for message completion: %w", err)
			}
			return fmt.Errorf("protocol error: expected EOM but more data available")
		}
		return fmt.Errorf("CLAIMTOBE authentication failed: client error")
	}

	// Receive username with size limit to prevent DoS
	username, err := msg.GetStringWithMaxSize(ctx, MaxUsernameSize)
	if err != nil {
		return fmt.Errorf("failed to receive username: %w", err)
	}

	// Verify we've received the complete message with EOM marker
	_, err = msg.GetChar(ctx)
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("protocol error: error checking for message completion: %w", err)
		}
		return fmt.Errorf("protocol error: expected EOM but more data available")
	}

	// Check if domain is included
	includeDomain := true // Default to true
	// Could support SEC_CLAIMTOBE_INCLUDE_DOMAIN config here

	if includeDomain {
		// The claimed user@domain, split at the last '@'; a name without a
		// domain takes ours (condor_auth_claim.cpp).
		user, domain := SplitFQU(username)
		if domain == "" {
			domain = a.config.LocalUIDDomain()
		}
		negotiation.User = joinFQU(user, domain)
	} else {
		negotiation.User = username
	}

	// Send success acknowledgment
	responseMsg := message.NewMessageForStream(a.stream)
	if err := responseMsg.PutInt(ctx, 1); err != nil {
		return fmt.Errorf("failed to send acknowledgment: %w", err)
	}
	if err := responseMsg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish acknowledgment: %w", err)
	}

	return nil
}

// getClaimUsername gets the username to claim for authentication
func (a *Authenticator) getClaimUsername(config *SecurityConfig) (string, error) {
	// Could support SEC_CLAIMTOBE_USER config to override username
	// if config.ClaimToBeUser != "" {
	//     return config.ClaimToBeUser, nil
	// }

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %w", err)
	}

	return currentUser.Username, nil
}
