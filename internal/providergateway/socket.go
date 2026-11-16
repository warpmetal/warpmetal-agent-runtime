package providergateway

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// socketPermissions is the only mode a live gateway socket may have. The
	// socket is root-only because the sandbox agent's socat runs as the same
	// Runtime/agent identity that owns the workspace.
	socketPermissions = 0o600
	// socketDirectoryPermissions is how a missing socket directory is created,
	// and the maximum access an existing one may grant.
	socketDirectoryPermissions = 0o700
	// staleSocketProbeTimeout bounds the dial used to distinguish a live socket
	// from a stale file left behind by a crashed gateway.
	staleSocketProbeTimeout = 250 * time.Millisecond
)

// prepareSocket turns the configured path into a listening Unix socket:
//
//   - the socket directory is created 0700 when missing, and an existing one
//     must already be owner-only and not a symlink;
//   - when RootDir is set, the directory must resolve inside it (no symlink
//     escape) and the root must already exist;
//   - an existing non-socket path is never overwritten;
//   - an existing socket that still accepts connections is refused (a second
//     gateway must not hijack a live one), while a stale socket file left by a
//     crashed process is replaced;
//   - the created socket is chmodded to 0600 and its identity captured so close
//     can remove it only while it is still ours.
func prepareSocket(socketPath, rootDir string) (*net.UnixListener, string, os.FileInfo, error) {
	directory := filepath.Dir(socketPath)
	var resolvedRoot string
	if rootDir != "" {
		rootInfo, err := os.Stat(rootDir)
		if err != nil {
			return nil, "", nil, fmt.Errorf("providergateway: allowed root %q: %w", rootDir, err)
		}
		if !rootInfo.IsDir() {
			return nil, "", nil, fmt.Errorf("providergateway: allowed root %q is not a directory", rootDir)
		}
		resolvedRoot, err = filepath.EvalSymlinks(rootDir)
		if err != nil {
			return nil, "", nil, fmt.Errorf("providergateway: resolve allowed root %q: %w", rootDir, err)
		}
		if err := refusePathEscape(directory, rootDir, resolvedRoot); err != nil {
			return nil, "", nil, err
		}
	}
	if err := ensureSocketDirectory(directory); err != nil {
		return nil, "", nil, fmt.Errorf("providergateway: %w", err)
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, "", nil, fmt.Errorf("providergateway: resolve socket directory %q: %w", directory, err)
	}
	if rootDir != "" && !pathWithin(resolvedDirectory, resolvedRoot) {
		return nil, "", nil, fmt.Errorf(
			"providergateway: socket directory %q resolves outside the allowed root %q",
			directory, rootDir,
		)
	}
	listenPath := filepath.Join(resolvedDirectory, filepath.Base(socketPath))
	if err := replaceStaleSocket(listenPath); err != nil {
		return nil, "", nil, fmt.Errorf("providergateway: %w", err)
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: listenPath, Net: "unix"})
	if err != nil {
		return nil, "", nil, fmt.Errorf("providergateway: listen on %q: %w", listenPath, err)
	}
	// The gateway owns socket cleanup: removeSocketFile checks the inode, so a
	// replacement at the same path is never removed by us.
	listener.SetUnlinkOnClose(false)
	discard := func() {
		_ = listener.Close()
		_ = os.Remove(listenPath)
	}
	if err := os.Chmod(listenPath, socketPermissions); err != nil {
		discard()
		return nil, "", nil, fmt.Errorf("providergateway: set socket permissions: %w", err)
	}
	info, err := os.Lstat(listenPath)
	if err != nil {
		discard()
		return nil, "", nil, fmt.Errorf("providergateway: stat socket %q: %w", listenPath, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		discard()
		return nil, "", nil, fmt.Errorf("providergateway: %q is not a socket after listen", listenPath)
	}
	if info.Mode().Perm() != socketPermissions {
		discard()
		return nil, "", nil, fmt.Errorf(
			"providergateway: socket %q permissions are %04o, want %04o",
			listenPath, info.Mode().Perm(), socketPermissions,
		)
	}
	return listener, listenPath, info, nil
}

// refusePathEscape rejects a socket directory that lexically or (after
// resolving the nearest existing ancestor) actually escapes the allowed root.
// Resolving the nearest existing ancestor before creating anything means a
// symlink planted inside the root cannot make the gateway create directories
// outside it.
func refusePathEscape(directory, rootDir, resolvedRoot string) error {
	if !pathWithin(directory, rootDir) {
		return fmt.Errorf(
			"providergateway: socket directory %q is outside the allowed root %q",
			directory, rootDir,
		)
	}
	existing, err := nearestExistingAncestor(directory)
	if err != nil {
		return fmt.Errorf("providergateway: resolve socket directory %q: %w", directory, err)
	}
	resolvedExisting, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return fmt.Errorf("providergateway: resolve %q: %w", existing, err)
	}
	if !pathWithin(resolvedExisting, resolvedRoot) {
		return fmt.Errorf(
			"providergateway: socket directory %q resolves outside the allowed root %q",
			directory, rootDir,
		)
	}
	return nil
}

// nearestExistingAncestor returns path when it exists, or its closest existing
// ancestor. path must be absolute.
func nearestExistingAncestor(path string) (string, error) {
	for current := path; ; current = filepath.Dir(current) {
		_, err := os.Lstat(current)
		switch {
		case err == nil:
			return current, nil
		case errors.Is(err, fs.ErrNotExist):
			if filepath.Dir(current) == current {
				return "", fmt.Errorf("%q has no existing ancestor", path)
			}
		default:
			return "", err
		}
	}
}

// ensureSocketDirectory creates the socket directory owner-only when missing.
// An existing directory must be owner-only and must not be a symlink: a
// symlinked socket directory would put the socket somewhere the caller did not
// intend and on some systems bypasses the directory permission that protects it.
func ensureSocketDirectory(path string) error {
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("socket directory %q must not be a symlink", path)
		}
		if !info.IsDir() {
			return fmt.Errorf("socket directory %q is not a directory", path)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf(
				"socket directory %q must be owner-only (found mode %04o)",
				path, info.Mode().Perm(),
			)
		}
		return nil
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(path, socketDirectoryPermissions); err != nil {
			return fmt.Errorf("create socket directory %q: %w", path, err)
		}
		return nil
	default:
		return err
	}
}

// replaceStaleSocket refuses to touch an existing entry at the socket path
// unless it is a socket file with no live listener, in which case it is a
// leftover from a crashed gateway and may be removed.
func replaceStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect socket path %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink at socket path %q", path)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to overwrite existing non-socket path %q", path)
	}
	probe, dialErr := net.DialTimeout("unix", path, staleSocketProbeTimeout)
	if dialErr == nil {
		_ = probe.Close()
		return fmt.Errorf("socket %q is already in use by another server", path)
	}
	if removeErr := os.Remove(path); removeErr != nil {
		return fmt.Errorf("remove stale socket %q: %w", path, removeErr)
	}
	return nil
}

// removeSocketFile removes the socket at path only when it is still the exact
// inode the gateway created. If another process replaced the path after our
// listener closed, the replacement is left untouched.
func removeSocketFile(path string, info os.FileInfo) {
	if path == "" || info == nil {
		return
	}
	current, err := os.Lstat(path)
	if err != nil {
		return
	}
	if current.Mode()&os.ModeSocket == 0 {
		return
	}
	if !os.SameFile(info, current) {
		return
	}
	_ = os.Remove(path)
}

// pathWithin reports whether path is root or lives under it. Both arguments
// must be absolute; the lexical form and resolved form are each compared in
// their own call sites.
func pathWithin(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	prefix := root
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(path, prefix)
}
