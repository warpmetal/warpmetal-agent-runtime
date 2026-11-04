package qualification

import (
	"context"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const InstalledScriptContainerRoot = "/usr/local/libexec/warpmetal-agent-cells"
const InstalledScriptManifestName = "warpmetal_installed_scripts.json"

type InstalledScriptManifest struct {
	FormatVersion      int    `json:"formatVersion"`
	RegisteredSourceID string `json:"registeredSourceId"`
	ContainerRoot      string `json:"containerRoot"`
	ScriptPath         string `json:"scriptPath"`
	ScriptSHA256       string `json:"scriptSHA256"`
	ScriptByteCount    int    `json:"scriptByteCount"`
}

// Read the image installation owner's ONE fixed registry manifest. HostImageRoot
// is supplied only by the normal authenticated Podman image mapping, never a
// policy/root selector. Script bytes remain unopened until their operation fence.
func MeasureInstalledScriptImageRoot(ctx context.Context, hostImageRoot string, mappedUID uint32) (InstalledScriptRootRegistration, error) {
	var empty InstalledScriptRootRegistration
	if ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	st, err := os.Lstat(hostImageRoot)
	if err != nil || !st.IsDir() {
		return empty, ErrUntrusted
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return empty, ErrUntrusted
	}
	image, err := confinedRoot(hostImageRoot, uint64(stat.Dev), stat.Ino)
	if err != nil {
		return empty, err
	}
	defer image.Close()
	fd, err := unix.Dup(int(image.Fd()))
	if err != nil {
		return empty, err
	}
	for _, part := range []string{"usr", "local", "libexec", "warpmetal-agent-cells"} {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return empty, ErrUntrusted
		}
		fd = next
	}
	root := os.NewFile(uintptr(fd), InstalledScriptContainerRoot)
	defer root.Close()
	var identity unix.Stat_t
	if unix.Fstat(fd, &identity) != nil || identity.Uid != mappedUID || identity.Mode&0022 != 0 {
		return empty, ErrUntrusted
	}
	fileFD, err := unix.Openat(fd, InstalledScriptManifestName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, ErrUntrusted
	}
	file := os.NewFile(uintptr(fileFD), InstalledScriptManifestName)
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fileFD, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != mappedUID || before.Mode&0222 != 0 || before.Size < 1 || before.Size > 262144 {
		return empty, ErrUntrusted
	}
	first, err := file.Stat()
	if err != nil {
		return empty, ErrUntrusted
	}
	raw, err := io.ReadAll(io.LimitReader(file, 262145))
	last, statErr := file.Stat()
	if err != nil || statErr != nil || int64(len(raw)) != before.Size || unix.Fstat(fileFD, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Size != after.Size || !first.ModTime().Equal(last.ModTime()) || planChangeTime(first.Sys().(*syscall.Stat_t)) != planChangeTime(last.Sys().(*syscall.Stat_t)) || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	var manifest InstalledScriptManifest
	if decode(raw, &manifest) != nil || manifest.FormatVersion != 1 || !safeID.MatchString(manifest.RegisteredSourceID) || manifest.ContainerRoot != InstalledScriptContainerRoot ||
		manifest.ScriptPath != "warpmetal_sv09_record_totals.py" || !rawHash.MatchString(manifest.ScriptSHA256) || manifest.ScriptByteCount < 1 || manifest.ScriptByteCount > 16384 {
		return empty, ErrUntrusted
	}
	return InstalledScriptRootRegistration{FormatVersion: 1, RegisteredSourceID: manifest.RegisteredSourceID, InstalledManifest: raw,
		Workspace: TrustedWorkspace{HostRoot: filepath.Join(hostImageRoot, InstalledScriptContainerRoot), ContainerRoot: manifest.ContainerRoot, WorkspaceDigest: Digest(raw), Device: uint64(identity.Dev), Inode: identity.Ino}}, nil
}
