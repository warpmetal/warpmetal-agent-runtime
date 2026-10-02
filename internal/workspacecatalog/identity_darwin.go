//go:build darwin

package workspacecatalog

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func identityForFile(file *os.File) (fileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return fileIdentity{}, err
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &filesystem); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, Mount: fmt.Sprintf("%d:%d", filesystem.Fsid.Val[0], filesystem.Fsid.Val[1])}, nil
}

// imageIdentity observes the durable host-filesystem identity of the workspace
// image file at path without following a final symlink: the file must be the
// exact regular file object, never a link to another object. The modification
// time is recorded as observation provenance only, never as identity: mounted
// filesystem writes legitimately move it while the object stays unchanged.
func imageIdentity(path string) (state.ManagedProjectImageIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return state.ManagedProjectImageIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return state.ManagedProjectImageIdentity{}, fmt.Errorf("workspace image %s is not a regular file", path)
	}
	return state.ManagedProjectImageIdentity{
		Device: uint64(stat.Dev), Inode: stat.Ino, Size: stat.Size,
		ModifiedUnixNano: stat.Mtim.Sec*1_000_000_000 + stat.Mtim.Nsec,
	}, nil
}
