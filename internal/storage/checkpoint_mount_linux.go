//go:build linux

package storage

import (
	"os"

	"golang.org/x/sys/unix"
)

func materializedIdentity(file *os.File) (unix.Stat_t, uint64, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return stat, 0, err
	}
	var statx unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &statx); err != nil {
		return stat, 0, err
	}
	return stat, statx.Mnt_id, nil
}
