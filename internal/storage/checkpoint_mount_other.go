//go:build !linux

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
	return stat, uint64(stat.Dev), nil
}
