//go:build linux

package workspacecatalog

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// hostLoopBackingFile names the file that backs the loop device with the given
// device number, using the kernel's own sysfs node
// /sys/dev/block/<major>:<minor>/loop/backing_file. The kernel reports the same
// path the mount was configured with (Workspaces.Ensure always passes an
// absolute image path). Any unreadable or empty node reports the backing file
// as unavailable: the host cannot name it, so callers fall back to the
// persisted image identity.
func hostLoopBackingFile(device uint64) (string, error) {
	if device == 0 {
		return "", errLoopBackingUnavailable
	}
	path := fmt.Sprintf("/sys/dev/block/%d:%d/loop/backing_file", unix.Major(device), unix.Minor(device))
	payload, err := os.ReadFile(path)
	if err != nil {
		return "", errLoopBackingUnavailable
	}
	name := strings.TrimSuffix(string(payload), "\n")
	if name == "" {
		return "", errLoopBackingUnavailable
	}
	return name, nil
}
