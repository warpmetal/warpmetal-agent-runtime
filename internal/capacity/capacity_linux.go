package capacity

import (
	"bufio"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func Detect(stateRoot string) (model.Resources, error) {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return model.Resources{}, errors.New("cgroups v2 is required")
	}
	memoryMiB, err := totalMemoryMiB()
	if err != nil {
		return model.Resources{}, err
	}
	var filesystem syscall.Statfs_t
	if err := syscall.Statfs(stateRoot, &filesystem); err != nil {
		return model.Resources{}, err
	}
	diskGiB := int((filesystem.Blocks * uint64(filesystem.Bsize)) / (1024 * 1024 * 1024))
	return model.Resources{
		CPUMillicores:    max(0, runtime.NumCPU()*1000-500),
		MemoryMiB:        max(0, memoryMiB-1024),
		WorkspaceDiskGiB: max(0, diskGiB-10),
		PIDs:             32768,
	}, nil
}

func totalMemoryMiB() (int, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			value, err := strconv.Atoi(fields[1])
			return value / 1024, err
		}
	}
	return 0, errors.New("MemTotal is unavailable")
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
