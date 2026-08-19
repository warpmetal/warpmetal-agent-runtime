package capacity

import "github.com/warpmetal/warpmetal-agent-runtime/internal/model"

const (
	hostCPUReserveMillicores = 500
	hostMemoryReserveMiB     = 512
	hostDiskReserveGiB       = 5
)

func allocatable(cpuCount, memoryMiB, diskGiB int) model.Resources {
	return model.Resources{
		CPUMillicores:    max(0, cpuCount*1000-hostCPUReserveMillicores),
		MemoryMiB:        max(0, memoryMiB-hostMemoryReserveMiB),
		WorkspaceDiskGiB: max(0, diskGiB-hostDiskReserveGiB),
		PIDs:             32768,
	}
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
