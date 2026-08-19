package capacity

import (
	"reflect"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func TestAllocatableKeepsHostHeadroomWithoutRejectingPurchasedCapacity(t *testing.T) {
	got := allocatable(4, 7941, 76)
	want := model.Resources{
		CPUMillicores:    3500,
		MemoryMiB:        7429,
		WorkspaceDiskGiB: 71,
		PIDs:             32768,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allocatable() = %#v, want %#v", got, want)
	}
	purchased := model.Resources{
		CPUMillicores:    3500,
		MemoryMiB:        7168,
		WorkspaceDiskGiB: 70,
	}
	if !purchased.Fits(got) {
		t.Fatalf("valid purchased capacity %#v does not fit detected capacity %#v", purchased, got)
	}
}

func TestAllocatableDoesNotGoNegative(t *testing.T) {
	got := allocatable(0, 256, 2)
	if got.CPUMillicores != 0 || got.MemoryMiB != 0 || got.WorkspaceDiskGiB != 0 {
		t.Fatalf("allocatable() returned negative host resources: %#v", got)
	}
}
