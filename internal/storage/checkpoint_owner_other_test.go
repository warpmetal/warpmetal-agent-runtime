//go:build !linux

package storage

import (
	"path/filepath"
	"testing"
)

func mappedMaterializationDestination(_ *testing.T, base string) string {
	return filepath.Join(base, "restore-leaf")
}

func prepareMappedCaptureSource(*testing.T, string) func() { return func() {} }

func mappedMaterializationAuthority(*testing.T, string) *MaterializationOwnership { return nil }

func runMappedMaterializationProbeChild(*testing.T) bool { return false }

func assertMappedMaterializationOwner(*testing.T, string) {}
