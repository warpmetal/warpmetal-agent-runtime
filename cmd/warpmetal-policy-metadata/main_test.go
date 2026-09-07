//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCompareDetectsContentModeTimestampAndXattrDrift(t *testing.T) {
	dir := t.TempDir()
	left := filepath.Join(dir, "left")
	right := filepath.Join(dir, "right")
	for _, path := range []string{left, right} {
		if err := os.WriteFile(path, []byte("policy"), 0o640); err != nil {
			t.Fatal(err)
		}
		stamp := time.Unix(1_700_000_000, 123456789)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if err := unix.Setxattr(path, "user.warpmetal_test", []byte("value"), 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := run([]string{"compare", left, right}); err != nil {
		t.Fatal(err)
	}

	mutations := []func() error{
		func() error { return os.WriteFile(right, []byte("changed"), 0o640) },
		func() error { return os.Chmod(right, 0o600) },
		func() error { return os.Chtimes(right, time.Unix(1_700_000_001, 0), time.Unix(1_700_000_001, 0)) },
		func() error { return unix.Setxattr(right, "user.warpmetal_test", []byte("changed"), 0) },
	}
	for index, mutate := range mutations {
		leftMetadata, err := readMetadata(left)
		if err != nil {
			t.Fatal(err)
		}
		if err := mutate(); err != nil {
			t.Fatal(err)
		}
		rightMetadata, err := readMetadata(right)
		if err != nil {
			t.Fatal(err)
		}
		if equalMetadata(leftMetadata, rightMetadata) {
			t.Fatalf("mutation %d was not detected", index)
		}
		if err := os.Remove(right); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(right, []byte("policy"), 0o640); err != nil {
			t.Fatal(err)
		}
		stamp := time.Unix(1_700_000_000, 123456789)
		if err := os.Chtimes(right, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if err := unix.Setxattr(right, "user.warpmetal_test", []byte("value"), 0); err != nil {
			t.Fatal(err)
		}
	}
}
