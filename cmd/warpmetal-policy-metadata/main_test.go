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
		leftMetadata, err := readPathMetadata(left)
		if err != nil {
			t.Fatal(err)
		}
		if err := mutate(); err != nil {
			t.Fatal(err)
		}
		rightMetadata, err := readPathMetadata(right)
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

func TestCopyPreservesMetadataWithoutChangingSourceAtime(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	destination := filepath.Join(dir, "destination")
	if err := os.WriteFile(source, []byte("policy bytes\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1_600_000_000, 987654321)
	if err := os.Chtimes(source, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(source, "user.warpmetal_test", []byte("preserve-me"), 0); err != nil {
		t.Fatal(err)
	}
	var before unix.Stat_t
	if err := unix.Stat(source, &before); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"copy", source, destination}); err != nil {
		t.Fatal(err)
	}
	var after unix.Stat_t
	if err := unix.Stat(source, &after); err != nil {
		t.Fatal(err)
	}
	if before.Atim != after.Atim {
		t.Fatalf("source atime changed: before=%v after=%v", before.Atim, after.Atim)
	}
	if err := run([]string{"compare", source, destination}); err != nil {
		t.Fatal(err)
	}
}

func TestCopyRejectsNonregularSymlinkAndExistingDestination(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, []byte("policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"copy", source, existing}); err == nil {
		t.Fatal("copy accepted an existing destination")
	}
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(source, symlink); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"copy", symlink, filepath.Join(dir, "from-symlink")}); err == nil {
		t.Fatal("copy accepted a symlink source")
	}
	if err := run([]string{"copy", dir, filepath.Join(dir, "from-directory")}); err == nil {
		t.Fatal("copy accepted a nonregular source")
	}
	destinationSymlink := filepath.Join(dir, "destination-symlink")
	if err := os.Symlink(existing, destinationSymlink); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"copy", source, destinationSymlink}); err == nil {
		t.Fatal("copy accepted a symlink destination")
	}
}
