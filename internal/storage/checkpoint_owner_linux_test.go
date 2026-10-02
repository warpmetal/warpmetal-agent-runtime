//go:build linux

package storage

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

const (
	materializationOwnerGate  = "WARPMETAL_REAL_WORKSPACE_OWNER_TEST"
	materializationOwnerChild = "WARPMETAL_MATERIALIZATION_OWNER_CHILD_ROOT"
	materializationHostUID    = 997
	materializationHostGID    = 987
)

func prepareMappedCaptureSource(t *testing.T, source string) func() {
	t.Helper()
	if os.Getenv(materializationOwnerGate) != "1" {
		return func() {}
	}
	if os.Geteuid() != 0 {
		t.Fatal("real mapped source journey requires root in a private Linux test container")
	}
	previousUmask := syscall.Umask(0027) // packaged warpmetald.service execution policy
	t.Cleanup(func() { syscall.Umask(previousUmask) })
	sentinelDirectory := t.TempDir()
	sentinel := filepath.Join(sentinelDirectory, "fsmonitor-executed")
	script := filepath.Join(sentinelDirectory, "fsmonitor")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+sentinel+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(source, ".git", "config")
	file, err := os.OpenFile(config, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(file, "\n[core]\n\tfsmonitor = %s\n", script); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected fixture symlink %s", path)
		}
		return os.Chown(path, materializationHostUID, materializationHostGID)
	}); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(source, ".git", "index")
	beforeBytes, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(index)
	if err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if _, err := os.Lstat(sentinel); !os.IsNotExist(err) {
			t.Fatalf("repository fsmonitor executed during root capture: %v", err)
		}
		afterBytes, err := os.ReadFile(index)
		if err != nil || !bytes.Equal(afterBytes, beforeBytes) {
			t.Fatalf("source Git index bytes changed during capture: %v", err)
		}
		afterInfo, err := os.Stat(index)
		if err != nil || !os.SameFile(beforeInfo, afterInfo) || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
			t.Fatalf("source Git index identity/mtime changed during capture: %v", err)
		}
	}
}

func mappedMaterializationDestination(t *testing.T, base string) string {
	t.Helper()
	if os.Getenv(materializationOwnerGate) != "1" {
		return filepath.Join(base, "restore-leaf")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real materialization owner journey requires root in a private Linux test container")
	}
	if err := os.Chmod(filepath.Dir(base), 0711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0711); err != nil {
		t.Fatal(err)
	}
	anchor := filepath.Join(base, "workspace")
	if err := os.Mkdir(anchor, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(anchor, materializationHostUID, materializationHostGID); err != nil {
		t.Fatal(err)
	}
	projects := filepath.Join(anchor, "projects")
	if err := os.Mkdir(projects, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(projects, materializationHostUID, materializationHostGID); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(projects, "restore-leaf")
}

func mappedMaterializationAuthority(t *testing.T, destination string) *MaterializationOwnership {
	t.Helper()
	if os.Getenv(materializationOwnerGate) != "1" {
		return nil
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	return &MaterializationOwnership{
		Anchor: filepath.Dir(filepath.Dir(destination)), RootDevice: uint64(stat.Dev), RootInode: stat.Ino,
	}
}

func runMappedMaterializationProbeChild(t *testing.T) bool {
	t.Helper()
	root := os.Getenv(materializationOwnerChild)
	if root == "" {
		return false
	}
	for name, want := range map[string]string{"tracked.txt": "continued work\n", "new.bin": string([]byte{0, 9, 0xff})} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != want {
			t.Fatalf("mapped owner cannot read materialized %s: %q, %v", name, got, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "worker-probe.txt"), []byte("mapped owner work\n"), 0600); err != nil {
		t.Fatalf("mapped owner cannot write materialized worktree: %v", err)
	}
	for _, args := range [][]string{{"-C", root, "status", "--short"}, {"-C", root, "add", "worker-probe.txt"}} {
		command := exec.Command("git", args...)
		command.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "LANG=C"}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("mapped owner cannot run git %v: %v\n%s", args, err, output)
		}
	}
	return true
}

func assertMappedMaterializationOwner(t *testing.T, root string) {
	t.Helper()
	if os.Getenv(materializationOwnerGate) != "1" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestMaterializeNewSeedsVerifiedBaseIntoExclusiveEmptyLeaf$", "-test.v")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: materializationHostUID, Gid: materializationHostGID}}
	command.Env = append(os.Environ(), materializationOwnerChild+"="+root)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("mapped host UID/GID cannot use real materialized project %s: %v\n%s", root, err, output)
	}
}
