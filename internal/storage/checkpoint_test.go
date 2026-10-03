package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func checkpointIdentity(epoch string) model.ContinuityIdentityV1 {
	taskID := "task_test12345"
	taskAttempt := int64(2)
	return model.ContinuityIdentityV1{
		WorkID: "work_test12345", ProjectID: "project_test12345", SandboxID: "sbx_test12345",
		WorkspaceEpoch: epoch, SandboxGeneration: 4, TaskID: &taskID,
		TaskAttempt: &taskAttempt, ExpectedRevision: 9,
	}
}

func runGit(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-c", "safe.directory=" + directory}, arguments...)...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", arguments, err, output)
	}
	return string(bytes.TrimSpace(output))
}

func writeFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
}

func fixtureRepository(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init", "--initial-branch=main")
	runGit(t, root, "config", "user.name", "Continuity Test")
	runGit(t, root, "config", "user.email", "continuity@example.invalid")
	writeFile(t, filepath.Join(root, "tracked.txt"), []byte("base\n"), 0600)
	writeFile(t, filepath.Join(root, "deleted.txt"), []byte("delete me\n"), 0600)
	runGit(t, root, "add", "tracked.txt", "deleted.txt")
	runGit(t, root, "commit", "-m", "base")
	return root
}

func manifestEntry(t *testing.T, manifest CheckpointManifestV1, path string) CheckpointEntryV1 {
	t.Helper()
	for _, entry := range manifest.Entries {
		if entry.Path == path {
			return entry
		}
	}
	t.Fatalf("manifest has no %q entry: %#v", path, manifest.Entries)
	return CheckpointEntryV1{}
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestCheckpointRoundTripPreservesWorktreeIndexAndDoesNotMutateSourceGit(t *testing.T) {
	source := fixtureRepository(t)
	writeFile(t, filepath.Join(source, "tracked.txt"), []byte("staged\n"), 0600)
	runGit(t, source, "add", "tracked.txt")
	writeFile(t, filepath.Join(source, "tracked.txt"), []byte("working\n"), 0600)
	writeFile(t, filepath.Join(source, "binary.dat"), []byte{0, 1, 2, 0xff, 0, 9}, 0600)
	writeFile(t, filepath.Join(source, "bin", "tool"), []byte("#!/bin/sh\nexit 0\n"), 0700)
	if err := os.Remove(filepath.Join(source, "deleted.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("tracked.txt", filepath.Join(source, "safe-link")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(source, ".env"), []byte("TOKEN=secret\n"), 0600)
	writeFile(t, filepath.Join(source, ".ssh", "id_test"), []byte("private\n"), 0600)
	// A private managed task worktree under .warpmetal/worktrees is not workspace
	// content: capturing it would leak task-private state into continuity
	// checkpoints, an independent task-worktree change would falsely fail
	// verification, and a restore could clobber the active task subtree. Ordinary
	// .warpmetal user files must remain captured.
	writeFile(t, filepath.Join(source, ".warpmetal", "legacy-user.txt"), []byte("legacy user file\n"), 0600)
	writeFile(t, filepath.Join(source, ".warpmetal", "worktrees", "task_fixture", "private.txt"), []byte("private task state\n"), 0600)

	headBefore := runGit(t, source, "rev-parse", "HEAD")
	indexPath := runGit(t, source, "rev-parse", "--git-path", "index")
	if !filepath.IsAbs(indexPath) {
		indexPath = filepath.Join(source, indexPath)
	}
	indexBefore, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}

	objects := CheckpointStore{Root: filepath.Join(t.TempDir(), "objects"), MaxBytes: 256 << 20, MaxFiles: 10_000}
	checkpoint, err := objects.Capture(context.Background(), CaptureRequest{
		OperationID: "continuity_op_12345", Identity: checkpointIdentity("epoch_source123"),
		WorkspaceRoot: source,
	})
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Manifest.Git.Head != headBefore || checkpoint.Manifest.Git.IndexDigest != digest(indexBefore) {
		t.Fatalf("git metadata was not captured exactly: %#v", checkpoint.Manifest.Git)
	}
	tracked := manifestEntry(t, checkpoint.Manifest, "tracked.txt")
	if tracked.Index == nil || tracked.Index.Digest != digest([]byte("staged\n")) ||
		tracked.Worktree == nil || tracked.Worktree.Digest != digest([]byte("working\n")) {
		t.Fatalf("staged/unstaged distinction was lost: %#v", tracked)
	}
	deleted := manifestEntry(t, checkpoint.Manifest, "deleted.txt")
	if deleted.Index == nil || deleted.Worktree != nil {
		t.Fatalf("worktree deletion was not represented: %#v", deleted)
	}
	link := manifestEntry(t, checkpoint.Manifest, "safe-link")
	if link.Worktree == nil || link.Worktree.Kind != "symlink" || link.Worktree.LinkTarget != "tracked.txt" {
		t.Fatalf("safe symlink was followed or changed: %#v", link)
	}
	paths := make([]string, 0, len(checkpoint.Manifest.Entries))
	for _, entry := range checkpoint.Manifest.Entries {
		paths = append(paths, entry.Path)
	}
	if slices.Contains(paths, ".env") || slices.Contains(paths, ".ssh/id_test") {
		t.Fatalf("default secret exclusions entered manifest: %#v", paths)
	}
	legacy := manifestEntry(t, checkpoint.Manifest, ".warpmetal/legacy-user.txt")
	if legacy.Worktree == nil || legacy.Worktree.Digest != digest([]byte("legacy user file\n")) {
		t.Fatalf("ordinary .warpmetal user file was not captured: %#v", legacy)
	}
	for _, entry := range checkpoint.Manifest.Entries {
		if entry.Path == ".warpmetal/worktrees" || strings.HasPrefix(entry.Path, ".warpmetal/worktrees/") {
			t.Fatalf("private managed task worktree entry %q was captured", entry.Path)
		}
	}
	if got := runGit(t, source, "rev-parse", "HEAD"); got != headBefore {
		t.Fatalf("capture changed HEAD from %s to %s", headBefore, got)
	}
	indexAfter, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(indexAfter, indexBefore) {
		t.Fatal("capture changed the real Git index")
	}

	// An independent change inside the private managed task worktree must not
	// invalidate workspace verification; only workspace content does.
	writeFile(t, filepath.Join(source, ".warpmetal", "worktrees", "task_fixture", "private.txt"), []byte("private task state changed\n"), 0600)
	if err := objects.VerifyWorkspace(context.Background(), checkpoint.ID, source); err != nil {
		t.Fatalf("private managed task worktree change invalidated verification: %v", err)
	}

	destination := filepath.Join(t.TempDir(), "destination")
	runGit(t, filepath.Dir(destination), "clone", "--no-hardlinks", source, destination)
	destinationIdentity := checkpointIdentity("epoch_destination123")
	receipt, err := objects.Materialize(context.Background(), MaterializeRequest{
		CheckpointID: checkpoint.ID, SourceIdentity: checkpoint.Manifest.Identity,
		DestinationIdentity: destinationIdentity, DestinationRoot: destination,
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ManifestDigest != checkpoint.ManifestDigest || !receipt.DestinationIdentity.Equal(destinationIdentity) {
		t.Fatalf("materialization receipt does not bind exact target: %#v", receipt)
	}
	if content, _ := os.ReadFile(filepath.Join(destination, "tracked.txt")); string(content) != "working\n" {
		t.Fatalf("working content = %q", content)
	}
	if content, _ := os.ReadFile(filepath.Join(destination, "binary.dat")); !bytes.Equal(content, []byte{0, 1, 2, 0xff, 0, 9}) {
		t.Fatalf("binary content = %v", content)
	}
	if _, err := os.Stat(filepath.Join(destination, "deleted.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted file was materialized: %v", err)
	}
	if content, _ := os.ReadFile(filepath.Join(destination, ".warpmetal", "legacy-user.txt")); string(content) != "legacy user file\n" {
		t.Fatalf("ordinary .warpmetal user file was not materialized: %q", content)
	}
	if _, err := os.Stat(filepath.Join(destination, ".warpmetal", "worktrees", "task_fixture", "private.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private managed task worktree file was materialized: %v", err)
	}
	if info, err := os.Stat(filepath.Join(destination, "bin", "tool")); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("executable mode changed: %#v %v", info, err)
	}
	if target, err := os.Readlink(filepath.Join(destination, "safe-link")); err != nil || target != "tracked.txt" {
		t.Fatalf("symlink = %q, %v", target, err)
	}
	destinationIndex := runGit(t, destination, "rev-parse", "--git-path", "index")
	if !filepath.IsAbs(destinationIndex) {
		destinationIndex = filepath.Join(destination, destinationIndex)
	}
	materializedIndex, err := os.ReadFile(destinationIndex)
	if err != nil {
		t.Fatal(err)
	}
	if digest(materializedIndex) != checkpoint.Manifest.Git.IndexDigest {
		t.Fatal("materialized Git index digest does not match checkpoint")
	}
}

func TestVerifyWorkspaceDetectsPostCheckpointChangeWithoutPublishingOrMutatingGit(t *testing.T) {
	source := fixtureRepository(t)
	objects := CheckpointStore{Root: filepath.Join(t.TempDir(), "objects"), MaxBytes: 256 << 20, MaxFiles: 10_000}
	capture, err := objects.Capture(context.Background(), CaptureRequest{
		OperationID: "continuity_op_currentfiles", Identity: checkpointIdentity("epoch_source123"), WorkspaceRoot: source,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpointRoot := filepath.Join(objects.Root, "checkpoints")
	entriesBefore, err := os.ReadDir(checkpointRoot)
	if err != nil {
		t.Fatal(err)
	}
	headBefore := runGit(t, source, "rev-parse", "HEAD")
	indexPath := runGit(t, source, "rev-parse", "--git-path", "index")
	if !filepath.IsAbs(indexPath) {
		indexPath = filepath.Join(source, indexPath)
	}
	indexBefore, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := objects.VerifyWorkspace(context.Background(), capture.ID, source); err != nil {
		t.Fatalf("unchanged workspace refused: %v", err)
	}
	writeFile(t, filepath.Join(source, "tracked.txt"), []byte("changed after checkpoint\n"), 0600)
	if err := objects.VerifyWorkspace(context.Background(), capture.ID, source); !errors.Is(err, ErrWorkspaceChanged) {
		t.Fatalf("changed workspace error = %v, want ErrWorkspaceChanged", err)
	}
	entriesAfter, err := os.ReadDir(checkpointRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entriesAfter) != len(entriesBefore) {
		t.Fatalf("read-only verification published a checkpoint: %d -> %d", len(entriesBefore), len(entriesAfter))
	}
	if got := runGit(t, source, "rev-parse", "HEAD"); got != headBefore {
		t.Fatalf("workspace verification changed HEAD from %s to %s", headBefore, got)
	}
	indexAfter, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(indexAfter, indexBefore) {
		t.Fatal("workspace verification changed the real Git index")
	}
}

func TestCheckpointRejectsEscapingSymlinkHardlinkAndSpecialFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("filesystem inode behavior is Unix-specific")
	}
	tests := []struct {
		name  string
		build func(*testing.T, string)
	}{
		{"escaping symlink", func(t *testing.T, root string) {
			if err := os.Symlink("../outside", filepath.Join(root, "escape")); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, "first"), []byte("same inode"), 0600)
			if err := os.Link(filepath.Join(root, "first"), filepath.Join(root, "second")); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo", func(t *testing.T, root string) {
			if err := exec.Command("mkfifo", filepath.Join(root, "pipe")).Run(); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := fixtureRepository(t)
			test.build(t, root)
			objects := CheckpointStore{Root: filepath.Join(t.TempDir(), "objects"), MaxBytes: 256 << 20, MaxFiles: 10_000}
			_, err := objects.Capture(context.Background(), CaptureRequest{
				OperationID: "continuity_op_unsafe", Identity: checkpointIdentity("epoch_source123"), WorkspaceRoot: root,
			})
			if !errors.Is(err, ErrUnsafeCheckpointEntry) {
				t.Fatalf("unsafe entry error = %v, want ErrUnsafeCheckpointEntry", err)
			}
		})
	}
}

func TestCheckpointRejectsTrackedExclusionsAndUnsupportedLinkedWorktree(t *testing.T) {
	t.Run("tracked exclusion", func(t *testing.T) {
		root := fixtureRepository(t)
		writeFile(t, filepath.Join(root, ".env"), []byte("TOKEN=secret\n"), 0600)
		runGit(t, root, "add", ".env")
		objects := CheckpointStore{Root: filepath.Join(t.TempDir(), "objects")}
		_, err := objects.Capture(context.Background(), CaptureRequest{
			OperationID: "continuity_op_tracked_exclusion", Identity: checkpointIdentity("epoch_source123"), WorkspaceRoot: root,
		})
		if !errors.Is(err, ErrUnsafeCheckpointEntry) {
			t.Fatalf("tracked exclusion error = %v, want ErrUnsafeCheckpointEntry", err)
		}
	})
	t.Run("linked worktree", func(t *testing.T) {
		root := fixtureRepository(t)
		linked := filepath.Join(t.TempDir(), "linked")
		runGit(t, root, "worktree", "add", linked, "-b", "linked-test")
		objects := CheckpointStore{Root: filepath.Join(t.TempDir(), "objects")}
		_, err := objects.Capture(context.Background(), CaptureRequest{
			OperationID: "continuity_op_linked_git", Identity: checkpointIdentity("epoch_source123"), WorkspaceRoot: linked,
		})
		if !errors.Is(err, ErrUnsupportedGitLayout) {
			t.Fatalf("linked Git layout error = %v, want ErrUnsupportedGitLayout", err)
		}
	})
}

func TestCheckpointLimitsAbortWithoutPublishingObject(t *testing.T) {
	root := fixtureRepository(t)
	writeFile(t, filepath.Join(root, "large.bin"), bytes.Repeat([]byte{1}, 33), 0600)
	objectRoot := filepath.Join(t.TempDir(), "objects")
	objects := CheckpointStore{Root: objectRoot, MaxBytes: 32, MaxFiles: 10_000}
	_, err := objects.Capture(context.Background(), CaptureRequest{
		OperationID: "continuity_op_overflow", Identity: checkpointIdentity("epoch_source123"), WorkspaceRoot: root,
	})
	if !errors.Is(err, ErrCheckpointQuota) {
		t.Fatalf("capture error = %v, want ErrCheckpointQuota", err)
	}
	entries, readErr := os.ReadDir(filepath.Join(objectRoot, "checkpoints"))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("overflow published checkpoint objects: %#v", entries)
	}
}

func TestMaterializeRefusesSourceEpochAndDirtyDestination(t *testing.T) {
	source := fixtureRepository(t)
	objects := CheckpointStore{Root: filepath.Join(t.TempDir(), "objects"), MaxBytes: 256 << 20, MaxFiles: 10_000}
	checkpoint, err := objects.Capture(context.Background(), CaptureRequest{
		OperationID: "continuity_op_12345", Identity: checkpointIdentity("epoch_source123"), WorkspaceRoot: source,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = objects.Materialize(context.Background(), MaterializeRequest{
		CheckpointID: checkpoint.ID, SourceIdentity: checkpoint.Manifest.Identity,
		DestinationIdentity: checkpoint.Manifest.Identity, DestinationRoot: source,
	})
	if !errors.Is(err, ErrLiveWorkspaceTarget) {
		t.Fatalf("same workspace materialization error = %v", err)
	}
	destination := filepath.Join(t.TempDir(), "destination")
	runGit(t, filepath.Dir(destination), "clone", "--no-hardlinks", source, destination)
	writeFile(t, filepath.Join(destination, "owner-change.txt"), []byte("preserve me\n"), 0600)
	_, err = objects.Materialize(context.Background(), MaterializeRequest{
		CheckpointID: checkpoint.ID, SourceIdentity: checkpoint.Manifest.Identity,
		DestinationIdentity: checkpointIdentity("epoch_destination123"), DestinationRoot: destination,
	})
	if !errors.Is(err, ErrDestinationChanged) {
		t.Fatalf("dirty destination error = %v, want ErrDestinationChanged", err)
	}
	if content, readErr := os.ReadFile(filepath.Join(destination, "owner-change.txt")); readErr != nil || string(content) != "preserve me\n" {
		t.Fatalf("refused materialization changed destination: %q %v", content, readErr)
	}
}

func TestMaterializeNewSeedsVerifiedBaseIntoExclusiveEmptyLeaf(t *testing.T) {
	if runMappedMaterializationProbeChild(t) {
		return
	}
	source := fixtureRepository(t)
	writeFile(t, filepath.Join(source, "tracked.txt"), []byte("continued work\n"), 0600)
	writeFile(t, filepath.Join(source, "new.bin"), []byte{0, 9, 0xff}, 0600)
	verifyMappedSource := prepareMappedCaptureSource(t, source)
	objects := CheckpointStore{Root: filepath.Join(t.TempDir(), "objects"), MaxBytes: 256 << 20, MaxFiles: 10_000}
	capture, err := objects.Capture(context.Background(), CaptureRequest{
		OperationID: "op_restore_capture0001", Identity: checkpointIdentity("epoch_restore_source0001"), WorkspaceRoot: source,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyMappedSource()
	destination := mappedMaterializationDestination(t, t.TempDir())
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	receipt, err := objects.MaterializeNew(context.Background(), MaterializeNewRequest{
		CheckpointID: capture.ID, SourceIdentity: capture.Manifest.Identity,
		DestinationIdentity: checkpointIdentity("epoch_restore_destination0001"),
		SourceRoot:          source, DestinationRoot: destination,
		Ownership: mappedMaterializationAuthority(t, destination),
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ManifestDigest != capture.ManifestDigest || receipt.Bytes != capture.Bytes || receipt.ObjectCount != capture.ObjectCount {
		t.Fatalf("new target receipt drifted from checkpoint: %#v", receipt)
	}
	if got, err := os.ReadFile(filepath.Join(destination, "tracked.txt")); err != nil || string(got) != "continued work\n" {
		t.Fatalf("restored tracked content = %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(destination, "new.bin")); err != nil || !bytes.Equal(got, []byte{0, 9, 0xff}) {
		t.Fatalf("restored binary content = %v, %v", got, err)
	}
	if got := runGit(t, destination, "rev-parse", "HEAD"); got != capture.Manifest.Git.Base {
		t.Fatalf("restored base = %s, want %s", got, capture.Manifest.Git.Base)
	}
	assertMappedMaterializationOwner(t, destination)
	verifyMappedSource()
}

// modeFidelityCapture captures a repository whose worktree holds one 0644 and
// one 0600 file. Both are chmod'ed after writing so the test process umask
// cannot influence the captured modes.
func modeFidelityCapture(t *testing.T) (CheckpointStore, DurableCapture, string) {
	t.Helper()
	source := fixtureRepository(t)
	wide := filepath.Join(source, "captured-wide.txt")
	writeFile(t, wide, []byte("wide\n"), 0644)
	if err := os.Chmod(wide, 0644); err != nil {
		t.Fatal(err)
	}
	narrow := filepath.Join(source, "captured-narrow.txt")
	writeFile(t, narrow, []byte("narrow\n"), 0600)
	if err := os.Chmod(narrow, 0600); err != nil {
		t.Fatal(err)
	}
	objects := CheckpointStore{Root: filepath.Join(t.TempDir(), "objects"), MaxBytes: 256 << 20, MaxFiles: 10_000}
	capture, err := objects.Capture(context.Background(), CaptureRequest{
		OperationID: "op_mode_fidelity0001", Identity: checkpointIdentity("epoch_mode_source0001"), WorkspaceRoot: source,
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry := manifestEntry(t, capture.Manifest, "captured-wide.txt"); entry.Worktree == nil || entry.Worktree.Mode != 0o644 {
		t.Fatalf("captured wide mode = %#v", entry.Worktree)
	}
	if entry := manifestEntry(t, capture.Manifest, "captured-narrow.txt"); entry.Worktree == nil || entry.Worktree.Mode != 0o600 {
		t.Fatalf("captured narrow mode = %#v", entry.Worktree)
	}
	return objects, capture, source
}

// modeFidelityLeaf pins the packaged daemon umask (warpmetald.service runs
// with UMask=0027) and creates the empty exclusive destination leaf.
func modeFidelityLeaf(t *testing.T) string {
	t.Helper()
	previous := syscall.Umask(0o027) // packaged warpmetald.service execution policy
	t.Cleanup(func() { syscall.Umask(previous) })
	destination := filepath.Join(t.TempDir(), "mode-leaf")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	return destination
}

func modeFidelityRequest(capture DurableCapture, source, destination string) MaterializeNewRequest {
	return MaterializeNewRequest{
		CheckpointID: capture.ID, SourceIdentity: capture.Manifest.Identity,
		DestinationIdentity: checkpointIdentity("epoch_mode_destination0001"),
		SourceRoot:          source, DestinationRoot: destination,
	}
}

func assertWorktreeMode(t *testing.T, destination, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(filepath.Join(destination, path))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("materialized %q mode = %o, want %o", path, got, want)
	}
}

func TestMaterializeNewPreservesCapturedWorktreeModesUnderRestrictiveUmask(t *testing.T) {
	objects, capture, source := modeFidelityCapture(t)
	destination := modeFidelityLeaf(t)
	receipt, err := objects.MaterializeNew(context.Background(), modeFidelityRequest(capture, source, destination))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ManifestDigest != capture.ManifestDigest || receipt.Bytes != capture.Bytes || receipt.ObjectCount != capture.ObjectCount {
		t.Fatalf("mode-fidelity receipt drifted from checkpoint: %#v", receipt)
	}
	assertWorktreeMode(t, destination, "captured-wide.txt", 0o644)
	assertWorktreeMode(t, destination, "captured-narrow.txt", 0o600)
}

func TestMaterializeNewRepairsUmaskReducedWorktreeModesOnReplay(t *testing.T) {
	objects, capture, source := modeFidelityCapture(t)
	destination := modeFidelityLeaf(t)
	request := modeFidelityRequest(capture, source, destination)
	if _, err := objects.MaterializeNew(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	// Simulate a leaf first materialized by the umask-affected producer.
	if err := os.Chmod(filepath.Join(destination, "captured-wide.txt"), 0o640); err != nil {
		t.Fatal(err)
	}
	receipt, err := objects.MaterializeNew(context.Background(), request)
	if err != nil {
		t.Fatalf("replay of an umask-reduced leaf: %v", err)
	}
	if receipt.ManifestDigest != capture.ManifestDigest || receipt.Bytes != capture.Bytes || receipt.ObjectCount != capture.ObjectCount {
		t.Fatalf("repaired receipt drifted from checkpoint: %#v", receipt)
	}
	assertWorktreeMode(t, destination, "captured-wide.txt", 0o644)
	assertWorktreeMode(t, destination, "captured-narrow.txt", 0o600)
}

func TestMaterializeNewRefusesWidenedWorktreeModesOnReplay(t *testing.T) {
	objects, capture, source := modeFidelityCapture(t)
	destination := modeFidelityLeaf(t)
	request := modeFidelityRequest(capture, source, destination)
	if _, err := objects.MaterializeNew(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	// A wider mode is not an umask reduction and must never be accepted.
	if err := os.Chmod(filepath.Join(destination, "captured-wide.txt"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.MaterializeNew(context.Background(), request); !errors.Is(err, ErrCheckpointCorrupt) {
		t.Fatalf("widened worktree mode error = %v, want ErrCheckpointCorrupt", err)
	}
	assertWorktreeMode(t, destination, "captured-wide.txt", 0o666)
}

func TestMaterializeNewRefusesTamperedContentBeforeRepairingModes(t *testing.T) {
	objects, capture, source := modeFidelityCapture(t)
	destination := modeFidelityLeaf(t)
	request := modeFidelityRequest(capture, source, destination)
	if _, err := objects.MaterializeNew(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	entry := manifestEntry(t, capture.Manifest, "captured-wide.txt")
	if entry.Worktree == nil {
		t.Fatal("fixture entry has no worktree version")
	}
	target := filepath.Join(destination, "captured-wide.txt")
	if err := os.WriteFile(target, bytes.Repeat([]byte{'x'}, int(entry.Worktree.Size)), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.MaterializeNew(context.Background(), request); !errors.Is(err, ErrCheckpointCorrupt) {
		t.Fatalf("tampered content error = %v, want ErrCheckpointCorrupt", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("refused replay repaired mode to %o before content verification", got)
	}
}

func TestMaterializeNewVerifiesEveryCheckpointObjectBeforeMutatingLeaf(t *testing.T) {
	source := fixtureRepository(t)
	objects := CheckpointStore{Root: filepath.Join(t.TempDir(), "objects"), MaxBytes: 256 << 20, MaxFiles: 10_000}
	capture, err := objects.Capture(context.Background(), CaptureRequest{
		OperationID: "op_restore_corrupt0001", Identity: checkpointIdentity("epoch_restore_source0001"), WorkspaceRoot: source,
	})
	if err != nil {
		t.Fatal(err)
	}
	var objectRef string
	for _, entry := range capture.Manifest.Entries {
		if entry.Worktree != nil {
			objectRef = entry.Worktree.ObjectRef
			break
		}
	}
	if objectRef == "" {
		t.Fatal("fixture checkpoint has no worktree object")
	}
	if err := os.WriteFile(filepath.Join(objects.Root, "checkpoints", capture.ID, filepath.FromSlash(objectRef)), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "restore-leaf")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	_, err = objects.MaterializeNew(context.Background(), MaterializeNewRequest{
		CheckpointID: capture.ID, SourceIdentity: capture.Manifest.Identity,
		DestinationIdentity: checkpointIdentity("epoch_restore_destination0001"),
		SourceRoot:          source, DestinationRoot: destination,
	})
	if !errors.Is(err, ErrCheckpointCorrupt) {
		t.Fatalf("corrupt object error = %v, want ErrCheckpointCorrupt", err)
	}
	entries, readErr := os.ReadDir(destination)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("failed verification mutated fresh restore leaf: %#v, %v", entries, readErr)
	}
}
