package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckpointCollectionRefusesSymlinkAndUnknownStoreEntries(t *testing.T) {
	root := t.TempDir()
	checkpointRoot := filepath.Join(root, "checkpoints")
	if err := os.Mkdir(checkpointRoot, 0700); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(t.TempDir(), "live-workspace")
	if err := os.Mkdir(live, 0700); err != nil {
		t.Fatal(err)
	}
	liveFile := filepath.Join(live, "keep.txt")
	if err := os.WriteFile(liveFile, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	captureID := "capture_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.Symlink(live, filepath.Join(checkpointRoot, captureID)); err != nil {
		t.Fatal(err)
	}
	store := CheckpointStore{Root: root}
	err := store.Collect(context.Background(), CollectionRequest{
		CaptureID: captureID, ObjectID: captureID,
		ManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if !errors.Is(err, ErrUnsafeCheckpointStore) {
		t.Fatalf("symlink object collection = %v", err)
	}
	if content, err := os.ReadFile(liveFile); err != nil || string(content) != "keep" {
		t.Fatalf("collection touched live workspace: %q, %v", content, err)
	}
	if err := os.Mkdir(filepath.Join(checkpointRoot, "unknown-format"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CollectStaging(context.Background(), time.Now().UTC().Add(time.Hour), 32); !errors.Is(err, ErrUnsafeCheckpointStore) {
		t.Fatalf("unknown object-store entry = %v", err)
	}
}

func TestCheckpointStagingCollectionRefusesSymlinkNamedLikePublishedCapture(t *testing.T) {
	root := t.TempDir()
	checkpointRoot := filepath.Join(root, "checkpoints")
	if err := os.Mkdir(checkpointRoot, 0700); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(t.TempDir(), "live-workspace")
	if err := os.Mkdir(live, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "keep.txt"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	name := "capture_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := os.Symlink(live, filepath.Join(checkpointRoot, name)); err != nil {
		t.Fatal(err)
	}
	store := CheckpointStore{Root: root}
	if _, err := store.CollectStaging(context.Background(), time.Now().UTC().Add(time.Hour), 32); !errors.Is(err, ErrUnsafeCheckpointStore) {
		t.Fatalf("published-looking symlink = %v", err)
	}
	if content, err := os.ReadFile(filepath.Join(live, "keep.txt")); err != nil || string(content) != "keep" {
		t.Fatalf("staging collection touched live workspace: %q, %v", content, err)
	}
}

func TestCheckpointCollectionRemovesEmptyDirectoryLeftAfterInterruptedUnlink(t *testing.T) {
	root := t.TempDir()
	checkpointRoot := filepath.Join(root, "checkpoints")
	if err := os.Mkdir(checkpointRoot, 0700); err != nil {
		t.Fatal(err)
	}
	captureID := "capture_cccccccccccccccccccccccccccccccc"
	path := filepath.Join(checkpointRoot, captureID)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	store := CheckpointStore{Root: root}
	if err := store.Collect(context.Background(), CollectionRequest{
		CaptureID: captureID, ObjectID: captureID,
		ManifestDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}); err != nil {
		t.Fatalf("resume empty object unlink = %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted object directory remains: %v", err)
	}
}
