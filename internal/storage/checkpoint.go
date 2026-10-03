package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

var (
	ErrCheckpointQuota       = errors.New("checkpoint capture exceeds configured limits")
	ErrUnsafeCheckpointEntry = errors.New("workspace contains an unsafe checkpoint entry")
	ErrUnsupportedGitLayout  = errors.New("workspace uses an unsupported Git layout")
	ErrLiveWorkspaceTarget   = errors.New("materialization target is the source workspace")
	ErrDestinationChanged    = errors.New("materialization destination is not a pristine base checkout")
	ErrCheckpointCorrupt     = errors.New("checkpoint object failed integrity verification")
	ErrWorkspaceChanged      = errors.New("workspace changed after checkpoint capture")
	ErrCheckpointUnavailable = errors.New("checkpoint object is no longer retained")
	ErrUnsafeCheckpointStore = errors.New("checkpoint object store is unsafe")
)

type CheckpointStore struct {
	Root     string
	MaxBytes int64
	MaxFiles int
	Now      func() time.Time
}

type CaptureRequest struct {
	OperationID   string
	Identity      model.ContinuityIdentityV1
	WorkspaceRoot string
	MaxBytes      int64
}

type FileVersionV1 struct {
	Kind       string `json:"kind"`
	Mode       uint32 `json:"mode"`
	Size       int64  `json:"size"`
	Digest     string `json:"digest"`
	ObjectRef  string `json:"objectRef"`
	LinkTarget string `json:"linkTarget,omitempty"`
	GitOID     string `json:"gitOid,omitempty"`
}

type CheckpointEntryV1 struct {
	Path     string         `json:"path"`
	Tracked  bool           `json:"tracked"`
	Worktree *FileVersionV1 `json:"worktree,omitempty"`
	Index    *FileVersionV1 `json:"index,omitempty"`
}

type CheckpointGitV1 struct {
	Head           string `json:"head"`
	Base           string `json:"base"`
	IndexDigest    string `json:"indexDigest"`
	IndexObjectRef string `json:"indexObjectRef"`
}

type CheckpointManifestV1 struct {
	FormatVersion int                        `json:"formatVersion"`
	Identity      model.ContinuityIdentityV1 `json:"identity"`
	OperationID   string                     `json:"operationId"`
	CreatedAt     time.Time                  `json:"createdAt"`
	Git           CheckpointGitV1            `json:"git"`
	Entries       []CheckpointEntryV1        `json:"entries"`
	Exclusions    []string                   `json:"exclusions"`
	Bytes         int64                      `json:"bytes"`
	ObjectCount   int                        `json:"objectCount"`
}

type DurableCapture struct {
	ID             string
	ObjectID       string
	ManifestDigest string
	Manifest       CheckpointManifestV1
	Bytes          int64
	ObjectCount    int
}

type CollectionRequest struct {
	CaptureID      string
	ObjectID       string
	ManifestDigest string
}

type MaterializeRequest struct {
	CheckpointID        string
	SourceIdentity      model.ContinuityIdentityV1
	DestinationIdentity model.ContinuityIdentityV1
	DestinationRoot     string
}

type MaterializeNewRequest struct {
	CheckpointID        string
	SourceIdentity      model.ContinuityIdentityV1
	DestinationIdentity model.ContinuityIdentityV1
	SourceRoot          string
	DestinationRoot     string
	Ownership           *MaterializationOwnership
}

// MaterializationOwnership is host-private catalog authority for an exclusive
// continuity leaf. The owner comes from the verified anchor descriptor.
type MaterializationOwnership struct {
	Anchor     string
	RootDevice uint64
	RootInode  uint64
}

type MaterializeReceipt struct {
	ManifestDigest      string
	DestinationIdentity model.ContinuityIdentityV1
	Bytes               int64
	ObjectCount         int
}

func (s CheckpointStore) Capture(ctx context.Context, request CaptureRequest) (DurableCapture, error) {
	if err := ctx.Err(); err != nil {
		return DurableCapture{}, err
	}
	root, err := filepath.Abs(request.WorkspaceRoot)
	if err != nil {
		return DurableCapture{}, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return DurableCapture{}, err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return DurableCapture{}, fmt.Errorf("inspect registered workspace: %w", err)
	}
	maximumBytes := s.MaxBytes
	if maximumBytes <= 0 {
		maximumBytes = 256 << 20
	}
	if request.MaxBytes > 0 && request.MaxBytes < maximumBytes {
		maximumBytes = request.MaxBytes
	}
	maximumFiles := s.MaxFiles
	if maximumFiles <= 0 {
		maximumFiles = 10_000
	}
	checkpointRoot := filepath.Join(s.Root, "checkpoints")
	if err := os.MkdirAll(checkpointRoot, 0700); err != nil {
		return DurableCapture{}, fmt.Errorf("create checkpoint root: %w", err)
	}
	if err := os.Chmod(checkpointRoot, 0700); err != nil {
		return DurableCapture{}, fmt.Errorf("protect checkpoint root: %w", err)
	}
	temporary, err := os.MkdirTemp(checkpointRoot, ".capture-")
	if err != nil {
		return DurableCapture{}, fmt.Errorf("create checkpoint staging directory: %w", err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0700); err != nil {
		return DurableCapture{}, err
	}
	blobs := filepath.Join(temporary, "blobs")
	if err := os.Mkdir(blobs, 0700); err != nil {
		return DurableCapture{}, err
	}

	manifest, err := buildCheckpointManifest(ctx, root, request, temporary, maximumBytes, maximumFiles, s.now())
	if err != nil {
		return DurableCapture{}, err
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return DurableCapture{}, err
	}
	manifestDigest := digestBytes(manifestJSON)
	captureID := "capture_" + strings.TrimPrefix(manifestDigest, "sha256:")[:32]
	if err := writeDurableFile(filepath.Join(temporary, "manifest.json"), manifestJSON, 0600); err != nil {
		return DurableCapture{}, err
	}
	if err := syncDirectory(blobs); err != nil {
		return DurableCapture{}, err
	}
	if err := syncDirectory(temporary); err != nil {
		return DurableCapture{}, err
	}
	finalPath := filepath.Join(checkpointRoot, captureID)
	if err := os.Rename(temporary, finalPath); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return DurableCapture{}, fmt.Errorf("publish checkpoint: %w", err)
		}
		loaded, loadErr := s.Verify(ctx, captureID)
		if loadErr != nil || loaded.ManifestDigest != manifestDigest {
			return DurableCapture{}, errors.Join(ErrCheckpointCorrupt, loadErr)
		}
		return loaded, nil
	}
	removeTemporary = false
	if err := syncDirectory(checkpointRoot); err != nil {
		return DurableCapture{}, err
	}
	return DurableCapture{
		ID: captureID, ObjectID: captureID, ManifestDigest: manifestDigest,
		Manifest: manifest, Bytes: manifest.Bytes, ObjectCount: manifest.ObjectCount,
	}, nil
}

// VerifyWorkspace compares a registered workspace to an immutable capture
// using the exact capture scanner. It writes only temporary comparison blobs
// beneath the private object store; it never publishes a checkpoint or writes
// the workspace, Git index, or HEAD.
func (s CheckpointStore) VerifyWorkspace(ctx context.Context, captureID, workspaceRoot string) error {
	capture, err := s.Verify(ctx, captureID)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return errors.Join(ErrWorkspaceChanged, err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return errors.Join(ErrWorkspaceChanged, err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return errors.Join(ErrWorkspaceChanged, err)
	}

	checkpointRoot := filepath.Join(s.Root, "checkpoints")
	temporary, err := os.MkdirTemp(checkpointRoot, ".verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0700); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(temporary, "blobs"), 0700); err != nil {
		return err
	}
	maximumBytes := s.MaxBytes
	if maximumBytes <= 0 {
		maximumBytes = 256 << 20
	}
	maximumFiles := s.MaxFiles
	if maximumFiles <= 0 {
		maximumFiles = 10_000
	}
	candidate, err := buildCheckpointManifest(ctx, root, CaptureRequest{
		OperationID: capture.Manifest.OperationID,
		Identity:    capture.Manifest.Identity,
	}, temporary, maximumBytes, maximumFiles, capture.Manifest.CreatedAt)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return errors.Join(ErrWorkspaceChanged, err)
	}
	payload, err := json.Marshal(candidate)
	if err != nil {
		return err
	}
	if digestBytes(payload) != capture.ManifestDigest {
		return ErrWorkspaceChanged
	}
	return nil
}

func buildCheckpointManifest(
	ctx context.Context,
	root string,
	request CaptureRequest,
	temporary string,
	maximumBytes int64,
	maximumFiles int,
	createdAt time.Time,
) (CheckpointManifestV1, error) {
	head, err := gitOutput(ctx, root, nil, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return CheckpointManifestV1{}, fmt.Errorf("resolve checkpoint HEAD: %w", ErrUnsupportedGitLayout)
	}
	gitDirectory, err := gitOutput(ctx, root, nil, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return CheckpointManifestV1{}, fmt.Errorf("resolve Git directory: %w", ErrUnsupportedGitLayout)
	}
	commonDirectory, err := gitOutput(ctx, root, nil, "rev-parse", "--git-common-dir")
	if err != nil {
		return CheckpointManifestV1{}, fmt.Errorf("resolve Git common directory: %w", ErrUnsupportedGitLayout)
	}
	if !filepath.IsAbs(commonDirectory) {
		commonDirectory = filepath.Join(root, commonDirectory)
	}
	if err := validateGitLayout(root, gitDirectory, commonDirectory); err != nil {
		return CheckpointManifestV1{}, err
	}
	indexPath, err := gitOutput(ctx, root, nil, "rev-parse", "--git-path", "index")
	if err != nil {
		return CheckpointManifestV1{}, fmt.Errorf("resolve Git index: %w", ErrUnsupportedGitLayout)
	}
	if !filepath.IsAbs(indexPath) {
		indexPath = filepath.Join(root, indexPath)
	}
	if filepath.Clean(indexPath) != filepath.Join(root, ".git", "index") {
		return CheckpointManifestV1{}, ErrUnsupportedGitLayout
	}
	indexBytes, err := os.ReadFile(indexPath)
	if err != nil {
		return CheckpointManifestV1{}, fmt.Errorf("read Git index: %w", err)
	}
	account := &captureAccount{maximumBytes: maximumBytes, maximumFiles: maximumFiles}
	indexVersion, err := storeBytes(temporary, indexBytes, 0600, "regular", "", account, false)
	if err != nil {
		return CheckpointManifestV1{}, err
	}
	entries := map[string]*CheckpointEntryV1{}
	indexOutput, err := gitBytes(ctx, root, nil, "ls-files", "--stage", "-z")
	if err != nil {
		return CheckpointManifestV1{}, fmt.Errorf("read Git index entries: %w", err)
	}
	for _, record := range bytes.Split(indexOutput, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		tab := bytes.IndexByte(record, '\t')
		if tab < 0 {
			return CheckpointManifestV1{}, ErrUnsupportedGitLayout
		}
		fields := strings.Fields(string(record[:tab]))
		if len(fields) != 3 || fields[2] != "0" {
			return CheckpointManifestV1{}, ErrUnsupportedGitLayout
		}
		path := string(record[tab+1:])
		if err := validateRelativePath(path); err != nil {
			return CheckpointManifestV1{}, err
		}
		if excludedCheckpointPath(path) {
			return CheckpointManifestV1{}, fmt.Errorf("%w: tracked exclusion %s", ErrUnsafeCheckpointEntry, path)
		}
		mode, err := strconv.ParseUint(fields[0], 8, 32)
		if err != nil {
			return CheckpointManifestV1{}, ErrUnsupportedGitLayout
		}
		blob, err := gitBytes(ctx, root, nil, "cat-file", "blob", fields[1])
		if err != nil {
			return CheckpointManifestV1{}, fmt.Errorf("read staged blob: %w", err)
		}
		version, err := storeBytes(temporary, blob, uint32(mode), "regular", "", account, false)
		if err != nil {
			return CheckpointManifestV1{}, err
		}
		version.GitOID = fields[1]
		entry := entryFor(entries, path)
		entry.Tracked = true
		entry.Index = &version
	}
	headOutput, err := gitBytes(ctx, root, nil, "ls-tree", "-r", "--name-only", "-z", head)
	if err != nil {
		return CheckpointManifestV1{}, fmt.Errorf("read base tree: %w", err)
	}
	for _, name := range bytes.Split(headOutput, []byte{0}) {
		if len(name) == 0 {
			continue
		}
		path := string(name)
		if err := validateRelativePath(path); err != nil {
			return CheckpointManifestV1{}, err
		}
		if excludedCheckpointPath(path) {
			return CheckpointManifestV1{}, fmt.Errorf("%w: base exclusion %s", ErrUnsafeCheckpointEntry, path)
		}
		entryFor(entries, path).Tracked = true
	}

	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return CheckpointManifestV1{}, err
	}
	defer unix.Close(rootFD)
	exclusions := []string{".git", ".env", ".env.*", ".ssh", ".aws", ".config/gcloud", "node_modules"}
	err = filepath.WalkDir(root, func(path string, directory fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		relative = filepath.ToSlash(relative)
		if excludedCheckpointPath(relative) {
			if directory.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if err := validateRelativePath(relative); err != nil {
			return err
		}
		info, err := directory.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		entry := entryFor(entries, relative)
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if !safeSymlink(relative, target) {
				return fmt.Errorf("%w: %s", ErrUnsafeCheckpointEntry, relative)
			}
			version, err := storeBytes(temporary, []byte(target), uint32(info.Mode().Perm()), "symlink", target, account, true)
			if err != nil {
				return err
			}
			entry.Worktree = &version
		case info.Mode().IsRegular():
			if hardlinked(info) {
				return fmt.Errorf("%w: hardlink %s", ErrUnsafeCheckpointEntry, relative)
			}
			content, mode, err := readRegularBeneath(rootFD, relative)
			if err != nil {
				return fmt.Errorf("%w: %s: %v", ErrUnsafeCheckpointEntry, relative, err)
			}
			version, err := storeBytes(temporary, content, uint32(mode.Perm()), "regular", "", account, true)
			if err != nil {
				return err
			}
			entry.Worktree = &version
		default:
			return fmt.Errorf("%w: special file %s", ErrUnsafeCheckpointEntry, relative)
		}
		return nil
	})
	if err != nil {
		return CheckpointManifestV1{}, err
	}
	paths := make([]string, 0, len(entries))
	for path := range entries {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	if len(paths) > maximumFiles {
		return CheckpointManifestV1{}, ErrCheckpointQuota
	}
	manifestEntries := make([]CheckpointEntryV1, 0, len(paths))
	for _, path := range paths {
		manifestEntries = append(manifestEntries, *entries[path])
	}
	return CheckpointManifestV1{
		FormatVersion: 1, Identity: request.Identity, OperationID: request.OperationID,
		CreatedAt: createdAt.UTC(), Git: CheckpointGitV1{
			Head: head, Base: head, IndexDigest: indexVersion.Digest, IndexObjectRef: indexVersion.ObjectRef,
		},
		Entries: manifestEntries, Exclusions: exclusions, Bytes: account.bytes,
		ObjectCount: len(paths),
	}, nil
}

type captureAccount struct {
	bytes        int64
	files        int
	maximumBytes int64
	maximumFiles int
}

func storeBytes(
	temporary string,
	content []byte,
	mode uint32,
	kind string,
	linkTarget string,
	account *captureAccount,
	countFile bool,
) (FileVersionV1, error) {
	if int64(len(content)) > account.maximumBytes-account.bytes {
		return FileVersionV1{}, ErrCheckpointQuota
	}
	if countFile {
		account.files++
		if account.files > account.maximumFiles {
			return FileVersionV1{}, ErrCheckpointQuota
		}
	}
	account.bytes += int64(len(content))
	digest := digestBytes(content)
	reference := filepath.ToSlash(filepath.Join("blobs", strings.TrimPrefix(digest, "sha256:")))
	path := filepath.Join(temporary, filepath.FromSlash(reference))
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := writeDurableFile(path, content, 0600); err != nil {
			return FileVersionV1{}, err
		}
	} else if err != nil {
		return FileVersionV1{}, err
	}
	return FileVersionV1{
		Kind: kind, Mode: mode, Size: int64(len(content)), Digest: digest,
		ObjectRef: reference, LinkTarget: linkTarget,
	}, nil
}

func entryFor(entries map[string]*CheckpointEntryV1, path string) *CheckpointEntryV1 {
	entry := entries[path]
	if entry == nil {
		entry = &CheckpointEntryV1{Path: path}
		entries[path] = entry
	}
	return entry
}

func (s CheckpointStore) Verify(ctx context.Context, captureID string) (DurableCapture, error) {
	if err := validateObjectID(captureID); err != nil {
		return DurableCapture{}, err
	}
	directory := filepath.Join(s.Root, "checkpoints", captureID)
	manifestJSON, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return DurableCapture{}, ErrCheckpointUnavailable
		}
		return DurableCapture{}, err
	}
	var manifest CheckpointManifestV1
	decoder := json.NewDecoder(bytes.NewReader(manifestJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return DurableCapture{}, errors.Join(ErrCheckpointCorrupt, err)
	}
	if manifest.FormatVersion != 1 {
		return DurableCapture{}, ErrCheckpointCorrupt
	}
	for _, entry := range manifest.Entries {
		if err := ctx.Err(); err != nil {
			return DurableCapture{}, err
		}
		for _, version := range []*FileVersionV1{entry.Worktree, entry.Index} {
			if version != nil {
				if err := verifyVersion(directory, *version); err != nil {
					return DurableCapture{}, err
				}
			}
		}
	}
	if _, err := readObject(directory, manifest.Git.IndexObjectRef, manifest.Git.IndexDigest); err != nil {
		return DurableCapture{}, err
	}
	digest := digestBytes(manifestJSON)
	if captureID != "capture_"+strings.TrimPrefix(digest, "sha256:")[:32] {
		return DurableCapture{}, ErrCheckpointCorrupt
	}
	return DurableCapture{
		ID: captureID, ObjectID: captureID, ManifestDigest: digest, Manifest: manifest,
		Bytes: manifest.Bytes, ObjectCount: manifest.ObjectCount,
	}, nil
}

func (s CheckpointStore) Collect(ctx context.Context, request CollectionRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateObjectID(request.CaptureID) != nil || request.ObjectID != request.CaptureID ||
		!validSHA256Digest(request.ManifestDigest) {
		return ErrUnsafeCheckpointStore
	}
	rootFD, rootDevice, err := s.openCheckpointRoot(false)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrCheckpointUnavailable
	}
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	var entry unix.Stat_t
	if err := unix.Fstatat(rootFD, request.CaptureID, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return ErrCheckpointUnavailable
		}
		return err
	}
	if entry.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(entry.Dev) != rootDevice {
		return ErrUnsafeCheckpointStore
	}
	capture, err := s.Verify(ctx, request.CaptureID)
	if err != nil {
		if errors.Is(err, ErrCheckpointUnavailable) {
			removed, removeErr := removeEmptyCheckpointDirectoryAt(rootFD, request.CaptureID, rootDevice)
			if removeErr != nil {
				return removeErr
			}
			if removed {
				return unix.Fsync(rootFD)
			}
			return err
		}
		return errors.Join(ErrUnsafeCheckpointStore, err)
	}
	if capture.ObjectID != request.ObjectID || capture.ManifestDigest != request.ManifestDigest {
		return ErrCheckpointCorrupt
	}
	if err := removeCheckpointDirectoryAt(ctx, rootFD, request.CaptureID, rootDevice); err != nil {
		return err
	}
	return unix.Fsync(rootFD)
}

func removeEmptyCheckpointDirectoryAt(parentFD int, name string, rootDevice uint64) (bool, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return false, ErrUnsafeCheckpointStore
		}
		return false, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return false, err
	}
	if uint64(stat.Dev) != rootDevice {
		unix.Close(fd)
		return false, ErrUnsafeCheckpointStore
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		unix.Close(fd)
		return false, err
	}
	directory := os.NewFile(uintptr(dup), name)
	if directory == nil {
		unix.Close(dup)
		unix.Close(fd)
		return false, ErrUnsafeCheckpointStore
	}
	names, err := directory.Readdirnames(1)
	directory.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		unix.Close(fd)
		return false, err
	}
	if len(names) != 0 {
		unix.Close(fd)
		return false, nil
	}
	if err := unix.Fsync(fd); err != nil {
		unix.Close(fd)
		return false, err
	}
	if err := unix.Close(fd); err != nil {
		return false, err
	}
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil {
		return false, err
	}
	return true, nil
}

func (s CheckpointStore) CollectStaging(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, errors.New("checkpoint staging collection limit must be positive")
	}
	rootFD, rootDevice, err := s.openCheckpointRoot(false)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer unix.Close(rootFD)
	dup, err := unix.Dup(rootFD)
	if err != nil {
		return 0, err
	}
	directory := os.NewFile(uintptr(dup), "checkpoint-root")
	if directory == nil {
		unix.Close(dup)
		return 0, ErrUnsafeCheckpointStore
	}
	names, err := directory.Readdirnames(-1)
	directory.Close()
	if err != nil {
		return 0, err
	}
	sort.Strings(names)
	removed := 0
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		var entry unix.Stat_t
		if err := unix.Fstatat(rootFD, name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return removed, err
		}
		if entry.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(entry.Dev) != rootDevice {
			return removed, ErrUnsafeCheckpointStore
		}
		if validateObjectID(name) == nil {
			continue
		}
		if !strings.HasPrefix(name, ".capture-") && !strings.HasPrefix(name, ".verify-") {
			return removed, ErrUnsafeCheckpointStore
		}
		info, err := os.Lstat(filepath.Join(s.Root, "checkpoints", name))
		if err != nil {
			return removed, err
		}
		modified := info.ModTime()
		if modified.After(cutoff) || removed >= limit {
			continue
		}
		if err := removeCheckpointDirectoryAt(ctx, rootFD, name, rootDevice); err != nil {
			return removed, err
		}
		removed++
	}
	if removed > 0 {
		if err := unix.Fsync(rootFD); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

func (s CheckpointStore) openCheckpointRoot(create bool) (int, uint64, error) {
	root := filepath.Join(s.Root, "checkpoints")
	if create {
		if err := os.MkdirAll(root, 0700); err != nil {
			return -1, 0, err
		}
	}
	info, err := os.Lstat(root)
	if err != nil {
		return -1, 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return -1, 0, ErrUnsafeCheckpointStore
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, 0, errors.Join(ErrUnsafeCheckpointStore, err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	return fd, uint64(stat.Dev), nil
}

func removeCheckpointDirectoryAt(ctx context.Context, parentFD int, name string, rootDevice uint64) error {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return ErrUnsafeCheckpointStore
		}
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return err
	}
	if uint64(stat.Dev) != rootDevice {
		unix.Close(fd)
		return ErrUnsafeCheckpointStore
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		unix.Close(fd)
		return err
	}
	directory := os.NewFile(uintptr(dup), name)
	if directory == nil {
		unix.Close(dup)
		unix.Close(fd)
		return ErrUnsafeCheckpointStore
	}
	names, err := directory.Readdirnames(-1)
	directory.Close()
	if err != nil {
		unix.Close(fd)
		return err
	}
	for _, child := range names {
		if err := ctx.Err(); err != nil {
			unix.Close(fd)
			return err
		}
		var entry unix.Stat_t
		if err := unix.Fstatat(fd, child, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			unix.Close(fd)
			return err
		}
		switch entry.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			if err := unix.Unlinkat(fd, child, 0); err != nil {
				unix.Close(fd)
				return err
			}
		case unix.S_IFDIR:
			if uint64(entry.Dev) != rootDevice {
				unix.Close(fd)
				return ErrUnsafeCheckpointStore
			}
			if err := removeCheckpointDirectoryAt(ctx, fd, child, rootDevice); err != nil {
				unix.Close(fd)
				return err
			}
		default:
			unix.Close(fd)
			return ErrUnsafeCheckpointStore
		}
	}
	if err := unix.Fsync(fd); err != nil {
		unix.Close(fd)
		return err
	}
	if err := unix.Close(fd); err != nil {
		return err
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}

func validSHA256Digest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func verifyVersion(directory string, version FileVersionV1) error {
	if !validBlobReference(version.ObjectRef, version.Digest) {
		return ErrCheckpointCorrupt
	}
	content, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(version.ObjectRef)))
	if err != nil || digestBytes(content) != version.Digest || int64(len(content)) != version.Size {
		return errors.Join(ErrCheckpointCorrupt, err)
	}
	return nil
}

func (s CheckpointStore) Materialize(ctx context.Context, request MaterializeRequest) (MaterializeReceipt, error) {
	if request.SourceIdentity.Equal(request.DestinationIdentity) ||
		request.SourceIdentity.WorkspaceEpoch == request.DestinationIdentity.WorkspaceEpoch {
		return MaterializeReceipt{}, ErrLiveWorkspaceTarget
	}
	capture, err := s.Verify(ctx, request.CheckpointID)
	if err != nil {
		return MaterializeReceipt{}, err
	}
	if !capture.Manifest.Identity.Equal(request.SourceIdentity) {
		return MaterializeReceipt{}, ErrLiveWorkspaceTarget
	}
	destination, err := filepath.Abs(request.DestinationRoot)
	if err != nil {
		return MaterializeReceipt{}, err
	}
	destination, err = filepath.EvalSymlinks(destination)
	if err != nil {
		return MaterializeReceipt{}, err
	}
	gitDirectory, err := gitOutput(ctx, destination, nil, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return MaterializeReceipt{}, ErrDestinationChanged
	}
	commonDirectory, err := gitOutput(ctx, destination, nil, "rev-parse", "--git-common-dir")
	if err != nil {
		return MaterializeReceipt{}, ErrDestinationChanged
	}
	if !filepath.IsAbs(commonDirectory) {
		commonDirectory = filepath.Join(destination, commonDirectory)
	}
	if err := validateGitLayout(destination, gitDirectory, commonDirectory); err != nil {
		return MaterializeReceipt{}, errors.Join(ErrDestinationChanged, err)
	}
	head, err := gitOutput(ctx, destination, nil, "rev-parse", "--verify", "HEAD")
	if err != nil || head != capture.Manifest.Git.Base {
		return MaterializeReceipt{}, ErrDestinationChanged
	}
	status, err := gitBytes(ctx, destination, nil, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil || len(status) != 0 {
		return MaterializeReceipt{}, ErrDestinationChanged
	}
	directory := filepath.Join(s.Root, "checkpoints", capture.ID)
	destinationFD, err := unix.Open(destination, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return MaterializeReceipt{}, err
	}
	defer unix.Close(destinationFD)
	for _, entry := range capture.Manifest.Entries {
		if entry.Index == nil || entry.Index.Kind != "regular" {
			continue
		}
		content, err := readObject(directory, entry.Index.ObjectRef, entry.Index.Digest)
		if err != nil {
			return MaterializeReceipt{}, err
		}
		written, err := gitOutput(ctx, destination, content, "hash-object", "-w", "--stdin")
		if err != nil || written != entry.Index.GitOID {
			return MaterializeReceipt{}, errors.Join(ErrCheckpointCorrupt, err)
		}
	}
	for _, entry := range capture.Manifest.Entries {
		if err := ctx.Err(); err != nil {
			return MaterializeReceipt{}, err
		}
		if err := validateRelativePath(entry.Path); err != nil {
			return MaterializeReceipt{}, err
		}
		parentFD, name, err := openParentBeneath(destinationFD, entry.Path, entry.Worktree != nil)
		if err != nil {
			return MaterializeReceipt{}, err
		}
		if entry.Worktree == nil {
			err := unix.Unlinkat(parentFD, name, 0)
			unix.Close(parentFD)
			if err != nil && !errors.Is(err, unix.ENOENT) {
				return MaterializeReceipt{}, err
			}
			continue
		}
		content, err := readObject(directory, entry.Worktree.ObjectRef, entry.Worktree.Digest)
		if err != nil {
			unix.Close(parentFD)
			return MaterializeReceipt{}, err
		}
		switch entry.Worktree.Kind {
		case "regular":
			if err := atomicReplaceAt(parentFD, name, content, os.FileMode(entry.Worktree.Mode)); err != nil {
				unix.Close(parentFD)
				return MaterializeReceipt{}, err
			}
		case "symlink":
			if !safeSymlink(entry.Path, string(content)) || string(content) != entry.Worktree.LinkTarget {
				unix.Close(parentFD)
				return MaterializeReceipt{}, ErrCheckpointCorrupt
			}
			if err := atomicSymlinkAt(parentFD, name, string(content)); err != nil {
				unix.Close(parentFD)
				return MaterializeReceipt{}, err
			}
		default:
			unix.Close(parentFD)
			return MaterializeReceipt{}, ErrCheckpointCorrupt
		}
		unix.Close(parentFD)
	}
	indexBytes, err := readObject(directory, capture.Manifest.Git.IndexObjectRef, capture.Manifest.Git.IndexDigest)
	if err != nil {
		return MaterializeReceipt{}, err
	}
	indexPath, err := gitOutput(ctx, destination, nil, "rev-parse", "--git-path", "index")
	if err != nil {
		return MaterializeReceipt{}, err
	}
	if !filepath.IsAbs(indexPath) {
		indexPath = filepath.Join(destination, indexPath)
	}
	if err := atomicReplace(indexPath, indexBytes, 0600); err != nil {
		return MaterializeReceipt{}, err
	}
	materializedIndex, err := os.ReadFile(indexPath)
	if err != nil || digestBytes(materializedIndex) != capture.Manifest.Git.IndexDigest {
		return MaterializeReceipt{}, ErrCheckpointCorrupt
	}
	if err := verifyMaterializedTree(destinationFD, capture.Manifest.Entries, true); err != nil {
		return MaterializeReceipt{}, err
	}
	return MaterializeReceipt{
		ManifestDigest: capture.ManifestDigest, DestinationIdentity: request.DestinationIdentity,
		Bytes: capture.Bytes, ObjectCount: capture.ObjectCount,
	}, nil
}

// MaterializeNew seeds the checkpoint's immutable Git base into an exclusive
// empty registry-owned leaf, then delegates index/worktree restoration to the
// ordinary materializer. Checkpoint objects are fully verified before the
// destination is touched.
func (s CheckpointStore) MaterializeNew(ctx context.Context, request MaterializeNewRequest) (MaterializeReceipt, error) {
	if request.SourceIdentity.Equal(request.DestinationIdentity) ||
		request.SourceIdentity.WorkspaceEpoch == request.DestinationIdentity.WorkspaceEpoch {
		return MaterializeReceipt{}, ErrLiveWorkspaceTarget
	}
	capture, err := s.Verify(ctx, request.CheckpointID)
	if err != nil {
		return MaterializeReceipt{}, err
	}
	if !capture.Manifest.Identity.Equal(request.SourceIdentity) {
		return MaterializeReceipt{}, ErrLiveWorkspaceTarget
	}
	source, sourceInfo, err := verifiedOrdinaryRepository(ctx, request.SourceRoot)
	if err != nil {
		return MaterializeReceipt{}, err
	}
	if _, err := gitOutput(ctx, source, nil, "cat-file", "-e", capture.Manifest.Git.Base+"^{commit}"); err != nil {
		return MaterializeReceipt{}, ErrDestinationChanged
	}
	destination, err := filepath.Abs(request.DestinationRoot)
	if err != nil {
		return MaterializeReceipt{}, err
	}
	destination, err = filepath.EvalSymlinks(destination)
	if err != nil {
		return MaterializeReceipt{}, err
	}
	if request.Ownership != nil {
		if err := validateMaterializationTarget(destination, *request.Ownership); err != nil {
			return MaterializeReceipt{}, err
		}
	}
	destinationInfo, err := os.Lstat(destination)
	if err != nil || !destinationInfo.IsDir() || destinationInfo.Mode()&os.ModeSymlink != 0 {
		return MaterializeReceipt{}, errors.Join(ErrDestinationChanged, err)
	}
	entries, err := os.ReadDir(destination)
	if err != nil {
		return MaterializeReceipt{}, errors.Join(ErrDestinationChanged, err)
	}
	if len(entries) != 0 {
		// Prove the content first so a tampered destination is refused without
		// any mode-repair side effect; only then restore umask-reduced modes
		// and re-run the strict verification.
		if _, err := verifyCompletedMaterializationContent(ctx, capture, request.DestinationIdentity, destination); err != nil {
			return MaterializeReceipt{}, err
		}
		if err := repairMaterializedTreeModes(destination, capture.Manifest.Entries); err != nil {
			return MaterializeReceipt{}, err
		}
		receipt, err := verifyCompletedMaterialization(ctx, capture, request.DestinationIdentity, destination)
		if err != nil || request.Ownership == nil {
			return receipt, err
		}
		if err := s.completeMaterializationOwner(ctx, capture, destination, *request.Ownership); err != nil {
			return MaterializeReceipt{}, err
		}
		return receipt, nil
	}
	if os.SameFile(sourceInfo, destinationInfo) {
		return MaterializeReceipt{}, ErrLiveWorkspaceTarget
	}
	if err := cloneWithoutCheckout(ctx, source, destination, s.Root); err != nil {
		return MaterializeReceipt{}, err
	}
	if err := seedBaseTree(ctx, destination, capture.Manifest.Git.Base); err != nil {
		return MaterializeReceipt{}, err
	}
	if changed, err := os.Stat(source); err != nil || !os.SameFile(sourceInfo, changed) {
		return MaterializeReceipt{}, errors.Join(ErrDestinationChanged, err)
	}
	receipt, err := s.Materialize(ctx, MaterializeRequest{
		CheckpointID: request.CheckpointID, SourceIdentity: request.SourceIdentity,
		DestinationIdentity: request.DestinationIdentity, DestinationRoot: destination,
	})
	if err != nil || request.Ownership == nil {
		return receipt, err
	}
	if err := s.completeMaterializationOwner(ctx, capture, destination, *request.Ownership); err != nil {
		return MaterializeReceipt{}, err
	}
	return receipt, nil
}

func verifyCompletedMaterialization(ctx context.Context, capture DurableCapture, destinationIdentity model.ContinuityIdentityV1, destination string) (MaterializeReceipt, error) {
	return verifyCompletedMaterializationMode(ctx, capture, destinationIdentity, destination, true)
}

// verifyCompletedMaterializationContent runs the same integrity checks as
// verifyCompletedMaterialization but tolerates strict-subset (umask-reduced)
// worktree modes. The mode repair runs only after this content pass succeeds.
func verifyCompletedMaterializationContent(ctx context.Context, capture DurableCapture, destinationIdentity model.ContinuityIdentityV1, destination string) (MaterializeReceipt, error) {
	return verifyCompletedMaterializationMode(ctx, capture, destinationIdentity, destination, false)
}

func verifyCompletedMaterializationMode(ctx context.Context, capture DurableCapture, destinationIdentity model.ContinuityIdentityV1, destination string, strictModes bool) (MaterializeReceipt, error) {
	gitDirectory, err := gitOutput(ctx, destination, nil, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return MaterializeReceipt{}, ErrDestinationChanged
	}
	commonDirectory, err := gitOutput(ctx, destination, nil, "rev-parse", "--git-common-dir")
	if err != nil {
		return MaterializeReceipt{}, ErrDestinationChanged
	}
	if !filepath.IsAbs(commonDirectory) {
		commonDirectory = filepath.Join(destination, commonDirectory)
	}
	if err := validateGitLayout(destination, gitDirectory, commonDirectory); err != nil {
		return MaterializeReceipt{}, ErrDestinationChanged
	}
	head, err := gitOutput(ctx, destination, nil, "rev-parse", "--verify", "HEAD")
	if err != nil || head != capture.Manifest.Git.Base {
		return MaterializeReceipt{}, ErrDestinationChanged
	}
	indexPath, err := gitOutput(ctx, destination, nil, "rev-parse", "--git-path", "index")
	if err != nil {
		return MaterializeReceipt{}, ErrDestinationChanged
	}
	if !filepath.IsAbs(indexPath) {
		indexPath = filepath.Join(destination, indexPath)
	}
	index, err := os.ReadFile(indexPath)
	if err != nil || digestBytes(index) != capture.Manifest.Git.IndexDigest {
		return MaterializeReceipt{}, errors.Join(ErrCheckpointCorrupt, err)
	}
	rootFD, err := unix.Open(destination, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return MaterializeReceipt{}, err
	}
	defer unix.Close(rootFD)
	if err := verifyMaterializedTree(rootFD, capture.Manifest.Entries, strictModes); err != nil {
		return MaterializeReceipt{}, err
	}
	expectedFiles := make(map[string]bool)
	expectedDirectories := make(map[string]bool)
	for _, entry := range capture.Manifest.Entries {
		parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(entry.Path)))
		for parent != "." && parent != "" {
			expectedDirectories[parent] = true
			parent = filepath.ToSlash(filepath.Dir(filepath.FromSlash(parent)))
		}
		if entry.Worktree != nil {
			expectedFiles[entry.Path] = true
		}
	}
	err = filepath.WalkDir(destination, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(destination, path)
		if err != nil || relative == "." {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == ".git" {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			if !expectedDirectories[relative] {
				return ErrDestinationChanged
			}
			return nil
		}
		if !expectedFiles[relative] {
			return ErrDestinationChanged
		}
		delete(expectedFiles, relative)
		return nil
	})
	if err != nil || len(expectedFiles) != 0 {
		return MaterializeReceipt{}, errors.Join(ErrDestinationChanged, err)
	}
	return MaterializeReceipt{ManifestDigest: capture.ManifestDigest, DestinationIdentity: destinationIdentity, Bytes: capture.Bytes, ObjectCount: capture.ObjectCount}, nil
}

func verifiedOrdinaryRepository(ctx context.Context, value string) (string, fs.FileInfo, error) {
	root, err := filepath.Abs(value)
	if err != nil {
		return "", nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, errors.Join(ErrUnsupportedGitLayout, err)
	}
	gitDirectory, err := gitOutput(ctx, root, nil, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return "", nil, ErrUnsupportedGitLayout
	}
	commonDirectory, err := gitOutput(ctx, root, nil, "rev-parse", "--git-common-dir")
	if err != nil {
		return "", nil, ErrUnsupportedGitLayout
	}
	if !filepath.IsAbs(commonDirectory) {
		commonDirectory = filepath.Join(root, commonDirectory)
	}
	if err := validateGitLayout(root, gitDirectory, commonDirectory); err != nil {
		return "", nil, err
	}
	return root, info, nil
}

func cloneWithoutCheckout(ctx context.Context, source, destination, privateRoot string) error {
	// A direct local clone starts git-upload-pack in a separate process that
	// does not inherit the exact safe.directory option. Package refs in a
	// private temporary bundle with the verified source as one fixed Git
	// command, then clone that bundle. No source object is hardlinked.
	temporary, err := os.CreateTemp(privateRoot, ".checkpoint-clone-*.bundle")
	if err != nil {
		return err
	}
	bundle := temporary.Name()
	if err := temporary.Close(); err != nil {
		os.Remove(bundle)
		return err
	}
	defer os.Remove(bundle)
	command := exec.CommandContext(ctx, "git", "-c", "safe.directory="+source, "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null", "-c", "core.fsmonitor=false", "bundle", "create", bundle, "--all")
	command.Dir = source
	command.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "LANG=C"}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("seed checkpoint bundle: %s: %w", boundedCheckpointError(output), err)
	}
	command = exec.CommandContext(ctx, "git", "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null", "-c", "core.fsmonitor=false", "clone", "--no-checkout", "--", bundle, destination)
	command.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "LANG=C"}
	output, err = command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("seed checkpoint base: %s: %w", boundedCheckpointError(output), err)
	}
	config := []byte("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n")
	return atomicReplace(filepath.Join(destination, ".git", "config"), config, 0600)
}

func seedBaseTree(ctx context.Context, destination, base string) error {
	if err := atomicReplace(filepath.Join(destination, ".git", "HEAD"), []byte(base+"\n"), 0600); err != nil {
		return err
	}
	if _, err := gitOutput(ctx, destination, nil, "read-tree", base); err != nil {
		return err
	}
	listing, err := gitBytes(ctx, destination, nil, "ls-tree", "-r", "-z", base)
	if err != nil {
		return err
	}
	rootFD, err := unix.Open(destination, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	for _, record := range bytes.Split(listing, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		tab := bytes.IndexByte(record, '\t')
		if tab < 0 {
			return ErrUnsupportedGitLayout
		}
		fields := strings.Fields(string(record[:tab]))
		path := string(record[tab+1:])
		if len(fields) != 3 || fields[1] != "blob" || validateRelativePath(path) != nil || excludedCheckpointPath(path) {
			return ErrUnsupportedGitLayout
		}
		mode, err := strconv.ParseUint(fields[0], 8, 32)
		if err != nil || mode != 0100644 && mode != 0100755 && mode != 0120000 {
			return ErrUnsupportedGitLayout
		}
		content, err := gitBytes(ctx, destination, nil, "cat-file", "blob", fields[2])
		if err != nil {
			return err
		}
		parentFD, name, err := openParentBeneath(rootFD, path, true)
		if err != nil {
			return err
		}
		if mode == 0120000 {
			if !safeSymlink(path, string(content)) {
				unix.Close(parentFD)
				return ErrUnsafeCheckpointEntry
			}
			err = atomicSymlinkAt(parentFD, name, string(content))
		} else {
			permissions := os.FileMode(0600)
			if mode == 0100755 {
				permissions = 0700
			}
			err = atomicReplaceAt(parentFD, name, content, permissions)
		}
		unix.Close(parentFD)
		if err != nil {
			return err
		}
	}
	status, err := gitBytes(ctx, destination, nil, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil || len(status) != 0 {
		return errors.Join(ErrDestinationChanged, err)
	}
	if err := syncDirectory(filepath.Join(destination, ".git")); err != nil {
		return err
	}
	return syncDirectory(destination)
}

func readObject(directory, reference, digest string) ([]byte, error) {
	if !validBlobReference(reference, digest) {
		return nil, ErrCheckpointCorrupt
	}
	content, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(reference)))
	if err != nil || digestBytes(content) != digest {
		return nil, errors.Join(ErrCheckpointCorrupt, err)
	}
	return content, nil
}

func validateGitLayout(root, gitDirectory, commonDirectory string) error {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrUnsupportedGitLayout, err)
	}
	expected := filepath.Join(root, ".git")
	gitInfo, err := os.Lstat(expected)
	if err != nil || !gitInfo.IsDir() || gitInfo.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrUnsupportedGitLayout, err)
	}
	if filepath.Clean(gitDirectory) != expected || filepath.Clean(commonDirectory) != expected {
		return ErrUnsupportedGitLayout
	}
	return nil
}

func validBlobReference(reference, digest string) bool {
	const digestPrefix = "sha256:"
	if !strings.HasPrefix(digest, digestPrefix) || len(digest) != len(digestPrefix)+64 {
		return false
	}
	hexDigest := strings.TrimPrefix(digest, digestPrefix)
	if _, err := hex.DecodeString(hexDigest); err != nil {
		return false
	}
	return reference == "blobs/"+hexDigest
}

// repairMaterializedTreeModes restores worktree modes that an earlier
// materialization created under the packaged daemon umask (warpmetald.service
// runs with UMask=0027). It runs only after the content pass proved the tree
// otherwise intact. Only strict subsets of the captured mode are repaired;
// every other mismatch is left for strict verification to refuse, so a mode is
// never widened.
func repairMaterializedTreeModes(destination string, entries []CheckpointEntryV1) error {
	rootFD, err := unix.Open(destination, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.Join(ErrDestinationChanged, err)
	}
	defer unix.Close(rootFD)
	for _, entry := range entries {
		if entry.Worktree == nil || entry.Worktree.Kind != "regular" {
			continue
		}
		want := entry.Worktree.Mode
		parentFD, name, err := openParentBeneath(rootFD, entry.Path, false)
		if err != nil {
			return errors.Join(ErrDestinationChanged, err)
		}
		var stat unix.Stat_t
		statErr := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if statErr != nil {
			unix.Close(parentFD)
			return errors.Join(ErrDestinationChanged, statErr)
		}
		actual := uint32(stat.Mode) & 0o777
		var chmodErr error
		if actual != want && actual&^want == 0 {
			chmodErr = unix.Fchmodat(parentFD, name, want, 0)
		}
		unix.Close(parentFD)
		if chmodErr != nil {
			return errors.Join(ErrDestinationChanged, chmodErr)
		}
	}
	return nil
}

// verifyMaterializedTree verifies kind, digest, and symlink target for every
// manifest entry. strictModes requires exact captured modes; otherwise a
// strict-subset (umask-reduced) regular-file mode is tolerated so the content
// pass can run before the mode repair.
func verifyMaterializedTree(rootFD int, entries []CheckpointEntryV1, strictModes bool) error {
	for _, entry := range entries {
		if entry.Worktree == nil {
			var stat unix.Stat_t
			err := unix.Fstatat(rootFD, entry.Path, &stat, unix.AT_SYMLINK_NOFOLLOW)
			if err == nil || !errors.Is(err, unix.ENOENT) {
				return errors.Join(ErrCheckpointCorrupt, err)
			}
			continue
		}
		switch entry.Worktree.Kind {
		case "regular":
			content, mode, err := readRegularBeneath(rootFD, entry.Path)
			if err != nil || digestBytes(content) != entry.Worktree.Digest {
				return errors.Join(ErrCheckpointCorrupt, err)
			}
			actual := uint32(mode.Perm())
			if strictModes {
				if actual != entry.Worktree.Mode {
					return ErrCheckpointCorrupt
				}
			} else if actual&^entry.Worktree.Mode != 0 {
				return ErrCheckpointCorrupt
			}
		case "symlink":
			parentFD, name, err := openParentBeneath(rootFD, entry.Path, false)
			if err != nil {
				return errors.Join(ErrCheckpointCorrupt, err)
			}
			buffer := make([]byte, 4096)
			length, readErr := unix.Readlinkat(parentFD, name, buffer)
			unix.Close(parentFD)
			if readErr != nil || string(buffer[:length]) != entry.Worktree.LinkTarget ||
				digestBytes(buffer[:length]) != entry.Worktree.Digest {
				return errors.Join(ErrCheckpointCorrupt, readErr)
			}
		default:
			return ErrCheckpointCorrupt
		}
	}
	return nil
}

func readRegularBeneath(rootFD int, relative string) ([]byte, os.FileMode, error) {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	current, err := unix.Dup(rootFD)
	if err != nil {
		return nil, 0, err
	}
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			unix.Close(current)
			return nil, 0, err
		}
		unix.Close(current)
		current = next
	}
	fd, err := unix.Openat(current, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	unix.Close(current)
	if err != nil {
		return nil, 0, err
	}
	file := os.NewFile(uintptr(fd), relative)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || hardlinked(before) {
		return nil, 0, ErrUnsafeCheckpointEntry
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, 0, err
	}
	after, err := file.Stat()
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) ||
		before.Mode() != after.Mode() {
		return nil, 0, ErrUnsafeCheckpointEntry
	}
	return content, before.Mode(), nil
}

func hardlinked(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink > 1
}

func safeSymlink(path, target string) bool {
	if target == "" || filepath.IsAbs(target) || strings.ContainsRune(target, 0) {
		return false
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(filepath.FromSlash(path)), target))
	return resolved != ".." && !strings.HasPrefix(resolved, ".."+string(os.PathSeparator))
}

func validateRelativePath(path string) error {
	if path == "" || filepath.IsAbs(path) || strings.ContainsRune(path, 0) ||
		path == ".." || strings.HasPrefix(filepath.ToSlash(path), "../") ||
		filepath.ToSlash(filepath.Clean(path)) != filepath.ToSlash(path) {
		return fmt.Errorf("%w: invalid path", ErrUnsafeCheckpointEntry)
	}
	return nil
}

func excludedCheckpointPath(path string) bool {
	first := strings.Split(path, "/")[0]
	return first == ".git" || first == ".ssh" || first == ".aws" || first == "node_modules" ||
		path == ".env" || strings.HasPrefix(path, ".env.") || path == ".config/gcloud" ||
		strings.HasPrefix(path, ".config/gcloud/") ||
		// The managed task worktree subtree is private runtime state, not workspace
		// content. Exclude exactly .warpmetal/worktrees (never all of .warpmetal,
		// whose other user files remain captured) from capture and verification.
		path == ".warpmetal/worktrees" || strings.HasPrefix(path, ".warpmetal/worktrees/")
}

func openParentBeneath(rootFD int, relative string, create bool) (int, string, error) {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) == 0 || parts[len(parts)-1] == "" {
		return -1, "", ErrUnsafeCheckpointEntry
	}
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(current, part, 0700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				unix.Close(current)
				return -1, "", mkdirErr
			}
			next, openErr = unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			unix.Close(current)
			return -1, "", errors.Join(ErrUnsafeCheckpointEntry, openErr)
		}
		unix.Close(current)
		current = next
	}
	return current, parts[len(parts)-1], nil
}

func atomicReplaceAt(parentFD int, name string, content []byte, mode os.FileMode) error {
	temporary := ".warpmetal-materialize-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fd, err := unix.Openat(parentFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = unix.Unlinkat(parentFD, temporary, 0)
		}
	}()
	// The packaged daemon runs with a restrictive umask, so force the exact
	// captured mode instead of relying on the creation mode.
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(parentFD, temporary, parentFD, name); err != nil {
		return err
	}
	removeTemporary = false
	return unix.Fsync(parentFD)
}

func atomicSymlinkAt(parentFD int, name, target string) error {
	temporary := ".warpmetal-link-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := unix.Symlinkat(target, parentFD, temporary); err != nil {
		return err
	}
	defer unix.Unlinkat(parentFD, temporary, 0)
	if err := unix.Renameat(parentFD, temporary, parentFD, name); err != nil {
		return err
	}
	return unix.Fsync(parentFD)
}

func atomicReplace(path string, content []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".warpmetal-materialize-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode.Perm()); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func atomicSymlink(path, target string) error {
	temporary := filepath.Join(filepath.Dir(path), ".warpmetal-link-"+strconv.FormatInt(time.Now().UnixNano(), 36))
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func writeDurableFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func gitOutput(ctx context.Context, root string, stdin []byte, arguments ...string) (string, error) {
	output, err := gitBytes(ctx, root, stdin, arguments...)
	return string(bytes.TrimSpace(output)), err
}

func gitBytes(ctx context.Context, root string, stdin []byte, arguments ...string) ([]byte, error) {
	fixed := []string{"-c", "safe.directory=" + root, "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null", "-c", "core.fsmonitor=false"}
	fixed = append(fixed, arguments...)
	command := exec.CommandContext(ctx, "git", fixed...)
	command.Dir = root
	command.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "LANG=C"}
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git %s failed: %s: %w", arguments[0], boundedCheckpointError(output), err)
	}
	return output, nil
}

func boundedCheckpointError(output []byte) string {
	message := strings.TrimSpace(string(output))
	if len(message) > 300 {
		message = message[:300]
	}
	return message
}

func digestBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateObjectID(value string) error {
	if !strings.HasPrefix(value, "capture_") || len(value) != len("capture_")+32 {
		return ErrCheckpointCorrupt
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "capture_"))
	if err != nil {
		return ErrCheckpointCorrupt
	}
	return nil
}

func (s CheckpointStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
