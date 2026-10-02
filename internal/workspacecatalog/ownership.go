package workspacecatalog

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type workspaceOwner struct{ uid, gid uint32 }

func ownerOf(file *os.File) (workspaceOwner, unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return workspaceOwner{}, stat, err
	}
	return workspaceOwner{stat.Uid, stat.Gid}, stat, nil
}

func sameOwner(file *os.File, owner workspaceOwner) bool {
	current, _, err := ownerOf(file)
	return err == nil && current == owner
}

func chownOpened(file *os.File, owner workspaceOwner) error {
	if !sameOwner(file, owner) {
		if err := unix.Fchown(int(file.Fd()), int(owner.uid), int(owner.gid)); err != nil {
			return err
		}
	}
	if !sameOwner(file, owner) {
		return ErrProjectChanged
	}
	return file.Sync()
}

// A root-owned shared projects directory may be the old Runtime's output.
// Require every existing direct child to be a recorded allocation before
// changing that parent. An already correctly owned parent may contain user
// projects and is deliberately left alone.
func (c Catalog) projectsOwnerPreflight(ctx context.Context, projects *os.File, anchorIdentity fileIdentity, anchorPath string, target workspaceOwner) (bool, error) {
	current, stat, err := ownerOf(projects)
	if err != nil || stat.Mode&0777 != 0700 {
		return false, ErrUnsafeProjectRoot
	}
	if current == target {
		return false, nil
	}
	if current.uid != 0 {
		return false, ErrUnsafeProjectRoot
	}
	entries, err := projects.ReadDir(-1)
	if err != nil || len(entries) > maxCatalogEntries {
		return false, ErrUnsafeProjectRoot
	}
	records, err := c.State.ManagedProjects(ctx)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !safeComponent.MatchString(entry.Name()) {
			return false, ErrUnsafeProjectRoot
		}
		path := filepath.Join(filepath.Clean(anchorPath), "projects", entry.Name())
		var attributed *state.LocalManagedProject
		for index := range records {
			record := &records[index]
			if record.HostRoot == path && record.Anchor == filepath.Clean(anchorPath) &&
				record.AnchorDevice == anchorIdentity.Device && record.AnchorInode == anchorIdentity.Inode &&
				record.RootInode != 0 && attest(*record) == record.Report.RootAttestation {
				attributed = record
				break
			}
		}
		if attributed == nil {
			return false, ErrUnsafeProjectRoot
		}
		child, err := openDirectoryAt(projects, entry.Name())
		if err != nil {
			return false, ErrUnsafeProjectRoot
		}
		identity, identityErr := identityForFile(child)
		child.Close()
		if identityErr != nil || !sameMount(anchorIdentity, identity) ||
			!sameDurableObject(attributed.RootDevice, attributed.RootInode, identity) {
			return false, ErrUnsafeProjectRoot
		}
	}
	return true, nil
}

func (c Catalog) ensureProjectsOwner(ctx context.Context, anchor, projects *os.File, anchorIdentity fileIdentity, anchorPath string) error {
	target, _, err := ownerOf(anchor)
	if err != nil {
		return ErrUnsafeProjectRoot
	}
	change, err := c.projectsOwnerPreflight(ctx, projects, anchorIdentity, anchorPath, target)
	if err != nil {
		return err
	}
	if change {
		if err := chownOpened(projects, target); err != nil {
			return ErrUnsafeProjectRoot
		}
	}
	return nil
}

func verifyPublishedOwner(record state.LocalManagedProject) error {
	anchor, anchorIdentity, err := openDirectoryNoFollow(record.Anchor)
	if err != nil || !sameDurableObject(record.AnchorDevice, record.AnchorInode, anchorIdentity) {
		if anchor != nil {
			anchor.Close()
		}
		return ErrProjectChanged
	}
	defer anchor.Close()
	owner, _, err := ownerOf(anchor)
	if err != nil {
		return ErrProjectChanged
	}
	projects, err := openDirectoryAt(anchor, "projects")
	if err != nil {
		return ErrProjectChanged
	}
	defer projects.Close()
	projectsIdentity, err := identityForFile(projects)
	if err != nil || !sameMount(anchorIdentity, projectsIdentity) || !sameOwner(projects, owner) {
		return ErrProjectChanged
	}
	root, _, err := openVerifiedRoot(record)
	if err != nil {
		return err
	}
	defer root.Close()
	if !sameOwner(root, owner) {
		return ErrProjectChanged
	}
	return nil
}

func (c Catalog) repairDefaultOwner(ctx context.Context, record state.LocalManagedProject) error {
	anchor, anchorIdentity, err := openDirectoryNoFollow(record.Anchor)
	if err != nil || !sameDurableObject(record.AnchorDevice, record.AnchorInode, anchorIdentity) {
		if anchor != nil {
			anchor.Close()
		}
		return ErrProjectChanged
	}
	defer anchor.Close()
	target, _, err := ownerOf(anchor)
	if err != nil {
		return ErrProjectChanged
	}
	projects, err := openDirectoryAt(anchor, "projects")
	if err != nil {
		return ErrProjectChanged
	}
	defer projects.Close()
	root, _, err := openVerifiedRoot(record)
	if err != nil {
		return err
	}
	defer root.Close()
	if sameOwner(root, target) && sameOwner(projects, target) {
		return nil
	}
	return c.ownDefaultBootstrap(ctx, record)
}

type bootstrapNode struct {
	file *os.File
	mode uint32
}

func (c Catalog) ownDefaultBootstrap(ctx context.Context, record state.LocalManagedProject) error {
	if record.Report.Designation != "team_project" || record.AllocationDigest == "" || record.RootInode == 0 ||
		(record.Phase != "created" && record.Phase != "ready") || attest(record) != record.Report.RootAttestation {
		return ErrProjectChanged
	}
	anchor, anchorIdentity, err := openDirectoryNoFollow(record.Anchor)
	if err != nil || !sameDurableObject(record.AnchorDevice, record.AnchorInode, anchorIdentity) {
		if anchor != nil {
			anchor.Close()
		}
		return ErrProjectChanged
	}
	defer anchor.Close()
	target, _, err := ownerOf(anchor)
	if err != nil {
		return ErrProjectChanged
	}
	projects, err := openDirectoryAt(anchor, "projects")
	if err != nil {
		return ErrProjectChanged
	}
	defer projects.Close()
	projectsIdentity, err := identityForFile(projects)
	if err != nil || !sameMount(anchorIdentity, projectsIdentity) {
		return ErrProjectChanged
	}
	changeProjects, err := c.projectsOwnerPreflight(ctx, projects, anchorIdentity, record.Anchor, target)
	if err != nil {
		return ErrProjectChanged
	}
	root, rootIdentity, err := openVerifiedRoot(record)
	if err != nil {
		return err
	}
	defer root.Close()
	nodes, err := preflightBootstrap(root, rootIdentity, target)
	if err != nil {
		return ErrProjectChanged
	}
	defer func() {
		for _, node := range nodes[1:] {
			node.file.Close()
		}
	}()
	// Every byte, entry, owner, mode, inode, and mount is checked before the
	// first mutation. The leaf and then shared parent are transferred last.
	for index := len(nodes) - 1; index >= 1; index-- {
		if err := chownOpened(nodes[index].file, target); err != nil {
			return ErrProjectChanged
		}
	}
	if err := chownOpened(root, target); err != nil {
		return ErrProjectChanged
	}
	if changeProjects {
		if err := chownOpened(projects, target); err != nil {
			return ErrProjectChanged
		}
	}
	if err := verifyPublishedOwner(record); err != nil {
		return err
	}
	return nil
}

func preflightBootstrap(root *os.File, mount fileIdentity, target workspaceOwner) ([]bootstrapNode, error) {
	var nodes []bootstrapNode
	closeOnError := true
	defer func() {
		if closeOnError {
			for _, node := range nodes {
				if node.file != root {
					node.file.Close()
				}
			}
		}
	}()
	add := func(file *os.File, mode uint32) error {
		identity, err := identityForFile(file)
		if err != nil || !sameMount(mount, identity) {
			return ErrProjectChanged
		}
		owner, stat, err := ownerOf(file)
		actualMode := uint32(stat.Mode & 0777)
		// The packaged service uses UMask=0027. Its immutable Git objects
		// therefore retain 0440, while older/default-mask bootstraps use 0444.
		modeMatches := actualMode == mode || mode == 0444 && actualMode == 0440
		if err != nil || !modeMatches || (owner.uid != 0 && owner != target) ||
			(owner.uid == target.uid && owner.gid != target.gid) ||
			(stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink != 1) {
			return ErrProjectChanged
		}
		nodes = append(nodes, bootstrapNode{file, mode})
		return nil
	}
	openDir := func(parent *os.File, name string) (*os.File, error) {
		file, err := openDirectoryAt(parent, name)
		if err != nil {
			return nil, err
		}
		if err := add(file, 0700); err != nil {
			file.Close()
			return nil, err
		}
		return file, nil
	}
	openFile := func(parent *os.File, name string, mode uint32) (*os.File, error) {
		file, err := openRegularAt(parent, name, mount)
		if err != nil {
			return nil, err
		}
		if err := add(file, mode); err != nil {
			file.Close()
			return nil, err
		}
		return file, nil
	}
	if err := add(root, 0700); err != nil || exactEntries(root, ".git") != nil {
		return nil, ErrProjectChanged
	}
	git, err := openDir(root, ".git")
	if err != nil || exactEntries(git, "HEAD", "config", "index", "objects", "refs") != nil {
		return nil, ErrProjectChanged
	}
	for name, want := range map[string]string{
		"HEAD":   "ref: refs/heads/main\n",
		"config": "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n",
	} {
		file, err := openFile(git, name, 0600)
		if err != nil {
			return nil, err
		}
		value, err := readBounded(file, 256)
		if err != nil || value != want {
			return nil, ErrProjectChanged
		}
	}
	index, err := openFile(git, "index", 0600)
	if err != nil {
		return nil, err
	}
	indexBytes, err := io.ReadAll(io.LimitReader(index, 33))
	header := make([]byte, 12)
	copy(header, "DIRC")
	binary.BigEndian.PutUint32(header[4:8], 2)
	checksum := sha1.Sum(header)
	if err != nil || !bytes.Equal(indexBytes, append(header, checksum[:]...)) {
		return nil, ErrProjectChanged
	}
	refs, err := openDir(git, "refs")
	if err != nil || exactEntries(refs, "heads", "tags") != nil {
		return nil, ErrProjectChanged
	}
	heads, err := openDir(refs, "heads")
	if err != nil || exactEntries(heads, "main") != nil {
		return nil, ErrProjectChanged
	}
	tags, err := openDir(refs, "tags")
	if err != nil || exactEntries(tags) != nil {
		return nil, ErrProjectChanged
	}
	mainRef, err := openFile(heads, "main", 0600)
	if err != nil {
		return nil, err
	}
	refText, err := readBounded(mainRef, 41)
	commitID := strings.TrimSuffix(refText, "\n")
	if err != nil || len(commitID) != 40 || refText != commitID+"\n" || !isHex40(commitID) {
		return nil, ErrProjectChanged
	}
	treeHash := sha1.Sum([]byte("tree 0\x00"))
	treeID := hex.EncodeToString(treeHash[:])
	objects, err := openDir(git, "objects")
	if err != nil {
		return nil, err
	}
	wants := map[string][]string{}
	for _, id := range []string{treeID, commitID} {
		wants[id[:2]] = append(wants[id[:2]], id[2:])
	}
	prefixes := make([]string, 0, len(wants))
	for prefix := range wants {
		prefixes = append(prefixes, prefix)
	}
	if err := exactEntries(objects, prefixes...); err != nil {
		return nil, err
	}
	for _, prefix := range prefixes {
		directory, err := openDir(objects, prefix)
		if err != nil || exactEntries(directory, wants[prefix]...) != nil {
			return nil, ErrProjectChanged
		}
		for _, suffix := range wants[prefix] {
			file, err := openFile(directory, suffix, 0444)
			if err != nil {
				return nil, err
			}
			id := prefix + suffix
			payload, err := readGitObject(file, id)
			if err != nil {
				return nil, err
			}
			if id == treeID && string(payload) != "tree 0\x00" || id == commitID && !validInitialCommit(payload, treeID) {
				return nil, ErrProjectChanged
			}
		}
	}
	closeOnError = false
	return nodes, nil
}

func exactEntries(directory *os.File, expected ...string) error {
	if directory == nil {
		return ErrProjectChanged
	}
	entries, err := directory.ReadDir(-1)
	if err != nil || len(entries) != len(expected) {
		return ErrProjectChanged
	}
	actual := make([]string, len(entries))
	for index, entry := range entries {
		actual[index] = entry.Name()
	}
	sort.Strings(actual)
	sort.Strings(expected)
	for index := range actual {
		if actual[index] != expected[index] {
			return ErrProjectChanged
		}
	}
	return nil
}

func isHex40(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func readGitObject(file *os.File, expectedID string) ([]byte, error) {
	compressed, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(compressed) > 4096 {
		return nil, ErrProjectChanged
	}
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, ErrProjectChanged
	}
	defer reader.Close()
	payload, err := io.ReadAll(io.LimitReader(reader, 2049))
	if err != nil || len(payload) > 2048 {
		return nil, ErrProjectChanged
	}
	hash := sha1.Sum(payload)
	if hex.EncodeToString(hash[:]) != expectedID {
		return nil, ErrProjectChanged
	}
	var exact bytes.Buffer
	writer := zlib.NewWriter(&exact)
	if _, err := writer.Write(payload); err != nil {
		return nil, ErrProjectChanged
	}
	if err := writer.Close(); err != nil || !bytes.Equal(compressed, exact.Bytes()) {
		return nil, ErrProjectChanged
	}
	return payload, nil
}

func validInitialCommit(payload []byte, treeID string) bool {
	boundary := bytes.IndexByte(payload, 0)
	if boundary < 0 || string(payload[:boundary]) != fmt.Sprintf("commit %d", len(payload)-boundary-1) {
		return false
	}
	body := strings.Split(string(payload[boundary+1:]), "\n")
	if len(body) != 6 || body[0] != "tree "+treeID || body[3] != "" || body[4] != "Initial project" || body[5] != "" {
		return false
	}
	author := "author WarpMetal Runtime <runtime@localhost> "
	committer := "committer WarpMetal Runtime <runtime@localhost> "
	if !strings.HasPrefix(body[1], author) || !strings.HasPrefix(body[2], committer) {
		return false
	}
	timePart := strings.TrimPrefix(body[1], author)
	if !strings.HasSuffix(timePart, " +0000") || strings.TrimPrefix(body[2], committer) != timePart {
		return false
	}
	for _, digit := range strings.TrimSuffix(timePart, " +0000") {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
