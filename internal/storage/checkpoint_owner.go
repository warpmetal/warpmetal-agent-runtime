package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type materializedNode struct {
	path  string
	dev   uint64
	inode uint64
	mode  uint32
	uid   uint32
	gid   uint32
	kind  uint32
}

type materializationBoundary struct {
	anchor   *os.File
	projects *os.File
	root     *os.File
	ownerUID uint32
	ownerGID uint32
	dev      uint64
	mount    uint64
}

func (b *materializationBoundary) close() {
	if b.root != nil {
		b.root.Close()
	}
	if b.projects != nil {
		b.projects.Close()
	}
	if b.anchor != nil {
		b.anchor.Close()
	}
}

func openOwnedDirectoryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func openMaterializationBoundary(destination string, authority MaterializationOwnership) (*materializationBoundary, error) {
	if authority.Anchor == "" || !filepath.IsAbs(authority.Anchor) || authority.RootDevice == 0 || authority.RootInode == 0 {
		return nil, ErrDestinationChanged
	}
	leaf := filepath.Base(destination)
	if leaf == "." || leaf == ".." || strings.HasPrefix(leaf, ".") ||
		filepath.Clean(destination) != filepath.Join(filepath.Clean(authority.Anchor), "projects", leaf) {
		return nil, ErrDestinationChanged
	}
	boundary := &materializationBoundary{}
	fail := func() (*materializationBoundary, error) {
		boundary.close()
		return nil, ErrDestinationChanged
	}
	anchorFD, err := unix.Open(authority.Anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrDestinationChanged
	}
	boundary.anchor = os.NewFile(uintptr(anchorFD), authority.Anchor)
	anchor, mount, err := materializedIdentity(boundary.anchor)
	if err != nil || anchor.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fail()
	}
	boundary.ownerUID, boundary.ownerGID, boundary.dev, boundary.mount = anchor.Uid, anchor.Gid, uint64(anchor.Dev), mount
	boundary.projects, err = openOwnedDirectoryAt(boundary.anchor, "projects")
	if err != nil {
		return fail()
	}
	projects, projectsMount, err := materializedIdentity(boundary.projects)
	if err != nil || uint64(projects.Dev) != boundary.dev || projectsMount != mount ||
		projects.Uid != anchor.Uid || projects.Gid != anchor.Gid || projects.Mode&0777 != 0700 {
		return fail()
	}
	boundary.root, err = openOwnedDirectoryAt(boundary.projects, leaf)
	if err != nil {
		return fail()
	}
	root, rootMount, err := materializedIdentity(boundary.root)
	if err != nil || uint64(root.Dev) != authority.RootDevice || root.Ino != authority.RootInode ||
		rootMount != mount || root.Mode&0777 != 0700 ||
		(root.Uid != 0 && (root.Uid != anchor.Uid || root.Gid != anchor.Gid)) {
		return fail()
	}
	return boundary, nil
}

func validateMaterializationTarget(destination string, authority MaterializationOwnership) error {
	boundary, err := openMaterializationBoundary(destination, authority)
	if err != nil {
		return err
	}
	boundary.close()
	return nil
}

func (s CheckpointStore) completeMaterializationOwner(ctx context.Context, capture DurableCapture, destination string, authority MaterializationOwnership) error {
	// MaterializeNew starts from this exact exclusive empty leaf. A replay may
	// reach here only after the full checkpoint is verified again.
	if err := s.VerifyWorkspace(ctx, capture.ID, destination); err != nil {
		return err
	}
	boundary, err := openMaterializationBoundary(destination, authority)
	if err != nil {
		return err
	}
	defer boundary.close()
	allowedLinks := map[string]bool{}
	for _, entry := range capture.Manifest.Entries {
		if entry.Worktree != nil && entry.Worktree.Kind == "symlink" {
			allowedLinks[entry.Path] = true
		}
	}
	nodes := make([]materializedNode, 0, 256)
	if err := preflightMaterializedTree(boundary, boundary.root, "", allowedLinks, &nodes); err != nil {
		return err
	}
	root, _, err := materializedIdentity(boundary.root)
	if err != nil {
		return ErrDestinationChanged
	}
	rootAlreadyOwned := root.Uid == boundary.ownerUID && root.Gid == boundary.ownerGID
	if rootAlreadyOwned {
		for _, node := range nodes {
			if node.kind != unix.S_IFLNK && (node.uid != boundary.ownerUID || node.gid != boundary.ownerGID) {
				return ErrDestinationChanged
			}
		}
	} else {
		// Descendants are changed before the leaf. A partial transfer can be
		// replayed while the root remains inaccessible to the mapped worker.
		sort.Slice(nodes, func(i, j int) bool {
			depthI := strings.Count(nodes[i].path, "/")
			depthJ := strings.Count(nodes[j].path, "/")
			if depthI != depthJ {
				return depthI > depthJ
			}
			return nodes[i].path < nodes[j].path
		})
		for _, node := range nodes {
			if node.kind == unix.S_IFLNK {
				continue
			}
			if err := chownMaterializedNode(boundary, node); err != nil {
				return err
			}
		}
		if err := unix.Fchown(int(boundary.root.Fd()), int(boundary.ownerUID), int(boundary.ownerGID)); err != nil {
			return errors.Join(ErrDestinationChanged, err)
		}
		if err := boundary.root.Sync(); err != nil {
			return errors.Join(ErrDestinationChanged, err)
		}
	}
	if err := validateMaterializationTarget(destination, authority); err != nil {
		return err
	}
	return s.VerifyWorkspace(ctx, capture.ID, destination)
}

func preflightMaterializedTree(boundary *materializationBoundary, directory *os.File, relative string, allowedLinks map[string]bool, nodes *[]materializedNode) error {
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return errors.Join(ErrDestinationChanged, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
			return ErrDestinationChanged
		}
		path := name
		if relative != "" {
			path = relative + "/" + name
		}
		if len(path) > 4096 || len(*nodes) >= 200000 {
			return ErrDestinationChanged
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return ErrDestinationChanged
		}
		kind := uint32(stat.Mode & unix.S_IFMT)
		if kind == unix.S_IFLNK {
			if strings.HasPrefix(path, ".git/") || path == ".git" || !allowedLinks[path] || uint64(stat.Dev) != boundary.dev {
				return ErrDestinationChanged
			}
			*nodes = append(*nodes, materializedNode{path: path, dev: uint64(stat.Dev), inode: stat.Ino, mode: uint32(stat.Mode), uid: stat.Uid, gid: stat.Gid, kind: kind})
			continue
		}
		if kind != unix.S_IFDIR && kind != unix.S_IFREG || stat.Uid != 0 && (stat.Uid != boundary.ownerUID || stat.Gid != boundary.ownerGID) ||
			kind == unix.S_IFREG && stat.Nlink != 1 {
			return ErrDestinationChanged
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if kind == unix.S_IFDIR {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK
		}
		fd, err := unix.Openat(int(directory.Fd()), name, flags, 0)
		if err != nil {
			return ErrDestinationChanged
		}
		child := os.NewFile(uintptr(fd), path)
		opened, mount, err := materializedIdentity(child)
		if err != nil || uint64(opened.Dev) != boundary.dev || mount != boundary.mount || opened.Ino != stat.Ino ||
			opened.Mode != stat.Mode || opened.Nlink != stat.Nlink {
			child.Close()
			return ErrDestinationChanged
		}
		*nodes = append(*nodes, materializedNode{path: path, dev: uint64(stat.Dev), inode: stat.Ino, mode: uint32(stat.Mode), uid: stat.Uid, gid: stat.Gid, kind: kind})
		if kind == unix.S_IFDIR {
			err = preflightMaterializedTree(boundary, child, path, allowedLinks, nodes)
		}
		child.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func chownMaterializedNode(boundary *materializationBoundary, node materializedNode) error {
	parts := strings.Split(node.path, "/")
	current := boundary.root
	opened := make([]*os.File, 0, len(parts))
	defer func() {
		for _, file := range opened {
			file.Close()
		}
	}()
	for index, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if index < len(parts)-1 || node.kind == unix.S_IFDIR {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK
		}
		fd, err := unix.Openat(int(current.Fd()), part, flags, 0)
		if err != nil {
			return ErrDestinationChanged
		}
		current = os.NewFile(uintptr(fd), part)
		opened = append(opened, current)
		stat, mount, err := materializedIdentity(current)
		if err != nil || uint64(stat.Dev) != boundary.dev || mount != boundary.mount {
			return ErrDestinationChanged
		}
		if index == len(parts)-1 && (stat.Ino != node.inode || uint32(stat.Mode) != node.mode ||
			(stat.Uid != 0 && (stat.Uid != boundary.ownerUID || stat.Gid != boundary.ownerGID)) ||
			node.kind == unix.S_IFREG && stat.Nlink != 1) {
			return ErrDestinationChanged
		}
	}
	stat, _, err := materializedIdentity(current)
	if err != nil {
		return ErrDestinationChanged
	}
	if stat.Uid != boundary.ownerUID || stat.Gid != boundary.ownerGID {
		if err := unix.Fchown(int(current.Fd()), int(boundary.ownerUID), int(boundary.ownerGID)); err != nil {
			return errors.Join(ErrDestinationChanged, err)
		}
	}
	if err := current.Sync(); err != nil {
		return errors.Join(ErrDestinationChanged, err)
	}
	return nil
}
