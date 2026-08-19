package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var sandboxID = regexp.MustCompile(`^sbx_[A-Za-z0-9_-]{8,60}$`)

type Workspace struct {
	Root  string
	Owner string
}

func (w Workspace) Ensure(ctx context.Context, id string, sizeGiB int) (string, error) {
	directory, err := w.path(id)
	if err != nil {
		return "", err
	}
	ownerUID, ownerGID, err := w.ownerIdentity()
	if err != nil {
		return "", err
	}
	if err := ensureDirectory(filepath.Dir(directory), 0710, 0, ownerGID); err != nil {
		return "", err
	}
	if err := ensureDirectory(directory, 0710, 0, ownerGID); err != nil {
		return "", err
	}
	mountpoint := filepath.Join(directory, "workspace")
	image := filepath.Join(directory, "workspace.ext4")
	if err := os.MkdirAll(mountpoint, 0700); err != nil {
		return "", fmt.Errorf("create workspace mountpoint: %w", err)
	}
	if _, err := os.Stat(image); errors.Is(err, os.ErrNotExist) {
		if err := command(ctx, "truncate", "-s", strconv.Itoa(sizeGiB)+"G", image); err != nil {
			return "", err
		}
		if err := command(ctx, "mkfs.ext4", "-q", "-F", image); err != nil {
			return "", err
		}
		if err := os.Chmod(image, 0600); err != nil {
			return "", fmt.Errorf("protect workspace image: %w", err)
		}
	}
	mounted, err := isMounted(ctx, mountpoint)
	if err != nil {
		return "", err
	}
	if !mounted {
		if err := command(ctx, "mount", "-o", "loop,nodev,nosuid", image, mountpoint); err != nil {
			return "", err
		}
	}
	if err := os.Chown(mountpoint, ownerUID, ownerGID); err != nil {
		return "", fmt.Errorf("own workspace mountpoint: %w", err)
	}
	if err := os.Chmod(mountpoint, 0700); err != nil {
		return "", fmt.Errorf("protect workspace mountpoint: %w", err)
	}
	return mountpoint, nil
}

func (w Workspace) Destroy(ctx context.Context, id string) error {
	directory, err := w.path(id)
	if err != nil {
		return err
	}
	mountpoint := filepath.Join(directory, "workspace")
	mounted, err := isMounted(ctx, mountpoint)
	if err != nil {
		return err
	}
	if mounted {
		if err := command(ctx, "umount", mountpoint); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(directory); err != nil {
		return fmt.Errorf("remove workspace: %w", err)
	}
	return nil
}

func (w Workspace) ownerIdentity() (int, int, error) {
	name := w.Owner
	if name == "" {
		name = "warpmetal-runtime"
	}
	identity, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup workspace owner: %w", err)
	}
	uid, err := strconv.Atoi(identity.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse workspace owner UID: %w", err)
	}
	gid, err := strconv.Atoi(identity.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse workspace owner GID: %w", err)
	}
	return uid, gid, nil
}

func ensureDirectory(path string, mode os.FileMode, uid, gid int) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("create workspace directory: %w", err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("own workspace directory: %w", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("protect workspace directory: %w", err)
	}
	return nil
}

func (w Workspace) path(id string) (string, error) {
	if !sandboxID.MatchString(id) {
		return "", errors.New("invalid sandbox ID")
	}
	root, err := filepath.Abs(w.Root)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "sandboxes", id)
	if !strings.HasPrefix(path, root+string(os.PathSeparator)) {
		return "", errors.New("workspace path escaped state root")
	}
	return path, nil
}

func isMounted(ctx context.Context, path string) (bool, error) {
	cmd := exec.CommandContext(ctx, "mountpoint", "-q", path)
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code := exit.ExitCode()
		if code == 1 || code == 32 {
			return false, nil
		}
	}
	return false, fmt.Errorf("check workspace mount: %w", err)
}

func command(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 300 {
			message = message[:300]
		}
		return fmt.Errorf("%s failed: %s: %w", name, message, err)
	}
	return nil
}
