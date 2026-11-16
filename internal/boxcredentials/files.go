package boxcredentials

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// atomicWriteFile replaces path with content through a same-directory temporary
// file, an fsync and an atomic rename. A crash can only leave the previous
// complete file or the new complete file behind, never a truncated private key
// or a half-written envelope document.
func atomicWriteFile(path string, content []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".warpmetal-boxcredentials-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
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
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// readPrivateFile reads a bounded root-only regular file. It refuses symlinks,
// non-regular files, oversized files and files whose mode grants any access to
// group or other, so a mis-provisioned state directory cannot silently expose
// the Box private key or the sealed envelopes.
func readPrivateFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s permissions are too open", filepath.Base(path))
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("%s is too large", filepath.Base(path))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf("%s is too large", filepath.Base(path))
	}
	return content, nil
}

// ensurePrivateDirectory creates the state directory if needed and pins its
// mode to 0700. It refuses a non-directory or a symlinked path.
func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("box credential state path is not a directory")
	}
	return os.Chmod(path, 0o700)
}
