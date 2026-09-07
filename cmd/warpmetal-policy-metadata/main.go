//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type fileMetadata struct {
	content []byte
	uid     uint32
	gid     uint32
	mode    uint32
	atimeNS int64
	mtimeNS int64
	xattrs  map[string][]byte
}

func readXattrs(path string) (map[string][]byte, error) {
	size, err := unix.Listxattr(path, nil)
	if errors.Is(err, syscall.ENOTSUP) {
		return map[string][]byte{}, nil
	}
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return map[string][]byte{}, nil
	}
	namesBuffer := make([]byte, size)
	size, err = unix.Listxattr(path, namesBuffer)
	if err != nil {
		return nil, err
	}
	names := strings.Split(strings.TrimSuffix(string(namesBuffer[:size]), "\x00"), "\x00")
	sort.Strings(names)
	result := make(map[string][]byte, len(names))
	for _, name := range names {
		valueSize, err := unix.Getxattr(path, name, nil)
		if err != nil {
			return nil, err
		}
		value := make([]byte, valueSize)
		if valueSize > 0 {
			valueSize, err = unix.Getxattr(path, name, value)
			if err != nil {
				return nil, err
			}
			value = value[:valueSize]
		}
		result[name] = value
	}
	return result, nil
}

func readMetadata(path string) (fileMetadata, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return fileMetadata{}, err
	}
	if !info.Mode().IsRegular() {
		return fileMetadata{}, errors.New("not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileMetadata{}, errors.New("Linux stat metadata unavailable")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOATIME, 0)
	if err != nil {
		return fileMetadata{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return fileMetadata{}, errors.New("could not create file handle")
	}
	content, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil {
		return fileMetadata{}, readErr
	}
	if closeErr != nil {
		return fileMetadata{}, closeErr
	}
	xattrs, err := readXattrs(path)
	if err != nil {
		return fileMetadata{}, err
	}
	return fileMetadata{
		content: content,
		uid:     stat.Uid,
		gid:     stat.Gid,
		mode:    stat.Mode,
		atimeNS: stat.Atim.Sec*1_000_000_000 + stat.Atim.Nsec,
		mtimeNS: stat.Mtim.Sec*1_000_000_000 + stat.Mtim.Nsec,
		xattrs:  xattrs,
	}, nil
}

func equalMetadata(left, right fileMetadata) bool {
	if !bytes.Equal(left.content, right.content) ||
		left.uid != right.uid || left.gid != right.gid || left.mode != right.mode ||
		left.atimeNS != right.atimeNS || left.mtimeNS != right.mtimeNS ||
		len(left.xattrs) != len(right.xattrs) {
		return false
	}
	for name, value := range left.xattrs {
		rightValue, ok := right.xattrs[name]
		if !ok || !bytes.Equal(value, rightValue) {
			return false
		}
	}
	return true
}

func run(args []string) error {
	if len(args) != 3 || args[0] != "compare" {
		return errors.New("invalid arguments")
	}
	left, err := readMetadata(args[1])
	if err != nil {
		return err
	}
	right, err := readMetadata(args[2])
	if err != nil {
		return err
	}
	if !equalMetadata(left, right) {
		return errors.New("metadata mismatch")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "runtime_apparmor_policy_metadata_mismatch")
		os.Exit(1)
	}
}
