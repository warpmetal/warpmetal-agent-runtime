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

func readXattrs(file *os.File) (map[string][]byte, error) {
	fd := int(file.Fd())
	size, err := unix.Flistxattr(fd, nil)
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
	size, err = unix.Flistxattr(fd, namesBuffer)
	if err != nil {
		return nil, err
	}
	names := strings.Split(strings.TrimSuffix(string(namesBuffer[:size]), "\x00"), "\x00")
	sort.Strings(names)
	result := make(map[string][]byte, len(names))
	for _, name := range names {
		valueSize, err := unix.Fgetxattr(fd, name, nil)
		if err != nil {
			return nil, err
		}
		value := make([]byte, valueSize)
		if valueSize > 0 {
			valueSize, err = unix.Fgetxattr(fd, name, value)
			if err != nil {
				return nil, err
			}
			value = value[:valueSize]
		}
		result[name] = value
	}
	return result, nil
}

func readMetadata(file *os.File) (fileMetadata, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return fileMetadata{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fileMetadata{}, errors.New("not a regular file")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fileMetadata{}, err
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return fileMetadata{}, err
	}
	xattrs, err := readXattrs(file)
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

func openForMetadata(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOATIME|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("could not create file handle")
	}
	return file, nil
}

func readPathMetadata(path string) (metadata fileMetadata, err error) {
	file, err := openForMetadata(path)
	if err != nil {
		return fileMetadata{}, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	return readMetadata(file)
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

func comparePaths(leftPath, rightPath string) error {
	left, err := readPathMetadata(leftPath)
	if err != nil {
		return err
	}
	right, err := readPathMetadata(rightPath)
	if err != nil {
		return err
	}
	if !equalMetadata(left, right) {
		return errors.New("metadata mismatch")
	}
	return nil
}

func copyPath(sourcePath, destinationPath string) (err error) {
	source, err := openForMetadata(sourcePath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := source.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	before, err := readMetadata(source)
	if err != nil {
		return err
	}

	destinationFD, err := unix.Open(
		destinationPath,
		unix.O_RDWR|unix.O_CLOEXEC|unix.O_CREAT|unix.O_EXCL|unix.O_NOATIME|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return err
	}
	destination := os.NewFile(uintptr(destinationFD), destinationPath)
	if destination == nil {
		_ = unix.Close(destinationFD)
		return errors.New("could not create destination file handle")
	}
	defer func() {
		if closeErr := destination.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	if _, err = destination.Write(before.content); err != nil {
		return err
	}
	if err = unix.Fchown(destinationFD, int(before.uid), int(before.gid)); err != nil {
		return err
	}

	// Default ACLs and security policy may attach attributes at create time.
	// Remove the complete inherited set before applying the source set so the
	// final map is exact rather than additive.
	inherited, err := readXattrs(destination)
	if err != nil {
		return err
	}
	for name := range inherited {
		if err = unix.Fremovexattr(destinationFD, name); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(before.xattrs))
	for name := range before.xattrs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err = unix.Fsetxattr(destinationFD, name, before.xattrs[name], 0); err != nil {
			return err
		}
	}
	if err = unix.Fchmod(destinationFD, before.mode&^uint32(unix.S_IFMT)); err != nil {
		return err
	}
	if err = unix.UtimesNanoAt(destinationFD, "", []unix.Timespec{
		unix.NsecToTimespec(before.atimeNS),
		unix.NsecToTimespec(before.mtimeNS),
	}, unix.AT_EMPTY_PATH); err != nil {
		return err
	}
	if err = destination.Sync(); err != nil {
		return err
	}

	after, err := readMetadata(source)
	if err != nil {
		return err
	}
	if !equalMetadata(before, after) {
		return errors.New("source mutated during copy")
	}
	copied, err := readMetadata(destination)
	if err != nil {
		return err
	}
	if !equalMetadata(before, copied) {
		return errors.New("copied metadata mismatch")
	}
	return nil
}

func run(args []string) error {
	if len(args) != 3 {
		return errors.New("invalid arguments")
	}
	switch args[0] {
	case "compare":
		return comparePaths(args[1], args[2])
	case "copy":
		return copyPath(args[1], args[2])
	default:
		return errors.New("invalid arguments")
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "runtime_apparmor_policy_metadata_mismatch")
		os.Exit(1)
	}
}
