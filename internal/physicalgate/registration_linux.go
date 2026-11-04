//go:build linux

package physicalgate

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
)

const bridgePath = "/usr/local/libexec/warpmetal-agent-cells/warpmetal_physical_gate.py"

func observeOwnAccessProcess() (ProcessIdentity, error) {
	p, err := processIdentity(os.Getpid())
	if err != nil || p.UID != 0 || p.GID != uint32(os.Getgid()) {
		return ProcessIdentity{}, ErrPrerequisite
	}
	return p, nil
}

func proc(pid int, name string) string { return fmt.Sprintf("/proc/%d/%s", pid, name) }
func processIdentity(pid int) (ProcessIdentity, error) {
	var p ProcessIdentity
	p.PID = pid
	stat, e := os.ReadFile(proc(pid, "stat"))
	if e != nil {
		return p, ErrPrerequisite
	}
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return p, ErrPrerequisite
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return p, ErrPrerequisite
	}
	p.ParentPID, e = strconv.Atoi(fields[1])
	if e != nil {
		return p, ErrPrerequisite
	}
	p.StartTime, e = strconv.ParseUint(fields[19], 10, 64)
	if e != nil {
		return p, ErrPrerequisite
	}
	status, e := os.ReadFile(proc(pid, "status"))
	if e != nil {
		return p, ErrPrerequisite
	}
	haveUID, haveGID := false, false
	for _, l := range strings.Split(string(status), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "Uid:", "Gid:":
			if len(f) != 5 {
				return p, ErrPrerequisite
			}
			for _, v := range f[2:] {
				if v != f[1] {
					return p, ErrPrerequisite
				}
			}
			v, e := strconv.ParseUint(f[1], 10, 32)
			if e != nil {
				return p, ErrPrerequisite
			}
			if f[0] == "Uid:" {
				p.UID = uint32(v)
				haveUID = true
			} else {
				p.GID = uint32(v)
				haveGID = true
			}
		case "NSpid:":
			p.ContainerPID, e = strconv.Atoi(f[len(f)-1])
			if e != nil {
				return p, ErrPrerequisite
			}
		}
	}
	if !haveUID || !haveGID || p.ContainerPID < 1 {
		return p, ErrPrerequisite
	}
	p.Namespaces = map[string]string{}
	for _, n := range []string{"pid", "user", "mnt", "net", "ipc", "uts"} {
		v, e := os.Readlink(proc(pid, "ns/"+n))
		if e != nil {
			return p, ErrPrerequisite
		}
		p.Namespaces[n] = v
	}
	c, e := os.ReadFile(proc(pid, "cgroup"))
	if e != nil || len(c) == 0 {
		return p, ErrPrerequisite
	}
	p.Cgroup = string(c)
	f, e := os.Open(proc(pid, "exe"))
	if e != nil {
		return p, ErrPrerequisite
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > 256*1024*1024 {
		return p, ErrPrerequisite
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, 256*1024*1024+1)); e != nil {
		return p, ErrPrerequisite
	}
	p.ExecutableDigest = fmt.Sprintf("sha256:%x", h.Sum(nil))
	p.ExecutableDevice = uint64(st.Dev)
	p.ExecutableInode = st.Ino
	return p, nil
}

// Fixed image-owned helper/interpreter measurement. proc/<pid>/root is a kernel
// link, not a client path; reject client-writable/symlink helper ancestry.
func imageDigest(pid int, name string) (string, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return "", ErrPrerequisite
	}
	root, e := unix.Open(proc(pid, "root"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", ErrPrerequisite
	}
	defer unix.Close(root)
	fd, e := unix.Dup(root)
	if e != nil {
		return "", ErrPrerequisite
	}
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if e != nil {
			return "", ErrPrerequisite
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&0022 != 0 {
			unix.Close(fd)
			return "", ErrPrerequisite
		}
		// Root inside the current user namespace maps to a subordinate uid,
		// never the model/native UID. Verify via kernel uid_map, not guessed 0.
		maps, e := os.ReadFile(proc(pid, "uid_map"))
		if e != nil {
			unix.Close(fd)
			return "", ErrPrerequisite
		}
		rootUID := uint64(0)
		found := false
		for _, line := range strings.Split(string(maps), "\n") {
			f := strings.Fields(line)
			if len(f) == 3 && f[0] == "0" {
				rootUID, e = strconv.ParseUint(f[1], 10, 32)
				found = e == nil
			}
		}
		if !found || uint64(st.Uid) != rootUID {
			unix.Close(fd)
			return "", ErrPrerequisite
		}
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 256*1024*1024 {
		return "", ErrPrerequisite
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, 256*1024*1024+1)); e != nil {
		return "", ErrPrerequisite
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
func observeNativeProcess(c ContainerObservation, containerPID int) (ProcessIdentity, string, string, error) {
	init, e := processIdentity(c.InitPID)
	if e != nil {
		return ProcessIdentity{}, "", "", e
	}
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return ProcessIdentity{}, "", "", e
	}
	var found *ProcessIdentity
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		// Filter from kernel namespace/status before hashing a process executable.
		// This is observation, never a body-supplied identity shortcut.
		pidNS, e := os.Readlink(proc(pid, "ns/pid"))
		if e != nil || pidNS != init.Namespaces["pid"] {
			continue
		}
		status, e := os.ReadFile(proc(pid, "status"))
		if e != nil {
			continue
		}
		matches := false
		for _, line := range strings.Split(string(status), "\n") {
			f := strings.Fields(line)
			if len(f) > 1 && f[0] == "NSpid:" {
				v, err := strconv.Atoi(f[len(f)-1])
				matches = err == nil && v == containerPID
			}
		}
		if !matches {
			continue
		}
		p, e := processIdentity(pid)
		if e != nil || p.ContainerPID != containerPID || !reflect.DeepEqual(p.Namespaces, init.Namespaces) {
			continue
		}
		if found != nil {
			return ProcessIdentity{}, "", "", ErrPrerequisite
		}
		copy := p
		found = &copy
	}
	if found == nil {
		return ProcessIdentity{}, "", "", ErrPrerequisite
	}
	args, e := os.ReadFile(proc(found.PID, "cmdline"))
	if e != nil || !bytes.Contains(args, []byte("\x00serve\x00")) || !bytes.Contains(args, []byte("\x00--persist-events\x00")) {
		return ProcessIdentity{}, "", "", ErrPrerequisite
	}
	// Actual interpreter inode path follows the image's fixed python3 alias once;
	// resolve via the kernel link, then verify the canonical image-owned target.
	alias, e := os.Readlink(proc(found.PID, "root/usr/bin/python3"))
	if e != nil {
		return ProcessIdentity{}, "", "", ErrPrerequisite
	}
	if !filepath.IsAbs(alias) {
		alias = filepath.Join("/usr/bin", alias)
	}
	interpreter, e := imageDigest(found.PID, alias)
	if e != nil {
		return ProcessIdentity{}, "", "", e
	}
	bridge, e := imageDigest(found.PID, bridgePath)
	if e != nil {
		return ProcessIdentity{}, "", "", e
	}
	return *found, interpreter, bridge, nil
}

func holdNativePeer(peer Peer, n NativeRegistration) (func() error, func(), error) {
	fd, err := unix.PidfdOpen(peer.PID, 0)
	if err != nil {
		return nil, nil, ErrPrerequisite
	}
	nfd, err := unix.PidfdOpen(n.Native.PID, 0)
	if err != nil {
		unix.Close(fd)
		return nil, nil, ErrPrerequisite
	}
	close := func() { unix.Close(fd); unix.Close(nfd) }
	check := func() error {
		for _, f := range []int{fd, nfd} {
			fds := []unix.PollFd{{Fd: int32(f), Events: unix.POLLIN}}
			if _, err := unix.Poll(fds, 0); err != nil || fds[0].Revents != 0 {
				return ErrPrerequisite
			}
		}
		return verifyNativePeer(peer, n)
	}
	if err = check(); err != nil {
		close()
		return nil, nil, err
	}
	return check, close, nil
}
func verifyNativePeer(peer Peer, n NativeRegistration) error {
	fd, e := unix.PidfdOpen(peer.PID, 0)
	if e != nil {
		return ErrPrerequisite
	}
	defer unix.Close(fd)
	nfd, e := unix.PidfdOpen(n.Native.PID, 0)
	if e != nil {
		return ErrPrerequisite
	}
	defer unix.Close(nfd)
	p, e := processIdentity(peer.PID)
	if e != nil || p.UID != peer.UID || p.GID != peer.GID || p.UID != n.Native.UID || p.GID != n.Native.GID || !reflect.DeepEqual(p.Namespaces, n.Native.Namespaces) || p.Cgroup != n.Native.Cgroup || p.ExecutableDigest != n.InterpreterDigest || p.ParentPID != n.Native.PID {
		return ErrPrerequisite
	}
	endpoint, e := os.Stat(proc(peer.PID, "root") + ContainerDirectory)
	if e != nil {
		return ErrPrerequisite
	}
	endpointStat, ok := endpoint.Sys().(*syscall.Stat_t)
	if !ok || uint64(endpointStat.Dev) != n.Container.EndpointDevice || endpointStat.Ino != n.Container.EndpointInode {
		return ErrPrerequisite
	}
	args, e := os.ReadFile(proc(peer.PID, "cmdline"))
	if e != nil {
		return ErrPrerequisite
	}
	tokens := bytes.Split(bytes.TrimSuffix(args, []byte{0}), []byte{0})
	if len(tokens) != 3 || string(tokens[0]) != "/usr/bin/python3" || string(tokens[1]) != "-I" || string(tokens[2]) != bridgePath {
		return ErrPrerequisite
	}
	bridge, e := imageDigest(peer.PID, bridgePath)
	if e != nil || bridge != n.BridgeDigest {
		return ErrPrerequisite
	}
	actual, e := processIdentity(n.Native.PID)
	if e != nil || !reflect.DeepEqual(actual, n.Native) {
		return ErrPrerequisite
	}
	again, e := processIdentity(peer.PID)
	if e != nil || !reflect.DeepEqual(again, p) {
		return ErrPrerequisite
	}
	for _, pidfd := range []int{fd, nfd} {
		fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		if _, e = unix.Poll(fds, 0); e != nil || fds[0].Revents != 0 {
			return ErrPrerequisite
		}
	}
	return nil
}

const journalDirectory = "/home/agent/.warpmetal/opencode/qualification/real-provider"

func readNativePhysicalJournal(n NativeRegistration, operation, suffix string, maximum int) ([]byte, error) {
	if !model.PhysicalIDValid(operation) {
		return nil, ErrPrerequisite
	}
	fd, e := unix.Open(proc(n.Native.PID, "root"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrPrerequisite
	}
	parts := strings.Split(strings.TrimPrefix(journalDirectory, "/"), "/")
	parts = append(parts, "gate-"+operation+suffix)
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if e != nil {
			return nil, ErrPrerequisite
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			unix.Close(fd)
			return nil, ErrPrerequisite
		}
		if i >= 2 && (st.Uid != n.Native.UID || st.Mode&0077 != 0) {
			unix.Close(fd)
			return nil, ErrPrerequisite
		}
		if i == len(parts)-1 && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size > int64(maximum)) {
			unix.Close(fd)
			return nil, ErrPrerequisite
		}
	}
	f := os.NewFile(uintptr(fd), "native-private-physical-evidence")
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return nil, ErrPrerequisite
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(maximum)+1))
	after, e2 := f.Stat()
	if e != nil || e2 != nil || len(raw) > maximum || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, ErrPrerequisite
	}
	return raw, nil
}
func verifiedNativeSettlementOriginals(n NativeRegistration, o state.PhysicalOperation, e model.PhysicalSettlement) (state.NativeSettlementOriginals, error) {
	var empty state.NativeSettlementOriginals
	request, err := readNativePhysicalJournal(n, o.OperationID, "-request.body", 32768)
	if err != nil || model.RawPhysicalDigest(request) != o.Permit.Request.RequestDigest {
		return empty, ErrPrerequisite
	}
	response, err := readNativePhysicalJournal(n, o.OperationID, "-response.body", 262144)
	if err != nil || model.RawPhysicalDigest(response) != e.ResponseDigest || len(response) != e.ResponseByteCount {
		return empty, ErrPrerequisite
	}
	raw, err := readNativePhysicalJournal(n, o.OperationID, "-completion.json", 65536)
	if err != nil || model.RawPhysicalDigest(raw) != e.EvidenceDigest {
		return empty, ErrPrerequisite
	}
	var observed struct {
		RequestDigest     string `json:"requestDigest"`
		ResponseDigest    string `json:"responseDigest"`
		ResponseByteCount int    `json:"responseByteCount"`
		HTTPStatus        int    `json:"httpStatus"`
		UsageUsdMicros    int64  `json:"usageUsdMicros"`
	}
	if model.DecodePhysicalClosed(raw, &observed) != nil || observed.RequestDigest != e.RequestDigest || observed.ResponseDigest != e.ResponseDigest || observed.ResponseByteCount != e.ResponseByteCount || observed.HTTPStatus != e.HTTPStatus || observed.UsageUsdMicros != e.UsageUsdMicros || e.UsageUsdMicros > state.PhysicalReservationUsdMicros {
		return empty, ErrPrerequisite
	}
	// Metadata alone cannot authenticate a price. Join ORIGINAL whole completed
	// response usage at the frozen consumer tariff; missing/ambiguous stays unknown.
	if o.Permit.Case.AccountingVersion == 2 {
		_, cost, usageErr := ProviderResponseUsage(o.Permit.Case.ProviderPolicyDigest, response, e.HTTPStatus)
		if usageErr != nil || cost != e.UsageUsdMicros {
			return empty, ErrPrerequisite
		}
	} else if err = verifyOriginalUsage(o.Permit.Request.Consumer, response, e.HTTPStatus, e.UsageUsdMicros); err != nil {
		return empty, err
	}
	journal, err := readNativePhysicalJournal(n, o.OperationID, "-admission.json", 65536)
	var admitted model.PhysicalAdmitRequest
	if err != nil || model.DecodePhysicalClosed(journal, &admitted) != nil || !reflect.DeepEqual(admitted, o.Permit.Request) {
		return empty, ErrPrerequisite
	}
	var transport, providerResponse []byte
	providerRequestID := ""
	if o.Permit.Case.AccountingVersion == 2 {
		transport, err = readNativePhysicalJournal(n, o.OperationID, "-transport.json", 1024)
		var observed struct{ Method, URL, BodyDigest string }
		if err != nil || model.DecodePhysicalClosed(transport, &observed) != nil || observed.Method != "POST" || observed.URL != "https://api.deepseek.com/responses" || observed.BodyDigest != e.RequestDigest {
			return empty, ErrPrerequisite
		}
		providerResponse, err = readNativePhysicalJournal(n, o.OperationID, "-provider-response.json", 2048)
		var metadata struct {
			FormatVersion     int    `json:"formatVersion"`
			ProviderRequestID string `json:"providerRequestId"`
		}
		if err != nil || model.DecodePhysicalClosed(providerResponse, &metadata) != nil || metadata.FormatVersion != 1 || !model.PhysicalIDValid(metadata.ProviderRequestID) || len(metadata.ProviderRequestID) > 128 {
			return empty, ErrPrerequisite
		}
		providerRequestID = metadata.ProviderRequestID
	}
	return state.NativeSettlementOriginals{Journal: journal, Request: request, Response: response, Completion: raw, Transport: transport, ProviderResponse: providerResponse, ProviderRequestID: providerRequestID}, nil
}

func verifiedNativeAdmissionOriginal(n NativeRegistration, id string, request model.PhysicalAdmitRequest) ([]byte, error) {
	original, err := readNativePhysicalJournal(n, id, "-request.body", 32768)
	if err != nil || len(original) == 0 || model.RawPhysicalDigest(original) != request.RequestDigest {
		return nil, ErrPrerequisite
	}
	admission, err := readNativePhysicalJournal(n, id, "-admission.json", 65536)
	var recorded model.PhysicalAdmitRequest
	if err != nil || model.DecodePhysicalClosed(admission, &recorded) != nil || !reflect.DeepEqual(recorded, request) {
		return nil, ErrPrerequisite
	}
	return original, nil
}
