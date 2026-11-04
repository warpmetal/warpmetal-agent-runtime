//go:build linux

package physicalgate

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Root host observation is selected ONLY by the FIRST owning registration. The
// tracked identities come from the immutable pre-cancel cut, not shell/PID ACKs.
func observeRegisteredSourceKernel(n NativeRegistration, tracked []ProcessIdentity) (SourceKernelCut, error) {
	cut := SourceKernelCut{Caller: n.Caller.Subject(), StatOriginals: map[int]string{}, SocketOriginals: map[int][]string{}}
	native, err := processIdentity(n.Native.PID)
	if err != nil || !reflect.DeepEqual(native, n.Native) {
		return cut, ErrPrerequisite
	}
	cut.Native = native
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return cut, ErrPrerequisite
	}
	parents := map[int][]int{}
	parentSnapshot := map[int]int{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(proc(pid, "stat"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return cut, ErrPrerequisite
		}
		end := strings.LastIndexByte(string(raw), ')')
		if end < 0 {
			return cut, ErrPrerequisite
		}
		fields := strings.Fields(string(raw[end+1:]))
		if len(fields) < 20 {
			return cut, ErrPrerequisite
		}
		parent, err := strconv.Atoi(fields[1])
		if err != nil {
			return cut, ErrPrerequisite
		}
		parents[parent] = append(parents[parent], pid)
		parentSnapshot[pid] = parent
	}
	pending := []int{native.PID}
	seen := map[int]bool{}
	for len(pending) > 0 {
		pid := pending[0]
		pending = pending[1:]
		if seen[pid] || len(seen) >= 128 {
			return cut, ErrPrerequisite
		}
		seen[pid] = true
		identity, err := processIdentity(pid)
		if err != nil {
			return cut, err
		}
		// Jail namespaces may legitimately differ for native tool descendants.
		// Owning ancestry is kernel-observed, not a same-namespace guess. An exit
		// or reparent during the capture invalidates the cut instead of hiding it.
		if identity.ParentPID != parentSnapshot[pid] {
			return cut, ErrPrerequisite
		}
		raw, err := os.ReadFile(proc(pid, "stat"))
		if err != nil || len(raw) > 32768 {
			return cut, ErrPrerequisite
		}
		// Zombies and transitions during the two kernel reads are not exit proof.
		end := strings.LastIndexByte(string(raw), ')')
		if end < 0 {
			return cut, ErrPrerequisite
		}
		fields := strings.Fields(string(raw[end+1:]))
		if len(fields) < 20 || fields[0] == "Z" {
			return cut, ErrPrerequisite
		}
		start, err := strconv.ParseUint(fields[19], 10, 64)
		if err != nil || start != identity.StartTime {
			return cut, ErrPrerequisite
		}
		cut.StatOriginals[pid] = string(raw)
		fds, err := os.ReadDir(proc(pid, "fd"))
		if err != nil || len(fds) > 1024 {
			return cut, ErrPrerequisite
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(proc(pid, "fd"), fd.Name()))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return cut, ErrPrerequisite
			}
			if strings.HasPrefix(target, "socket:[") {
				cut.SocketOriginals[pid] = append(cut.SocketOriginals[pid], fd.Name()+"="+target)
			}
		}
		if pid != native.PID {
			cut.Descendants = append(cut.Descendants, identity)
		}
		pending = append(pending, parents[pid]...)
	}
	sort.Slice(cut.Descendants, func(i, j int) bool { return cut.Descendants[i].PID < cut.Descendants[j].PID })
	for _, table := range []string{"net/tcp", "net/tcp6"} {
		raw, err := os.ReadFile(proc(native.PID, table))
		if err != nil {
			return cut, ErrPrerequisite
		}
		connections, err := sourceProcConnections(raw, cut.SocketOriginals[native.PID])
		if err != nil {
			return cut, err
		}
		cut.NativeConnections = append(cut.NativeConnections, connections...)
	}
	for _, original := range tracked {
		_, err := os.Stat(proc(original.PID, "stat"))
		if errors.Is(err, os.ErrNotExist) {
			cut.TrackedExited = append(cut.TrackedExited, original)
			continue
		}
		// Reparented, PID-reused, inaccessible or still-running tracked descendants
		// cannot disappear just because the present root tree no longer lists them.
		return cut, ErrPrerequisite
	}
	again, err := processIdentity(native.PID)
	if err != nil || !reflect.DeepEqual(native, again) {
		return cut, ErrPrerequisite
	}
	cut.ObservedAt = time.Now().UTC()
	return cut, boundedSourceKernel(cut)
}
