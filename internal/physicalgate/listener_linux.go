//go:build linux

package physicalgate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func endpointOwner() (uint32, error) {
	u, e := user.Lookup("warpmetal-runtime")
	if e != nil {
		return 0, ErrPrerequisite
	}
	gid, e := strconv.ParseUint(u.Gid, 10, 32)
	return uint32(gid), e
}
func EndpointIdentity() (uint64, uint64, error) {
	gid, e := endpointOwner()
	if e != nil {
		return 0, 0, e
	}
	var device, inode uint64
	for p := HostDirectory; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return 0, 0, ErrPrerequisite
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 0 || st.Mode().Perm()&0022 != 0 {
			return 0, 0, ErrPrerequisite
		}
		if p == HostDirectory {
			if s.Gid != gid || st.Mode().Perm() != 0750 {
				return 0, 0, ErrPrerequisite
			}
			device, inode = uint64(s.Dev), s.Ino
		}
		if p == "/" {
			return device, inode, nil
		}
	}
}

type listenerIdentity struct{ Device, Inode uint64 }

// Only Runtime root writes this dedicated directory; neither DB nor credentials
// are delivered. Safe stale-listener replacement never touches ledger ownership.
func ListenProtected() (*net.UnixListener, error) {
	gid, e := endpointOwner()
	if e != nil {
		return nil, e
	}
	if e = os.Mkdir(HostDirectory, 0750); e == nil {
		if e = os.Chown(HostDirectory, 0, int(gid)); e != nil {
			return nil, e
		}
	} else if !os.IsExist(e) {
		return nil, e
	}
	if _, _, e = EndpointIdentity(); e != nil {
		return nil, e
	}
	marker := filepath.Join(HostDirectory, "listener.json")
	if st, e := os.Lstat(HostSocket); e == nil {
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || st.Mode()&os.ModeSocket == 0 || s.Uid != 0 || s.Gid != gid || st.Mode().Perm() != 0660 {
			return nil, ErrPrerequisite
		}
		m, e := os.Lstat(marker)
		if e != nil || !m.Mode().IsRegular() || m.Mode().Perm() != 0600 || m.Sys().(*syscall.Stat_t).Uid != 0 {
			return nil, ErrPrerequisite
		}
		raw, e := os.ReadFile(marker)
		var own listenerIdentity
		if e != nil || json.Unmarshal(raw, &own) != nil || own.Device != uint64(s.Dev) || own.Inode != s.Ino {
			return nil, ErrPrerequisite
		}
		c, e := net.DialTimeout("unix", HostSocket, time.Second)
		if e == nil {
			c.Close()
			return nil, ErrPrerequisite
		}
		if !errors.Is(e, syscall.ECONNREFUSED) {
			return nil, ErrPrerequisite
		}
		if e = os.Remove(HostSocket); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: HostSocket, Net: "unix"})
	if e != nil {
		return nil, e
	}
	l.SetUnlinkOnClose(false)
	if e = os.Chown(HostSocket, 0, int(gid)); e != nil {
		l.Close()
		return nil, e
	}
	if e = os.Chmod(HostSocket, 0660); e != nil {
		l.Close()
		return nil, e
	}
	st, e := os.Lstat(HostSocket)
	if e != nil {
		l.Close()
		return nil, e
	}
	s := st.Sys().(*syscall.Stat_t)
	raw, _ := json.Marshal(listenerIdentity{uint64(s.Dev), s.Ino})
	// Retain every ownership record. The pointer can change, not its history.
	name := filepath.Join(HostDirectory, fmt.Sprintf("listener-%d-%d.json", s.Dev, s.Ino))
	f, e := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		l.Close()
		return nil, e
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		l.Close()
		return nil, e
	}
	if e = os.Rename(name, marker+".next"); e != nil {
		l.Close()
		return nil, e
	}
	// Keep an immutable copy as well as the current pointer.
	if e = os.Link(marker+".next", name); e != nil {
		l.Close()
		return nil, e
	}
	if e = os.Rename(marker+".next", marker); e != nil {
		l.Close()
		return nil, e
	}
	d, e := os.Open(HostDirectory)
	if e == nil {
		e = d.Sync()
		d.Close()
	}
	if e != nil {
		l.Close()
		return nil, e
	}
	return l, nil
}
