//go:build darwin

package physicalgate

import (
	"golang.org/x/sys/unix"
	"syscall"
)

// Darwin supports the retained local SOURCE test, never installed Linux authority.
func socketPeer(c interface {
	SyscallConn() (syscall.RawConn, error)
}) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var p Peer
	var inner error
	err = raw.Control(func(fd uintptr) {
		pid, e := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		inner = e
		if e != nil {
			return
		}
		u, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		inner = e
		if e == nil {
			p = Peer{PID: pid, UID: u.Uid, GID: u.Groups[0]}
		}
	})
	if err != nil {
		return p, err
	}
	return p, inner
}
