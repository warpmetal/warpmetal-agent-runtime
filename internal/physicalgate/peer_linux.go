//go:build linux

package physicalgate

import (
	"golang.org/x/sys/unix"
	"syscall"
)

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
		u, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		inner = e
		if e == nil {
			p = Peer{PID: int(u.Pid), UID: u.Uid, GID: u.Gid}
		}
	})
	if err != nil {
		return p, err
	}
	return p, inner
}
