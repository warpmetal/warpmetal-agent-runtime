//go:build darwin

package sourcebridge

import (
	"golang.org/x/sys/unix"
	"net"
)

func socketPeer(conn *net.UnixConn) (Peer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var peer Peer
	var inner error
	err = raw.Control(func(fd uintptr) {
		pid, e := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if e != nil {
			inner = e
			return
		}
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		inner = e
		if e == nil && cred.Ngroups > 0 {
			peer = Peer{PID: pid, UID: cred.Uid, GID: cred.Groups[0]}
		}
	})
	if err != nil {
		return Peer{}, err
	}
	return peer, inner
}
