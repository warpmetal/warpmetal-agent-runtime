//go:build linux

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
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		inner = e
		if e == nil {
			peer = Peer{PID: int(cred.Pid), UID: cred.Uid, GID: cred.Gid}
		}
	})
	if err != nil {
		return Peer{}, err
	}
	return peer, inner
}
