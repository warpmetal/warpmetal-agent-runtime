//go:build !linux && !darwin

package sourcebridge

import (
	"errors"
	"net"
)

func socketPeer(*net.UnixConn) (Peer, error) {
	return Peer{}, errors.New("SOURCE kernel peer authentication unsupported")
}
