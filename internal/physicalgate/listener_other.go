//go:build !linux

package physicalgate

import "net"

func EndpointIdentity() (uint64, uint64, error)   { return 0, 0, ErrPrerequisite }
func ListenProtected() (*net.UnixListener, error) { return nil, ErrPrerequisite }
