package physicalgate

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
)

type SourceTCPConnection struct {
	LocalAddress, RemoteAddress, State, Inode, OriginalRow string
}

func sourceNativeOwnsSocket(cut SourceKernelCut, x SourceExchange) bool {
	for _, connection := range cut.NativeConnections {
		if connection.State != "01" || connection.OriginalRow == "" || !sameSourceAddress(connection.LocalAddress, x.RemoteAddress) || !sameSourceAddress(connection.RemoteAddress, x.LocalAddress) {
			continue
		}
		for _, fd := range cut.SocketOriginals[cut.Native.PID] {
			if strings.HasSuffix(fd, "=socket:["+connection.Inode+"]") {
				return true
			}
		}
	}
	return false
}
func sourceNativeClosedSocket(cut SourceKernelCut, x SourceExchange) bool {
	for _, connection := range cut.NativeConnections {
		// TIME_WAIT has no owning fd. Any still-owned connection to this fixed
		// listener, including an unsolicited reconnect, invalidates quiescence.
		if sameSourceAddress(connection.RemoteAddress, x.LocalAddress) {
			return false
		}
	}
	return true
}
func sameSourceAddress(a, b string) bool {
	ah, ap, e := net.SplitHostPort(a)
	if e != nil {
		return false
	}
	bh, bp, e := net.SplitHostPort(b)
	if e != nil {
		return false
	}
	aIP, bIP := net.ParseIP(ah), net.ParseIP(bh)
	return aIP != nil && bIP != nil && aIP.Equal(bIP) && ap == bp
}

// Linux proc uses native-endian32-bit address words, even for IPv6. Each returned
// tuple must also match the REGISTERED native process's actual fd socket inode.
func sourceProcAddress(raw string) (string, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return "", ErrPrerequisite
	}
	address, err := hex.DecodeString(parts[0])
	if err != nil || (len(address) != 4 && len(address) != 16) {
		return "", ErrPrerequisite
	}
	for i := 0; i < len(address); i += 4 {
		word := binary.NativeEndian.Uint32(address[i : i+4])
		binary.BigEndian.PutUint32(address[i:i+4], word)
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", ErrPrerequisite
	}
	return net.JoinHostPort(net.IP(address).String(), strconv.FormatUint(port, 10)), nil
}
func sourceProcConnections(raw []byte, sockets []string) ([]SourceTCPConnection, error) {
	if len(raw) > 65536 {
		return nil, ErrPrerequisite
	}
	out := []SourceTCPConnection{}
	for index, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if index == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return nil, ErrPrerequisite
		}
		owned := false
		for _, fd := range sockets {
			if strings.HasSuffix(fd, "=socket:["+fields[9]+"]") {
				owned = true
			}
		}
		if !owned {
			continue
		}
		local, err := sourceProcAddress(fields[1])
		if err != nil {
			return nil, err
		}
		remote, err := sourceProcAddress(fields[2])
		if err != nil {
			return nil, err
		}
		out = append(out, SourceTCPConnection{LocalAddress: local, RemoteAddress: remote, State: fields[3], Inode: fields[9], OriginalRow: line})
	}
	return out, nil
}
