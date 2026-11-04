package qualification

import (
	"bytes"
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// The two contract-fixed private delivery leaves ONLY. No public/caller path
// selector, expanded generic evidence dispatcher or additional ledger.
func (p *Producer) paidDomainDirectory(demand string, create bool) (int, error) {
	if p == nil || !hash.MatchString(demand) || rootPrivate(p.config.EvidenceRoot, true) != nil {
		return -1, ErrUntrusted
	}
	fd, err := unix.Open(p.config.EvidenceRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range []string{"paid-case-domains", demand[7:]} {
		if create {
			if err = unix.Mkdirat(fd, part, 0700); err != nil && !errors.Is(err, syscall.EEXIST) {
				unix.Close(fd)
				return -1, err
			}
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			unix.Close(fd)
			return -1, e
		}
		var st unix.Stat_t
		if unix.Fstat(next, &st) != nil || st.Uid != 0 || st.Mode&0077 != 0 {
			unix.Close(next)
			unix.Close(fd)
			return -1, ErrUntrusted
		}
		if create {
			if e = unix.Fsync(fd); e != nil {
				unix.Close(next)
				unix.Close(fd)
				return -1, e
			}
		}
		unix.Close(fd)
		fd = next
	}
	return fd, nil
}
func paidDomainLeaf(leaf string) bool {
	return leaf == "adoption-envelope.json" || leaf == "acceptance-envelope.json"
}
func (p *Producer) readPaidDomainEnvelope(demand, leaf string) ([]byte, error) {
	if !paidDomainLeaf(leaf) {
		return nil, ErrUntrusted
	}
	dir, e := p.paidDomainDirectory(demand, false)
	if e != nil {
		return nil, e
	}
	defer unix.Close(dir)
	fd, e := unix.Openat(dir, leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "private-paid-domain-original")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0077 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size > 65536 {
		return nil, ErrUntrusted
	}
	raw, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(raw) == 0 || len(raw) > 65536 {
		return nil, ErrUntrusted
	}
	return raw, nil
}
func (p *Producer) retainPaidDomainEnvelope(demand, leaf string, raw []byte) error {
	if !paidDomainLeaf(leaf) || len(raw) == 0 || len(raw) > 65536 {
		return ErrUntrusted
	}
	dir, e := p.paidDomainDirectory(demand, true)
	if e != nil {
		return e
	}
	defer unix.Close(dir)
	fd, e := unix.Openat(dir, leaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if errors.Is(e, syscall.EEXIST) {
		first, err := p.readPaidDomainEnvelope(demand, leaf)
		if err != nil || !bytes.Equal(first, raw) {
			return ErrUntrusted
		}
		return nil
	}
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "private-paid-domain-original")
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	return unix.Fsync(dir)
}
