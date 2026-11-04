package qualification

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// The existing candidate/archive verifier's retained approved facts are joined
// before entry. Recheck its same raw DER P-256/SHA256 archive semantics against
// the independently selected PUBLIC anchor, then supplement the unique regular
// Runtime daemon measurement (the older candidate verifier does not provide it).
// No extraction, installer, enrollment script, subprocess or signing occurs.
func (p *Producer) verifyPlanReaderArchive(ctx context.Context, a PlanReaderAdoption) error {
	anchor, err := p.read("plan-source-reader-trust-anchor.pem", 4096)
	if err != nil || Digest(anchor) != a.TrustAnchorDigest {
		return ErrUntrusted
	}
	block, rest := pem.Decode(anchor)
	if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
		return ErrUntrusted
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ErrUntrusted
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve.Params().Name != "P-256" {
		return ErrUntrusted
	}
	signature, err := loadPlanReaderEvidence(p.read, a.RuntimeSignature, 4096)
	if err != nil {
		return err
	}
	target := filepath.Join(p.config.EvidenceRoot, a.RuntimeArchive.Name)
	if rootPrivate(target, false) != nil {
		return ErrUntrusted
	}
	fd, err := unix.Open(target, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return ErrUntrusted
	}
	f := os.NewFile(uintptr(fd), target)
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != a.RuntimeArchive.ByteCount {
		return ErrUntrusted
	}
	h := sha256.New()
	count, err := io.Copy(h, io.LimitReader(f, 256*1024*1024+1))
	if err != nil || ctx.Err() != nil || count != a.RuntimeArchive.ByteCount || "sha256:"+hex.EncodeToString(h.Sum(nil)) != a.RuntimeArchive.Digest || !ecdsa.VerifyASN1(key, h.Sum(nil), signature) {
		return ErrUntrusted
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return ErrUntrusted
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		return ErrUntrusted
	}
	defer gz.Close()
	// The archive is read only; hardlinks/symlinks/special/PAX members and
	// duplicate/escaping paths cannot stand in for an actual regular daemon.
	tr := tar.NewReader(io.LimitReader(gz, 512*1024*1024+1))
	seen := make(map[string]bool)
	found := false
	var total int64
	prefix := "warpmetal-runtime-" + a.RuntimeVersion + "-linux-amd64/"
	for n := 0; ; n++ {
		header, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil || n >= 4096 || ctx.Err() != nil {
			return ErrUntrusted
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00") ||
			(name != strings.TrimSuffix(prefix, "/") && !strings.HasPrefix(name, prefix)) || seen[name] ||
			(header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir) || header.Size < 0 || header.Size > 256*1024*1024 {
			return ErrUntrusted
		}
		seen[name] = true
		total += header.Size
		if total > 512*1024*1024 {
			return ErrUntrusted
		}
		if name != a.RuntimeBinaryMember {
			continue
		}
		if found || header.Typeflag != tar.TypeReg || header.Size < 1 {
			return ErrUntrusted
		}
		h = sha256.New()
		if count, e = io.Copy(h, io.LimitReader(tr, header.Size+1)); e != nil || count != header.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != a.RuntimeBinarySHA256 {
			return ErrUntrusted
		}
		found = true
	}
	// Consume gzip trailer/CRC, not merely tar's zero blocks.
	padding, err := io.ReadAll(io.LimitReader(gz, 65537))
	if err != nil || len(padding) > 65536 || len(bytes.Trim(padding, "\x00")) != 0 {
		return ErrUntrusted
	}
	after, err := f.Stat()
	if !found || err != nil || !samePlanFile(before, after) || ctx.Err() != nil {
		return ErrUntrusted
	}
	return nil
}
