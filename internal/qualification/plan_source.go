package qualification

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"golang.org/x/sys/unix"
)

// Host-private current observations, constructed by registered Runtime/catalog
// consumers, never by the document/request body. Reader must come from actual
// installed/adopted identity, NOT from readOperation.reader or metadata readiness.
type PlanSourceWitness struct {
	Owner           model.ControllerOwner
	Workspace       model.ManagedServiceWorkspaceV1
	Root            TrustedWorkspace
	Reader          model.PlanSourceReader
	RuntimeRevision int64
}

type planReadJournal interface {
	load(string, int) ([]byte, error)
	create(string, []byte) error
}
type producerPlanJournal struct{ p *Producer }

func (j producerPlanJournal) load(name string, limit int) ([]byte, error) {
	if filepath.Base(name) != name {
		return nil, ErrUntrusted
	}
	if _, err := os.Lstat(filepath.Join(j.p.config.EvidenceRoot, name)); err != nil {
		return nil, err
	}
	return j.p.read(name, limit)
}
func (j producerPlanJournal) create(name string, b []byte) error { return j.p.create(name, b) }

type planFileRead struct {
	bytes         []byte
	device, inode uint64
}

// O_NONBLOCK prevents a substituted FIFO/device from blocking before the regular
// leaf check. Every source component is opened relative to a held descriptor.
func openPlanLeaf(root *os.File, path string, device uint64) (*os.File, error) {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\\\x00") {
		return nil, ErrUntrusted
	}
	parts := strings.Split(path, "/")
	fd, err := unix.Dup(int(root.Fd()))
	if err != nil {
		return nil, err
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			unix.Close(fd)
			return nil, ErrUntrusted
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if e != nil {
			return nil, ErrUntrusted
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != device || (i == len(parts)-1 && st.Mode&unix.S_IFMT != unix.S_IFREG) {
			unix.Close(fd)
			return nil, ErrUntrusted
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func samePlanFile(before, after os.FileInfo) bool {
	b, bok := before.Sys().(*syscall.Stat_t)
	a, aok := after.Sys().(*syscall.Stat_t)
	return bok && aok && b.Dev == a.Dev && b.Ino == a.Ino && b.Nlink == a.Nlink && b.Uid == a.Uid && b.Gid == a.Gid &&
		before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime() == after.ModTime() && planChangeTime(b) == planChangeTime(a)
}

func readPlanSourceFile(ctx context.Context, w TrustedWorkspace, path string, count int, digest string) (planFileRead, error) {
	var empty planFileRead
	if count < 1 || count > 262144 || !hash.MatchString(digest) || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	root, err := confinedRoot(w.HostRoot, w.Device, w.Inode)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	rootBefore, err := root.Stat()
	if err != nil {
		return empty, ErrUntrusted
	}
	file, err := openPlanLeaf(root, path, w.Device)
	if err != nil {
		return empty, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || before.Size() != int64(count) || !before.Mode().IsRegular() {
		return empty, ErrUntrusted
	}
	// Count+1 remains checked even if the leaf grows after the initial fstat.
	buffer := make([]byte, count+1)
	used := 0
	for used < len(buffer) {
		if ctx.Err() != nil {
			return empty, ErrUntrusted
		}
		n, e := file.Read(buffer[used:])
		used += n
		if e == io.EOF {
			break
		}
		if e != nil || n == 0 {
			return empty, ErrUntrusted
		}
	}
	if ctx.Err() != nil || used != count || Digest(buffer[:used]) != digest {
		return empty, ErrUntrusted
	}
	after, err := file.Stat()
	if err != nil || !samePlanFile(before, after) {
		return empty, ErrUntrusted
	}
	// Re-prove the current root and entire path, not just the now-open inode.
	currentRoot, err := confinedRoot(w.HostRoot, w.Device, w.Inode)
	if err != nil {
		return empty, err
	}
	defer currentRoot.Close()
	currentRootStat, err := currentRoot.Stat()
	if err != nil || !samePlanFile(rootBefore, currentRootStat) {
		return empty, ErrUntrusted
	}
	current, err := openPlanLeaf(currentRoot, path, w.Device)
	if err != nil {
		return empty, err
	}
	defer current.Close()
	currentStat, err := current.Stat()
	if err != nil || !samePlanFile(before, currentStat) {
		return empty, ErrUntrusted
	}
	st := after.Sys().(*syscall.Stat_t)
	return planFileRead{buffer[:used], uint64(st.Dev), st.Ino}, nil
}

func capturePlanSource(ctx context.Context, op model.PlanSourceReadOperation, w TrustedWorkspace, journal planReadJournal) (model.PlanSourceReadback, error) {
	var empty model.PlanSourceReadback
	if !safeID.MatchString(op.OperationID) || !hash.MatchString(op.OperationDigest) {
		return empty, ErrUntrusted
	}
	expiry, err := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if err != nil || !time.Now().Before(expiry) {
		return empty, ErrUntrusted
	}
	ctx, cancel := context.WithDeadline(ctx, expiry)
	defer cancel()
	ctx, wallCancel := context.WithTimeout(ctx, 30*time.Second)
	defer wallCancel()
	prefix := "plan-source-" + op.OperationID
	claim := canonicalBytes(map[string]string{"operationDigest": op.OperationDigest})
	if retained, e := journal.load(prefix+"-readback.json", 1<<20); e == nil {
		var prior model.PlanSourceReadback
		fence, fe := journal.load(prefix+"-fence.json", 16384)
		if fe != nil || string(fence) != string(claim) || workflowcontract.ValidatePlanRead("readback", retained) != nil || decode(retained, &prior) != nil || model.WorkspaceDigest(prior.Operation) != model.WorkspaceDigest(op) || prior.RootDevice != w.Device || prior.RootInode != w.Inode || prior.ValidateBytes() != nil || !bytesCanonical(retained, prior) {
			return empty, ErrUntrusted
		}
		return prior, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return empty, ErrUntrusted
	}
	if err = journal.create(prefix+"-fence.json", claim); err != nil {
		return empty, ErrUntrusted
	}
	read, err := readPlanSourceFile(ctx, w, op.Document.Source.Reference.Path, op.Document.Source.ByteCount, op.Document.Source.Reference.SourceDigest)
	if err != nil {
		return empty, err
	}
	back := model.PlanSourceReadback{Operation: op, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), RootDevice: w.Device, RootInode: w.Inode,
		SourceDevice: read.device, SourceInode: read.inode, SourceBytesBase64: base64.StdEncoding.EncodeToString(read.bytes)}
	if ctx.Err() != nil || back.ValidateBytes() != nil {
		return empty, ErrUntrusted
	}
	if err = journal.create(prefix+"-readback.json", canonicalBytes(back)); err != nil {
		return empty, err
	}
	return back, nil
}

// Sole operation-specific signer. No supplied readback, arbitrary payload,
// session/preparation, child lineage or model tool can reach this method.
func (p *Producer) ReadPlanSource(ctx context.Context, op model.PlanSourceReadOperation, w PlanSourceWitness) (model.PlanSourceReadEnvelope, error) {
	var empty model.PlanSourceReadEnvelope
	if p == nil || p.key == nil || ctx.Err() != nil || op.Validate() != nil || op.Document.Owner != w.Owner || op.Document.Workspace != w.Workspace ||
		op.Reader != w.Reader || op.RuntimeRevision != w.RuntimeRevision || w.Root.WorkspaceDigest != w.Workspace.RootAttestation ||
		op.Reader.Producer.KeyID != p.config.KeyID || op.Reader.Producer.KeySHA256 != p.config.KeySHA256 || op.Reader.Producer.ServerID != p.config.ServerID || op.Reader.Producer.NodeTokenHash != p.config.NodeTokenHash {
		return empty, ErrUntrusted
	}
	expiry, err := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if err != nil || !time.Now().Before(expiry) {
		return empty, ErrUntrusted
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	root, err := confinedRoot(w.Root.HostRoot, w.Root.Device, w.Root.Inode)
	if err != nil {
		return empty, err
	}
	root.Close()
	prefix := "plan-source-" + op.OperationID
	if prior, err := p.read(prefix+"-envelope.json", 1<<20); err == nil {
		var envelope model.PlanSourceReadEnvelope
		if workflowcontract.ValidatePlanRead("readEnvelope", prior) != nil || decode(prior, &envelope) != nil || envelope.Validate() != nil || model.WorkspaceDigest(envelope.Payload.Readback.Operation) != model.WorkspaceDigest(op) || !bytesCanonical(prior, envelope) ||
			envelope.Payload.Readback.RootDevice != w.Root.Device || envelope.Payload.Readback.RootInode != w.Root.Inode {
			return empty, ErrUntrusted
		}
		body, _ := model.WorkspaceCanonicalJSON(envelope.Payload)
		sum := sha256.Sum256(body)
		sig, _ := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
		back, e := p.read(prefix+"-readback.json", 1<<20)
		fence, fe := p.read(prefix+"-fence.json", 16384)
		if !ecdsa.VerifyASN1(&p.key.PublicKey, sum[:], sig) || e != nil || string(back) != string(canonicalBytes(envelope.Payload.Readback)) ||
			fe != nil || string(fence) != string(canonicalBytes(map[string]string{"operationDigest": op.OperationDigest})) {
			return empty, ErrUntrusted
		}
		return envelope, nil
	} else if _, err = os.Lstat(filepath.Join(p.config.EvidenceRoot, prefix+"-envelope.json")); !errors.Is(err, os.ErrNotExist) {
		return empty, ErrUntrusted
	}
	// A readback without its original envelope is interrupted capture, not a
	// license to sign/re-read on restart. Leave all history untouched.
	if _, err = os.Lstat(filepath.Join(p.config.EvidenceRoot, prefix+"-readback.json")); !errors.Is(err, os.ErrNotExist) {
		return empty, ErrUntrusted
	}
	back, err := capturePlanSource(ctx, op, w.Root, producerPlanJournal{p})
	if err != nil {
		return empty, err
	}
	issued := time.Now().UTC().Format(time.RFC3339Nano)
	payload := model.PlanSourceReadPayload{FormatVersion: 1, Purpose: "workspace_workflow_plan_source_read", RequestID: op.OperationID, OperationID: op.OperationID,
		OperationDigest: op.OperationDigest, TaskID: op.Document.Owner.TaskID, NodeTokenHash: p.config.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: issued, NotAfter: op.ExpiresAt, Readback: back}
	if ctx.Err() != nil || !time.Now().Before(expiry) {
		return empty, ErrUntrusted
	}
	body, err := model.WorkspaceCanonicalJSON(payload)
	if err != nil {
		return empty, err
	}
	sum := sha256.Sum256(body)
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, sum[:])
	if err != nil {
		return empty, err
	}
	envelope := model.PlanSourceReadEnvelope{Payload: payload, KeyID: p.config.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}
	if envelope.Validate() != nil {
		return empty, ErrUntrusted
	}
	if err = p.create(prefix+"-envelope.json", canonicalBytes(envelope)); err != nil {
		return empty, err
	}
	return envelope, nil
}
