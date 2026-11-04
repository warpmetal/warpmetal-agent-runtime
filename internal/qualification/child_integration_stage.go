package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"golang.org/x/sys/unix"
)

type integrationStage struct {
	EntryDigest        string `json:"entryDigest"`
	GenerationDigest   string `json:"generationDigest"`
	DeliveryPlanDigest string `json:"deliveryPlanDigest"`
	InputID            string `json:"inputId"`
	InputDigest        string `json:"inputDigest"`
	TargetDetailDigest string `json:"targetDetailDigest"`
	ContainerRoot      string `json:"containerRoot"`
	RootAttestation    string `json:"rootAttestation"`
	RootDevice         uint64 `json:"rootDevice"`
	RootInode          uint64 `json:"rootInode"`
	SourcePath         string `json:"sourcePath"`
	SourceDigest       string `json:"sourceDigest"`
	ByteCount          int    `json:"byteCount"`
	SourceDevice       uint64 `json:"sourceDevice"`
	SourceInode        uint64 `json:"sourceInode"`
}

func integrationStageName(w ChildProductWitness, c ChildProductControl) string {
	return "integration-stage-" + w.Preparation.PreparationID + "-" + c.Generation.Policy.Payload.IntegrationDelivery.DeliveryPlanDigest[7:]
}

func integrationStageClaim(w ChildProductWitness, c ChildProductControl, root TrustedWorkspace, detail json.RawMessage, body []byte) (integrationStage, error) {
	var out integrationStage
	target, err := c.IntegrationTarget()
	if err != nil || verifyIntegrationProductInput(c.Generation.PreparationPolicy.Payload, c.Generation.Policy.Payload, w, time.Now()) != nil || workflowcontract.Validate(workflowcontract.Domain, "resultDetail", detail) != nil {
		return out, ErrUntrusted
	}
	q := c.Generation.Policy.Payload
	d := q.IntegrationDelivery
	if verifyTargetArtifactOriginal(d.Target, d.TargetBinding, target.Artifact, detail, body) != nil {
		return out, ErrUntrusted
	}
	artifact := childFields(target.Artifact)
	if len(body) < 1 || len(body) > 8192 || int64(len(body)) != childInteger(artifact, "byteCount") || Digest(body) != target.Reference.SourceDigest || childString(artifact, "digest") != Digest(body) ||
		root.WorkspaceDigest != q.Root.Workspace.RootAttestation || root.Device == 0 || root.Inode == 0 || root.HostRoot == "" || root.ContainerRoot == "" ||
		CanonicalDigest(map[string]any{"directory": root.ContainerRoot, "projectId": childString(childFields(q.Binding), "nativeProjectId"), "workspaceId": nil}) != childString(childFields(q.Binding), "nativeLocationDigest") {
		return out, ErrUntrusted
	}
	out = integrationStage{EntryDigest: CanonicalDigest(w.Entry), GenerationDigest: c.Descriptor.GenerationDigest, DeliveryPlanDigest: d.DeliveryPlanDigest,
		InputID: d.InputID, InputDigest: d.InputDigest, TargetDetailDigest: CanonicalDigest(detail), ContainerRoot: root.ContainerRoot,
		RootAttestation: root.WorkspaceDigest, RootDevice: root.Device, RootInode: root.Inode, SourcePath: target.Reference.Path, SourceDigest: Digest(body), ByteCount: len(body)}
	return out, nil
}

// The selected parent directory must already exist under the registered root.
// Only an absent leaf may be created; a symlink/different current file denies.
func createIntegrationLeaf(ctx context.Context, root TrustedWorkspace, relative string, body []byte, uid uint32) error {
	if ctx.Err() != nil || relative == "" || strings.HasPrefix(relative, "/") || strings.ContainsAny(relative, "\\\x00") {
		return ErrUntrusted
	}
	parts := strings.Split(relative, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return ErrUntrusted
		}
	}
	held, err := confinedRoot(root.HostRoot, root.Device, root.Inode)
	if err != nil {
		return err
	}
	defer held.Close()
	fd, err := unix.Dup(int(held.Fd()))
	if err != nil {
		return err
	}
	defer func() { unix.Close(fd) }()
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return ErrUntrusted
		}
		unix.Close(fd)
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != root.Device {
			return ErrUntrusted
		}
	}
	leaf, err := unix.Openat(fd, parts[len(parts)-1], unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if errors.Is(err, unix.EEXIST) {
		return nil
	} // Exact existing bytes are checked below; never overwrite.
	if err != nil {
		return ErrUntrusted
	}
	file := os.NewFile(uintptr(leaf), relative)
	defer file.Close()
	if unix.Fchown(leaf, int(uid), -1) != nil || ctx.Err() != nil {
		return ErrUntrusted
	}
	if n, e := file.Write(body); e != nil || n != len(body) || file.Sync() != nil || unix.Fsync(fd) != nil {
		return ErrUntrusted
	}
	return nil
}

func stageIntegrationTarget(ctx context.Context, w ChildProductWitness, c ChildProductControl, root TrustedWorkspace, detail json.RawMessage, body []byte, journal workflowObservationJournal, uid uint32) (integrationStage, error) {
	var empty integrationStage
	claim, err := integrationStageClaim(w, c, root, detail, body)
	if err != nil {
		return empty, err
	}
	name := integrationStageName(w, c)
	if raw, e := journal.load(name+".json", 65536); e == nil {
		var prior integrationStage
		if decode(raw, &prior) != nil || !bytesCanonical(raw, prior) {
			return empty, ErrUntrusted
		}
		base := prior
		base.SourceDevice = 0
		base.SourceInode = 0
		originalClaim, ce := journal.load(name+"-claim.json", 65536)
		oldDetail, de := journal.load(name+"-target.json", 65536)
		oldBody, be := journal.load(name+"-target.body", 8192)
		actual, re := readPlanSourceFile(ctx, root, claim.SourcePath, claim.ByteCount, claim.SourceDigest)
		if !sameProduct(base, claim) || ce != nil || !bytes.Equal(originalClaim, canonicalBytes(claim)) || de != nil || be != nil || !bytes.Equal(oldDetail, canonicalBytes(detail)) || !bytes.Equal(oldBody, body) || re != nil || actual.device != prior.SourceDevice || actual.inode != prior.SourceInode {
			return empty, ErrUntrusted
		}
		return prior, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return empty, ErrUntrusted
	}
	// An interrupted prior claim is UNKNOWN; do not recreate success or retry.
	if journal.create(name+"-claim.json", canonicalBytes(claim)) != nil || journal.create(name+"-target.json", canonicalBytes(detail)) != nil || journal.create(name+"-target.body", body) != nil {
		return empty, ErrUntrusted
	}
	if createIntegrationLeaf(ctx, root, claim.SourcePath, body, uid) != nil {
		return empty, ErrUntrusted
	}
	actual, err := readPlanSourceFile(ctx, root, claim.SourcePath, claim.ByteCount, claim.SourceDigest)
	if err != nil {
		return empty, err
	}
	claim.SourceDevice = actual.device
	claim.SourceInode = actual.inode
	if ctx.Err() != nil || journal.create(name+".json", canonicalBytes(claim)) != nil {
		return empty, ErrUntrusted
	}
	return claim, nil
}
