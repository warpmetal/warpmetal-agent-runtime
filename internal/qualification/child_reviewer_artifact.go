package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Host-private immutable artifact custody, distinct from a live workspace read.
// Directory/body identity describes the producer's private storage only.
type ReviewerArtifactCapture struct {
	OperationDigest    string `json:"operationDigest"`
	EntryDigest        string `json:"entryDigest"`
	GenerationDigest   string `json:"generationDigest"`
	AuthorityDigest    string `json:"authorityDigest"`
	InputID            string `json:"inputId"`
	InputDigest        string `json:"inputDigest"`
	TargetDetailDigest string `json:"targetDetailDigest"`
	DirectoryDevice    uint64 `json:"directoryDevice"`
	DirectoryInode     uint64 `json:"directoryInode"`
	BodyDevice         uint64 `json:"bodyDevice"`
	BodyInode          uint64 `json:"bodyInode"`
	Bytes              []byte `json:"bytes"`
	ObservedAt         string `json:"observedAt"`
}

type reviewerPrivateRead struct {
	planFileRead
	DirectoryDevice, DirectoryInode uint64
}

type reviewerArtifactJournal interface {
	workflowObservationJournal
	readArtifact(context.Context, string, int, string) (reviewerPrivateRead, error)
}

type producerReviewerArtifactJournal struct{ producerPlanJournal }

func (j producerReviewerArtifactJournal) readArtifact(ctx context.Context, name string, count int, digest string) (reviewerPrivateRead, error) {
	var empty reviewerPrivateRead
	root := j.p.config.EvidenceRoot
	if filepath.Base(name) != name || rootPrivate(root, true) != nil || rootPrivate(filepath.Join(root, name), false) != nil {
		return empty, ErrUntrusted
	}
	st, err := os.Lstat(root)
	if err != nil {
		return empty, err
	}
	id, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return empty, ErrUntrusted
	}
	w := TrustedWorkspace{HostRoot: root, Device: uint64(id.Dev), Inode: id.Ino}
	r, err := readPlanSourceFile(ctx, w, name, count, digest)
	if err != nil || rootPrivate(filepath.Join(root, name), false) != nil {
		return empty, ErrUntrusted
	}
	return reviewerPrivateRead{planFileRead: r, DirectoryDevice: w.Device, DirectoryInode: w.Inode}, nil
}

type reviewerArtifactFetch func(context.Context, json.RawMessage, json.RawMessage, string) (json.RawMessage, []byte, error)

func reviewerArtifactName(w ChildProductWitness, c ChildProductControl, op model.WorkflowCaptureOperation) string {
	return "reviewer-artifact-" + CanonicalDigest(map[string]any{"preparationId": w.Preparation.PreparationID, "generationDigest": c.Descriptor.GenerationDigest, "operationId": op.OperationID})[7:]
}

func reviewerArtifactClaim(op model.WorkflowCaptureOperation, w ChildProductWitness, c ChildProductControl) (ReviewerArtifactCapture, error) {
	return reviewerArtifactClaimAt(op, w, c, time.Now())
}
func reviewerArtifactClaimAt(op model.WorkflowCaptureOperation, w ChildProductWitness, c ChildProductControl, now time.Time) (ReviewerArtifactCapture, error) {
	var out ReviewerArtifactCapture
	if c.Generation.Policy == nil || c.Generation.FormatVersion != 5 || c.Generation.Phase != "execute" || c.Descriptor.PolicyDigest == nil ||
		*c.Descriptor.PolicyDigest != CanonicalDigest(c.Generation.Policy.Payload) || c.Descriptor.GenerationDigest != CanonicalDigest(c.Generation) ||
		c.Descriptor.PreparationID != w.Preparation.PreparationID {
		return out, ErrUntrusted
	}
	q := c.Generation.Policy.Payload
	p := c.Generation.PreparationPolicy.Payload
	if verifyReviewerArtifactSelection(p, q, w, now) != nil || w.ReviewCompilation == nil ||
		model.VerifyReviewerInput(*w.ReviewCompilation, *q.ReviewDelivery, string(w.Input), now) != nil ||
		!sameProduct(w.Binding, q.Binding) || !sameProduct(w.Assignment, q.Assignment) || !sameProduct(p.Intent, w.Intent) {
		return out, ErrUntrusted
	}
	call := model.WorkflowCaptureRequest{FormatVersion: 1, RequestID: "reviewer_artifact_read", Binding: q.Binding, Operation: op.Operation}
	if op.ValidateFor(call, w.Root.Producer.NodeTokenHash, w.Root.RuntimeRevision, now) != nil ||
		!sameProduct(op.Binding, q.Binding) || childString(childFields(op.Snapshot), "role") != "reviewer" ||
		childString(childFields(op.Snapshot), "desiredState") != "active" ||
		childInteger(childFields(op.Snapshot), "desiredRevision") != w.Entry.DesiredRevision {
		return out, ErrUntrusted
	}
	a := childFields(q.ArtifactReads[0])
	artifact := childFields(a["artifact"])
	observed := childFields(op.Operation.Observation)
	if childString(observed, "type") != "source_read" || !sameProduct(observed["reference"], a["reference"]) ||
		childString(observed, "observedDigest") != childString(artifact, "digest") || childInteger(observed, "byteCount") != childInteger(artifact, "byteCount") ||
		childString(a, "manifestDigest") != CanonicalDigest([]json.RawMessage{a["artifact"]}) {
		return out, ErrUntrusted
	}
	return ReviewerArtifactCapture{OperationDigest: op.OperationDigest, EntryDigest: CanonicalDigest(w.Entry), GenerationDigest: c.Descriptor.GenerationDigest,
		AuthorityDigest: CanonicalDigest(q.ArtifactReads[0]), InputID: q.Instructions.InputID, InputDigest: q.Instructions.InputDigest}, nil
}

// Fixed private storage only. Signed current policy selects each request; a
// callback can supply transport but cannot select a different target or path.
func captureReviewerArtifact(ctx context.Context, op model.WorkflowCaptureOperation, w ChildProductWitness, c ChildProductControl, fetch reviewerArtifactFetch, journal reviewerArtifactJournal) (ReviewerArtifactCapture, error) {
	var empty ReviewerArtifactCapture
	claim, err := reviewerArtifactClaim(op, w, c)
	if err != nil || fetch == nil || journal == nil || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	expires, err := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if err != nil {
		return empty, ErrUntrusted
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	ctx, bounded := context.WithTimeout(ctx, 30*time.Second)
	defer bounded()
	q := c.Generation.Policy.Payload
	a := childFields(q.ArtifactReads[0])
	artifact := childFields(a["artifact"])
	count, digest := int(childInteger(artifact, "byteCount")), childString(artifact, "digest")
	name := reviewerArtifactName(w, c, op)
	claimBytes := canonicalBytes(claim)
	if raw, err := journal.load(name+"-read.json", 65536); err == nil {
		var prior ReviewerArtifactCapture
		fence, fe := journal.load(name+"-claim.json", 16384)
		detail, de := journal.load(name+"-detail.json", 65536)
		body, be := journal.readArtifact(ctx, name+"-body", count, digest)
		if fe != nil || de != nil || be != nil || !bytes.Equal(fence, claimBytes) || decode(raw, &prior) != nil || !bytesCanonical(raw, prior) ||
			prior.TargetDetailDigest != CanonicalDigest(json.RawMessage(detail)) || prior.DirectoryDevice != body.DirectoryDevice || prior.DirectoryInode != body.DirectoryInode ||
			prior.BodyDevice != body.device || prior.BodyInode != body.inode || !bytes.Equal(prior.Bytes, body.bytes) ||
			verifyTargetArtifactOriginal(a["target"], a["targetBinding"], a["artifact"], detail, body.bytes) != nil {
			return empty, ErrUntrusted
		}
		expected := claim
		expected.TargetDetailDigest = prior.TargetDetailDigest
		expected.DirectoryDevice = prior.DirectoryDevice
		expected.DirectoryInode = prior.DirectoryInode
		expected.BodyDevice = prior.BodyDevice
		expected.BodyInode = prior.BodyInode
		expected.Bytes = prior.Bytes
		expected.ObservedAt = prior.ObservedAt
		if !sameProduct(expected, prior) || mustChildTime(prior.ObservedAt).IsZero() || ctx.Err() != nil {
			return empty, ErrUntrusted
		}
		return prior, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, ErrUntrusted
	}
	if err = journal.create(name+"-claim.json", claimBytes); err != nil {
		return empty, ErrUntrusted
	}
	if journal.create(name+"-operation.json", canonicalBytes(op)) != nil {
		return empty, ErrUntrusted
	}
	detail, body, err := fetch(ctx, a["target"], a["artifact"], childString(childFields(q.Binding), "executionId"))
	if err != nil || verifyTargetArtifactOriginal(a["target"], a["targetBinding"], a["artifact"], detail, body) != nil ||
		len(body) != count || Digest(body) != digest || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	if journal.create(name+"-detail.json", detail) != nil || journal.create(name+"-body", body) != nil {
		return empty, ErrUntrusted
	}
	actual, err := journal.readArtifact(ctx, name+"-body", count, digest)
	if err != nil || actual.device == 0 || actual.inode == 0 || actual.DirectoryDevice == 0 || actual.DirectoryInode == 0 || !bytes.Equal(actual.bytes, body) || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	claim.TargetDetailDigest = CanonicalDigest(detail)
	claim.DirectoryDevice = actual.DirectoryDevice
	claim.DirectoryInode = actual.DirectoryInode
	claim.BodyDevice = actual.device
	claim.BodyInode = actual.inode
	claim.Bytes = actual.bytes
	claim.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if journal.create(name+"-read.json", canonicalBytes(claim)) != nil {
		return empty, ErrUntrusted
	}
	return claim, nil
}
