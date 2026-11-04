package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Host-private complete read, never public source bytes or native/model credit.
// The registered producer supplies its existing exclusive durable journal;
// unprivileged SOURCE tests supply only the journal, not production authority.
type workflowObservationJournal interface {
	load(string, int) ([]byte, error)
	create(string, []byte) error
}
type WorkflowSourceCapture struct {
	OperationDigest string `json:"operationDigest"`
	ScopeDigest     string `json:"scopeDigest"`
	RootDevice      uint64 `json:"rootDevice"`
	RootInode       uint64 `json:"rootInode"`
	SourceDevice    uint64 `json:"sourceDevice"`
	SourceInode     uint64 `json:"sourceInode"`
	Bytes           []byte `json:"bytes"`
	ObservedAt      string `json:"observedAt"`
}

func captureWorkflowSource(ctx context.Context, op model.WorkflowCaptureOperation, scope ChildSourceReadScope, w TrustedWorkspace, journal workflowObservationJournal) (WorkflowSourceCapture, error) {
	var grant struct {
		Reference model.ControllerPlanReference `json:"reference"`
		ByteCount int                           `json:"byteCount"`
	}
	if json.Unmarshal(scope.Grant, &grant) != nil || grant.Reference.Status == "unavailable" {
		return WorkflowSourceCapture{}, ErrUntrusted
	}
	return captureWorkflowFile(ctx, op, grant.Reference.Path, grant.ByteCount, grant.Reference.SourceDigest, CanonicalDigest(scope), w, journal)

}

// Common confined physical reader/fence only. Each PUBLIC producer separately
// proves source grant or exact own output path before selecting these facts.
func captureWorkflowFile(ctx context.Context, op model.WorkflowCaptureOperation, path string, byteCount int, digest, scopeDigest string, w TrustedWorkspace, journal workflowObservationJournal) (WorkflowSourceCapture, error) {
	var empty WorkflowSourceCapture
	if !safeID.MatchString(op.OperationID) || !hash.MatchString(op.OperationDigest) || byteCount < 0 || byteCount > 16384 || !hash.MatchString(digest) || !hash.MatchString(scopeDigest) {
		return empty, ErrUntrusted
	}
	expires, err := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if err != nil || !time.Now().Before(expires) || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	ctx, wallCancel := context.WithTimeout(ctx, 30*time.Second)
	defer wallCancel()
	name := "workflow-observation-" + op.OperationID
	claim := canonicalBytes(map[string]any{"operationDigest": op.OperationDigest, "scopeDigest": scopeDigest, "rootDevice": w.Device, "rootInode": w.Inode})
	if raw, err := journal.load(name+"-read.json", 65536); err == nil {
		var previous WorkflowSourceCapture
		fence, fe := journal.load(name+"-fence.json", 16384)
		if fe != nil || string(fence) != string(claim) || decode(raw, &previous) != nil || !bytesCanonical(raw, previous) || previous.OperationDigest != op.OperationDigest || previous.ScopeDigest != scopeDigest || previous.RootDevice != w.Device || previous.RootInode != w.Inode || len(previous.Bytes) != byteCount || Digest(previous.Bytes) != digest {
			return empty, ErrUntrusted
		}
		return previous, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, ErrUntrusted
	}
	if err = journal.create(name+"-fence.json", claim); err != nil {
		return empty, ErrUntrusted
	}
	actual, err := readPlanSourceFile(ctx, w, path, byteCount, digest)
	if err != nil {
		return empty, err
	}
	back := WorkflowSourceCapture{OperationDigest: op.OperationDigest, ScopeDigest: scopeDigest, RootDevice: w.Device, RootInode: w.Inode, SourceDevice: actual.device, SourceInode: actual.inode, Bytes: actual.bytes, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	if err = journal.create(name+"-read.json", canonicalBytes(back)); err != nil {
		return empty, err
	}
	return back, nil
}
