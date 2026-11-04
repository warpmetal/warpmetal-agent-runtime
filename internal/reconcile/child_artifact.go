package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type childArtifactControl interface {
	childEffectObservationControl
	UploadWorkflowArtifact(context.Context, model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt, []byte, string, string) (model.WorkflowArtifactReceipt, error)
}
type childArtifactRuntime interface {
	ReadCellProductArtifact(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, workspacecatalog.RegisteredProject, model.WorkflowCaptureRequest, model.WorkflowCaptureOperation, json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error)
	RetainCellProductObservationReceipt(context.Context, model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error
}

// One operation, one whole distinct ROOT read, one retained observation ACK and
// one artifact upload. Original reviewer output is joined by native capture in
// the Runtime adapter before the ROOT read; author/source receipts cannot stand
// in for it. No automatic poll/retry, provider effect or foreign-source staging.
func (r *Reconciler) ReadUploadApprovedChildArtifact(ctx context.Context, entry model.CellServiceV3, call model.WorkflowCaptureRequest, purpose, contentType string) (model.WorkflowArtifactReceipt, error) {
	owner, ok := r.currentChildSnapshotOwner()
	if !ok {
		return model.WorkflowArtifactReceipt{}, errors.New("child artifact current protected supplier pending")
	}
	return r.readUploadApprovedChildArtifact(ctx, entry, call, purpose, contentType, owner.CurrentCellProductWorkflowSnapshot, "")
}

// The normal completion caller supplies its independently authenticated terminal
// snapshot reader. The protected artifact adapter still validates signed PRODUCT
// authority itself; this callback never substitutes for that validation.
func (r *Reconciler) readUploadApprovedChildArtifact(ctx context.Context, entry model.CellServiceV3, call model.WorkflowCaptureRequest, purpose, contentType string, currentSnapshot func(context.Context, model.CellServiceV3) (json.RawMessage, error), journalID string) (model.WorkflowArtifactReceipt, error) {
	var empty model.WorkflowArtifactReceipt
	control, ok := r.ManagedControl.(childArtifactControl)
	runtime, rok := r.ManagedRuntime.(childArtifactRuntime)
	if !ok || !rok || currentSnapshot == nil || r.Store == nil {
		return empty, errors.New("child artifact current protected supplier pending")
	}
	current := r.currentAuthorityManifest()
	found := false
	for _, actual := range current.CellEntriesV3 {
		if reflect.DeepEqual(actual, entry) {
			found = true
		}
	}
	if !found || entry.DesiredState != "active" || entry.LifecyclePhase != "execute" {
		return empty, errors.New("child artifact preparation changed")
	}
	box, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil {
		return empty, err
	}
	if box == nil || box.ObservedState != "running" || box.ObservedGeneration != entry.SandboxGeneration {
		return empty, errors.New("child artifact Sandbox changed")
	}
	project, err := r.lookupCellProject(ctx, cellV2View(entry))
	if err != nil {
		return empty, err
	}
	if project == nil || project.ServerID != current.ServerID || project.Report.Availability != "available" || project.ScopeRevision != entry.Workspace.ScopeRevision {
		return empty, errors.New("child artifact registered project changed")
	}
	root := workspacecatalog.RegisteredProject{Report: project.Report, HostRoot: project.HostRoot, ContainerRoot: project.ContainerRoot, ScopeRevision: project.ScopeRevision, RootDevice: project.RootDevice, RootInode: project.RootInode}
	snapshot, err := currentSnapshot(ctx, entry)
	if err != nil {
		return empty, err
	}
	var op model.WorkflowCaptureOperation
	err = r.childArtifactStep(ctx, journalID, "operation", call, func() (any, error) {
		return control.WorkflowObservationOperation(ctx, call, current.DesiredRevision)
	}, &op)
	if err != nil {
		return empty, err
	}
	if !op.MatchesCurrentSnapshot(snapshot) {
		return empty, errors.New("child artifact workflow current conflict")
	}
	text, err := r.fetchCellFirstText(ctx, cellV2View(entry))
	if err != nil {
		return empty, err
	}
	var original struct {
		Envelope model.WorkflowObservationEnvelope
		Read     qualification.WorkflowSourceCapture
	}
	err = r.childArtifactStep(ctx, journalID, "read", op, func() (any, error) {
		envelope, read, err := runtime.ReadCellProductArtifact(ctx, model.Sandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, ImageDigest: box.ImageDigest, Cell: true}, entry, current, []byte(text), root, call, op, snapshot)
		return struct {
			Envelope model.WorkflowObservationEnvelope
			Read     qualification.WorkflowSourceCapture
		}{envelope, read}, err
	}, &original)
	if err != nil {
		return empty, err
	}
	envelope, read := original.Envelope, original.Read
	again, err := currentSnapshot(ctx, entry)
	if err != nil || model.WorkspaceDigest(again) != model.WorkspaceDigest(snapshot) || r.currentAuthorityManifest().DesiredRevision != current.DesiredRevision {
		return empty, errors.New("child artifact current authority moved")
	}
	currentProject, err := r.lookupCellProject(ctx, cellV2View(entry))
	if err != nil || currentProject == nil || currentProject.HostRoot != root.HostRoot || currentProject.RootDevice != root.RootDevice || currentProject.RootInode != root.RootInode || currentProject.Report.RootAttestation != root.Report.RootAttestation {
		return empty, errors.New("child artifact root moved during read")
	}
	var receipt model.WorkflowObservationReceipt
	err = r.childArtifactStep(ctx, journalID, "ack", envelope, func() (any, error) {
		return control.ReportWorkflowObservation(ctx, envelope)
	}, &receipt)
	if err != nil {
		return empty, err
	}
	var retained bool
	if err = r.childArtifactStep(ctx, journalID, "private-ack", receipt, func() (any, error) {
		return true, runtime.RetainCellProductObservationReceipt(ctx, envelope, receipt)
	}, &retained); err != nil {
		return empty, err
	}
	if !retained {
		return empty, errors.New("child artifact private acknowledgement refused")
	}
	var uploaded model.WorkflowArtifactReceipt
	err = r.childArtifactStep(ctx, journalID, "upload", map[string]any{"read": receipt, "purpose": purpose, "contentType": contentType, "digest": model.RawPhysicalDigest(read.Bytes)}, func() (any, error) {
		return control.UploadWorkflowArtifact(ctx, envelope, receipt, read.Bytes, purpose, contentType)
	}, &uploaded)
	return uploaded, err
}

// Existing explicit callers remain single invocations. Normal continuation uses
// the existing immutable journal, retaining each original before the next effect.
func (r *Reconciler) childArtifactStep(ctx context.Context, id, stage string, claim any, effect func() (any, error), out any) error {
	if id != "" {
		return r.ownedContinuationOnce(ctx, id, "completion-artifact-"+stage, claim, effect, out)
	}
	value, err := effect()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
