package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type preparedReviewerRoleRuntime interface {
	AttestPreparedCellWorkflowRole(context.Context, model.WorkflowRoleOperation, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, model.ChildProductDelivery, workspacecatalog.RegisteredProject, json.RawMessage) (model.WorkflowRoleEnvelope, error)
}
type reviewerPublishedSourceRuntime interface {
	preparedReviewerRoleRuntime
	reviewerSourceRuntime
	ApprovedCellProductReviewerSources(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, model.ChildProductDelivery) (qualification.ReviewerSourceSelection, error)
	ReadCellProductReviewerArtifact(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, workspacecatalog.RegisteredProject, model.ChildProductDelivery, model.WorkflowCaptureRequest, model.WorkflowCaptureOperation, json.RawMessage, qualification.ReviewerArtifactTransport, string) (model.WorkflowObservationEnvelope, qualification.ReviewerArtifactCapture, error)
	RetainCellProductReviewerArtifact(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, model.ChildProductDelivery, model.WorkflowObservationEnvelope, qualification.ReviewerArtifactCapture, model.WorkflowObservationReceipt) error
	ReadCellProductReviewerReceipts(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, model.ChildProductDelivery) (qualification.ReviewerReadOriginals, error)
}
type reviewerPublishedSelection struct {
	Binding json.RawMessage
	Scope   struct {
		Owner               model.ControllerOwner
		ConfigurationDigest string
		Workspace           model.ManagedServiceWorkspaceV1
	}
}

type reviewerSourceClaim struct {
	Entry            model.CellServiceV3                   `json:"entry"`
	GenerationDigest string                                `json:"generationDigest"`
	InputDigest      string                                `json:"inputDigest"`
	Selection        qualification.ReviewerSourceSelection `json:"selection"`
}
type reviewerSourceOriginalIndex struct {
	Base        string `json:"base"`
	ClaimDigest string `json:"claimDigest"`
}

func (c reviewerSourceClaim) base() string { return "reviewer-source-" + model.WorkspaceDigest(c)[7:] }

// A locator to the first completed source/role lifecycle, not a new grant or a
// replacement copy of its proof, lease or read acknowledgements.
func (r *Reconciler) pinReviewerSourceOriginal(ctx context.Context, claim reviewerSourceClaim) error {
	index := reviewerSourceOriginalIndex{claim.base(), model.WorkspaceDigest(claim)}
	var first reviewerSourceOriginalIndex
	return r.ownedContinuationOnce(ctx, claim.Entry.PreparationID, "reviewer-source-original", claim, func() (any, error) { return index, nil }, &first)
}

// Only current reviewer4/control5 has a prepared identity/read phase. It follows
// independent original-facts export, and never substitutes for strict adoption.
func (r *Reconciler) ensurePreparedReviewerSources(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, delivery model.ChildProductDelivery, input []byte) error {
	var wire struct {
		Generation struct {
			FormatVersion int
			Policy        struct{ Payload reviewerPublishedSelection }
		}
	}
	if json.Unmarshal(delivery.Bytes(), &wire) != nil {
		return qualification.ErrUntrusted
	}
	if wire.Generation.FormatVersion != 5 {
		return nil
	} // Closed prior versions keep their existing order.
	if entry.LifecyclePhase != "execute" || entry.Role != "reviewer" || entry.ExecutionGrant == nil {
		return qualification.ErrUntrusted
	}
	runtime, ok := r.ManagedRuntime.(reviewerPublishedSourceRuntime)
	fetch, fok := r.ManagedControl.(qualification.ReviewerArtifactTransport)
	if !ok || !fok || r.Store == nil {
		return errors.New("reviewer protected prepared/read suppliers unavailable")
	}
	// This is a protected current signed selector, not an unverified wire policy.
	selection, err := runtime.ApprovedCellProductReviewerSources(ctx, box, entry, current, input, delivery)
	if err != nil {
		return err
	}
	if len(selection.Physical) > 64 || selection.Artifact.ByteCount < 0 {
		return qualification.ErrUntrusted
	}
	selected := wire.Generation.Policy.Payload
	claim := reviewerSourceClaim{entry, delivery.GenerationDigest(), model.RawPhysicalDigest(input), selection}
	base := claim.base()
	if pending, e := r.Store.HasPendingOwnedContinuation(ctx, entry.PreparationID, "reviewer-source-"); e != nil {
		return e
	} else if pending {
		return state.ErrOwnedContinuationUnknown
	}
	execution, err := r.Store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if execution != nil {
		raw, e := r.Store.OwnedContinuationResult(ctx, entry.PreparationID, base+"-complete", mustWorkflowJSON(claim))
		var first qualification.ReviewerReadOriginals
		if e != nil || len(raw) == 0 || model.DecodePhysicalClosed(raw, &first) != nil {
			return errors.New("reviewer first own custody absent after execution")
		}
		observed, e := runtime.ReadCellProductReviewerReceipts(ctx, box, entry, current, input, delivery)
		if e != nil || !sameReviewerReadOriginals(first, observed) {
			return errors.New("reviewer first own custody changed")
		}
		return nil
	}
	root, err := r.currentReviewerRegisteredRoot(ctx, entry)
	if err != nil {
		return err
	}
	lease, err := r.ensurePreparedReviewerRole(ctx, box, entry, current, input, delivery, selected, root, base)
	if err != nil {
		return err
	}
	makeCall := func(read qualification.ChildApprovedSourceRead) model.WorkflowCaptureRequest {
		id := model.WorkspaceDigest(map[string]any{"claim": claim, "reference": read.Reference})[7:]
		return model.WorkflowCaptureRequest{FormatVersion: 1, RequestID: "wfreview_read_" + id, Binding: selected.Binding, Operation: model.WorkflowCapture{Kind: "observation", Reconciles: json.RawMessage("null"), Observation: mustWorkflowJSON(map[string]any{"type": "source_read", "reference": read.Reference, "observedDigest": read.Reference.SourceDigest, "byteCount": read.ByteCount})}}
	}
	originals := qualification.ReviewerReadOriginals{Physical: []qualification.ChildSourceReadOriginal{}}
	for _, read := range selection.Physical {
		call := makeCall(read)
		stage := "reviewer-source-read-" + model.WorkspaceDigest(map[string]any{"claim": claim, "reference": read.Reference})[7:]
		first, complete, e := r.retainedWorkerSourceRead(ctx, entry.PreparationID, stage, call)
		if e != nil {
			return e
		}
		if !complete {
			first, e = r.ensurePublishedSourceRead(ctx, entry, current, delivery, read, stage, call, func(sourceRoot qualification.TrustedWorkspace, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
				return runtime.ReadCellProductSource(ctx, box, entry, current, input, sourceRoot, delivery, call, op, snapshot)
			}, func(envelope model.WorkflowObservationEnvelope, capture qualification.WorkflowSourceCapture, receipt model.WorkflowObservationReceipt) error {
				if e := runtime.RetainCellProductObservationReceipt(ctx, envelope, receipt); e != nil {
					return e
				}
				return runtime.RetainCellProductReviewerRead(ctx, entry, current, input, delivery, envelope, capture, receipt)
			})
			if e != nil {
				return e
			}
		}
		originals.Physical = append(originals.Physical, first)
	}
	originals.Artifact, err = r.ensureReviewerArtifactRead(ctx, runtime, fetch, box, entry, current, input, delivery, root, lease.Lease, selection.Artifact, base+"-artifact", makeCall(selection.Artifact))
	if err != nil {
		return err
	}
	observed, err := runtime.ReadCellProductReviewerReceipts(ctx, box, entry, current, input, delivery)
	if err != nil || !sameReviewerReadOriginals(originals, observed) {
		return errors.New("reviewer own read acknowledgements incomplete")
	}
	if model.WorkspaceDigest(r.currentAuthorityManifest()) != model.WorkspaceDigest(current) {
		return errors.New("reviewer current authority changed")
	}
	var first qualification.ReviewerReadOriginals
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, base+"-complete", claim, func() (any, error) { return originals, nil }, &first); err != nil {
		return err
	}
	return r.pinReviewerSourceOriginal(ctx, claim)
}
func sameReviewerReadOriginals(a, b qualification.ReviewerReadOriginals) bool {
	return sameSourceOriginals(a.Physical, b.Physical) && model.WorkspaceDigest(a.Artifact) == model.WorkspaceDigest(b.Artifact)
}
func (r *Reconciler) currentReviewerRegisteredRoot(ctx context.Context, entry model.CellServiceV3) (workspacecatalog.RegisteredProject, error) {
	p, err := r.lookupCellProject(ctx, cellV2View(entry))
	if err != nil {
		return workspacecatalog.RegisteredProject{}, err
	}
	if p == nil || p.Report.Availability != "available" || p.ScopeRevision != entry.Workspace.ScopeRevision {
		return workspacecatalog.RegisteredProject{}, errors.New("reviewer current registered root unavailable")
	}
	return workspacecatalog.RegisteredProject{Report: p.Report, HostRoot: p.HostRoot, ContainerRoot: p.ContainerRoot, ScopeRevision: p.ScopeRevision, RootDevice: p.RootDevice, RootInode: p.RootInode}, nil
}

func (r *Reconciler) ensurePreparedReviewerRole(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, delivery model.ChildProductDelivery, selected reviewerPublishedSelection, root workspacecatalog.RegisteredProject, stage string) (model.WorkflowRoleEnrollment, error) {
	var empty model.WorkflowRoleEnrollment
	control, ok := r.ManagedControl.(workflowRoleControl)
	runtime, rok := r.ManagedRuntime.(preparedReviewerRoleRuntime)
	observer, sok := r.currentChildSnapshotOwner()
	if !ok || !rok || !sok {
		return empty, errors.New("prepared reviewer current role authority unavailable")
	}
	var parent *model.ControllerParentIntent
	for _, p := range current.ParentServices {
		if p.Role == "manager" && p.DesiredState == "active" && p.Owner == selected.Scope.Owner && p.Workspace == selected.Scope.Workspace {
			if parent != nil {
				return empty, state.ErrControllerActivityConflict
			}
			v := p
			parent = &v
		}
	}
	o := selected.Scope.Owner
	if parent == nil || o.ServerID != current.ServerID || o.SandboxID != entry.SandboxID || o.SandboxGeneration != entry.SandboxGeneration || o.CellID != entry.OwnerCellID || o.ControllerID != entry.ControllerID || o.ControllerRevision != entry.ControllerRevision || o.AuthorityRevision != entry.AuthorityRevision {
		return empty, state.ErrControllerActivityConflict
	}
	app, err := r.Store.WorkspaceApplication(ctx, parent.ApplicationOperationID)
	if err != nil || app == nil || !app.Applied || app.ApplicationID == "" || len(app.EnvelopeJSON) == 0 || app.Operation.ConfigurationDigest != selected.Scope.ConfigurationDigest || app.Operation.TargetRuntimeRevision != current.DesiredRevision {
		return empty, state.ErrControllerActivityConflict
	}
	if _, err = app.Operation.ParentDependency(*parent); err != nil {
		return empty, err
	}
	var binding struct{ WorkID, ExecutionID, PreparationID, NativeSessionID, ServiceRegistrationID string }
	if json.Unmarshal(selected.Binding, &binding) != nil || binding.WorkID == "" || binding.ExecutionID == "" || binding.PreparationID != entry.PreparationID || binding.NativeSessionID != entry.NativeSessionID || binding.ServiceRegistrationID != entry.ServiceRegistrationID {
		return empty, state.ErrControllerActivityConflict
	}
	subject := model.WorkflowRoleSubject{AccountID: o.AccountID, TaskID: o.TaskID, ServerID: o.ServerID, SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration, CellID: entry.OwnerCellID, Role: entry.Role, ControllerID: entry.ControllerID, ControllerRevision: entry.ControllerRevision, AuthorityRevision: entry.AuthorityRevision, ServiceRegistrationID: entry.ServiceRegistrationID, ServiceGeneration: entry.ServiceGeneration, NativeSessionID: entry.NativeSessionID, WorkID: &binding.WorkID, ExecutionID: &binding.ExecutionID}
	call := model.WorkflowRoleOperationRequest{FormatVersion: 1, RequestID: "wfreview_role_" + model.WorkspaceDigest(map[string]any{"application": app.Operation.OperationDigest, "binding": selected.Binding, "subject": subject})[7:], Subject: subject}
	snapshot, err := observer.CurrentCellProductWorkflowSnapshot(ctx, entry)
	if err != nil {
		return empty, err
	}
	var identity struct{ ManagedServiceReceiptDigest, NativeContextDigest string }
	if json.Unmarshal(snapshot, &identity) != nil {
		return empty, state.ErrControllerActivityConflict
	}
	var op model.WorkflowRoleOperation
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-role-operation", call, func() (any, error) { return control.WorkflowRoleEnrollmentOperation(ctx, call) }, &op); err != nil {
		return empty, err
	}
	expiry, e := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if op.Validate() != nil || !reflect.DeepEqual(op.Subject, subject) || op.NodeTokenHash != app.Operation.Producer.NodeTokenHash || op.ManagedServiceReceiptDigest != identity.ManagedServiceReceiptDigest || op.NativeContextDigest != identity.NativeContextDigest || e != nil || !r.now().Before(expiry) {
		return empty, state.ErrControllerActivityConflict
	}
	var proof model.WorkflowRoleEnvelope
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-role-proof", op, func() (any, error) {
		return runtime.AttestPreparedCellWorkflowRole(ctx, op, box, entry, current, input, delivery, root, snapshot)
	}, &proof); err != nil {
		return empty, err
	}
	limit, e := time.Parse(time.RFC3339Nano, proof.Payload.NotAfter)
	if proof.Validate() != nil || proof.KeyID != app.Operation.Producer.KeyID || proof.Payload.OperationID != op.OperationID || proof.Payload.OperationDigest != op.OperationDigest || !reflect.DeepEqual(proof.Payload.Subject, subject) || proof.Payload.NodeTokenHash != op.NodeTokenHash || proof.Payload.NativeContextDigest != op.NativeContextDigest || proof.Payload.ManagedServiceReceiptDigest != op.ManagedServiceReceiptDigest || e != nil || !r.now().Before(limit) || limit.After(expiry) {
		return empty, state.ErrControllerActivityConflict
	}
	again, e := observer.CurrentCellProductWorkflowSnapshot(ctx, entry)
	latest, e2 := r.currentReviewerRegisteredRoot(ctx, entry)
	if e != nil || e2 != nil || !reflect.DeepEqual(latest, root) || model.WorkspaceDigest(again) != model.WorkspaceDigest(snapshot) || model.WorkspaceDigest(r.currentAuthorityManifest()) != model.WorkspaceDigest(current) {
		return empty, state.ErrControllerActivityConflict
	}
	var enrolled model.WorkflowRoleEnrollment
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-role-enroll", proof, func() (any, error) { return control.EnrollWorkflowRole(ctx, proof) }, &enrolled); err != nil {
		return empty, err
	}
	deadline, e := time.Parse(time.RFC3339Nano, enrolled.ExpiresAt)
	if enrolled.Validate() != nil || e != nil || !r.now().Before(deadline) || deadline.After(limit) {
		return empty, ErrWorkflowRoleExpired
	}
	return enrolled, nil
}

type reviewerArtifactOriginal struct {
	Envelope model.WorkflowObservationEnvelope
	Read     qualification.ReviewerArtifactCapture
}

func (r *Reconciler) ensureReviewerArtifactRead(ctx context.Context, runtime reviewerPublishedSourceRuntime, fetch qualification.ReviewerArtifactTransport, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, delivery model.ChildProductDelivery, root workspacecatalog.RegisteredProject, lease string, selected qualification.ChildApprovedSourceRead, stage string, call model.WorkflowCaptureRequest) (qualification.ChildSourceReadOriginal, error) {
	var empty qualification.ChildSourceReadOriginal
	// A completed first read/ACK is history even when that ACK advanced the
	// backend snapshot. The current private getter is independently compared
	// before adoption; never re-fetch or re-sign merely to recover this marker.
	if first, complete, err := r.retainedReviewerArtifactRead(ctx, entry.PreparationID, stage, call); err != nil {
		return empty, err
	} else if complete {
		return first, nil
	}
	control, ok := r.ManagedControl.(childEffectObservationControl)
	owner, sok := r.currentChildSnapshotOwner()
	if !ok || !sok {
		return empty, errors.New("reviewer artifact current observation unavailable")
	}
	snapshot, err := owner.CurrentCellProductWorkflowSnapshot(ctx, entry)
	if err != nil {
		return empty, err
	}
	var op model.WorkflowCaptureOperation
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-operation", call, func() (any, error) { return control.WorkflowObservationOperation(ctx, call, current.DesiredRevision) }, &op); err != nil {
		return empty, err
	}
	if !op.MatchesCurrentSnapshot(snapshot) {
		return empty, state.ErrControllerActivityConflict
	}
	var original reviewerArtifactOriginal
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-read", op, func() (any, error) {
		envelope, read, err := runtime.ReadCellProductReviewerArtifact(ctx, box, entry, current, input, root, delivery, call, op, snapshot, fetch, lease)
		return reviewerArtifactOriginal{envelope, read}, err
	}, &original); err != nil {
		return empty, err
	}
	// The private owner selects/verifies target/artifact original bytes; its
	// receipt is compared with the exact node operation before any ACK credit.
	var request struct{ Binding, Reconciles, Observation json.RawMessage }
	if original.Envelope.Validate() != nil || json.Unmarshal(original.Envelope.Payload.Request, &request) != nil || model.WorkspaceDigest(request.Binding) != model.WorkspaceDigest(call.Binding) || model.WorkspaceDigest(request.Observation) != model.WorkspaceDigest(call.Operation.Observation) || string(request.Reconciles) != "null" || original.Envelope.Payload.OperationDigest != op.OperationDigest {
		return empty, state.ErrControllerActivityConflict
	}
	again, err := owner.CurrentCellProductWorkflowSnapshot(ctx, entry)
	latest, e := r.currentReviewerRegisteredRoot(ctx, entry)
	if err != nil || e != nil || !reflect.DeepEqual(latest, root) || model.WorkspaceDigest(again) != model.WorkspaceDigest(snapshot) || model.WorkspaceDigest(r.currentAuthorityManifest()) != model.WorkspaceDigest(current) {
		return empty, state.ErrControllerActivityConflict
	}
	var receipt model.WorkflowObservationReceipt
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-ack", original.Envelope, func() (any, error) { return control.ReportWorkflowObservation(ctx, original.Envelope) }, &receipt); err != nil {
		return empty, err
	}
	var retained bool
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, stage+"-private-ack", receipt, func() (any, error) {
		return true, runtime.RetainCellProductReviewerArtifact(ctx, box, entry, current, input, delivery, original.Envelope, original.Read, receipt)
	}, &retained); err != nil {
		return empty, err
	}
	if !retained {
		return empty, state.ErrControllerActivityConflict
	}
	return qualification.ChildSourceReadOriginal{Envelope: original.Envelope, Receipt: receipt}, nil
}

func (r *Reconciler) retainedReviewerArtifactRead(ctx context.Context, preparation, stage string, call model.WorkflowCaptureRequest) (qualification.ChildSourceReadOriginal, bool, error) {
	var empty qualification.ChildSourceReadOriginal
	var op model.WorkflowCaptureOperation
	var original reviewerArtifactOriginal
	var receipt model.WorkflowObservationReceipt
	var retained bool
	for _, step := range []struct {
		name  string
		claim any
		out   any
	}{
		{stage + "-operation", call, &op},
		{stage + "-read", &op, &original},
		{stage + "-ack", &original.Envelope, &receipt},
		{stage + "-private-ack", &receipt, &retained},
	} {
		raw, err := r.Store.OwnedContinuationResult(ctx, preparation, step.name, mustWorkflowJSON(step.claim))
		if err != nil || len(raw) == 0 {
			return empty, false, err
		}
		if err = model.DecodePhysicalClosed(raw, step.out); err != nil {
			return empty, false, err
		}
	}
	if !retained {
		return empty, false, state.ErrControllerActivityConflict
	}
	return qualification.ChildSourceReadOriginal{Envelope: original.Envelope, Receipt: receipt}, true, nil
}
