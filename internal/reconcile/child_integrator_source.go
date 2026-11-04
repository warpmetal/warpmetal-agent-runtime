package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type integrationSourceRuntime interface {
	IntegrationCellProductTarget(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte) (qualification.ChildIntegrationTarget, error)
	StageCellProductIntegrationTarget(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, qualification.TrustedWorkspace, json.RawMessage, []byte) error
	ReadCellProductIntegrationSource(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, qualification.TrustedWorkspace, model.WorkflowCaptureRequest, model.WorkflowCaptureOperation, json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error)
	RetainCellProductIntegrationSourceRead(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, model.WorkflowObservationReceipt) error
	ReadCellProductIntegrationSourceReceipts(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte) ([]qualification.ChildSourceReadOriginal, error)
	SealCellProductIntegrationDelivery(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, qualification.TrustedWorkspace) error
}
type integrationTargetControl interface {
	ReadWorkflowResult(context.Context, json.RawMessage, string) (json.RawMessage, error)
	FetchWorkflowArtifact(context.Context, string, json.RawMessage, string) ([]byte, error)
}
type integrationTargetOriginal struct {
	Detail   json.RawMessage
	Artifact []byte
}

// This runs only after actual execute control adoption, before the V3 claim.
// Retained started/terminal inputs validate first custody without restaging the
// before-image that the authorized integrator has since legitimately changed.
func (r *Reconciler) ensurePublishedIntegrationSource(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, delivery model.ChildProductDelivery, input []byte) error {
	if entry.LifecyclePhase != "execute" {
		return nil
	}
	var wire struct {
		Generation struct {
			FormatVersion int
			Policy        struct {
				Payload struct {
					Binding json.RawMessage
					Scope   struct {
						Owner               model.ControllerOwner
						ConfigurationDigest string
						Workspace           model.ManagedServiceWorkspaceV1
					}
				}
			}
		}
	}
	if json.Unmarshal(delivery.Bytes(), &wire) != nil {
		return qualification.ErrUntrusted
	}
	if wire.Generation.FormatVersion != 4 {
		return nil
	} // Already adopted closed legacy/coding publication.
	runtime, ok := r.ManagedRuntime.(integrationSourceRuntime)
	if !ok || r.Store == nil {
		return errors.New("integrator protected custody unavailable")
	}
	target, err := runtime.IntegrationCellProductTarget(ctx, box, entry, current, input)
	if err != nil {
		return err
	}
	if len(target.Reads) < 2 || len(target.Reads) > 64 {
		return errors.New("integrator source scope refused")
	}
	claim := map[string]any{"entry": entry, "generationDigest": delivery.GenerationDigest(), "inputDigest": model.RawPhysicalDigest(input), "target": target}
	key := model.WorkspaceDigest(claim)[7:]
	base := "integrator-source-" + key
	if pending, err := r.Store.HasPendingOwnedContinuation(ctx, entry.PreparationID, "integrator-source-"); err != nil {
		return err
	} else if pending {
		return state.ErrOwnedContinuationUnknown
	}
	execution, err := r.Store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if execution != nil {
		raw, err := r.Store.OwnedContinuationResult(ctx, entry.PreparationID, base+"-sealed", mustWorkflowJSON(claim))
		var original []qualification.ChildSourceReadOriginal
		if err != nil || len(raw) == 0 || json.Unmarshal(raw, &original) != nil {
			return errors.New("integrator first sealed custody absent")
		}
		currentReads, err := runtime.ReadCellProductIntegrationSourceReceipts(ctx, box, entry, current, input)
		if err != nil || !sameSourceOriginals(original, currentReads) || model.WorkspaceDigest(current) != model.WorkspaceDigest(r.currentAuthorityManifest()) {
			return errors.New("integrator retained custody changed")
		}
		return nil
	}
	control, ok := r.ManagedControl.(integrationTargetControl)
	if !ok {
		return errors.New("integrator target transport unavailable")
	}
	lease, err := r.integrationManagerLease(ctx, current, entry, wire.Generation.Policy.Payload.Scope.Owner, wire.Generation.Policy.Payload.Scope.Workspace, wire.Generation.Policy.Payload.Scope.ConfigurationDigest)
	if err != nil {
		return err
	}
	var binding struct{ ExecutionID string }
	if json.Unmarshal(wire.Generation.Policy.Payload.Binding, &binding) != nil || binding.ExecutionID == "" {
		return qualification.ErrUntrusted
	}
	var original integrationTargetOriginal
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, base+"-target", claim, func() (any, error) {
		detail, err := control.ReadWorkflowResult(ctx, target.Target, lease)
		if err != nil {
			return nil, err
		}
		body, err := control.FetchWorkflowArtifact(ctx, binding.ExecutionID, target.Artifact, lease)
		if err != nil {
			return nil, err
		}
		return integrationTargetOriginal{detail, body}, nil
	}, &original); err != nil {
		return err
	}
	makeCall := func(read qualification.ChildApprovedSourceRead) model.WorkflowCaptureRequest {
		id := model.WorkspaceDigest(map[string]any{"claim": claim, "reference": read.Reference})[7:]
		return model.WorkflowCaptureRequest{FormatVersion: 1, RequestID: "wfsrc_" + id, Binding: wire.Generation.Policy.Payload.Binding, Operation: model.WorkflowCapture{Kind: "observation", Reconciles: json.RawMessage("null"), Observation: mustWorkflowJSON(map[string]any{"type": "source_read", "reference": read.Reference, "observedDigest": read.Reference.SourceDigest, "byteCount": read.ByteCount})}}
	}
	var targetRead *qualification.ChildApprovedSourceRead
	seen := map[string]bool{}
	for i, read := range target.Reads {
		key := model.WorkspaceDigest(read.Reference)
		if seen[key] || read.ByteCount < 1 || read.ByteCount > 16384 {
			return qualification.ErrUntrusted
		}
		seen[key] = true
		if read.Reference == target.Reference {
			targetRead = &target.Reads[i]
		}
	}
	if targetRead == nil {
		return qualification.ErrUntrusted
	}
	root, err := r.resolveApprovedProductSourceRoot(ctx, entry, delivery, makeCall(*targetRead))
	if err != nil {
		return err
	}
	var staged bool
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, base+"-stage", map[string]any{"claim": claim, "original": original, "root": root}, func() (any, error) {
		return true, runtime.StageCellProductIntegrationTarget(ctx, box, entry, current, input, root, original.Detail, original.Artifact)
	}, &staged); err != nil {
		return err
	}
	if !staged {
		return errors.New("integrator target stage absent")
	}
	retained := make([]qualification.ChildSourceReadOriginal, 0, len(target.Reads))
	for _, read := range target.Reads {
		call := makeCall(read)
		stage := "integrator-source-read-" + model.WorkspaceDigest(map[string]any{"claim": claim, "reference": read.Reference})[7:]
		prior, complete, err := r.retainedWorkerSourceRead(ctx, entry.PreparationID, stage, call)
		if err != nil {
			return err
		}
		if !complete {
			prior, err = r.ensurePublishedSourceRead(ctx, entry, current, delivery, read, stage, call,
				func(sourceRoot qualification.TrustedWorkspace, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
					return runtime.ReadCellProductIntegrationSource(ctx, box, entry, current, input, sourceRoot, call, op, snapshot)
				},
				func(envelope model.WorkflowObservationEnvelope, read qualification.WorkflowSourceCapture, receipt model.WorkflowObservationReceipt) error {
					return runtime.RetainCellProductIntegrationSourceRead(ctx, box, entry, current, input, envelope, read, receipt)
				})
			if err != nil {
				return err
			}
		}
		retained = append(retained, prior)
	}
	actual, err := runtime.ReadCellProductIntegrationSourceReceipts(ctx, box, entry, current, input)
	if err != nil || !sameSourceOriginals(retained, actual) {
		return errors.New("integrator first own acknowledgements unavailable")
	}
	again, err := r.resolveApprovedProductSourceRoot(ctx, entry, delivery, makeCall(*targetRead))
	if err != nil || again != root || model.WorkspaceDigest(current) != model.WorkspaceDigest(r.currentAuthorityManifest()) {
		return errors.New("integrator root/current authority changed")
	}
	var sealed []qualification.ChildSourceReadOriginal
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, base+"-sealed", claim, func() (any, error) {
		if err := runtime.SealCellProductIntegrationDelivery(ctx, box, entry, current, input, root); err != nil {
			return nil, err
		}
		return retained, nil
	}, &sealed); err != nil {
		return err
	}
	if !sameSourceOriginals(sealed, retained) {
		return qualification.ErrUntrusted
	}
	return nil
}

func sameSourceOriginals(a, b []qualification.ChildSourceReadOriginal) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	pending := map[string]bool{}
	for _, v := range a {
		key := model.WorkspaceDigest(v)
		if pending[key] {
			return false
		}
		pending[key] = true
	}
	for _, v := range b {
		key := model.WorkspaceDigest(v)
		if !pending[key] {
			return false
		}
		delete(pending, key)
	}
	return len(pending) == 0
}

func (r *Reconciler) integrationManagerLease(ctx context.Context, current model.Manifest, entry model.CellServiceV3, owner model.ControllerOwner, workspace model.ManagedServiceWorkspaceV1, configurationDigest string) (string, error) {
	bound := r.firstTaskManagerAuthority
	if bound == nil || bound.lease == "" || bound.parent.Role != "manager" || bound.parent.DesiredState != "active" || bound.parent.Owner != owner || bound.parent.Workspace != workspace || workspace.SelectionID != entry.Workspace.SelectionID || workspace.ProjectID != entry.Workspace.ProjectID || workspace.WorkspaceEpoch != entry.Workspace.WorkspaceEpoch || workspace.ScopeRevision != entry.Workspace.ScopeRevision || workspace.RootAttestation != entry.Workspace.RootAttestation || owner.SandboxID != entry.SandboxID || owner.SandboxGeneration != entry.SandboxGeneration {
		return "", errors.New("integrator current manager lease unavailable")
	}
	count := 0
	for _, p := range current.ParentServices {
		if reflect.DeepEqual(p, bound.parent) {
			count++
		}
	}
	if count != 1 {
		return "", errors.New("integrator manager authority changed")
	}
	app, err := r.Store.WorkspaceApplication(ctx, bound.parent.ApplicationOperationID)
	if err != nil || app == nil || !app.Applied || app.ApplicationID == "" || len(app.EnvelopeJSON) == 0 || app.Operation.OperationDigest != bound.operationDigest || app.Operation.ConfigurationDigest != configurationDigest || app.Operation.TargetRuntimeRevision != current.DesiredRevision {
		return "", errors.New("integrator accepted application changed")
	}
	if _, err = app.Operation.ParentDependency(bound.parent); err != nil {
		return "", err
	}
	return bound.lease, nil
}
