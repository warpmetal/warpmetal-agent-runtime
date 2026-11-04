package reconcile

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

var ErrSourceLocalGrantPending = errors.New("SOURCE local grant/activation wire pending; metadata grants no execution")

type sourceTransportRuntime interface {
	SourceTransportSelected(context.Context, qualification.SourceTransportTarget) (bool, error)
	AdoptSourceTransportMetadata(context.Context, model.Sandbox, model.Manifest, qualification.SourceTransportTarget, json.RawMessage) error
}
type sourceTransportControl interface {
	ChildSourceTransportPrepare(context.Context, string) (json.RawMessage, error)
	ChildSourceTransportControl(context.Context, string) (json.RawMessage, error)
	ControllerSourceTransportPrepare(context.Context, string) (json.RawMessage, error)
	ControllerSourceTransportControl(context.Context, string) (json.RawMessage, error)
}

func (r *Reconciler) adoptSourceTransportTarget(ctx context.Context, box model.Sandbox, current model.Manifest, target qualification.SourceTransportTarget) (bool, error) {
	owner, ok := r.ManagedRuntime.(sourceTransportRuntime)
	if !ok {
		return false, nil
	}
	selected, err := owner.SourceTransportSelected(ctx, target)
	if err != nil || !selected {
		return selected, err
	}
	control, ok := r.ManagedControl.(sourceTransportControl)
	if !ok {
		return true, qualification.ErrUntrusted
	}
	var raw json.RawMessage
	if target.TargetKind == "cell_session" {
		if target.Phase == "prepare" {
			raw, err = control.ChildSourceTransportPrepare(ctx, target.PreparationID)
		} else {
			raw, err = control.ChildSourceTransportControl(ctx, target.PreparationID)
		}
	} else {
		if target.Phase == "prepare" {
			raw, err = control.ControllerSourceTransportPrepare(ctx, target.PreparationID)
		} else {
			raw, err = control.ControllerSourceTransportControl(ctx, target.PreparationID)
		}
	}
	if err != nil {
		return true, err
	}
	if err = owner.AdoptSourceTransportMetadata(ctx, box, current, target, raw); err != nil {
		return true, err
	}
	if model.WorkspaceDigest(current) != model.WorkspaceDigest(r.currentAuthorityManifest()) {
		return true, qualification.ErrUntrusted
	}
	return true, nil
}

// Called only AFTER normal prepared receipt acceptance. Metadata-only adoption
// cannot POST a registration for a preparation that has not actually been bound.
func (r *Reconciler) publishSourcePreparedProcess(ctx context.Context, current model.Manifest, target qualification.SourceTransportTarget) error {
	if target.Phase != "prepare" {
		return qualification.ErrUntrusted
	}
	owner, ok := r.ManagedRuntime.(sourceTransportRuntime)
	if !ok {
		return nil
	}
	selected, err := owner.SourceTransportSelected(ctx, target)
	if err != nil || !selected {
		return err
	}
	local, err := r.Store.Sandbox(ctx, target.Scope.SandboxID)
	if err != nil || local == nil || local.Generation != target.Scope.SandboxGeneration {
		return qualification.ErrUntrusted
	}
	box := model.Sandbox{ID: local.ID, Generation: local.Generation, ImageDigest: local.ImageDigest, Cell: true}
	control, ok := r.ManagedControl.(sourceTransportControl)
	if !ok {
		return qualification.ErrUntrusted
	}
	var raw json.RawMessage
	if target.TargetKind == "cell_session" {
		raw, err = control.ChildSourceTransportPrepare(ctx, target.PreparationID)
	} else {
		raw, err = control.ControllerSourceTransportPrepare(ctx, target.PreparationID)
	}
	if err != nil {
		return err
	}
	if err = owner.AdoptSourceTransportMetadata(ctx, box, current, target, raw); err != nil {
		return err
	}
	// Independent registration observation precedes any future LOCAL grant
	// request. Absent genuine registered/current process facts still refuse.
	processOwner, pok := r.ManagedRuntime.(interface {
		ObserveSourceRegisteredProcess(context.Context, model.Sandbox, model.Manifest, qualification.SourceTransportTarget, json.RawMessage) (model.SourceProcessObservationRequest, error)
	})
	processControl, cok := r.ManagedControl.(interface {
		PublishSourceProcessObservation(context.Context, model.SourceProcessObservationRequest) (json.RawMessage, error)
	})
	if !pok || !cok {
		return qualification.ErrUntrusted
	}
	observation, err := processOwner.ObserveSourceRegisteredProcess(ctx, box, current, target, raw)
	if err != nil {
		return err
	}
	if model.WorkspaceDigest(current) != model.WorkspaceDigest(r.currentAuthorityManifest()) {
		return qualification.ErrUntrusted
	}
	original, err := processControl.PublishSourceProcessObservation(ctx, observation)
	if err != nil || string(original) != string(observation.Observation) {
		return qualification.ErrUntrusted
	}
	if model.WorkspaceDigest(current) != model.WorkspaceDigest(r.currentAuthorityManifest()) || ctx.Err() != nil {
		return qualification.ErrUntrusted
	}
	currentOwner, ok := r.ManagedRuntime.(interface {
		ObserveSourceCurrentControl(context.Context, model.Manifest, qualification.SourceTransportTarget, json.RawMessage, qualification.SourceControlOriginalReader) (model.SourceCurrentControlObservation, error)
	})
	currentControl, cok := r.ManagedControl.(qualification.SourceControlOriginalReader)
	if !ok || !cok {
		return qualification.ErrUntrusted
	}
	if _, err = currentOwner.ObserveSourceCurrentControl(ctx, current, target, raw, currentControl); err != nil {
		return err
	}
	if model.WorkspaceDigest(current) != model.WorkspaceDigest(r.currentAuthorityManifest()) || ctx.Err() != nil {
		return qualification.ErrUntrusted
	}
	return nil
}
func childSourceTransportTarget(entry model.CellServiceV3, current model.Manifest) (qualification.SourceTransportTarget, error) {
	tuple, err := entry.PreparedTuple()
	if err != nil {
		return qualification.SourceTransportTarget{}, err
	}
	raw, _ := json.Marshal(tuple)
	return qualification.SourceTransportTarget{TargetKind: "cell_session", PreparationID: entry.PreparationID, Phase: entry.LifecyclePhase, TargetID: tuple.OperationID, SourceID: entry.ServiceRegistrationID, RequestDigest: entry.RequestDigest, PreparedTuple: raw, Scope: model.ControllerOwner{ServerID: current.ServerID, SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration, CellID: entry.OwnerCellID, ControllerID: entry.ControllerID, ControllerRevision: entry.ControllerRevision, AuthorityRevision: entry.AuthorityRevision}}, nil
}
