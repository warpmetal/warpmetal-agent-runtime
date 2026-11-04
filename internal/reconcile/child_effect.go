package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

type childEffectObservationControl interface {
	WorkflowObservationOperation(context.Context, model.WorkflowCaptureRequest, int64) (model.WorkflowCaptureOperation, error)
	ReportWorkflowObservation(context.Context, model.WorkflowObservationEnvelope) (model.WorkflowObservationReceipt, error)
}
type childEffectObservationRuntime interface {
	ObserveCellProductEffect(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, model.WorkflowCaptureRequest, model.WorkflowCaptureOperation, json.RawMessage) (model.WorkflowObservationEnvelope, error)
	RetainCellProductObservationReceipt(context.Context, model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error
}
type currentChildWorkflowSnapshot interface {
	// Owning independent current lifecycle/workflow facts, not op.Snapshot echo.
	// Missing implementation is an explicit denial, not readiness fabrication.
	CurrentCellProductWorkflowSnapshot(context.Context, model.CellServiceV3) (json.RawMessage, error)
}

func (r *Reconciler) currentChildSnapshotOwner() (currentChildWorkflowSnapshot, bool) {
	// Backend owns the independent assignment/lifecycle/grant/child/effect facts.
	// Keep explicit Runtime suppliers for retained SOURCE boundary tests only.
	if owner, ok := r.ManagedControl.(currentChildWorkflowSnapshot); ok {
		return owner, true
	}
	owner, ok := r.ManagedRuntime.(currentChildWorkflowSnapshot)
	return owner, ok
}

// Explicit operation-specific actual native capture -> existing ROOT signer ->
// proof retention -> observation receipt -> durable private ACK. No scheduler,
// inline retry, new model/tool effect, or client-supplied assessment generation.
func (r *Reconciler) ReportApprovedChildEffect(ctx context.Context, entry model.CellServiceV3, call model.WorkflowCaptureRequest) (model.WorkflowObservationReceipt, error) {
	var empty model.WorkflowObservationReceipt
	control, ok := r.ManagedControl.(childEffectObservationControl)
	runtime, rok := r.ManagedRuntime.(childEffectObservationRuntime)
	owner, sok := r.currentChildSnapshotOwner()
	if !ok || !rok || !sok || r.Store == nil {
		return empty, errors.New("child effect current observation supplier pending")
	}
	current := r.currentAuthorityManifest()
	found := false
	for _, actual := range current.CellEntriesV3 {
		if reflect.DeepEqual(actual, entry) {
			found = true
		}
	}
	if !found || entry.DesiredState != "active" || entry.LifecyclePhase != "execute" {
		return empty, errors.New("child effect observation entry changed")
	}
	box, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil {
		return empty, err
	}
	if box == nil || box.ObservedState != "running" || box.ObservedGeneration != entry.SandboxGeneration {
		return empty, errors.New("child effect observation Sandbox changed")
	}
	snapshot, err := owner.CurrentCellProductWorkflowSnapshot(ctx, entry)
	if err != nil {
		return empty, err
	}
	op, err := control.WorkflowObservationOperation(ctx, call, current.DesiredRevision)
	if err != nil {
		return empty, err
	}
	if !op.MatchesCurrentSnapshot(snapshot) {
		return empty, errors.New("child effect operation current snapshot conflict")
	}
	text, err := r.fetchCellFirstText(ctx, cellV2View(entry))
	if err != nil {
		return empty, err
	}
	envelope, err := runtime.ObserveCellProductEffect(ctx, model.Sandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, ImageDigest: box.ImageDigest, Cell: true}, entry, current, []byte(text), call, op, snapshot)
	if err != nil {
		return empty, err
	}
	again, err := owner.CurrentCellProductWorkflowSnapshot(ctx, entry)
	if err != nil || model.WorkspaceDigest(again) != model.WorkspaceDigest(snapshot) || r.currentAuthorityManifest().DesiredRevision != current.DesiredRevision {
		return empty, errors.New("child effect current authority moved")
	}
	receipt, err := control.ReportWorkflowObservation(ctx, envelope)
	if err != nil {
		return empty, err
	}
	if err = runtime.RetainCellProductObservationReceipt(ctx, envelope, receipt); err != nil {
		return empty, err
	}
	return receipt, nil
}

type childEffectControl interface {
	ChildProductEffectControl(context.Context, string, int) (model.ChildProductEffectDelivery, error)
}
type childEffectRuntime interface {
	AdoptCellProductEffectControl(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, model.ChildProductEffectDelivery, []byte) error
}

// Explicit post-admission current publication on existing node transport. F1 GET
// independently requires committed child-admission and (for ordinal1) actual
// settled own MCP artifact/ROOT receipt. No polling, retry or model invocation.
func (r *Reconciler) PublishApprovedChildEffect(ctx context.Context, entry model.CellServiceV3, ordinal int) error {
	control, ok := r.ManagedControl.(childEffectControl)
	runtime, rok := r.ManagedRuntime.(childEffectRuntime)
	if !ok || !rok || r.Store == nil || ordinal < 0 || ordinal > 1 || entry.DesiredState != "active" || entry.LifecyclePhase != "execute" {
		return errors.New("child effect publication dependency pending")
	}
	current := r.currentAuthorityManifest()
	found := false
	for _, actual := range current.CellEntriesV3 {
		if reflect.DeepEqual(actual, entry) {
			found = true
		}
	}
	if !found {
		return errors.New("child effect current entry changed")
	}
	local, err := r.Store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil {
		return err
	}
	if local == nil || local.Report.ObservedState != "ready" || local.Report.Child == nil || local.Report.Child.SessionID != entry.NativeSessionID || !reflect.DeepEqual(entry.ExecutionGrant, &local.Grant) || (local.Phase != "admitted" && local.Phase != "terminal") {
		return errors.New("child effect actual admission pending")
	}
	box, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil {
		return err
	}
	if box == nil || box.ObservedState != "running" || box.ObservedGeneration != entry.SandboxGeneration {
		return errors.New("child effect Sandbox changed")
	}
	delivery, err := control.ChildProductEffectControl(ctx, entry.PreparationID, ordinal)
	if err != nil {
		return err
	}
	text, err := r.fetchCellFirstText(ctx, cellV2View(entry))
	if err != nil {
		return err
	}
	if r.currentAuthorityManifest().DesiredRevision != current.DesiredRevision {
		return errors.New("child effect authority moved")
	}
	return runtime.AdoptCellProductEffectControl(ctx, model.Sandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, ImageDigest: box.ImageDigest, Cell: true}, entry, current, delivery, []byte(text))
}
