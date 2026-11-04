package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Local durable original readout, not a new backend/native wire or a business
// result-decision. completed means accepted intents' exact native executions were
// terminalized by existing authenticated STATE; it never means cash/artifact/review
// acceptance or substitutes for those independent workflow records.
type ControllerFirstTaskResult struct {
	Owner                api.OwnerFirstTaskOriginal       `json:"owner"`
	ManagerPreparationID string                           `json:"managerPreparationId"`
	IntentReceipt        model.ManagerActionReceipt       `json:"intentReceipt"`
	State                string                           `json:"state"`
	Children             []ControllerFirstTaskChildResult `json:"children"`
}
type ControllerFirstTaskChildResult struct {
	Handle                 model.IntentHandle                 `json:"handle"`
	ExecutionID            string                             `json:"executionId"`
	Binding                json.RawMessage                    `json:"binding"`
	PreparationAssociation model.ActualPreparationAssociation `json:"preparationAssociation"`
	AdmissionAssociation   model.ChildAdmissionAssociation    `json:"admissionAssociation"`
	NativeReport           model.CellServiceReportV1          `json:"nativeReport"`
	BackendSnapshot        json.RawMessage                    `json:"backendSnapshot"`
}
type childTerminalSnapshotReader interface {
	WorkflowCurrentSnapshot(context.Context, string) (json.RawMessage, error)
}

// Snapshot is a fresh authentication witness, not immutable identity: later
// settled observations may legitimately appear. Retain the first full witness
// unchanged, and key replay by the immutable owner/accepted associations/terminal
// originals only. Every normal pass still performs the current read/failure gate.
func controllerFirstTaskResultClaim(result ControllerFirstTaskResult) ControllerFirstTaskResult {
	result.Children = append([]ControllerFirstTaskChildResult(nil), result.Children...)
	for i := range result.Children {
		result.Children[i].BackendSnapshot = nil
	}
	return result
}

func (r *Reconciler) readControllerFirstTaskChildTerminalLocked(ctx context.Context, owner api.OwnerFirstTaskOriginal, handle model.IntentHandle, actual model.ActualPreparationAssociation, entry model.CellServiceV3, admission model.ChildAdmissionAssociation) (ControllerFirstTaskChildResult, error) {
	return r.readControllerChildTerminalLocked(ctx, owner.Owner, handle, actual, entry, admission)
}

func (r *Reconciler) readControllerChildTerminalLocked(ctx context.Context, owner model.ControllerOwner, handle model.IntentHandle, actual model.ActualPreparationAssociation, entry model.CellServiceV3, admission model.ChildAdmissionAssociation) (ControllerFirstTaskChildResult, error) {
	var empty ControllerFirstTaskChildResult
	if handle.Owner != owner || actual.ValidateIntegrity() != nil || actual.HandleID != handle.HandleID || actual.Intent != handle.Intent || admission.ValidateIntegrity() != nil || admission.HandleID != handle.HandleID || admission.PreparationAssociationDigest != actual.AssociationDigest || entry.ExecutionGrant == nil || !reflect.DeepEqual(admission.Grant, *entry.ExecutionGrant) || entry.ValidateExecutionAuthority(actual.PreparedReceipt) != nil {
		return empty, state.ErrControllerActivityConflict
	}
	var binding struct {
		WorkID                string `json:"workId"`
		WorkRevision          int64  `json:"workRevision"`
		ExecutionID           string `json:"executionId"`
		PreparationID         string `json:"preparationId"`
		NativeSessionID       string `json:"nativeSessionId"`
		NativeProjectID       string `json:"nativeProjectId"`
		ServiceRegistrationID string `json:"serviceRegistrationId"`
		ServiceGeneration     int64  `json:"serviceGeneration"`
		SandboxGeneration     int64  `json:"sandboxGeneration"`
		Attempt               int64  `json:"attempt"`
		Fence                 string `json:"fence"`
	}
	// Whole closed domain binding is validated, then only its selector is projected.
	if workflowcontract.Validate(workflowcontract.Domain, "binding", actual.Binding) != nil || json.Unmarshal(actual.Binding, &binding) != nil || binding.WorkID == "" || binding.WorkRevision < 1 || binding.PreparationID != entry.PreparationID || binding.NativeSessionID != entry.NativeSessionID || binding.NativeProjectID != entry.NativeProjectID || binding.ServiceRegistrationID != entry.ServiceRegistrationID || binding.ServiceGeneration != entry.ServiceGeneration || binding.SandboxGeneration != entry.SandboxGeneration || binding.Attempt != entry.Attempt || binding.Fence != entry.Fence {
		return empty, state.ErrControllerActivityConflict
	}
	local, err := r.Store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil {
		return empty, err
	}
	if local == nil {
		return empty, ErrControllerFirstTaskPending
	} // Normal V3 dispatch not yet observed.
	if !reflect.DeepEqual(local.Grant, admission.Grant) || local.Report.LastError != nil || local.Report.Exhausted || local.Report.Child == nil || local.Phase == "unknown" || local.Phase == "exhausted" {
		return empty, state.ErrOwnedContinuationUnknown
	}
	var native managedCellExecuteResultV3
	if decodeManagedReceipt(local.EffectJSON, &native, true) != nil || native.GuardReceipt == nil || native.GuardReceipt.State != "delivered" && native.GuardReceipt.State != "admitted" || native.GuardReceipt.FormatVersion != 1 || native.GuardReceipt.SessionID != entry.NativeSessionID || native.GuardReceipt.InboxID != local.Grant.InputID || native.GuardReceipt.GuardID != local.Grant.GrantID || native.GuardReceipt.BindingDigest != actual.PreparedReceipt.BindingDigest || native.SchemaVersion != 1 || !CellExecutionEnabled(native.RuntimeContractVersion) || native.OperationID != entry.LaunchOperationID || native.SessionID != entry.NativeSessionID || native.MessageID != local.Grant.InputID || native.Attempt != entry.Attempt || native.Exhausted {
		return empty, state.ErrCellV3OperationConflict
	}
	expected := r.cancelledReport(cellV2View(entry), entry.Attempt, "ready", model.RawPhysicalDigest(local.EffectJSON))
	expected.FormatVersion = 3
	expected.Child = &model.ManagedCellChildV1{OperationID: native.OperationID, SessionID: native.SessionID, MessageID: native.MessageID, State: native.State, Attempt: native.Attempt, Outcome: native.Outcome, Exhausted: false}
	if !reflect.DeepEqual(expected, local.Report) {
		return empty, state.ErrCellV3OperationConflict
	}
	if local.Phase == "admitted" && native.State == "running" && native.Outcome == nil {
		return empty, ErrControllerFirstTaskPending
	}
	if local.Phase != "terminal" || native.State != "terminal" || native.Outcome == nil || (*native.Outcome != "succeeded" && *native.Outcome != "failed") || native.GuardReceipt.State != "delivered" {
		return empty, state.ErrCellV3OperationConflict
	}
	reader, ok := r.ManagedControl.(childTerminalSnapshotReader)
	if !ok {
		return empty, errors.New("existing authenticated execution snapshot reader unavailable")
	}
	raw, err := reader.WorkflowCurrentSnapshot(ctx, binding.ExecutionID)
	if err != nil {
		return empty, err
	}
	var snapshot struct {
		ExecutionState              string  `json:"executionState"`
		ExecutionReceiptDigest      *string `json:"executionReceiptDigest"`
		DesiredState                string  `json:"desiredState"`
		DesiredRevision             int64   `json:"desiredRevision"`
		ManagedServiceReceiptDigest string  `json:"managedServiceReceiptDigest"`
		NativeContextDigest         string  `json:"nativeContextDigest"`
		Role                        string  `json:"role"`
		Grants                      []struct {
			GrantID string `json:"grantId"`
			State   string `json:"state"`
			Fence   string `json:"fence"`
			Attempt int64  `json:"attempt"`
		} `json:"grants"`
		Children []struct {
			ExecutionID   string  `json:"executionId"`
			State         string  `json:"state"`
			ReceiptDigest *string `json:"receiptDigest"`
		} `json:"children"`
		Effects []struct {
			ReceiptID     string `json:"receiptId"`
			ReceiptDigest string `json:"receiptDigest"`
			Status        string `json:"status"`
		} `json:"effects"`
	}
	if model.DecodePhysicalClosed(raw, &snapshot) != nil || snapshot.DesiredState != entry.DesiredState || snapshot.DesiredRevision != entry.DesiredRevision || snapshot.Role != entry.Role || !model.PhysicalDigestValid(snapshot.ManagedServiceReceiptDigest) || !model.PhysicalDigestValid(snapshot.NativeContextDigest) || snapshot.Grants == nil || snapshot.Children == nil || snapshot.Effects == nil || len(snapshot.Grants) > 64 || len(snapshot.Children) > 64 || len(snapshot.Effects) > 64 {
		return empty, state.ErrControllerActivityConflict
	}
	matched := 0
	for _, grant := range snapshot.Grants {
		if grant.GrantID == local.Grant.GrantID {
			matched++
			if grant.Fence != entry.Fence || grant.Attempt != entry.Attempt || grant.State != "consumed" {
				return empty, state.ErrControllerActivityConflict
			}
		}
	}
	if matched != 1 {
		return empty, state.ErrControllerActivityConflict
	}
	for _, child := range snapshot.Children {
		if child.ExecutionID == "" || child.ReceiptDigest == nil || !model.PhysicalDigestValid(*child.ReceiptDigest) || (child.State != "completed" && child.State != "failed") {
			return empty, state.ErrControllerActivityConflict
		}
	}
	for _, effect := range snapshot.Effects {
		if effect.Status == "unknown" {
			return empty, state.ErrOwnedContinuationUnknown
		}
		if effect.ReceiptID == "" || !model.PhysicalDigestValid(effect.ReceiptDigest) || effect.Status != "settled" {
			return empty, state.ErrControllerActivityConflict
		}
	}
	if (snapshot.ExecutionState == "admitted" || snapshot.ExecutionState == "running") && snapshot.ExecutionReceiptDigest == nil {
		return empty, ErrControllerFirstTaskPending
	} // Exact terminal report has not reached STATE yet.
	stateExpected := "completed"
	if *native.Outcome == "failed" {
		stateExpected = "failed"
	}
	if snapshot.ExecutionState != stateExpected || snapshot.ExecutionReceiptDigest == nil || *snapshot.ExecutionReceiptDigest != local.Report.ReceiptDigest || ctx.Err() != nil {
		return empty, state.ErrControllerActivityConflict
	}
	return ControllerFirstTaskChildResult{handle, binding.ExecutionID, append(json.RawMessage(nil), actual.Binding...), actual, admission, local.Report, append(json.RawMessage(nil), raw...)}, nil
}

// Read only the original already authenticated by normal continuation. No POST,
// effect, snapshot GET, signing or STORE claim is performed by this observer.
func (r *Reconciler) ReadControllerFirstTaskResult(ctx context.Context, taskID string) (ControllerFirstTaskResult, error) {
	var empty ControllerFirstTaskResult
	if err := r.lockControllerOriginalRead(ctx); err != nil {
		return empty, err
	}
	defer r.mu.Unlock()
	return r.readControllerFirstTaskResultLocked(ctx, taskID)
}

func (r *Reconciler) readControllerFirstTaskResultLocked(ctx context.Context, taskID string) (ControllerFirstTaskResult, error) {
	var empty ControllerFirstTaskResult
	if r.Store == nil {
		return empty, state.ErrControllerActivityConflict
	}
	claim, err := r.Store.OwnedContinuationClaim(ctx, taskID, "result")
	if err != nil {
		return empty, err
	}
	if len(claim) == 0 {
		return empty, ErrControllerFirstTaskPending
	}
	raw, err := r.Store.OwnedContinuationResult(ctx, taskID, "result", claim)
	if err != nil {
		return empty, err
	}
	var result ControllerFirstTaskResult
	if model.DecodePhysicalClosed(raw, &result) != nil || result.Owner.FirstTaskID != taskID || model.WorkspaceDigest(json.RawMessage(claim)) != model.WorkspaceDigest(controllerFirstTaskResultClaim(result)) || len(result.Children) == 0 || (result.State != "completed" && result.State != "failed") {
		return empty, state.ErrControllerActivityConflict
	}
	ownerClaim, err := r.Store.OwnedContinuationClaim(ctx, taskID, "owner-original")
	if err != nil {
		return empty, err
	}
	ownerRaw, err := r.Store.OwnedContinuationResult(ctx, taskID, "owner-original", ownerClaim)
	if err != nil {
		return empty, err
	}
	if model.WorkspaceDigest(json.RawMessage(ownerRaw)) != model.WorkspaceDigest(result.Owner) {
		return empty, state.ErrControllerActivityConflict
	}
	preparedRaw, err := r.Store.ControllerActivityStage(ctx, result.ManagerPreparationID, state.ControllerNativePrepared)
	if err != nil {
		return empty, err
	}
	var prepared model.ControllerPreparedEnvelope
	if json.Unmarshal(preparedRaw, &prepared) != nil || prepared.Payload.PreparedTuple.Role != "manager" {
		return empty, state.ErrControllerActivityConflict
	}
	current, err := r.readControllerFirstTaskParentPreparationLocked(ctx, taskID, prepared.Payload.PreparedTuple.ServiceRegistrationID)
	if err != nil {
		return empty, err
	}
	if current.PreparationID != result.ManagerPreparationID || !reflect.DeepEqual(current, prepared.Payload) {
		return empty, state.ErrControllerActivityConflict
	}
	action, err := r.readControllerParentActionReceiptLocked(ctx, current.PreparationID)
	if err != nil {
		return empty, err
	}
	if model.WorkspaceDigest(json.RawMessage(action)) != model.WorkspaceDigest(result.IntentReceipt) {
		return empty, state.ErrControllerActivityConflict
	}
	return result, nil
}
