package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type childWorkflowRoleRuntime interface {
	AttestCellWorkflowRole(context.Context, model.WorkflowRoleOperation, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, workspacecatalog.RegisteredProject, json.RawMessage) (model.WorkflowRoleEnvelope, error)
}

// Continue only the children whose accepted manager intent and native terminal
// originals were retained by the owning first-task path. Completion does not
// grant a child a parent lease or imply result/integration/review acceptance.
func (r *Reconciler) reconcileControllerChildCompletionLocked(ctx context.Context, owner api.OwnerFirstTaskOriginal) error {
	if _, ok := r.ManagedRuntime.(childWorkflowRoleRuntime); !ok {
		return nil // Preserve older metadata-only adapters; they cannot report results.
	}
	result, err := r.readControllerFirstTaskResultLocked(ctx, owner.FirstTaskID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(result.Owner, owner) {
		return state.ErrControllerActivityConflict
	}
	if result.State != "completed" {
		return nil
	}
	scope := controllerChildApplicationFromFirstTask(owner)
	for _, child := range result.Children {
		var entry *model.CellServiceV3
		for _, actual := range r.currentAuthorityManifest().CellEntriesV3 {
			if actual.PreparationID == child.PreparationAssociation.PreparationID {
				if entry != nil {
					return state.ErrControllerActivityConflict
				}
				copy := actual
				entry = &copy
			}
		}
		if entry == nil {
			return ErrControllerFirstTaskPending
		}
		pending, err := r.Store.HasPendingOwnedContinuation(ctx, entry.PreparationID, "completion-")
		if err != nil {
			return err
		}
		if pending {
			return state.ErrOwnedContinuationUnknown
		}
		if complete, err := r.completedChildResultHistoryLocked(ctx, scope, child, *entry); err != nil {
			return err
		} else if complete {
			if err := r.retainCompletedChildOriginLocked(ctx, "first_task", owner.FirstTaskID, scope, child, *entry); err != nil {
				return err
			}
			continue
		}
		role, err := r.ensureCompletedChildWorkflowRoleLocked(ctx, scope, child, *entry)
		if err != nil {
			return fmt.Errorf("completed child role: %w", err)
		}
		settlement, err := r.ensureCompletedChildSettlementLocked(ctx, scope, child, *entry)
		if err != nil {
			return fmt.Errorf("completed child settlement: %w", err)
		}
		artifact, err := r.ensureCompletedChildArtifactLocked(ctx, scope, child, *entry)
		if err != nil {
			return fmt.Errorf("completed child artifact: %w", err)
		}
		if err = r.ensureCompletedChildResultLocked(ctx, scope, child, *entry, role, settlement, artifact); err != nil {
			return fmt.Errorf("completed child result: %w", err)
		}
		if raw, e := r.Store.OwnedContinuationClaim(ctx, entry.PreparationID, "completion-result"); e != nil {
			return e
		} else if len(raw) != 0 {
			if e = r.retainCompletedChildOriginLocked(ctx, "first_task", owner.FirstTaskID, scope, child, *entry); e != nil {
				return e
			}
		}
	}
	return nil
}

func (r *Reconciler) ensureCompletedChildWorkflowRoleLocked(ctx context.Context, owner controllerChildApplication, child ControllerFirstTaskChildResult, entry model.CellServiceV3) (model.WorkflowRoleEnrollment, error) {
	var empty model.WorkflowRoleEnrollment
	control, ok := r.ManagedControl.(workflowRoleControl)
	runtime, rok := r.ManagedRuntime.(childWorkflowRoleRuntime)
	if !ok || !rok || r.Store == nil {
		return empty, ErrControllerFirstTaskAuthorityPending
	}
	// Recheck local STATE and independently fetched backend state; the old terminal
	// snapshot is history, not an authority to enroll after a fence or role change.
	view, err := r.currentCompletedChildAuthority(ctx, owner, child, entry)
	if err != nil {
		return empty, err
	}
	fresh, app, current, root, text := view.Fresh, view.Application, view.Manifest, view.Root, view.Input
	var binding struct {
		WorkID      string `json:"workId"`
		ExecutionID string `json:"executionId"`
	}
	if json.Unmarshal(child.Binding, &binding) != nil || binding.WorkID == "" || binding.ExecutionID != child.ExecutionID || (entry.Role != "worker" && entry.Role != "reviewer") {
		return empty, state.ErrControllerActivityConflict
	}
	o := owner.Owner
	subject := model.WorkflowRoleSubject{AccountID: o.AccountID, TaskID: o.TaskID, ServerID: o.ServerID, SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration, CellID: entry.OwnerCellID, Role: entry.Role, ControllerID: entry.ControllerID, ControllerRevision: entry.ControllerRevision, AuthorityRevision: entry.AuthorityRevision, ServiceRegistrationID: entry.ServiceRegistrationID, ServiceGeneration: entry.ServiceGeneration, NativeSessionID: entry.NativeSessionID, WorkID: &binding.WorkID, ExecutionID: &binding.ExecutionID}
	call := model.WorkflowRoleOperationRequest{FormatVersion: 1, RequestID: "wfroleop_req_" + model.WorkspaceDigest(map[string]any{"application": owner.ApplicationOperationDigest, "binding": child.Binding, "subject": subject})[7:39], Subject: subject}
	var snapshot struct {
		ManagedServiceReceiptDigest string `json:"managedServiceReceiptDigest"`
		NativeContextDigest         string `json:"nativeContextDigest"`
	}
	if json.Unmarshal(fresh.BackendSnapshot, &snapshot) != nil {
		return empty, state.ErrControllerActivityConflict
	}
	var op model.WorkflowRoleOperation
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-role-operation", call, func() (any, error) { return control.WorkflowRoleEnrollmentOperation(ctx, call) }, &op); err != nil {
		return empty, err
	}
	expiry, err := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if op.Validate() != nil || !reflect.DeepEqual(op.Subject, subject) || op.NodeTokenHash != app.Operation.Producer.NodeTokenHash || op.ManagedServiceReceiptDigest != snapshot.ManagedServiceReceiptDigest || op.NativeContextDigest != snapshot.NativeContextDigest {
		return empty, fmt.Errorf("role operation conflict: %w", state.ErrControllerActivityConflict)
	}
	if err != nil || !r.now().Before(expiry) {
		return empty, ErrWorkflowRoleExpired
	}
	var proof model.WorkflowRoleEnvelope
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-role-proof", op, func() (any, error) {
		return runtime.AttestCellWorkflowRole(ctx, op, view.Sandbox, entry, current, text, root, fresh.BackendSnapshot)
	}, &proof); err != nil {
		return empty, err
	}
	proofExpiry, err := time.Parse(time.RFC3339Nano, proof.Payload.NotAfter)
	if proof.Validate() != nil || proof.KeyID != app.Operation.Producer.KeyID || proof.Payload.OperationDigest != op.OperationDigest || proof.Payload.OperationID != op.OperationID || !reflect.DeepEqual(proof.Payload.Subject, subject) || proof.Payload.NodeTokenHash != op.NodeTokenHash || proof.Payload.NativeContextDigest != op.NativeContextDigest || proof.Payload.ManagedServiceReceiptDigest != op.ManagedServiceReceiptDigest {
		return empty, fmt.Errorf("role proof conflict: %w", state.ErrControllerActivityConflict)
	}
	if err != nil || !r.now().Before(proofExpiry) || proofExpiry.After(expiry) {
		return empty, ErrWorkflowRoleExpired
	}
	again, err := r.currentCompletedChildAuthority(ctx, owner, child, entry)
	if err != nil {
		return empty, err
	}
	if !sameCompletedChildAuthority(view, again) {
		return empty, fmt.Errorf("current role observation changed: %w", state.ErrControllerActivityConflict)
	}
	var enrolled model.WorkflowRoleEnrollment
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-role-enroll", proof, func() (any, error) { return control.EnrollWorkflowRole(ctx, proof) }, &enrolled); err != nil {
		return empty, err
	}
	leaseExpiry, err := time.Parse(time.RFC3339Nano, enrolled.ExpiresAt)
	if enrolled.Validate() != nil || err != nil || !r.now().Before(leaseExpiry) || leaseExpiry.After(proofExpiry) {
		return empty, ErrWorkflowRoleExpired
	}
	return enrolled, nil
}
