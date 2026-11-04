package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

var ErrControllerFirstTaskChildIssuerPending = fmt.Errorf("%w: independent child policy/activation issuer delivery pending", ErrControllerFirstTaskPending)

// SAME normal owning pass after actual accepted manager action. Never dispatch a
// child directly: existing V3 manifest/report consumers own prepare and execute.
// Fixed public-original delivery precedes preparation and PRODUCT continuation;
// neither an unsigned basis nor a future execute policy supplies pre-header input.
func (r *Reconciler) reconcileControllerFirstTaskChildrenLocked(ctx context.Context, owner api.OwnerFirstTaskOriginal, parentID string, bound controllerFirstTaskAuthority) error {
	progress, err := r.reconcileControllerChildrenLocked(ctx, owner.Owner, parentID, bound)
	if err != nil {
		return err
	}
	result := ControllerFirstTaskResult{Owner: owner, ManagerPreparationID: progress.ManagerPreparationID, IntentReceipt: progress.IntentReceipt, State: progress.State, Children: progress.Children}
	var retained ControllerFirstTaskResult
	return r.ownedContinuationOnce(ctx, owner.FirstTaskID, "result", controllerFirstTaskResultClaim(result), func() (any, error) { return result, nil }, &retained)
}

type controllerChildrenProgress struct {
	ManagerPreparationID string                           `json:"managerPreparationId"`
	IntentReceipt        model.ManagerActionReceipt       `json:"intentReceipt"`
	State                string                           `json:"state"`
	Children             []ControllerFirstTaskChildResult `json:"children"`
}

func (r *Reconciler) reconcileControllerChildrenLocked(ctx context.Context, owner model.ControllerOwner, parentID string, bound controllerFirstTaskAuthority) (controllerChildrenProgress, error) {
	var empty controllerChildrenProgress
	if bound.parent.Role != "manager" || bound.lease == "" || r.Store == nil {
		return empty, state.ErrControllerActivityConflict
	}
	action, err := r.readControllerParentActionReceiptLocked(ctx, parentID)
	if err != nil {
		return empty, err
	}
	var accepted model.ManagerActionReceipt
	if json.Unmarshal(action, &accepted) != nil {
		return empty, state.ErrControllerActivityConflict
	}
	type child struct {
		member  string
		pending model.IntentPreparationReference
	}
	children := []child{}
	for _, member := range accepted.Members() {
		decision, err := accepted.Decision(member)
		if err != nil {
			return empty, state.ErrControllerActivityConflict
		}
		if decision.Choice != "admit" {
			continue
		} // No rejected member is dispatched.
		pending, err := r.BeginApprovedManagerChild(ctx, parentID, member, bound.lease)
		if err != nil {
			return empty, err
		} // UNKNOWN or denial stops before any next effect.
		children = append(children, child{member, pending})
	}
	var waiting error
	var unpublishedPreparations []string
	result := controllerChildrenProgress{ManagerPreparationID: parentID, IntentReceipt: accepted, State: "completed", Children: []ControllerFirstTaskChildResult{}}
	for _, child := range children {
		local, err := r.Store.CellV3Operation(ctx, child.pending.PreparationID)
		if err != nil {
			return empty, err
		}
		if local == nil || local.Phase == "pending" {
			if _, ok := r.ManagedRuntime.(managerChildDeliveryRuntime); !ok {
				waiting = ErrControllerFirstTaskPending
			} else {
				if err := r.ensureChildPreparationDeliveryLocked(ctx, parentID, child.member, bound.lease, child.pending); errors.Is(err, ErrControllerFirstTaskPending) {
					waiting = err
					var deliveryWait *controllerChildPrepareDeliveryPending
					if errors.As(err, &deliveryWait) {
						unpublishedPreparations = append(unpublishedPreparations, deliveryWait.preparationIDs...)
					}
				} else if err != nil {
					return empty, err
				}
			}
			continue
		} // Known missing actual prepare/report.
		if local.Phase != "reported" {
			if local.Phase == "pending" || local.Phase == "prepared" {
				waiting = ErrControllerFirstTaskPending
				continue
			}
			return empty, state.ErrCellV3OperationConflict
		}
		_, handle, _, actual, entry, err := r.managerChildPreparedCurrent(ctx, parentID, child.member, bound.lease, false)
		if err != nil {
			return empty, err
		}
		if !reflect.DeepEqual(local.Receipt, actual.PreparedReceipt) {
			return empty, state.ErrCellV3OperationConflict
		}
		assignment, err := r.AssignApprovedManagerChild(ctx, parentID, child.member, bound.lease)
		if err != nil {
			return empty, err
		}
		if entry.LifecyclePhase == "prepare" {
			if _, ok := r.ManagedRuntime.(managerChildDeliveryRuntime); ok {
				if err := r.ensureChildProductDeliveryLocked(ctx, parentID, child.member, bound.lease, handle, actual, entry); errors.Is(err, ErrControllerFirstTaskPending) {
					waiting = err
					continue
				} else if err != nil {
					return empty, err
				}
			}
			// Existing owning POST journal is an original source, not a new issuer
			// or speculative GET. Missing independent signed request stays blocked.
			claim, err := r.Store.OwnedContinuationClaim(ctx, handle.HandleID, "product-policy")
			if err != nil {
				return empty, err
			}
			if len(claim) == 0 {
				waiting = ErrControllerFirstTaskChildIssuerPending
				continue
			}
			var original struct {
				HandleDigest              string          `json:"handleDigest"`
				PreparedAssociationDigest string          `json:"preparedAssociationDigest"`
				Request                   json.RawMessage `json:"request"`
			}
			if model.DecodePhysicalClosed(claim, &original) != nil || original.HandleDigest != handle.HandleDigest || original.PreparedAssociationDigest != actual.AssociationDigest || workflowcontract.Validate(workflowcontract.Budget, "policyAcceptRequest", original.Request) != nil {
				return empty, state.ErrControllerActivityConflict
			}
			// A lost policy ACK cannot be retried by the normal observation caller.
			if _, err = r.Store.OwnedContinuationResult(ctx, handle.HandleID, "product-policy", claim); err != nil {
				return empty, err
			}
			if _, err = r.ObserveApprovedManagerChildAuthorization(ctx, parentID, child.member, bound.lease, original.Request); err != nil {
				return empty, err
			}
			waiting = ErrControllerFirstTaskChildIssuerPending // Independent activation + published execute manifest next.
			continue
		}
		if entry.LifecyclePhase != "execute" {
			return empty, state.ErrCellV3OperationConflict
		}
		// Existing product-control carries genuine published signed originals;
		// adoption independently verifies them before retaining admission association.
		claim, err := r.Store.OwnedContinuationClaim(ctx, handle.HandleID, "adopt")
		if err != nil {
			return empty, err
		}
		var admitted model.ChildAdmissionAssociation
		if len(claim) == 0 {
			admitted, err = r.AdoptApprovedManagerChild(ctx, parentID, child.member, bound.lease)
		} else {
			var raw []byte
			raw, err = r.Store.OwnedContinuationResult(ctx, handle.HandleID, "adopt", claim)
			if err == nil {
				err = model.DecodeManagerContract("childAdmissionAssociation", raw, &admitted)
			}
			var original struct {
				HandleDigest              string                     `json:"handleDigest"`
				PreparedAssociationDigest string                     `json:"preparedAssociationDigest"`
				Assignment                json.RawMessage            `json:"assignment"`
				PolicyDigest              string                     `json:"policyDigest"`
				Grant                     model.CellExecutionGrantV3 `json:"grant"`
			}
			if err == nil && (model.DecodePhysicalClosed(claim, &original) != nil || original.HandleDigest != handle.HandleDigest || original.PreparedAssociationDigest != actual.AssociationDigest || model.WorkspaceDigest(original.Assignment) != model.WorkspaceDigest(admitted.Assignment) || original.PolicyDigest != admitted.PolicyDigest || !reflect.DeepEqual(original.Grant, admitted.Grant)) {
				return empty, state.ErrControllerActivityConflict
			}
		}
		if err != nil {
			return empty, err
		}
		if model.WorkspaceDigest(admitted.Assignment) != model.WorkspaceDigest(assignment) || admitted.AllocationID != handle.AllocationID {
			return empty, state.ErrControllerActivityConflict
		}
		terminal, err := r.readControllerChildTerminalLocked(ctx, owner, handle, actual, entry, admitted)
		if errors.Is(err, ErrControllerFirstTaskPending) {
			waiting = err
			continue
		}
		if err != nil {
			return empty, err
		}
		result.Children = append(result.Children, terminal)
		if terminal.NativeReport.Child.Outcome != nil && *terminal.NativeReport.Child.Outcome == "failed" {
			result.State = "failed"
		}
	}
	if len(unpublishedPreparations) != 0 {
		return empty, &controllerChildPrepareDeliveryPending{unpublishedPreparations}
	}
	if waiting != nil {
		return empty, waiting
	}
	if len(result.Children) == 0 {
		return empty, state.ErrControllerActivityConflict
	}
	return result, nil
}
