package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type controllerInitialDecisionReader interface {
	ReadControllerInitialDecision(context.Context, model.Manifest, model.ControllerParentIntent, model.ControllerApprovedInputContext, json.RawMessage) (qualification.ControllerDeclaredInput, error)
}

type controllerInitialDecisionOriginal struct {
	OwnerOriginal api.OwnerFirstTaskOriginal            `json:"ownerOriginal"`
	Advice        json.RawMessage                       `json:"advice"`
	Manager       model.ControllerParentIntent          `json:"manager"`
	DeclaredInput qualification.ControllerDeclaredInput `json:"declaredInput"`
}

// SAME task/application; choose only its actual current manager, never a second
// owner task, caller-selected role or direct workflow Prepare call.
func (r *Reconciler) reconcileControllerInitialDecisionLocked(ctx context.Context, o api.OwnerFirstTaskOriginal, advice json.RawMessage) error {
	if workflowcontract.Validate(workflowcontract.Domain, "adviceReceipt", advice) != nil {
		return state.ErrControllerActivityConflict
	}
	var manager *model.ControllerParentIntent
	for _, parent := range r.currentAuthorityManifest().ParentServices {
		if parent.ApplicationOperationID == o.ApplicationOperationID && parent.Role == "manager" && parent.DesiredState == "active" {
			if manager != nil || parent.Owner != o.Owner {
				return state.ErrControllerActivityConflict
			}
			copy := parent
			manager = &copy
		}
	}
	if manager == nil {
		return ErrControllerFirstTaskAuthorityPending
	}
	bound := r.firstTaskManagerAuthority
	if bound == nil {
		return ErrControllerFirstTaskAuthorityPending
	}
	if bound.operationDigest != o.ApplicationOperationDigest || bound.parent != *manager {
		return state.ErrControllerActivityConflict
	}
	claimRaw, err := model.WorkspaceCanonicalJSON(o)
	if err != nil {
		return err
	}
	raw, err := r.Store.OwnedContinuationResult(ctx, o.FirstTaskID, "parent-prepare", claimRaw)
	var prepared model.ControllerPreparedReceipt
	if err != nil {
		return err
	}
	if json.Unmarshal(raw, &prepared) != nil {
		return state.ErrControllerActivityConflict
	}
	input, err := r.readControllerParentApprovedInputLocked(ctx, prepared.PreparationID)
	if err != nil {
		return err
	}
	// Once retained, the declaration is immutable task history. A later file
	// extension/expiry cannot silently rebind it or erase a completed activity.
	prior, err := r.Store.OwnedContinuationClaim(ctx, o.FirstTaskID, "initial-decision-original")
	if err != nil {
		return err
	}
	var declared qualification.ControllerDeclaredInput
	if len(prior) != 0 {
		var original controllerInitialDecisionOriginal
		if json.Unmarshal(prior, &original) != nil || !reflect.DeepEqual(original.OwnerOriginal, o) || original.Manager != *manager || model.WorkspaceDigest(original.Advice) != model.WorkspaceDigest(advice) {
			return state.ErrOwnedContinuationUnknown
		}
		result, err := r.Store.OwnedContinuationResult(ctx, o.FirstTaskID, "initial-decision-original", prior)
		if err != nil {
			return err
		}
		if json.Unmarshal(result, &declared) != nil || !reflect.DeepEqual(original.DeclaredInput, declared) {
			return state.ErrOwnedContinuationUnknown
		}
	} else {
		reader, ok := r.ManagedRuntime.(controllerInitialDecisionReader)
		if !ok {
			return ErrControllerFirstTaskAuthorityPending
		}
		declared, err = reader.ReadControllerInitialDecision(ctx, r.currentAuthorityManifest(), *manager, input.Context, advice)
		if errors.Is(err, qualification.ErrControllerDeclarationPending) {
			return ErrControllerFirstTaskPending
		}
		if err != nil {
			return err
		}
	}
	item, err := model.WorkspaceCanonicalJSON(declared)
	document, definition := workflowcontract.Budget, "approvedInputItem2"
	if declared.Target.Kind == "manager_work_intent" && o.FormatVersion == 2 {
		document, definition = workflowcontract.ManagerSingle, "approvedInputItem3"
	}
	if err != nil || workflowcontract.Validate(document, definition, item) != nil || declared.ServiceRegistrationID != manager.ServiceRegistrationID || (declared.Target.Kind != "manager_work_intents" && declared.Target.Kind != "manager_work_intent") || declared.Target.Role != "manager" || declared.Target.Advice == nil || model.WorkspaceDigest(*declared.Target.Advice) != model.WorkspaceDigest(advice) || !reflect.DeepEqual(declared.Plan, input.Context.Plan) {
		return state.ErrControllerActivityConflict
	}
	app, err := r.Store.WorkspaceApplication(ctx, o.ApplicationOperationID)
	if err != nil {
		return err
	}
	if app == nil {
		return state.ErrControllerActivityConflict
	}
	dependency, err := app.Operation.ParentDependency(*manager)
	if err != nil || dependency.Projection.ModelSelection == nil {
		return state.ErrControllerActivityConflict
	}
	call := api.ControllerPreparationRequest{FormatVersion: 1, RequestID: declared.WorkflowRequestID, ServiceRegistrationID: manager.ServiceRegistrationID, InputID: declared.InputID, InputDigest: model.RawPhysicalDigest([]byte(declared.InputText)), ModelSelection: *dependency.Projection.ModelSelection}
	if o.FormatVersion == 2 {
		p := providerpolicy.Flash()
		if call.ModelSelection.Authority != (model.CellPreparedAuthorityV3{ProviderID: p.ProviderID, ModelID: p.ModelID, AuthMode: p.AuthMode}) || o.ParentActivityRequest.ProviderPolicyDigest != providerpolicy.FlashDigest {
			return state.ErrControllerActivityConflict
		}
		call.FormatVersion, call.ProviderPolicyDigest = 2, o.ParentActivityRequest.ProviderPolicyDigest
	}
	claim := controllerInitialDecisionOriginal{o, advice, *manager, declared}
	var retained qualification.ControllerDeclaredInput
	if err = r.ownedContinuationOnce(ctx, o.FirstTaskID, "initial-decision-original", claim, func() (any, error) { return declared, nil }, &retained); err != nil {
		return err
	}
	_, err = r.progressControllerFirstTaskParentLocked(ctx, o.FirstTaskID, "initial-decision", claim, *bound, call, retained.InputText, &retained)
	if err != nil {
		return err
	}
	prepared, err = r.readControllerFirstTaskParentPreparationLocked(ctx, o.FirstTaskID, manager.ServiceRegistrationID)
	if err != nil {
		return err
	}
	return r.reconcileControllerFirstTaskChildrenLocked(ctx, o, prepared.PreparationID, *bound)
}
