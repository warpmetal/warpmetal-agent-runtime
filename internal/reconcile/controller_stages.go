package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type controllerStageControl interface {
	ControllerStageInput(context.Context, string, string, string) (model.ControllerStageReadout, error)
}
type controllerStageRuntime interface {
	ReadControllerFirstTaskApplicability(context.Context, model.Manifest, qualification.ControllerPolicyWitness) (qualification.Applicability, error)
	ReadControllerDeclaredStage(context.Context, model.Manifest, model.ControllerParentIntent, model.ControllerStageReadout) (qualification.ControllerDeclaredInput, error)
}
type controllerStageOriginal struct {
	Readout  model.ControllerStageReadout          `json:"readout"`
	Declared qualification.ControllerDeclaredInput `json:"declared"`
}

var ErrControllerLaterChildPending = fmt.Errorf("%w: accepted later parent action awaits its distinct child/result continuation", ErrControllerFirstTaskPending)

// Read-only discovery is application-scoped. Every new effect still uses the
// original protected declaration, current role and the SAME normal parent engine.
func (r *Reconciler) reconcileControllerStagesLocked(ctx context.Context, current model.Manifest) error {
	control, ok := r.ManagedControl.(controllerStageControl)
	runtime, rok := r.ManagedRuntime.(controllerStageRuntime)
	if !ok || !rok || r.Store == nil {
		return nil
	}
	for _, parent := range current.ParentServices {
		if parent.DesiredState != "active" || (parent.Role != "manager" && parent.Role != "orchestrator") {
			continue
		}
		app, err := r.Store.WorkspaceApplication(ctx, parent.ApplicationOperationID)
		if err != nil {
			return err
		}
		if app == nil || !app.Applied {
			continue
		}
		role, err := app.Operation.ParentDependency(parent)
		if err != nil {
			return err
		}
		descriptor := providerpolicy.Flash()
		if role.Projection.ModelSelection == nil || role.Projection.ModelSelection.Authority != (model.CellPreparedAuthorityV3{ProviderID: descriptor.ProviderID, ModelID: descriptor.ModelID, AuthMode: descriptor.AuthMode}) {
			continue
		} // Legacy first-task behavior is unchanged.
		w, err := r.controllerActivityCurrentWitness(ctx, parent.ServiceRegistrationID, qualification.Applicability{}, false)
		if err != nil {
			return err
		}
		installed, err := runtime.ReadControllerFirstTaskApplicability(ctx, current, w.Installed)
		if err != nil {
			return err
		}
		if installed.FormatVersion != 2 || installed.ProviderPolicyDigest != providerpolicy.FlashDigest {
			return state.ErrControllerActivityConflict
		}
		names := []string{"manager_integrate", "manager_review", "manager_accept", "continuation"}
		if parent.Role == "orchestrator" {
			names = []string{"followup", "peer_advice"}
		}
		for _, name := range names {
			claim := map[string]any{"applicationOperationDigest": app.Operation.OperationDigest, "serviceRegistrationId": parent.ServiceRegistrationID, "serviceGeneration": parent.ServiceGeneration, "allocationName": name}
			claimRaw, _ := model.WorkspaceCanonicalJSON(claim)
			step := "controller-stage-" + name
			raw, err := r.Store.OwnedContinuationResult(ctx, app.Operation.OperationID, step, claimRaw)
			if err != nil {
				return err
			}
			var original controllerStageOriginal
			if len(raw) == 0 {
				readout, err := control.ControllerStageInput(ctx, app.Operation.OperationID, parent.ServiceRegistrationID, name)
				if err != nil {
					var response *api.ResponseError
					if errors.As(err, &response) && response.Status == 409 && response.Code == "controller_approved_context_pending" {
						continue
					}
					return err
				}
				if readout.ApplicationOperationDigest != app.Operation.OperationDigest || readout.ServiceGeneration != parent.ServiceGeneration {
					return state.ErrControllerActivityConflict
				}
				declared, err := runtime.ReadControllerDeclaredStage(ctx, current, parent, readout)
				if err != nil {
					return err
				}
				if model.WorkspaceDigest(declared) != readout.DeclarationItemDigest || model.WorkspaceDigest(declared) != model.WorkspaceDigest(readout.Item) {
					return state.ErrControllerActivityConflict
				}
				original = controllerStageOriginal{readout, declared}
				if err = r.ownedContinuationOnce(ctx, app.Operation.OperationID, step, claim, func() (any, error) { return original, nil }, &original); err != nil {
					return err
				}
			} else if json.Unmarshal(raw, &original) != nil {
				return state.ErrControllerActivityConflict
			}
			if original.Readout.ApplicationOperationDigest != app.Operation.OperationDigest || original.Readout.ServiceRegistrationID != parent.ServiceRegistrationID || original.Readout.ServiceGeneration != parent.ServiceGeneration || original.Readout.AllocationName != name || original.Readout.CaseManifestDigest != installed.CaseManifestDigest || model.WorkspaceDigest(original.Declared) != original.Readout.DeclarationItemDigest {
				return state.ErrControllerActivityConflict
			}
			id := controllerStageID(original)
			// An accepted action is immutable history. Expired original input
			// cannot grant another effect, but cannot erase that acknowledged act.
			originalRaw, _ := model.WorkspaceCanonicalJSON(original)
			preparedRaw, e := r.Store.OwnedContinuationResult(ctx, id, "parent-prepare", originalRaw)
			if e != nil {
				return e
			}
			if len(preparedRaw) != 0 {
				var prepared model.ControllerPreparedReceipt
				if json.Unmarshal(preparedRaw, &prepared) != nil {
					return state.ErrControllerActivityConflict
				}
				action, e := r.Store.ControllerActivityStage(ctx, prepared.PreparationID, state.ControllerActionReceipt)
				if e != nil {
					return e
				}
				if len(action) != 0 {
					accepted, e := r.readControllerParentActionReceiptLocked(ctx, prepared.PreparationID)
					if e != nil {
						return e
					}
					if e = r.reconcileControllerStageActionLocked(ctx, id, original, prepared.PreparationID, accepted, app, parent, installed); e != nil {
						return e
					}
					continue
				}
			}
			bound := r.firstTaskManagerAuthority
			if parent.Role == "orchestrator" {
				bound = r.firstTaskAuthority
			}
			if bound == nil {
				return ErrControllerFirstTaskAuthorityPending
			}
			if bound.operationDigest != app.Operation.OperationDigest || bound.parent != parent || !reflect.DeepEqual(bound.applicability, installed) {
				return state.ErrControllerActivityConflict
			}
			// UNKNOWN belongs to this exact stage even if a later snapshot changes.
			if pending, e := r.Store.HasPendingOwnedContinuation(ctx, id, "parent-"); e != nil {
				return e
			} else if pending {
				return state.ErrOwnedContinuationUnknown
			}
			declared, err := runtime.ReadControllerDeclaredStage(ctx, current, parent, original.Readout)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(declared, original.Declared) {
				return state.ErrControllerActivityConflict
			}
			if err = r.refreshControllerDependenciesLocked(ctx, original, "before_parent"); err != nil {
				return err
			}
			call := api.ControllerPreparationRequest{FormatVersion: 2, RequestID: "controller_stage_" + model.WorkspaceDigest(original)[7:39], ServiceRegistrationID: parent.ServiceRegistrationID, InputID: declared.InputID, InputDigest: model.ControllerTextDigest(declared.InputText), ModelSelection: *role.Projection.ModelSelection, ProviderPolicyDigest: providerpolicy.FlashDigest}
			action, err := r.progressControllerFirstTaskParentLocked(ctx, id, "parent", original, *bound, call, declared.InputText, &declared)
			if err != nil {
				return err
			}
			preparedRaw, err = r.Store.OwnedContinuationResult(ctx, id, "parent-prepare", originalRaw)
			var prepared model.ControllerPreparedReceipt
			if err != nil {
				return err
			}
			if json.Unmarshal(preparedRaw, &prepared) != nil {
				return state.ErrControllerActivityConflict
			}
			if err = r.reconcileControllerStageActionLocked(ctx, id, original, prepared.PreparationID, action, app, parent, installed); err != nil {
				return err
			}
		}
	}
	return nil
}

type controllerStageChildResult struct {
	Stage       controllerStageOriginal    `json:"stage"`
	Application controllerChildApplication `json:"application"`
	Progress    controllerChildrenProgress `json:"progress"`
}

func (r *Reconciler) reconcileControllerStageActionLocked(ctx context.Context, id string, original controllerStageOriginal, parentID string, action json.RawMessage, app *state.LocalWorkspaceApplication, parent model.ControllerParentIntent, installed qualification.Applicability) error {
	if original.Declared.Target.Kind != "manager_intent" {
		return controllerLaterAction(original.Declared, action)
	}
	scope := controllerChildApplication{parent.Owner, app.ApplicationID, app.Operation.OperationID, app.Operation.OperationDigest}
	if retained, found, err := r.controllerStageChildrenHistoryLocked(ctx, id, original, scope); err != nil {
		return err
	} else if found {
		return r.completeControllerStageChildLocked(ctx, id, retained)
	}
	// Discovery never authorizes a child effect. Recheck the exact protected
	// declaration at this second causal boundary before refreshing dependencies.
	runtime, ok := r.ManagedRuntime.(controllerStageRuntime)
	if !ok {
		return ErrControllerFirstTaskAuthorityPending
	}
	declared, err := runtime.ReadControllerDeclaredStage(ctx, r.currentAuthorityManifest(), parent, original.Readout)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(declared, original.Declared) {
		return state.ErrControllerActivityConflict
	}
	if err = r.refreshControllerDependenciesLocked(ctx, original, "accepted_child"); err != nil {
		return err
	}
	bound := r.firstTaskManagerAuthority
	if bound == nil {
		return ErrControllerFirstTaskAuthorityPending
	}
	if parent.Role != "manager" || bound.parent != parent || bound.operationDigest != app.Operation.OperationDigest || !reflect.DeepEqual(bound.applicability, installed) {
		return state.ErrControllerActivityConflict
	}
	// This ordinary accepted-intent lifecycle owns prepare/delivery/adoption;
	// V3 manifest/report reconciliation independently owns native execution.
	progress, err := r.reconcileControllerChildrenLocked(ctx, parent.Owner, parentID, *bound)
	if err != nil {
		return err
	}
	result := controllerStageChildResult{original, scope, progress}
	claim := result
	claim.Progress.Children = append([]ControllerFirstTaskChildResult(nil), progress.Children...)
	for i := range claim.Progress.Children {
		claim.Progress.Children[i].BackendSnapshot = nil
	}
	var retained controllerStageChildResult
	if err = r.ownedContinuationOnce(ctx, id, "children", claim, func() (any, error) { return result, nil }, &retained); err != nil {
		return err
	}
	if retained.Progress.State == "failed" {
		return ErrControllerLaterChildPending
	}
	for _, child := range retained.Progress.Children {
		for _, entry := range r.currentAuthorityManifest().CellEntriesV3 {
			if entry.PreparationID == child.PreparationAssociation.PreparationID {
				if err := r.retainCompletedChildOriginLocked(ctx, "controller_stage", id, scope, child, entry); err != nil {
					return err
				}
			}
		}
	}
	return r.completeControllerStageChildLocked(ctx, id, retained)
}

func (r *Reconciler) completeControllerStageChildLocked(ctx context.Context, id string, retained controllerStageChildResult) error {
	if retained.Stage.Readout.AllocationName == "manager_integrate" {
		return r.reconcileControllerIntegrationLocked(ctx, id, retained)
	}
	if retained.Stage.Readout.AllocationName == "manager_review" {
		return r.reconcileControllerReviewLocked(ctx, id, retained)
	}
	// Terminal child is not integration/review acceptance. Its role-specific
	// observation/candidate or review continuation remains independently gated.
	return ErrControllerLaterChildPending
}

func controllerLaterAction(declared qualification.ControllerDeclaredInput, action json.RawMessage) error {
	definition := "adviceReceipt"
	switch declared.Target.Kind {
	case "manager_intent":
		return ErrControllerLaterChildPending
	case "result_decision":
		definition = "decisionReceipt"
	case "advice_decision":
		definition = "adviceDecisionReceipt"
	case "advice":
	default:
		return state.ErrControllerActivityConflict
	}
	if workflowcontract.Validate(workflowcontract.Domain, definition, action) != nil {
		return state.ErrControllerActivityConflict
	}
	return nil
}

func controllerStageID(original controllerStageOriginal) string {
	return "ctrlstage_" + model.WorkspaceDigest(map[string]any{"caseManifestDigest": original.Readout.CaseManifestDigest, "allocationId": original.Declared.AllocationID, "serviceRegistrationId": original.Readout.ServiceRegistrationID})[7:]
}
