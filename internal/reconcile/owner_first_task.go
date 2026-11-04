package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type ownerFirstTaskReader interface {
	OwnerFirstTask(context.Context, string) (api.OwnerFirstTaskResponse, error)
}
type controllerFirstTaskAuthority struct {
	operationDigest string
	parent          model.ControllerParentIntent
	applicability   qualification.Applicability
	lease           string
}

var ErrControllerFirstTaskPending = errors.New("normal first-task progression pending")
var ErrControllerFirstTaskAuthorityPending = fmt.Errorf("%w: original installed applicability/existing workflow-role lease pending", ErrControllerFirstTaskPending)
var ErrControllerFirstTaskGrantPending = fmt.Errorf("%w: independently signed grant original pending at PrepareControllerParentActivation", ErrControllerFirstTaskPending)
var ErrControllerFirstTaskActivationPending = fmt.Errorf("%w: committed signed activation pending at PublishControllerParentActivation", ErrControllerFirstTaskPending)

// Private process-owner attachment of ALREADY issued independent authority to an
// accepted application. It never issues a lease, grants a task, changes config or
// substitutes task fields for installed pins. The existing policy/installed and
// backend workflow-context consumers independently verify both before native use.
// Normal delivery is ensureControllerFirstTaskAuthoritiesLocked: original node
// operation -> fresh native/root proof -> actual enroll ACK -> protected installed
// original -> this scoped attachment. The public wrapper does not issue authority.
func (r *Reconciler) BindControllerFirstTaskAuthority(ctx context.Context, operationID string, installed qualification.Applicability, lease string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bindControllerFirstTaskAuthorityLocked(ctx, operationID, "orchestrator", installed, lease)
}

func (r *Reconciler) bindControllerFirstTaskAuthorityLocked(ctx context.Context, operationID, role string, installed qualification.Applicability, lease string) error {
	if r.Store == nil || !strings.HasPrefix(lease, "wfl_") || len(lease) > 256 || strings.ContainsAny(lease, "\r\n\x00") {
		return state.ErrControllerActivityConflict
	}
	app, err := r.Store.WorkspaceApplication(ctx, operationID)
	if err != nil {
		return err
	}
	if app == nil || !app.Applied || app.ApplicationID == "" || len(app.EnvelopeJSON) == 0 {
		return ErrControllerFirstTaskAuthorityPending
	}
	var parent *model.ControllerParentIntent
	for _, p := range r.currentAuthorityManifest().ParentServices {
		if p.ApplicationOperationID == operationID && p.Role == role && p.DesiredState == "active" {
			if parent != nil {
				return state.ErrControllerActivityConflict
			}
			copy := p
			parent = &copy
		}
	}
	if parent == nil || installed.AccountID != parent.Owner.AccountID || installed.TaskID != parent.Owner.TaskID || installed.ServerID != parent.Owner.ServerID || installed.SandboxID != parent.Owner.SandboxID || installed.SandboxGeneration != parent.Owner.SandboxGeneration {
		return state.ErrControllerActivityConflict
	}
	w, err := r.controllerActivityCurrentWitness(ctx, parent.ServiceRegistrationID, installed, false)
	if err != nil {
		return err
	}
	if w.Installed.Identity.Projection.ModelSelection == nil || w.Installed.Identity.Projection.ModelSelection.CredentialBinding == nil || installed.Connection != *w.Installed.Identity.Projection.ModelSelection.CredentialBinding {
		return state.ErrControllerActivityConflict
	}
	bound := controllerFirstTaskAuthority{app.Operation.OperationDigest, *parent, installed, lease}
	target := &r.firstTaskAuthority
	if role == "manager" {
		target = &r.firstTaskManagerAuthority
	}
	if *target != nil && !reflect.DeepEqual(**target, bound) {
		return state.ErrControllerActivityConflict
	}
	*target = &bound
	return nil
}

// SAME heavy current pass, only after accepted application and registered parent.
// Read/retain is not prompt consent. A successful preparation remains separate
// from operator grant/activation, native input and accepted output progression.
func (r *Reconciler) reconcileOwnerFirstTasksLocked(ctx context.Context, current model.Manifest) error {
	control, ok := r.ManagedControl.(ownerFirstTaskReader)
	if !ok {
		return nil
	} // V2/older metadata-only adapters remain unchanged.
	for _, parent := range current.ParentServices {
		if parent.Role != "orchestrator" || parent.DesiredState != "active" {
			continue
		}
		app, err := r.Store.WorkspaceApplication(ctx, parent.ApplicationOperationID)
		if err != nil {
			return err
		}
		if app == nil || !app.Applied || app.ApplicationID == "" || len(app.EnvelopeJSON) == 0 {
			continue
		}
		local, err := r.Store.ControllerParent(ctx, parent.ServiceRegistrationID)
		if err != nil {
			return err
		}
		if local == nil || local.Intent != parent || local.Report.ValidateReady(parent) != nil || local.AcceptedReceiptDigest == "" || local.AcceptedReceiptDigest != local.Report.ReceiptDigest {
			continue
		}
		task, err := control.OwnerFirstTask(ctx, app.Operation.OperationID)
		if err != nil {
			var missing *api.ResponseError
			if errors.As(err, &missing) && missing.Status == 404 && missing.Code == "workspace_first_task_not_found" {
				continue
			}
			return err
		}
		o := task.OwnerFirstTaskOriginal
		originalRaw, err := model.WorkspaceCanonicalJSON(o)
		if err != nil || workflowcontract.ValidateOwnerFirstTask("ownerFirstTaskOriginal", originalRaw) != nil {
			return ErrControllerActivityPending
		}
		dependency, err := app.Operation.ParentDependency(parent)
		if err != nil || app.Operation.TargetRuntimeRevision != current.DesiredRevision || o.ApplicationID != app.ApplicationID || o.ApplicationOperationID != app.Operation.OperationID || o.ApplicationOperationDigest != app.Operation.OperationDigest || o.SetupIntentID != app.Operation.SetupIntentID || o.ConfigurationID != app.Operation.ConfigurationID || o.ConfigurationRevision != app.Operation.ConfigurationRevision || o.ConfigurationDigest != app.Operation.ConfigurationDigest || o.Owner != parent.Owner || o.Parent.ServiceRegistrationID != parent.ServiceRegistrationID || o.Parent.ServiceGeneration != parent.ServiceGeneration || o.Parent.Role != parent.Role || o.Parent.ConfigDigest != parent.ConfigDigest || o.Parent.DesiredRevision != parent.DesiredRevision || local.Report.NativeRegistration == nil || o.Parent.NativeRegistration != *local.Report.NativeRegistration || dependency.Projection.ModelSelection == nil || !reflect.DeepEqual(o.ParentActivityRequest.ModelSelection, *dependency.Projection.ModelSelection) || !exactControllerText(o.InputText, o.ParentActivityRequest.InputDigest) {
			return ErrControllerActivityPending
		}
		// Status evolves; the original never does. Commit SAME immutable consent
		// before even diagnosing the independent execution supplier. Restart/replay
		// cannot replace it with another input or current status projection.
		var retained api.OwnerFirstTaskOriginal
		if err = r.ownedContinuationOnce(ctx, o.FirstTaskID, "owner-original", o, func() (any, error) { return o, nil }, &retained); err != nil {
			return err
		}
		if complete, err := r.completedFirstTaskHistoryLocked(ctx, o); err != nil {
			return err
		} else if complete {
			continue
		}
		if err = r.ensureControllerFirstTaskAuthoritiesLocked(ctx, o.FirstTaskID, o.ApplicationOperationID); err != nil {
			return err
		}
		bound := r.firstTaskAuthority
		if bound == nil {
			return ErrControllerFirstTaskAuthorityPending
		}
		if bound.operationDigest != o.ApplicationOperationDigest || bound.parent != parent {
			return state.ErrControllerActivityConflict
		}
		advice, err := r.progressControllerFirstTaskParentLocked(ctx, o.FirstTaskID, "parent", o, *bound, o.ParentActivityRequest, o.InputText, nil)
		if err != nil {
			return err
		}
		if err = r.reconcileControllerInitialDecisionLocked(ctx, o, advice); err != nil {
			return err
		}
		if err = r.reconcileControllerChildCompletionLocked(ctx, o); err != nil {
			return err
		}
	}
	return nil
}

// One implementation for BOTH declared parents; only the normal first-task caller
// chooses these stages. Observers never prepare/admit/complete a parent.
func (r *Reconciler) progressControllerFirstTaskParentLocked(ctx context.Context, taskID, step string, claim any, bound controllerFirstTaskAuthority, call api.ControllerPreparationRequest, text string, declared *qualification.ControllerDeclaredInput) (json.RawMessage, error) {
	var receipt model.ControllerPreparedReceipt
	if err := r.ownedContinuationOnce(ctx, taskID, step+"-prepare", claim, func() (any, error) {
		return r.prepareControllerParentDeclaredActivityLocked(ctx, call, bound.applicability, text, bound.lease, declared)
	}, &receipt); err != nil {
		return nil, err
	}
	if err := r.ensureControllerIssuerDeliveryLocked(ctx, receipt, bound); err != nil {
		return nil, err
	}
	grantRaw, err := r.Store.ControllerActivityStage(ctx, receipt.PreparationID, state.ControllerGrantOriginal)
	if err != nil {
		return nil, err
	}
	if len(grantRaw) == 0 {
		return nil, ErrControllerFirstTaskGrantPending
	}
	var grant model.ControllerGrantEnvelope
	if json.Unmarshal(grantRaw, &grant) != nil || grant.Payload.PreparationID != receipt.PreparationID || grant.Payload.PreparedReceiptDigest != receipt.PreparedReceiptDigest {
		return nil, state.ErrControllerActivityConflict
	}
	activation, err := r.Store.ControllerActivityStage(ctx, receipt.PreparationID, state.ControllerActivated)
	if err != nil {
		return nil, err
	}
	if len(activation) == 0 {
		return nil, ErrControllerFirstTaskActivationPending
	}
	var admitted bool
	if err = r.ownedContinuationOnce(ctx, taskID, step+"-admit", map[string]any{"original": claim, "grant": grant, "activation": json.RawMessage(activation)}, func() (any, error) {
		err := r.admitControllerParentActivityLocked(ctx, grant, bound.applicability, text, bound.lease)
		return err == nil, err
	}, &admitted); err != nil {
		return nil, err
	}
	if !admitted {
		return nil, state.ErrOwnedContinuationUnknown
	}
	action, err := r.Store.ControllerActivityStage(ctx, receipt.PreparationID, state.ControllerActionReceipt)
	if err != nil {
		return nil, err
	}
	if len(action) != 0 {
		return json.RawMessage(action), nil
	}
	return r.completeControllerParentOutputLocked(ctx, receipt.PreparationID, bound.applicability, bound.lease)
}
