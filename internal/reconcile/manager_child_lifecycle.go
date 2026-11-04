package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type managerChildControl interface {
	ManagerAcceptedIntent(context.Context, model.ControllerOutputOperation, model.ManagerActionReceipt, string, string) (model.IntentHandle, error)
	PrepareManagerIntent(context.Context, model.IntentHandle, model.ManagerIntentSelection, string) (model.IntentPreparationReference, error)
	ManagerPreparedAssociation(context.Context, model.IntentHandle, model.IntentPreparationReference, string) (model.ActualPreparationAssociation, error)
	AssignManagerIntent(context.Context, model.IntentHandle, model.ManagerIntentSelection, model.ActualPreparationAssociation, model.CellServiceV3, string) (json.RawMessage, error)
	GrantManagerIntent(context.Context, model.IntentHandle, model.ManagerIntentSelection, model.ActualPreparationAssociation, json.RawMessage, string, string) (model.ChildAdmissionAssociation, error)
}

// No effect can select its own operation/receipt. These are the original
// independently signed output and backend acceptance retained by CompleteOutput.
func (r *Reconciler) acceptedManagerChild(ctx context.Context, parentID, member, lease string) (managerChildControl, model.ControllerOutputOperation, model.ManagerActionReceipt, model.ManagerIntentSelection, model.IntentHandle, error) {
	var op model.ControllerOutputOperation
	var pair model.ManagerActionReceipt
	var selection model.ManagerIntentSelection
	var handle model.IntentHandle
	control, ok := r.ManagedControl.(managerChildControl)
	bad := errors.New("manager child original acceptance pending")
	if !ok || r.Store == nil || lease == "" {
		return nil, op, pair, selection, handle, bad
	}
	raw, err := r.Store.ControllerActivityStage(ctx, parentID, state.ControllerOutputOperation)
	if err != nil || json.Unmarshal(raw, &op) != nil {
		return nil, op, pair, selection, handle, bad
	}
	raw, err = r.Store.ControllerActivityStage(ctx, parentID, state.ControllerOutputEnvelope)
	var signed model.ControllerOutputEnvelope
	if err != nil || workflowcontract.Validate(workflowcontract.Producer, "controllerOutputEnvelope", raw) != nil || json.Unmarshal(raw, &signed) != nil || signed.Payload.OperationID != op.OperationID || signed.Payload.OperationDigest != op.OperationDigest {
		return nil, op, pair, selection, handle, bad
	}
	raw, err = r.Store.ControllerActivityStage(ctx, parentID, state.ControllerActionReceipt)
	if err != nil || json.Unmarshal(raw, &pair) != nil || pair.ValidateOutput(op, signed) != nil {
		return nil, op, pair, selection, handle, bad
	}
	selection, err = pair.Select(op, member)
	if err != nil {
		return nil, op, pair, selection, handle, err
	}
	// Normal client reauthenticates current node AND exact manager lease before
	// diagnostics, then rechecks the original owning output/handle association.
	handle, err = control.ManagerAcceptedIntent(ctx, op, pair, member, lease)
	return control, op, pair, selection, handle, err
}

func (r *Reconciler) ownedContinuationOnce(ctx context.Context, id, step string, claim any, effect func() (any, error), out any) error {
	raw, err := model.WorkspaceCanonicalJSON(claim)
	if err != nil || r.Store == nil {
		return state.ErrOwnedContinuationUnknown
	}
	prior, err := r.Store.OwnedContinuationResult(ctx, id, step, raw)
	if err != nil {
		return err
	}
	if len(prior) != 0 {
		return json.Unmarshal(prior, out)
	}
	if err = r.Store.ClaimOwnedContinuation(ctx, id, step, raw); err != nil {
		return err
	}
	result, err := effect()
	if err != nil {
		return err
	} // retain claim/UNKNOWN; NEVER inline retry
	completion, err := model.WorkspaceCanonicalJSON(result)
	if err != nil {
		return err
	}
	if err = r.Store.CompleteOwnedContinuation(ctx, id, step, raw, completion); err != nil {
		return err
	}
	return json.Unmarshal(completion, out)
}

// Begin ONE accepted member. The other member needs its own explicit call and
// exact handle. This reserves through F1's existing prepare service, not a local
// successful row, prompt, grant, signing window or replacement allocation.
func (r *Reconciler) BeginApprovedManagerChild(ctx context.Context, parentID, member, lease string) (model.IntentPreparationReference, error) {
	var out model.IntentPreparationReference
	control, op, pair, selected, handle, err := r.acceptedManagerChild(ctx, parentID, member, lease)
	if err != nil {
		return out, err
	}
	err = r.ownedContinuationOnce(ctx, handle.HandleID, "prepare", managerPrepareClaim(op, pair, selected, handle), func() (any, error) {
		return control.PrepareManagerIntent(ctx, handle, selected, lease)
	}, &out)
	return out, err
}

func managerPrepareClaim(op model.ControllerOutputOperation, pair model.ManagerActionReceipt, selected model.ManagerIntentSelection, handle model.IntentHandle) any {
	return map[string]any{"operationDigest": op.OperationDigest, "associationDigest": pair.AssociationDigest(), "handle": handle, "selection": selected}
}

func (r *Reconciler) managerChildPrepared(ctx context.Context, parentID, member, lease string) (managerChildControl, model.IntentHandle, model.ManagerIntentSelection, model.ActualPreparationAssociation, model.CellServiceV3, error) {
	return r.managerChildPreparedCurrent(ctx, parentID, member, lease, true)
}

func (r *Reconciler) managerChildPreparedCurrent(ctx context.Context, parentID, member, lease string, allowPrepare bool) (managerChildControl, model.IntentHandle, model.ManagerIntentSelection, model.ActualPreparationAssociation, model.CellServiceV3, error) {
	var actual model.ActualPreparationAssociation
	var entry model.CellServiceV3
	control, op, pair, selected, handle, err := r.acceptedManagerChild(ctx, parentID, member, lease)
	if err != nil {
		return control, handle, selected, actual, entry, err
	}
	var pending model.IntentPreparationReference
	if allowPrepare {
		pending, err = r.BeginApprovedManagerChild(ctx, parentID, member, lease)
	} else {
		claim, e := model.WorkspaceCanonicalJSON(managerPrepareClaim(op, pair, selected, handle))
		var raw []byte
		if e == nil {
			raw, e = r.Store.OwnedContinuationResult(ctx, handle.HandleID, "prepare", claim)
		}
		if e != nil || len(raw) == 0 || model.DecodeManagerContract("intentPreparationReference", raw, &pending) != nil {
			err = errors.Join(e, errors.New("manager child retained preparation original pending"))
		}
	}
	if err != nil {
		return control, handle, selected, actual, entry, err
	}
	actual, err = control.ManagerPreparedAssociation(ctx, handle, pending, lease)
	if err != nil || actual.ValidateIntegrity() != nil {
		return control, handle, selected, actual, entry, errors.Join(err, errors.New("manager child actual prepared association pending"))
	}
	for _, candidate := range r.currentAuthorityManifest().CellEntriesV3 {
		if candidate.PreparationID == actual.PreparationID {
			entry = candidate
		}
	}
	local, err := r.Store.CellV3Operation(ctx, actual.PreparationID)
	if err != nil || local == nil || local.Phase != "reported" || !reflect.DeepEqual(local.Receipt, actual.PreparedReceipt) || actual.PreparedReceipt.ValidateFor(entry) != nil {
		return control, handle, selected, actual, entry, errors.New("manager child native receipt/STATE not independently reported")
	}
	return control, handle, selected, actual, entry, nil
}

func (r *Reconciler) AssignApprovedManagerChild(ctx context.Context, parentID, member, lease string) (json.RawMessage, error) {
	var out json.RawMessage
	control, handle, selected, actual, entry, err := r.managerChildPrepared(ctx, parentID, member, lease)
	if err != nil {
		return nil, err
	}
	err = r.ownedContinuationOnce(ctx, handle.HandleID, "assign", map[string]any{"handleDigest": handle.HandleDigest, "preparedAssociation": actual}, func() (any, error) {
		return control.AssignManagerIntent(ctx, handle, selected, actual, entry, lease)
	}, &out)
	return out, err
}

// Consume only an ALREADY published signed activation/V3 association. Detached
// signing and grant-intents remain with their existing owners; this method never
// creates either. Actual native dispatch stays at the existing V3 reconcile path.
func (r *Reconciler) AdoptApprovedManagerChild(ctx context.Context, parentID, member, lease string) (model.ChildAdmissionAssociation, error) {
	var out model.ChildAdmissionAssociation
	control, handle, selected, actual, entry, err := r.managerChildPrepared(ctx, parentID, member, lease)
	if err != nil {
		return out, err
	}
	assignment, err := r.AssignApprovedManagerChild(ctx, parentID, member, lease)
	if err != nil {
		return out, err
	}
	transport, ok := r.ManagedControl.(cellProductTransport)
	if !ok {
		return out, errors.New("manager child signed product supplier pending")
	}
	delivery, err := transport.ChildProductControl(ctx, entry.PreparationID)
	if err != nil {
		return out, err
	}
	var published struct {
		Descriptor struct {
			Phase        string  `json:"phase"`
			PolicyDigest *string `json:"policyDigest"`
		} `json:"descriptor"`
	}
	if json.Unmarshal(delivery.Bytes(), &published) != nil || published.Descriptor.Phase != "execute" || published.Descriptor.PolicyDigest == nil || entry.ExecutionGrant == nil {
		return out, errors.New("manager child committed activation/publication pending")
	}
	if err = r.verifyCurrentChildProductOrQualification(ctx, entry); err != nil {
		return out, err
	}
	err = r.ownedContinuationOnce(ctx, handle.HandleID, "adopt", map[string]any{"handleDigest": handle.HandleDigest, "preparedAssociationDigest": actual.AssociationDigest, "assignment": assignment, "policyDigest": *published.Descriptor.PolicyDigest, "grant": entry.ExecutionGrant}, func() (any, error) {
		association, err := control.GrantManagerIntent(ctx, handle, selected, actual, assignment, *published.Descriptor.PolicyDigest, lease)
		if err != nil || association.ValidateIntegrity() != nil || !reflect.DeepEqual(association.Grant, *entry.ExecutionGrant) {
			return nil, errors.Join(err, errors.New("manager child published grant changed"))
		}
		return association, nil
	}, &out)
	return out, err
}
