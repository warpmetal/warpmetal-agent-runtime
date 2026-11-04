package reconcile

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type controllerIssuerDeliveryRuntime interface {
	ReadControllerGrantOriginal(context.Context, model.ControllerPreparedReceipt, qualification.ControllerOutputWitness) (model.ControllerGrantEnvelope, error)
	ReadControllerActivationOriginal(context.Context, model.ControllerPreparedReceipt, qualification.ControllerOutputWitness) (api.ControllerActivationEnvelope, error)
	ExportControllerActivationHandoff(context.Context, model.ControllerPreparedReceipt, qualification.ControllerOutputWitness, []byte) error
}

// Normal owning pass after immutable actual preparation. File presence is not
// authority: the protected reader and existing owning methods independently check
// current policy/pin/scope/receipt/expiry. UNKNOWN survives every pass unchanged.
func (r *Reconciler) ensureControllerIssuerDeliveryLocked(ctx context.Context, prepared model.ControllerPreparedReceipt, bound controllerFirstTaskAuthority) error {
	if err := r.checkOwnedDeliveryUnknown(ctx, prepared.PreparationID, "parent-signing-handoff", "parent-activation-publication"); err != nil {
		return err
	}
	activated, err := r.Store.ControllerActivityStage(ctx, prepared.PreparationID, state.ControllerActivated)
	if err != nil {
		return err
	}
	if len(activated) != 0 {
		return nil
	}
	runtime, ok := r.ManagedRuntime.(controllerIssuerDeliveryRuntime)
	if !ok {
		return errors.New("normal protected parent issuer delivery unavailable")
	}
	control, ok := r.ManagedRuntime.(controllerActivityRuntime)
	if !ok {
		return state.ErrControllerActivityConflict
	}
	raw, err := r.Store.ControllerActivityStage(ctx, prepared.PreparationID, state.ControllerApprovedContext)
	if err != nil {
		return err
	}
	var input controllerApprovedInput
	if json.Unmarshal(raw, &input) != nil {
		return state.ErrControllerActivityConflict
	}
	w, err := r.controllerActivityWitness(ctx, prepared.PreparedTuple.ServiceRegistrationID, bound.applicability)
	if err != nil {
		return err
	}
	w.ApprovedContext, w.ApprovedInputText = input.Context, input.InputText
	w.Policy, err = control.VerifyControllerPolicy(ctx, w.Sandbox, input.Context.PolicyDigest, w.Installed)
	if err != nil {
		return err
	}
	grant, err := runtime.ReadControllerGrantOriginal(ctx, prepared, w)
	if errors.Is(err, qualification.ErrOperatorDeliveryPending) {
		return r.expectedDeliveryMissingBeforeClaim(ctx, prepared.PreparationID, "parent-signing-handoff", ErrControllerFirstTaskGrantPending)
	}
	if err != nil {
		return err
	}
	var handoff ControllerParentSigningHandoff
	claim := map[string]any{"preparedReceipt": prepared, "grant": grant}
	if err = r.ownedContinuationOnce(ctx, prepared.PreparationID, "parent-signing-handoff", claim, func() (any, error) {
		return r.prepareControllerParentActivationLocked(ctx, grant, bound.applicability, bound.lease)
	}, &handoff); err != nil {
		return err
	}
	bytes, err := model.WorkspaceCanonicalJSON(handoff)
	if err != nil {
		return err
	}
	if err = runtime.ExportControllerActivationHandoff(ctx, prepared, w, bytes); err != nil {
		return err
	}
	activation, err := runtime.ReadControllerActivationOriginal(ctx, prepared, w)
	if errors.Is(err, qualification.ErrOperatorDeliveryPending) {
		return r.expectedDeliveryMissingBeforeClaim(ctx, prepared.PreparationID, "parent-activation-publication", ErrControllerFirstTaskActivationPending)
	}
	if err != nil {
		return err
	}
	var receipt api.ControllerActivationReceipt
	return r.ownedContinuationOnce(ctx, prepared.PreparationID, "parent-activation-publication", activation, func() (any, error) {
		return r.publishControllerParentActivationLocked(ctx, activation, bound.applicability)
	}, &receipt)
}
