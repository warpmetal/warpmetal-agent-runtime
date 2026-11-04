package reconcile

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type ControllerParentSigningHandoff struct {
	Intent            api.ControllerActivationSigningIntent `json:"intent"`
	HeaderObservation model.ControllerAuthorizationEnvelope `json:"headerObservation"`
}

type controllerActivationOriginalAdopter interface {
	AdoptPublishedControllerActivation(context.Context, model.ControllerPreparedReceipt, qualification.ControllerOutputWitness, api.ControllerActivationEnvelope) error
}

// Commit SAME reservation first, then expose the backend's immutable signing
// basis to the existing operator workflow. Runtime never holds an operator key.
func (r *Reconciler) PrepareControllerParentActivation(ctx context.Context, envelope model.ControllerGrantEnvelope, applicability qualification.Applicability, workflowLease string) (ControllerParentSigningHandoff, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prepareControllerParentActivationLocked(ctx, envelope, applicability, workflowLease)
}
func (r *Reconciler) prepareControllerParentActivationLocked(ctx context.Context, envelope model.ControllerGrantEnvelope, applicability qualification.Applicability, workflowLease string) (ControllerParentSigningHandoff, error) {
	var empty ControllerParentSigningHandoff
	control, ok := r.ManagedControl.(controllerActivityControl)
	runtime, rok := r.ManagedRuntime.(controllerActivityRuntime)
	if !ok || !rok || r.Store == nil || workflowLease == "" {
		return empty, ErrControllerActivityPending
	}
	id := envelope.Payload.PreparationID
	raw, e := r.Store.ControllerActivityStage(ctx, id, state.ControllerNativePrepared)
	if e != nil {
		return empty, e
	}
	var prepared model.ControllerPreparedEnvelope
	if json.Unmarshal(raw, &prepared) != nil {
		return empty, ErrControllerActivityPending
	}
	raw, e = r.Store.ControllerActivityStage(ctx, id, state.ControllerHeaderObserved)
	if e != nil {
		return empty, e
	}
	var header model.ControllerAuthorizationEnvelope
	if json.Unmarshal(raw, &header) != nil || header.Payload.PreparationID != id || header.Payload.PreparedReceiptDigest != prepared.Payload.PreparedReceiptDigest {
		return empty, ErrControllerActivityPending
	}
	c, e := control.ControllerWorkflowContext(ctx, id, workflowLease)
	if e != nil {
		return empty, e
	}
	raw, e = r.Store.ControllerActivityStage(ctx, id, state.ControllerApprovedContext)
	if e != nil {
		return empty, e
	}
	var input controllerApprovedInput
	if json.Unmarshal(raw, &input) != nil || !reflect.DeepEqual(c, input.Context) {
		return empty, state.ErrControllerActivityConflict
	}
	w, e := r.controllerActivityWitness(ctx, prepared.Payload.PreparedTuple.ServiceRegistrationID, applicability)
	if e != nil {
		return empty, e
	}
	w.Policy, e = runtime.VerifyControllerPolicy(ctx, w.Sandbox, c.PolicyDigest, w.Installed)
	if e != nil {
		return empty, e
	}
	if header.KeyID != w.Producer.KeyID || header.Payload.TargetKind != "controller_authorization" || envelope.Payload.PolicyDigest != c.PolicyDigest {
		return empty, state.ErrControllerActivityConflict
	}
	if w.Policy.ValidateContext(c) != nil || w.Policy.ValidatePreparedReceipt(prepared.Payload) != nil {
		return empty, state.ErrControllerActivityConflict
	}
	// Retain the independently supplied signed original before the existing
	// reservation effect. This is not grant authority: backend Reserve and the
	// protected atomic activation reader still verify it independently.
	grantRaw, e := model.WorkspaceCanonicalJSON(envelope)
	if e != nil {
		return empty, e
	}
	if e = r.Store.PinControllerActivityStage(ctx, id, state.ControllerGrantOriginal, grantRaw); e != nil {
		return empty, e
	}
	g, e := control.ReserveControllerActivity(ctx, envelope)
	if e != nil {
		return empty, e
	}
	if g != envelope.Payload {
		return empty, state.ErrControllerActivityConflict
	}
	intent, e := control.ControllerActivationIntent(ctx, id)
	if e != nil {
		return empty, e
	}
	basis, e := qualification.ControllerActivationFromSigningBasis(intent.PayloadBasis, intent.NotBefore, header.Payload.AuthorizationSHA256, w.Policy, c, r.now())
	if e != nil || !reflect.DeepEqual(basis.Admission.PreparedReceipt, prepared.Payload) || basis.Admission.Grant != g || basis.GrantEnvelopeDigest != model.WorkspaceDigest(envelope) {
		return empty, state.ErrControllerActivityConflict
	}
	if at, e := time.Parse(time.RFC3339Nano, intent.NotBefore); e != nil || at.After(r.now()) {
		return empty, ErrControllerActivityPending
	}
	return ControllerParentSigningHandoff{Intent: intent, HeaderObservation: header}, nil
}

// Existing independently operator-signed activation only. Backend commits those
// exact bytes before publication; root then requires BOTH verified physical
// members. Pending/unknown cannot unlock prompt, allocate, retry or refund.
func (r *Reconciler) PublishControllerParentActivation(ctx context.Context, envelope api.ControllerActivationEnvelope, applicability qualification.Applicability) (api.ControllerActivationReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.publishControllerParentActivationLocked(ctx, envelope, applicability)
}
func (r *Reconciler) publishControllerParentActivationLocked(ctx context.Context, envelope api.ControllerActivationEnvelope, applicability qualification.Applicability) (api.ControllerActivationReceipt, error) {
	var empty api.ControllerActivationReceipt
	control, ok := r.ManagedControl.(controllerActivityControl)
	runtime, rok := r.ManagedRuntime.(controllerActivityRuntime)
	if !ok || !rok || r.Store == nil {
		return empty, ErrControllerActivityPending
	}
	a := envelope.Payload
	id := a.Admission.PreparedReceipt.PreparationID
	raw, e := r.Store.ControllerActivityStage(ctx, id, state.ControllerHeaderObserved)
	if e != nil {
		return empty, e
	}
	var header model.ControllerAuthorizationEnvelope
	if json.Unmarshal(raw, &header) != nil || header.Payload.AuthorizationSHA256 != a.AuthorizationSHA256 || header.Payload.PreparedReceiptDigest != a.Admission.PreparedReceipt.PreparedReceiptDigest {
		return empty, state.ErrControllerActivityConflict
	}
	raw, e = r.Store.ControllerActivityStage(ctx, id, state.ControllerNativePrepared)
	if e != nil {
		return empty, e
	}
	var prepared model.ControllerPreparedEnvelope
	if json.Unmarshal(raw, &prepared) != nil || !reflect.DeepEqual(prepared.Payload, a.Admission.PreparedReceipt) {
		return empty, state.ErrControllerActivityConflict
	}
	w, e := r.controllerActivityWitness(ctx, prepared.Payload.PreparedTuple.ServiceRegistrationID, applicability)
	if e != nil {
		return empty, e
	}
	w.Policy, e = runtime.VerifyControllerPolicy(ctx, w.Sandbox, a.PolicyDigest, w.Installed)
	if e != nil {
		return empty, e
	}
	raw, e = r.Store.ControllerActivityStage(ctx, id, state.ControllerApprovedContext)
	if e != nil {
		return empty, e
	}
	var input controllerApprovedInput
	if json.Unmarshal(raw, &input) != nil || a.ValidateContext(w.Policy, input.Context) != nil {
		return empty, state.ErrControllerActivityConflict
	}
	w.ApprovedContext, w.ApprovedInputText = input.Context, input.InputText
	receipt, e := control.PublishControllerActivation(ctx, api.ControllerActivationPublication{Activation: envelope, HeaderObservation: header})
	if e != nil {
		return receipt, e
	}
	if adopter, ok := r.ManagedRuntime.(controllerActivationOriginalAdopter); ok && (a.FormatVersion == 3 || a.FormatVersion == 4) {
		if e = adopter.AdoptPublishedControllerActivation(ctx, prepared.Payload, w, envelope); e != nil {
			return receipt, e
		}
	}
	current, e := runtime.ReadControllerActivation(ctx, w.Sandbox, w.Policy, prepared.Payload, false)
	if e != nil {
		return receipt, e
	}
	if !reflect.DeepEqual(current, a) {
		return receipt, state.ErrControllerActivityConflict
	}
	raw, _ = json.Marshal(current)
	if e = r.Store.PinControllerActivityStage(ctx, id, state.ControllerActivated, raw); e != nil {
		return receipt, e
	}
	return receipt, nil
}
