package reconcile

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type managerChildDeliveryControl interface {
	ManagerChildPolicyIntent(context.Context, model.IntentHandle, string, string) (json.RawMessage, error)
	AcceptManagerChildPreparationPolicy(context.Context, model.IntentHandle, json.RawMessage, string) (json.RawMessage, error)
	ManagerChildActivationIntent(context.Context, model.IntentHandle, json.RawMessage, string) (json.RawMessage, error)
	AcceptManagerChildActivation(context.Context, model.IntentHandle, json.RawMessage, string) (json.RawMessage, error)
	PublishManagerChildControl(context.Context, model.IntentHandle, string, string, json.RawMessage, string) (json.RawMessage, error)
}
type managerChildDeliveryRuntime interface {
	ReadChildPolicyOriginal(context.Context, model.Sandbox, model.IntentHandle, string, string, json.RawMessage) (json.RawMessage, error)
	ReadChildActivationOriginal(context.Context, model.Sandbox, model.IntentHandle, qualification.RealCase, json.RawMessage) (json.RawMessage, error)
	ExportChildSigningIntent(context.Context, model.Sandbox, model.IntentHandle, string, []byte) error
}

// Correlation-only deferral, never authority. Backend already lists a prepare
// tuple before signed control publication; precisely those owned preparations
// must wait instead of attempting native preparation ahead of their public file.
type controllerChildPrepareDeliveryPending struct{ preparationIDs []string }

func (e *controllerChildPrepareDeliveryPending) Error() string {
	return ErrControllerFirstTaskChildIssuerPending.Error()
}
func (e *controllerChildPrepareDeliveryPending) Unwrap() error {
	return ErrControllerFirstTaskChildIssuerPending
}

func (r *Reconciler) checkOwnedDeliveryUnknown(ctx context.Context, id string, steps ...string) error {
	for _, step := range steps {
		claim, err := r.Store.OwnedContinuationClaim(ctx, id, step)
		if err != nil {
			return err
		}
		if len(claim) != 0 {
			if _, err = r.Store.OwnedContinuationResult(ctx, id, step, claim); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Reconciler) expectedDeliveryMissingBeforeClaim(ctx context.Context, id, step string, pending error) error {
	claim, err := r.Store.OwnedContinuationClaim(ctx, id, step)
	if err != nil {
		return err
	}
	if len(claim) != 0 {
		return state.ErrControllerActivityConflict
	} // Previously delivered bytes disappeared, not first delivery.
	return pending
}

func (r *Reconciler) childPolicySigningIntentLocked(ctx context.Context, box model.Sandbox, h model.IntentHandle, preparationID, stage, lease string) (json.RawMessage, error) {
	control, ok := r.ManagedControl.(managerChildDeliveryControl)
	if !ok {
		return nil, errors.New("normal child policy owning client unavailable")
	}
	runtime, ok := r.ManagedRuntime.(managerChildDeliveryRuntime)
	if !ok {
		return nil, ErrControllerFirstTaskChildIssuerPending
	}
	var intent json.RawMessage
	claim := map[string]any{"handleDigest": h.HandleDigest, "preparationId": preparationID, "stage": stage}
	if err := r.ownedContinuationOnce(ctx, h.HandleID, stage+"-policy-intent", claim, func() (any, error) { return control.ManagerChildPolicyIntent(ctx, h, stage, lease) }, &intent); err != nil {
		return nil, err
	}
	if err := runtime.ExportChildSigningIntent(ctx, box, h, stage, intent); err != nil {
		return nil, err
	}
	return intent, nil
}

func (r *Reconciler) ensureChildPreparationDeliveryLocked(ctx context.Context, parentID, member, lease string, pending model.IntentPreparationReference) error {
	runtime, ok := r.ManagedRuntime.(managerChildDeliveryRuntime)
	if !ok {
		return ErrControllerFirstTaskChildIssuerPending
	}
	control, ok := r.ManagedControl.(managerChildDeliveryControl)
	if !ok {
		return errors.New("normal child preparation owning client unavailable")
	}
	_, _, _, selected, h, err := r.acceptedManagerChild(ctx, parentID, member, lease)
	if err != nil {
		return err
	}
	if err = r.checkOwnedDeliveryUnknown(ctx, h.HandleID, "prepare-policy", "prepare-control-publication"); err != nil {
		return err
	}
	box, err := r.Store.Sandbox(ctx, h.Owner.SandboxID)
	if err != nil {
		return err
	}
	if box == nil {
		return state.ErrControllerActivityConflict
	}
	if box.Generation != h.Owner.SandboxGeneration || box.ObservedGeneration != box.Generation || box.ObservedState != "running" {
		return state.ErrControllerActivityConflict
	}
	sandbox := model.Sandbox{ID: box.ID, Generation: box.Generation, ImageDigest: box.ImageDigest, Cell: true}
	intent, err := r.childPolicySigningIntentLocked(ctx, sandbox, h, pending.PreparationID, "prepare", lease)
	if err != nil {
		return err
	}
	request, err := runtime.ReadChildPolicyOriginal(ctx, sandbox, h, pending.PreparationID, "prepare", intent)
	if errors.Is(err, qualification.ErrOperatorDeliveryPending) {
		return r.expectedDeliveryMissingBeforeClaim(ctx, h.HandleID, "prepare-policy", &controllerChildPrepareDeliveryPending{[]string{pending.PreparationID}})
	}
	if err != nil {
		return err
	}
	var receipt json.RawMessage
	claim := map[string]any{"handleDigest": h.HandleDigest, "preparationId": pending.PreparationID, "request": request}
	if err = r.ownedContinuationOnce(ctx, h.HandleID, "prepare-policy", claim, func() (any, error) { return control.AcceptManagerChildPreparationPolicy(ctx, h, request, lease) }, &receipt); err != nil {
		return err
	}
	body := model.IntentPrepareRequest{FormatVersion: 1, RequestID: selected.PrepareRequestID, HandleID: h.HandleID, ExpectedAdmissionRevision: selected.ExpectedAdmissionRevision}
	raw, err := model.WorkspaceCanonicalJSON(body)
	if err != nil {
		return err
	}
	var published json.RawMessage
	if err = r.ownedContinuationOnce(ctx, h.HandleID, "prepare-control-publication", map[string]any{"request": body, "policyReceipt": receipt}, func() (any, error) {
		return control.PublishManagerChildControl(ctx, h, pending.PreparationID, "prepare", raw, lease)
	}, &published); err != nil {
		return err
	}
	return ErrControllerFirstTaskPending // NEXT ordinary manifest pass owns prepare.
}

func (r *Reconciler) ensureChildProductDeliveryLocked(ctx context.Context, parentID, member, lease string, h model.IntentHandle, actual model.ActualPreparationAssociation, entry model.CellServiceV3) error {
	if err := r.checkOwnedDeliveryUnknown(ctx, h.HandleID, "product-policy", "grant-intent", "authorization-originals", "authorization-observation", "activation-intent", "activation", "execute-control-publication"); err != nil {
		return err
	}
	runtime, ok := r.ManagedRuntime.(managerChildDeliveryRuntime)
	if !ok {
		return ErrControllerFirstTaskChildIssuerPending
	}
	control, ok := r.ManagedControl.(managerChildDeliveryControl)
	if !ok {
		return errors.New("normal child PRODUCT owning client unavailable")
	}
	box, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil {
		return err
	}
	if box == nil {
		return state.ErrControllerActivityConflict
	}
	if box.Generation != entry.SandboxGeneration || box.ObservedGeneration != box.Generation || box.ObservedState != "running" {
		return state.ErrControllerActivityConflict
	}
	sandbox := model.Sandbox{ID: box.ID, Generation: box.Generation, ImageDigest: box.ImageDigest, Cell: true}
	intent, err := r.childPolicySigningIntentLocked(ctx, sandbox, h, entry.PreparationID, "product", lease)
	if err != nil {
		return err
	}
	request, err := runtime.ReadChildPolicyOriginal(ctx, sandbox, h, entry.PreparationID, "product", intent)
	if errors.Is(err, qualification.ErrOperatorDeliveryPending) {
		return r.expectedDeliveryMissingBeforeClaim(ctx, h.HandleID, "product-policy", ErrControllerFirstTaskChildIssuerPending)
	}
	if err != nil {
		return err
	}
	// PRODUCT must preserve the exact earlier independently accepted preparation
	// envelope, never a newly signed equivalent under another key/approval.
	prepareClaim, err := r.Store.OwnedContinuationClaim(ctx, h.HandleID, "prepare-policy")
	if err != nil {
		return err
	}
	var retained struct {
		HandleDigest  string          `json:"handleDigest"`
		PreparationID string          `json:"preparationId"`
		Request       json.RawMessage `json:"request"`
	}
	if model.DecodePhysicalClosed(prepareClaim, &retained) != nil || retained.HandleDigest != h.HandleDigest || retained.PreparationID != entry.PreparationID {
		return state.ErrControllerActivityConflict
	}
	if _, err = r.Store.OwnedContinuationResult(ctx, h.HandleID, "prepare-policy", prepareClaim); err != nil {
		return err
	}
	var prior, current struct{ PreparationPolicy json.RawMessage }
	if json.Unmarshal(retained.Request, &prior) != nil || json.Unmarshal(request, &current) != nil || model.WorkspaceDigest(prior.PreparationPolicy) != model.WorkspaceDigest(current.PreparationPolicy) {
		return state.ErrControllerActivityConflict
	}
	authorization, err := r.ObserveApprovedManagerChildAuthorization(ctx, parentID, member, lease, request)
	if err != nil {
		return err
	}
	_, _, selected, _, _, err := r.managerChildPreparedCurrent(ctx, parentID, member, lease, false)
	if err != nil {
		return err
	}
	body := map[string]any{"formatVersion": 1, "requestId": selected.GrantRequestID, "authorizationObservation": authorization}
	activationRequest, err := model.WorkspaceCanonicalJSON(body)
	if err != nil {
		return err
	}
	var activationIntent json.RawMessage
	if err = r.ownedContinuationOnce(ctx, h.HandleID, "activation-intent", body, func() (any, error) { return control.ManagerChildActivationIntent(ctx, h, activationRequest, lease) }, &activationIntent); err != nil {
		return err
	}
	if err = runtime.ExportChildSigningIntent(ctx, sandbox, h, "activation", activationIntent); err != nil {
		return err
	}
	var original struct {
		Payload struct{ Case qualification.RealCase }
	}
	if json.Unmarshal(intent, &original) != nil {
		return state.ErrControllerActivityConflict
	}
	activation, err := runtime.ReadChildActivationOriginal(ctx, sandbox, h, original.Payload.Case, activationIntent)
	if errors.Is(err, qualification.ErrOperatorDeliveryPending) {
		return r.expectedDeliveryMissingBeforeClaim(ctx, h.HandleID, "activation", ErrControllerFirstTaskChildIssuerPending)
	}
	if err != nil {
		return err
	}
	var accepted json.RawMessage
	if err = r.ownedContinuationOnce(ctx, h.HandleID, "activation", activation, func() (any, error) { return control.AcceptManagerChildActivation(ctx, h, activation, lease) }, &accepted); err != nil {
		return err
	}
	assignment, err := r.AssignApprovedManagerChild(ctx, parentID, member, lease)
	if err != nil {
		return err
	}
	var assigned struct{ AssignmentDigest string }
	var policy struct {
		Policy struct{ Payload json.RawMessage }
	}
	if json.Unmarshal(assignment, &assigned) != nil || json.Unmarshal(request, &policy) != nil {
		return state.ErrControllerActivityConflict
	}
	publication := model.IntentGrantRequest{FormatVersion: 1, RequestID: selected.GrantRequestID, HandleID: h.HandleID, ProductPolicyDigest: model.WorkspaceDigest(policy.Policy.Payload), PreparedReceiptDigest: actual.PreparedReceipt.PreparedReceiptDigest, AssignmentDigest: assigned.AssignmentDigest}
	publicationRaw, err := model.WorkspaceCanonicalJSON(publication)
	if err != nil {
		return err
	}
	var published json.RawMessage
	if err = r.ownedContinuationOnce(ctx, h.HandleID, "execute-control-publication", map[string]any{"request": publication, "activationReceipt": accepted}, func() (any, error) {
		return control.PublishManagerChildControl(ctx, h, entry.PreparationID, "execute", publicationRaw, lease)
	}, &published); err != nil {
		return err
	}
	return ErrControllerFirstTaskPending // Existing desired manifest/adopter/V3 next.
}
