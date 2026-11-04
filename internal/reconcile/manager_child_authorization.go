package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type managerChildAuthorizationControl interface {
	AcceptManagerChildProductPolicy(context.Context, model.IntentHandle, json.RawMessage, string) (json.RawMessage, error)
	ManagerChildGrantIntent(context.Context, model.IntentHandle, model.IntentGrantRequest, string) (json.RawMessage, error)
}
type managerChildAuthorizationRuntime interface {
	ObserveCellProductAuthorization(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, containers.ChildAuthorizationIntentSource) (qualification.ChildEnvelope[qualification.ChildAuthorizationObservation], error)
}
type retainedManagerChildAuthorization struct {
	Original                qualification.ChildAuthorizationIntent
	PolicyAcceptanceRequest json.RawMessage
	PolicyAcceptanceReceipt json.RawMessage
}
type managerChildAuthorizationReader struct {
	r                       *Reconciler
	parentID, member, lease string
}

var _ containers.ChildAuthorizationIntentSource = managerChildAuthorizationReader{}

func authorizationOriginalClaim(handle model.IntentHandle, actual model.ActualPreparationAssociation) any {
	return map[string]any{"handleDigest": handle.HandleDigest, "preparationAssociationDigest": actual.AssociationDigest}
}

// Concrete READ ONLY supplier. Reauthenticates current node/exact manager lease,
// accepted parent output/handle and actual reported preparation association on
// BOTH Podman reads. No POST, signature, activation or authority fallback here.
func (s managerChildAuthorizationReader) ReadCurrentChildAuthorizationIntent(ctx context.Context, preparationID string) (qualification.ChildAuthorizationIntent, error) {
	var empty qualification.ChildAuthorizationIntent
	if s.r == nil || s.r.Store == nil {
		return empty, qualification.ErrUntrusted
	}
	_, handle, _, actual, entry, err := s.r.managerChildPreparedCurrent(ctx, s.parentID, s.member, s.lease, false)
	if err != nil || actual.PreparationID != preparationID || entry.LifecyclePhase != "prepare" || entry.DesiredState != "active" {
		return empty, errors.Join(err, qualification.ErrUntrusted)
	}
	claim, _ := model.WorkspaceCanonicalJSON(authorizationOriginalClaim(handle, actual))
	raw, err := s.r.Store.OwnedContinuationResult(ctx, handle.HandleID, "authorization-originals", claim)
	var retained retainedManagerChildAuthorization
	if err != nil || len(raw) == 0 || model.DecodePhysicalClosed(raw, &retained) != nil || retained.Original.PreparationID != preparationID || model.WorkspaceDigest(retained.Original.PreparationAssociation) != model.WorkspaceDigest(actual) {
		return empty, errors.Join(err, qualification.ErrUntrusted)
	}
	var submitted struct{ Policy, PolicyBinding json.RawMessage }
	var accepted struct{ HandleID, PreparationID, PolicyDigest, PolicyBindingDigest, Stage string }
	var policy, binding struct{ Payload json.RawMessage }
	if workflowcontract.Validate(workflowcontract.Budget, "policyAcceptRequest", retained.PolicyAcceptanceRequest) != nil || workflowcontract.Validate(workflowcontract.ChildProduct, "policyAcceptReceipt", retained.PolicyAcceptanceReceipt) != nil || json.Unmarshal(retained.PolicyAcceptanceRequest, &submitted) != nil || json.Unmarshal(retained.PolicyAcceptanceReceipt, &accepted) != nil || json.Unmarshal(submitted.Policy, &policy) != nil || json.Unmarshal(submitted.PolicyBinding, &binding) != nil || accepted.HandleID != handle.HandleID || accepted.PreparationID != preparationID || accepted.Stage != "product" || accepted.PolicyDigest != model.WorkspaceDigest(policy.Payload) || accepted.PolicyBindingDigest != model.WorkspaceDigest(binding.Payload) || model.WorkspaceDigest(submitted.Policy) != model.WorkspaceDigest(retained.Original.Policy) || model.WorkspaceDigest(submitted.PolicyBinding) != model.WorkspaceDigest(retained.Original.PolicyBinding) {
		return empty, qualification.ErrUntrusted
	}
	// Signature/expiry/strict policy/assignment/reservation/grant joins are made by
	// the independent installed PrepareChildAuthorization consumer, not this GET.
	return retained.Original, nil
}

// Existing explicit accepted-manager continuation. Policy request contains only
// originals supplied by the separate operator signing owner. POST progression is
// durable before native header observation; a lost result remains UNKNOWN, never
// a read-triggered retry. This does not publish activation or execute a child.
func (r *Reconciler) ObserveApprovedManagerChildAuthorization(ctx context.Context, parentID, member, lease string, policyRequest json.RawMessage) (qualification.ChildEnvelope[qualification.ChildAuthorizationObservation], error) {
	var out qualification.ChildEnvelope[qualification.ChildAuthorizationObservation]
	control, ok := r.ManagedControl.(managerChildAuthorizationControl)
	runtime, rok := r.ManagedRuntime.(managerChildAuthorizationRuntime)
	if !ok || !rok || r.Store == nil || workflowcontract.Validate(workflowcontract.Budget, "policyAcceptRequest", policyRequest) != nil {
		return out, qualification.ErrUntrusted
	}
	var request struct {
		Stage                 string
		Policy, PolicyBinding json.RawMessage
	}
	if json.Unmarshal(policyRequest, &request) != nil || request.Stage != "product" {
		return out, qualification.ErrUntrusted
	}
	_, handle, selected, actual, entry, err := r.managerChildPrepared(ctx, parentID, member, lease)
	if err != nil || entry.LifecyclePhase != "prepare" {
		return out, errors.Join(err, qualification.ErrUntrusted)
	}
	var policy struct {
		Payload struct {
			Binding         json.RawMessage
			Assignment      json.RawMessage
			PreparedReceipt model.PreparedReceipt
		}
	}
	if json.Unmarshal(request.Policy, &policy) != nil || !reflect.DeepEqual(policy.Payload.PreparedReceipt, actual.PreparedReceipt) || model.WorkspaceDigest(policy.Payload.Binding) != model.WorkspaceDigest(actual.Binding) {
		return out, qualification.ErrUntrusted
	}
	assignment, err := r.AssignApprovedManagerChild(ctx, parentID, member, lease)
	if err != nil {
		return out, err
	}
	if model.WorkspaceDigest(policy.Payload.Assignment) != model.WorkspaceDigest(assignment) {
		return out, qualification.ErrUntrusted
	}
	var acceptance json.RawMessage
	if err = r.ownedContinuationOnce(ctx, handle.HandleID, "product-policy", map[string]any{"handleDigest": handle.HandleDigest, "preparedAssociationDigest": actual.AssociationDigest, "request": policyRequest}, func() (any, error) { return control.AcceptManagerChildProductPolicy(ctx, handle, policyRequest, lease) }, &acceptance); err != nil {
		return out, err
	}
	var payload struct{ Payload json.RawMessage }
	_ = json.Unmarshal(request.Policy, &payload)
	var assigned struct{ AssignmentDigest string }
	_ = json.Unmarshal(assignment, &assigned)
	grantCall := model.IntentGrantRequest{FormatVersion: 1, RequestID: selected.GrantRequestID, HandleID: handle.HandleID, PreparedReceiptDigest: actual.PreparedReceipt.PreparedReceiptDigest, AssignmentDigest: assigned.AssignmentDigest, ProductPolicyDigest: model.WorkspaceDigest(payload.Payload)}
	var grant json.RawMessage
	if err = r.ownedContinuationOnce(ctx, handle.HandleID, "grant-intent", grantCall, func() (any, error) { return control.ManagerChildGrantIntent(ctx, handle, grantCall, lease) }, &grant); err != nil {
		return out, err
	}
	association, _ := model.WorkspaceCanonicalJSON(actual)
	retained := retainedManagerChildAuthorization{qualification.ChildAuthorizationIntent{PreparationID: entry.PreparationID, PreparationAssociation: association, Policy: request.Policy, PolicyBinding: request.PolicyBinding, GrantIntent: grant}, policyRequest, acceptance}
	var original retainedManagerChildAuthorization
	if err = r.ownedContinuationOnce(ctx, handle.HandleID, "authorization-originals", authorizationOriginalClaim(handle, actual), func() (any, error) { return retained, nil }, &original); err != nil {
		return out, err
	}
	if model.WorkspaceDigest(original) != model.WorkspaceDigest(retained) {
		return out, qualification.ErrUntrusted
	}
	input, err := r.fetchCellFirstText(ctx, cellV2View(entry))
	if err != nil {
		return out, err
	}
	box, err := r.Store.Sandbox(ctx, entry.SandboxID)
	if err != nil || box == nil || box.Generation != entry.SandboxGeneration || box.ObservedGeneration != entry.SandboxGeneration {
		return out, qualification.ErrUntrusted
	}
	current := r.currentAuthorityManifest()
	// Native/header itself has a pre-effect one-shot fence. Replays reauthenticate
	// above but return SAME original observation rather than doing another read.
	err = r.ownedContinuationOnce(ctx, handle.HandleID, "authorization-observation", authorizationOriginalClaim(handle, actual), func() (any, error) {
		return runtime.ObserveCellProductAuthorization(ctx, model.Sandbox{ID: box.ID, Generation: box.Generation, ImageDigest: box.ImageDigest, Cell: true}, entry, current, []byte(input), managerChildAuthorizationReader{r, parentID, member, lease})
	}, &out)
	return out, err
}
