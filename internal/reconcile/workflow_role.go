package reconcile

import (
	"context"
	"errors"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type workflowRoleControl interface {
	WorkflowRoleEnrollmentOperation(context.Context, model.WorkflowRoleOperationRequest) (model.WorkflowRoleOperation, error)
	EnrollWorkflowRole(context.Context, model.WorkflowRoleEnvelope) (model.WorkflowRoleEnrollment, error)
}
type workflowRoleRuntime interface {
	AttestWorkflowRole(context.Context, model.WorkflowRoleOperation, qualification.WorkspaceApplicationWitness, model.WorkspaceRegisteredProducer) (model.WorkflowRoleEnvelope, error)
	ReadControllerFirstTaskApplicability(context.Context, model.Manifest, qualification.ControllerPolicyWitness) (qualification.Applicability, error)
}

var ErrWorkflowRoleExpired = errors.New("retained workflow role proof/lease expired; automatic re-enrollment refused")

func (r *Reconciler) ensureControllerFirstTaskAuthoritiesLocked(ctx context.Context, taskID, operationID string) error {
	control, ok := r.ManagedControl.(workflowRoleControl)
	runtime, rok := r.ManagedRuntime.(workflowRoleRuntime)
	if !ok || !rok {
		return nil
	} // Existing metadata-only adapters stay fail-closed below.
	for _, parent := range r.currentAuthorityManifest().ParentServices {
		if parent.ApplicationOperationID != operationID || parent.DesiredState != "active" || (parent.Role != "manager" && parent.Role != "orchestrator") {
			continue
		}
		// A current accepted registered parent witness requires NO role lease.
		w, err := r.controllerActivityCurrentWitness(ctx, parent.ServiceRegistrationID, qualification.Applicability{}, false)
		if err != nil {
			return err
		}
		if w.Parent.Report.NativeRegistration == nil {
			return state.ErrControllerActivityConflict
		}
		subject := model.CurrentWorkflowRoleSubject(parent, *w.Parent.Report.NativeRegistration)
		call := model.WorkflowRoleOperationRequest{FormatVersion: 1, RequestID: "wfroleop_req_" + model.WorkspaceDigest(map[string]any{"application": w.ApplicationOperation.OperationDigest, "subject": subject})[7:39], Subject: subject}
		step := "role-" + parent.Role
		var op model.WorkflowRoleOperation
		if err = r.ownedContinuationOnce(ctx, taskID, step+"-operation", call, func() (any, error) { return control.WorkflowRoleEnrollmentOperation(ctx, call) }, &op); err != nil {
			return err
		}
		if op.Validate() != nil || op.Subject != subject || op.NodeTokenHash != w.Producer.NodeTokenHash || op.ManagedServiceReceiptDigest != w.Parent.Report.ReceiptDigest || op.NativeContextDigest != model.WorkspaceDigest(w.Parent.Report.NativeRegistration) {
			return state.ErrControllerActivityConflict
		}
		expiry, err := time.Parse(time.RFC3339Nano, op.ExpiresAt)
		if err != nil || !r.now().Before(expiry) {
			return ErrWorkflowRoleExpired
		}
		// Inspect fresh process/native effective role AND registered binding after
		// the actual operation ACK, before a role-proof signing claim is consumed.
		fresh, err := r.controllerActivityCurrentWitness(ctx, parent.ServiceRegistrationID, qualification.Applicability{}, true)
		if err != nil {
			return err
		}
		if model.WorkspaceDigest(fresh.Parent) != model.WorkspaceDigest(w.Parent) {
			return state.ErrControllerActivityConflict
		}
		var proof model.WorkflowRoleEnvelope
		if err = r.ownedContinuationOnce(ctx, taskID, step+"-proof", op, func() (any, error) { return runtime.AttestWorkflowRole(ctx, op, fresh.Parent, w.Producer) }, &proof); err != nil {
			return err
		}
		if proof.Validate() != nil || proof.Payload.OperationDigest != op.OperationDigest || proof.Payload.Subject != subject || proof.Payload.NativeContextDigest != op.NativeContextDigest || proof.Payload.ManagedServiceReceiptDigest != op.ManagedServiceReceiptDigest || proof.KeyID != w.Producer.KeyID {
			return state.ErrControllerActivityConflict
		}
		proofExpiry, err := time.Parse(time.RFC3339Nano, proof.Payload.NotAfter)
		if err != nil || !r.now().Before(proofExpiry) || proofExpiry.After(expiry) {
			return ErrWorkflowRoleExpired
		}
		var enrolled model.WorkflowRoleEnrollment
		if err = r.ownedContinuationOnce(ctx, taskID, step+"-enroll", proof, func() (any, error) { return control.EnrollWorkflowRole(ctx, proof) }, &enrolled); err != nil {
			return err
		}
		leaseExpiry, err := time.Parse(time.RFC3339Nano, enrolled.ExpiresAt)
		if err != nil || enrolled.Validate() != nil || !r.now().Before(leaseExpiry) || leaseExpiry.After(proofExpiry) {
			return ErrWorkflowRoleExpired
		}
		// Original operation/proof/accepted lease are durable BEFORE attachment.
		installed, err := runtime.ReadControllerFirstTaskApplicability(ctx, r.currentAuthorityManifest(), fresh.Installed)
		if errors.Is(err, qualification.ErrControllerDeclarationPending) {
			return ErrControllerFirstTaskAuthorityPending
		}
		if err != nil {
			return err
		}
		var original qualification.Applicability
		if err = r.ownedContinuationOnce(ctx, taskID, step+"-installed", map[string]any{"operationDigest": op.OperationDigest, "parent": parent, "runtimeRevision": r.currentAuthorityManifest().DesiredRevision}, func() (any, error) { return installed, nil }, &original); err != nil {
			return err
		}
		if model.WorkspaceDigest(original) != model.WorkspaceDigest(installed) {
			return state.ErrControllerActivityConflict
		}
		if err = r.bindControllerFirstTaskAuthorityLocked(ctx, operationID, parent.Role, installed, enrolled.Lease); err != nil {
			return err
		}
	}
	return nil
}
