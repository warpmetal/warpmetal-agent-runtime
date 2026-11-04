package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

type controllerApplicationSubmitter interface {
	SubmitWorkspaceApplication(context.Context, model.WorkspaceApplicationEnvelope) (api.WorkspaceApplicationAccepted, error)
}
type controllerApplicationAttestor interface {
	AttestWorkspaceApplication(context.Context, model.WorkspaceApplicationReadback, []qualification.WorkspaceApplicationWitness) (model.WorkspaceApplicationEnvelope, error)
}

// Invoked only AFTER the exact Runtime Report has a successful protected node
// ACK. Not a broker, readiness switch or model grant. Pin/replay one immutable
// signed application envelope before submitting; lost ACK replays exact bytes.

// RedriveWorkspaceApplications retries the post-ACK acceptance phase from the
// durable, already-ACKed controller-parent reports when a previous pass lost or
// raced its acceptance response. It never fabricates a report: only stored
// reports whose AcceptedReceiptDigest exactly equals their current receipt are
// included, and CompleteWorkspaceApplications remains the single idempotent
// submit path (the backend replays a same-operation acceptance).
func (r *Reconciler) RedriveWorkspaceApplications(ctx context.Context) error {
	authority := r.currentAuthorityManifest()
	if len(authority.ParentServices) == 0 {
		return nil
	}
	report := model.Report{ServerID: r.ServerID, AppliedRevision: authority.DesiredRevision}
	seen := map[string]bool{}
	for _, intent := range authority.ParentServices {
		if intent.DesiredState != "active" || seen[intent.ApplicationOperationID] {
			continue
		}
		seen[intent.ApplicationOperationID] = true
		stored, err := r.Store.ControllerParent(ctx, intent.ServiceRegistrationID)
		if err != nil {
			return err
		}
		if stored == nil || stored.AcceptedReceiptDigest == "" ||
			stored.AcceptedReceiptDigest != stored.Report.ReceiptDigest ||
			stored.Report.ObservedState != "ready" {
			continue
		}
		report.ParentServices = append(report.ParentServices, stored.Report)
	}
	if len(report.ParentServices) == 0 {
		return nil
	}
	return r.CompleteWorkspaceApplications(ctx, report)
}

func (r *Reconciler) CompleteWorkspaceApplications(ctx context.Context, acknowledged model.Report) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	authority := r.currentAuthorityManifest()
	if len(authority.ParentServices) == 0 {
		return nil
	}
	if acknowledged.ServerID != r.ServerID {
		return errors.New("application report ACK server conflict")
	}
	if err := r.Store.AcknowledgeControllerParents(ctx, acknowledged.ParentServices); err != nil {
		return err
	}
	submitter, ok := r.ManagedControl.(controllerApplicationSubmitter)
	if !ok {
		return errors.New("application receipt transport dependency pending")
	}
	attestor, ok := r.ManagedRuntime.(controllerApplicationAttestor)
	if !ok {
		return errors.New("registered application root producer dependency pending")
	}
	seen := map[string]bool{}
	for _, parent := range authority.ParentServices {
		if parent.DesiredState != "active" || seen[parent.ApplicationOperationID] {
			continue
		}
		seen[parent.ApplicationOperationID] = true
		localApp, err := r.Store.WorkspaceApplication(ctx, parent.ApplicationOperationID)
		if err != nil {
			return err
		}
		if localApp == nil {
			return errors.New("application durable operation missing")
		}
		if localApp.Applied {
			continue
		}
		op, _, err := r.readControllerApplication(ctx, authority, parent)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(op, localApp.Operation) || acknowledged.AppliedRevision != op.TargetRuntimeRevision {
			return errors.New("application applied Runtime revision conflict")
		}
		readback := model.WorkspaceApplicationReadback{Operation: op, AppliedRuntimeRevision: acknowledged.AppliedRevision, SetupReceipts: op.Dependencies.SetupReceipts, Profiles: op.Dependencies.Profiles, RoleBindings: []model.AppliedControllerRole{}, Limits: op.Limits, MaterializerDigest: op.MaterializerDigest, DependencyDigest: op.DependencyDigest}
		witnesses := []qualification.WorkspaceApplicationWitness{}
		parents := []model.ControllerParentIntent{}
		reports := []model.ControllerParentReport{}
		for _, binding := range op.RoleBindings {
			var intent *model.ControllerParentIntent
			for i := range authority.ParentServices {
				candidate := &authority.ParentServices[i]
				if candidate.ServiceRegistrationID == binding.ServiceRegistrationID {
					intent = candidate
				}
			}
			if intent == nil || intent.DesiredState != "active" {
				return errors.New("application current role withdrawn")
			}
			stored, err := r.Store.ControllerParent(ctx, binding.ServiceRegistrationID)
			if err != nil {
				return err
			}
			if stored == nil || stored.Intent != *intent || stored.AcceptedReceiptDigest == "" || stored.AcceptedReceiptDigest != stored.Report.ReceiptDigest {
				return errors.New("application role lacks exact protected report ACK")
			}
			included := false
			for _, reported := range acknowledged.ParentServices {
				if reported.ServiceRegistrationID == binding.ServiceRegistrationID && reflect.DeepEqual(reported, stored.Report) {
					included = true
				}
			}
			if !included {
				return errors.New("application role missing from exact acknowledged report")
			}
			if err := stored.Report.ValidateReady(*intent); err != nil {
				return err
			}
			// Complete current-file and actual installed-source readback, independently
			// for each role. Metadata-only/idempotent; never prompts/imports/grants.
			if err := r.stageControllerApplicationProfiles(ctx, op, *intent); err != nil {
				return err
			}
			project, err := r.resolveControllerProject(ctx, op, *intent)
			if err != nil {
				return err
			}
			statusRequest := parentRequest(*intent)
			statusRequest["probe"] = true
			current, err := r.controllerHelper(ctx, *intent, containers.ManagedSupervisorStatus, statusRequest)
			if err != nil {
				return err
			}
			materializer, err := controllerMaterializer(op.MaterializerDigest)
			if err != nil {
				return err
			}
			if err := validateParentNativeReceipt(*intent, current, materializer); err != nil {
				return err
			}
			native := stored.Report.NativeRegistration
			if current.SessionID != native.NativeSessionID || current.NativeProjectID != native.NativeProjectID || current.NativeLocationDigest != native.NativeLocationDigest || !reflect.DeepEqual(current.NativeRoleReadback, stored.Report.NativeRoleReadback) {
				return errors.New("application native changed after report ACK")
			}
			readback.RoleBindings = append(readback.RoleBindings, model.AppliedControllerRole{Binding: binding, NativeRegistration: *native, NativeRoleReadback: *stored.Report.NativeRoleReadback})
			parents = append(parents, *intent)
			reports = append(reports, stored.Report)
			witnesses = append(witnesses, qualification.WorkspaceApplicationWitness{Parent: *intent, Report: stored.Report, Workspace: qualification.TrustedWorkspace{HostRoot: project.HostRoot, ContainerRoot: project.ContainerRoot, WorkspaceDigest: project.Report.RootAttestation, Device: project.RootDevice, Inode: project.RootInode}})
		}
		if err := readback.Validate(parents, reports); err != nil {
			return err
		}
		var envelope model.WorkspaceApplicationEnvelope
		if len(localApp.EnvelopeJSON) > 0 {
			if err := json.Unmarshal(localApp.EnvelopeJSON, &envelope); err != nil {
				return err
			}
		} else {
			envelope, err = attestor.AttestWorkspaceApplication(ctx, readback, witnesses)
			if err != nil {
				return err
			}
		}
		if err := envelope.Validate(); err != nil {
			return err
		}
		if !reflect.DeepEqual(envelope.Payload.NativeReceipt.Readback, readback) || envelope.Payload.ManagedServiceReceiptDigest != reports[0].ReceiptDigest {
			return errors.New("application signed current readback conflict")
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		if err := r.Store.PinWorkspaceApplicationEnvelope(ctx, op.OperationID, raw); err != nil {
			return err
		}
		accepted, err := submitter.SubmitWorkspaceApplication(ctx, envelope)
		if err != nil {
			return err
		}
		if err := r.Store.AcceptWorkspaceApplication(ctx, op.OperationID, accepted.ApplicationID, raw); err != nil {
			return err
		}
	}
	return nil
}
