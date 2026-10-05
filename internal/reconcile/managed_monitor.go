package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// ApplyInsightMonitorPolicy changes the managed process environment only at a
// host-verified idle boundary. Every restart reuses the exact pinned service,
// workspace, instruction, and existing native session tuple.
func (r *Reconciler) ApplyInsightMonitorPolicy(ctx context.Context, policy model.InsightPolicyV1) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ref := range policy.Sources {
		if err := r.applyInsightMonitorSource(ctx, policy, ref); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) applyInsightMonitorSource(ctx context.Context, policy model.InsightPolicyV1, ref model.InsightPolicySourceV1) error {
	source, err := r.Store.ContinuitySource(ctx, ref.RegisteredSourceID)
	if err != nil {
		return err
	}
	if source == nil || source.Report.SandboxID != policy.SandboxID || source.Report.SandboxGeneration != ref.SandboxGeneration ||
		source.Report.ServiceRegistrationID != ref.ServiceRegistrationID || source.Report.ServiceGeneration != ref.ServiceGeneration ||
		source.Report.WorkspaceEpoch != ref.WorkspaceEpoch || source.Report.NativeSessionID != ref.NativeSessionID ||
		source.Lifecycle != "running" || source.Report.Availability != "available" {
		return errors.New("insight monitor policy does not match current source authority")
	}
	previous, err := r.Store.InsightPolicyState(ctx, ref.RegisteredSourceID)
	if err != nil {
		return err
	}
	unchanged := false
	if previous != nil {
		if policy.Revision < previous.Revision {
			return errors.New("insight monitor policy revision regressed")
		}
		if policy.Revision == previous.Revision && policy.Enabled == previous.Enabled {
			// Equal revision is only a no-op after the current process status
			// below proves the policy effect on the actual native process.
			unchanged = true
		}
	} else if !policy.Enabled {
		return r.Store.PutInsightPolicyState(ctx, state.InsightPolicyState{RegisteredSourceID: ref.RegisteredSourceID, Revision: policy.Revision})
	}
	if !unchanged && !source.NoAdmittedExecution {
		// A changed policy always requires a restart; hold before any restart.
		return errors.New("managed service is not at a safe idle monitor boundary")
	}
	local, err := r.Store.ManagedService(ctx, ref.ServiceRegistrationID)
	if err != nil {
		return err
	}
	if local == nil || local.Phase != "ready" || local.Report.ObservedState != "ready" ||
		local.Manifest.Identity.ExpectedServiceGeneration != ref.ServiceGeneration || local.Manifest.Identity.SandboxGeneration != ref.SandboxGeneration {
		return errors.New("managed service is not exactly ready for monitor restart")
	}
	project, err := r.Store.ManagedProject(ctx, local.Manifest.Workspace.SelectionID)
	if err != nil {
		return err
	}
	if project == nil || project.Report.ProjectID != local.Manifest.Workspace.ProjectID ||
		project.Report.WorkspaceEpoch != ref.WorkspaceEpoch || project.Report.RootAttestation != local.Manifest.Workspace.RootAttestation {
		return errors.New("managed project authority changed before monitor restart")
	}
	setup, err := r.Store.SetupOperation(ctx, local.Manifest.Profile.SetupOperationID)
	if err != nil || setup == nil || setup.State != "ready" {
		return errors.Join(err, errors.New("managed profile is not ready for monitor restart"))
	}
	var setupManifest model.SetupOperation
	if err := json.Unmarshal(setup.RequestJSON, &setupManifest); err != nil {
		return err
	}
	version := ""
	if setupManifest.Materializer.Bin != nil {
		version = setupManifest.Materializer.Bin.Version
	}
	fetch := model.ManagedServiceFetchRequestV1{
		FormatVersion: 1, OperationID: local.Manifest.OperationID, ActionRevision: local.Manifest.ActionRevision,
		DesiredRevision: local.Manifest.DesiredRevision, ConfigDigest: local.Manifest.ConfigDigest,
		ServiceRegistrationID: ref.ServiceRegistrationID, ServiceGeneration: ref.ServiceGeneration,
		SandboxID: policy.SandboxID, SandboxGeneration: ref.SandboxGeneration, ProcessInstance: local.ProcessInstance,
	}
	instruction, err := r.ManagedControl.ManagedServiceInstructions(ctx, ref.ServiceRegistrationID, fetch)
	if err != nil || instruction.InstructionRevision != local.Manifest.Instructions.InstructionRevision ||
		instruction.InstructionDigest != local.Manifest.Instructions.InstructionDigest || !instruction.ExpiresAt.After(r.now()) ||
		!validateManagedInstruction(instruction.Content, instruction.InstructionDigest) {
		return errors.Join(err, errors.New("managed instructions changed before monitor restart"))
	}
	statusPayload, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "sandboxId": policy.SandboxID, "instance": local.Manifest.Identity.Instance,
		"profileId": local.Manifest.Profile.ProfileID, "profileDigest": local.Manifest.Profile.ProfileDigest,
		"probe": true, "requestTimeoutSeconds": 30,
	})
	statusJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, policy.SandboxID, containers.ManagedSupervisorStatus, statusPayload)
	if err != nil {
		return err
	}
	status, err := validateManagedSupervisorReceipt(statusJSON, "status", "running")
	if err != nil || !status.Ready || status.SessionID != ref.NativeSessionID ||
		status.NativeProjectID != source.Report.NativeProjectID || status.NativeLocationDigest != source.Report.NativeLocationDigest ||
		status.InstructionRevision != instruction.InstructionRevision || status.InstructionDigest != instruction.InstructionDigest || !status.InstructionApplied {
		return errors.Join(err, errors.New("managed native identity changed before monitor restart"))
	}
	intent := managedMonitorIntent{Enabled: policy.Enabled}
	if policy.Enabled {
		intent.SourceInstanceID = ref.RegisteredSourceID
		intent.WorkspaceEpoch = ref.WorkspaceEpoch
	}
	if unchanged {
		if monitorErr := validateManagedMonitorReceipt(intent, status); monitorErr == nil {
			// The current actual process already proves the policy effect, so
			// the equal revision is a verified no-op even while a worker task
			// is active; only an actual restart needs the idle boundary.
			return nil
		}
		if !source.NoAdmittedExecution {
			return errors.New("managed service is not at a safe idle monitor boundary")
		}
	}
	restartRequest := managedLaunchComposition{
		SandboxID:              policy.SandboxID,
		Instance:               local.Manifest.Identity.Instance,
		ProfileID:              local.Manifest.Profile.ProfileID,
		ProfileDigest:          local.Manifest.Profile.ProfileDigest,
		Version:                version,
		Port:                   managedServicePort,
		ProjectRoot:            project.ContainerRoot,
		SessionMode:            "lookup_only",
		InstructionText:        instruction.Content,
		InstructionDigest:      instruction.InstructionDigest,
		InstructionRevision:    instruction.InstructionRevision,
		RuntimeContractVersion: local.Manifest.RuntimeContractVersion,
		Monitor:                intent,
	}.request()
	restartPayload, _ := json.Marshal(restartRequest)
	restartJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, policy.SandboxID, containers.ManagedSupervisorRestart, restartPayload)
	if err != nil {
		return err
	}
	restarted, err := validateManagedSupervisorReceipt(restartJSON, "restart", "ready")
	if err != nil || !restarted.Ready || restarted.SessionID != ref.NativeSessionID ||
		restarted.NativeProjectID != source.Report.NativeProjectID || restarted.NativeLocationDigest != source.Report.NativeLocationDigest ||
		restarted.InstructionRevision != instruction.InstructionRevision || restarted.InstructionDigest != instruction.InstructionDigest || !restarted.InstructionApplied {
		return errors.Join(err, fmt.Errorf("managed monitor restart did not preserve current native authority"))
	}
	if err := validateManagedMonitorReceipt(intent, restarted); err != nil {
		return err
	}
	return r.Store.PutInsightPolicyState(ctx, state.InsightPolicyState{
		RegisteredSourceID: ref.RegisteredSourceID, Revision: policy.Revision, Enabled: policy.Enabled,
	})
}
