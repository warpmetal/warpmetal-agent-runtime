package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

const managedServicePort = 18443

var managedNativeProjectPattern = regexp.MustCompile(`^(global|[a-f0-9]{40})$`)
var managedSafeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$`)
var managedWorkerTaskPattern = regexp.MustCompile(`^task_[A-Za-z0-9_-]{4,72}$`)

var managedWorkerActivePhases = map[string]bool{
	"claimed": true, "payload": true, "prompt_pending": true, "running": true,
}

var managedWorkerSettledPhases = map[string]bool{
	"reported": true, "requeued": true, "reconciling": true,
}

type managedSupervisorReceipt struct {
	SchemaVersion              int                             `json:"schemaVersion"`
	Command                    string                          `json:"command"`
	Status                     string                          `json:"status"`
	Phase                      string                          `json:"phase"`
	Reason                     string                          `json:"reason"`
	Instance                   string                          `json:"instance"`
	SandboxID                  string                          `json:"sandboxId"`
	ProfileID                  string                          `json:"profileId"`
	ProfileDigest              string                          `json:"profileDigest"`
	ProfileRevision            int64                           `json:"profileRevision"`
	Version                    string                          `json:"version"`
	Hostname                   string                          `json:"hostname"`
	Port                       int                             `json:"port"`
	PID                        int                             `json:"pid"`
	Ready                      bool                            `json:"ready"`
	StartCount                 int                             `json:"startCount"`
	SessionID                  string                          `json:"sessionId"`
	SessionCreated             bool                            `json:"sessionCreated"`
	SessionReused              bool                            `json:"sessionReused"`
	SessionCreatedCount        int                             `json:"sessionCreatedCount"`
	ConversationCount          int                             `json:"conversationCount"`
	SessionMode                string                          `json:"sessionMode"`
	NativeProjectID            string                          `json:"nativeProjectId"`
	NativeLocationDigest       string                          `json:"nativeLocationDigest"`
	InstructionRevision        int64                           `json:"instructionRevision"`
	InstructionDigest          string                          `json:"instructionDigest"`
	InstructionApplied         bool                            `json:"instructionApplied"`
	ManagerPluginDigest        string                          `json:"managerPluginDigest"`
	ManagerPluginLoaded        bool                            `json:"managerPluginLoaded"`
	ManagerProfile             model.InsightsManagerProfileV1  `json:"managerProfile"`
	ManagerProviderID          string                          `json:"managerProviderId"`
	ManagerModelID             string                          `json:"managerModelId"`
	ManagerNativeProtocol      string                          `json:"managerNativeProtocol"`
	ManagerProviderRouteDigest string                          `json:"managerProviderRouteDigest"`
	ManagerRecommendAvailable  bool                            `json:"managerRecommendAvailable"`
	ManagerCapabilityReason    *string                         `json:"managerCapabilityReason"`
	ManagerRecipeIDs           []string                        `json:"managerRecipeIds"`
	NativeGuard                *model.NativeGuardObservationV1 `json:"nativeGuard,omitempty"`
	Applied                    bool                            `json:"applied"`
	Restarted                  bool                            `json:"restarted"`
	BindingRevision            int64                           `json:"bindingRevision"`
	Binding                    json.RawMessage                 `json:"binding"`
	Stored                     bool                            `json:"stored"`
	EnrollmentID               string                          `json:"enrollmentId"`
	Drained                    bool                            `json:"drained"`
	ReceiptDigest              string                          `json:"receiptDigest"`
	LeaseTokenPresent          bool                            `json:"leaseTokenPresent"`
	LeaseRole                  string                          `json:"leaseRole"`
	LeaseExpired               bool                            `json:"leaseExpired"`
	Generation                 int64                           `json:"generation"`
}

type managedWorkerReceipt struct {
	SchemaVersion int             `json:"schemaVersion"`
	Command       string          `json:"command"`
	Status        string          `json:"status"`
	Instance      string          `json:"instance"`
	Busy          bool            `json:"busy"`
	ActiveTask    json.RawMessage `json:"activeTask"`
	TaskID        *string         `json:"taskId"`
	MessageID     *string         `json:"messageId"`
	Attempt       *int64          `json:"attempt"`
	Outcome       *string         `json:"outcome"`
	Deduped       bool            `json:"deduped"`
}

type managedWorkerActiveTask struct {
	TaskID    string  `json:"taskId"`
	Phase     string  `json:"phase"`
	Attempt   *int64  `json:"attempt"`
	MessageID *string `json:"messageId"`
	SessionID *string `json:"sessionId"`
	Outcome   *string `json:"outcome"`
	UpdatedAt *string `json:"updatedAt"`
}

type managedSourceRegistrationReceipt struct {
	SchemaVersion         int    `json:"schemaVersion"`
	Command               string `json:"command"`
	Status                string `json:"status"`
	Instance              string `json:"instance"`
	SandboxID             string `json:"sandboxId"`
	ProfileID             string `json:"profileId"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
	ServiceGeneration     int64  `json:"serviceGeneration"`
	RegisteredSourceID    string `json:"registeredSourceId"`
	WorkspaceEpoch        string `json:"workspaceEpoch"`
	NativeSessionID       string `json:"nativeSessionId"`
	NativeProjectID       string `json:"nativeProjectId"`
	NativeLocationDigest  string `json:"nativeLocationDigest"`
	ProfileRevision       int64  `json:"profileRevision"`
	ProfileDigest         string `json:"profileDigest"`
	InstructionRevision   int64  `json:"instructionRevision"`
	InstructionDigest     string `json:"instructionDigest"`
	Ready                 bool   `json:"ready"`
}

func (r *Reconciler) reconcileManagedWorkspaceRequests(ctx context.Context, manifest model.Manifest) error {
	for _, request := range manifest.ManagedWorkspaceRequests {
		if request.Request != "create_default" {
			return errors.New("unsupported managed workspace request")
		}
		if r.Workspaces == nil {
			return errors.New("managed workspace request has no trusted workspace provider")
		}
		diskGiB := 0
		for _, sandbox := range manifest.Sandboxes {
			if sandbox.ID == request.SandboxID && sandbox.Generation == request.SandboxGeneration {
				diskGiB = sandbox.Resources.WorkspaceDiskGiB
				break
			}
		}
		if diskGiB < 1 {
			return errors.New("managed workspace request has no current sandbox disk authority")
		}
		anchor, err := r.Workspaces.Ensure(ctx, request.SandboxID, diskGiB)
		if err != nil {
			return fmt.Errorf("resolve trusted workspace anchor: %w", err)
		}
		_, err = r.ManagedCatalog.EnsureDefault(ctx, workspacecatalog.DefaultProjectRequest{
			Anchor: anchor, ServerID: request.ServerID, TeamID: request.TeamID, MemberID: request.MemberID,
			SandboxID: request.SandboxID, SandboxGeneration: request.SandboxGeneration,
			ServiceRegistrationID: request.ServiceRegistrationID, AllocationDigest: request.AllocationDigest,
		})
		if err != nil {
			return fmt.Errorf("create managed project %s: %w", request.OperationID, err)
		}
	}
	return nil
}

// reconcileManagedServices reconciles every managed service of the manifest. It
// returns the bounded, retryable workspace-remount reasons it deferred and, in
// a separate error, the first fatal failure: a deferred service never hides the
// failure of another service, and a fatal failure never turns a deferred reason
// into a silent skip of the whole pass.
func (r *Reconciler) reconcileManagedServices(ctx context.Context, manifest model.Manifest) (deferred, fatal error) {
	for _, desired := range manifest.ManagedServices {
		if err := r.reconcileManagedService(ctx, desired); err != nil {
			wrapped := fmt.Errorf("managed service %s: %w", desired.Identity.ServiceRegistrationID, err)
			if errors.Is(err, workspacecatalog.ErrManagedProjectRemountAttestation) {
				// Fail-closed: this service was not admitted, executed or
				// advanced. Its bounded, retryable remount reason is deferred so
				// every other service in the same manifest still reconciles.
				deferred = errors.Join(deferred, wrapped)
				continue
			}
			return deferred, wrapped
		}
	}
	return deferred, nil
}

func (r *Reconciler) reconcileManagedService(ctx context.Context, desired model.ManagedServiceV1) error {
	// A durably completed stop/retirement is an acknowledgement of that exact
	// intent, not authority to stop a later sandbox generation or registration.
	// Replay it before resolving the now potentially replaced live resources.
	if desired.DesiredState == "stopped" || desired.DesiredState == "retired" {
		completed, err := r.Store.ManagedService(ctx, desired.Identity.ServiceRegistrationID)
		if err != nil {
			return err
		}
		if completed != nil && completed.Phase == desired.DesiredState && completed.ErrorCode == "" &&
			reflect.DeepEqual(completed.Manifest, desired) &&
			completed.Report.FormatVersion == 1 && completed.Report.LastError == nil &&
			completed.Report.Identity == desired.Identity && completed.Report.ConfigDigest == desired.ConfigDigest &&
			completed.Report.OperationID == desired.OperationID && completed.Report.ActionRevision == desired.ActionRevision &&
			completed.Report.ObservedDesiredRevision == desired.DesiredRevision &&
			completed.Report.ObservedState == desired.DesiredState && completed.Report.WorkerStatus == "stopped" &&
			setupReceiptDigestPattern.MatchString(completed.Report.ReceiptDigest) &&
			!r.managedWorkerExecutionActive(desired.Identity.ServiceRegistrationID) {
			return nil
		}
	}
	sandbox, err := r.Store.Sandbox(ctx, desired.Identity.SandboxID)
	if err != nil {
		return err
	}
	if sandbox == nil || sandbox.ObservedState != "running" ||
		sandbox.ObservedGeneration != desired.Identity.SandboxGeneration {
		return errors.New("managed service sandbox generation is not running")
	}
	setup, err := r.Store.SetupOperation(ctx, desired.Profile.SetupOperationID)
	if err != nil {
		return err
	}
	if setup == nil || setup.State != "ready" || setup.SandboxID != desired.Identity.SandboxID ||
		setup.SandboxGeneration != desired.Identity.SandboxGeneration || setup.ProfileID != desired.Profile.ProfileID ||
		setup.ProfileRevision != desired.Profile.ProfileRevision || setup.ProfileDigest != desired.Profile.ProfileDigest {
		return errors.New("managed service profile is not exactly ready")
	}
	project, err := r.resolveManagedProject(ctx, desired)
	if err != nil {
		return err
	}
	processInstance := model.ManagedServiceProcessInstance(desired.Identity.Instance, desired.Identity.ExpectedServiceGeneration)
	if err := r.Store.PutManagedServiceIntent(ctx, state.LocalManagedService{
		Manifest: desired, Phase: "pending", ProcessInstance: processInstance, Port: managedServicePort,
		ServiceGeneration: desired.Identity.ExpectedServiceGeneration,
	}); err != nil {
		return err
	}
	local, err := r.Store.ManagedService(ctx, desired.Identity.ServiceRegistrationID)
	if err != nil || local == nil {
		return errors.Join(err, errors.New("managed service intent disappeared"))
	}
	if desired.DesiredState != "active" {
		return r.reconcileManagedServiceInactive(ctx, desired, project, local)
	}
	fetch := model.ManagedServiceFetchRequestV1{
		FormatVersion: 1, OperationID: desired.OperationID, ActionRevision: desired.ActionRevision,
		DesiredRevision: desired.DesiredRevision, ConfigDigest: desired.ConfigDigest,
		ServiceRegistrationID: desired.Identity.ServiceRegistrationID,
		ServiceGeneration:     desired.Identity.ExpectedServiceGeneration,
		SandboxID:             desired.Identity.SandboxID, SandboxGeneration: desired.Identity.SandboxGeneration,
		ProcessInstance: processInstance,
	}
	enrollment, err := r.ManagedControl.ManagedServiceEnrollment(ctx, desired.Identity.ServiceRegistrationID, fetch)
	if err != nil {
		return r.failManagedService(ctx, desired, "enrollment_unavailable", err)
	}
	instruction, err := r.ManagedControl.ManagedServiceInstructions(ctx, desired.Identity.ServiceRegistrationID, fetch)
	if err != nil {
		return r.failManagedService(ctx, desired, "instruction_unavailable", err)
	}
	if enrollment.EnrollmentToken == "" || enrollment.ExchangePath == "" || !enrollment.EnrollmentExpiresAt.After(r.now()) {
		return r.failManagedService(ctx, desired, "invalid_enrollment", errors.New("node enrollment is absent or expired"))
	}
	if instruction.InstructionRevision != desired.Instructions.InstructionRevision ||
		instruction.InstructionDigest != desired.Instructions.InstructionDigest || !instruction.ExpiresAt.After(r.now()) ||
		!validateManagedInstruction(instruction.Content, instruction.InstructionDigest) {
		return r.failManagedService(ctx, desired, "invalid_instruction", errors.New("node instruction tuple is invalid"))
	}
	enrollRequest := map[string]any{
		"schemaVersion": 1, "sandboxId": desired.Identity.SandboxID, "instance": desired.Identity.Instance,
		"profileId": desired.Profile.ProfileID, "endpoint": r.ManagedControl.ManagedServiceEndpoint(),
		"enrollmentToken": enrollment.EnrollmentToken, "serverId": desired.Identity.ServerID,
		"teamId": desired.Identity.TeamID, "memberId": desired.Identity.MemberID,
		"generation": desired.Identity.SandboxGeneration, "processInstance": processInstance,
		"allowInsecureLoopback": false, "requestTimeoutSeconds": 30,
	}
	enrollPayload, _ := json.Marshal(enrollRequest)
	enrollReceipt, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorEnroll, enrollPayload)
	if err != nil {
		return r.failManagedService(ctx, desired, "enrollment_failed", err)
	}
	var enrolled managedSupervisorReceipt
	err = decodeManagedSupervisorReceipt(enrollReceipt, &enrolled)
	validEnrollmentStatus := enrolled.Status == "enrolled" || enrolled.Status == "refreshed"
	if enrolled.SchemaVersion != 1 || enrolled.Command != "enroll" {
		validEnrollmentStatus = false
	}
	if err != nil || !validEnrollmentStatus || !enrolled.Stored || !enrolled.LeaseTokenPresent || enrolled.LeaseExpired ||
		enrolled.LeaseRole != desired.Identity.Role || enrolled.Generation != desired.Identity.SandboxGeneration {
		if err == nil {
			err = errors.New("managed enrollment receipt did not prove current role and lease")
		}
		return r.failManagedService(ctx, desired, "invalid_enrollment_receipt", err)
	}
	rebindReceipt, err := r.rebindManagedServiceAuthority(ctx, desired)
	if err != nil {
		return r.failManagedService(ctx, desired, "authority_rebind_failed", err)
	}
	sessionMode := local.RecoverySessionMode()
	if err := r.Store.MarkManagedServiceCreationDispatched(ctx, desired.Identity.ServiceRegistrationID, desired.ConfigDigest); err != nil {
		return err
	}
	var setupManifest model.SetupOperation
	if err := json.Unmarshal(setup.RequestJSON, &setupManifest); err != nil {
		return r.failManagedService(ctx, desired, "invalid_profile_state", err)
	}
	version := ""
	if desired.Profile.ProfileID == "opencode" && setupManifest.Materializer.Bin != nil {
		version = setupManifest.Materializer.Bin.Version
	}
	startRequest := map[string]any{
		"schemaVersion": 1, "sandboxId": desired.Identity.SandboxID, "instance": desired.Identity.Instance,
		"profileId": desired.Profile.ProfileID, "profileDigest": desired.Profile.ProfileDigest,
		"version": version, "port": managedServicePort,
		"projectRoot": project.ContainerRoot, "sessionMode": sessionMode,
		"instructionText": instruction.Content, "instructionDigest": instruction.InstructionDigest,
		"instructionRevision": instruction.InstructionRevision,
	}
	if version := desired.RuntimeContractVersion; version != "" {
		startRequest["runtimeContractVersion"] = version
	}
	startPayload, _ := json.Marshal(startRequest)
	startReceiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorStart, startPayload)
	if err != nil {
		return r.progressManagedService(ctx, desired, "start_outcome_unknown", fmt.Errorf("managed start outcome is unknown: %w", err))
	}
	var startReceipt managedSupervisorReceipt
	err = decodeManagedSupervisorReceipt(startReceiptJSON, &startReceipt)
	validStartStatus := startReceipt.Status == "ready" || startReceipt.Status == "already_running"
	if startReceipt.SchemaVersion != 1 || startReceipt.Command != "start" {
		validStartStatus = false
	}
	if err != nil || !validStartStatus || !startReceipt.Ready || startReceipt.Phase != "running" || startReceipt.SessionID == "" ||
		startReceipt.Instance != desired.Identity.Instance || startReceipt.SandboxID != desired.Identity.SandboxID ||
		startReceipt.ProfileID != desired.Profile.ProfileID || startReceipt.ProfileDigest != desired.Profile.ProfileDigest ||
		startReceipt.ProfileRevision != desired.Profile.ProfileRevision || startReceipt.Version != version ||
		startReceipt.Port != managedServicePort ||
		!managedNativeProjectPattern.MatchString(startReceipt.NativeProjectID) || !setupReceiptDigestPattern.MatchString(startReceipt.NativeLocationDigest) ||
		startReceipt.InstructionRevision != instruction.InstructionRevision ||
		startReceipt.InstructionDigest != instruction.InstructionDigest || !startReceipt.InstructionApplied {
		if err == nil {
			err = errors.New("managed start receipt did not prove native and instruction readiness")
		}
		return r.failManagedService(ctx, desired, "invalid_start_receipt", err)
	}
	statusPayload, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "sandboxId": desired.Identity.SandboxID, "instance": desired.Identity.Instance,
		"profileId": desired.Profile.ProfileID, "profileDigest": desired.Profile.ProfileDigest,
		"probe": true, "requestTimeoutSeconds": 30,
	})
	statusReceiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorStatus, statusPayload)
	if err != nil {
		return r.failManagedService(ctx, desired, "native_status_failed", err)
	}
	statusReceipt, err := validateManagedSupervisorReceipt(statusReceiptJSON, "status", "running")
	if err != nil || !statusReceipt.Ready || statusReceipt.SessionID != startReceipt.SessionID ||
		statusReceipt.NativeProjectID != startReceipt.NativeProjectID || statusReceipt.NativeLocationDigest != startReceipt.NativeLocationDigest ||
		statusReceipt.InstructionRevision != instruction.InstructionRevision || statusReceipt.InstructionDigest != instruction.InstructionDigest ||
		!statusReceipt.InstructionApplied {
		if err == nil {
			err = errors.New("managed status did not preserve exact native readiness")
		}
		return r.failManagedService(ctx, desired, "invalid_native_status", err)
	}
	workerReceipts, err := r.runManagedWorkerBoundary(ctx, desired)
	if err != nil {
		return r.failManagedService(ctx, desired, "worker_not_ready", err)
	}
	if err := r.recheckManagedAuthority(ctx, desired, project); err != nil {
		return r.failManagedService(ctx, desired, "authority_changed", err)
	}
	registeredSourceID := managedSourceID(desired.Identity.ServiceRegistrationID)
	registrationReceipt, err := r.registerManagedSource(ctx, desired, registeredSourceID, startReceipt, instruction)
	if err != nil {
		return r.failManagedService(ctx, desired, "source_registration_failed", err)
	}
	var execution *managedWorkerExecution
	if desired.Identity.Role != "manager" {
		execution = r.ensureManagedWorkerExecution(desired, project)
	}
	native := &model.ManagedNativeRegistrationV1{
		RegisteredSourceID: registeredSourceID, WorkspaceEpoch: desired.Workspace.WorkspaceEpoch,
		NativeSessionID: startReceipt.SessionID, NativeProjectID: startReceipt.NativeProjectID,
		NativeLocationDigest: startReceipt.NativeLocationDigest,
	}
	receiptDigest := digestManagedReceipts(enrollReceipt, append(append(append(rebindReceipt, startReceiptJSON...), statusReceiptJSON...), registrationReceipt...), workerReceipts)
	report := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: desired.OperationID, ActionRevision: desired.ActionRevision,
		ObservedDesiredRevision: desired.DesiredRevision, ConfigDigest: desired.ConfigDigest, ObservedState: "ready",
		Identity: desired.Identity, ServiceGeneration: desired.Identity.ExpectedServiceGeneration,
		ProfileStatus: "ready", WorkspaceStatus: "ready", EnrollmentStatus: "ready", WorkerStatus: "ready",
		InstructionApplied: true, InstructionRevision: instruction.InstructionRevision,
		InstructionDigest: instruction.InstructionDigest, NativeRegistration: native, ReceiptDigest: receiptDigest,
	}
	// A lease renewal proves current health but does not replace the durable
	// completion receipt for this action. Preserve it only after all fresh
	// boundary checks above and only if every reported semantic field matches.
	if local.Phase == "ready" && local.ErrorCode == "" && setupReceiptDigestPattern.MatchString(local.Report.ReceiptDigest) {
		renewed := report
		renewed.ReceiptDigest = local.Report.ReceiptDigest
		if reflect.DeepEqual(renewed, local.Report) {
			report = local.Report
		}
	}
	previousSource, err := r.Store.ContinuitySource(ctx, registeredSourceID)
	if err != nil {
		return r.failManagedService(ctx, desired, "source_registration_failed", err)
	}
	source := state.LocalContinuitySource{
		Report: model.ContinuitySourceReportV1{
			FormatVersion: 1, RegisteredSourceID: registeredSourceID,
			ServiceRegistrationID: desired.Identity.ServiceRegistrationID,
			ServiceGeneration:     desired.Identity.ExpectedServiceGeneration, ProjectID: desired.Workspace.ProjectID,
			SandboxID: desired.Identity.SandboxID, SandboxGeneration: desired.Identity.SandboxGeneration,
			WorkspaceEpoch: desired.Workspace.WorkspaceEpoch, NativeSessionID: startReceipt.SessionID,
			NativeProjectID: startReceipt.NativeProjectID, NativeLocationDigest: startReceipt.NativeLocationDigest,
			ScopeRevision: desired.Workspace.ScopeRevision, Role: desired.Identity.Role,
			ProfileRevision: desired.Profile.ProfileRevision, InstructionRevision: instruction.InstructionRevision,
			Availability: "available", LastObservedAt: r.now(),
		},
		Root: project.HostRoot, Instance: desired.Identity.Instance, Lifecycle: "running",
		LifecycleRevision:   desired.ActionRevision,
		NoAdmittedExecution: preservedIdleBoundary(desired, previousSource, startReceipt.SessionID),
	}
	capability, err := managedManagerCapability(desired, registeredSourceID, startReceipt, *statusReceipt)
	if err != nil {
		return r.failManagedService(ctx, desired, "manager_capability_invalid", err)
	}
	if err := r.Store.PutManagerCapability(ctx, capability); err != nil {
		return err
	}
	if err := r.Store.PutContinuitySource(ctx, source); err != nil {
		return err
	}
	if execution != nil {
		r.promoteIdleManagedExecution(ctx, desired, execution)
	}
	return r.Store.UpdateManagedService(ctx, desired.Identity.ServiceRegistrationID, "ready", &report, "")
}

func (r *Reconciler) rebindManagedServiceAuthority(ctx context.Context, desired model.ManagedServiceV1) ([]byte, error) {
	authority, modelID, authMode, ok := completeManagedServiceAuthority(desired)
	if !ok {
		return nil, nil
	}
	request := map[string]any{
		"schemaVersion": 1, "sandboxId": desired.Identity.SandboxID, "instance": desired.Identity.Instance,
		"profileId": desired.Profile.ProfileID, "profileDigest": desired.Profile.ProfileDigest,
		"provider": authority.ProviderID, "model": modelID, "authMode": authMode,
		"bindingRevision": authority.TeamRevision, "restart": false,
	}
	if version := desired.RuntimeContractVersion; version != "" {
		request["runtimeContractVersion"] = version
	}
	payload, _ := json.Marshal(request)
	receiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorRebind, payload)
	if err != nil {
		// The explicit Team revision makes this exact replay idempotent. If the
		// first call durably wrote the tuple but lost its response, the supervisor
		// accepts the same revision and tuple without another drain or restart.
		receiptJSON, _, err = r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorRebind, payload)
	}
	if err != nil {
		return nil, fmt.Errorf("rebind managed provider authority: %w", err)
	}
	var receipt managedSupervisorReceipt
	err = decodeManagedSupervisorReceipt(receiptJSON, &receipt)
	if err != nil || receipt.SchemaVersion != 1 || receipt.Command != "rebind" || receipt.Status != "applied" ||
		!receipt.Applied || receipt.Restarted || receipt.BindingRevision != authority.TeamRevision ||
		receipt.SandboxID != desired.Identity.SandboxID || receipt.Instance != desired.Identity.Instance ||
		receipt.ProfileID != desired.Profile.ProfileID || receipt.ProfileDigest != desired.Profile.ProfileDigest {
		if err == nil {
			err = errors.New("managed rebind receipt did not prove the exact service authority")
		}
		return nil, err
	}
	var binding struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
		AuthMode string `json:"authMode"`
	}
	decoder := json.NewDecoder(bytes.NewReader(receipt.Binding))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		binding.Provider != authority.ProviderID || binding.Model != normalizedManagedModelID(authority.ProviderID, modelID) ||
		binding.AuthMode != authMode {
		if err == nil {
			err = errors.New("managed rebind receipt changed the authority tuple")
		}
		return nil, err
	}
	return receiptJSON, nil
}

func completeManagedServiceAuthority(desired model.ManagedServiceV1) (*model.ManagedServiceAuthorityV1, string, string, bool) {
	authority := desired.Authority
	if authority == nil || authority.ModelID == nil || authority.AuthMode == nil {
		return authority, "", "", false
	}
	return authority, *authority.ModelID, *authority.AuthMode, true
}

func normalizedManagedModelID(providerID, modelID string) string {
	return strings.TrimPrefix(modelID, providerID+"/")
}

func (r *Reconciler) registerManagedSource(ctx context.Context, desired model.ManagedServiceV1, registeredSourceID string, native managedSupervisorReceipt, instruction model.ManagedServiceInstructionV1) ([]byte, error) {
	request := map[string]any{
		"schemaVersion": 1, "sandboxId": desired.Identity.SandboxID, "instance": desired.Identity.Instance,
		"profileId": desired.Profile.ProfileID,
		"registration": map[string]any{
			"formatVersion": 1,
			"identity": map[string]any{
				"serverId": desired.Identity.ServerID, "teamId": desired.Identity.TeamID, "memberId": desired.Identity.MemberID,
				"sandboxId": desired.Identity.SandboxID, "sandboxGeneration": desired.Identity.SandboxGeneration,
				"serviceRegistrationId": desired.Identity.ServiceRegistrationID, "serviceGeneration": desired.Identity.ExpectedServiceGeneration,
				"instance": desired.Identity.Instance, "role": desired.Identity.Role, "projectId": desired.Workspace.ProjectID,
				"workspaceEpoch": desired.Workspace.WorkspaceEpoch, "profileId": desired.Profile.ProfileID,
				"profileRevision": desired.Profile.ProfileRevision, "profileDigest": desired.Profile.ProfileDigest,
				"instructionRevision": instruction.InstructionRevision, "instructionDigest": instruction.InstructionDigest,
			},
			"source": map[string]any{
				"registeredSourceId": registeredSourceID, "nativeSessionId": native.SessionID,
				"nativeProjectId": native.NativeProjectID, "nativeLocationDigest": native.NativeLocationDigest,
			},
		},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	receiptJSON, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, containers.ManagedSupervisorRegisterSource, payload)
	if err != nil {
		return nil, err
	}
	var receipt managedSourceRegistrationReceipt
	if err := decodeManagedReceipt(receiptJSON, &receipt, true); err != nil {
		return nil, err
	}
	validStatus := receipt.Status == "registered" || receipt.Status == "unchanged"
	if receipt.SchemaVersion != 1 || receipt.Command != "register-source" || !validStatus || receipt.Ready ||
		receipt.Instance != desired.Identity.Instance || receipt.SandboxID != desired.Identity.SandboxID ||
		receipt.ProfileID != desired.Profile.ProfileID || receipt.ServiceRegistrationID != desired.Identity.ServiceRegistrationID ||
		receipt.ServiceGeneration != desired.Identity.ExpectedServiceGeneration || receipt.RegisteredSourceID != registeredSourceID ||
		receipt.WorkspaceEpoch != desired.Workspace.WorkspaceEpoch || receipt.NativeSessionID != native.SessionID ||
		receipt.NativeProjectID != native.NativeProjectID || receipt.NativeLocationDigest != native.NativeLocationDigest ||
		receipt.ProfileRevision != desired.Profile.ProfileRevision || receipt.ProfileDigest != desired.Profile.ProfileDigest ||
		receipt.InstructionRevision != instruction.InstructionRevision || receipt.InstructionDigest != instruction.InstructionDigest {
		return nil, errors.New("managed source registration receipt did not preserve exact host authority")
	}
	return receiptJSON, nil
}

func (r *Reconciler) resolveManagedProject(ctx context.Context, desired model.ManagedServiceV1) (workspacecatalog.RegisteredProject, error) {
	project, err := r.ManagedCatalog.Resolve(ctx, workspacecatalog.ResolveProjectRequest{
		SelectionID: desired.Workspace.SelectionID, ProjectID: desired.Workspace.ProjectID,
		WorkspaceEpoch: desired.Workspace.WorkspaceEpoch, SandboxID: desired.Identity.SandboxID,
		SandboxGeneration:     desired.Identity.SandboxGeneration,
		ServiceRegistrationID: desired.Identity.ServiceRegistrationID, ConfigDigest: desired.ConfigDigest,
	})
	if err == nil {
		if project.Report.RootAttestation != desired.Workspace.RootAttestation {
			// The local record is fully verified and holds a newer root
			// attestation than the manifest. When its superseded attestation is
			// exactly the manifest's, the manifest still carries the
			// pre-remount authority of the documented workspace remount: the
			// service stays untouched and the bounded reason is deferred until a
			// manifest carrying the ratified re-attestation arrives. Any other
			// attestation mismatch stays a project change.
			if project.SupersededRootAttestation != "" && project.SupersededRootAttestation == desired.Workspace.RootAttestation {
				return workspacecatalog.RegisteredProject{}, workspacecatalog.ErrManagedProjectRemountAttestation
			}
			return workspacecatalog.RegisteredProject{}, workspacecatalog.ErrProjectChanged
		}
		return project, nil
	}
	record, stateErr := r.Store.ManagedProject(ctx, desired.Workspace.SelectionID)
	if stateErr != nil || record == nil {
		return workspacecatalog.RegisteredProject{}, errors.Join(err, stateErr)
	}
	project, err = r.ManagedCatalog.EnsureDefault(ctx, workspacecatalog.DefaultProjectRequest{
		Anchor: record.Anchor, ServerID: record.ServerID, TeamID: record.TeamID, MemberID: record.MemberID,
		SandboxID: record.Report.SandboxID, SandboxGeneration: record.Report.SandboxGeneration,
		ServiceRegistrationID: desired.Identity.ServiceRegistrationID, AllocationDigest: record.AllocationDigest,
		ConfigDigest: desired.ConfigDigest, RebindSelectionID: desired.Workspace.SelectionID,
	})
	if err != nil || project.Report.ProjectID != desired.Workspace.ProjectID ||
		project.Report.WorkspaceEpoch != desired.Workspace.WorkspaceEpoch {
		return workspacecatalog.RegisteredProject{}, errors.Join(err, workspacecatalog.ErrProjectChanged)
	}
	if project.Report.RootAttestation != desired.Workspace.RootAttestation {
		return workspacecatalog.RegisteredProject{}, errors.New("managed project was rebound; wait for the current catalog attestation")
	}
	return project, nil
}

func (r *Reconciler) reconcileManagedServiceInactive(ctx context.Context, desired model.ManagedServiceV1, project workspacecatalog.RegisteredProject, local *state.LocalManagedService) error {
	if err := r.cancelManagedWorkerExecution(ctx, desired.Identity.ServiceRegistrationID); err != nil {
		return r.failManagedService(ctx, desired, "worker_cancel_failed", err)
	}
	action := containers.ManagedSupervisorDrain
	expectedStatus := "drained"
	phase := desired.DesiredState
	if desired.DesiredState == "stopped" || desired.DesiredState == "retired" {
		action = containers.ManagedSupervisorStop
		expectedStatus = "stopped"
	}
	payload, _ := json.Marshal(map[string]any{"schemaVersion": 1, "sandboxId": desired.Identity.SandboxID, "instance": desired.Identity.Instance, "profileId": desired.Profile.ProfileID, "graceSeconds": 15})
	receipt, _, err := r.ManagedRuntime.ExecManagedSupervisor(ctx, desired.Identity.SandboxID, action, payload)
	if err != nil {
		return r.failManagedService(ctx, desired, "lifecycle_action_failed", err)
	}
	var lifecycleReceipt managedSupervisorReceipt
	err = decodeManagedSupervisorReceipt(receipt, &lifecycleReceipt)
	validStatus := lifecycleReceipt.SchemaVersion == 1 && lifecycleReceipt.Command == string(action) && lifecycleReceipt.Status == expectedStatus
	if action == containers.ManagedSupervisorStop && lifecycleReceipt.Status == "not_running" {
		validStatus = lifecycleReceipt.SchemaVersion == 1 && lifecycleReceipt.Command == string(action)
	}
	if err != nil || !validStatus {
		if err == nil {
			err = errors.New("managed lifecycle receipt did not acknowledge the requested state")
		}
		return r.failManagedService(ctx, desired, "invalid_lifecycle_receipt", err)
	}
	report := local.Report
	if report.FormatVersion != 1 {
		report = model.ManagedServiceReportV1{
			FormatVersion: 1, ConfigDigest: desired.ConfigDigest, Identity: desired.Identity,
			ServiceGeneration: desired.Identity.ExpectedServiceGeneration,
			ProfileStatus:     "ready", WorkspaceStatus: "ready", EnrollmentStatus: "failed",
			InstructionRevision: desired.Instructions.InstructionRevision,
			InstructionDigest:   desired.Instructions.InstructionDigest,
		}
	}
	report.OperationID, report.ActionRevision, report.ObservedDesiredRevision = desired.OperationID, desired.ActionRevision, desired.DesiredRevision
	report.ObservedState = phase
	report.Identity = desired.Identity
	report.LastError = nil
	if phase == "paused" {
		report.WorkerStatus = "paused"
	} else {
		report.WorkerStatus = "stopped"
	}
	report.ReceiptDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(receipt))
	if report.NativeRegistration != nil {
		source, err := r.Store.ContinuitySource(ctx, report.NativeRegistration.RegisteredSourceID)
		if err != nil {
			return err
		}
		if source != nil {
			reason := "service_" + phase
			source.Report.Availability = "unavailable"
			source.Report.Reason = &reason
			source.Report.LastObservedAt = r.now()
			source.Lifecycle = "stopped"
			source.LifecycleRevision = desired.ActionRevision
			if err := r.Store.PutContinuitySource(ctx, *source); err != nil {
				return err
			}
		}
	}
	_ = project
	return r.Store.UpdateManagedService(ctx, desired.Identity.ServiceRegistrationID, phase, &report, "")
}

func (r *Reconciler) runManagedWorkerBoundary(ctx context.Context, desired model.ManagedServiceV1) ([][]byte, error) {
	var receipts [][]byte
	actions := []containers.ManagedWorkerAction{containers.ManagedWorkerReconcile, containers.ManagedWorkerStatus}
	// Managers delegate broker work; only workers/reviewers may claim it.
	// Read-only status still proves that no task is active before publication.
	if desired.Identity.Role == "manager" || r.managedWorkerExecutionActive(desired.Identity.ServiceRegistrationID) {
		actions = []containers.ManagedWorkerAction{containers.ManagedWorkerStatus}
	}
	for _, action := range actions {
		request := map[string]any{
			"schemaVersion": 1, "command": string(action), "instance": desired.Identity.Instance,
			"root": "/home/agent", "allowInsecureLoopback": false, "requestTimeoutSeconds": 30,
		}
		payload, _ := json.Marshal(request)
		receiptJSON, _, err := r.ManagedRuntime.ExecManagedWorker(ctx, desired.Identity.SandboxID, action, payload)
		if err != nil {
			return receipts, err
		}
		receipt, err := validateManagedWorkerReceipt(receiptJSON, string(action))
		if err != nil {
			return receipts, err
		}
		if action == containers.ManagedWorkerStatus && receipt.Status != "ok" {
			return receipts, errors.New("managed worker status is unavailable")
		}
		if action == containers.ManagedWorkerStatus {
			if desired.Identity.Role == "manager" && receipt.Busy {
				return receipts, errors.New("manager has unexpected active broker work")
			}
			taskID, attempt, err := managedWorkerStatusAuthority(receipt)
			if err != nil {
				return receipts, errors.New("managed worker task authority is invalid")
			}
			if err := r.Store.PutManagedTaskAuthority(ctx, state.LocalManagedTaskAuthority{
				ServiceRegistrationID: desired.Identity.ServiceRegistrationID,
				ServiceGeneration:     desired.Identity.ExpectedServiceGeneration,
				SandboxGeneration:     desired.Identity.SandboxGeneration,
				TaskID:                taskID,
				TaskAttempt:           attempt,
				Busy:                  receipt.Busy,
				ObservedAt:            r.now(),
			}); err != nil {
				return receipts, err
			}
		}
		receipts = append(receipts, receiptJSON)
	}
	return receipts, nil
}

func managedWorkerStatusAuthority(receipt *managedWorkerReceipt) (*string, *int64, error) {
	// The packaged status producer carries current and latest task facts only in
	// activeTask. Top-level task fields belong to reconcile/execute receipts and
	// must never substitute authority on a status response.
	if receipt.TaskID != nil || receipt.Attempt != nil {
		return nil, nil, errors.New("status carried top-level task authority")
	}
	raw := bytes.TrimSpace(receipt.ActiveTask)
	if len(raw) == 0 {
		return nil, nil, errors.New("status omitted activeTask")
	}
	if bytes.Equal(raw, []byte("null")) {
		if receipt.Busy {
			return nil, nil, errors.New("busy status omitted active task")
		}
		return nil, nil, nil
	}
	var active managedWorkerActiveTask
	if err := decodeManagedReceipt(raw, &active, true); err != nil {
		return nil, nil, err
	}
	if !managedWorkerTaskPattern.MatchString(active.TaskID) ||
		active.Attempt != nil && *active.Attempt < 1 {
		return nil, nil, errors.New("status active task identity is invalid")
	}
	if receipt.Busy {
		if !managedWorkerActivePhases[active.Phase] || active.Attempt == nil {
			return nil, nil, errors.New("busy status active task is invalid")
		}
		taskID := active.TaskID
		attempt := *active.Attempt
		return &taskID, &attempt, nil
	}
	if !managedWorkerSettledPhases[active.Phase] {
		return nil, nil, errors.New("idle status carried active task")
	}
	// A latest settled marker is useful status metadata but grants no current
	// task authority. Persist the explicit idle observation with nil task refs.
	return nil, nil, nil
}

// preservedIdleBoundary keeps the last verified idle observation for the same
// live source. A managed-service lease renewal or an idle worker-loop restart is
// not an admitted execution, and clearing the flag there races the monitor
// policy apply out of its required safe boundary.
func preservedIdleBoundary(desired model.ManagedServiceV1, previous *state.LocalContinuitySource, nativeSessionID string) bool {
	if desired.Identity.Role == "manager" {
		return true
	}
	if previous == nil || !previous.NoAdmittedExecution {
		return false
	}
	return previous.Report.ServiceRegistrationID == desired.Identity.ServiceRegistrationID &&
		previous.Report.ServiceGeneration == desired.Identity.ExpectedServiceGeneration &&
		previous.Report.NativeSessionID == nativeSessionID
}

func (r *Reconciler) managedWorkerExecutionActive(serviceID string) bool {
	r.managedWorkerMu.Lock()
	defer r.managedWorkerMu.Unlock()
	return r.managedExecutions[serviceID] != nil
}

func (r *Reconciler) ensureManagedWorkerExecution(desired model.ManagedServiceV1, project workspacecatalog.RegisteredProject) *managedWorkerExecution {
	serviceID := desired.Identity.ServiceRegistrationID
	r.managedWorkerMu.Lock()
	if execution := r.managedExecutions[serviceID]; execution != nil {
		r.managedWorkerMu.Unlock()
		return execution
	}
	if r.managedExecutions == nil {
		r.managedExecutions = make(map[string]*managedWorkerExecution)
	}
	lifecycle := r.ManagedExecutionContext
	if lifecycle == nil {
		lifecycle = context.Background()
	}
	executionContext, cancel := context.WithTimeout(lifecycle, 35*time.Minute)
	execution := &managedWorkerExecution{cancel: cancel, done: make(chan struct{})}
	r.managedExecutions[serviceID] = execution
	r.managedWorkerMu.Unlock()

	request, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "command": string(containers.ManagedWorkerExecute), "instance": desired.Identity.Instance,
		"root": "/home/agent", "projectPath": project.ContainerRoot,
		"allowInsecureLoopback": false, "requestTimeoutSeconds": 30,
	})
	go func() {
		defer cancel()
		receiptJSON, _, err := r.ManagedRuntime.ExecManagedWorker(executionContext, desired.Identity.SandboxID, containers.ManagedWorkerExecute, request)
		idle := false
		if err == nil {
			if receipt, validateErr := validateManagedWorkerReceipt(receiptJSON, string(containers.ManagedWorkerExecute)); validateErr == nil {
				idle = receipt.Status == "idle"
			}
		}
		execution.mu.Lock()
		execution.idle = idle
		execution.mu.Unlock()
		close(execution.done)
		r.promoteIdleManagedExecution(context.Background(), desired, execution)
		r.managedWorkerMu.Lock()
		if r.managedExecutions[serviceID] == execution {
			delete(r.managedExecutions, serviceID)
		}
		r.managedWorkerMu.Unlock()
	}()
	return execution
}

// ScheduleContinuationHandoff starts the one targeted broker worker for an
// already projected separate-session baseline. The packaged worker reopens
// the private registration and performs the final consume-before-prompt fence.
func (r *Reconciler) ScheduleContinuationHandoff(
	ctx context.Context,
	operationID string,
	manifest model.ContinuationHandoffManifestV1,
	registration model.ContinuityRegistrationV1,
) error {
	if r.Store == nil || r.ManagedRuntime == nil || !managedSafeIDPattern.MatchString(operationID) || operationID != manifest.OperationID ||
		registration.Binding.RegisteredSourceID == "" || registration.Binding.ServiceRegistrationID != manifest.TargetPolicy.ServiceRegistrationID {
		return errors.New("invalid targeted continuation worker request")
	}
	service, err := r.Store.ManagedService(ctx, manifest.TargetPolicy.ServiceRegistrationID)
	if err != nil || service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" ||
		service.ServiceGeneration != manifest.TargetPolicy.ServiceGeneration ||
		service.Manifest.Identity.SandboxID != manifest.TargetPolicy.SandboxID ||
		service.Manifest.Identity.SandboxGeneration != manifest.TargetPolicy.SandboxGeneration ||
		service.Manifest.Identity.TeamID != manifest.TargetPolicy.TeamID ||
		service.Manifest.Identity.MemberID != manifest.TargetPolicy.MemberID ||
		service.Manifest.Identity.Role != manifest.TargetPolicy.Role ||
		service.Manifest.Profile.ProfileRevision != manifest.TargetPolicy.ProfileRevision ||
		service.Manifest.Profile.ProfileDigest != manifest.TargetPolicy.ProfileDigest ||
		service.Manifest.Instructions.InstructionRevision != manifest.TargetPolicy.InstructionRevision ||
		service.Manifest.Instructions.InstructionDigest != manifest.TargetPolicy.InstructionDigest {
		return errors.Join(err, errors.New("targeted worker service authority changed"))
	}
	stored, err := r.Store.ContinuityRegistration(ctx, registration.Binding.BindingID)
	if err != nil || stored == nil || stored.ObservedStatus != "verified" ||
		stored.ServiceGeneration != manifest.TargetPolicy.ServiceGeneration || !reflect.DeepEqual(stored.Manifest, registration) {
		return errors.Join(err, errors.New("targeted worker registration is not verified"))
	}
	projects, err := r.Store.ManagedProjects(ctx)
	if err != nil {
		return err
	}
	var project *state.LocalManagedProject
	for index := range projects {
		candidate := &projects[index]
		if candidate.Report.ProjectID == registration.Identity.ProjectID && candidate.Report.WorkspaceEpoch == registration.Identity.WorkspaceEpoch {
			if project != nil {
				return errors.New("targeted worker project authority is ambiguous")
			}
			project = candidate
		}
	}
	if project == nil || project.Phase != "ready" || project.Report.Availability != "available" ||
		project.Report.SandboxID != registration.Identity.SandboxID ||
		project.Report.SandboxGeneration != registration.Identity.SandboxGeneration {
		return errors.New("targeted worker project authority changed")
	}
	switch manifest.HandoffKind {
	case "reviewer":
		if project.Report.Designation != "continuity-handoff" || project.Report.ServiceRegistrationID == nil ||
			*project.Report.ServiceRegistrationID != manifest.TargetPolicy.ServiceRegistrationID {
			return errors.New("targeted worker project authority changed")
		}
	case "restored_target":
		if project.Report.Designation != "continuity-materialization" || project.Report.ServiceRegistrationID != nil {
			return errors.New("targeted worker project authority changed")
		}
	default:
		return errors.New("targeted worker handoff kind is invalid")
	}
	serviceID := manifest.TargetPolicy.ServiceRegistrationID
	r.managedWorkerMu.Lock()
	if r.managedExecutions != nil && r.managedExecutions[serviceID] != nil {
		r.managedWorkerMu.Unlock()
		return nil
	}
	if r.managedExecutions == nil {
		r.managedExecutions = make(map[string]*managedWorkerExecution)
	}
	lifecycle := r.ManagedExecutionContext
	if lifecycle == nil {
		lifecycle = context.Background()
	}
	executionContext, cancel := context.WithTimeout(lifecycle, 35*time.Minute)
	execution := &managedWorkerExecution{cancel: cancel, done: make(chan struct{})}
	r.managedExecutions[serviceID] = execution
	r.managedWorkerMu.Unlock()

	request, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "command": string(containers.ManagedWorkerExecute),
		"instance": service.Manifest.Identity.Instance, "root": "/home/agent",
		"projectPath": project.ContainerRoot, "continuationOperationId": operationID,
		"allowInsecureLoopback": false, "requestTimeoutSeconds": 30,
	})
	go func() {
		defer cancel()
		_, _, _ = r.ManagedRuntime.ExecManagedWorker(executionContext, manifest.TargetPolicy.SandboxID, containers.ManagedWorkerExecute, request)
		close(execution.done)
		r.managedWorkerMu.Lock()
		if r.managedExecutions[serviceID] == execution {
			delete(r.managedExecutions, serviceID)
		}
		r.managedWorkerMu.Unlock()
	}()
	return nil
}

func (r *Reconciler) cancelManagedWorkerExecution(ctx context.Context, serviceID string) error {
	r.managedWorkerMu.Lock()
	execution := r.managedExecutions[serviceID]
	r.managedWorkerMu.Unlock()
	if execution == nil {
		return nil
	}
	execution.cancel()
	select {
	case <-execution.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
		return errors.New("managed worker did not stop after cancellation")
	}
}

func (r *Reconciler) promoteIdleManagedExecution(ctx context.Context, desired model.ManagedServiceV1, execution *managedWorkerExecution) {
	select {
	case <-execution.done:
	default:
		return
	}
	execution.mu.Lock()
	idle := execution.idle
	execution.mu.Unlock()
	if !idle {
		return
	}
	sourceID := managedSourceID(desired.Identity.ServiceRegistrationID)
	source, err := r.Store.ContinuitySource(ctx, sourceID)
	if err != nil || source == nil || source.Report.ServiceGeneration != desired.Identity.ExpectedServiceGeneration ||
		source.Lifecycle != "running" || source.LifecycleRevision != desired.ActionRevision {
		return
	}
	_ = r.Store.MarkContinuitySourceIdle(ctx, *source)
}

func (r *Reconciler) recheckManagedAuthority(ctx context.Context, desired model.ManagedServiceV1, project workspacecatalog.RegisteredProject) error {
	sandbox, err := r.Store.Sandbox(ctx, desired.Identity.SandboxID)
	if err != nil || sandbox == nil || sandbox.ObservedState != "running" ||
		sandbox.ObservedGeneration != desired.Identity.SandboxGeneration {
		return errors.Join(err, errors.New("managed sandbox lifecycle changed"))
	}
	local, err := r.Store.ManagedService(ctx, desired.Identity.ServiceRegistrationID)
	if err != nil || local == nil || local.Manifest.ConfigDigest != desired.ConfigDigest ||
		local.Manifest.Identity != desired.Identity || local.Manifest.ActionRevision != desired.ActionRevision {
		return errors.Join(err, errors.New("managed service authority changed"))
	}
	resolved, err := r.ManagedCatalog.Resolve(ctx, workspacecatalog.ResolveProjectRequest{
		SelectionID: desired.Workspace.SelectionID, ProjectID: desired.Workspace.ProjectID,
		WorkspaceEpoch: desired.Workspace.WorkspaceEpoch, SandboxID: desired.Identity.SandboxID,
		SandboxGeneration:     desired.Identity.SandboxGeneration,
		ServiceRegistrationID: desired.Identity.ServiceRegistrationID, ConfigDigest: desired.ConfigDigest,
	})
	if err != nil || resolved.HostRoot != project.HostRoot || resolved.Report.RootAttestation != project.Report.RootAttestation {
		return errors.Join(err, errors.New("managed project authority changed"))
	}
	return nil
}

func (r *Reconciler) failManagedService(ctx context.Context, desired model.ManagedServiceV1, code string, cause error) error {
	digestPayload, _ := json.Marshal(struct {
		OperationID  string `json:"operationId"`
		Action       int64  `json:"actionRevision"`
		ConfigDigest string `json:"configDigest"`
		Code         string `json:"code"`
	}{desired.OperationID, desired.ActionRevision, desired.ConfigDigest, code})
	report := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: desired.OperationID, ActionRevision: desired.ActionRevision,
		ObservedDesiredRevision: desired.DesiredRevision, ConfigDigest: desired.ConfigDigest,
		ObservedState: "failed", Identity: desired.Identity,
		ServiceGeneration: desired.Identity.ExpectedServiceGeneration,
		ProfileStatus:     "ready", WorkspaceStatus: "ready", EnrollmentStatus: "failed", WorkerStatus: "failed",
		InstructionRevision: desired.Instructions.InstructionRevision,
		InstructionDigest:   desired.Instructions.InstructionDigest,
		ReceiptDigest:       fmt.Sprintf("sha256:%x", sha256.Sum256(digestPayload)),
		LastError:           &model.ManagedServiceErrorV1{Code: code},
	}
	var tombstoneErr error
	if previous, err := r.Store.ManagedService(ctx, desired.Identity.ServiceRegistrationID); err != nil {
		tombstoneErr = err
	} else if previous != nil && previous.Report.NativeRegistration != nil {
		if source, err := r.Store.ContinuitySource(ctx, previous.Report.NativeRegistration.RegisteredSourceID); err != nil {
			tombstoneErr = err
		} else if source != nil {
			reason := "service_failed"
			source.Report.Availability = "unavailable"
			source.Report.Reason = &reason
			source.Report.LastObservedAt = r.now()
			source.Lifecycle = "stopped"
			source.LifecycleRevision = desired.ActionRevision
			tombstoneErr = r.Store.PutContinuitySource(ctx, *source)
		}
	}
	updateErr := r.Store.UpdateManagedService(ctx, desired.Identity.ServiceRegistrationID, "failed", &report, code)
	return errors.Join(cause, tombstoneErr, updateErr)
}

func (r *Reconciler) progressManagedService(ctx context.Context, desired model.ManagedServiceV1, privateCode string, cause error) error {
	digestPayload, _ := json.Marshal(struct {
		OperationID  string `json:"operationId"`
		Action       int64  `json:"actionRevision"`
		ConfigDigest string `json:"configDigest"`
		Progress     string `json:"progress"`
	}{desired.OperationID, desired.ActionRevision, desired.ConfigDigest, "start_dispatched"})
	report := model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: desired.OperationID, ActionRevision: desired.ActionRevision,
		ObservedDesiredRevision: desired.DesiredRevision, ConfigDigest: desired.ConfigDigest,
		ObservedState: "registering", Identity: desired.Identity,
		ServiceGeneration: desired.Identity.ExpectedServiceGeneration,
		ProfileStatus:     "ready", WorkspaceStatus: "ready", EnrollmentStatus: "ready", WorkerStatus: "failed",
		InstructionRevision: desired.Instructions.InstructionRevision,
		InstructionDigest:   desired.Instructions.InstructionDigest,
		ReceiptDigest:       fmt.Sprintf("sha256:%x", sha256.Sum256(digestPayload)),
	}
	updateErr := r.Store.UpdateManagedService(ctx, desired.Identity.ServiceRegistrationID, "recovery_required", &report, privateCode)
	return errors.Join(cause, updateErr)
}

func validateManagedInstruction(content, digest string) bool {
	if content == "" || len([]byte(content)) > 32768 || !utf8.ValidString(content) || strings.ContainsRune(content, 0) {
		return false
	}
	return digest == fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(content)))
}

func validateManagedSupervisorReceipt(payload []byte, command, status string) (*managedSupervisorReceipt, error) {
	var receipt managedSupervisorReceipt
	if err := decodeManagedSupervisorReceipt(payload, &receipt); err != nil {
		return nil, err
	}
	if receipt.SchemaVersion != 1 || receipt.Command != command || receipt.Status != status {
		return nil, errors.New("managed supervisor receipt envelope is invalid")
	}
	return &receipt, nil
}

func validateManagedWorkerReceipt(payload []byte, command string) (*managedWorkerReceipt, error) {
	var receipt managedWorkerReceipt
	if err := decodeManagedReceipt(payload, &receipt, false); err != nil {
		return nil, err
	}
	validStatus := false
	switch command {
	case "status":
		validStatus = receipt.Status == "ok"
	case "reconcile", "execute":
		validStatus = receipt.Status == "idle" || receipt.Status == "deduped" ||
			receipt.Status == "reconciled" || receipt.Status == "message"
	}
	if receipt.SchemaVersion != 1 || receipt.Command != command || !validStatus {
		return nil, errors.New("managed worker receipt envelope is invalid")
	}
	return &receipt, nil
}

func decodeManagedReceipt(payload []byte, target any, strict bool) error {
	if len(payload) == 0 || len(payload) > 64*1024 {
		return errors.New("managed helper receipt size is invalid")
	}
	if err := rejectDuplicateJSONFields(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("managed helper receipt has trailing data")
	}
	return nil
}

func decodeManagedSupervisorReceipt(payload []byte, target any) error {
	if len(payload) == 0 || len(payload) > 64*1024 {
		return errors.New("managed helper receipt size is invalid")
	}
	if err := rejectDuplicateJSONFields(payload); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return err
	}
	for field := range fields {
		if !managedSupervisorReceiptFields[field] {
			return fmt.Errorf("managed supervisor receipt has unknown field %q", field)
		}
	}
	return json.Unmarshal(payload, target)
}

var managedSupervisorReceiptFields = func() map[string]bool {
	fields := []string{
		"schemaVersion", "command", "status", "phase", "instance", "sandboxId", "profileId", "profileDigest",
		"profileRevision", "version", "hostname", "port", "pid", "ready", "error", "upgradeError", "restored",
		"snapshotId", "writerVersion", "sweptProcesses", "activeSessions", "startCount", "state", "reason",
		"serverRunning", "binding", "observed", "install", "admission", "bindingRevision", "generation",
		"settingRevision", "sharingEnabled", "cleared", "checkedAt", "freshUntil", "ttlSeconds", "observation",
		"projection", "action", "applied", "drained", "restarted", "previousBindingRevision", "leaseId",
		"leaseTokenPresent", "leaseRole", "leaseOperations", "leaseExpiresAt", "leaseExpired", "secondsRemaining",
		"clockSkewSeconds", "endpointHost", "stored", "enrolledAt", "sessionId", "sessionCreated", "sessionReused",
		"sessionCreatedCount", "conversationCount", "sessionMode", "nativeProjectId", "nativeLocationDigest",
		"instructionRevision", "instructionDigest", "instructionApplied", "receiptDigest",
		"managerPluginDigest", "managerPluginLoaded", "managerProfile", "managerProviderId", "managerModelId",
		"managerNativeProtocol", "managerProviderRouteDigest", "managerRecommendAvailable", "managerCapabilityReason", "managerRecipeIds",
		"nativeGuard",
		"mappingId", "operationId", "registeredSourceId", "serviceGeneration", "serviceRegistrationId",
		"targetWorkId", "targetWorkspace", "workspaceEpoch",
	}
	allowed := make(map[string]bool, len(fields))
	for _, field := range fields {
		allowed[field] = true
	}
	return allowed
}()

func managedManagerCapability(desired model.ManagedServiceV1, sourceID string, start, status managedSupervisorReceipt) (state.LocalManagerCapability, error) {
	if start.ManagerPluginDigest == "" || !setupReceiptDigestPattern.MatchString(start.ManagerPluginDigest) || !start.ManagerPluginLoaded ||
		start.ManagerProfile.ProfileID != "warpmetal-insights-manager" || start.ManagerProfile.ProfileRevision < 1 ||
		!setupReceiptDigestPattern.MatchString(start.ManagerProfile.ProfileDigest) ||
		!setupReceiptDigestPattern.MatchString(start.ManagerProviderRouteDigest) ||
		len(start.ManagerRecipeIDs) == 0 || len(start.ManagerRecipeIDs) > 4 {
		return state.LocalManagerCapability{}, errors.New("managed supervisor omitted closed manager capability proof")
	}
	allowedProtocol := start.ManagerNativeProtocol == "" || start.ManagerNativeProtocol == "open_responses" ||
		start.ManagerNativeProtocol == "openai_chat" || start.ManagerNativeProtocol == "anthropic_messages" ||
		start.ManagerNativeProtocol == "google_generative_ai" || start.ManagerNativeProtocol == "bedrock_converse" ||
		start.ManagerNativeProtocol == "mistral_chat"
	if !allowedProtocol || start.ManagerRecommendAvailable &&
		(start.ManagerProviderID == "" || start.ManagerModelID == "" || start.ManagerNativeProtocol == "") {
		return state.LocalManagerCapability{}, errors.New("managed supervisor reported invalid manager route capability")
	}
	if start.NativeGuard != nil {
		guard := start.NativeGuard
		if guard.GuardVersion != "warpmetal.atomic-input.v1" || guard.CustomVersion == "" || guard.SourceRevision == "" ||
			guard.PatchDigest == "" || guard.ArtifactSHA256 == "" || guard.BinarySHA256 == "" {
			return state.LocalManagerCapability{}, errors.New("managed supervisor reported invalid native guard")
		}
	}
	if authority, modelID, _, ok := completeManagedServiceAuthority(desired); ok &&
		(start.ManagerProviderID != authority.ProviderID || start.ManagerModelID != normalizedManagedModelID(authority.ProviderID, modelID)) {
		return state.LocalManagerCapability{}, errors.New("managed supervisor manager route changed the requested authority")
	}
	startCapability := struct {
		PluginDigest                                     string
		PluginLoaded                                     bool
		Profile                                          model.InsightsManagerProfileV1
		ProviderID, ModelID, NativeProtocol, RouteDigest string
		Available                                        bool
		Reason                                           *string
		Recipes                                          string
		Guard                                            *model.NativeGuardObservationV1
	}{start.ManagerPluginDigest, start.ManagerPluginLoaded, start.ManagerProfile, start.ManagerProviderID, start.ManagerModelID,
		start.ManagerNativeProtocol, start.ManagerProviderRouteDigest, start.ManagerRecommendAvailable, start.ManagerCapabilityReason,
		strings.Join(start.ManagerRecipeIDs, "\x00"), start.NativeGuard}
	statusCapability := struct {
		PluginDigest                                     string
		PluginLoaded                                     bool
		Profile                                          model.InsightsManagerProfileV1
		ProviderID, ModelID, NativeProtocol, RouteDigest string
		Available                                        bool
		Reason                                           *string
		Recipes                                          string
		Guard                                            *model.NativeGuardObservationV1
	}{status.ManagerPluginDigest, status.ManagerPluginLoaded, status.ManagerProfile, status.ManagerProviderID, status.ManagerModelID,
		status.ManagerNativeProtocol, status.ManagerProviderRouteDigest, status.ManagerRecommendAvailable, status.ManagerCapabilityReason,
		strings.Join(status.ManagerRecipeIDs, "\x00"), status.NativeGuard}
	if !reflect.DeepEqual(startCapability, statusCapability) {
		return state.LocalManagerCapability{}, errors.New("managed supervisor manager capability changed between ready probes")
	}
	allowedRecipes := map[string]bool{"inspect_first_failure@1": true, "check_repeated_operation@1": true, "refine_query@1": true, "inspect_active_phase@1": true}
	seen := map[string]bool{}
	for _, recipe := range start.ManagerRecipeIDs {
		if !allowedRecipes[recipe] || seen[recipe] {
			return state.LocalManagerCapability{}, errors.New("managed supervisor reported unsupported manager recipe")
		}
		seen[recipe] = true
	}
	reason := ""
	if start.ManagerCapabilityReason != nil {
		reason = *start.ManagerCapabilityReason
	}
	if start.ManagerRecommendAvailable && reason != "" || !start.ManagerRecommendAvailable && reason == "" {
		return state.LocalManagerCapability{}, errors.New("managed supervisor manager availability proof is inconsistent")
	}
	return state.LocalManagerCapability{
		RegisteredSourceID: sourceID, ServiceRegistrationID: desired.Identity.ServiceRegistrationID,
		ServiceGeneration: desired.Identity.ExpectedServiceGeneration, WorkspaceEpoch: desired.Workspace.WorkspaceEpoch,
		NativeSessionID: start.SessionID, SandboxID: desired.Identity.SandboxID, SandboxGeneration: desired.Identity.SandboxGeneration,
		ProfileRevision: desired.Profile.ProfileRevision, InstructionRevision: desired.Instructions.InstructionRevision,
		NativeVersion: start.Version, NativeSourceRevision: "08462140ec0de1e4b17d4a353d8d5827f53cf7b0", Protocol: "opencode-supervisor/1",
		NativeProtocol: start.ManagerNativeProtocol, ProviderID: start.ManagerProviderID, ModelID: start.ManagerModelID,
		ProviderRouteDigest: start.ManagerProviderRouteDigest, RecipeIDs: append([]string(nil), start.ManagerRecipeIDs...),
		ManagerPluginDigest: start.ManagerPluginDigest, ManagerProfile: start.ManagerProfile, NativeGuard: start.NativeGuard,
		MaxInputTokens: 8000, MaxOutputTokens: 1000, FinalRequestMaxBytes: 7000,
		ToolsAllowed: false, MediaAllowed: false, HardOutputTokenLimit: true,
		Available: start.ManagerRecommendAvailable, Reason: reason,
	}, nil
}

func digestManagedReceipts(enroll, start []byte, worker [][]byte) string {
	hash := sha256.New()
	for _, payload := range append([][]byte{enroll, start}, worker...) {
		var length [8]byte
		for index := range length {
			length[7-index] = byte(uint64(len(payload)) >> (index * 8))
		}
		hash.Write(length[:])
		hash.Write(payload)
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}

func managedSourceID(serviceID string) string {
	if strings.HasPrefix(serviceID, "service_") {
		return "source_" + strings.TrimPrefix(serviceID, "service_")
	}
	digest := sha256.Sum256([]byte(serviceID))
	return fmt.Sprintf("source_%x", digest[:12])
}
