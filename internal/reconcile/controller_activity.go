package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type controllerActivityControl interface {
	PrepareControllerActivity(context.Context, api.ControllerPreparationRequest) (api.ControllerPreparationResult, error)
	ControllerWorkflowContext(context.Context, string, string) (model.ControllerApprovedInputContext, error)
	ControllerCredential(context.Context, string) (api.ControllerCredential, error)
	SubmitControllerPreparedReceipt(context.Context, api.ControllerPreparedEnvelope) (model.ControllerPreparedReceipt, error)
	ReserveControllerActivity(context.Context, api.ControllerGrantEnvelope) (model.ControllerActivityGrant, error)
	AuthorizeControllerOutput(context.Context, model.ControllerOutputOperationRequest, string) (model.ControllerOutputOperation, error)
	ControllerOutputOperation(context.Context, string, string) (model.ControllerOutputOperation, error)
	SubmitControllerOutputAction(context.Context, model.ControllerOutputEnvelope, string) (json.RawMessage, error)
	ControllerActivationIntent(context.Context, string) (api.ControllerActivationSigningIntent, error)
	PublishControllerActivation(context.Context, api.ControllerActivationPublication) (api.ControllerActivationReceipt, error)
}
type controllerActivityRuntime interface {
	VerifyControllerPolicy(context.Context, model.Sandbox, string, qualification.ControllerPolicyWitness) (qualification.ControllerPolicy, error)
	ReadControllerActivation(context.Context, model.Sandbox, qualification.ControllerPolicy, model.ControllerPreparedReceipt, bool) (qualification.ControllerActivation, error)
	AttestControllerPrepared(context.Context, model.ControllerPreparedReceipt, qualification.ControllerOutputWitness) (model.ControllerPreparedEnvelope, error)
	AttestControllerOutput(context.Context, model.ControllerOutputOperation, qualification.ControllerCapture, qualification.ControllerOutputWitness) (model.ControllerOutputEnvelope, error)
	ObserveControllerAuthorization(context.Context, model.ControllerPreparedReceipt, qualification.ControllerOutputWitness) (model.ControllerAuthorizationEnvelope, error)
}

var ErrControllerActivityPending = errors.New("controller activity protected authority pending")

// Existing registered application/root/report boundaries; no node-supplied true
// assertion is accepted. Applicability comes from the approved installed case,
// not the model, and the signed store + actual container/binary consumers recheck it.
func (r *Reconciler) controllerActivityWitness(ctx context.Context, serviceID string, applicability qualification.Applicability) (qualification.ControllerOutputWitness, error) {
	return r.controllerActivityCurrentWitness(ctx, serviceID, applicability, true)
}

func (r *Reconciler) controllerActivityCurrentWitness(ctx context.Context, serviceID string, applicability qualification.Applicability, probe bool) (qualification.ControllerOutputWitness, error) {
	var w qualification.ControllerOutputWitness
	if r.Store == nil || r.ManagedCatalog == nil || r.ManagedRuntime == nil || r.ManagedControl == nil {
		return w, ErrControllerActivityPending
	}
	manifest := r.currentAuthorityManifest()
	var parent *model.ControllerParentIntent
	for i := range manifest.ParentServices {
		if manifest.ParentServices[i].ServiceRegistrationID == serviceID {
			parent = &manifest.ParentServices[i]
		}
	}
	if parent == nil || parent.DesiredState != "active" || parent.Owner.ServerID != r.ServerID {
		return w, ErrControllerActivityPending
	}
	local, e := r.Store.ControllerParent(ctx, serviceID)
	if e != nil {
		return w, e
	}
	if local == nil || local.Intent != *parent || local.Report.ValidateReady(*parent) != nil || local.AcceptedReceiptDigest == "" || local.AcceptedReceiptDigest != local.Report.ReceiptDigest {
		return w, ErrControllerActivityPending
	}
	app, e := r.Store.WorkspaceApplication(ctx, parent.ApplicationOperationID)
	if e != nil {
		return w, e
	}
	if app == nil || !app.Applied || app.ApplicationID == "" || len(app.EnvelopeJSON) == 0 || app.Operation.TargetRuntimeRevision != manifest.DesiredRevision {
		return w, ErrControllerActivityPending
	}
	var envelope model.WorkspaceApplicationEnvelope
	if json.Unmarshal(app.EnvelopeJSON, &envelope) != nil || envelope.Validate() != nil || envelope.Payload.OperationID != app.Operation.OperationID || envelope.Payload.OperationDigest != app.Operation.OperationDigest || !reflect.DeepEqual(envelope.Payload.NativeReceipt.Readback.Operation, app.Operation) {
		return w, ErrControllerActivityPending
	}
	var projection *model.ControllerRoleProjection
	for i := range app.Operation.Dependencies.Roles {
		role := &app.Operation.Dependencies.Roles[i]
		if role.Binding.ServiceRegistrationID == serviceID {
			projection = &role.Projection
		}
	}
	if projection == nil || projection.ModelSelection == nil || projection.ModelSelection.CredentialBinding == nil || !projection.ToolsDisabled || !projection.MCPDisabled {
		return w, ErrControllerActivityPending
	}
	project, e := r.resolveControllerProject(ctx, app.Operation, *parent)
	if e != nil {
		return w, e
	}
	for _, box := range manifest.Sandboxes {
		if box.ID == parent.Owner.SandboxID {
			w.Sandbox = box
		}
	}
	if w.Sandbox.ID == "" || w.Sandbox.Generation != parent.Owner.SandboxGeneration || w.Sandbox.DesiredState != "running" {
		return w, ErrControllerActivityPending
	}
	n := local.Report.NativeRegistration
	i := model.ControllerIdentity{Intent: *parent, Projection: *projection}
	i.Source.FormatVersion = 2
	ownerRaw, _ := json.Marshal(parent.Owner)
	var sourceIdentity map[string]any
	_ = json.Unmarshal(ownerRaw, &sourceIdentity)
	for k, v := range map[string]any{"serviceRegistrationId": serviceID, "serviceGeneration": parent.ServiceGeneration, "instance": parent.Instance, "role": parent.Role, "projectId": parent.Workspace.ProjectID, "workspaceEpoch": parent.Workspace.WorkspaceEpoch, "profileId": parent.Profile.ProfileID, "profileRevision": parent.Profile.ProfileRevision, "profileDigest": parent.Profile.ProfileDigest, "instructionRevision": parent.Instructions.InstructionRevision, "instructionDigest": parent.Instructions.InstructionDigest} {
		sourceIdentity[k] = v
	}
	identityRaw, _ := json.Marshal(sourceIdentity)
	if json.Unmarshal(identityRaw, &i.Source.Identity) != nil {
		return w, ErrControllerActivityPending
	}
	i.Source.Source.RegisteredSourceID = n.RegisteredSourceID
	i.Source.Source.NativeSessionID = n.NativeSessionID
	i.Source.Source.NativeProjectID = n.NativeProjectID
	i.Source.Source.NativeLocationDigest = n.NativeLocationDigest
	// Read-only history retains the acknowledged application-time observation.
	// Effect callers replace it with the independently checked current probe.
	workspaceMaterializer := envelope.Payload.NativeReceipt.Readback.MaterializerDigest
	if probe {
		request := parentRequest(*parent)
		request["probe"] = true
		observed, err := r.controllerHelper(ctx, *parent, containers.ManagedSupervisorStatus, request)
		if err != nil {
			return w, err
		}
		materializer, mErr := controllerMaterializer(app.Operation.MaterializerDigest)
		if mErr != nil {
			return w, state.ErrControllerActivityConflict
		}
		if validateParentNativeReceipt(*parent, observed, materializer) != nil || observed.SessionID != n.NativeSessionID || observed.NativeProjectID != n.NativeProjectID || observed.NativeLocationDigest != n.NativeLocationDigest {
			return w, state.ErrControllerActivityConflict
		}
		workspaceMaterializer = observed.MaterializerDigest
		var binding struct {
			Identity        model.ControllerIdentity         `json:"identity"`
			State           string                           `json:"state"`
			PreparedReceipt *model.ControllerPreparedReceipt `json:"preparedReceipt"`
		}
		var fields map[string]json.RawMessage
		expectedNative := i
		if i.Projection.ModelSelection.Authority == (model.CellPreparedAuthorityV3{ProviderID: providerpolicy.Flash().ProviderID, ModelID: providerpolicy.Flash().ModelID, AuthMode: providerpolicy.Flash().AuthMode}) {
			var err error
			expectedNative, err = i.DeriveWM8NativeIdentity()
			if err != nil {
				return w, state.ErrControllerActivityConflict
			}
		}
		if model.DecodePhysicalClosed(observed.Binding, &binding) != nil || json.Unmarshal(observed.Binding, &fields) != nil || len(fields) != 3 || fields["preparedReceipt"] == nil || !reflect.DeepEqual(binding.Identity, expectedNative) || (binding.State != "registered" && binding.State != "bound") || binding.State == "registered" && binding.PreparedReceipt != nil || binding.State == "bound" && (binding.PreparedReceipt == nil || binding.PreparedReceipt.PreparedTuple.ValidateControllerPolicyIdentity(expectedNative) != nil) {
			return w, state.ErrControllerActivityConflict
		}
	}
	w.Parent = qualification.WorkspaceApplicationWitness{Parent: *parent, Report: local.Report, Workspace: qualification.TrustedWorkspace{HostRoot: project.HostRoot, ContainerRoot: project.ContainerRoot, WorkspaceDigest: project.Report.RootAttestation, Device: project.RootDevice, Inode: project.RootInode}}
	w.Producer = app.Operation.Producer
	w.ApplicationOperation = app.Operation
	w.Installed = qualification.ControllerPolicyWitness{Applicability: applicability, Identity: i, Application: qualification.ControllerApplication{OperationID: app.Operation.OperationID, OperationDigest: app.Operation.OperationDigest, ApplicationID: app.ApplicationID, ReceiptDigest: model.WorkspaceDigest(envelope)}, ApplicationConfigurationDigest: app.Operation.ConfigurationDigest, WorkspaceMaterializerDigest: workspaceMaterializer}
	return w, nil
}
func exactControllerText(text, digest string) bool {
	return utf8.ValidString(text) && len(text) > 0 && len(text) <= 16384 && !strings.ContainsRune(text, 0) && fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(text))) == digest
}
func (r *Reconciler) controllerTransport(ctx context.Context, parent model.ControllerParentIntent, action containers.ManagedSupervisorAction, fields map[string]any, result any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	request := parentRequest(parent)
	for k, v := range fields {
		request[k] = v
	}
	raw, e := json.Marshal(request)
	if e != nil {
		return e
	}
	response, _, e := r.ManagedRuntime.ExecManagedSupervisor(ctx, parent.Owner.SandboxID, action, raw)
	if err := ctx.Err(); err != nil {
		return err
	}
	if e != nil {
		return e
	}
	return model.DecodeControllerTransportReceipt(response, string(action), result)
}

// Explicit protected caller, not a daemon scheduler/response loop. F1's context
// is fetched/retained before credential import and BEFORE input. No model text
// or consumer-selected target can create it. Missing F1 supplier stops this path.
func (r *Reconciler) PrepareControllerParentActivity(ctx context.Context, call api.ControllerPreparationRequest, applicability qualification.Applicability, text, workflowLease string) (model.ControllerPreparedReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prepareControllerParentActivityLocked(ctx, call, applicability, text, workflowLease)
}

// Reconcile owns r.mu already. All authority, credential and receipt gates remain
// in this SAME implementation; callers cannot bypass them through the lock split.
func (r *Reconciler) prepareControllerParentActivityLocked(ctx context.Context, call api.ControllerPreparationRequest, applicability qualification.Applicability, text, workflowLease string) (model.ControllerPreparedReceipt, error) {
	return r.prepareControllerParentDeclaredActivityLocked(ctx, call, applicability, text, workflowLease, nil)
}

func (r *Reconciler) prepareControllerParentDeclaredActivityLocked(ctx context.Context, call api.ControllerPreparationRequest, applicability qualification.Applicability, text, workflowLease string, declared *qualification.ControllerDeclaredInput) (model.ControllerPreparedReceipt, error) {
	var empty model.ControllerPreparedReceipt
	control, ok := r.ManagedControl.(controllerActivityControl)
	runtime, rok := r.ManagedRuntime.(controllerActivityRuntime)
	if !ok || !rok || r.Store == nil || workflowLease == "" || !exactControllerText(text, call.InputDigest) {
		return empty, ErrControllerActivityPending
	}
	w, e := r.controllerActivityWitness(ctx, call.ServiceRegistrationID, applicability)
	if e != nil {
		return empty, e
	}
	if !reflect.DeepEqual(w.Installed.Identity.Projection.ModelSelection, &call.ModelSelection) {
		return empty, ErrControllerActivityPending
	}
	prep, e := control.PrepareControllerActivity(ctx, call)
	if e != nil {
		return empty, e
	}
	if prep.PreparedTuple == nil {
		return empty, ErrControllerActivityPending
	}
	preparedRaw, _ := json.Marshal(prep.PreparedTuple)
	target := qualification.SourceTransportTarget{TargetKind: "controller_activity", PreparationID: prep.PreparationID, Phase: "prepare", TargetID: call.InputID, SourceID: call.ServiceRegistrationID, RequestDigest: model.WorkspaceDigest(call), PreparedTuple: preparedRaw, Scope: prep.PreparedTuple.Owner}
	selected, se := r.adoptSourceTransportTarget(ctx, w.Sandbox, r.currentAuthorityManifest(), target)
	if se != nil {
		return empty, se
	}
	if selected {
		// Retain verified prepare metadata before credentials/native binding.
		// The source-only policy/admission basis still waits the local grant wire.
		return empty, ErrSourceLocalGrantPending
	}
	if e = r.ensurePaidCaseDomain(ctx, r.currentAuthorityManifest()); e != nil {
		return empty, e
	}
	c, e := control.ControllerWorkflowContext(ctx, prep.PreparationID, workflowLease)
	if e != nil {
		return empty, e
	}
	if c.InputID != call.InputID || c.InputDigest != call.InputDigest || c.PreparationID != prep.PreparationID {
		return empty, ErrControllerActivityPending
	}
	if declared != nil && !declared.MatchesContext(c) {
		return empty, state.ErrControllerActivityConflict
	}
	w.ApprovedContext = c
	w.Policy, e = runtime.VerifyControllerPolicy(ctx, w.Sandbox, c.PolicyDigest, w.Installed)
	if e != nil {
		return empty, e
	}
	if w.Policy.ValidateContext(c) != nil || prep.PreparedTuple.ValidateControllerPolicyIdentity(w.Policy.NativeIdentity()) != nil || prep.PreparedTuple.ConfigurationDigest != w.ApplicationOperation.ConfigurationDigest {
		return empty, ErrControllerActivityPending
	}
	if w.Policy.FormatVersion == 6 && (prep.FormatVersion != 2 || prep.ApplicationConfigDigest != w.Policy.ApplicationIdentity().Intent.ConfigDigest || prep.ApplicationRoleAgentDigest != w.Policy.ApplicationIdentity().Intent.RoleAgentDigest || prep.IdentityAssociationDigest != w.Policy.IdentityAssociation.AssociationDigest) {
		return empty, state.ErrControllerActivityConflict
	}
	if w.Policy.FormatVersion == 6 {
		// Exact canonical body already read through the protected signature store;
		// its context digest addresses the retained signed snapshot. History alone
		// never replaces the current protected reader before any new effect.
		policyRaw, err := model.WorkspaceCanonicalJSON(w.Policy)
		if err != nil {
			return empty, err
		}
		if err = r.Store.PinControllerActivityStage(ctx, prep.PreparationID, state.ControllerPolicyVerified, policyRaw); err != nil {
			return empty, err
		}
	}
	installedRaw, _ := json.Marshal(w.Installed.Applicability)
	if e = r.Store.PinControllerActivityStage(ctx, prep.PreparationID, state.ControllerInstalledApplicability, installedRaw); e != nil {
		return empty, e
	}
	w.ApprovedInputText = text
	raw, _ := json.Marshal(controllerApprovedInput{Context: c, InputText: text})
	if e = r.Store.PinControllerActivityStage(ctx, prep.PreparationID, state.ControllerApprovedContext, raw); e != nil {
		return empty, e
	}
	prior, e := r.Store.ControllerActivityStage(ctx, prep.PreparationID, state.ControllerNativePrepared)
	if e != nil {
		return empty, e
	}
	var envelope model.ControllerPreparedEnvelope
	if len(prior) > 0 {
		if json.Unmarshal(prior, &envelope) != nil || !reflect.DeepEqual(envelope.Payload.PreparedTuple, *prep.PreparedTuple) {
			return empty, state.ErrControllerActivityConflict
		}
	} else {
		credential, e := control.ControllerCredential(ctx, prep.PreparationID)
		if e != nil {
			return empty, e
		}
		binding := w.Policy.Applicability.Connection
		if credential.ConnectionID != binding.ConnectionID || credential.ConnectionRevision != binding.ConnectionRevision || credential.ProviderID != binding.ProviderID || credential.AuthMode != binding.AuthMode {
			return empty, state.ErrControllerActivityConflict
		}
		var native struct {
			SchemaVersion   int                             `json:"schemaVersion"`
			Command         string                          `json:"command"`
			Status          string                          `json:"status"`
			PreparedReceipt model.ControllerPreparedReceipt `json:"preparedReceipt"`
		}
		e = r.controllerTransport(ctx, w.Parent.Parent, containers.ManagedSupervisorControllerPrepare, map[string]any{"preparationId": prep.PreparationID, "preparedTuple": prep.PreparedTuple, "credential": credential, "policyDigest": c.PolicyDigest}, &native)
		if e != nil {
			return empty, e
		}
		if native.SchemaVersion != 1 || native.Command != "controller-prepare" || native.Status != "prepared" || w.Policy.ValidatePreparedReceipt(native.PreparedReceipt) != nil || !reflect.DeepEqual(native.PreparedReceipt.PreparedTuple, *prep.PreparedTuple) {
			return empty, ErrControllerActivityPending
		}
		envelope, e = runtime.AttestControllerPrepared(ctx, native.PreparedReceipt, w)
		if e != nil {
			return empty, e
		}
		raw, _ = json.Marshal(envelope)
		if e = r.Store.PinControllerActivityStage(ctx, prep.PreparationID, state.ControllerNativePrepared, raw); e != nil {
			return empty, e
		}
	}
	if w.Policy.ValidatePreparedReceipt(envelope.Payload) != nil {
		return empty, state.ErrControllerActivityConflict
	}
	ack, e := control.SubmitControllerPreparedReceipt(ctx, envelope)
	if e != nil {
		return empty, e
	}
	if !reflect.DeepEqual(ack, envelope.Payload) {
		return empty, state.ErrControllerActivityConflict
	}
	if e = r.publishSourcePreparedProcess(ctx, r.currentAuthorityManifest(), target); e != nil {
		return empty, e
	}
	header, e := runtime.ObserveControllerAuthorization(ctx, ack, w)
	if e != nil {
		return empty, e
	}
	raw, _ = json.Marshal(header)
	if e = r.Store.PinControllerActivityStage(ctx, prep.PreparationID, state.ControllerHeaderObserved, raw); e != nil {
		return empty, e
	}
	return ack, nil
}

// Operator envelope comes from the EXISTING independently approved signing
// workflow. Reserve replays SAME backend ledger; native activity is impossible
// until both committed signed atomic activation members are read and joined.
func (r *Reconciler) AdmitControllerParentActivity(ctx context.Context, envelope model.ControllerGrantEnvelope, applicability qualification.Applicability, text, workflowLease string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.admitControllerParentActivityLocked(ctx, envelope, applicability, text, workflowLease)
}

func (r *Reconciler) admitControllerParentActivityLocked(ctx context.Context, envelope model.ControllerGrantEnvelope, applicability qualification.Applicability, text, workflowLease string) error {
	control, ok := r.ManagedControl.(controllerActivityControl)
	runtime, rok := r.ManagedRuntime.(controllerActivityRuntime)
	if !ok || !rok || r.Store == nil || workflowLease == "" {
		return ErrControllerActivityPending
	}
	id := envelope.Payload.PreparationID
	raw, e := r.Store.ControllerActivityStage(ctx, id, state.ControllerNativePrepared)
	if e != nil {
		return e
	}
	var prepared model.ControllerPreparedEnvelope
	if len(raw) == 0 || json.Unmarshal(raw, &prepared) != nil || !exactControllerText(text, prepared.Payload.PreparedTuple.InputDigest) {
		return ErrControllerActivityPending
	}
	c, e := control.ControllerWorkflowContext(ctx, id, workflowLease)
	if e != nil {
		return e
	}
	raw, e = json.Marshal(controllerApprovedInput{Context: c, InputText: text})
	if e != nil {
		return e
	}
	if e = r.Store.PinControllerActivityStage(ctx, id, state.ControllerApprovedContext, raw); e != nil {
		return e
	}
	w, e := r.controllerActivityWitness(ctx, prepared.Payload.PreparedTuple.ServiceRegistrationID, applicability)
	if e != nil {
		return e
	}
	w.ApprovedContext = c
	w.ApprovedInputText = text
	w.Policy, e = runtime.VerifyControllerPolicy(ctx, w.Sandbox, c.PolicyDigest, w.Installed)
	if e != nil {
		return e
	}
	if w.Policy.ValidateContext(c) != nil || w.Policy.ValidatePreparedReceipt(prepared.Payload) != nil || c.PreparationID != id || c.InputID != prepared.Payload.PreparedTuple.InputID || c.InputDigest != prepared.Payload.PreparedTuple.InputDigest {
		return ErrControllerActivityPending
	}
	if c.FormatVersion >= 2 && envelope.Payload.PhysicalIndex != c.PhysicalIndex {
		return ErrControllerActivityPending
	}
	g, e := control.ReserveControllerActivity(ctx, envelope)
	if e != nil {
		return e
	}
	if g != envelope.Payload {
		return state.ErrControllerActivityConflict
	}
	a, e := runtime.ReadControllerActivation(ctx, w.Sandbox, w.Policy, prepared.Payload, false)
	if e != nil {
		return e
	}
	if a.ValidateContext(w.Policy, c) != nil || a.Admission.Grant != g || a.GrantEnvelopeDigest != model.WorkspaceDigest(envelope) {
		return state.ErrControllerActivityConflict
	}
	raw, _ = json.Marshal(a)
	if e = r.Store.PinControllerActivityStage(ctx, id, state.ControllerActivated, raw); e != nil {
		return e
	}
	if e = r.Store.FenceControllerActivityPrompt(ctx, id); e != nil {
		return e
	}
	var native struct {
		SchemaVersion   int             `json:"schemaVersion"`
		Command         string          `json:"command"`
		Status          string          `json:"status"`
		NativeAdmission json.RawMessage `json:"nativeAdmission"`
	}
	if e = r.controllerTransport(ctx, w.Parent.Parent, containers.ManagedSupervisorControllerPrompt, map[string]any{"admission": a.Admission, "text": text}, &native); e != nil {
		return e
	}
	if native.SchemaVersion != 1 || native.Command != "controller-prompt" || native.Status != "admitted" {
		return ErrControllerActivityPending
	}
	// Preserve original owning started/input/process cut before the independent
	// native deadline can remove it. Capture failure does not retry the prompt or
	// replace FIRST admission, and a missing cut cannot later release OFFLINE.
	return r.sourceTerminalBeforeCancel(ctx, id)
}

type controllerApprovedInput struct {
	Context   model.ControllerApprovedInputContext `json:"context"`
	InputText string                               `json:"inputText"`
}

// One explicit settled readback/action, never a scheduler/model response loop.
func (r *Reconciler) CompleteControllerParentOutput(ctx context.Context, id string, applicability qualification.Applicability, workflowLease string) (json.RawMessage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.completeControllerParentOutputLocked(ctx, id, applicability, workflowLease)
}

func (r *Reconciler) completeControllerParentOutputLocked(ctx context.Context, id string, applicability qualification.Applicability, workflowLease string) (json.RawMessage, error) {
	control, ok := r.ManagedControl.(controllerActivityControl)
	runtime, rok := r.ManagedRuntime.(controllerActivityRuntime)
	if !ok || !rok || r.Store == nil || workflowLease == "" {
		return nil, ErrControllerActivityPending
	}
	raw, e := r.Store.ControllerActivityStage(ctx, id, state.ControllerNativePrepared)
	if e != nil {
		return nil, e
	}
	var prepared model.ControllerPreparedEnvelope
	if len(raw) == 0 || json.Unmarshal(raw, &prepared) != nil {
		return nil, ErrControllerActivityPending
	}
	raw, e = r.Store.ControllerActivityStage(ctx, id, state.ControllerApprovedContext)
	if e != nil {
		return nil, e
	}
	var retained controllerApprovedInput
	if json.Unmarshal(raw, &retained) != nil || !exactControllerText(retained.InputText, prepared.Payload.PreparedTuple.InputDigest) {
		return nil, ErrControllerActivityPending
	}
	c, e := control.ControllerWorkflowContext(ctx, id, workflowLease)
	if e != nil {
		return nil, e
	}
	if !reflect.DeepEqual(c, retained.Context) {
		return nil, state.ErrControllerActivityConflict
	}
	w, e := r.controllerActivityWitness(ctx, prepared.Payload.PreparedTuple.ServiceRegistrationID, applicability)
	if e != nil {
		return nil, e
	}
	w.ApprovedContext = c
	w.ApprovedInputText = retained.InputText
	w.Policy, e = runtime.VerifyControllerPolicy(ctx, w.Sandbox, c.PolicyDigest, w.Installed)
	if e != nil {
		return nil, e
	}
	if w.Policy.ValidatePreparedReceipt(prepared.Payload) != nil || w.Policy.ValidateContext(c) != nil {
		return nil, state.ErrControllerActivityConflict
	}
	w.Activation, e = runtime.ReadControllerActivation(ctx, w.Sandbox, w.Policy, prepared.Payload, true)
	if e != nil {
		return nil, e
	}
	capture, e := r.readControllerOwningCapture(ctx, w, retained.InputText)
	if e != nil {
		return nil, e
	}
	identity, _ := json.Marshal(w.Policy.NativeIdentity())
	lineage, e := capture.Verify(retained.InputText, identity, w.Activation.Admission)
	if e != nil {
		return nil, e
	}
	proposal, e := model.ControllerProposal(c, lineage.OutputText)
	if e != nil {
		return nil, e
	}
	prior, e := r.Store.ControllerActivityStage(ctx, id, state.ControllerOutputOperation)
	if e != nil {
		return nil, e
	}
	var operation model.ControllerOutputOperation
	if len(prior) > 0 {
		if json.Unmarshal(prior, &operation) != nil {
			return nil, state.ErrControllerActivityConflict
		}
		current, e := control.ControllerOutputOperation(ctx, operation.OperationID, workflowLease)
		if e != nil {
			return nil, e
		}
		if !reflect.DeepEqual(current, operation) {
			return nil, state.ErrControllerActivityConflict
		}
	} else {
		call := model.ControllerOutputOperationRequest{FormatVersion: c.FormatVersion, RequestID: "ctrlout_" + model.WorkspaceDigest(c.ContextID)[7:39], ContextID: c.ContextID, Lineage: lineage, Proposal: proposal}
		e = r.ownedContinuationOnce(ctx, id, "parent-output-operation", call, func() (any, error) { return control.AuthorizeControllerOutput(ctx, call, workflowLease) }, &operation)
		if e != nil {
			return nil, e
		}
		raw, _ = json.Marshal(operation)
		if e = r.Store.PinControllerActivityStage(ctx, id, state.ControllerOutputOperation, raw); e != nil {
			return nil, e
		}
	}
	if !reflect.DeepEqual(operation.Context, c) || !reflect.DeepEqual(operation.Lineage, lineage) || model.WorkspaceDigest(operation.Proposal) != model.WorkspaceDigest(proposal) {
		return nil, state.ErrControllerActivityConflict
	}
	// The root consumer re-verifies capture/operator/root/current pins even on
	// replay, then returns the original immutable envelope (never remints expiry).
	signed, e := runtime.AttestControllerOutput(ctx, operation, capture, w)
	if e != nil {
		return nil, e
	}
	raw, _ = json.Marshal(signed)
	if e = r.Store.PinControllerActivityStage(ctx, id, state.ControllerOutputEnvelope, raw); e != nil {
		return nil, e
	}
	var result json.RawMessage
	e = r.ownedContinuationOnce(ctx, id, "parent-output-action", signed, func() (any, error) { return control.SubmitControllerOutputAction(ctx, signed, workflowLease) }, &result)
	if e != nil {
		return nil, e
	}
	if e = r.Store.PinControllerActivityStage(ctx, id, state.ControllerActionReceipt, result); e != nil {
		return nil, e
	}
	return result, nil
}
