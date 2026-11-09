package reconcile

import (
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
)

// controllerApplicationIdentity builds the closed controller identity from the
// issued parent intent, the approved role projection and the observed native
// registration. It is the same deterministic projection the qualification
// association consumes; it is never signing/provider authority.
func controllerApplicationIdentity(parent model.ControllerParentIntent, projection model.ControllerRoleProjection, native model.ManagedNativeRegistrationV1) (model.ControllerIdentity, error) {
	var empty model.ControllerIdentity
	identity := model.ControllerIdentity{Intent: parent, Projection: projection}
	identity.Source.FormatVersion = 2
	ownerRaw, err := json.Marshal(parent.Owner)
	if err != nil {
		return empty, err
	}
	var sourceIdentity map[string]any
	if err := json.Unmarshal(ownerRaw, &sourceIdentity); err != nil {
		return empty, err
	}
	for key, value := range map[string]any{
		"serviceRegistrationId": parent.ServiceRegistrationID,
		"serviceGeneration":     parent.ServiceGeneration,
		"instance":              parent.Instance,
		"role":                  parent.Role,
		"projectId":             parent.Workspace.ProjectID,
		"workspaceEpoch":        parent.Workspace.WorkspaceEpoch,
		"profileId":             parent.Profile.ProfileID,
		"profileRevision":       parent.Profile.ProfileRevision,
		"profileDigest":         parent.Profile.ProfileDigest,
		"instructionRevision":   parent.Instructions.InstructionRevision,
		"instructionDigest":     parent.Instructions.InstructionDigest,
	} {
		sourceIdentity[key] = value
	}
	identityRaw, err := json.Marshal(sourceIdentity)
	if err != nil {
		return empty, err
	}
	if err := json.Unmarshal(identityRaw, &identity.Source.Identity); err != nil {
		return empty, err
	}
	identity.Source.Source.RegisteredSourceID = native.RegisteredSourceID
	identity.Source.Source.NativeSessionID = native.NativeSessionID
	identity.Source.Source.NativeProjectID = native.NativeProjectID
	identity.Source.Source.NativeLocationDigest = native.NativeLocationDigest
	return identity, nil
}

// controllerExpectedNativeIdentity is the identity the native sandbox must bind
// and return from its status probe: the DeepSeek Flash native derivation when
// the projection selects the pinned Flash authority, otherwise the unchanged
// application identity. Both Runtime and the controller join on this value.
func controllerExpectedNativeIdentity(identity model.ControllerIdentity) (model.ControllerIdentity, error) {
	if identity.Projection.ModelSelection == nil {
		return identity, nil
	}
	flash := providerpolicy.Flash()
	if identity.Projection.ModelSelection.Authority == (model.CellPreparedAuthorityV3{ProviderID: flash.ProviderID, ModelID: flash.ModelID, AuthMode: flash.AuthMode}) {
		return identity.DeriveWM8NativeIdentity()
	}
	return identity, nil
}

// addDeepSeekControllerIdentity adds the deepseek-only closed controllerIdentity
// field to one supervisor request. Every other profile keeps the byte-identical
// OpenCode request envelope: no field is added and no existing value changes.
func addDeepSeekControllerIdentity(request map[string]any, parent model.ControllerParentIntent, projection model.ControllerRoleProjection, native model.ManagedNativeRegistrationV1) error {
	if parent.Profile.ProfileID != "deepseek" {
		return nil
	}
	identity, err := controllerApplicationIdentity(parent, projection, native)
	if err != nil {
		return err
	}
	expected, err := controllerExpectedNativeIdentity(identity)
	if err != nil {
		return err
	}
	request["controllerIdentity"] = expected
	return nil
}

// controllerSourceRegistrationRequest builds the exact register-source request
// for one current controller parent. The DeepSeek transport additionally binds
// the full native controller identity; the OpenCode payload is unchanged.
func controllerSourceRegistrationRequest(parent model.ControllerParentIntent, projection model.ControllerRoleProjection, native model.ManagedNativeRegistrationV1) (map[string]any, error) {
	identity := map[string]any{"serverId": parent.Owner.ServerID, "accountId": parent.Owner.AccountID, "taskId": parent.Owner.TaskID, "sandboxId": parent.Owner.SandboxID, "sandboxGeneration": parent.Owner.SandboxGeneration, "cellId": parent.Owner.CellID, "controllerId": parent.Owner.ControllerID, "controllerRevision": parent.Owner.ControllerRevision, "authorityRevision": parent.Owner.AuthorityRevision, "serviceRegistrationId": parent.ServiceRegistrationID, "serviceGeneration": parent.ServiceGeneration, "instance": parent.Instance, "role": parent.Role, "projectId": parent.Workspace.ProjectID, "workspaceEpoch": parent.Workspace.WorkspaceEpoch, "profileId": parent.Profile.ProfileID, "profileRevision": parent.Profile.ProfileRevision, "profileDigest": parent.Profile.ProfileDigest, "instructionRevision": parent.Instructions.InstructionRevision, "instructionDigest": parent.Instructions.InstructionDigest}
	request := parentRequest(parent)
	request["registration"] = map[string]any{
		"formatVersion": 2,
		"identity":      identity,
		"source": map[string]any{
			"registeredSourceId":   native.RegisteredSourceID,
			"nativeSessionId":      native.NativeSessionID,
			"nativeProjectId":      native.NativeProjectID,
			"nativeLocationDigest": native.NativeLocationDigest,
		},
	}
	if err := addDeepSeekControllerIdentity(request, parent, projection, native); err != nil {
		return nil, err
	}
	return request, nil
}

// controllerStatusBinding validates the closed status.binding a native sandbox
// returns for the expected identity: exactly {identity,state,preparedReceipt},
// the identity is the current expected identity, and the state/receipt pair is
// coherent. The DeepSeek controller echoes the Runtime-supplied identity; the
// existing OpenCode native binding is validated by the same join.
func controllerStatusBinding(raw json.RawMessage, expectedNative model.ControllerIdentity) error {
	var binding struct {
		Identity        model.ControllerIdentity         `json:"identity"`
		State           string                           `json:"state"`
		PreparedReceipt *model.ControllerPreparedReceipt `json:"preparedReceipt"`
	}
	var fields map[string]json.RawMessage
	if len(raw) == 0 || model.DecodePhysicalClosed(raw, &binding) != nil || json.Unmarshal(raw, &fields) != nil ||
		len(fields) != 3 || fields["preparedReceipt"] == nil || !reflect.DeepEqual(binding.Identity, expectedNative) ||
		(binding.State != "registered" && binding.State != "bound") ||
		binding.State == "registered" && binding.PreparedReceipt != nil ||
		binding.State == "bound" && (binding.PreparedReceipt == nil || binding.PreparedReceipt.PreparedTuple.ValidateControllerPolicyIdentity(expectedNative) != nil) {
		return errors.New("controller status binding refused")
	}
	return nil
}
