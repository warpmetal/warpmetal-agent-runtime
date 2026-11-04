package model

import (
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

const ControllerWM8Normalization = "opencode-wm8-controller-v1"

// DeriveWM8NativeIdentity is a deterministic projection, never an authority or
// native observation. The complete application identity remains unchanged.
func (application ControllerIdentity) DeriveWM8NativeIdentity() (ControllerIdentity, error) {
	var empty ControllerIdentity
	raw, err := json.Marshal(application)
	if err != nil || workflowcontract.Validate(workflowcontract.ControllerProvider, "applicationIdentity", raw) != nil || application.Intent.Validate() != nil {
		return empty, errors.New("invalid application controller identity")
	}
	i, p, s := application.Intent, application.Projection, application.Source
	expected := ControllerSourceIdentity{
		AccountID: i.Owner.AccountID, TaskID: i.Owner.TaskID, ServerID: i.Owner.ServerID,
		SandboxID: i.Owner.SandboxID, SandboxGeneration: i.Owner.SandboxGeneration,
		CellID: i.Owner.CellID, ControllerID: i.Owner.ControllerID,
		ControllerRevision: i.Owner.ControllerRevision, AuthorityRevision: i.Owner.AuthorityRevision,
		ServiceRegistrationID: i.ServiceRegistrationID, ServiceGeneration: i.ServiceGeneration,
		Instance: i.Instance, Role: i.Role, ProjectID: i.Workspace.ProjectID,
		WorkspaceEpoch: i.Workspace.WorkspaceEpoch, ProfileID: i.Profile.ProfileID,
		ProfileRevision: i.Profile.ProfileRevision, ProfileDigest: i.Profile.ProfileDigest,
		InstructionRevision: i.Instructions.InstructionRevision, InstructionDigest: i.Instructions.InstructionDigest,
	}
	if s.FormatVersion != 2 || s.Identity != expected || WorkspaceDigest(p) != i.RoleAgentDigest || p.NativeAgentID != "warpmetal-controller-"+i.Role || p.SystemDigest != i.Instructions.InstructionDigest || !p.ApprovedProfile.valid() || !p.ToolsDisabled || !p.MCPDisabled {
		return empty, errors.New("application controller identity join refused")
	}
	native := application
	native.Projection.ToolClosureDigest = ""
	approved := p.ApprovedProfile
	native.Intent.Profile.ProfileID = approved.ProfileID
	native.Intent.Profile.ProfileRevision = approved.ProfileRevision
	native.Intent.Profile.ProfileDigest = approved.ProfileDigest
	native.Intent.RoleAgentDigest = WorkspaceDigest(native.Projection)
	raw, err = json.Marshal(native.Intent)
	var fields map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &fields) != nil {
		return empty, errors.New("native controller identity encoding failed")
	}
	delete(fields, "configDigest")
	native.Intent.ConfigDigest = WorkspaceDigest(fields)
	native.Source.Identity.ProfileID = approved.ProfileID
	native.Source.Identity.ProfileRevision = approved.ProfileRevision
	native.Source.Identity.ProfileDigest = approved.ProfileDigest
	return native, nil
}

type ControllerApplicationReference struct {
	OperationID     string `json:"operationId"`
	OperationDigest string `json:"operationDigest"`
	ApplicationID   string `json:"applicationId"`
	ReceiptDigest   string `json:"receiptDigest"`
}
type ControllerMaterializerAssociation struct {
	DeclaredDigest  string `json:"declaredDigest"`
	InstalledDigest string `json:"installedDigest"`
	ClosureVersion  string `json:"closureVersion"`
}
type ControllerIdentityAssociation struct {
	FormatVersion             int                               `json:"formatVersion"`
	Normalization             string                            `json:"normalization"`
	Application               ControllerApplicationReference    `json:"application"`
	Materializer              ControllerMaterializerAssociation `json:"materializer"`
	ApplicationIdentity       ControllerIdentity                `json:"applicationIdentity"`
	ApplicationIdentityDigest string                            `json:"applicationIdentityDigest"`
	NativeIdentity            ControllerIdentity                `json:"nativeIdentity"`
	NativeIdentityDigest      string                            `json:"nativeIdentityDigest"`
	AssociationDigest         string                            `json:"associationDigest"`
}

// ValidateIntegrity verifies the closed pair and exact derivation. It does not
// establish that its application, materializer or native binding is current.
func (a ControllerIdentityAssociation) ValidateIntegrity() error {
	raw, err := json.Marshal(a)
	if err != nil || workflowcontract.Validate(workflowcontract.ControllerProvider, "controllerIdentityAssociation1", raw) != nil {
		return errors.New("controller identity association wire refused")
	}
	native, err := a.ApplicationIdentity.DeriveWM8NativeIdentity()
	var fields map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &fields) != nil || !reflect.DeepEqual(native, a.NativeIdentity) || a.ApplicationIdentityDigest != WorkspaceDigest(a.ApplicationIdentity) || a.NativeIdentityDigest != WorkspaceDigest(a.NativeIdentity) {
		return errors.New("controller identity association derivation refused")
	}
	delete(fields, "associationDigest")
	if a.AssociationDigest != WorkspaceDigest(fields) || a.Application.OperationID != a.ApplicationIdentity.Intent.ApplicationOperationID {
		return errors.New("controller identity association digest refused")
	}
	return nil
}

// ValidateAccepted joins independently retained application bytes and observed
// native binding. The caller must obtain installedDigest through the protected
// installed materializer/adoption check, never from this signed association.
func (a ControllerIdentityAssociation) ValidateAccepted(op WorkspaceApplicationOperation, applicationID, receiptDigest, installedDigest string, observedNative ControllerIdentity) error {
	if a.ValidateIntegrity() != nil || a.Application != (ControllerApplicationReference{op.OperationID, op.OperationDigest, applicationID, receiptDigest}) || a.Materializer.DeclaredDigest != op.MaterializerDigest || a.Materializer.InstalledDigest != installedDigest || !reflect.DeepEqual(a.NativeIdentity, observedNative) {
		return errors.New("controller identity association current witness refused")
	}
	role, err := op.ParentDependency(a.ApplicationIdentity.Intent)
	if err != nil || !reflect.DeepEqual(role.Projection, a.ApplicationIdentity.Projection) || op.Dependencies.ToolClosure == nil || a.ApplicationIdentity.Projection.ToolClosureDigest != WorkspaceDigest(op.Dependencies.ToolClosure) {
		return errors.New("controller identity association application closure refused")
	}
	return nil
}
