package model

// Exact consumers of the unchanged controller admission definitions in F1's
// ONE producer schema and F2's immutable hook. Metadata is not activity authority.
import (
	"encoding/json"
	"errors"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"reflect"
)

type ControllerSourceIdentity struct {
	AccountID             string `json:"accountId"`
	TaskID                string `json:"taskId"`
	ServerID              string `json:"serverId"`
	SandboxID             string `json:"sandboxId"`
	SandboxGeneration     int64  `json:"sandboxGeneration"`
	CellID                string `json:"cellId"`
	ControllerID          string `json:"controllerId"`
	ControllerRevision    int64  `json:"controllerRevision"`
	AuthorityRevision     int64  `json:"authorityRevision"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
	ServiceGeneration     int64  `json:"serviceGeneration"`
	Instance              string `json:"instance"`
	Role                  string `json:"role"`
	ProjectID             string `json:"projectId"`
	WorkspaceEpoch        string `json:"workspaceEpoch"`
	ProfileID             string `json:"profileId"`
	ProfileRevision       int64  `json:"profileRevision"`
	ProfileDigest         string `json:"profileDigest"`
	InstructionRevision   int64  `json:"instructionRevision"`
	InstructionDigest     string `json:"instructionDigest"`
}
type ControllerSource struct {
	FormatVersion int                      `json:"formatVersion"`
	Identity      ControllerSourceIdentity `json:"identity"`
	Source        struct {
		RegisteredSourceID   string `json:"registeredSourceId"`
		NativeSessionID      string `json:"nativeSessionId"`
		NativeProjectID      string `json:"nativeProjectId"`
		NativeLocationDigest string `json:"nativeLocationDigest"`
	} `json:"source"`
}
type ControllerIdentity struct {
	Intent     ControllerParentIntent   `json:"intent"`
	Source     ControllerSource         `json:"source"`
	Projection ControllerRoleProjection `json:"projection"`
}
type ControllerPreparedTuple struct {
	Owner                 ControllerOwner             `json:"owner"`
	Role                  string                      `json:"role"`
	ServiceRegistrationID string                      `json:"serviceRegistrationId"`
	ServiceGeneration     int64                       `json:"serviceGeneration"`
	NativeRegistration    ManagedNativeRegistrationV1 `json:"nativeRegistration"`
	RoleAgentDigest       string                      `json:"roleAgentDigest"`
	ConfigurationDigest   string                      `json:"configurationDigest"`
	ConfigDigest          string                      `json:"configDigest"`
	InputID               string                      `json:"inputId"`
	InputDigest           string                      `json:"inputDigest"`
	Authority             CellPreparedAuthorityV3     `json:"authority"`
	CredentialBinding     CellCredentialBindingV3     `json:"credentialBinding"`
}
type ControllerPreparedReceipt struct {
	FormatVersion         int                     `json:"formatVersion"`
	TargetKind            string                  `json:"targetKind"`
	PreparationID         string                  `json:"preparationId"`
	PreparedTuple         ControllerPreparedTuple `json:"preparedTuple"`
	CredentialID          string                  `json:"credentialId"`
	NativeCredentialID    string                  `json:"nativeCredentialId"`
	BindingDigest         string                  `json:"bindingDigest"`
	PreparedReceiptDigest string                  `json:"preparedReceiptDigest"`
}
type ControllerActivityGrant struct {
	FormatVersion         int    `json:"formatVersion"`
	TargetKind            string `json:"targetKind"`
	GrantID               string `json:"grantId"`
	PreparationID         string `json:"preparationId"`
	PreparedReceiptDigest string `json:"preparedReceiptDigest"`
	ReservationID         string `json:"reservationId"`
	CaseID                string `json:"caseId"`
	CaseManifestDigest    string `json:"caseManifestDigest"`
	PolicyDigest          string `json:"policyDigest"`
	RequestIndex          int    `json:"requestIndex"`
	PhysicalIndex         int    `json:"physicalIndex"`
	MaxInputTokens        int    `json:"maxInputTokens"`
	MaxOutputTokens       int    `json:"maxOutputTokens"`
	MaxUSDMicros          int64  `json:"maxUsdMicros"`
	DeadlineAt            string `json:"deadlineAt"`
	ExpiresAt             string `json:"expiresAt"`
}
type ControllerAdmission struct {
	FormatVersion   int                       `json:"formatVersion"`
	TargetKind      string                    `json:"targetKind"`
	PreparedReceipt ControllerPreparedReceipt `json:"preparedReceipt"`
	Grant           ControllerActivityGrant   `json:"grant"`
}
type ControllerActivity struct {
	Admission           ControllerAdmission `json:"admission"`
	InputID             string              `json:"inputID"`
	InputSeq            int64               `json:"inputSeq"`
	ExecutionStartedSeq int64               `json:"executionStartedSeq"`
}

func (t ControllerPreparedTuple) ValidateControllerPolicyIdentity(i ControllerIdentity) error {
	selected := i.Projection.ModelSelection
	if i.Intent.Validate() != nil || selected == nil || selected.CredentialBinding == nil ||
		t.Owner != i.Intent.Owner || t.Role != i.Intent.Role || t.ServiceRegistrationID != i.Intent.ServiceRegistrationID || t.ServiceGeneration != i.Intent.ServiceGeneration ||
		t.RoleAgentDigest != i.Intent.RoleAgentDigest || t.ConfigDigest != i.Intent.ConfigDigest || t.Authority != selected.Authority || t.CredentialBinding != *selected.CredentialBinding ||
		t.NativeRegistration.RegisteredSourceID != i.Source.Source.RegisteredSourceID || t.NativeRegistration.NativeSessionID != i.Source.Source.NativeSessionID ||
		t.NativeRegistration.NativeProjectID != i.Source.Source.NativeProjectID || t.NativeRegistration.NativeLocationDigest != i.Source.Source.NativeLocationDigest || t.NativeRegistration.WorkspaceEpoch != i.Intent.Workspace.WorkspaceEpoch {
		return errors.New("controller prepared identity mismatch")
	}
	return nil
}

type ControllerPreparedEnvelope struct {
	Payload   ControllerPreparedReceipt `json:"payload"`
	KeyID     string                    `json:"keyId"`
	Signature string                    `json:"signature"`
}
type ControllerGrantEnvelope struct {
	Payload   ControllerActivityGrant `json:"payload"`
	KeyID     string                  `json:"keyId"`
	Signature string                  `json:"signature"`
}

func (r ControllerPreparedReceipt) Validate() error {
	if err := r.validateWire(); err != nil {
		return err
	}
	if r.PreparedTuple.Authority != (CellPreparedAuthorityV3{ProviderID: "openai", ModelID: "gpt-4.1-mini-2025-04-14", AuthMode: "api_key"}) {
		return errors.New("controller executable model denied")
	}
	return nil
}

// ValidateProvider checks native facts against one selected immutable provider
// policy. Callers still own signed policy/current witness/grant validation.
func (r ControllerPreparedReceipt) ValidateProvider(policyDigest string) error {
	p := providerpolicy.Flash()
	if policyDigest != providerpolicy.FlashDigest || r.validateWire() != nil || r.PreparedTuple.Authority != (CellPreparedAuthorityV3{ProviderID: p.ProviderID, ModelID: p.ModelID, AuthMode: p.AuthMode}) {
		return errors.New("controller provider receipt denied")
	}
	return nil
}

// Wire identity is not executable policy. Actual F2 normalization fixtures keep
// their own exact model; all executable consumers must still call Validate.
func (r ControllerPreparedReceipt) validateWire() error {
	t := r.PreparedTuple
	if r.FormatVersion != 1 || r.TargetKind != "controller_activity" || !t.Owner.valid() ||
		(t.Role != "manager" && t.Role != "orchestrator") || t.ServiceGeneration < 1 ||
		t.CredentialBinding.Validate() != nil || (t.Authority.ProviderID != "openai" && !(t.Authority.ProviderID == providerpolicy.Flash().ProviderID && t.Authority.ModelID == providerpolicy.Flash().ModelID)) ||
		t.Authority.ModelID == "" || t.Authority.AuthMode != "api_key" ||
		t.CredentialBinding.ProviderID != t.Authority.ProviderID || t.CredentialBinding.AuthMode != t.Authority.AuthMode {
		return errors.New("invalid controller receipt")
	}
	for _, id := range []string{r.PreparationID, r.CredentialID, r.NativeCredentialID, t.ServiceRegistrationID, t.InputID, t.NativeRegistration.RegisteredSourceID, t.NativeRegistration.WorkspaceEpoch} {
		if !cellV3SafeIDPattern.MatchString(id) {
			return errors.New("invalid controller receipt identity")
		}
	}
	for _, d := range []string{t.RoleAgentDigest, t.ConfigurationDigest, t.ConfigDigest, t.InputDigest, t.NativeRegistration.NativeLocationDigest} {
		if !setupDigestPattern.MatchString(d) {
			return errors.New("invalid controller receipt pin")
		}
	}
	if !cellNativeSessionIDPattern.MatchString(t.NativeRegistration.NativeSessionID) || !cellNativeProjectPattern.MatchString(t.NativeRegistration.NativeProjectID) {
		return errors.New("invalid controller native identity")
	}
	binding := map[string]any{"preparationId": r.PreparationID, "preparedTuple": t, "credentialId": r.CredentialID, "nativeCredentialId": r.NativeCredentialID}
	if WorkspaceDigest(binding) != r.BindingDigest {
		return errors.New("controller binding digest mismatch")
	}
	binding["bindingDigest"] = r.BindingDigest
	if WorkspaceDigest(binding) != r.PreparedReceiptDigest {
		return errors.New("controller prepared receipt digest mismatch")
	}
	return nil
}

func (r *ControllerPreparedReceipt) UnmarshalJSON(raw []byte) error {
	type wire ControllerPreparedReceipt
	var value wire
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	if err := decodeStrictCellJSON(raw, &value); err != nil {
		return err
	}
	if err := requiredApplicationFields(raw, reflect.TypeOf(value)); err != nil {
		return err
	}
	*r = ControllerPreparedReceipt(value)
	return r.validateWire()
}

// DecodeControllerAdmission requires the complete closed shape, including zero
// sequence/index fields. Eligibility/signatures/expiry belong to qualification.
func DecodeControllerAdmission(raw []byte) (ControllerAdmission, error) {
	var value ControllerAdmission
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return value, err
	}
	if err := decodeStrictCellJSON(raw, &value); err != nil {
		return value, err
	}
	if err := requiredApplicationFields(json.RawMessage(raw), reflect.TypeOf(value)); err != nil {
		return value, err
	}
	if value.FormatVersion != 1 || value.TargetKind != "controller_activity" {
		return value, errors.New("invalid controller admission")
	}
	return value, value.PreparedReceipt.Validate()
}
