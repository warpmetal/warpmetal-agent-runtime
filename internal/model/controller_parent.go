package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// ControllerParentIntent consumes only the manager-frozen parentServiceIntent
// definition (Q37 a427d2cb...). It is neither a Team member nor a delegated cell.
type ControllerParentIntent struct {
	FormatVersion            int                          `json:"formatVersion"`
	TargetKind               string                       `json:"targetKind"`
	OperationID              string                       `json:"operationId"`
	ActionRevision           int64                        `json:"actionRevision"`
	DesiredRevision          int64                        `json:"desiredRevision"`
	ConfigDigest             string                       `json:"configDigest"`
	DesiredState             string                       `json:"desiredState"`
	SessionMode              string                       `json:"sessionMode"`
	Owner                    ControllerOwner              `json:"owner"`
	Role                     string                       `json:"role"`
	ServiceRegistrationID    string                       `json:"serviceRegistrationId"`
	ServiceGeneration        int64                        `json:"serviceGeneration"`
	Instance                 string                       `json:"instance"`
	Profile                  ManagedServiceProfileV1      `json:"profile"`
	Instructions             ManagedServiceInstructionsV1 `json:"instructions"`
	Workspace                ManagedServiceWorkspaceV1    `json:"workspace"`
	ApplicationOperationID   string                       `json:"applicationOperationId"`
	ConnectionRevisionDigest string                       `json:"connectionRevisionDigest"`
	ModelAuthorityDigest     string                       `json:"modelAuthorityDigest"`
	RoleAgentDigest          string                       `json:"roleAgentDigest"`
	RuntimeContractVersion   string                       `json:"runtimeContractVersion"`
}

type ControllerOwner struct {
	AccountID          string `json:"accountId"`
	TaskID             string `json:"taskId"`
	ServerID           string `json:"serverId"`
	SandboxID          string `json:"sandboxId"`
	SandboxGeneration  int64  `json:"sandboxGeneration"`
	CellID             string `json:"cellId"`
	ControllerID       string `json:"controllerId"`
	ControllerRevision int64  `json:"controllerRevision"`
	AuthorityRevision  int64  `json:"authorityRevision"`
}

func (owner ControllerOwner) valid() bool {
	for _, id := range []string{owner.AccountID, owner.TaskID, owner.ServerID, owner.SandboxID, owner.CellID, owner.ControllerID} {
		if !cellV3SafeIDPattern.MatchString(id) {
			return false
		}
	}
	for _, revision := range []int64{owner.SandboxGeneration, owner.ControllerRevision, owner.AuthorityRevision} {
		if revision < 1 || revision > 9007199254740991 {
			return false
		}
	}
	return true
}

// UnmarshalJSON rejects absent/null fields as well as unknown/duplicate ones.
// Authentication and current root/application authority are separate consumers.
func (entry *ControllerParentIntent) UnmarshalJSON(raw []byte) error {
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	type wire ControllerParentIntent
	var decoded wire
	if err := decodeStrictCellJSON(raw, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	t := reflect.TypeOf(decoded)
	if len(fields) != t.NumField() {
		return errors.New("incomplete controller parent intent")
	}
	for i := 0; i < t.NumField(); i++ {
		if value, ok := fields[t.Field(i).Tag.Get("json")]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("missing controller parent pin")
		}
	}
	result := ControllerParentIntent(decoded)
	if err := result.Validate(); err != nil {
		return err
	}
	*entry = result
	return nil
}

func (entry ControllerParentIntent) Validate() error {
	invalid := errors.New("invalid controller parent intent")
	if entry.FormatVersion != 2 || entry.TargetKind != "controller_parent" || entry.RuntimeContractVersion != "0.1.52" ||
		(entry.Role != "manager" && entry.Role != "orchestrator") || !entry.Owner.valid() {
		return invalid
	}
	for _, id := range []string{entry.OperationID, entry.ServiceRegistrationID, entry.ApplicationOperationID, entry.Profile.SetupOperationID,
		entry.Profile.ProfileID, entry.Workspace.SelectionID, entry.Workspace.ProjectID, entry.Workspace.WorkspaceEpoch} {
		if !cellV3SafeIDPattern.MatchString(id) {
			return invalid
		}
	}
	for _, revision := range []int64{entry.ActionRevision, entry.DesiredRevision, entry.ServiceGeneration, entry.Profile.ProfileRevision,
		entry.Instructions.InstructionRevision, entry.Workspace.ScopeRevision} {
		if revision < 1 || revision > 9007199254740991 {
			return invalid
		}
	}
	for _, digest := range []string{entry.ConfigDigest, entry.Profile.ProfileDigest, entry.Instructions.InstructionDigest, entry.Workspace.RootAttestation,
		entry.ConnectionRevisionDigest, entry.ModelAuthorityDigest, entry.RoleAgentDigest} {
		if !setupDigestPattern.MatchString(digest) {
			return invalid
		}
	}
	expectedInstance := fmt.Sprintf("parent-%s-%x", entry.Role, sha256.Sum256([]byte(entry.ServiceRegistrationID)))
	expectedInstance = expectedInstance[:len("parent-"+entry.Role+"-")+12]
	if entry.Instance != expectedInstance || entry.Workspace.Designation != "team_project" ||
		(entry.DesiredState != "active" && entry.DesiredState != "paused" && entry.DesiredState != "stopped" && entry.DesiredState != "retired") ||
		(entry.SessionMode != "create_initial" && entry.SessionMode != "lookup_only") {
		return invalid
	}
	// Maps are sorted by the same canonical encoder used for V3 authority. All
	// parent fields are ASCII bounded identifiers/digests/integers, never text.
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	delete(value, "configDigest")
	digest, err := canonicalSHA256(value)
	if err != nil || digest != entry.ConfigDigest {
		return errors.New("controller parent config digest mismatch")
	}
	return nil
}

type ControllerRoleReadback struct {
	Role            string  `json:"role"`
	NativeAgentID   string  `json:"nativeAgentId"`
	SessionAgentID  string  `json:"sessionAgentId"`
	ParentSessionID *string `json:"parentSessionId"`
	RoleAgentDigest string  `json:"roleAgentDigest"`
}

func (readback *ControllerRoleReadback) UnmarshalJSON(raw []byte) error {
	type wire ControllerRoleReadback
	var decoded wire
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	if err := decodeStrictCellJSON(raw, &decoded); err != nil {
		return err
	}
	if err := requiredApplicationFields(raw, reflect.TypeOf(decoded)); err != nil {
		return err
	}
	*readback = ControllerRoleReadback(decoded)
	return nil
}

type ControllerParentReport struct {
	FormatVersion           int                          `json:"formatVersion"`
	TargetKind              string                       `json:"targetKind"`
	OperationID             string                       `json:"operationId"`
	ActionRevision          int64                        `json:"actionRevision"`
	ObservedDesiredRevision int64                        `json:"observedDesiredRevision"`
	ConfigDigest            string                       `json:"configDigest"`
	ObservedState           string                       `json:"observedState"`
	Owner                   ControllerOwner              `json:"owner"`
	Role                    string                       `json:"role"`
	ServiceRegistrationID   string                       `json:"serviceRegistrationId"`
	ServiceGeneration       int64                        `json:"serviceGeneration"`
	ProfileStatus           string                       `json:"profileStatus"`
	WorkspaceStatus         string                       `json:"workspaceStatus"`
	InstructionApplied      bool                         `json:"instructionApplied"`
	InstructionRevision     int64                        `json:"instructionRevision"`
	InstructionDigest       string                       `json:"instructionDigest"`
	NativeRegistration      *ManagedNativeRegistrationV1 `json:"nativeRegistration"`
	NativeRoleReadback      *ControllerRoleReadback      `json:"nativeRoleReadback"`
	ReceiptDigest           string                       `json:"receiptDigest"`
	LastError               *ManagedServiceErrorV1       `json:"lastError"`
}

func (entry ControllerParentIntent) PendingReport() (ControllerParentReport, error) {
	report := ControllerParentReport{FormatVersion: 2, TargetKind: "controller_parent", OperationID: entry.OperationID,
		ActionRevision: entry.ActionRevision, ObservedDesiredRevision: entry.DesiredRevision, ConfigDigest: entry.ConfigDigest,
		ObservedState: "pending", Owner: entry.Owner, Role: entry.Role, ServiceRegistrationID: entry.ServiceRegistrationID,
		ServiceGeneration: entry.ServiceGeneration, ProfileStatus: "pending", WorkspaceStatus: "pending",
		InstructionRevision: entry.Instructions.InstructionRevision, InstructionDigest: entry.Instructions.InstructionDigest,
		LastError: &ManagedServiceErrorV1{Code: "dependency_pending"}}
	err := report.Seal()
	return report, err
}

func (report *ControllerParentReport) Seal() error {
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	delete(value, "receiptDigest")
	report.ReceiptDigest = WorkspaceDigest(value)
	if report.ReceiptDigest == "" {
		return errors.New("invalid parent report digest")
	}
	return nil
}

func (report ControllerParentReport) ValidateReady(parent ControllerParentIntent) error {
	sealed := report
	if sealed.Seal() != nil || sealed.ReceiptDigest != report.ReceiptDigest {
		return errors.New("parent report digest conflict")
	}
	if report.FormatVersion != 2 || report.TargetKind != "controller_parent" || report.OperationID != parent.OperationID || report.ActionRevision != parent.ActionRevision || report.ObservedDesiredRevision != parent.DesiredRevision || report.ConfigDigest != parent.ConfigDigest || report.Owner != parent.Owner || report.Role != parent.Role || report.ServiceRegistrationID != parent.ServiceRegistrationID || report.ServiceGeneration != parent.ServiceGeneration || report.ObservedState != "ready" || report.ProfileStatus != "ready" || report.WorkspaceStatus != "ready" || !report.InstructionApplied || report.InstructionRevision != parent.Instructions.InstructionRevision || report.InstructionDigest != parent.Instructions.InstructionDigest || report.LastError != nil || report.NativeRegistration == nil || report.NativeRoleReadback == nil {
		return errors.New("parent current ready report conflict")
	}
	n, r := report.NativeRegistration, report.NativeRoleReadback
	if !cellV3SafeIDPattern.MatchString(n.RegisteredSourceID) || n.WorkspaceEpoch != parent.Workspace.WorkspaceEpoch || !cellNativeSessionIDPattern.MatchString(n.NativeSessionID) || !cellNativeProjectPattern.MatchString(n.NativeProjectID) || !setupDigestPattern.MatchString(n.NativeLocationDigest) || r.Role != parent.Role || r.NativeAgentID != "warpmetal-controller-"+parent.Role || r.SessionAgentID != r.NativeAgentID || r.ParentSessionID != nil || r.RoleAgentDigest != parent.RoleAgentDigest {
		return errors.New("parent native identity conflict")
	}
	return nil
}

func decodeManagedServiceEntries(raw json.RawMessage) ([]ManagedServiceV1, []ControllerParentIntent, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil, nil
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return nil, nil, err
	}
	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err != nil {
		return nil, nil, err
	}
	var legacy []ManagedServiceV1
	var parents []ControllerParentIntent
	for _, raw := range elements {
		var tag struct {
			FormatVersion int `json:"formatVersion"`
		}
		if err := json.Unmarshal(raw, &tag); err != nil {
			return nil, nil, err
		}
		switch tag.FormatVersion {
		case 1:
			var entry ManagedServiceV1
			if err := decodeStrictCellJSON(raw, &entry); err != nil {
				return nil, nil, err
			}
			legacy = append(legacy, entry)
		case 2:
			var entry ControllerParentIntent
			if err := json.Unmarshal(raw, &entry); err != nil {
				return nil, nil, err
			}
			parents = append(parents, entry)
		default:
			return nil, nil, errors.New("unsupported managedServices discriminator")
		}
	}
	return legacy, parents, nil
}
