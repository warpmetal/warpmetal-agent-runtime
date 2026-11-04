package model

import (
	"errors"
	"regexp"
	"strings"
)

// CellExecutionContractVersion is the NEW supervisor capability that first
// advertises SA4 cell execution. The prior 0.1.46 supervisor contract MUST NOT
// claim cell support: cell reconcile is gated on exactly this capability.
const CellExecutionContractVersion = "0.1.47"

// SupportsCellExecution reports whether the given supervisor runtime contract
// version advertises cell execution. Deliberately an exact match so an older
// 0.1.46 contract never silently inherits cell support.
func SupportsCellExecution(contractVersion string) bool {
	return contractVersion == CellExecutionContractVersion
}

// ManagedServiceV2Profile is the cell entry profile sub-object.
type ManagedServiceV2Profile struct {
	SetupOperationID string `json:"setupOperationId"`
	ProfileID        string `json:"profileId"`
	ProfileRevision  int64  `json:"profileRevision"`
	ProfileDigest    string `json:"profileDigest"`
}

// ManagedServiceV2Authority is the cell entry authority sub-object. It carries
// only the non-secret provider/model/auth tuple, exactly as the frozen producer
// emits it (no TeamRevision).
type ManagedServiceV2Authority struct {
	ProviderID string  `json:"providerId"`
	ModelID    *string `json:"modelId"`
	AuthMode   *string `json:"authMode"`
}

// ManagerLaunchBinding returns the exact non-secret provider/model/auth-mode
// tuple a cell's managed manager session must be bound to before launch. All
// three are required: the supervisor's retained 0.1.52 start request has no
// binding field, so a manager started without this tuple falls back to the
// default provider route and cannot read or accept a product wake. Absence or
// an incomplete tuple is therefore an error, never an implicit default.
// ModelID is normalized to the bare native model id (a leading "<provider>/"
// is stripped exactly once, matching the supervisor's request validator).
func (authority *ManagedServiceV2Authority) ManagerLaunchBinding() (providerID, modelID, authMode string, err error) {
	if authority == nil {
		return "", "", "", errors.New("cell manager authority binding is absent")
	}
	providerID = authority.ProviderID
	if !providerIDPattern.MatchString(providerID) {
		return "", "", "", errors.New("cell manager authority provider is invalid")
	}
	if authority.ModelID == nil {
		return "", "", "", errors.New("cell manager authority model is absent")
	}
	modelID = strings.TrimPrefix(*authority.ModelID, providerID+"/")
	if modelID == "" || !modelIDPattern.MatchString(modelID) {
		return "", "", "", errors.New("cell manager authority model is invalid")
	}
	if authority.AuthMode == nil {
		return "", "", "", errors.New("cell manager authority auth mode is absent")
	}
	authMode = *authority.AuthMode
	if authMode != "api_key" && authMode != "chatgpt_subscription" {
		return "", "", "", errors.New("cell manager authority auth mode is invalid")
	}
	return providerID, modelID, authMode, nil
}

// ManagedServiceV2Workspace is the exact permitted source/worktree/ordinary-dir
// contract the Runtime must materialize and bind BEFORE any prompt. It names the
// backend-attested selection/project/epoch/root so the Runtime never invents a
// repository, Git metadata or a legacy Team workspace path.
type ManagedServiceV2Workspace struct {
	SelectionID     string `json:"selectionId"`
	ProjectID       string `json:"projectId"`
	WorkspaceEpoch  string `json:"workspaceEpoch"`
	ScopeRevision   int64  `json:"scopeRevision"`
	RootAttestation string `json:"rootAttestation"`
}

// ManagedServiceV2Instructions is the cell entry's pinned effective instruction
// tuple. The Runtime fetches the content through the authenticated instruction
// endpoint and verifies it against this exact tuple; it never invents a prompt
// locally.
type ManagedServiceV2Instructions struct {
	InstructionRevision int64  `json:"instructionRevision"`
	InstructionDigest   string `json:"instructionDigest"`
}

// ManagedServiceV2 is one formatVersion 2 cell-owned service entry from the
// frozen backend managed_services.cell_manifest_entries wire. It matches that
// object exactly: it is owned by a cell, carries no memberId/teamId, and is
// decoded, validated and reconciled separately from the byte-compatible
// formatVersion 1 member ManagedServiceV1. Attempt is the authoritative,
// immutable execution attempt fixed at admit time; the Runtime echoes it
// verbatim and never derives it from a local retry counter.
type ManagedServiceV2 struct {
	FormatVersion int    `json:"formatVersion"`
	TargetKind    string `json:"targetKind"`
	OperationID   string `json:"operationId"`
	// LaunchOperationID is the launch operation (the backend cell execution's
	// launch_operation_id). The durable service lineage uses OperationID
	// (op_managed_<launch>); the trusted adapter derives the deterministic child
	// native ids and correlates its receipt from LaunchOperationID, so the two
	// are deliberately distinct.
	LaunchOperationID     string                       `json:"launchOperationId"`
	ActionRevision        int64                        `json:"actionRevision"`
	DesiredRevision       int64                        `json:"desiredRevision"`
	DesiredState          string                       `json:"desiredState"`
	SessionMode           string                       `json:"sessionMode"`
	ServiceRegistrationID string                       `json:"serviceRegistrationId"`
	OwnerCellID           string                       `json:"ownerCellId"`
	OwnerRole             string                       `json:"ownerRole"`
	OwnerGeneration       int64                        `json:"ownerGeneration"`
	SandboxID             string                       `json:"sandboxId"`
	SandboxGeneration     int64                        `json:"sandboxGeneration"`
	ServiceGeneration     int64                        `json:"serviceGeneration"`
	ConfigDigest          string                       `json:"configDigest"`
	Fence                 string                       `json:"fence"`
	Attempt               int64                        `json:"attempt"`
	Instance              string                       `json:"instance"`
	Role                  string                       `json:"role"`
	NativeSessionID       string                       `json:"nativeSessionId"`
	NativeProjectID       string                       `json:"nativeProjectId"`
	WorkspaceEpoch        string                       `json:"workspaceEpoch"`
	Workspace             ManagedServiceV2Workspace    `json:"workspace"`
	Instructions          ManagedServiceV2Instructions `json:"instructions"`
	Profile               ManagedServiceV2Profile      `json:"profile"`
	Authority             *ManagedServiceV2Authority   `json:"authority,omitempty"`
}

// ManagedCellChildV1 is the exact re-verified child identity returned by the
// trusted cell adapter. Exhausted is the durable exhaustion marker.
type ManagedCellChildV1 struct {
	OperationID string  `json:"operationId"`
	SessionID   string  `json:"sessionId"`
	MessageID   string  `json:"messageId"`
	State       string  `json:"state"`
	Attempt     int64   `json:"attempt"`
	Outcome     *string `json:"outcome,omitempty"`
	Exhausted   bool    `json:"exhausted"`
}

// CellServiceReportV1 is the current-authority cell report. ObservedState is
// ready (ordinary terminal completion), exhausted (unknown effects, never an
// ordinary terminal), unknown (no terminal yet / lost effect) or failed.
// On the V3 report path, ready with a pending/running child proves native
// admission only; STATE settles work only for a correlated terminal child.
type CellServiceReportV1 struct {
	FormatVersion           int                    `json:"formatVersion"`
	OperationID             string                 `json:"operationId"`
	ActionRevision          int64                  `json:"actionRevision"`
	ObservedDesiredRevision int64                  `json:"observedDesiredRevision"`
	ServiceRegistrationID   string                 `json:"serviceRegistrationId"`
	ObservedState           string                 `json:"observedState"`
	DesiredState            string                 `json:"desiredState"`
	OwnerCellID             string                 `json:"ownerCellId"`
	OwnerRole               string                 `json:"ownerRole"`
	OwnerGeneration         int64                  `json:"ownerGeneration"`
	SandboxID               string                 `json:"sandboxId"`
	SandboxGeneration       int64                  `json:"sandboxGeneration"`
	ServiceGeneration       int64                  `json:"serviceGeneration"`
	Fence                   string                 `json:"fence"`
	Instance                string                 `json:"instance"`
	Role                    string                 `json:"role"`
	NativeSessionID         string                 `json:"nativeSessionId"`
	NativeProjectID         string                 `json:"nativeProjectId"`
	WorkspaceEpoch          string                 `json:"workspaceEpoch"`
	Attempt                 int64                  `json:"attempt"`
	Child                   *ManagedCellChildV1    `json:"child,omitempty"`
	Exhausted               bool                   `json:"exhausted"`
	ReceiptDigest           string                 `json:"receiptDigest"`
	LastError               *ManagedServiceErrorV1 `json:"lastError,omitempty"`
}

var cellNativeSessionIDPattern = regexp.MustCompile(`^ses_[A-Za-z0-9_-]{4,64}$`)
var cellNativeProjectPattern = regexp.MustCompile(`^(global|[a-f0-9]{40})$`)
var cellFencePattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ValidCellNativeSessionID reports whether value has the native session id
// shape the trusted cell adapter accepts. It is used for identities the
// Runtime resolves outside the manifest (the manager/supervisor session), so a
// malformed value is rejected before it can cross the adapter boundary.
func ValidCellNativeSessionID(value string) bool {
	return cellNativeSessionIDPattern.MatchString(value)
}

func validCellFence(fence string) bool { return cellFencePattern.MatchString(fence) }

var validCellAdapterStates = map[string]bool{
	"absent": true, "bound": true, "pending": true, "running": true,
	"uncertain": true, "terminal": true, "exhausted": true,
}

var validCellTerminalOutcomes = map[string]bool{
	"succeeded": true, "failed": true, "interrupted": true,
}

// ValidCellAdapterState reports whether state is in the closed child vocabulary.
func ValidCellAdapterState(state string) bool { return validCellAdapterStates[state] }

// ValidCellTerminalOutcome reports whether outcome is an ordinary terminal idle.
func ValidCellTerminalOutcome(outcome string) bool { return validCellTerminalOutcomes[outcome] }

// ValidateManagedServiceV2 validates one formatVersion 2 cell entry against the
// current sandbox generation and the ready profile setup operation it names.
func ValidateManagedServiceV2(entry ManagedServiceV2, sandboxGeneration int64, sandboxExists bool, profile *SetupOperation) error {
	if entry.FormatVersion != 2 || entry.TargetKind != "cell_session" {
		return errInvalidCellEntry("cell entry envelope is invalid")
	}
	if !continuityIDPattern.MatchString(entry.OperationID) || entry.ActionRevision < 1 || entry.DesiredRevision < 1 ||
		!setupDigestPattern.MatchString(entry.Profile.ProfileDigest) {
		return errInvalidCellEntry("cell entry revision or digest is invalid")
	}
	if entry.ServiceGeneration < 1 || entry.Attempt < 1 || !validCellFence(entry.Fence) {
		return errInvalidCellEntry("cell entry service generation, attempt or fence is invalid")
	}
	if entry.DesiredState != "active" && entry.DesiredState != "paused" &&
		entry.DesiredState != "stopped" && entry.DesiredState != "retired" {
		return errInvalidCellEntry("cell entry desired state is invalid")
	}
	if entry.SessionMode != "create_initial" && entry.SessionMode != "lookup_only" {
		return errInvalidCellEntry("cell entry session mode is invalid")
	}
	if !continuityIDPattern.MatchString(entry.ServiceRegistrationID) {
		return errInvalidCellEntry("cell entry service registration is invalid")
	}
	if !continuityIDPattern.MatchString(entry.OwnerCellID) ||
		(entry.OwnerRole != "manager" && entry.OwnerRole != "orchestrator") ||
		entry.OwnerGeneration < 1 {
		return errInvalidCellEntry("cell entry owner authority is invalid")
	}
	if !continuityIDPattern.MatchString(entry.LaunchOperationID) {
		return errInvalidCellEntry("cell entry launch operation is invalid")
	}
	if !continuityIDPattern.MatchString(entry.Instance) ||
		(entry.Role != "worker" && entry.Role != "reviewer") {
		return errInvalidCellEntry("cell entry instance or role is invalid")
	}
	if !sandboxExists || sandboxGeneration != entry.SandboxGeneration {
		return errInvalidCellEntry("cell entry sandbox generation is not current")
	}
	if !cellNativeSessionIDPattern.MatchString(entry.NativeSessionID) ||
		!cellNativeProjectPattern.MatchString(entry.NativeProjectID) ||
		!continuityIDPattern.MatchString(entry.WorkspaceEpoch) {
		return errInvalidCellEntry("cell entry native identity is invalid")
	}
	if !continuityIDPattern.MatchString(entry.Workspace.SelectionID) ||
		!continuityIDPattern.MatchString(entry.Workspace.ProjectID) ||
		!continuityIDPattern.MatchString(entry.Workspace.WorkspaceEpoch) ||
		entry.Workspace.ScopeRevision < 1 ||
		!setupDigestPattern.MatchString(entry.Workspace.RootAttestation) {
		return errInvalidCellEntry("cell entry workspace contract is invalid")
	}
	if entry.Instructions.InstructionRevision < 1 ||
		!setupDigestPattern.MatchString(entry.Instructions.InstructionDigest) {
		return errInvalidCellEntry("cell entry instruction tuple is invalid")
	}
	validAuthority := true
	if authority := entry.Authority; authority != nil {
		validModel := authority.ModelID == nil || modelIDPattern.MatchString(*authority.ModelID)
		validAuthMode := authority.AuthMode == nil || *authority.AuthMode == "api_key" || *authority.AuthMode == "chatgpt_subscription"
		validAuthority = providerIDPattern.MatchString(authority.ProviderID) && validModel && validAuthMode
	}
	if !validAuthority {
		return errInvalidCellEntry("cell entry authority is invalid")
	}
	if profile == nil || profile.SandboxID != entry.SandboxID ||
		profile.SandboxGeneration != entry.SandboxGeneration || profile.ProfileID != entry.Profile.ProfileID ||
		profile.ProfileRevision != entry.Profile.ProfileRevision || profile.ProfileDigest != entry.Profile.ProfileDigest {
		return errInvalidCellEntry("cell entry profile is not exactly ready")
	}
	return nil
}

type invalidCellEntryError string

func (e invalidCellEntryError) Error() string { return string(e) }

func errInvalidCellEntry(message string) error { return invalidCellEntryError(message) }
