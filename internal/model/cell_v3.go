package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// CellLifecycleFormatVersion is the formatVersion of the frozen backend
// cell-lifecycle-v3 wire (backend/contracts/cell-lifecycle-v3.schema.json,
// including the required preparedTuple.authority revision frozen in §17.15).
// It preserves the complete formatVersion 2 cell identity tuple and adds the
// prepare/execute discriminated lifecycle phase, the account-owned
// credentialBinding, the node-authenticated preparedReceiptDigest and the
// backend-issued executionGrant. Retained formatVersion 2 rows have no
// conversion and no v3 fallback route.
const CellLifecycleFormatVersion = 3

// cellV3SafeIDPattern is the frozen schema safeId contract. It deliberately
// differs from the legacy continuityIDPattern by permitting "." and ":" so the
// v3 wire is decoded exactly as the schema declares it; retained v2 validation
// keeps using continuityIDPattern unchanged.
var (
	cellV3SafeIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	cellV3ProviderIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)
	cellV3RawDigestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// deriveNativeIDs is the canonical backend derivation
// (agent_manager/cell_service.py:derive_native_ids): base32(sha256(utf8(op)))
// without padding, prefixed ses_/msg_. The child session and input are always
// derived from the LAUNCH operation, never from the managed-service operation.
func deriveNativeIDs(operationID string) (sessionID, inputID string) {
	sum := sha256.Sum256([]byte(operationID))
	suffix := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return "ses_" + suffix, "msg_" + suffix
}

// CellCredentialBindingV3 is the account-authorized owner credential reference
// carried in the formatVersion 3 owner wire. It names an account-owned
// connection revision only and carries no secret material and no native
// credential id; the protected lease/native identity is returned only through
// the node-authenticated preparedReceipt.
type CellCredentialBindingV3 struct {
	ConnectionID       string `json:"connectionId"`
	ConnectionRevision int64  `json:"connectionRevision"`
	ProviderID         string `json:"providerId"`
	AuthMode           string `json:"authMode"`
}

// Validate reports whether the credential binding is exactly the frozen
// account-owned reference shape.
func (binding CellCredentialBindingV3) Validate() error {
	if !cellV3SafeIDPattern.MatchString(binding.ConnectionID) || binding.ConnectionRevision < 1 ||
		!cellV3ProviderIDPattern.MatchString(binding.ProviderID) ||
		(binding.AuthMode != "api_key" && binding.AuthMode != "chatgpt_subscription") {
		return errors.New("credential binding is invalid")
	}
	return nil
}

// digest is the canonical sha256 over {connectionId, connectionRevision,
// providerId, authMode}, matching the backend canonical_json contract.
func (binding CellCredentialBindingV3) digest() (string, error) {
	return canonicalSHA256(map[string]any{
		"connectionId":       binding.ConnectionID,
		"connectionRevision": binding.ConnectionRevision,
		"providerId":         binding.ProviderID,
		"authMode":           binding.AuthMode,
	})
}

// MatchesLease reports whether a fetched connection lease names exactly this
// account-owned connection revision. The Runtime validates the lease connection
// identity against the manifest binding rather than discarding it.
func (binding CellCredentialBindingV3) MatchesLease(connectionID string, connectionRevision int64) bool {
	return binding.ConnectionID == connectionID && binding.ConnectionRevision == connectionRevision
}

// CellParentIdentityV3 is the parent execution/packet authority bound by
// preparation and by the execution grant so a replay can never adopt a
// substitute parent. A retained top-level cell may carry a null parent
// execution/packet, but the packet id/revision are always present.
type CellParentIdentityV3 struct {
	ParentExecutionID *string `json:"parentExecutionId"`
	ParentPacketID    *string `json:"parentPacketId"`
	PacketID          string  `json:"packetId"`
	PacketRevision    int64   `json:"packetRevision"`
}

// Validate reports whether the parent identity is internally consistent: a
// parent execution and parent packet are both null or both present, and the
// packet id/revision are always well formed.
func (parent CellParentIdentityV3) Validate() error {
	if (parent.ParentExecutionID == nil) != (parent.ParentPacketID == nil) {
		return errors.New("parent execution and packet must both be null or both present")
	}
	if parent.ParentExecutionID != nil && !cellV3SafeIDPattern.MatchString(*parent.ParentExecutionID) {
		return errors.New("parent execution is invalid")
	}
	if parent.ParentPacketID != nil && !cellV3SafeIDPattern.MatchString(*parent.ParentPacketID) {
		return errors.New("parent packet is invalid")
	}
	if !cellV3SafeIDPattern.MatchString(parent.PacketID) || parent.PacketRevision < 1 {
		return errors.New("packet identity is invalid")
	}
	return nil
}

// CellExecutionGrantV3 is the backend-issued, single-use execution authority.
// Runtime and native code cannot mint it. Every field is bound to the accepted
// prepared identity and crosschecked against the entry before admission.
type CellExecutionGrantV3 struct {
	GrantID                 string  `json:"grantId"`
	OperationID             string  `json:"operationId"`
	SessionID               string  `json:"sessionId"`
	InputID                 string  `json:"inputId"`
	ControllerID            string  `json:"controllerId"`
	ControllerRevision      int64   `json:"controllerRevision"`
	AuthorityRevision       int64   `json:"authorityRevision"`
	Attempt                 int64   `json:"attempt"`
	Fence                   string  `json:"fence"`
	ParentExecutionID       *string `json:"parentExecutionId"`
	ParentPacketID          *string `json:"parentPacketId"`
	PacketID                string  `json:"packetId"`
	PacketRevision          int64   `json:"packetRevision"`
	ConfigDigest            string  `json:"configDigest"`
	ProfileDigest           string  `json:"profileDigest"`
	WorkspaceDigest         string  `json:"workspaceDigest"`
	CredentialBindingDigest string  `json:"credentialBindingDigest"`
	PreparedReceiptDigest   string  `json:"preparedReceiptDigest"`
	ExpiresAt               string  `json:"expiresAt"`
}

// CellServiceV3 is one formatVersion 3 cell lifecycle entry carried on the
// retained {cellServices:[...]} envelope. prepare carries no execution grant;
// execute requires exactly one preparedReceiptDigest and executionGrant object.
type CellServiceV3 struct {
	FormatVersion         int    `json:"formatVersion"`
	TargetKind            string `json:"targetKind"`
	OperationID           string `json:"operationId"`
	LaunchOperationID     string `json:"launchOperationId"`
	ActionRevision        int64  `json:"actionRevision"`
	DesiredRevision       int64  `json:"desiredRevision"`
	DesiredState          string `json:"desiredState"`
	SessionMode           string `json:"sessionMode"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
	OwnerCellID           string `json:"ownerCellId"`
	OwnerRole             string `json:"ownerRole"`
	OwnerGeneration       int64  `json:"ownerGeneration"`
	SandboxID             string `json:"sandboxId"`
	SandboxGeneration     int64  `json:"sandboxGeneration"`
	ServiceGeneration     int64  `json:"serviceGeneration"`
	ConfigDigest          string `json:"configDigest"`
	Fence                 string `json:"fence"`
	Attempt               int64  `json:"attempt"`
	Instance              string `json:"instance"`
	Role                  string `json:"role"`
	NativeSessionID       string `json:"nativeSessionId"`
	NativeProjectID       string `json:"nativeProjectId"`
	WorkspaceEpoch        string `json:"workspaceEpoch"`

	Workspace    ManagedServiceV2Workspace    `json:"workspace"`
	Instructions ManagedServiceV2Instructions `json:"instructions"`
	Profile      ManagedServiceV2Profile      `json:"profile"`
	Authority    *ManagedServiceV2Authority   `json:"authority,omitempty"`

	// FormatVersion 3 lifecycle additions.
	LifecyclePhase     string                  `json:"lifecyclePhase"`
	PreparationID      string                  `json:"preparationId"`
	CredentialBinding  CellCredentialBindingV3 `json:"credentialBinding"`
	ControllerID       string                  `json:"controllerId"`
	ControllerRevision int64                   `json:"controllerRevision"`
	AuthorityRevision  int64                   `json:"authorityRevision"`
	ParentIdentity     CellParentIdentityV3    `json:"parentIdentity"`
	RequestDigest      string                  `json:"requestDigest"`
	// PreparedReceiptDigest and ExecutionGrant are null on prepare and required
	// on execute. They are pointers so an absent vs explicit-null field decodes
	// to the same nil value and the phase rule is enforced in one place.
	PreparedReceiptDigest *string               `json:"preparedReceiptDigest"`
	ExecutionGrant        *CellExecutionGrantV3 `json:"executionGrant"`
}

// ValidateManagedServiceV3 validates one formatVersion 3 entry against the
// current sandbox generation and the ready profile setup operation it names.
// The frozen schema's lifecycle discrimination, nested security objects and
// cross-field grant consistency are enforced here.
func ValidateManagedServiceV3(entry CellServiceV3, sandboxGeneration int64, sandboxExists bool, profile *SetupOperation) error {
	if entry.FormatVersion != CellLifecycleFormatVersion || entry.TargetKind != "cell_session" {
		return errInvalidCellEntry("cell v3 entry envelope is invalid")
	}
	if !cellV3SafeIDPattern.MatchString(entry.OperationID) ||
		!cellV3SafeIDPattern.MatchString(entry.LaunchOperationID) ||
		entry.ActionRevision < 1 || entry.DesiredRevision < 1 ||
		!setupDigestPattern.MatchString(entry.ConfigDigest) {
		return errInvalidCellEntry("cell v3 entry revision or digest is invalid")
	}
	if entry.ServiceGeneration < 1 || entry.Attempt < 1 || !validCellFence(entry.Fence) {
		return errInvalidCellEntry("cell v3 entry service generation, attempt or fence is invalid")
	}
	if entry.DesiredState != "active" && entry.DesiredState != "paused" &&
		entry.DesiredState != "stopped" && entry.DesiredState != "retired" {
		return errInvalidCellEntry("cell v3 entry desired state is invalid")
	}
	if entry.SessionMode != "create_initial" && entry.SessionMode != "lookup_only" {
		return errInvalidCellEntry("cell v3 entry session mode is invalid")
	}
	if !cellV3SafeIDPattern.MatchString(entry.ServiceRegistrationID) ||
		!cellV3SafeIDPattern.MatchString(entry.OwnerCellID) ||
		(entry.OwnerRole != "manager" && entry.OwnerRole != "orchestrator") ||
		entry.OwnerGeneration < 1 {
		return errInvalidCellEntry("cell v3 entry owner authority is invalid")
	}
	if !cellV3SafeIDPattern.MatchString(entry.SandboxID) || entry.SandboxGeneration < 1 {
		return errInvalidCellEntry("cell v3 entry sandbox identity is invalid")
	}
	if !cellV3SafeIDPattern.MatchString(entry.Instance) ||
		(entry.Role != "worker" && entry.Role != "reviewer") {
		return errInvalidCellEntry("cell v3 entry instance or role is invalid")
	}
	if !cellNativeSessionIDPattern.MatchString(entry.NativeSessionID) ||
		!cellNativeProjectPattern.MatchString(entry.NativeProjectID) ||
		!cellV3SafeIDPattern.MatchString(entry.WorkspaceEpoch) {
		return errInvalidCellEntry("cell v3 entry native identity is invalid")
	}
	// The child session is canonically derived from the LAUNCH operation, not the
	// managed-service operation and not merely a regex-shaped string.
	derivedSessionID, _ := deriveNativeIDs(entry.LaunchOperationID)
	if entry.NativeSessionID != derivedSessionID {
		return errInvalidCellEntry("cell v3 entry native session does not match the launch operation")
	}
	if !cellV3SafeIDPattern.MatchString(entry.Workspace.SelectionID) ||
		!cellV3SafeIDPattern.MatchString(entry.Workspace.ProjectID) ||
		!cellV3SafeIDPattern.MatchString(entry.Workspace.WorkspaceEpoch) ||
		entry.Workspace.ScopeRevision < 1 ||
		!setupDigestPattern.MatchString(entry.Workspace.RootAttestation) {
		return errInvalidCellEntry("cell v3 entry workspace contract is invalid")
	}
	if entry.Instructions.InstructionRevision < 1 ||
		!setupDigestPattern.MatchString(entry.Instructions.InstructionDigest) {
		return errInvalidCellEntry("cell v3 entry instruction tuple is invalid")
	}
	if !validCellV3Authority(entry.Authority) {
		return errInvalidCellEntry("cell v3 entry authority is invalid")
	}
	if !sandboxExists || sandboxGeneration != entry.SandboxGeneration {
		return errInvalidCellEntry("cell v3 entry sandbox generation is not current")
	}
	if profile == nil || profile.SandboxID != entry.SandboxID ||
		profile.SandboxGeneration != entry.SandboxGeneration || profile.ProfileID != entry.Profile.ProfileID ||
		profile.ProfileRevision != entry.Profile.ProfileRevision || profile.ProfileDigest != entry.Profile.ProfileDigest {
		return errInvalidCellEntry("cell v3 entry profile is not exactly ready")
	}
	if entry.LifecyclePhase != "prepare" && entry.LifecyclePhase != "execute" {
		return errInvalidCellEntry("cell v3 entry lifecycle phase is invalid")
	}
	if !cellV3SafeIDPattern.MatchString(entry.ControllerID) ||
		entry.ControllerRevision < 1 || entry.AuthorityRevision < 1 {
		return errInvalidCellEntry("cell v3 entry controller authority is invalid")
	}
	if !cellV3SafeIDPattern.MatchString(entry.PreparationID) {
		return errInvalidCellEntry("cell v3 entry preparation id is invalid")
	}
	if err := entry.CredentialBinding.Validate(); err != nil {
		return errInvalidCellEntry("cell v3 entry credential binding is invalid")
	}
	if err := validCellV3CredentialAuthority(entry.Authority, entry.CredentialBinding); err != nil {
		return errInvalidCellEntry("cell v3 credential binding does not match the entry authority")
	}
	if err := entry.ParentIdentity.Validate(); err != nil {
		return errInvalidCellEntry("cell v3 entry parent identity is invalid")
	}
	if !cellV3RawDigestPattern.MatchString(entry.RequestDigest) {
		return errInvalidCellEntry("cell v3 entry request digest is invalid")
	}
	if entry.LifecyclePhase == "prepare" {
		if entry.PreparedReceiptDigest != nil || entry.ExecutionGrant != nil {
			return errInvalidCellEntry("cell v3 prepare entry must not carry a grant or receipt digest")
		}
		return nil
	}
	if entry.PreparedReceiptDigest == nil || !setupDigestPattern.MatchString(*entry.PreparedReceiptDigest) {
		return errInvalidCellEntry("cell v3 execute entry requires a prepared receipt digest")
	}
	if entry.ExecutionGrant == nil {
		return errInvalidCellEntry("cell v3 execute entry requires an execution grant")
	}
	return entry.ExecutionGrant.validateAgainst(entry)
}

func validCellV3Authority(authority *ManagedServiceV2Authority) bool {
	if authority == nil {
		return true
	}
	validModel := authority.ModelID == nil || modelIDPattern.MatchString(*authority.ModelID)
	validAuthMode := authority.AuthMode == nil || *authority.AuthMode == "api_key" || *authority.AuthMode == "chatgpt_subscription"
	return cellV3ProviderIDPattern.MatchString(authority.ProviderID) && validModel && validAuthMode
}

// validCellV3CredentialAuthority checks the account-owned credential binding
// against the entry authority at the typed boundary: the binding must name the
// same provider and auth mode, and the authority must select an explicit model
// so the connection/model pairing is determinate. The account connection's
// allowed-model list is enforced server-side against the account store.
func validCellV3CredentialAuthority(authority *ManagedServiceV2Authority, binding CellCredentialBindingV3) error {
	if authority == nil {
		return errors.New("cell v3 entry authority is required")
	}
	if authority.ProviderID != binding.ProviderID {
		return errors.New("cell v3 credential binding provider does not match authority")
	}
	if authority.ModelID == nil || *authority.ModelID == "" {
		return errors.New("cell v3 authority model is required")
	}
	if authority.AuthMode == nil || *authority.AuthMode != binding.AuthMode {
		return errors.New("cell v3 credential binding auth mode does not match authority")
	}
	if binding.AuthMode == "chatgpt_subscription" && binding.ProviderID != "openai" {
		return errors.New("cell v3 subscription authority requires OpenAI")
	}
	return nil
}

// validateAgainst enforces the exact execute-phase consistency between the
// backend-issued grant and the accepted entry: authority/session/input/parent/
// attempt/fence tuple equality plus the canonical config/profile/workspace/
// credential/ prepared-receipt digests.
func (grant CellExecutionGrantV3) validateAgainst(entry CellServiceV3) error {
	if !cellV3SafeIDPattern.MatchString(grant.GrantID) {
		return errInvalidCellEntry("cell v3 grant id is invalid")
	}
	// The grant binds the LAUNCH operation (SS17.7) and names the canonical
	// derive_native_ids(launchOperationId) session/input, not merely regex-shaped
	// strings.
	if grant.OperationID != entry.LaunchOperationID {
		return errInvalidCellEntry("cell v3 grant operation is inconsistent")
	}
	derivedSessionID, derivedInputID := deriveNativeIDs(entry.LaunchOperationID)
	if grant.SessionID != derivedSessionID || grant.SessionID != entry.NativeSessionID {
		return errInvalidCellEntry("cell v3 grant session is inconsistent")
	}
	if grant.InputID != derivedInputID {
		return errInvalidCellEntry("cell v3 grant input is inconsistent")
	}
	if grant.ControllerID != entry.ControllerID ||
		grant.ControllerRevision != entry.ControllerRevision ||
		grant.AuthorityRevision != entry.AuthorityRevision {
		return errInvalidCellEntry("cell v3 grant controller authority is inconsistent")
	}
	if grant.Attempt != entry.Attempt || grant.Fence != entry.Fence {
		return errInvalidCellEntry("cell v3 grant attempt or fence is inconsistent")
	}
	parent := entry.ParentIdentity
	if !nilableStringEqual(grant.ParentExecutionID, parent.ParentExecutionID) ||
		!nilableStringEqual(grant.ParentPacketID, parent.ParentPacketID) ||
		grant.PacketID != parent.PacketID || grant.PacketRevision != parent.PacketRevision {
		return errInvalidCellEntry("cell v3 grant parent identity is inconsistent")
	}
	if grant.ConfigDigest != entry.ConfigDigest || grant.ProfileDigest != entry.Profile.ProfileDigest {
		return errInvalidCellEntry("cell v3 grant config or profile digest is inconsistent")
	}
	expectedWorkspaceDigest, err := workspaceIdentityDigest(entry.Workspace)
	if err != nil || grant.WorkspaceDigest != expectedWorkspaceDigest {
		return errInvalidCellEntry("cell v3 grant workspace digest is inconsistent")
	}
	// The complete workspace identity digest must never be equated with the
	// root attestation; a rootAttestation-shaped workspaceDigest is a drift bug.
	if expectedWorkspaceDigest == entry.Workspace.RootAttestation {
		return errInvalidCellEntry("cell v3 workspace digest must not equal the root attestation")
	}
	expectedBindingDigest, err := entry.CredentialBinding.digest()
	if err != nil || grant.CredentialBindingDigest != expectedBindingDigest {
		return errInvalidCellEntry("cell v3 grant credential binding digest is inconsistent")
	}
	if entry.PreparedReceiptDigest == nil || grant.PreparedReceiptDigest != *entry.PreparedReceiptDigest {
		return errInvalidCellEntry("cell v3 grant prepared receipt digest is inconsistent")
	}
	if _, err := time.Parse(time.RFC3339, grant.ExpiresAt); err != nil {
		return errInvalidCellEntry("cell v3 grant expiry is invalid")
	}
	return nil
}

// ValidateExecutionAuthority checks only the separately issued execution
// authority. Native still owns atomic consumption and the delivery recheck.
func (entry CellServiceV3) ValidateExecutionAuthority(receipt PreparedReceipt) error {
	if entry.LifecyclePhase != "execute" || entry.ExecutionGrant == nil || entry.PreparedReceiptDigest == nil {
		return errors.New("cell v3 execution requires separately issued authority")
	}
	if err := receipt.ValidateFor(entry); err != nil {
		return err
	}
	if *entry.PreparedReceiptDigest != receipt.PreparedReceiptDigest {
		return errors.New("cell v3 execution does not match the accepted preparation")
	}
	return entry.ExecutionGrant.validateAgainst(entry)
}

// SamePreparationIdentity compares every manifest field except the explicitly
// mutable lifecycle/desired-state authority. Tuple, workspace, profile, model,
// instructions, controller revisions and attempt/fence remain immutable. Action
// revisions are checked separately for monotonic desired-state controls.
func (entry CellServiceV3) SamePreparationIdentity(other CellServiceV3) bool {
	normalize := func(value CellServiceV3) CellServiceV3 {
		value.DesiredState, value.DesiredRevision, value.ActionRevision, value.LifecyclePhase = "", 0, 0, ""
		value.PreparedReceiptDigest, value.ExecutionGrant = nil, nil
		return value
	}
	return reflect.DeepEqual(normalize(entry), normalize(other))
}

// SamePreparationIdentityExceptSessionMode compares the preparation identity
// with the Runtime session mode normalized away. A backend may repair the
// session mode for a still-pending preparation (the WP-150 reviewer first
// preparation was journaled lookup_only before the product selected
// create_initial); the journal writer uses this predicate to allow that ONE
// bounded, mode-only refresh while every other identity field stays exact.
func (entry CellServiceV3) SamePreparationIdentityExceptSessionMode(other CellServiceV3) bool {
	entry.SessionMode, other.SessionMode = "", ""
	return entry.SamePreparationIdentity(other)
}

// ValidCellV3SessionMode reports the closed Runtime session-mode vocabulary.
func ValidCellV3SessionMode(mode string) bool {
	return mode == "create_initial" || mode == "lookup_only"
}

// ValidateCellCredentialMaterial enforces the frozen protected adoption union.
// Errors describe shape only; secret material is never included.
func ValidateCellCredentialMaterial(raw json.RawMessage, provider, authMode string) error {
	invalid := errors.New("cell credential material does not match the frozen adoption union")
	if len(raw) == 0 || rejectDuplicateJSONFields(raw) != nil {
		return invalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return invalid
	}
	exact := func(fields map[string]json.RawMessage, names ...string) bool {
		if len(fields) != len(names) {
			return false
		}
		for _, name := range names {
			if _, ok := fields[name]; !ok {
				return false
			}
		}
		return true
	}
	var tag string
	if json.Unmarshal(fields["type"], &tag) != nil {
		return invalid
	}
	if authMode == "api_key" && tag == "key" {
		if !exact(fields, "type", "key") {
			return invalid
		}
		var material struct {
			Type string `json:"type"`
			Key  string `json:"key"`
		}
		if decodeStrictCellJSON(raw, &material) != nil || strings.TrimSpace(material.Key) == "" {
			return invalid
		}
		return nil
	}
	if authMode == "chatgpt_subscription" && provider == "openai" && tag == "oauth" {
		var metadata map[string]json.RawMessage
		if !exact(fields, "type", "methodID", "access", "refresh", "expires", "metadata") || json.Unmarshal(fields["metadata"], &metadata) != nil || !exact(metadata, "accountID") {
			return invalid
		}
		var material struct {
			Type     string `json:"type"`
			MethodID string `json:"methodID"`
			Access   string `json:"access"`
			Refresh  string `json:"refresh"`
			Expires  *int64 `json:"expires"`
			Metadata struct {
				AccountID string `json:"accountID"`
			} `json:"metadata"`
		}
		if decodeStrictCellJSON(raw, &material) != nil ||
			(material.MethodID != "chatgpt-browser" && material.MethodID != "chatgpt-headless") ||
			strings.TrimSpace(material.Access) == "" || strings.TrimSpace(material.Refresh) == "" ||
			material.Expires == nil || *material.Expires < 0 || strings.TrimSpace(material.Metadata.AccountID) == "" {
			return invalid
		}
		return nil
	}
	return invalid
}

func nilableStringEqual(left, right *string) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

// Renews reports whether the receiver is the bounded backend renewal
// (R-WP119-1) of an older, never-consumed grant: the SAME accepted
// preparation/attempt/fence identity and every bound digest unchanged, a
// DISTINCT grant id and a strictly later expiry.
//
// A renewal is not new authority: the backend re-issues it only for an expired,
// unconsumed grant whose execution is still pending with no admission. The
// Runtime therefore adopts it in exactly that state and rejects every other
// difference, so a grant can never be swapped, extended in place or escalated
// by the node, and native single-use consumption stays the arbiter.
func (grant CellExecutionGrantV3) Renews(older CellExecutionGrantV3) bool {
	if grant.GrantID == "" || older.GrantID == "" || grant.GrantID == older.GrantID {
		return false
	}
	if grant.OperationID != older.OperationID || grant.SessionID != older.SessionID ||
		grant.InputID != older.InputID || grant.ControllerID != older.ControllerID ||
		grant.ControllerRevision != older.ControllerRevision || grant.AuthorityRevision != older.AuthorityRevision ||
		grant.Attempt != older.Attempt || grant.Fence != older.Fence ||
		!nilableStringEqual(grant.ParentExecutionID, older.ParentExecutionID) ||
		!nilableStringEqual(grant.ParentPacketID, older.ParentPacketID) ||
		grant.PacketID != older.PacketID || grant.PacketRevision != older.PacketRevision ||
		grant.ConfigDigest != older.ConfigDigest || grant.ProfileDigest != older.ProfileDigest ||
		grant.WorkspaceDigest != older.WorkspaceDigest ||
		grant.CredentialBindingDigest != older.CredentialBindingDigest ||
		grant.PreparedReceiptDigest != older.PreparedReceiptDigest {
		return false
	}
	renewed, err := time.Parse(time.RFC3339, grant.ExpiresAt)
	if err != nil {
		return false
	}
	previous, err := time.Parse(time.RFC3339, older.ExpiresAt)
	if err != nil {
		return false
	}
	return renewed.After(previous)
}

// workspaceIdentityDigest is the canonical sha256 over the COMPLETE workspace
// identity (selectionId, projectId, workspaceEpoch, scopeRevision and root
// attestation), matching the backend canonical_json (UTF-8, sorted keys,
// compact separators).
func workspaceIdentityDigest(workspace ManagedServiceV2Workspace) (string, error) {
	return canonicalSHA256(map[string]any{
		"selectionId":     workspace.SelectionID,
		"projectId":       workspace.ProjectID,
		"workspaceEpoch":  workspace.WorkspaceEpoch,
		"scopeRevision":   workspace.ScopeRevision,
		"rootAttestation": workspace.RootAttestation,
	})
}

func canonicalSHA256(value any) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	payload := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	return fmt.Sprintf("sha256:%x", sha256.Sum256(payload)), nil
}

// decodeCellServiceEntries decodes the single retained {cellServices:[...]}
// wire array into version-discriminated typed collections. An entry is routed
// by formatVersion only; unknown versions, unknown fields (including nested
// security objects) and duplicate JSON keys are rejected. There is no second
// wire array and no v3-to-v2 fallback.
func decodeCellServiceEntries(raw json.RawMessage) ([]ManagedServiceV2, []CellServiceV3, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil, nil
	}
	if err := rejectDuplicateJSONFields(trimmed); err != nil {
		return nil, nil, fmt.Errorf("cellServices: %w", err)
	}
	var elements []json.RawMessage
	if err := json.Unmarshal(trimmed, &elements); err != nil {
		return nil, nil, fmt.Errorf("cellServices must be an array: %w", err)
	}
	entriesV2 := make([]ManagedServiceV2, 0, len(elements))
	entriesV3 := make([]CellServiceV3, 0, len(elements))
	for index, element := range elements {
		var envelope struct {
			FormatVersion *int `json:"formatVersion"`
		}
		if err := json.Unmarshal(element, &envelope); err != nil || envelope.FormatVersion == nil {
			return nil, nil, fmt.Errorf("cellServices[%d]: formatVersion is required", index)
		}
		switch *envelope.FormatVersion {
		case 2:
			var entry ManagedServiceV2
			if err := decodeStrictCellJSON(element, &entry); err != nil {
				return nil, nil, fmt.Errorf("cellServices[%d]: %w", index, err)
			}
			entriesV2 = append(entriesV2, entry)
		case CellLifecycleFormatVersion:
			var entry CellServiceV3
			if err := decodeStrictCellJSON(element, &entry); err != nil {
				return nil, nil, fmt.Errorf("cellServices[%d]: %w", index, err)
			}
			entriesV3 = append(entriesV3, entry)
		default:
			return nil, nil, fmt.Errorf("cellServices[%d]: unsupported formatVersion %d", index, *envelope.FormatVersion)
		}
	}
	return entriesV2, entriesV3, nil
}

// encodeCellServiceEntries re-emits the single wire array from both typed
// collections so a mixed v2/v3 manifest round-trips across the local snapshot.
func encodeCellServiceEntries(entriesV2 []ManagedServiceV2, entriesV3 []CellServiceV3) (json.RawMessage, error) {
	if len(entriesV2) == 0 && len(entriesV3) == 0 {
		return nil, nil
	}
	elements := make([]json.RawMessage, 0, len(entriesV2)+len(entriesV3))
	for _, entry := range entriesV2 {
		payload, err := json.Marshal(entry)
		if err != nil {
			return nil, err
		}
		elements = append(elements, payload)
	}
	for _, entry := range entriesV3 {
		payload, err := json.Marshal(entry)
		if err != nil {
			return nil, err
		}
		elements = append(elements, payload)
	}
	return json.Marshal(elements)
}

func decodeStrictCellJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

// rejectDuplicateJSONFields rejects any object with a repeated key anywhere in
// the document, including nested security objects such as credentialBinding and
// executionGrant.
func rejectDuplicateJSONFields(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := validateUniqueJSONValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON token %v", token)
	}
	return nil
}

func validateUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = true
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

// CellPreparedAuthorityV3 is the immutable model/credential selection bound by
// the preparation receipt, not a second independent execution-grant field.
type CellPreparedAuthorityV3 struct {
	ProviderID string `json:"providerId"`
	AuthMode   string `json:"authMode"`
	ModelID    string `json:"modelId"`
}

// PreparedTuple is the canonical, fully specified prepared identity tuple
// (SS17.5/17.15). Its operationId binds the LAUNCH operation (SS17.7); the backend
// stores preparedReceiptDigest over exactly this tuple, including authority.
type PreparedTuple struct {
	OperationID           string                  `json:"operationId"`
	ControllerID          string                  `json:"controllerId"`
	ControllerRevision    int64                   `json:"controllerRevision"`
	AuthorityRevision     int64                   `json:"authorityRevision"`
	ServiceRegistrationID string                  `json:"serviceRegistrationId"`
	ServiceGeneration     int64                   `json:"serviceGeneration"`
	SandboxID             string                  `json:"sandboxId"`
	SandboxGeneration     int64                   `json:"sandboxGeneration"`
	ParentExecutionID     *string                 `json:"parentExecutionId"`
	ParentPacketID        *string                 `json:"parentPacketId"`
	PacketID              string                  `json:"packetId"`
	PacketRevision        int64                   `json:"packetRevision"`
	RequestDigest         string                  `json:"requestDigest"`
	ConfigDigest          string                  `json:"configDigest"`
	ProfileDigest         string                  `json:"profileDigest"`
	WorkspaceDigest       string                  `json:"workspaceDigest"`
	CredentialBinding     CellCredentialBindingV3 `json:"credentialBinding"`
	Authority             CellPreparedAuthorityV3 `json:"authority"`
	Attempt               int64                   `json:"attempt"`
	Fence                 string                  `json:"fence"`
}

// Digest is the canonical local qualification join; receipt/grant wire remains unchanged.
func (tuple PreparedTuple) Digest() (string, error) { return canonicalSHA256(tuple.canonicalMap()) }

// PreparedTuple builds the prepared tuple a Runtime reports for the accepted
// resourceVersion 3 execution: identity is taken from the entry, operationId
// binds the launch operation, and workspaceDigest is the canonical complete
// workspace-identity digest.
func (entry CellServiceV3) PreparedTuple() (PreparedTuple, error) {
	if !validCellV3Authority(entry.Authority) || validCellV3CredentialAuthority(entry.Authority, entry.CredentialBinding) != nil {
		return PreparedTuple{}, errors.New("cell v3 prepared tuple requires exact model authority")
	}
	workspaceDigest, err := workspaceIdentityDigest(entry.Workspace)
	if err != nil {
		return PreparedTuple{}, err
	}
	return PreparedTuple{
		OperationID:           entry.LaunchOperationID,
		ControllerID:          entry.ControllerID,
		ControllerRevision:    entry.ControllerRevision,
		AuthorityRevision:     entry.AuthorityRevision,
		ServiceRegistrationID: entry.ServiceRegistrationID,
		ServiceGeneration:     entry.ServiceGeneration,
		SandboxID:             entry.SandboxID,
		SandboxGeneration:     entry.SandboxGeneration,
		ParentExecutionID:     entry.ParentIdentity.ParentExecutionID,
		ParentPacketID:        entry.ParentIdentity.ParentPacketID,
		PacketID:              entry.ParentIdentity.PacketID,
		PacketRevision:        entry.ParentIdentity.PacketRevision,
		RequestDigest:         entry.RequestDigest,
		ConfigDigest:          entry.ConfigDigest,
		ProfileDigest:         entry.Profile.ProfileDigest,
		WorkspaceDigest:       workspaceDigest,
		CredentialBinding:     entry.CredentialBinding,
		Authority: CellPreparedAuthorityV3{
			ProviderID: entry.Authority.ProviderID,
			AuthMode:   *entry.Authority.AuthMode,
			ModelID:    *entry.Authority.ModelID,
		},
		Attempt: entry.Attempt,
		Fence:   entry.Fence,
	}, nil
}

func (tuple PreparedTuple) canonicalMap() map[string]any {
	return map[string]any{
		"operationId":           tuple.OperationID,
		"controllerId":          tuple.ControllerID,
		"controllerRevision":    tuple.ControllerRevision,
		"authorityRevision":     tuple.AuthorityRevision,
		"serviceRegistrationId": tuple.ServiceRegistrationID,
		"serviceGeneration":     tuple.ServiceGeneration,
		"sandboxId":             tuple.SandboxID,
		"sandboxGeneration":     tuple.SandboxGeneration,
		"parentExecutionId":     tuple.ParentExecutionID,
		"parentPacketId":        tuple.ParentPacketID,
		"packetId":              tuple.PacketID,
		"packetRevision":        tuple.PacketRevision,
		"requestDigest":         tuple.RequestDigest,
		"configDigest":          tuple.ConfigDigest,
		"profileDigest":         tuple.ProfileDigest,
		"workspaceDigest":       tuple.WorkspaceDigest,
		"credentialBinding": map[string]any{
			"connectionId":       tuple.CredentialBinding.ConnectionID,
			"connectionRevision": tuple.CredentialBinding.ConnectionRevision,
			"providerId":         tuple.CredentialBinding.ProviderID,
			"authMode":           tuple.CredentialBinding.AuthMode,
		},
		"authority": map[string]any{
			"providerId": tuple.Authority.ProviderID,
			"authMode":   tuple.Authority.AuthMode,
			"modelId":    tuple.Authority.ModelID,
		},
		"attempt": tuple.Attempt,
		"fence":   tuple.Fence,
	}
}

func (tuple PreparedTuple) bindingDigest(credentialID, nativeCredentialID string) (string, error) {
	return canonicalSHA256(map[string]any{
		"preparedTuple":      tuple.canonicalMap(),
		"credentialId":       credentialID,
		"nativeCredentialId": nativeCredentialID,
	})
}

func (tuple PreparedTuple) preparedReceiptDigest(credentialID, nativeCredentialID, bindingDigest string) (string, error) {
	return canonicalSHA256(map[string]any{
		"preparedTuple":      tuple.canonicalMap(),
		"credentialId":       credentialID,
		"nativeCredentialId": nativeCredentialID,
		"bindingDigest":      bindingDigest,
	})
}

// PreparedReceipt is the node-authenticated preparation receipt. preparation
// materializes/binds workspace, profile and credential but has NO prompt grant
// and must not mark the native binding verified before this receipt.
type PreparedReceipt struct {
	FormatVersion         int           `json:"formatVersion"`
	PreparedTuple         PreparedTuple `json:"preparedTuple"`
	CredentialID          string        `json:"credentialId"`
	NativeCredentialID    string        `json:"nativeCredentialId"`
	BindingDigest         string        `json:"bindingDigest"`
	PreparedReceiptDigest string        `json:"preparedReceiptDigest"`
}

// ValidateFor crosschecks the receipt against the accepted manifest entry and
// recomputes both canonical digests at the typed boundary, so a caller cannot
// forward a receipt for a drifted tuple. It never mints a grant.
func (receipt PreparedReceipt) ValidateFor(entry CellServiceV3) error {
	if receipt.FormatVersion != CellLifecycleFormatVersion {
		return errors.New("cell v3 prepared receipt format version is invalid")
	}
	expectedTuple, err := entry.PreparedTuple()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(receipt.PreparedTuple.canonicalMap(), expectedTuple.canonicalMap()) {
		return errors.New("cell v3 prepared receipt tuple does not match the entry")
	}
	return receipt.ValidateIntegrity()
}

// Integrity alone is not readiness/admission. The actual manifest/native reporter
// must additionally ValidateFor its exact current entry before assignment.
func (receipt PreparedReceipt) ValidateIntegrity() error {
	if receipt.FormatVersion != CellLifecycleFormatVersion {
		return errors.New("cell v3 prepared receipt format version is invalid")
	}
	if !cellV3SafeIDPattern.MatchString(receipt.CredentialID) {
		return errors.New("cell v3 prepared receipt credential id is invalid")
	}
	if strings.TrimSpace(receipt.NativeCredentialID) == "" {
		return errors.New("cell v3 prepared receipt native credential id is invalid")
	}
	if !setupDigestPattern.MatchString(receipt.BindingDigest) {
		return errors.New("cell v3 prepared receipt binding digest is invalid")
	}
	bindingDigest, err := receipt.PreparedTuple.bindingDigest(receipt.CredentialID, receipt.NativeCredentialID)
	if err != nil || receipt.BindingDigest != bindingDigest {
		return errors.New("cell v3 prepared receipt binding digest is inconsistent")
	}
	receiptDigest, err := receipt.PreparedTuple.preparedReceiptDigest(
		receipt.CredentialID, receipt.NativeCredentialID, bindingDigest,
	)
	if err != nil || receipt.PreparedReceiptDigest != receiptDigest {
		return errors.New("cell v3 prepared receipt digest is inconsistent")
	}
	return nil
}

// CellPreparationReport is the node-authenticated POST
// /internal/runtime/cell-preparation body, matching the backend
// {preparationId, preparedReceipt} envelope exactly.
type CellPreparationReport struct {
	PreparationID   string          `json:"preparationId"`
	PreparedReceipt PreparedReceipt `json:"preparedReceipt"`
}

// CellPreparationView is the backend _prepared_view response for one applied
// preparation receipt.
type CellPreparationView struct {
	PreparationID           string `json:"preparationId"`
	TargetKind              string `json:"targetKind"`
	LifecyclePhase          string `json:"lifecyclePhase"`
	State                   string `json:"state"`
	OperationID             string `json:"operationId"`
	SandboxGeneration       int64  `json:"sandboxGeneration"`
	ControllerID            string `json:"controllerId"`
	ControllerRevision      int64  `json:"controllerRevision"`
	AuthorityRevision       int64  `json:"authorityRevision"`
	WorkspaceDigest         string `json:"workspaceDigest"`
	CredentialBindingDigest string `json:"credentialBindingDigest"`
	PreparedReceiptDigest   string `json:"preparedReceiptDigest"`
	CredentialID            string `json:"credentialId"`
	NativeCredentialID      string `json:"nativeCredentialId"`
}

func (view CellPreparationView) ValidateFor(entry CellServiceV3, receipt PreparedReceipt) error {
	bindingDigest, err := entry.CredentialBinding.digest()
	if err != nil {
		return err
	}
	if view.PreparationID != entry.PreparationID || view.TargetKind != "cell_session" || view.LifecyclePhase != "prepare" || view.State != "prepared" || view.OperationID != entry.LaunchOperationID || view.SandboxGeneration != entry.SandboxGeneration || view.ControllerID != entry.ControllerID || view.ControllerRevision != entry.ControllerRevision || view.AuthorityRevision != entry.AuthorityRevision || view.WorkspaceDigest != receipt.PreparedTuple.WorkspaceDigest || view.CredentialBindingDigest != bindingDigest || view.PreparedReceiptDigest != receipt.PreparedReceiptDigest || view.CredentialID != receipt.CredentialID || view.NativeCredentialID != receipt.NativeCredentialID {
		return errors.New("backend cell preparation acknowledgement identity mismatch")
	}
	return nil
}
