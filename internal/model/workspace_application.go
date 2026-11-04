package model

// Consumers of F1's ONE workspace-workflow-producer-v1 schema. This is typed
// transport, not another schema, source approval, model readiness or activity.
import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type ApprovedExpertiseProfile struct {
	ProfileID       string `json:"profileId"`
	ProfileRevision int64  `json:"profileRevision"`
	ProfileDigest   string `json:"profileDigest"`
	BundleDigest    string `json:"bundleDigest"`
}
type ExpertiseFile struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	ByteCount int64  `json:"byteCount"`
}
type AppliedExpertiseProfile struct {
	ApprovedProfile ApprovedExpertiseProfile `json:"approvedProfile"`
	EntryPath       string                   `json:"entryPath"`
	Files           []ExpertiseFile          `json:"files"`
}
type WorkspaceTool struct {
	ToolID   string `json:"toolId"`
	Revision int64  `json:"revision"`
	Digest   string `json:"digest"`
}
type WorkspaceModelSelection struct {
	Authority         CellPreparedAuthorityV3  `json:"authority"`
	CredentialBinding *CellCredentialBindingV3 `json:"credentialBinding"`
}
type WorkspaceProfileDeclaration struct {
	ProfileID       string                    `json:"profileId"`
	Name            string                    `json:"name"`
	Description     string                    `json:"description"`
	ApprovedProfile *ApprovedExpertiseProfile `json:"approvedProfile"`
	Tools           []WorkspaceTool           `json:"tools"`
	ModelSelection  *WorkspaceModelSelection  `json:"modelSelection"`
}
type WorkspaceRoleDeclaration struct {
	ManagerProfileID string `json:"managerProfileId"`
	AdvisorProfileID string `json:"advisorProfileId"`
}
type WorkspaceLaneDeclaration struct {
	LaneID       string   `json:"laneId"`
	Name         string   `json:"name"`
	Objective    string   `json:"objective"`
	ProfileIDs   []string `json:"profileIds"`
	Dependencies []string `json:"dependencies"`
	Acceptance   []string `json:"acceptance"`
}
type WorkspaceApplicationLimits struct {
	MaxActiveChildren *int64 `json:"maxActiveChildren"`
	ModelRequests     *int64 `json:"modelRequests"`
	ModelTurns        *int64 `json:"modelTurns"`
	InputTokens       *int64 `json:"inputTokens"`
	OutputTokens      *int64 `json:"outputTokens"`
	USDMicros         *int64 `json:"usdMicros"`
	WallClockSeconds  *int64 `json:"wallClockSeconds"`
}
type WorkspaceConfiguration struct {
	FormatVersion int                           `json:"formatVersion"`
	WorkspaceName string                        `json:"workspaceName"`
	Purpose       string                        `json:"purpose"`
	Profiles      []WorkspaceProfileDeclaration `json:"profiles"`
	Roles         WorkspaceRoleDeclaration      `json:"roles"`
	Lanes         []WorkspaceLaneDeclaration    `json:"lanes"`
	Limits        WorkspaceApplicationLimits    `json:"limits"`
	// AgentSetup is the additive v2 agent-kit declaration (WP-211). It is a
	// closed RAW document owned by the workspace-configuration v2 schema; both
	// the wire and this field stay optional so a retained v1 operation is
	// unchanged. Absent/empty means "v1 configuration, no kit declared": the
	// Runtime must not infer a kit, and default production behaviour is
	// untouched. The materializer request is built by internal/agentkit only
	// under a compiled TEST venue adoption record.
	AgentSetup json.RawMessage `json:"agentSetup,omitempty"`
}

// ControllerRoleProjection is the backend's roleAgentProjection. ToolClosureDigest
// is the version-1 closure binding from WP-40; it is absent from the retained
// six-field wire. The backend pins parent.RoleAgentDigest over THIS projection
// (including the digest), so the same seven-field projection is passed to the
// packaged Supervisor; stripping the binding would make the native role
// readback digest disagree with the backend intent.
type ControllerRoleProjection struct {
	NativeAgentID     string                   `json:"nativeAgentId"`
	SystemDigest      string                   `json:"systemDigest"`
	ApprovedProfile   ApprovedExpertiseProfile `json:"approvedProfile"`
	ModelSelection    *WorkspaceModelSelection `json:"modelSelection"`
	ToolsDisabled     bool                     `json:"toolsDisabled"`
	MCPDisabled       bool                     `json:"mcpDisabled"`
	ToolClosureDigest string                   `json:"toolClosureDigest,omitempty"`
}
type ApplicationRoleTarget struct {
	Owner                 ControllerOwner          `json:"owner"`
	Role                  string                   `json:"role"`
	ServiceRegistrationID string                   `json:"serviceRegistrationId"`
	ServiceGeneration     int64                    `json:"serviceGeneration"`
	ApprovedProfile       ApprovedExpertiseProfile `json:"approvedProfile"`
}
type ApplicationRoleDependency struct {
	Binding      ApplicationRoleTarget        `json:"binding"`
	Projection   ControllerRoleProjection     `json:"projection"`
	Instructions ManagedServiceInstructionsV1 `json:"instructions"`
	Workspace    ManagedServiceWorkspaceV1    `json:"workspace"`
	Profile      ManagedServiceProfileV1      `json:"profile"`
}
type ApplicationSetupReceipt struct {
	SetupOperationID string `json:"setupOperationId"`
	ReceiptDigest    string `json:"receiptDigest"`
}

// WorkspaceConnectorApproval is the producer contract's exact read-only MCP
// approval. It is a descriptor in the closure, never an execution grant.
type WorkspaceConnectorApproval struct {
	ConnectorID         string `json:"connectorId"`
	ConnectorRevision   int64  `json:"connectorRevision"`
	ToolID              string `json:"toolId"`
	ScopeRevision       int64  `json:"scopeRevision"`
	DataScope           string `json:"dataScope"`
	DefinitionDigest    string `json:"definitionDigest"`
	ConfigurationDigest string `json:"configurationDigest"`
	ReadOnly            bool   `json:"readOnly"`
	TimeoutSeconds      int64  `json:"timeoutSeconds"`
	MaxResponseBytes    int64  `json:"maxResponseBytes"`
}
type WorkspaceNativeEditCeiling struct {
	Mode  string   `json:"mode"`
	Tools []string `json:"tools"`
}
type WorkspaceMCPClosure struct {
	Mode  string                       `json:"mode"`
	Allow []WorkspaceConnectorApproval `json:"allow"`
}

// WorkspaceToolClosure is the producer contract's versioned, closed tool/MCP
// closure (WP-40). Policy is deny-by-default; tools are exact config references;
// MCP is either disabled or an exact read-only allowlist; delegation, subagents
// and host network are denied. It is a declaration, never an application grant.
type WorkspaceToolClosure struct {
	FormatVersion     int                        `json:"formatVersion"`
	Policy            string                     `json:"policy"`
	NativeEditCeiling WorkspaceNativeEditCeiling `json:"nativeEditCeiling"`
	Tools             []WorkspaceTool            `json:"tools"`
	MCP               WorkspaceMCPClosure        `json:"mcp"`
	Delegation        string                     `json:"delegation"`
	Subagents         string                     `json:"subagents"`
	HostNetwork       string                     `json:"hostNetwork"`
}

// ToolClosure is the additive version-1 member. Nil is the retained six-field
// wire (WP-91 install shape); a present closure is validated and digest-bound.
type WorkspaceApplicationDependencies struct {
	FormatVersion int                         `json:"formatVersion"`
	Phase         string                      `json:"phase"`
	SetupReceipts []ApplicationSetupReceipt   `json:"setupReceipts"`
	Profiles      []AppliedExpertiseProfile   `json:"profiles"`
	Roles         []ApplicationRoleDependency `json:"roles"`
	Tools         []WorkspaceTool             `json:"tools"`
	ToolClosure   *WorkspaceToolClosure       `json:"toolClosure,omitempty"`
}

// ControllerParentToolSurfaceEmpty reports the only surface a controller parent
// may compose: no declared connector/MCP tools. A closure-bearing operation must
// carry the empty disabled closure; the legacy six-field wire has no closure.
func (dependencies WorkspaceApplicationDependencies) ControllerParentToolSurfaceEmpty() bool {
	closure := dependencies.ToolClosure
	return closure == nil || len(closure.Tools) == 0 && closure.MCP.Mode == "disabled" && len(closure.MCP.Allow) == 0
}

type WorkspaceRegisteredProducer struct {
	KeyID         string `json:"keyId"`
	KeySHA256     string `json:"keySHA256"`
	ServerID      string `json:"serverId"`
	NodeTokenHash string `json:"nodeTokenHash"`
}
type WorkspaceApplicationOperation struct {
	FormatVersion            int                              `json:"formatVersion"`
	Kind                     string                           `json:"kind"`
	OperationID              string                           `json:"operationId"`
	OperationDigest          string                           `json:"operationDigest"`
	AccountID                string                           `json:"accountId"`
	TaskID                   string                           `json:"taskId"`
	ServerID                 string                           `json:"serverId"`
	SandboxID                string                           `json:"sandboxId"`
	SandboxGeneration        int64                            `json:"sandboxGeneration"`
	SetupIntentID            string                           `json:"setupIntentId"`
	ConfigurationID          string                           `json:"configurationId"`
	ConfigurationRevision    int64                            `json:"configurationRevision"`
	ConfigurationDigest      string                           `json:"configurationDigest"`
	TargetRuntimeRevision    int64                            `json:"targetRuntimeRevision"`
	SetupOperationIDs        []string                         `json:"setupOperationIds"`
	Profiles                 []ApprovedExpertiseProfile       `json:"profiles"`
	MaterializerDigest       string                           `json:"materializerDigest"`
	RoleBindings             []ApplicationRoleTarget          `json:"roleBindings"`
	Limits                   WorkspaceApplicationLimits       `json:"limits"`
	Configuration            WorkspaceConfiguration           `json:"configuration"`
	Dependencies             WorkspaceApplicationDependencies `json:"dependencies"`
	DependencyDigest         string                           `json:"dependencyDigest"`
	ConnectionRevisionDigest string                           `json:"connectionRevisionDigest"`
	ModelAuthorityDigest     string                           `json:"modelAuthorityDigest"`
	Producer                 WorkspaceRegisteredProducer      `json:"producer"`
	ExpiresAt                string                           `json:"expiresAt"`
}

// All fields are required, even nullable declarations. Ordinary Go decoding
// cannot distinguish missing modelSelection from the authoritative explicit null.
func requiredApplicationFields(raw json.RawMessage, typ reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if typ.Kind() == reflect.Pointer {
			return nil
		}
		return errors.New("null application field")
	}
	if typ.Kind() == reflect.Pointer {
		return requiredApplicationFields(raw, typ.Elem())
	}
	// Raw closed domain bodies are validated by their selected consumer, not by
	// reflecting the backing []byte as though it were a JSON array. Existing typed
	// application fields do not use RawMessage and keep their exact required tree.
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var values map[string]json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		known := make(map[string]bool, typ.NumField())
		required := 0
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
			known[name] = true
			if !strings.Contains(options, "omitempty") {
				required++
			}
		}
		if len(values) < required {
			return errors.New("incomplete application fields")
		}
		for name := range values {
			if !known[name] {
				return errors.New("unknown application field")
			}
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
			value, ok := values[name]
			if !ok {
				if strings.Contains(options, "omitempty") {
					// version-1 wire optional members: a retained six-field
					// dependencies payload and its six-field role projections.
					continue
				}
				return errors.New("missing application field")
			}
			if strings.Contains(options, "omitempty") && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				// Present-but-null is not the retained absent wire version.
				return errors.New("null optional application field")
			}
			if err := requiredApplicationFields(value, field.Type); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := requiredApplicationFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (operation *WorkspaceApplicationOperation) UnmarshalJSON(raw []byte) error {
	if !utf8.Valid(raw) || len(raw) > 2*1024*1024 {
		return errors.New("invalid application bytes")
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	type wire WorkspaceApplicationOperation
	var value wire
	if err := decodeStrictCellJSON(raw, &value); err != nil {
		return err
	}
	if err := requiredApplicationFields(raw, reflect.TypeOf(value)); err != nil {
		return err
	}
	result := WorkspaceApplicationOperation(value)
	if err := result.Validate(); err != nil {
		return err
	}
	*operation = result
	return nil
}

// F1 security.canonical_json uses literal UTF-8, including U+2028/U+2029. Go's
// JSON encoder escapes those even with SetEscapeHTML(false), so encode strings
// explicitly here without changing legacy V3 hashes.
func WorkspaceCanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var tree any
	if err := decoder.Decode(&tree); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	var encode func(any) error
	encode = func(value any) error {
		switch v := value.(type) {
		case nil:
			out.WriteString("null")
		case bool:
			out.WriteString(strconv.FormatBool(v))
		case json.Number:
			if _, err := strconv.ParseInt(string(v), 10, 64); err != nil {
				return err
			}
			out.WriteString(string(v))
		case string:
			out.WriteByte('"')
			for _, r := range v {
				switch r {
				case '"', '\\':
					out.WriteByte('\\')
					out.WriteRune(r)
				case '\b':
					out.WriteString(`\b`)
				case '\f':
					out.WriteString(`\f`)
				case '\n':
					out.WriteString(`\n`)
				case '\r':
					out.WriteString(`\r`)
				case '\t':
					out.WriteString(`\t`)
				default:
					if r < 32 {
						fmt.Fprintf(&out, `\u%04x`, r)
					} else {
						out.WriteRune(r)
					}
				}
			}
			out.WriteByte('"')
		case []any:
			out.WriteByte('[')
			for i, item := range v {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := encode(item); err != nil {
					return err
				}
			}
			out.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			out.WriteByte('{')
			for i, key := range keys {
				if i > 0 {
					out.WriteByte(',')
				}
				_ = encode(key)
				out.WriteByte(':')
				if err := encode(v[key]); err != nil {
					return err
				}
			}
			out.WriteByte('}')
		default:
			return errors.New("invalid canonical application value")
		}
		return nil
	}
	if err := encode(tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func WorkspaceDigest(value any) string {
	raw, err := WorkspaceCanonicalJSON(value)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
}

func applicationPositive(value int64) bool { return value >= 1 && value <= 9007199254740991 }
func (ref ApprovedExpertiseProfile) valid() bool {
	return cellV3SafeIDPattern.MatchString(ref.ProfileID) && applicationPositive(ref.ProfileRevision) && setupDigestPattern.MatchString(ref.ProfileDigest) && setupDigestPattern.MatchString(ref.BundleDigest)
}
func validApplicationPath(path string) bool {
	if !utf8.ValidString(path) || len(path) == 0 || len(path) > 1024 || strings.ContainsAny(path, "\\\x00%?#[]*") || len(strings.Split(path, "/")) > 16 {
		return false
	}
	for _, r := range path {
		if r < 32 || r == 127 {
			return false
		}
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// validConnectorDataScope mirrors the producer schema's relative data-scope
// path: no leading/trailing whitespace, no empty/dot segments, and none of the
// reserved \ : # ? or control characters.
func validConnectorDataScope(path string) bool {
	if !utf8.ValidString(path) || len(path) == 0 || len(path) > 1024 || path[0] == '/' || strings.Contains(path, "//") {
		return false
	}
	first, _ := utf8.DecodeRuneInString(path)
	last, _ := utf8.DecodeLastRuneInString(path)
	if unicode.IsSpace(first) || unicode.IsSpace(last) {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	for _, r := range path {
		if r == '\\' || r == ':' || r == '#' || r == '?' || r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func (approval WorkspaceConnectorApproval) valid() bool {
	return cellV3SafeIDPattern.MatchString(approval.ConnectorID) && applicationPositive(approval.ConnectorRevision) &&
		cellV3SafeIDPattern.MatchString(approval.ToolID) && applicationPositive(approval.ScopeRevision) &&
		validConnectorDataScope(approval.DataScope) && setupDigestPattern.MatchString(approval.DefinitionDigest) &&
		setupDigestPattern.MatchString(approval.ConfigurationDigest) && approval.ReadOnly &&
		approval.TimeoutSeconds >= 1 && approval.TimeoutSeconds <= 30 &&
		approval.MaxResponseBytes >= 1 && approval.MaxResponseBytes <= 262144
}

func (closure WorkspaceToolClosure) valid() bool {
	if closure.FormatVersion != 1 || closure.Policy != "deny_by_default" || closure.Delegation != "denied" ||
		closure.Subagents != "denied" || closure.HostNetwork != "denied" ||
		closure.NativeEditCeiling.Mode != "workspace_scoped" || len(closure.NativeEditCeiling.Tools) != 3 {
		return false
	}
	ceiling := map[string]bool{"write": true, "edit": true, "patch": true}
	seenCeiling := map[string]bool{}
	for _, tool := range closure.NativeEditCeiling.Tools {
		if !ceiling[tool] || seenCeiling[tool] {
			return false
		}
		seenCeiling[tool] = true
	}
	if len(closure.Tools) > 32 {
		return false
	}
	for index, tool := range closure.Tools {
		if !cellV3SafeIDPattern.MatchString(tool.ToolID) || !applicationPositive(tool.Revision) || !setupDigestPattern.MatchString(tool.Digest) {
			return false
		}
		if index > 0 {
			previous := closure.Tools[index-1]
			if tool.ToolID < previous.ToolID || tool.ToolID == previous.ToolID && (tool.Revision < previous.Revision || tool.Revision == previous.Revision && tool.Digest <= previous.Digest) {
				return false
			}
		}
	}
	switch closure.MCP.Mode {
	case "disabled":
		if len(closure.Tools) != 0 || len(closure.MCP.Allow) != 0 {
			return false
		}
	case "exact_read_only":
		if len(closure.Tools) == 0 || len(closure.MCP.Allow) != len(closure.Tools) || len(closure.MCP.Allow) > 32 {
			return false
		}
	default:
		return false
	}
	for index, approval := range closure.MCP.Allow {
		if !approval.valid() {
			return false
		}
		if index > 0 {
			previous := closure.MCP.Allow[index-1]
			if approval.ToolID < previous.ToolID || approval.ToolID == previous.ToolID && (approval.ConnectorRevision < previous.ConnectorRevision || approval.ConnectorRevision == previous.ConnectorRevision && approval.ScopeRevision <= previous.ScopeRevision) {
				return false
			}
		}
	}
	if closure.MCP.Mode == "exact_read_only" {
		for index, tool := range closure.Tools {
			approval := closure.MCP.Allow[index]
			if approval.ToolID != tool.ToolID || approval.ConnectorRevision != tool.Revision || approval.DefinitionDigest != tool.Digest {
				return false
			}
		}
	}
	return true
}

// validateToolClosure binds the versioned closure into the same digested
// dependencies the backend used. A missing closure is the retained six-field
// wire (no projection digest); a present closure must be exact, must equal the
// dependency allowlist, and must be the digest each role projection carries.
func (op WorkspaceApplicationOperation) validateToolClosure() error {
	invalid := errors.New("invalid workspace application tool closure")
	digest := ""
	if closure := op.Dependencies.ToolClosure; closure != nil {
		if !closure.valid() || !reflect.DeepEqual(closure.Tools, op.Dependencies.Tools) {
			return invalid
		}
		digest = WorkspaceDigest(closure)
		if digest == "" {
			return invalid
		}
	}
	for _, role := range op.Dependencies.Roles {
		if role.Projection.ToolClosureDigest != digest {
			return invalid
		}
	}
	return nil
}

func (op WorkspaceApplicationOperation) Validate() error {
	invalid := errors.New("invalid workspace application operation")
	if op.FormatVersion != 1 || op.Kind != "configuration_application" || op.Dependencies.FormatVersion != 1 || op.Dependencies.Phase != "prompt_free" {
		return invalid
	}
	// Additive v2 configuration (WP-211 / P5): the operation wire stays v1 but a
	// v2 configuration carries an agent-kit declaration. Exactly the two declared
	// branches are accepted; a v1 configuration can never smuggle a kit, and a
	// v2 configuration must carry a non-empty closed agentSetup document.
	switch op.Configuration.FormatVersion {
	case 1:
		if len(op.Configuration.AgentSetup) != 0 {
			return invalid
		}
	case 2:
		if len(op.Configuration.AgentSetup) == 0 {
			return invalid
		}
	default:
		return invalid
	}
	for _, id := range []string{op.OperationID, op.AccountID, op.TaskID, op.ServerID, op.SandboxID, op.SetupIntentID, op.ConfigurationID, op.Producer.KeyID, op.Producer.ServerID} {
		if !cellV3SafeIDPattern.MatchString(id) {
			return invalid
		}
	}
	if op.Producer.ServerID != op.ServerID || !cellV3RawDigestPattern.MatchString(op.Producer.NodeTokenHash) {
		return invalid
	}
	for _, revision := range []int64{op.SandboxGeneration, op.ConfigurationRevision, op.TargetRuntimeRevision} {
		if !applicationPositive(revision) {
			return invalid
		}
	}
	for _, digest := range []string{op.OperationDigest, op.ConfigurationDigest, op.DependencyDigest, op.ConnectionRevisionDigest, op.ModelAuthorityDigest, op.MaterializerDigest, op.Producer.KeySHA256} {
		if !setupDigestPattern.MatchString(digest) {
			return invalid
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, op.ExpiresAt); err != nil {
		return invalid
	}
	if WorkspaceDigest(op.Dependencies) != op.DependencyDigest || WorkspaceDigest(op.Configuration) != op.ConfigurationDigest || !reflect.DeepEqual(op.Limits, op.Configuration.Limits) {
		return invalid
	}
	if len(op.SetupOperationIDs) < 1 || len(op.SetupOperationIDs) > 32 || len(op.Profiles) < 1 || len(op.Profiles) > 32 || len(op.RoleBindings) != 2 || len(op.Dependencies.Roles) != 2 || len(op.Dependencies.SetupReceipts) != len(op.SetupOperationIDs) || len(op.Dependencies.Profiles) != len(op.Profiles) {
		return invalid
	}
	for i, setup := range op.Dependencies.SetupReceipts {
		if !cellV3SafeIDPattern.MatchString(setup.SetupOperationID) || !setupDigestPattern.MatchString(setup.ReceiptDigest) || setup.SetupOperationID != op.SetupOperationIDs[i] || i > 0 && setup.SetupOperationID <= op.SetupOperationIDs[i-1] {
			return invalid
		}
	}
	for i, profile := range op.Dependencies.Profiles {
		if !profile.ApprovedProfile.valid() || profile.ApprovedProfile != op.Profiles[i] || !validApplicationPath(profile.EntryPath) || len(profile.Files) < 1 || len(profile.Files) > 64 {
			return invalid
		}
		if i > 0 {
			previous := op.Profiles[i-1]
			if previous.ProfileID > profile.ApprovedProfile.ProfileID || previous.ProfileID == profile.ApprovedProfile.ProfileID && previous.ProfileRevision >= profile.ApprovedProfile.ProfileRevision {
				return invalid
			}
		}
		entry, total := false, int64(0)
		for j, file := range profile.Files {
			if !validApplicationPath(file.Path) || !setupDigestPattern.MatchString(file.SHA256) || file.ByteCount < 0 || file.ByteCount > 262144 || j > 0 && file.Path <= profile.Files[j-1].Path {
				return invalid
			}
			total += file.ByteCount
			entry = entry || file.Path == profile.EntryPath
		}
		if !entry || total > 1048576 {
			return invalid
		}
	}
	if err := op.validateConfiguration(); err != nil {
		return err
	}
	if err := op.validateToolClosure(); err != nil {
		return err
	}
	for i, role := range op.Dependencies.Roles {
		expectedRole := []string{"manager", "orchestrator"}[i]
		b, p := role.Binding, role.Projection
		if b != op.RoleBindings[i] || b.Role != expectedRole || !b.Owner.valid() || !b.ApprovedProfile.valid() || !cellV3SafeIDPattern.MatchString(b.ServiceRegistrationID) || !applicationPositive(b.ServiceGeneration) || b.Owner.AccountID != op.AccountID || b.Owner.TaskID != op.TaskID || b.Owner.ServerID != op.ServerID || b.Owner.SandboxID != op.SandboxID || b.Owner.SandboxGeneration != op.SandboxGeneration || p.NativeAgentID != "warpmetal-controller-"+b.Role || p.ApprovedProfile != b.ApprovedProfile || !p.ToolsDisabled || !p.MCPDisabled || !setupDigestPattern.MatchString(p.SystemDigest) || p.SystemDigest != role.Instructions.InstructionDigest || !applicationPositive(role.Instructions.InstructionRevision) {
			return invalid
		}
		profileID := op.Configuration.Roles.ManagerProfileID
		if i == 1 {
			profileID = op.Configuration.Roles.AdvisorProfileID
		}
		matched := false
		for _, declaration := range op.Configuration.Profiles {
			if declaration.ProfileID == profileID && declaration.ApprovedProfile != nil && *declaration.ApprovedProfile == b.ApprovedProfile && reflect.DeepEqual(declaration.ModelSelection, p.ModelSelection) {
				matched = true
			}
		}
		if !matched {
			return invalid
		}
		for _, id := range []string{role.Workspace.SelectionID, role.Workspace.ProjectID, role.Workspace.WorkspaceEpoch, role.Profile.SetupOperationID, role.Profile.ProfileID} {
			if !cellV3SafeIDPattern.MatchString(id) {
				return invalid
			}
		}
		if role.Workspace.Designation != "team_project" || !applicationPositive(role.Workspace.ScopeRevision) || !setupDigestPattern.MatchString(role.Workspace.RootAttestation) || !applicationPositive(role.Profile.ProfileRevision) || !setupDigestPattern.MatchString(role.Profile.ProfileDigest) {
			return invalid
		}
		found := false
		for _, id := range op.SetupOperationIDs {
			found = found || id == role.Profile.SetupOperationID
		}
		if !found {
			return invalid
		}
	}
	if op.RoleBindings[0].ServiceRegistrationID == op.RoleBindings[1].ServiceRegistrationID {
		return invalid
	}
	raw, _ := json.Marshal(op)
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	_ = decoder.Decode(&value)
	delete(value, "operationDigest")
	if WorkspaceDigest(value) != op.OperationDigest {
		return errors.New("application operation digest mismatch")
	}
	return nil
}

func applicationText(value string, min, max int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= min && utf8.RuneCountInString(value) <= max
}
func (op WorkspaceApplicationOperation) validateConfiguration() error {
	invalid := errors.New("invalid application configuration")
	c := op.Configuration
	if !applicationText(c.WorkspaceName, 1, 120) || !applicationText(c.Purpose, 1, 8192) || len(c.Profiles) == 0 {
		return invalid
	}
	for _, ceiling := range []*int64{c.Limits.ModelRequests, c.Limits.ModelTurns, c.Limits.InputTokens, c.Limits.OutputTokens, c.Limits.USDMicros} {
		if ceiling != nil && (*ceiling < 0 || *ceiling > 9007199254740991) {
			return invalid
		}
	}
	for _, ceiling := range []*int64{c.Limits.MaxActiveChildren, c.Limits.WallClockSeconds} {
		if ceiling != nil && !applicationPositive(*ceiling) {
			return invalid
		}
	}
	profiles := map[string]bool{}
	references := map[ApprovedExpertiseProfile]bool{}
	tools := map[string]bool{}
	ordered := append([]WorkspaceProfileDeclaration(nil), c.Profiles...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ProfileID < ordered[j].ProfileID })
	connections, authorities := []any{}, []any{}
	for _, profile := range ordered {
		if !cellV3SafeIDPattern.MatchString(profile.ProfileID) || profiles[profile.ProfileID] || !applicationText(profile.Name, 1, 120) || !applicationText(profile.Description, 0, 4096) {
			return invalid
		}
		profiles[profile.ProfileID] = true
		if profile.ApprovedProfile != nil {
			if !profile.ApprovedProfile.valid() {
				return invalid
			}
			references[*profile.ApprovedProfile] = true
		}
		var connection, authority any
		if selection := profile.ModelSelection; selection != nil {
			if !cellV3ProviderIDPattern.MatchString(selection.Authority.ProviderID) || !applicationText(selection.Authority.ModelID, 1, 128) || selection.Authority.AuthMode != "api_key" && selection.Authority.AuthMode != "chatgpt_subscription" {
				return invalid
			}
			authority = selection.Authority
			connection = selection.CredentialBinding
			if binding := selection.CredentialBinding; binding != nil {
				if !cellV3SafeIDPattern.MatchString(binding.ConnectionID) || !applicationPositive(binding.ConnectionRevision) || binding.ProviderID != selection.Authority.ProviderID || binding.AuthMode != selection.Authority.AuthMode {
					return invalid
				}
			}
		}
		connections = append(connections, map[string]any{"profileId": profile.ProfileID, "credentialBinding": connection})
		authorities = append(authorities, map[string]any{"profileId": profile.ProfileID, "authority": authority})
		seen := map[string]bool{}
		for _, tool := range profile.Tools {
			if !cellV3SafeIDPattern.MatchString(tool.ToolID) || !applicationPositive(tool.Revision) || !setupDigestPattern.MatchString(tool.Digest) || seen[tool.ToolID] {
				return invalid
			}
			seen[tool.ToolID] = true
			tools[WorkspaceDigest(tool)] = true
		}
	}
	if !profiles[c.Roles.ManagerProfileID] || !profiles[c.Roles.AdvisorProfileID] || WorkspaceDigest(connections) != op.ConnectionRevisionDigest || WorkspaceDigest(authorities) != op.ModelAuthorityDigest || len(references) != len(op.Profiles) || len(tools) != len(op.Dependencies.Tools) || len(op.Dependencies.Tools) > 64 {
		return invalid
	}
	for _, profile := range op.Profiles {
		if !references[profile] {
			return invalid
		}
	}
	for i, tool := range op.Dependencies.Tools {
		if !tools[WorkspaceDigest(tool)] || i > 0 && (tool.ToolID < op.Dependencies.Tools[i-1].ToolID || tool.ToolID == op.Dependencies.Tools[i-1].ToolID && tool.Revision <= op.Dependencies.Tools[i-1].Revision) {
			return invalid
		}
	}
	lanes := map[string]bool{}
	for _, lane := range c.Lanes {
		if !cellV3SafeIDPattern.MatchString(lane.LaneID) || lanes[lane.LaneID] || !applicationText(lane.Name, 1, 120) || !applicationText(lane.Objective, 1, 8192) || len(lane.ProfileIDs) == 0 || len(lane.Acceptance) == 0 {
			return invalid
		}
		lanes[lane.LaneID] = true
		seen := map[string]bool{}
		for _, id := range lane.ProfileIDs {
			if !profiles[id] || seen[id] {
				return invalid
			}
			seen[id] = true
		}
		for _, item := range lane.Acceptance {
			if !applicationText(item, 1, 4096) {
				return invalid
			}
		}
	}
	for _, lane := range c.Lanes {
		seen := map[string]bool{}
		for _, id := range lane.Dependencies {
			if !lanes[id] || seen[id] {
				return invalid
			}
			seen[id] = true
		}
	}
	return nil
}

func (op WorkspaceApplicationOperation) ParentDependency(parent ControllerParentIntent) (ApplicationRoleDependency, error) {
	if err := op.Validate(); err != nil {
		return ApplicationRoleDependency{}, err
	}
	for _, role := range op.Dependencies.Roles {
		if parent.ApplicationOperationID == op.OperationID && parent.Owner == role.Binding.Owner && parent.Role == role.Binding.Role && parent.ServiceRegistrationID == role.Binding.ServiceRegistrationID && parent.ServiceGeneration == role.Binding.ServiceGeneration && parent.Profile == role.Profile && parent.Workspace == role.Workspace && parent.Instructions == role.Instructions && parent.ConnectionRevisionDigest == op.ConnectionRevisionDigest && parent.ModelAuthorityDigest == op.ModelAuthorityDigest && parent.RoleAgentDigest == WorkspaceDigest(role.Projection) {
			return role, nil
		}
	}
	return ApplicationRoleDependency{}, errors.New("parent application dependency conflict")
}
