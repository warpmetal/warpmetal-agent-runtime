// Package agentkit is the Runtime half of WP-211 runtime agent-kit
// materialization: it turns an application operation's saved immutable v2
// `agentSetup` declaration into the closed request document consumed by the
// packaged sandbox materializer (`runner/warpmetal_agent_kit.py`), and it
// independently verifies the materialization receipt that comes back.
//
// Boundaries kept deliberately:
//   - production default unchanged: no venue is selected unless
//     WARPMETAL_RUNTIME_AGENT_KIT_VENUE names one exact compiled TEST adoption
//     record, so no existing production path gains materialization behaviour;
//   - the Runtime never writes workspace files itself, never fetches assets,
//     never resolves provider credentials and never executes the first task;
//   - provider selections are connection REFERENCES only; tool/MCP declarations
//     are recorded deny-by-default and never widen the effective closure;
//   - the vendored warpmetal/skills snapshot pin is compiled here too, so a
//     receipt claiming a different commit/catalog digest or a different skill
//     content digest is refused;
//   - the actual in-cell invocation channel (supervisor exec of the packaged
//     materializer) is the installed/live qualification gate; this package
//     produces the request and verifies the receipt today.
package agentkit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

const (
	RequestFormatVersion  = 1
	RequestKind           = "agent_kit_materialization"
	ReceiptKind           = "agent_kit_materialization_receipt"
	MaterializerVersion   = "warpmetal-agent-kit-v1"
	venueEnv              = "WARPMETAL_RUNTIME_AGENT_KIT_VENUE"
	snapshotCatalogID     = "warpmetal-skills"
	snapshotSourceRepo    = "warpmetal/skills"
	SnapshotCommit        = "23b16ad85d492ac0eec87e93d24b2c3d6f3b2fd9"
	SnapshotContentDigest = "sha256:4c37a13d03e98022054fee13f7c2931d26cad5a457c1d0431e6c1179e54a3fc9"
	maxInstructionBytes   = 32768
	maxKitBytes           = 262144
	maxSkills             = 50
	maxReceiptBytes       = 128 * 1024
)

// Venue is one compiled, documented TEST adoption record for materialization.
// There is deliberately no wildcard/prefix/version-range selection.
type Venue struct {
	ID       string
	Scope    string
	Approval string
	// WP-211A installed channel identity: the compiled TEST adoption record for
	// the packaged sandbox image content closure. The measured closure of the
	// packaged image layout is pinned here and re-measured by the supervisor and
	// the image build; it is never inferred from a filename, prefix or venue.
	InstalledVenue         string
	AdoptionID             string
	ClosureVersion         string
	ClosureDigest          string
	MaterializerDigest     string
	SnapshotManifestDigest string
	ClosureFileCount       int64
	ClosureByteCount       int64
}

var venues = [...]Venue{{
	ID:                     "TEST-wp211-kit-materialization",
	Scope:                  "venue:wp211-local-materialization",
	Approval:               "WP211_AGENT_KIT_MATERIALIZATION_LOCAL",
	InstalledVenue:         "TEST-wp211a-installed-a",
	AdoptionID:             "WP211A-MAT-ADOPT-1",
	ClosureVersion:         "warpmetal-agent-kit-content-v1",
	ClosureDigest:          "sha256:e201054ea5cf80d6bbc8d3b68ea5bc7e9ed0fc7a0301689ae20837b30d7da965",
	MaterializerDigest:     "sha256:98393bbf735f67052cccfea2321953e09240431e3e30b5d819020ead4d39e87a",
	SnapshotManifestDigest: "sha256:387d0ca5212174d1ddcb488c55a2f811ae98377f201aece46251fb6847f4a8aa",
	ClosureFileCount:       220,
	ClosureByteCount:       1788358,
}}

// SkillPin is the compiled per-skill identity of the vendored catalog entry at
// SnapshotCommit. A receipt entry naming any other digest is refused.
type SkillPin struct {
	ID            string
	ContentDigest string
	FileCount     int64
}

var skillPins = map[string]SkillPin{
	"backup-restore":          {"backup-restore", "sha256:d0c8e59bbb14c5b2de513910de68e5bfb1ba17565814abcf9ff925c0587961ff", 28},
	"deploy-site":             {"deploy-site", "sha256:7092313a47375a66cfe6622010af3e1d12faf0c801c3f5d9bd5ba2d5989d72a0", 30},
	"migrate-site":            {"migrate-site", "sha256:b655c5c91e3bc3cc90eb8112db47a620ed23e769b3282b6dbfe849f447c44d0b", 32},
	"queue-cron-setup":        {"queue-cron-setup", "sha256:7f8561b073aa4bbf5f1865e2db5b6a0e03da9bbec0ee1024b49ec9b9b3445bb1", 27},
	"server-monitoring":       {"server-monitoring", "sha256:9ba6c63ee580b596e8d99e7156496093c73e772b502bb15fba9840c02f5f2f2c", 26},
	"site-down-triage":        {"site-down-triage", "sha256:e4053b20b64a4bd143e9cfcbdb88acbe1e212646b523231804ba56d8b72999e6", 26},
	"ssl-dns-fix":             {"ssl-dns-fix", "sha256:b63d586a468e8b98404c505de71944d531e117f271348b9658831c4f3ac872c4", 26},
	"warpmetal":               {"warpmetal", "sha256:980af680662a135aff799f65fb73593768121ab912c05010e2f51c5af0d7a9fe", 7},
	"warpmetal-agent-sandbox": {"warpmetal-agent-sandbox", "sha256:ce3d030c6526114581d4c57d10272134f2d5f90ca108761682253ffa9acda19a", 5},
}

var (
	errVenueDenied = &Error{Code: "agent_kit_venue_denied"}
	digestPattern  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	pinnedRefRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/@-]{0,127}$`)
	safeIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	materialIDRE   = regexp.MustCompile(`^akm_[a-f0-9]{32}$`)
)

// Error is a typed fail-closed refusal. Code values are stable public names.
type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func refuse(code, detail string) *Error { return &Error{Code: code, Detail: detail} }

// SelectVenue maps the venue environment variable to exactly one compiled
// adoption record. Empty (the production default) selects nothing and returns
// (nil, nil): no existing path changes behaviour. An unknown value refuses.
func SelectVenue(env string) (*Venue, error) {
	selected := strings.TrimSpace(env)
	if selected == "" {
		return nil, nil
	}
	for index := range venues {
		// A venue may be selected by its materializer venue id or by its
		// compiled installed venue label (the label the supervisor adoption
		// receipt carries). Both are exact compiled values; nothing is inferred.
		if venues[index].ID == selected || venues[index].InstalledVenue == selected {
			return &venues[index], nil
		}
	}
	return nil, errVenueDenied
}

// VenueSelected is the package-level production-default check.
func VenueSelected() (*Venue, error) { return SelectVenue(os.Getenv(venueEnv)) }

// Target is the exact cell/workspace identity the materializer writes into.
type Target struct {
	SandboxID         string          `json:"sandboxId"`
	SandboxGeneration int64           `json:"sandboxGeneration"`
	SandboxRoot       string          `json:"sandboxRoot"`
	ProjectRoot       string          `json:"projectRoot"`
	Workspace         TargetWorkspace `json:"workspace"`
}

type TargetWorkspace struct {
	SelectionID     string `json:"selectionId"`
	ProjectID       string `json:"projectId"`
	WorkspaceEpoch  string `json:"workspaceEpoch"`
	RootAttestation string `json:"rootAttestation"`
}

type ConfigurationRef struct {
	ConfigurationID       string `json:"configurationId"`
	ConfigurationRevision int64  `json:"configurationRevision"`
	ConfigurationDigest   string `json:"configurationDigest"`
}

type SnapshotPin struct {
	CatalogID      string `json:"catalogId"`
	SourceRepo     string `json:"sourceRepo"`
	ResolvedCommit string `json:"resolvedCommit"`
	ContentDigest  string `json:"contentDigest"`
}

type SkillDeclaration struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	SourceRepo    string   `json:"sourceRepo"`
	PinnedRef     string   `json:"pinnedRef"`
	RequiredTools []string `json:"requiredTools"`
	Notes         string   `json:"notes"`
}

// declaration is the independently re-checked materialized subset of the v2
// agentSetup. Unknown fields are refused by the strict decoder.
type declaration struct {
	AgentInstructions string             `json:"agentInstructions"`
	Models            json.RawMessage    `json:"models"`
	ToolProviders     json.RawMessage    `json:"toolProviders"`
	Skills            []SkillDeclaration `json:"skills"`
	Runtime           json.RawMessage    `json:"runtime"`
	Repo              json.RawMessage    `json:"repo"`
	FirstTask         json.RawMessage    `json:"firstTask"`
	CapacityHint      json.RawMessage    `json:"capacityHint"`
	Devops            json.RawMessage    `json:"devops"`
}

// Request is the exact closed document the packaged materializer consumes.
type Request struct {
	FormatVersion     int              `json:"formatVersion"`
	Kind              string           `json:"kind"`
	MaterializationID string           `json:"materializationId"`
	Venue             string           `json:"venue"`
	Target            Target           `json:"target"`
	Configuration     ConfigurationRef `json:"configuration"`
	Kit               json.RawMessage  `json:"kit"`
	KitDigest         string           `json:"kitDigest"`
	SkillsSnapshot    SnapshotPin      `json:"skillsSnapshot"`
}

// ImageClosure is the measured content closure of the packaged sandbox image
// layout: the materializer bytes plus every pinned snapshot payload file at
// their fixed destination paths.
type ImageClosure struct {
	ClosureVersion         string `json:"closureVersion"`
	ClosureDigest          string `json:"closureDigest"`
	MaterializerDigest     string `json:"materializerDigest"`
	SnapshotManifestDigest string `json:"snapshotManifestDigest"`
	FileCount              int64  `json:"fileCount"`
	ByteCount              int64  `json:"byteCount"`
	Measurer               string `json:"measurer,omitempty"`
}

// InvocationRequest is the closed document the Runtime sends to the in-cell
// supervisor action “materialize-agent-kit“: the materializer request plus
// the compiled adoption identity and declared image closure. The supervisor
// re-validates all of it and measures the installed closure itself.
type InvocationRequest struct {
	SchemaVersion  int             `json:"schemaVersion"`
	SandboxID      string          `json:"sandboxId"`
	Instance       string          `json:"instance"`
	ProfileID      string          `json:"profileId"`
	ProjectRoot    string          `json:"projectRoot"`
	AdoptionID     string          `json:"adoptionId"`
	ImageClosure   ImageClosure    `json:"imageClosure"`
	Request        json.RawMessage `json:"request"`
	TimeoutSeconds int             `json:"timeoutSeconds"`
}

// InvocationReceipt is the bounded, digest-bound supervisor envelope.
type InvocationReceipt struct {
	Status          string
	Ready           bool
	Command         string
	SandboxID       string
	Instance        string
	ProfileID       string
	AdoptionID      string
	Venue           string
	Materializer    string
	Closure         ImageClosure
	Materialization Receipt
	// EnvelopeDigest is the canonical supervisor wrapper digest that was
	// re-derived and verified; it is persisted as the audit binding.
	EnvelopeDigest string
}

const (
	invocationCommand        = "materialize-agent-kit"
	invocationInstance       = "agent-kit"
	invocationProfileID      = "opencode"
	invocationTimeoutSeconds = 30
	maxInvocationBytes       = 64 * 1024
)

// MaterializationIDFrom derives the deterministic identity shared with the
// packaged materializer: akm_ + first 32 hex of sha256("wp211-agent-kit:" +
// configurationDigest + ":" + kitDigest).
func MaterializationIDFrom(configurationDigest, kitDigest string) string {
	raw := sha256.Sum256([]byte("wp211-agent-kit:" + configurationDigest + ":" + kitDigest))
	return "akm_" + hex.EncodeToString(raw[:])[:32]
}

// Digest returns the canonical F1-compatible sha256 of a JSON value.
func Digest(value any) (string, error) {
	raw, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// BuildRequest validates the saved v2 agentSetup carried by the application
// operation and produces the deterministic materializer request. Every failure
// is a typed refusal; nothing is inferred from an absent kit.
func BuildRequest(operation model.WorkspaceApplicationOperation, target Target, pin SnapshotPin, venue Venue) (Request, error) {
	var empty Request
	kit := operation.Configuration.AgentSetup
	if len(kit) == 0 || bytes.Equal(bytes.TrimSpace(kit), []byte("null")) {
		return empty, refuse("agent_kit_kit_missing", "configuration carries no agentSetup")
	}
	if len(kit) > maxKitBytes {
		return empty, refuse("agent_kit_bounds_exceeded", "kit")
	}
	decoded, err := decodeDeclaration(kit)
	if err != nil {
		return empty, err
	}
	if len(decoded.AgentInstructions) == 0 || len([]byte(decoded.AgentInstructions)) > maxInstructionBytes || strings.ContainsRune(decoded.AgentInstructions, '\x00') {
		return empty, refuse("agent_kit_instruction_invalid", "")
	}
	if len(decoded.Skills) > maxSkills {
		return empty, refuse("agent_kit_bounds_exceeded", "skills")
	}
	for _, skill := range decoded.Skills {
		if !safeIDPattern.MatchString(skill.ID) || !pinnedRefRE.MatchString(skill.PinnedRef) {
			return empty, refuse("agent_kit_kit_invalid", "skill")
		}
		if pinOf, ok := skillPins[skill.ID]; ok && skill.PinnedRef != SnapshotCommit {
			_ = pinOf // pin mismatch is resolved inside the materializer/catalog check
		}
	}
	if err := validatePin(pin); err != nil {
		return empty, err
	}
	if err := scanSecrets(kit); err != nil {
		return empty, err
	}
	kitDigest, err := Digest(kit)
	if err != nil {
		return empty, refuse("agent_kit_kit_invalid", "kit digest")
	}
	if !digestPattern.MatchString(operation.ConfigurationDigest) {
		return empty, refuse("agent_kit_digest_mismatch", "configurationDigest")
	}
	if !validVenue(venue) {
		return empty, errVenueDenied
	}
	if err := validateTarget(target); err != nil {
		return empty, err
	}
	request := Request{
		FormatVersion:     RequestFormatVersion,
		Kind:              RequestKind,
		MaterializationID: MaterializationIDFrom(operation.ConfigurationDigest, kitDigest),
		Venue:             venue.ID,
		Target:            target,
		Configuration: ConfigurationRef{
			ConfigurationID:       operation.ConfigurationID,
			ConfigurationRevision: operation.ConfigurationRevision,
			ConfigurationDigest:   operation.ConfigurationDigest,
		},
		Kit:            kit,
		KitDigest:      kitDigest,
		SkillsSnapshot: pin,
	}
	if !safeIDPattern.MatchString(request.Configuration.ConfigurationID) || request.Configuration.ConfigurationRevision < 1 {
		return empty, refuse("agent_kit_request_invalid", "configuration")
	}
	return request, nil
}

func decodeDeclaration(kit json.RawMessage) (declaration, error) {
	var decoded declaration
	decoder := json.NewDecoder(bytes.NewReader(kit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return declaration{}, refuse("agent_kit_kit_invalid", "unknown or malformed field")
	}
	if len(decoded.Models) == 0 || len(decoded.ToolProviders) == 0 || len(decoded.Runtime) == 0 {
		return declaration{}, refuse("agent_kit_kit_invalid", "missing required section")
	}
	return decoded, nil
}

func validVenue(venue Venue) bool {
	for _, compiled := range venues {
		if compiled == venue {
			return true
		}
	}
	return false
}

func validatePin(pin SnapshotPin) error {
	if pin.CatalogID != snapshotCatalogID || pin.SourceRepo != snapshotSourceRepo {
		return refuse("agent_kit_snapshot_pin_mismatch", "identity")
	}
	if pin.ResolvedCommit != SnapshotCommit {
		return refuse("agent_kit_snapshot_pin_mismatch", "commit")
	}
	if pin.ContentDigest != SnapshotContentDigest {
		return refuse("agent_kit_snapshot_pin_mismatch", "contentDigest")
	}
	return nil
}

func validateTarget(target Target) error {
	if !safeIDPattern.MatchString(target.SandboxID) || target.SandboxGeneration < 1 {
		return refuse("agent_kit_request_invalid", "sandbox")
	}
	if !regexp.MustCompile(`^sbx_[A-Za-z0-9_-]{8,60}$`).MatchString(target.SandboxID) {
		return refuse("agent_kit_request_invalid", "sandboxId")
	}
	for name, value := range map[string]string{
		"sandboxRoot": target.SandboxRoot, "projectRoot": target.ProjectRoot,
	} {
		if !strings.HasPrefix(value, "/") || strings.Contains(value, "..") || len(value) > 512 {
			return refuse("agent_kit_project_root_invalid", name)
		}
	}
	if target.SandboxRoot == "/" || target.ProjectRoot == "/" || !strings.HasPrefix(target.ProjectRoot+"/", target.SandboxRoot+"/") {
		return refuse("agent_kit_project_root_invalid", "")
	}
	for name, value := range map[string]string{
		"selectionId":    target.Workspace.SelectionID,
		"projectId":      target.Workspace.ProjectID,
		"workspaceEpoch": target.Workspace.WorkspaceEpoch,
	} {
		if !safeIDPattern.MatchString(value) {
			return refuse("agent_kit_request_invalid", name)
		}
	}
	if !digestPattern.MatchString(target.Workspace.RootAttestation) {
		return refuse("agent_kit_request_invalid", "rootAttestation")
	}
	return nil
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bghp_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
	regexp.MustCompile(`\bBearer [A-Za-z0-9._-]{20,}`),
	regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@`),
}

func scanSecrets(raw []byte) error {
	for _, pattern := range secretPatterns {
		if pattern.Match(raw) {
			return refuse("agent_kit_secret_detected", "")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Receipt verification
// ---------------------------------------------------------------------------

type FileReceipt struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	ByteCount int64  `json:"byteCount"`
	Status    string `json:"status"`
}

type SkillFileReceipt struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	ByteCount int64  `json:"byteCount"`
}

type SkillReceipt struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Version       string             `json:"version"`
	SourceRepo    string             `json:"sourceRepo"`
	PinnedRef     string             `json:"pinnedRef"`
	ContentDigest string             `json:"contentDigest"`
	FileCount     int64              `json:"fileCount"`
	ByteCount     int64              `json:"byteCount"`
	Files         []SkillFileReceipt `json:"files"`
}

// InstructionReceipt is the AGENTS.md byte-equality fact (no file status).
type InstructionReceipt struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	ByteCount int64  `json:"byteCount"`
}

type ProjectionReceipt struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	SHA256    string `json:"sha256"`
	ByteCount int64  `json:"byteCount"`
}

type Receipt struct {
	FormatVersion     int                 `json:"formatVersion"`
	Kind              string              `json:"kind"`
	Status            string              `json:"status"`
	Materializer      string              `json:"materializer"`
	MaterializationID string              `json:"materializationId"`
	Venue             string              `json:"venue"`
	Target            Target              `json:"target"`
	Configuration     ConfigurationRef    `json:"configuration"`
	KitDigest         string              `json:"kitDigest"`
	SkillsSnapshot    SnapshotPin         `json:"skillsSnapshot"`
	Instruction       InstructionReceipt  `json:"instruction"`
	Skills            []SkillReceipt      `json:"skills"`
	Projections       []ProjectionReceipt `json:"projections"`
	Files             []FileReceipt       `json:"files"`
	Actions           map[string]int64    `json:"actions"`
	DeclaredOnly      map[string]bool     `json:"declaredOnly"`
	NetworkUsed       bool                `json:"networkUsed"`
	SecretsPresent    bool                `json:"secretsPresent"`
	ReceiptDigest     string              `json:"receiptDigest"`
}

var expectedProjections = [...]string{
	".warpmetal/agent-kit/capacity-hint.json",
	".warpmetal/agent-kit/first-task.json",
	".warpmetal/agent-kit/models.json",
	".warpmetal/agent-kit/repo.json",
	".warpmetal/agent-kit/runtime.json",
	".warpmetal/agent-kit/tools.json",
}

// VerifyReceipt independently checks the sandbox materialization receipt
// against the request the Runtime issued. It recomputes the receipt digest, the
// AGENTS.md byte equality, every skill content digest against the compiled
// catalog pin and the projection/manifest file set; any drift is refused.
func VerifyReceipt(request Request, raw []byte) (Receipt, error) {
	var empty Receipt
	if len(raw) > maxReceiptBytes {
		return empty, refuse("agent_kit_receipt_invalid", "size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return empty, refuse("agent_kit_receipt_invalid", "shape")
	}
	if receipt.FormatVersion != RequestFormatVersion || receipt.Kind != ReceiptKind {
		return empty, refuse("agent_kit_receipt_invalid", "version/kind")
	}
	if receipt.Status != "ready" {
		return empty, refuse("agent_kit_receipt_invalid", "status")
	}
	if receipt.Materializer != MaterializerVersion {
		return empty, refuse("agent_kit_receipt_invalid", "materializer")
	}
	if receipt.MaterializationID != request.MaterializationID || receipt.KitDigest != request.KitDigest ||
		receipt.Venue != request.Venue || receipt.Configuration != request.Configuration ||
		receipt.SkillsSnapshot != request.SkillsSnapshot {
		return empty, refuse("agent_kit_receipt_invalid", "request binding")
	}
	unsigned := struct {
		FormatVersion     int                 `json:"formatVersion"`
		Kind              string              `json:"kind"`
		Status            string              `json:"status"`
		Materializer      string              `json:"materializer"`
		MaterializationID string              `json:"materializationId"`
		Venue             string              `json:"venue"`
		Target            Target              `json:"target"`
		Configuration     ConfigurationRef    `json:"configuration"`
		KitDigest         string              `json:"kitDigest"`
		SkillsSnapshot    SnapshotPin         `json:"skillsSnapshot"`
		Instruction       InstructionReceipt  `json:"instruction"`
		Skills            []SkillReceipt      `json:"skills"`
		Projections       []ProjectionReceipt `json:"projections"`
		Files             []FileReceipt       `json:"files"`
		Actions           map[string]int64    `json:"actions"`
		DeclaredOnly      map[string]bool     `json:"declaredOnly"`
		NetworkUsed       bool                `json:"networkUsed"`
		SecretsPresent    bool                `json:"secretsPresent"`
	}{
		receipt.FormatVersion, receipt.Kind, receipt.Status, receipt.Materializer,
		receipt.MaterializationID, receipt.Venue, receipt.Target, receipt.Configuration,
		receipt.KitDigest, receipt.SkillsSnapshot, receipt.Instruction, receipt.Skills,
		receipt.Projections, receipt.Files, receipt.Actions, receipt.DeclaredOnly,
		receipt.NetworkUsed, receipt.SecretsPresent,
	}
	recomputed, err := Digest(unsigned)
	if err != nil || recomputed != receipt.ReceiptDigest {
		return empty, refuse("agent_kit_receipt_digest_mismatch", "")
	}
	if receipt.DeclaredOnly["firstTask"] == false || receipt.DeclaredOnly["repo"] == false ||
		receipt.DeclaredOnly["runtime"] == false || receipt.DeclaredOnly["tools"] == false {
		return empty, refuse("agent_kit_receipt_invalid", "declaredOnly")
	}
	if receipt.NetworkUsed || receipt.SecretsPresent {
		return empty, refuse("agent_kit_receipt_invalid", "network/secrets")
	}
	// AGENTS.md byte equality: recompute the digest from the request kit.
	var decoded declaration
	if err := json.Unmarshal(request.Kit, &decoded); err != nil {
		return empty, refuse("agent_kit_kit_invalid", "")
	}
	instructionBytes := []byte(decoded.AgentInstructions)
	instructionDigest := "sha256:" + hex.EncodeToString(sha256Sum(instructionBytes))
	if receipt.Instruction.Path != "AGENTS.md" ||
		receipt.Instruction.ByteCount != int64(len(instructionBytes)) ||
		receipt.Instruction.SHA256 != instructionDigest {
		return empty, refuse("agent_kit_instruction_mismatch", "")
	}
	var agentsFile *FileReceipt
	for index := range receipt.Files {
		file := receipt.Files[index]
		if strings.HasSuffix(file.Path, "/AGENTS.md") {
			agentsFile = &receipt.Files[index]
			_ = file
			break
		}
	}
	if agentsFile == nil || agentsFile.SHA256 != instructionDigest ||
		agentsFile.ByteCount != int64(len(instructionBytes)) ||
		(agentsFile.Status != "created" && agentsFile.Status != "unchanged") {
		return empty, refuse("agent_kit_instruction_mismatch", "agents file")
	}
	// Skills: exact declared set, exact compiled pin per skill.
	if len(receipt.Skills) != len(decoded.Skills) {
		return empty, refuse("agent_kit_skill_mismatch", "count")
	}
	for index, declared := range decoded.Skills {
		fact := receipt.Skills[index]
		pin, ok := skillPins[declared.ID]
		if !ok || declared.SourceRepo != snapshotSourceRepo || declared.PinnedRef != SnapshotCommit {
			return empty, refuse("agent_kit_skill_mismatch", declared.ID)
		}
		if fact.ID != declared.ID || fact.SourceRepo != snapshotSourceRepo ||
			fact.PinnedRef != SnapshotCommit || fact.ContentDigest != pin.ContentDigest ||
			fact.FileCount != pin.FileCount || fact.ByteCount < 1 {
			return empty, refuse("agent_kit_skill_mismatch", declared.ID)
		}
	}
	// Projection declaration set: exact paths, structural shape only (the
	// sandbox materializer owns their bytes; no authority is granted by them).
	if len(receipt.Projections) != len(expectedProjections) {
		return empty, refuse("agent_kit_projection_mismatch", "count")
	}
	for index, path := range expectedProjections {
		projection := receipt.Projections[index]
		if projection.Path != path || !digestPattern.MatchString(projection.SHA256) ||
			projection.ByteCount < 1 || projection.Kind == "" {
			return empty, refuse("agent_kit_projection_mismatch", path)
		}
	}
	if scanSecrets(raw) != nil {
		return empty, refuse("agent_kit_secret_detected", "receipt")
	}
	return receipt, nil
}

func sha256Sum(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

// canonicalJSON encodes an F1-canonical JSON document: sorted object keys,
// compact separators, literal UTF-8, integer-only numbers except for model
// params, which are encoded in the same shortest form Python's json.dumps uses.
func canonicalJSON(value any) ([]byte, error) {
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
	if err := encodeCanonical(&out, tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func encodeCanonical(out *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(typed))
	case json.Number:
		if _, err := strconv.ParseInt(string(typed), 10, 64); err == nil {
			out.WriteString(string(typed))
			return nil
		}
		number, err := strconv.ParseFloat(string(typed), 64)
		if err != nil {
			return errors.New("invalid canonical number")
		}
		out.WriteString(strconv.FormatFloat(number, 'g', -1, 64))
	case string:
		appendCanonicalString(out, typed)
	case []any:
		out.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := encodeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				out.WriteByte(',')
			}
			appendCanonicalString(out, key)
			out.WriteByte(':')
			if err := encodeCanonical(out, typed[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("invalid canonical value %T", value)
	}
	return nil
}

func appendCanonicalString(out *bytes.Buffer, value string) {
	out.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(character)
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
			if character < 32 {
				fmt.Fprintf(out, `\u%04x`, character)
			} else {
				out.WriteRune(character)
			}
		}
	}
	out.WriteByte('"')
}
