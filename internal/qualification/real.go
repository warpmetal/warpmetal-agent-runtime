package qualification

// The real-provider sidecar is independent of V3 wire authority. Preparation
// may lease/adopt without activation; execute always joins the actual grant.
import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

const RealModel = "gpt-4.1-mini-2025-04-14"
const RealEndpoint = "https://api.openai.com/v1/responses"
const SharedLedger = "model-qualification-and-product"
const RequestMicros = 421000

var artifactName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}\.txt$`)
var realTime = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z$`)

type RealCase struct {
	ParticipantInventoryDigest string `json:"participantInventoryDigest,omitempty"`
	AccountingVersion          int    `json:"accountingVersion,omitempty"`
	ProviderPolicyDigest       string `json:"providerPolicyDigest,omitempty"`
	CaseID                     string `json:"caseId"`
	CaseManifestDigest         string `json:"caseManifestDigest"`
	LedgerID                   string `json:"ledgerId"`
	Requests                   int    `json:"requests"`
	Preparations               int    `json:"preparations"`
	USDMicros                  int64  `json:"usdMicros"`
	PricingDigest              string `json:"pricingDigest"`
	OperatorKeySHA256          string `json:"operatorKeySHA256"`
	FormatVersion              int    `json:"formatVersion,omitempty"`
	ModelRequests              int    `json:"modelRequests,omitempty"`
	AccessRequests             int    `json:"accessRequests,omitempty"`
	PhysicalCeiling            int    `json:"physicalCeiling,omitempty"`
	USDCeilingMicros           int64  `json:"usdCeilingMicros,omitempty"`
	DemandManifestDigest       string `json:"demandManifestDigest,omitempty"`
	QualificationTuples        int    `json:"qualificationTuples,omitempty"`
	TupleInventoryDigest       string `json:"tupleInventoryDigest,omitempty"`
	ControlsDigest             string `json:"controlsDigest,omitempty"`
}
type Budget struct {
	Requests           int    `json:"requests"`
	Turns              int    `json:"turns"`
	InputTokens        int    `json:"inputTokens"`
	OutputTokens       int    `json:"outputTokens"`
	USDMicros          int64  `json:"usdMicros"`
	SDKRetries         int    `json:"sdkRetries"`
	ApplicationRetries int    `json:"applicationRetries"`
	RequestBytes       int    `json:"requestBytes"`
	ResponseBytes      int    `json:"responseBytes"`
	DeadlineSeconds    int    `json:"deadlineSeconds"`
	PricingDigest      string `json:"pricingDigest"`
}

func PricingDigest() string {
	b, _ := json.Marshal(map[string]any{"modelId": RealModel, "inputMicrosPerMillion": 400000, "cachedInputMicrosPerMillion": 100000, "outputMicrosPerMillion": 1600000})
	return Digest(b)
}
func RealBudget() Budget {
	return Budget{2, 2, 2095152, 2000, 842000, 0, 0, 32768, 262144, 120, PricingDigest()}
}
func (c RealCase) valid(l Limits) bool {
	return c.legacy() && safeID.MatchString(c.CaseID) && hash.MatchString(c.CaseManifestDigest) && c.LedgerID == SharedLedger &&
		c.Requests >= 2 && c.Requests <= 23 && c.Preparations >= 1 && c.Preparations <= 11 && c.Requests >= c.Preparations*2 &&
		c.USDMicros >= int64(c.Requests)*RequestMicros && c.USDMicros <= 10000000 && c.PricingDigest == PricingDigest() && hash.MatchString(c.OperatorKeySHA256) &&
		l == (Limits{c.Preparations, c.Requests, 1000, 32768, 262144, 0})
}

type Workload struct {
	Revision                   int    `json:"revision"`
	PromptDigest               string `json:"promptDigest"`
	ArtifactRelativePath       string `json:"artifactRelativePath"`
	ExpectedArtifactSHA256     string `json:"expectedArtifactSHA256"`
	ExpectedTerminalJSONDigest string `json:"expectedTerminalJSONDigest"`
	Tool                       string `json:"tool"`
	CommandDigest              string `json:"commandDigest"`
	TimeoutSeconds             int    `json:"timeoutSeconds"`
}
type Applicability struct {
	FormatVersion        int    `json:"formatVersion,omitempty"`
	ProviderPolicyDigest string `json:"providerPolicyDigest,omitempty"`
	AccountID            string `json:"accountId"`
	TaskID               string `json:"taskId"`
	ServerID             string `json:"serverId"`
	SandboxID            string `json:"sandboxId"`
	SandboxGeneration    int64  `json:"sandboxGeneration"`
	Backend              struct {
		SourceInventoryDigest string `json:"sourceInventoryDigest"`
		ImageDigest           string `json:"imageDigest"`
		MigrationHead         string `json:"migrationHead"`
		ContractDigest        string `json:"contractDigest"`
	} `json:"backend"`
	Native  ArtifactIdentity `json:"native"`
	Runtime ArtifactIdentity `json:"runtime"`
	Sandbox struct {
		RegistryManifestDigest string `json:"registryManifestDigest"`
		ConfigDigest           string `json:"configDigest"`
		PluginDigest           string `json:"pluginDigest"`
	} `json:"sandbox"`
	Profile struct {
		SetupOperationID   string `json:"setupOperationId"`
		ProfileID          string `json:"profileId"`
		Revision           int64  `json:"revision"`
		ProfileDigest      string `json:"profileDigest"`
		MaterializerDigest string `json:"materializerDigest"`
		BundleDigest       string `json:"bundleDigest"`
	} `json:"profile"`
	Connection model.CellCredentialBindingV3 `json:"connection"`
	Model      struct {
		ProviderID           string `json:"providerId"`
		ModelID              string `json:"modelId"`
		AuthMode             string `json:"authMode"`
		Endpoint             string `json:"endpoint"`
		EngineProfileVersion string `json:"engineProfileVersion"`
		AdapterVersion       string `json:"adapterVersion"`
	} `json:"model"`
	CaseManifestDigest string `json:"caseManifestDigest"`
}
type ArtifactIdentity struct {
	Version       string `json:"version"`
	ArchiveSHA256 string `json:"archiveSHA256"`
	BinarySHA256  string `json:"binarySHA256"`
}
type RealRun struct {
	Purpose            string        `json:"purpose"`
	QualificationID    string        `json:"qualificationId"`
	ReservationID      string        `json:"reservationId"`
	Tuple              Applicability `json:"tuple"`
	TupleDigest        string        `json:"tupleDigest"`
	CreatePermitDigest string        `json:"createPermitDigest"`
	Workload           Workload      `json:"workload"`
	Budget             Budget        `json:"budget"`
}
type Activation struct {
	ProviderPolicyDigest  string `json:"providerPolicyDigest,omitempty"`
	AccountingVersion     int    `json:"accountingVersion,omitempty"`
	FormatVersion         int    `json:"formatVersion"`
	Mode                  string `json:"mode"`
	Purpose               string `json:"purpose"`
	QualificationID       string `json:"qualificationId"`
	ReservationID         string `json:"reservationId"`
	CaseID                string `json:"caseId"`
	CaseManifestDigest    string `json:"caseManifestDigest"`
	TupleDigest           string `json:"tupleDigest"`
	PreparationID         string `json:"preparationId"`
	PreparedTupleDigest   string `json:"preparedTupleDigest"`
	PreparedReceiptDigest string `json:"preparedReceiptDigest"`
	PolicyDigest          string `json:"policyDigest"`
	GrantID               string `json:"grantId"`
	GrantDigest           string `json:"grantDigest"`
	ExecutionID           string `json:"executionId"`
	PermitDigest          string `json:"permitDigest"`
	AccessEvidenceDigest  string `json:"accessEvidenceDigest"`
	BudgetDigest          string `json:"budgetDigest"`
	DispatchStart         int    `json:"dispatchStart"`
	PreparationIndex      int    `json:"preparationIndex"`
	IssuedAt              string `json:"issuedAt"`
	ExpiresAt             string `json:"expiresAt"`
}

// CanonicalDigest uses an object representation so struct field declaration order
// cannot differ from backend/Node sorted-key canonical JSON.
func CanonicalDigest(v any) string {
	return Digest(canonicalBytes(v))
}
func canonicalBytes(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		return nil
	}
	var generic any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(&generic) != nil {
		return nil
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(generic) != nil {
		return nil
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
}
func purpose(s string) bool { return s == "model_qualification_bootstrap" || s == "normal_execution" }
func (r RealRun) valid(b Bootstrap, p Policy) bool {
	t, w := r.Tuple, r.Workload
	if !purpose(r.Purpose) || !safeID.MatchString(r.QualificationID) || !safeID.MatchString(r.ReservationID) || !hash.MatchString(r.CreatePermitDigest) ||
		r.TupleDigest != CanonicalDigest(t) || r.Budget != RealBudget() || b.Case == nil || t.CaseManifestDigest != b.Case.CaseManifestDigest ||
		!safeID.MatchString(t.AccountID) || !safeID.MatchString(t.TaskID) || !safeID.MatchString(t.ServerID) || t.SandboxID != b.SandboxID || t.SandboxGeneration != b.SandboxGeneration ||
		t.Profile.ProfileID != "opencode" || t.Profile.ProfileDigest != b.ProfileDigest || !safeID.MatchString(t.Profile.SetupOperationID) || t.Profile.Revision < 1 ||
		t.Connection.Validate() != nil || t.Connection.ProviderID != "openai" || t.Connection.AuthMode != "api_key" ||
		t.Model.ProviderID != "openai" || t.Model.ModelID != RealModel || t.Model.AuthMode != "api_key" || t.Model.Endpoint != RealEndpoint || t.Model.EngineProfileVersion != "opencode-2.0.14" || t.Model.AdapterVersion != "team-adapter-1" ||
		t.Sandbox.RegistryManifestDigest != b.ImageDigest[strings.LastIndex(b.ImageDigest, "@")+1:] || t.Sandbox.PluginDigest != b.PluginSHA256 ||
		w.Revision != 1 || w.Tool != "shell" || w.TimeoutSeconds != 120 || !artifactName.MatchString(w.ArtifactRelativePath) {
		return false
	}
	for _, d := range []string{t.Backend.SourceInventoryDigest, t.Backend.ImageDigest, t.Backend.ContractDigest, t.Native.ArchiveSHA256, t.Native.BinarySHA256, t.Runtime.ArchiveSHA256, t.Runtime.BinarySHA256, t.Sandbox.ConfigDigest, t.Profile.MaterializerDigest, t.Profile.BundleDigest, w.PromptDigest, w.CommandDigest, w.ExpectedArtifactSHA256, w.ExpectedTerminalJSONDigest} {
		if !hash.MatchString(d) {
			return false
		}
	}
	return safeID.MatchString(t.Native.Version) && safeID.MatchString(t.Runtime.Version) && safeID.MatchString(t.Backend.MigrationHead) && p.ModelID == RealModel
}
func (a Activation) valid(boot Bootstrap, p Policy, d Descriptor, now time.Time) bool {
	r := p.Run
	if r == nil || boot.Case == nil || a.ProviderPolicyDigest != "" || a.AccountingVersion != 0 {
		return false
	}
	c := boot.Case
	i, ie := time.Parse(time.RFC3339Nano, a.IssuedAt)
	x, xe := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	pExpiry, _ := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	bExpiry, _ := time.Parse(time.RFC3339Nano, boot.ExpiresAt)
	if a.FormatVersion != 1 || a.Mode != "real_provider" || a.Purpose != r.Purpose || a.QualificationID != r.QualificationID || a.ReservationID != r.ReservationID || a.CaseID != c.CaseID || a.CaseManifestDigest != c.CaseManifestDigest || a.TupleDigest != r.TupleDigest || a.PreparationID != d.PreparationID || a.PreparedTupleDigest != d.PreparedTupleDigest || a.PolicyDigest != d.PolicyDigest || !safeID.MatchString(a.GrantID) || !safeID.MatchString(a.ExecutionID) || a.BudgetDigest != CanonicalDigest(r.Budget) || a.DispatchStart < 1 || a.DispatchStart+1 > c.Requests || a.PreparationIndex < 1 || a.PreparationIndex > c.Preparations || !realTime.MatchString(a.IssuedAt) || !realTime.MatchString(a.ExpiresAt) || ie != nil || xe != nil || i.After(now.Add(30*time.Second)) || !now.Before(x) || !i.Before(x) || x.Sub(i) > 120*time.Second || x.After(pExpiry) || x.After(bExpiry) {
		return false
	}
	for _, d := range []string{a.PreparedReceiptDigest, a.GrantDigest, a.PermitDigest, a.AccessEvidenceDigest} {
		if !hash.MatchString(d) {
			return false
		}
	}
	return true
}
func (s Store) ReadActivation(box model.Sandbox, boot Bootstrap, p Policy, d Descriptor, now time.Time) (Activation, error) {
	tree, key, e := s.Paths(box.ID)
	if e != nil {
		return Activation{}, e
	}
	b, e := s.signed(tree, key, "activations/"+d.PreparationID, 16384)
	if e != nil {
		return Activation{}, e
	}
	var a Activation
	if decodeClosed(b, &a) != nil || !a.valid(boot, p, d, now) {
		return Activation{}, ErrUntrusted
	}
	return a, nil
}
func (s Store) realMaterial(box model.Sandbox, p Policy) error {
	tree, key, _ := s.Paths(box.ID)
	for _, d := range []string{p.Run.Workload.PromptDigest, p.Run.Workload.CommandDigest, p.Run.Workload.ExpectedTerminalJSONDigest} {
		b, e := s.read(filepath.Join(tree, "blobs", d[7:]), tree, key, 32768)
		if e != nil || Digest(b) != d {
			return ErrUntrusted
		}
		if d == p.Run.Workload.ExpectedTerminalJSONDigest {
			var terminal struct {
				Artifact string `json:"artifact"`
				SHA256   string `json:"sha256"`
			}
			if decodeClosed(b, &terminal) != nil || terminal.Artifact != p.Run.Workload.ArtifactRelativePath || terminal.SHA256 != p.Run.Workload.ExpectedArtifactSHA256 || CanonicalDigest(terminal) != d {
				return ErrUntrusted
			}
		}
	}
	return nil
}

// Required fields including zero retry counts cannot disappear/null while Go
// silently initializes them. Equality of closed key trees is independently
// checked in addition to the strict duplicate-free decoder.
func decodeClosed(b []byte, v any) error {
	if decode(b, v) != nil {
		return ErrUntrusted
	}
	x, _ := json.Marshal(v)
	var want, got any
	if json.Unmarshal(x, &want) != nil || json.Unmarshal(b, &got) != nil || !sameShape(want, got) {
		return ErrUntrusted
	}
	return nil
}
func sameShape(want, got any) bool {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || len(w) != len(g) {
			return false
		}
		for k, v := range w {
			x, ok := g[k]
			if !ok || !sameShape(v, x) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(w) != len(g) {
			return false
		}
		for i := range w {
			if !sameShape(w[i], g[i]) {
				return false
			}
		}
		return true
	default:
		return got != nil
	}
}
