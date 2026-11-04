package qualification

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// PRODUCT-only DTOs. Descriptor1/Policy3/RealRun and qualification counters are
// not reused. Nested owner definitions retain their complete schema-checked bytes.
type ChildEnvelope[T any] struct {
	Payload   T      `json:"payload"`
	KeyID     string `json:"keyId"`
	Signature string `json:"signature"`
}
type ChildProductDescriptor struct {
	FormatVersion           int     `json:"formatVersion"`
	TargetKind              string  `json:"targetKind"`
	Purpose                 string  `json:"purpose"`
	Phase                   string  `json:"phase"`
	PreparationID           string  `json:"preparationId"`
	PreparedTupleDigest     string  `json:"preparedTupleDigest"`
	PreparationPolicyDigest string  `json:"preparationPolicyDigest"`
	PolicyDigest            *string `json:"policyDigest"`
	GenerationDigest        string  `json:"generationDigest"`
}
type ChildQualificationPin struct {
	QualificationID string `json:"qualificationId"`
	TupleDigest     string `json:"tupleDigest"`
	EvidenceDigest  string `json:"evidenceDigest"`
	ValidUntil      string `json:"validUntil"`
}
type ChildRootScope struct {
	Workspace                 model.ManagedServiceWorkspaceV1   `json:"workspace"`
	RegisteredSourceID        string                            `json:"registeredSourceId"`
	TargetAuthority           json.RawMessage                   `json:"targetAuthority"`
	Producer                  model.WorkspaceRegisteredProducer `json:"producer"`
	CandidateDescriptorDigest string                            `json:"candidateDescriptorDigest"`
	RuntimeRevision           int64                             `json:"runtimeRevision"`
}
type ChildPreparationSelection struct {
	PreparationID       string              `json:"preparationId"`
	PreparedTuple       model.PreparedTuple `json:"preparedTuple"`
	PreparedTupleDigest string              `json:"preparedTupleDigest"`
	SessionID           string              `json:"sessionId"`
	InputID             string              `json:"inputId"`
}
type ChildInstructionPin struct {
	InstructionRevision int64  `json:"instructionRevision"`
	InstructionDigest   string `json:"instructionDigest"`
	InputID             string `json:"inputId"`
	InputDigest         string `json:"inputDigest"`
	InputByteCount      int    `json:"inputByteCount"`
}
type ChildReservation struct {
	ReservationID        string `json:"reservationId"`
	LedgerID             string `json:"ledgerId"`
	AllocationID         string `json:"allocationId"`
	DemandManifestDigest string `json:"demandManifestDigest"`
	PreparationOrdinal   int    `json:"preparationOrdinal"`
	FirstPhysicalIndex   int    `json:"firstPhysicalIndex"`
	LastPhysicalIndex    int    `json:"lastPhysicalIndex"`
	ModelRequests        int    `json:"modelRequests"`
	AccessRequests       int    `json:"accessRequests"`
	USDMicros            int64  `json:"usdMicros"`
}
type ChildBudget struct {
	ModelRequests        int    `json:"modelRequests"`
	Turns                int    `json:"turns"`
	InputTokens          int    `json:"inputTokens"`
	OutputTokens         int    `json:"outputTokens"`
	RequestReserveMicros int64  `json:"requestReserveMicros"`
	USDMicros            int64  `json:"usdMicros"`
	RequestBodyBytes     int    `json:"requestBodyBytes"`
	ResponseBodyBytes    int    `json:"responseBodyBytes"`
	DeadlineSeconds      int    `json:"deadlineSeconds"`
	SDKRetries           int    `json:"sdkRetries"`
	ApplicationRetries   int    `json:"applicationRetries"`
	AuxiliaryRequests    int    `json:"auxiliaryRequests"`
	PricingDigest        string `json:"pricingDigest"`
}
type ChildRequestControl struct {
	RequestIndex      int     `json:"requestIndex"`
	PhysicalIndex     int     `json:"physicalIndex"`
	ToolChoice        string  `json:"toolChoice"`
	ToolKind          *string `json:"toolKind"`
	NativeToolName    *string `json:"nativeToolName"`
	MaxInputTokens    int     `json:"maxInputTokens"`
	MaxOutputTokens   int     `json:"maxOutputTokens"`
	MaxUSDMicros      int64   `json:"maxUsdMicros"`
	ParallelToolCalls bool    `json:"parallelToolCalls"`
}
type ChildWorkload struct {
	Kind                string                `json:"kind"`
	NativeToolNames     []string              `json:"nativeToolNames"`
	Requests            []ChildRequestControl `json:"requests"`
	TerminalOutput      string                `json:"terminalOutput"`
	CodemodeDisabled    bool                  `json:"codemodeDisabled"`
	DelegationDisabled  bool                  `json:"delegationDisabled"`
	HostNetworkDisabled bool                  `json:"hostNetworkDisabled"`
}
type ChildPreparationPolicy struct {
	ProviderPolicyDigest string                    `json:"providerPolicyDigest,omitempty"`
	AccountingVersion    int                       `json:"accountingVersion,omitempty"`
	FormatVersion        int                       `json:"formatVersion"`
	TargetKind           string                    `json:"targetKind"`
	Mode                 string                    `json:"mode"`
	Stage                string                    `json:"stage"`
	Purpose              string                    `json:"purpose"`
	Case                 RealCase                  `json:"case"`
	Handle               model.IntentHandle        `json:"handle"`
	Intent               json.RawMessage           `json:"intent"`
	Scope                json.RawMessage           `json:"scope"`
	Root                 ChildRootScope            `json:"root"`
	Applicability        Applicability             `json:"applicability"`
	Qualification        ChildQualificationPin     `json:"qualification"`
	Preparation          ChildPreparationSelection `json:"preparation"`
	Instructions         ChildInstructionPin       `json:"instructions"`
	Reservation          ChildReservation          `json:"reservation"`
	Budget               ChildBudget               `json:"budget"`
	Workload             ChildWorkload             `json:"workload"`
	ToolRequirements     []json.RawMessage         `json:"toolRequirements"`
	IssuedAt             string                    `json:"issuedAt"`
	ExpiresAt            string                    `json:"expiresAt"`
}
type ChildSourceReadScope struct {
	Grant json.RawMessage `json:"grant"`
	Root  json.RawMessage `json:"root"`
}
type ChildToolScope struct {
	Kind             string          `json:"kind"`
	NativeToolName   string          `json:"nativeToolName"`
	Definition       json.RawMessage `json:"definition"`
	Approval         json.RawMessage `json:"approval"`
	InstalledWitness json.RawMessage `json:"installedWitness"`
	EffectOrdinal    int             `json:"effectOrdinal"`
	OutputPath       string          `json:"outputPath"`
	InputRule        string          `json:"inputRule"`
	InputReads       []string        `json:"inputReads"`
	ScriptRead       *string         `json:"scriptRead"`
	DataScope        string          `json:"dataScope"`
	DataScopeDigest  *string         `json:"dataScopeDigest"`
}
type ChildProductPolicy struct {
	ProviderPolicyDigest    string                         `json:"providerPolicyDigest,omitempty"`
	AccountingVersion       int                            `json:"accountingVersion,omitempty"`
	FormatVersion           int                            `json:"formatVersion"`
	TargetKind              string                         `json:"targetKind"`
	Mode                    string                         `json:"mode"`
	Stage                   string                         `json:"stage"`
	Purpose                 string                         `json:"purpose"`
	PreparationPolicyDigest string                         `json:"preparationPolicyDigest"`
	Case                    RealCase                       `json:"case"`
	Intent                  model.IntentRef                `json:"intent"`
	Scope                   json.RawMessage                `json:"scope"`
	Root                    ChildRootScope                 `json:"root"`
	Applicability           Applicability                  `json:"applicability"`
	Qualification           ChildQualificationPin          `json:"qualification"`
	Reservation             ChildReservation               `json:"reservation"`
	Budget                  ChildBudget                    `json:"budget"`
	Workload                ChildWorkload                  `json:"workload"`
	Instructions            ChildInstructionPin            `json:"instructions"`
	PreparedReceipt         model.PreparedReceipt          `json:"preparedReceipt"`
	Binding                 json.RawMessage                `json:"binding"`
	Assignment              json.RawMessage                `json:"assignment"`
	SourceReads             []ChildSourceReadScope         `json:"sourceReads"`
	ArtifactReads           []json.RawMessage              `json:"artifactReads,omitempty"`
	Tools                   []ChildToolScope               `json:"tools"`
	ReviewDelivery          *model.ReviewDeliveryPlan      `json:"reviewDelivery"`
	IntegrationDelivery     *model.IntegrationDeliveryPlan `json:"integrationDelivery,omitempty"`
	IssuedAt                string                         `json:"issuedAt"`
	ExpiresAt               string                         `json:"expiresAt"`
}
type ChildPolicyBinding struct {
	ProviderPolicyDigest  string          `json:"providerPolicyDigest,omitempty"`
	AccountingVersion     int             `json:"accountingVersion,omitempty"`
	FormatVersion         int             `json:"formatVersion"`
	Purpose               string          `json:"purpose"`
	Case                  RealCase        `json:"case"`
	AllocationID          string          `json:"allocationId"`
	Intent                model.IntentRef `json:"intent"`
	PolicyDigest          string          `json:"policyDigest"`
	PreparedReceiptDigest string          `json:"preparedReceiptDigest"`
	AssignmentDigest      string          `json:"assignmentDigest"`
	ModelRequests         int             `json:"modelRequests"`
	USDMicros             int64           `json:"usdMicros"`
	ExpiresAt             string          `json:"expiresAt"`
}
type ChildAuthorizationObservation struct {
	FormatVersion         int            `json:"formatVersion"`
	Purpose               string         `json:"purpose"`
	TaskID                string         `json:"taskId"`
	NodeTokenHash         string         `json:"nodeTokenHash"`
	PreparationID         string         `json:"preparationId"`
	PreparedReceiptDigest string         `json:"preparedReceiptDigest"`
	AuthorizationSHA256   string         `json:"authorizationSha256"`
	Root                  ChildRootScope `json:"root"`
	ObservedAt            string         `json:"observedAt"`
}
type ChildProductActivation struct {
	ProviderPolicyDigest           string                     `json:"providerPolicyDigest,omitempty"`
	AccountingVersion              int                        `json:"accountingVersion,omitempty"`
	FormatVersion                  int                        `json:"formatVersion"`
	TargetKind                     string                     `json:"targetKind"`
	Mode                           string                     `json:"mode"`
	Purpose                        string                     `json:"purpose"`
	CaseID                         string                     `json:"caseId"`
	CaseManifestDigest             string                     `json:"caseManifestDigest"`
	DemandManifestDigest           string                     `json:"demandManifestDigest"`
	AllocationID                   string                     `json:"allocationId"`
	Intent                         model.IntentRef            `json:"intent"`
	PreparationID                  string                     `json:"preparationId"`
	PreparationPolicyDigest        string                     `json:"preparationPolicyDigest"`
	PreparedTupleDigest            string                     `json:"preparedTupleDigest"`
	PreparedReceiptDigest          string                     `json:"preparedReceiptDigest"`
	AssignmentDigest               string                     `json:"assignmentDigest"`
	PolicyDigest                   string                     `json:"policyDigest"`
	PolicyBindingDigest            string                     `json:"policyBindingDigest"`
	Reservation                    ChildReservation           `json:"reservation"`
	Grant                          model.CellExecutionGrantV3 `json:"grant"`
	GrantDigest                    string                     `json:"grantDigest"`
	AuthorizationObservationDigest string                     `json:"authorizationObservationDigest"`
	AuthorizationSHA256            string                     `json:"authorizationSha256"`
	IssuedAt                       string                     `json:"issuedAt"`
	ExpiresAt                      string                     `json:"expiresAt"`
}
type ChildProductGeneration struct {
	ProviderPolicyDigest     string                                        `json:"providerPolicyDigest,omitempty"`
	AccountingVersion        int                                           `json:"accountingVersion,omitempty"`
	FormatVersion            int                                           `json:"formatVersion"`
	TargetKind               string                                        `json:"targetKind"`
	Phase                    string                                        `json:"phase"`
	PreparationID            string                                        `json:"preparationId"`
	Demand                   ChildEnvelope[DemandManifest]                 `json:"demand"`
	PreparationPolicy        ChildEnvelope[ChildPreparationPolicy]         `json:"preparationPolicy"`
	Policy                   *ChildEnvelope[ChildProductPolicy]            `json:"policy"`
	PolicyBinding            *ChildEnvelope[ChildPolicyBinding]            `json:"policyBinding"`
	Activation               *ChildEnvelope[ChildProductActivation]        `json:"activation"`
	AuthorizationObservation *ChildEnvelope[ChildAuthorizationObservation] `json:"authorizationObservation"`
}
type ChildProductControl struct {
	FormatVersion int                    `json:"formatVersion"`
	Descriptor    ChildProductDescriptor `json:"descriptor"`
	Generation    ChildProductGeneration `json:"generation"`
}

// This witness is supplied ONLY by independent current installed/enrollment,
// accepted qualification and actual lifecycle/assignment/ROOT consumers. Nothing
// in the policy, model, descriptor, source hash or a successful-row seed creates it.
type ChildProductWitness struct {
	OperatorKeyID               string
	Applicability               Applicability
	QualifiedApplicability      Applicability
	Qualification               ChildQualificationPin
	Case                        RealCase
	Scope                       json.RawMessage
	Intent                      json.RawMessage
	Handle                      model.IntentHandle
	Root                        ChildRootScope
	ProducerPEM                 []byte
	Preparation                 ChildPreparationSelection
	Instructions                ChildInstructionPin
	ActualReceipt               *model.PreparedReceipt
	Binding                     json.RawMessage
	Assignment                  json.RawMessage
	Grant                       *model.CellExecutionGrantV3
	Authorization               *ChildAuthorizationObservation
	SigningNotBefore            time.Time
	ProductSigningNotBefore     time.Time
	ActivationSigningNotBefore  time.Time
	AuthorizedUntil             time.Time
	InstalledTools              map[string]json.RawMessage
	SourceRoots                 map[string]json.RawMessage
	Input                       []byte
	ReviewReads                 []model.ReviewReadWitness
	ArtifactReviewReads         []model.ArtifactReviewReadWitness `json:"ArtifactReviewReads,omitempty"`
	ReviewCompilation           *model.ReviewInputCompilation
	Entry                       model.CellServiceV3
	AcceptedPreparationEnvelope json.RawMessage
	AcceptedDemandEnvelope      json.RawMessage
	SourceContinuation          json.RawMessage       `json:"SourceContinuation,omitempty"`
	InstalledInputs             *ChildInstalledInputs `json:"InstalledInputs,omitempty"`
	InstalledFactsDigest        string                `json:"InstalledFactsDigest,omitempty"`
}

func sameProduct(a, b any) bool { return CanonicalDigest(a) == CanonicalDigest(b) }
func childExpiry(value string, issued time.Time, bound time.Time, now time.Time, span time.Duration) bool {
	expiry, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !issued.After(now) && issued.Before(expiry) && now.Before(expiry) && !expiry.After(bound) && expiry.Sub(issued) <= span
}
func sameProductReceipt(a *model.PreparedReceipt, b model.PreparedReceipt) bool {
	return a != nil && a.ValidateIntegrity() == nil && b.ValidateIntegrity() == nil && reflect.DeepEqual(*a, b)
}
