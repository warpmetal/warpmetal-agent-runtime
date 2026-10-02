package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const (
	MinTemporarySeconds     = 900
	MaxTemporarySeconds     = 86400
	DefaultTemporarySeconds = 86400
	MaxSetupArtifactBytes   = 2_147_483_648
)

var (
	namePattern              = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	idPattern                = regexp.MustCompile(`^(?:sbx|grant)_[A-Za-z0-9_-]{8,60}$`)
	setupIDPattern           = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	imagePattern             = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}$`)
	setupDigestPattern       = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	continuityIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	managerEvidenceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{3,159}$`)
	npmPackagePattern        = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]{0,62}/)?[a-z0-9][a-z0-9._-]{0,62}$`)
	npmBinPattern            = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	relativePathPattern      = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,256}$`)
	semverPattern            = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	environmentNamePattern   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	providerIDPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	modelIDPattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	validDesired             = map[string]bool{"running": true, "stopped": true, "deleted": true}
)

type Resources struct {
	CPUMillicores    int `json:"cpuMillicores"`
	MemoryMiB        int `json:"memoryMiB"`
	WorkspaceDiskGiB int `json:"workspaceDiskGiB"`
	PIDs             int `json:"pids"`
}

func (r Resources) Add(other Resources) Resources {
	return Resources{
		CPUMillicores:    r.CPUMillicores + other.CPUMillicores,
		MemoryMiB:        r.MemoryMiB + other.MemoryMiB,
		WorkspaceDiskGiB: r.WorkspaceDiskGiB + other.WorkspaceDiskGiB,
		PIDs:             r.PIDs + other.PIDs,
	}
}

func (r Resources) Fits(capacity Resources) bool {
	return r.CPUMillicores <= capacity.CPUMillicores &&
		r.MemoryMiB <= capacity.MemoryMiB &&
		r.WorkspaceDiskGiB <= capacity.WorkspaceDiskGiB
}

type Sandbox struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Size             string     `json:"size"`
	Resources        Resources  `json:"resources"`
	ImageDigest      string     `json:"imageDigest,omitempty"`
	Lifetime         string     `json:"lifetime"`
	ExpiresInSeconds *int       `json:"expiresInSeconds"`
	StartedAt        *time.Time `json:"startedAt"`
	ExpiresAt        *time.Time `json:"expiresAt"`
	DesiredState     string     `json:"desiredState"`
	Generation       int64      `json:"generation"`
}

// ContinuityIdentityV1 is the shared immutable fence carried by every local
// capture, checkpoint, and materialization operation. ExpectedRevision is the
// caller's control-plane revision (the Work record revision); it is never the
// runtime manifest's DesiredRevision, which advances independently for
// unrelated server state. WorkspaceEpoch and SandboxGeneration fence host
// storage and container lifecycle independently.
type ContinuityIdentityV1 struct {
	WorkID            string  `json:"workId"`
	ProjectID         string  `json:"projectId"`
	SandboxID         string  `json:"sandboxId"`
	WorkspaceEpoch    string  `json:"workspaceEpoch"`
	SandboxGeneration int64   `json:"sandboxGeneration"`
	TaskID            *string `json:"taskId"`
	TaskAttempt       *int64  `json:"taskAttempt"`
	ExpectedRevision  int64   `json:"expectedRevision"`
}

type ContinuityBindingV1 struct {
	BindingID             string `json:"bindingId"`
	BindingRevision       int64  `json:"bindingRevision"`
	RegisteredSourceID    string `json:"registeredSourceId"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
	NativeSessionID       string `json:"nativeSessionId"`
	NativeProjectID       string `json:"nativeProjectId"`
	NativeLocationDigest  string `json:"nativeLocationDigest"`
}

type ContinuityRegistrationV1 struct {
	FormatVersion     int                  `json:"formatVersion"`
	DesiredState      string               `json:"desiredState"`
	ContinuityEnabled bool                 `json:"continuityEnabled"`
	ScopeRevision     int64                `json:"scopeRevision"`
	Identity          ContinuityIdentityV1 `json:"identity"`
	Binding           ContinuityBindingV1  `json:"binding"`
}

type ContinuityOperationV1 struct {
	FormatVersion int                  `json:"formatVersion"`
	OperationID   string               `json:"operationId"`
	Action        string               `json:"action"`
	RequestDigest string               `json:"requestDigest"`
	ScopeRevision int64                `json:"scopeRevision"`
	BoundaryKind  string               `json:"boundaryKind"`
	Identity      ContinuityIdentityV1 `json:"identity"`
	Binding       ContinuityBindingV1  `json:"binding"`
}

type ContinuitySourceReportV1 struct {
	FormatVersion         int       `json:"formatVersion"`
	RegisteredSourceID    string    `json:"registeredSourceId"`
	ServiceRegistrationID string    `json:"serviceRegistrationId"`
	ServiceGeneration     int64     `json:"serviceGeneration"`
	ProjectID             string    `json:"projectId"`
	SandboxID             string    `json:"sandboxId"`
	SandboxGeneration     int64     `json:"sandboxGeneration"`
	WorkspaceEpoch        string    `json:"workspaceEpoch"`
	NativeSessionID       string    `json:"nativeSessionId"`
	NativeProjectID       string    `json:"nativeProjectId"`
	NativeLocationDigest  string    `json:"nativeLocationDigest"`
	ScopeRevision         int64     `json:"scopeRevision"`
	Role                  string    `json:"role"`
	ProfileRevision       int64     `json:"profileRevision"`
	InstructionRevision   int64     `json:"instructionRevision"`
	Availability          string    `json:"availability"`
	Reason                *string   `json:"reason"`
	LastObservedAt        time.Time `json:"lastObservedAt"`
}

// SessionHandoffV1 is the closed, short-lived selector for one already
// registered managed native session. It grants no access on its own: Runtime
// separately requires a current sandbox access grant and current host-private
// registrations for every field below.
type SessionHandoffV1 struct {
	FormatVersion int                      `json:"formatVersion"`
	Action        string                   `json:"action"`
	HandoffID     string                   `json:"handoffId"`
	IssuedAt      time.Time                `json:"issuedAt"`
	ExpiresAt     time.Time                `json:"expiresAt"`
	Identity      SessionHandoffIdentityV1 `json:"identity"`
	Source        SessionHandoffSourceV1   `json:"source"`
	Task          *SessionHandoffTaskV1    `json:"task"`
	Work          *SessionHandoffWorkV1    `json:"work"`
}

type SessionHandoffIdentityV1 struct {
	ServerID              string `json:"serverId"`
	TeamID                string `json:"teamId"`
	MemberID              string `json:"memberId"`
	SandboxID             string `json:"sandboxId"`
	SandboxGeneration     int64  `json:"sandboxGeneration"`
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

type SessionHandoffSourceV1 struct {
	RegisteredSourceID   string `json:"registeredSourceId"`
	NativeSessionID      string `json:"nativeSessionId"`
	NativeProjectID      string `json:"nativeProjectId"`
	NativeLocationDigest string `json:"nativeLocationDigest"`
}

type SessionHandoffTaskV1 struct {
	TaskID      string `json:"taskId"`
	TaskAttempt int64  `json:"taskAttempt"`
}

type SessionHandoffWorkV1 struct {
	WorkID           string `json:"workId"`
	ExpectedRevision int64  `json:"expectedRevision"`
	BindingID        string `json:"bindingId"`
	BindingRevision  int64  `json:"bindingRevision"`
}

func ValidateSessionHandoffV1(value SessionHandoffV1, now time.Time) error {
	identity := value.Identity
	source := value.Source
	validRole := identity.Role == "worker" || identity.Role == "reviewer" || identity.Role == "manager"
	nativeProject := source.NativeProjectID == "global" || regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(source.NativeProjectID)
	if value.FormatVersion != 1 || value.Action != "open_session" ||
		!continuityIDPattern.MatchString(value.HandoffID) || value.IssuedAt.IsZero() || value.ExpiresAt.IsZero() ||
		!value.ExpiresAt.After(value.IssuedAt) || value.ExpiresAt.Sub(value.IssuedAt) > 120*time.Second ||
		now.Before(value.IssuedAt) || !now.Before(value.ExpiresAt) ||
		!continuityIDPattern.MatchString(identity.ServerID) || !continuityIDPattern.MatchString(identity.TeamID) ||
		!continuityIDPattern.MatchString(identity.MemberID) || !continuityIDPattern.MatchString(identity.SandboxID) ||
		identity.SandboxGeneration < 1 || !continuityIDPattern.MatchString(identity.ServiceRegistrationID) ||
		identity.ServiceGeneration < 1 || !continuityIDPattern.MatchString(identity.Instance) || !validRole ||
		!continuityIDPattern.MatchString(identity.ProjectID) || !continuityIDPattern.MatchString(identity.WorkspaceEpoch) ||
		identity.ProfileID != "opencode" || identity.ProfileRevision < 1 ||
		!setupDigestPattern.MatchString(identity.ProfileDigest) || identity.InstructionRevision < 1 ||
		!setupDigestPattern.MatchString(identity.InstructionDigest) ||
		!continuityIDPattern.MatchString(source.RegisteredSourceID) ||
		!continuityIDPattern.MatchString(source.NativeSessionID) || !nativeProject ||
		!setupDigestPattern.MatchString(source.NativeLocationDigest) {
		return errors.New("invalid session handoff")
	}
	if value.Task != nil && (!continuityIDPattern.MatchString(value.Task.TaskID) || value.Task.TaskAttempt < 1) {
		return errors.New("invalid session handoff task")
	}
	if value.Work != nil && (!continuityIDPattern.MatchString(value.Work.WorkID) || value.Work.ExpectedRevision < 1 ||
		!continuityIDPattern.MatchString(value.Work.BindingID) || value.Work.BindingRevision < 1) {
		return errors.New("invalid session handoff Work")
	}
	return nil
}

type ContinuityRegistrationReportV1 struct {
	ContinuityRegistrationV1
	ObservedStatus    string     `json:"observedStatus"`
	ServiceGeneration int64      `json:"serviceGeneration"`
	ReceiptDigest     string     `json:"receiptDigest"`
	LastError         *ItemError `json:"lastError,omitempty"`
}

type ContinuityOperationReportV1 struct {
	FormatVersion  int                  `json:"formatVersion"`
	OperationID    string               `json:"operationId"`
	Action         string               `json:"action"`
	ScopeRevision  int64                `json:"scopeRevision"`
	BoundaryKind   string               `json:"boundaryKind"`
	Identity       ContinuityIdentityV1 `json:"identity"`
	Binding        ContinuityBindingV1  `json:"binding"`
	Status         string               `json:"status"`
	CheckpointID   string               `json:"checkpointId,omitempty"`
	CaptureID      string               `json:"captureId,omitempty"`
	ManifestDigest string               `json:"manifestDigest,omitempty"`
	Bytes          int64                `json:"bytes,omitempty"`
	ObjectCount    int                  `json:"objectCount,omitempty"`
	ReceiptDigest  string               `json:"receiptDigest,omitempty"`
	LastError      *ItemError           `json:"lastError,omitempty"`
	// RequestDigest is host-private replay state. The shared report contract
	// deliberately omits it, while SQLite retains it to reject conflicting use
	// of an operation ID.
	RequestDigest string `json:"-"`
}

// MarshalJSON keeps the accepted-only fields on the wire even when their values
// are zero. The shared contract requires checkpointId, captureId, manifestDigest,
// bytes, objectCount and receiptDigest exactly for accepted reports (and forbids
// them otherwise), so plain omitempty tags would silently drop a zero-byte or
// zero-object capture and the control plane rejects the whole report.
func (value ContinuityOperationReportV1) MarshalJSON() ([]byte, error) {
	type alias ContinuityOperationReportV1
	if value.Status != "accepted" {
		return json.Marshal(alias(value))
	}
	return json.Marshal(struct {
		alias
		CheckpointID   string `json:"checkpointId"`
		CaptureID      string `json:"captureId"`
		ManifestDigest string `json:"manifestDigest"`
		Bytes          int64  `json:"bytes"`
		ObjectCount    int    `json:"objectCount"`
		ReceiptDigest  string `json:"receiptDigest,omitempty"`
	}{
		alias:          alias(value),
		CheckpointID:   value.CheckpointID,
		CaptureID:      value.CaptureID,
		ManifestDigest: value.ManifestDigest,
		Bytes:          value.Bytes,
		ObjectCount:    value.ObjectCount,
		ReceiptDigest:  value.ReceiptDigest,
	})
}

// ProjectCatalogReportV1 is safe to publish to the control plane. Filesystem
// paths and filesystem identity values deliberately remain in host-private
// state.
type ProjectCatalogReportV1 struct {
	FormatVersion         int       `json:"formatVersion"`
	SelectionID           string    `json:"selectionId"`
	ProjectID             string    `json:"projectId"`
	WorkspaceEpoch        string    `json:"workspaceEpoch"`
	SandboxID             string    `json:"sandboxId"`
	SandboxGeneration     int64     `json:"sandboxGeneration"`
	ServiceRegistrationID *string   `json:"serviceRegistrationId"`
	Designation           string    `json:"designation"`
	Label                 string    `json:"label"`
	Availability          string    `json:"availability"`
	Reason                *string   `json:"reason"`
	RootAttestation       string    `json:"rootAttestation"`
	LastObservedAt        time.Time `json:"lastObservedAt"`
}

type ManagedWorkspaceRequestV1 struct {
	FormatVersion         int    `json:"formatVersion"`
	OperationID           string `json:"operationId"`
	ActionRevision        int64  `json:"actionRevision"`
	DesiredRevision       int64  `json:"desiredRevision"`
	AllocationDigest      string `json:"allocationDigest"`
	Request               string `json:"request"`
	ServerID              string `json:"serverId"`
	TeamID                string `json:"teamId"`
	MemberID              string `json:"memberId"`
	SandboxID             string `json:"sandboxId"`
	SandboxGeneration     int64  `json:"sandboxGeneration"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
}

type ManagedServiceIdentityV1 struct {
	ServerID                  string `json:"serverId"`
	TeamID                    string `json:"teamId"`
	MemberID                  string `json:"memberId"`
	SandboxID                 string `json:"sandboxId"`
	SandboxGeneration         int64  `json:"sandboxGeneration"`
	ServiceRegistrationID     string `json:"serviceRegistrationId"`
	ExpectedServiceGeneration int64  `json:"expectedServiceGeneration"`
	Instance                  string `json:"instance"`
	Role                      string `json:"role"`
}

type ManagedServiceProfileV1 struct {
	SetupOperationID string `json:"setupOperationId"`
	ProfileID        string `json:"profileId"`
	ProfileRevision  int64  `json:"profileRevision"`
	ProfileDigest    string `json:"profileDigest"`
}

type ManagedServiceInstructionsV1 struct {
	InstructionRevision int64  `json:"instructionRevision"`
	InstructionDigest   string `json:"instructionDigest"`
}

type ManagedServiceWorkspaceV1 struct {
	SelectionID     string `json:"selectionId"`
	ProjectID       string `json:"projectId"`
	WorkspaceEpoch  string `json:"workspaceEpoch"`
	ScopeRevision   int64  `json:"scopeRevision"`
	Designation     string `json:"designation"`
	RootAttestation string `json:"rootAttestation"`
}

// ManagedServiceProcessInstance derives the fixed supervisor process-instance
// identity for one logical managed-service instance and service generation. The
// reconciliation writer stores exactly this value and the session-handoff gate
// accepts exactly this value, so the two can never drift.
func ManagedServiceProcessInstance(instance string, serviceGeneration int64) string {
	return fmt.Sprintf("wmsup-%s-%04d", instance, serviceGeneration)
}

// ManagedServiceAuthorityV1 carries only the non-secret Team authority needed
// to bind the managed native service. Credential material and credential
// references remain owned by the native provider connection inside the box.
type ManagedServiceAuthorityV1 struct {
	TeamRevision int64   `json:"teamRevision"`
	ProviderID   string  `json:"providerId"`
	ModelID      *string `json:"modelId"`
	AuthMode     *string `json:"authMode"`
}

type ManagedServiceV1 struct {
	FormatVersion   int                          `json:"formatVersion"`
	OperationID     string                       `json:"operationId"`
	ActionRevision  int64                        `json:"actionRevision"`
	DesiredRevision int64                        `json:"desiredRevision"`
	ConfigDigest    string                       `json:"configDigest"`
	DesiredState    string                       `json:"desiredState"`
	SessionMode     string                       `json:"sessionMode"`
	Authority       *ManagedServiceAuthorityV1   `json:"authority,omitempty"`
	Identity        ManagedServiceIdentityV1     `json:"identity"`
	Profile         ManagedServiceProfileV1      `json:"profile"`
	Instructions    ManagedServiceInstructionsV1 `json:"instructions"`
	Workspace       ManagedServiceWorkspaceV1    `json:"workspace"`
}

type ManagedNativeRegistrationV1 struct {
	RegisteredSourceID   string `json:"registeredSourceId"`
	WorkspaceEpoch       string `json:"workspaceEpoch"`
	NativeSessionID      string `json:"nativeSessionId"`
	NativeProjectID      string `json:"nativeProjectId"`
	NativeLocationDigest string `json:"nativeLocationDigest"`
}

type ManagedServiceErrorV1 struct {
	Code string `json:"code"`
}

type ManagedServiceReportV1 struct {
	FormatVersion           int                          `json:"formatVersion"`
	OperationID             string                       `json:"operationId"`
	ActionRevision          int64                        `json:"actionRevision"`
	ObservedDesiredRevision int64                        `json:"observedDesiredRevision"`
	ConfigDigest            string                       `json:"configDigest"`
	ObservedState           string                       `json:"observedState"`
	Identity                ManagedServiceIdentityV1     `json:"identity"`
	ServiceGeneration       int64                        `json:"serviceGeneration"`
	ProfileStatus           string                       `json:"profileStatus"`
	WorkspaceStatus         string                       `json:"workspaceStatus"`
	EnrollmentStatus        string                       `json:"enrollmentStatus"`
	WorkerStatus            string                       `json:"workerStatus"`
	InstructionApplied      bool                         `json:"instructionApplied"`
	InstructionRevision     int64                        `json:"instructionRevision"`
	InstructionDigest       string                       `json:"instructionDigest"`
	NativeRegistration      *ManagedNativeRegistrationV1 `json:"nativeRegistration,omitempty"`
	ReceiptDigest           string                       `json:"receiptDigest"`
	LastError               *ManagedServiceErrorV1       `json:"lastError,omitempty"`
}

type ManagedServiceFetchRequestV1 struct {
	FormatVersion         int    `json:"formatVersion"`
	OperationID           string `json:"operationId"`
	ActionRevision        int64  `json:"actionRevision"`
	DesiredRevision       int64  `json:"desiredRevision"`
	ConfigDigest          string `json:"configDigest"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
	ServiceGeneration     int64  `json:"serviceGeneration"`
	SandboxID             string `json:"sandboxId"`
	SandboxGeneration     int64  `json:"sandboxGeneration"`
	ProcessInstance       string `json:"processInstance"`
}

type ManagedServiceEnrollmentV1 struct {
	EnrollmentID        string    `json:"enrollmentId"`
	EnrollmentToken     string    `json:"enrollmentToken"`
	EnrollmentExpiresAt time.Time `json:"enrollmentExpiresAt"`
	ExchangePath        string    `json:"exchangePath"`
}

type ManagedServiceInstructionV1 struct {
	InstructionRevision int64     `json:"instructionRevision"`
	InstructionDigest   string    `json:"instructionDigest"`
	Content             string    `json:"content"`
	ExpiresAt           time.Time `json:"expiresAt"`
}

// Insights v1 is a closed metadata-only transport. These types deliberately
// have no field capable of carrying native event bodies, prompts, commands,
// paths, or credentials.
type InsightPolicyEnvelopeV1 struct {
	Policies []InsightPolicyV1 `json:"policies"`
}

type InsightPolicyV1 struct {
	SandboxID string                  `json:"sandboxId"`
	Revision  int64                   `json:"revision"`
	Enabled   bool                    `json:"enabled"`
	ExpiresAt time.Time               `json:"expiresAt"`
	Sources   []InsightPolicySourceV1 `json:"sources"`
}

type InsightPolicySourceV1 struct {
	RegisteredSourceID    string `json:"registeredSourceId"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
	SandboxGeneration     int64  `json:"sandboxGeneration"`
	ServiceGeneration     int64  `json:"serviceGeneration"`
	WorkspaceEpoch        string `json:"workspaceEpoch"`
	NativeSessionID       string `json:"nativeSessionId"`
}

type InsightRecoveryV1 struct {
	Predicate   string `json:"predicate"`
	Sequence    int64  `json:"sequence"`
	ReferenceID string `json:"referenceId"`
}

type InsightFindingV1 struct {
	FindingID        string             `json:"findingId"`
	RuleID           string             `json:"ruleId"`
	State            string             `json:"state"`
	Revision         int64              `json:"revision"`
	FirstSequence    int64              `json:"firstSequence"`
	LastSequence     int64              `json:"lastSequence"`
	Count            int64              `json:"count"`
	Threshold        int64              `json:"threshold"`
	MatchedCallIDs   []string           `json:"matchedCallIds"`
	FirstObservedAt  time.Time          `json:"firstObservedAt"`
	LastObservedAt   time.Time          `json:"lastObservedAt"`
	Coverage         string             `json:"coverage"`
	ToolCategory     string             `json:"toolCategory"`
	Phase            string             `json:"phase"`
	PhaseStartedAt   *time.Time         `json:"phaseStartedAt"`
	LastProgressAt   *time.Time         `json:"lastProgressAt"`
	HealthObservedAt *time.Time         `json:"healthObservedAt"`
	StallThresholdMS *int64             `json:"stallThresholdMs"`
	Recovery         *InsightRecoveryV1 `json:"recovery"`
}

type InsightBatchV1 struct {
	FormatVersion         int                `json:"formatVersion"`
	BatchID               string             `json:"batchId"`
	SandboxID             string             `json:"sandboxId"`
	SandboxGeneration     int64              `json:"sandboxGeneration"`
	PolicyRevision        int64              `json:"policyRevision"`
	RegisteredSourceID    string             `json:"registeredSourceId"`
	ServiceRegistrationID string             `json:"serviceRegistrationId"`
	ServiceGeneration     int64              `json:"serviceGeneration"`
	WorkspaceEpoch        string             `json:"workspaceEpoch"`
	NativeSessionID       string             `json:"nativeSessionId"`
	JournalGeneration     string             `json:"journalGeneration"`
	ThroughSequence       int64              `json:"throughSequence"`
	ObservedAt            time.Time          `json:"observedAt"`
	Status                string             `json:"status"`
	GapReason             *string            `json:"gapReason"`
	Findings              []InsightFindingV1 `json:"findings"`
}

type InsightBatchReceiptV1 struct {
	BatchID         string `json:"batchId"`
	Accepted        int    `json:"accepted"`
	ThroughSequence int64  `json:"throughSequence"`
}

// Agent Manager v1 is a closed metadata-only control surface. It deliberately
// cannot carry prompts, evidence excerpts, provider messages, paths, commands,
// URLs, or credentials.
type InsightsManagerSourceV1 struct {
	RegisteredSourceID    string `json:"registeredSourceId"`
	WorkspaceEpoch        string `json:"workspaceEpoch"`
	NativeSessionID       string `json:"nativeSessionId"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
	ServiceGeneration     int64  `json:"serviceGeneration"`
	SandboxGeneration     int64  `json:"sandboxGeneration"`
	ProfileRevision       int64  `json:"profileRevision"`
	InstructionRevision   int64  `json:"instructionRevision"`
}

type InsightsManagerTargetV1 struct {
	TeamID          string  `json:"teamId"`
	MemberID        string  `json:"memberId"`
	TaskID          *string `json:"taskId"`
	TaskAttempt     *int64  `json:"taskAttempt"`
	WorkID          *string `json:"workId"`
	WorkRevision    *int64  `json:"workRevision"`
	BindingID       *string `json:"bindingId"`
	BindingRevision *int64  `json:"bindingRevision"`
}

type InsightsManagerProfileV1 struct {
	ProfileID       string `json:"profileId"`
	ProfileRevision int64  `json:"profileRevision"`
	ProfileDigest   string `json:"profileDigest"`
}

type InsightsManagerBudgetV1 struct {
	ModelRequests int   `json:"modelRequests"`
	InputTokens   int64 `json:"inputTokens"`
	OutputTokens  int64 `json:"outputTokens"`
}

type InsightsManagerEffectiveLimitsV1 struct {
	SandboxDailyRuns       int   `json:"sandboxDailyRuns"`
	SandboxHourlyRuns      int   `json:"sandboxHourlyRuns"`
	SessionRuns24h         int   `json:"sessionRuns24h"`
	SessionCooldownSeconds int   `json:"sessionCooldownSeconds"`
	ServerConcurrentRuns   int   `json:"serverConcurrentRuns"`
	ServerHourlyStarts     int   `json:"serverHourlyStarts"`
	PerRunModelRequests    int   `json:"perRunModelRequests"`
	PerRunInputTokens      int64 `json:"perRunInputTokens"`
	PerRunOutputTokens     int64 `json:"perRunOutputTokens"`
}

type InsightsManagerPolicyManifestV1 struct {
	FormatVersion         int                              `json:"formatVersion"`
	SandboxID             string                           `json:"sandboxId"`
	SandboxGeneration     int64                            `json:"sandboxGeneration"`
	PolicyRevision        int64                            `json:"policyRevision"`
	Mode                  string                           `json:"mode"`
	AllowedRules          []string                         `json:"allowedRules"`
	DailyRunLimit         int                              `json:"dailyRunLimit"`
	DailyInputTokenLimit  int64                            `json:"dailyInputTokenLimit"`
	DailyOutputTokenLimit int64                            `json:"dailyOutputTokenLimit"`
	EffectiveLimits       InsightsManagerEffectiveLimitsV1 `json:"effectiveLimits"`
	ManagerProfile        InsightsManagerProfileV1         `json:"managerProfile"`
	ValidUntil            time.Time                        `json:"validUntil"`
	RunGeneration         int64                            `json:"runGeneration"`
	AutoSteerAvailable    bool                             `json:"autoSteerAvailable"`
}

// InsightsManagerFindingEvidenceV1 is the bounded Sandbox finding-evidence
// descriptor: the same 14 metadata keys the helper request carries. An
// authenticated manual review manifest may carry one canonical snapshot when
// the original acknowledged batch record no longer exists locally; it is
// reservation evidence, not a manufactured observation history.
type InsightsManagerFindingEvidenceV1 struct {
	FindingID         string    `json:"findingId"`
	FindingRevision   int64     `json:"findingRevision"`
	JournalGeneration string    `json:"journalGeneration"`
	RuleID            string    `json:"ruleId"`
	NativeSessionID   string    `json:"nativeSessionId"`
	FirstSequence     int64     `json:"firstSequence"`
	LastSequence      int64     `json:"lastSequence"`
	Count             int64     `json:"count"`
	MatchedCallIDs    []string  `json:"matchedCallIds"`
	Coverage          string    `json:"coverage"`
	FirstObservedAt   time.Time `json:"firstObservedAt"`
	LastObservedAt    time.Time `json:"lastObservedAt"`
	ToolCategory      string    `json:"toolCategory"`
	Phase             string    `json:"phase"`
}

type InsightsManagerReviewManifestV1 struct {
	FormatVersion       int                               `json:"formatVersion"`
	ReservationID       string                            `json:"reservationId"`
	RunID               string                            `json:"runId"`
	Manual              bool                              `json:"manual"`
	FindingID           string                            `json:"findingId"`
	FindingRevision     int64                             `json:"findingRevision"`
	PolicyRevision      int64                             `json:"policyRevision"`
	RuleID              string                            `json:"ruleId"`
	RecipeID            string                            `json:"recipeId"`
	ProviderRouteDigest string                            `json:"providerRouteDigest"`
	ManagerProfile      InsightsManagerProfileV1          `json:"managerProfile"`
	Source              InsightsManagerSourceV1           `json:"source"`
	Target              InsightsManagerTargetV1           `json:"target"`
	Budget              InsightsManagerBudgetV1           `json:"budget"`
	FindingEvidence     *InsightsManagerFindingEvidenceV1 `json:"findingEvidence,omitempty"`
	ValidUntil          time.Time                         `json:"validUntil"`
}

type InsightsManagerReservationRequestV1 struct {
	FormatVersion       int                     `json:"formatVersion"`
	ReservationID       string                  `json:"reservationId"`
	RequestID           string                  `json:"requestId"`
	Manual              bool                    `json:"manual"`
	FindingID           string                  `json:"findingId"`
	FindingRevision     int64                   `json:"findingRevision"`
	PolicyRevision      int64                   `json:"policyRevision"`
	RuleID              string                  `json:"ruleId"`
	RecipeID            string                  `json:"recipeId"`
	ProviderRouteDigest string                  `json:"providerRouteDigest"`
	Source              InsightsManagerSourceV1 `json:"source"`
	Target              InsightsManagerTargetV1 `json:"target"`
	Budget              InsightsManagerBudgetV1 `json:"budget"`
	ExpiresInSeconds    int                     `json:"expiresInSeconds"`
}

type InsightsManagerReservationExecutionV1 struct {
	ProviderRouteDigest string                   `json:"providerRouteDigest"`
	ManagerProfile      InsightsManagerProfileV1 `json:"managerProfile"`
}

type InsightsManagerRemainingV1 struct {
	SandboxDailyRuns         int   `json:"sandboxDailyRuns"`
	SandboxHourlyRuns        int   `json:"sandboxHourlyRuns"`
	SandboxDailyInputTokens  int64 `json:"sandboxDailyInputTokens"`
	SandboxDailyOutputTokens int64 `json:"sandboxDailyOutputTokens"`
	SessionRuns24h           int   `json:"sessionRuns24h"`
	SessionCooldownSeconds   int   `json:"sessionCooldownSeconds"`
	ServerConcurrentRuns     int   `json:"serverConcurrentRuns"`
	ServerHourlyStarts       int   `json:"serverHourlyStarts"`
}

type InsightsManagerReservationV1 struct {
	FormatVersion   int                                   `json:"formatVersion"`
	ReservationID   string                                `json:"reservationId"`
	RunID           string                                `json:"runId"`
	RequestID       string                                `json:"requestId"`
	Manual          bool                                  `json:"manual"`
	State           string                                `json:"state"`
	FindingID       string                                `json:"findingId"`
	FindingRevision int64                                 `json:"findingRevision"`
	PolicyRevision  int64                                 `json:"policyRevision"`
	Source          InsightsManagerSourceV1               `json:"source"`
	Target          InsightsManagerTargetV1               `json:"target"`
	ExpiresAt       time.Time                             `json:"expiresAt"`
	ReservedBudget  InsightsManagerBudgetV1               `json:"reservedBudget"`
	Execution       InsightsManagerReservationExecutionV1 `json:"execution"`
	Remaining       InsightsManagerRemainingV1            `json:"remaining"`
}

type InsightsManagerCapabilityV1 struct {
	Available bool    `json:"available"`
	Reason    *string `json:"reason"`
}

type InsightsManagerRecommendCapabilityV1 struct {
	Source              InsightsManagerSourceV1  `json:"source"`
	ProviderRouteDigest string                   `json:"providerRouteDigest"`
	ProviderID          string                   `json:"providerId"`
	ModelID             string                   `json:"modelId"`
	Protocol            string                   `json:"protocol"`
	RecipeIDs           []string                 `json:"recipeIds"`
	MaxInputTokens      int64                    `json:"maxInputTokens"`
	MaxOutputTokens     int64                    `json:"maxOutputTokens"`
	ToolsAllowed        bool                     `json:"toolsAllowed"`
	MediaAllowed        bool                     `json:"mediaAllowed"`
	ManagerProfile      InsightsManagerProfileV1 `json:"managerProfile"`
	Available           bool                     `json:"available"`
	Reason              *string                  `json:"reason"`
}

type InsightsManagerPolicyReportV1 struct {
	FormatVersion         int                                    `json:"formatVersion"`
	SandboxID             string                                 `json:"sandboxId"`
	SandboxGeneration     int64                                  `json:"sandboxGeneration"`
	PolicyRevision        int64                                  `json:"policyRevision"`
	RunGeneration         int64                                  `json:"runGeneration"`
	Status                string                                 `json:"status"`
	Recommend             InsightsManagerCapabilityV1            `json:"recommend"`
	RecommendCapabilities []InsightsManagerRecommendCapabilityV1 `json:"recommendCapabilities"`
	ReceiptDigest         string                                 `json:"receiptDigest"`
	ErrorCode             *string                                `json:"errorCode"`
}

type InsightsManagerProposalV1 struct {
	RecipeID       string  `json:"recipeId"`
	Outcome        string  `json:"outcome"`
	RationaleCode  string  `json:"rationaleCode"`
	FirstSequence  int64   `json:"firstSequence"`
	LastSequence   int64   `json:"lastSequence"`
	GuidanceDigest *string `json:"guidanceDigest"`
}

type InsightsManagerSessionV1 struct {
	NativeSessionID       string                   `json:"nativeSessionId"`
	NativeProjectID       string                   `json:"nativeProjectId"`
	NativeLocationDigest  string                   `json:"nativeLocationDigest"`
	ServiceRegistrationID string                   `json:"serviceRegistrationId"`
	ServiceGeneration     int64                    `json:"serviceGeneration"`
	ProviderRouteDigest   string                   `json:"providerRouteDigest"`
	ManagerProfile        InsightsManagerProfileV1 `json:"managerProfile"`
}

type InsightsManagerUsageV1 struct {
	ModelRequests int    `json:"modelRequests"`
	InputTokens   int64  `json:"inputTokens"`
	OutputTokens  int64  `json:"outputTokens"`
	UsageCertain  bool   `json:"usageCertain"`
	UnusedProof   string `json:"unusedProof"`
}

type InsightsManagerRunReportV1 struct {
	FormatVersion  int                        `json:"formatVersion"`
	ReservationID  string                     `json:"reservationId"`
	RunID          string                     `json:"runId"`
	Manual         bool                       `json:"manual"`
	State          string                     `json:"state"`
	PolicyRevision int64                      `json:"policyRevision"`
	Source         InsightsManagerSourceV1    `json:"source"`
	Target         InsightsManagerTargetV1    `json:"target"`
	Proposal       *InsightsManagerProposalV1 `json:"proposal"`
	ManagerSession *InsightsManagerSessionV1  `json:"managerSession"`
	Usage          InsightsManagerUsageV1     `json:"usage"`
	ReceiptDigest  string                     `json:"receiptDigest"`
	ErrorCode      *string                    `json:"errorCode"`
}

type InsightsManagerActivitySessionV1 struct {
	Capability string  `json:"capability"`
	Reason     *string `json:"reason"`
}

type InsightsManagerActivityV1 struct {
	RunID          string                           `json:"runId"`
	ReservationID  string                           `json:"reservationId"`
	RequestID      string                           `json:"requestId"`
	Manual         bool                             `json:"manual"`
	FindingID      string                           `json:"findingId"`
	RuleID         string                           `json:"ruleId"`
	RecipeID       string                           `json:"recipeId"`
	Source         InsightsManagerSourceV1          `json:"source"`
	Target         InsightsManagerTargetV1          `json:"target"`
	State          string                           `json:"state"`
	RationaleCode  *string                          `json:"rationaleCode"`
	ErrorCode      *string                          `json:"errorCode"`
	ModelRequests  int                              `json:"modelRequests"`
	InputTokens    int64                            `json:"inputTokens"`
	OutputTokens   int64                            `json:"outputTokens"`
	ManagerSession InsightsManagerActivitySessionV1 `json:"managerSession"`
	CreatedAt      time.Time                        `json:"createdAt"`
	UpdatedAt      time.Time                        `json:"updatedAt"`
}

type InsightsTakeoverManifestV1 struct {
	FormatVersion          int                     `json:"formatVersion"`
	OperationID            string                  `json:"operationId"`
	PredecessorOperationID *string                 `json:"predecessorOperationId"`
	Action                 string                  `json:"action"`
	FindingID              string                  `json:"findingId"`
	FindingRevision        int64                   `json:"findingRevision"`
	PolicyRevision         int64                   `json:"policyRevision"`
	RunGeneration          int64                   `json:"runGeneration"`
	HoldID                 string                  `json:"holdId"`
	HoldRevision           int64                   `json:"holdRevision"`
	HoldState              string                  `json:"holdState"`
	Source                 InsightsManagerSourceV1 `json:"source"`
	Target                 InsightsManagerTargetV1 `json:"target"`
	ValidUntil             time.Time               `json:"validUntil"`
}

type InsightsTakeoverPendingInputV1 struct {
	State           string `json:"state"`
	AlreadyConsumed bool   `json:"alreadyConsumed"`
}

type InsightsTakeoverReportV1 struct {
	FormatVersion          int                            `json:"formatVersion"`
	OperationID            string                         `json:"operationId"`
	PredecessorOperationID *string                        `json:"predecessorOperationId"`
	Action                 string                         `json:"action"`
	FindingID              string                         `json:"findingId"`
	FindingRevision        int64                          `json:"findingRevision"`
	PolicyRevision         int64                          `json:"policyRevision"`
	RunGeneration          int64                          `json:"runGeneration"`
	HoldID                 string                         `json:"holdId"`
	HoldRevision           int64                          `json:"holdRevision"`
	HoldState              string                         `json:"holdState"`
	Source                 InsightsManagerSourceV1        `json:"source"`
	Target                 InsightsManagerTargetV1        `json:"target"`
	Status                 string                         `json:"status"`
	PendingInput           InsightsTakeoverPendingInputV1 `json:"pendingInput"`
	ReceiptDigest          string                         `json:"receiptDigest"`
	ErrorCode              *string                        `json:"errorCode"`
}

// ContinuationIdentityV1 is the closed S2 continuation/restore identity. It is
// deliberately distinct from the capture identity because taskId and
// taskAttempt are not part of the continuation wire contract.
type ContinuationIdentityV1 struct {
	WorkID            string `json:"workId"`
	ProjectID         string `json:"projectId"`
	SandboxID         string `json:"sandboxId"`
	WorkspaceEpoch    string `json:"workspaceEpoch"`
	SandboxGeneration int64  `json:"sandboxGeneration"`
	ExpectedRevision  int64  `json:"expectedRevision"`
}

type ContinuationBindingRefV1 struct {
	BindingID             string `json:"bindingId"`
	BindingRevision       int64  `json:"bindingRevision"`
	ScopeRevision         int64  `json:"scopeRevision"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
	ServiceGeneration     int64  `json:"serviceGeneration"`
	RegisteredSourceID    string `json:"registeredSourceId"`
	NativeSessionID       string `json:"nativeSessionId"`
	NativeProjectID       string `json:"nativeProjectId"`
	NativeLocationDigest  string `json:"nativeLocationDigest"`
}

type ContinuationCheckpointRefV1 struct {
	OperationID    string `json:"operationId"`
	CheckpointID   string `json:"checkpointId"`
	ManifestDigest string `json:"manifestDigest"`
	Bytes          int64  `json:"bytes"`
	ObjectCount    int    `json:"objectCount"`
}

type ContinuationTargetV1 struct {
	TeamID                 string `json:"teamId"`
	TeamRevision           int64  `json:"teamRevision"`
	PolicyRevision         int64  `json:"policyRevision"`
	MemberID               string `json:"memberId"`
	SandboxID              string `json:"sandboxId"`
	SandboxGeneration      int64  `json:"sandboxGeneration"`
	ServiceRegistrationID  string `json:"serviceRegistrationId"`
	ServiceGeneration      int64  `json:"serviceGeneration"`
	ServiceDesiredRevision int64  `json:"serviceDesiredRevision"`
	ServiceActionRevision  int64  `json:"serviceActionRevision"`
	SelectionID            string `json:"selectionId"`
	ProjectID              string `json:"projectId"`
	WorkspaceEpoch         string `json:"workspaceEpoch"`
	ScopeRevision          int64  `json:"scopeRevision"`
	RootAttestation        string `json:"rootAttestation"`
	ProfileID              string `json:"profileId"`
	ProfileRevision        int64  `json:"profileRevision"`
	ProfileDigest          string `json:"profileDigest"`
	InstructionRevision    int64  `json:"instructionRevision"`
	InstructionDigest      string `json:"instructionDigest"`
	Role                   string `json:"role"`
}

type ContinuationContextV1 struct {
	Digest          string `json:"digest"`
	Bytes           int    `json:"bytes"`
	TokenUpperBound int    `json:"tokenUpperBound"`
}

type ContinuationManifestV1 struct {
	FormatVersion   int                         `json:"formatVersion"`
	OperationID     string                      `json:"operationId"`
	Action          string                      `json:"action"`
	DesiredRevision int64                       `json:"desiredRevision"`
	Identity        ContinuationIdentityV1      `json:"identity"`
	Binding         ContinuationBindingRefV1    `json:"binding"`
	Checkpoint      ContinuationCheckpointRefV1 `json:"checkpoint"`
	Target          ContinuationTargetV1        `json:"target"`
	Context         ContinuationContextV1       `json:"context"`
}

type ContinuationBaselineV1 struct {
	BaselineID        string    `json:"baselineId"`
	BaselineDigest    string    `json:"baselineDigest"`
	NativeSessionID   string    `json:"nativeSessionId"`
	ServiceGeneration int64     `json:"serviceGeneration"`
	ReadyAt           time.Time `json:"readyAt"`
}

// ContinuationBaselineAuthorityV1 is the backend's single-use persisted
// authority tuple. It is carried to the worker with the task; the Runtime
// readiness receipt alone is never prompt admission authority.
type ContinuationBaselineAuthorityV1 struct {
	BaselineDigest        string `json:"baselineDigest"`
	BaselineID            string `json:"baselineId"`
	ContextDigest         string `json:"contextDigest"`
	DesiredRevision       int64  `json:"desiredRevision"`
	NativeSessionID       string `json:"nativeSessionId"`
	OperationID           string `json:"operationId"`
	ReceiptDigest         string `json:"receiptDigest"`
	ServiceGeneration     int64  `json:"serviceGeneration"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
}

type ContinuationReportV1 struct {
	FormatVersion   int                         `json:"formatVersion"`
	OperationID     string                      `json:"operationId"`
	Action          string                      `json:"action"`
	Status          string                      `json:"status"`
	DesiredRevision int64                       `json:"desiredRevision"`
	Identity        ContinuationIdentityV1      `json:"identity"`
	Binding         ContinuationBindingRefV1    `json:"binding"`
	Checkpoint      ContinuationCheckpointRefV1 `json:"checkpoint"`
	Target          ContinuationTargetV1        `json:"target"`
	ContextDigest   string                      `json:"contextDigest"`
	Baseline        *ContinuationBaselineV1     `json:"baseline"`
	ReceiptDigest   string                      `json:"receiptDigest"`
	ErrorCode       *string                     `json:"errorCode"`
}

type ContinuationReleaseManifestV1 struct {
	FormatVersion   int                         `json:"formatVersion"`
	OperationID     string                      `json:"operationId"`
	Action          string                      `json:"action"`
	DesiredRevision int64                       `json:"desiredRevision"`
	Identity        ContinuationIdentityV1      `json:"identity"`
	Binding         ContinuationBindingRefV1    `json:"binding"`
	Checkpoint      ContinuationCheckpointRefV1 `json:"checkpoint"`
	Target          ContinuationTargetV1        `json:"target"`
	Context         ContinuationContextV1       `json:"context"`
	Reason          string                      `json:"reason"`
}

type ContinuationReleaseReportV1 struct {
	FormatVersion   int                         `json:"formatVersion"`
	OperationID     string                      `json:"operationId"`
	Action          string                      `json:"action"`
	DesiredRevision int64                       `json:"desiredRevision"`
	Identity        ContinuationIdentityV1      `json:"identity"`
	Binding         ContinuationBindingRefV1    `json:"binding"`
	Checkpoint      ContinuationCheckpointRefV1 `json:"checkpoint"`
	Target          ContinuationTargetV1        `json:"target"`
	Context         ContinuationContextV1       `json:"context"`
	Reason          string                      `json:"reason"`
	Status          string                      `json:"status"`
	ReceiptDigest   string                      `json:"receiptDigest"`
	ErrorCode       *string                     `json:"errorCode"`
}

// Continuation handoffs create a separate, checkpoint-backed native session
// under a current managed service. Paths remain host-private; every wire field
// below is an immutable authority fence shared with the backend and Sandbox.
type ContinuationHandoffLineageV1 struct {
	SourceWorkID          string  `json:"sourceWorkId"`
	SourceRevision        int64   `json:"sourceRevision"`
	SourceTaskID          *string `json:"sourceTaskId"`
	CheckpointOperationID string  `json:"checkpointOperationId"`
	RestoreOperationID    *string `json:"restoreOperationId"`
}

type ContinuationHandoffTargetPolicyV1 struct {
	TeamID                 string `json:"teamId"`
	TeamRevision           int64  `json:"teamRevision"`
	PolicyRevision         int64  `json:"policyRevision"`
	MemberID               string `json:"memberId"`
	Role                   string `json:"role"`
	SandboxID              string `json:"sandboxId"`
	SandboxGeneration      int64  `json:"sandboxGeneration"`
	ServiceRegistrationID  string `json:"serviceRegistrationId"`
	ServiceGeneration      int64  `json:"serviceGeneration"`
	ServiceDesiredRevision int64  `json:"serviceDesiredRevision"`
	ServiceActionRevision  int64  `json:"serviceActionRevision"`
	ProfileID              string `json:"profileId"`
	ProfileRevision        int64  `json:"profileRevision"`
	ProfileDigest          string `json:"profileDigest"`
	InstructionRevision    int64  `json:"instructionRevision"`
	InstructionDigest      string `json:"instructionDigest"`
}

type ContinuationHandoffWorkspaceRequestV1 struct {
	Mode               string  `json:"mode"`
	RestoreOperationID *string `json:"restoreOperationId"`
	SelectionID        *string `json:"selectionId"`
	ProjectID          *string `json:"projectId"`
	WorkspaceEpoch     *string `json:"workspaceEpoch"`
	ScopeRevision      *int64  `json:"scopeRevision"`
	RootAttestation    *string `json:"rootAttestation"`
}

type ContinuationHandoffTargetWorkspaceV1 struct {
	SelectionID     string `json:"selectionId"`
	ProjectID       string `json:"projectId"`
	WorkspaceEpoch  string `json:"workspaceEpoch"`
	ScopeRevision   int64  `json:"scopeRevision"`
	RootAttestation string `json:"rootAttestation"`
}

type ContinuationHandoffSessionV1 struct {
	MappingID            string `json:"mappingId"`
	RegisteredSourceID   string `json:"registeredSourceId"`
	NativeSessionID      string `json:"nativeSessionId"`
	NativeProjectID      string `json:"nativeProjectId"`
	NativeLocationDigest string `json:"nativeLocationDigest"`
	InstructionRevision  int64  `json:"instructionRevision"`
	InstructionDigest    string `json:"instructionDigest"`
	InstructionApplied   bool   `json:"instructionApplied"`
}

type ContinuationHandoffManifestV1 struct {
	FormatVersion   int                                   `json:"formatVersion"`
	OperationID     string                                `json:"operationId"`
	Action          string                                `json:"action"`
	DesiredRevision int64                                 `json:"desiredRevision"`
	HandoffKind     string                                `json:"handoffKind"`
	SessionMode     string                                `json:"sessionMode"`
	TargetWorkID    string                                `json:"targetWorkId"`
	MappingID       string                                `json:"mappingId"`
	Identity        ContinuationIdentityV1                `json:"identity"`
	Binding         ContinuationBindingRefV1              `json:"binding"`
	Checkpoint      ContinuationCheckpointRefV1           `json:"checkpoint"`
	Lineage         ContinuationHandoffLineageV1          `json:"lineage"`
	TargetPolicy    ContinuationHandoffTargetPolicyV1     `json:"targetPolicy"`
	Workspace       ContinuationHandoffWorkspaceRequestV1 `json:"workspace"`
	Context         ContinuationContextV1                 `json:"context"`
}

type ContinuationHandoffReportV1 struct {
	FormatVersion    int                                   `json:"formatVersion"`
	OperationID      string                                `json:"operationId"`
	Action           string                                `json:"action"`
	DesiredRevision  int64                                 `json:"desiredRevision"`
	HandoffKind      string                                `json:"handoffKind"`
	SessionMode      string                                `json:"sessionMode"`
	TargetWorkID     string                                `json:"targetWorkId"`
	MappingID        string                                `json:"mappingId"`
	Identity         ContinuationIdentityV1                `json:"identity"`
	Binding          ContinuationBindingRefV1              `json:"binding"`
	Checkpoint       ContinuationCheckpointRefV1           `json:"checkpoint"`
	Lineage          ContinuationHandoffLineageV1          `json:"lineage"`
	TargetPolicy     ContinuationHandoffTargetPolicyV1     `json:"targetPolicy"`
	WorkspaceRequest ContinuationHandoffWorkspaceRequestV1 `json:"workspaceRequest"`
	ContextDigest    string                                `json:"contextDigest"`
	Status           string                                `json:"status"`
	TargetWorkspace  *ContinuationHandoffTargetWorkspaceV1 `json:"targetWorkspace"`
	Session          *ContinuationHandoffSessionV1         `json:"session"`
	Baseline         *ContinuationBaselineV1               `json:"baseline"`
	ReceiptDigest    string                                `json:"receiptDigest"`
	ErrorCode        *string                               `json:"errorCode"`
}

type ContinuationHandoffReleaseManifestV1 struct {
	FormatVersion          int                                   `json:"formatVersion"`
	OperationID            string                                `json:"operationId"`
	Action                 string                                `json:"action"`
	DesiredRevision        int64                                 `json:"desiredRevision"`
	PrepareDesiredRevision int64                                 `json:"prepareDesiredRevision"`
	Reason                 string                                `json:"reason"`
	HandoffKind            string                                `json:"handoffKind"`
	SessionMode            string                                `json:"sessionMode"`
	TargetWorkID           string                                `json:"targetWorkId"`
	MappingID              string                                `json:"mappingId"`
	Identity               ContinuationIdentityV1                `json:"identity"`
	Binding                ContinuationBindingRefV1              `json:"binding"`
	Checkpoint             ContinuationCheckpointRefV1           `json:"checkpoint"`
	Lineage                ContinuationHandoffLineageV1          `json:"lineage"`
	TargetPolicy           ContinuationHandoffTargetPolicyV1     `json:"targetPolicy"`
	Workspace              ContinuationHandoffWorkspaceRequestV1 `json:"workspace"`
	Context                ContinuationContextV1                 `json:"context"`
}

type ContinuationHandoffReleaseReportV1 struct {
	ContinuationHandoffReleaseManifestV1
	Status        string  `json:"status"`
	ReceiptDigest string  `json:"receiptDigest"`
	ErrorCode     *string `json:"errorCode"`
}

type ContinuationTargetRegistrationV1 struct {
	FormatVersion           int                 `json:"formatVersion"`
	WorkID                  string              `json:"workId"`
	ProjectID               string              `json:"projectId"`
	SandboxID               string              `json:"sandboxId"`
	WorkspaceEpoch          string              `json:"workspaceEpoch"`
	SandboxGeneration       int64               `json:"sandboxGeneration"`
	TaskID                  *string             `json:"taskId"`
	TaskAttempt             *int64              `json:"taskAttempt"`
	ExpectedRevision        int64               `json:"expectedRevision"`
	BackgroundWriterState   string              `json:"backgroundWriterState"`
	LastAcceptedExecutionID *string             `json:"lastAcceptedExecutionId"`
	Binding                 ContinuityBindingV1 `json:"binding"`
}

type ContinuationTargetRegistrationRequestV1 struct {
	FormatVersion          int                              `json:"formatVersion"`
	Action                 string                           `json:"action"`
	Instance               string                           `json:"instance"`
	OperationID            string                           `json:"operationId"`
	PrepareDesiredRevision int64                            `json:"prepareDesiredRevision"`
	Registration           ContinuationTargetRegistrationV1 `json:"registration"`
}

type ContinuationTargetRegistrationReceiptV1 struct {
	FormatVersion    int                 `json:"formatVersion"`
	Action           string              `json:"action"`
	Status           string              `json:"status"`
	OperationID      string              `json:"operationId"`
	WorkID           string              `json:"workId"`
	ExpectedRevision int64               `json:"expectedRevision"`
	Binding          ContinuityBindingV1 `json:"binding"`
	ReceiptDigest    string              `json:"receiptDigest"`
}

type RestoreTargetV1 struct {
	Mode              string `json:"mode"`
	SandboxID         string `json:"sandboxId"`
	SandboxGeneration int64  `json:"sandboxGeneration"`
}

type RestoreManifestV1 struct {
	FormatVersion   int                         `json:"formatVersion"`
	OperationID     string                      `json:"operationId"`
	Action          string                      `json:"action"`
	DesiredRevision int64                       `json:"desiredRevision"`
	Identity        ContinuationIdentityV1      `json:"identity"`
	Binding         ContinuationBindingRefV1    `json:"binding"`
	Checkpoint      ContinuationCheckpointRefV1 `json:"checkpoint"`
	Target          RestoreTargetV1             `json:"target"`
}

type RestoreResultTargetV1 struct {
	SelectionID     string `json:"selectionId"`
	ProjectID       string `json:"projectId"`
	WorkspaceEpoch  string `json:"workspaceEpoch"`
	ScopeRevision   int64  `json:"scopeRevision"`
	RootAttestation string `json:"rootAttestation"`
}

type RestoreReportV1 struct {
	FormatVersion    int                         `json:"formatVersion"`
	OperationID      string                      `json:"operationId"`
	Action           string                      `json:"action"`
	Status           string                      `json:"status"`
	DesiredRevision  int64                       `json:"desiredRevision"`
	Identity         ContinuationIdentityV1      `json:"identity"`
	Binding          ContinuationBindingRefV1    `json:"binding"`
	Checkpoint       ContinuationCheckpointRefV1 `json:"checkpoint"`
	Target           *RestoreResultTargetV1      `json:"target"`
	DependencyStatus string                      `json:"dependencyStatus"`
	Exclusions       []string                    `json:"exclusions"`
	ReceiptDigest    string                      `json:"receiptDigest"`
	ErrorCode        *string                     `json:"errorCode"`
}

func (identity ContinuityIdentityV1) Equal(other ContinuityIdentityV1) bool {
	return identity.WorkID == other.WorkID && identity.ProjectID == other.ProjectID &&
		identity.SandboxID == other.SandboxID && identity.WorkspaceEpoch == other.WorkspaceEpoch &&
		identity.SandboxGeneration == other.SandboxGeneration &&
		equalStringPointer(identity.TaskID, other.TaskID) &&
		equalInt64Pointer(identity.TaskAttempt, other.TaskAttempt) &&
		identity.ExpectedRevision == other.ExpectedRevision
}

func equalStringPointer(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalInt64Pointer(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

// Keep the retired cliTools member inert during rolling upgrades without
// permitting arbitrary new sandbox controls through the closed manifest API.
func (sandbox *Sandbox) UnmarshalJSON(payload []byte) error {
	type wireSandbox Sandbox
	var decoded struct {
		wireSandbox
		LegacyTools json.RawMessage `json:"cliTools"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*sandbox = Sandbox(decoded.wireSandbox)
	return nil
}

type AccessGrant struct {
	ID             string `json:"id"`
	SandboxID      string `json:"sandboxId"`
	SSHPublicKey   string `json:"sshPublicKey"`
	SSHFingerprint string `json:"sshFingerprint"`
	DesiredState   string `json:"desiredState"`
}

type SetupArtifact struct {
	ID             string `json:"id"`
	Source         string `json:"source"`
	SHA256         string `json:"sha256"`
	Format         string `json:"format"`
	SizeBytes      int64  `json:"sizeBytes"`
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion"`
	InstallAs      string `json:"installAs"`
}

type SetupMaterializer struct {
	Kind      string                `json:"kind"`
	Platform  string                `json:"platform,omitempty"`
	Artifacts []SetupArtifact       `json:"artifacts,omitempty"`
	Bins      []string              `json:"bins,omitempty"`
	Launchers []SetupLauncher       `json:"launchers,omitempty"`
	Artifact  *SetupArchiveArtifact `json:"artifact,omitempty"`
	Bin       *SetupArchiveBin      `json:"bin,omitempty"`
}

type SetupLauncher struct {
	Bin         string            `json:"bin"`
	Kind        string            `json:"kind"`
	ArtifactID  string            `json:"artifactId"`
	Entrypoint  string            `json:"entrypoint"`
	Environment map[string]string `json:"environment"`
}

type SetupArchiveArtifact struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	SHA256    string `json:"sha256"`
	Integrity string `json:"integrity,omitempty"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"sizeBytes"`
}

type SetupArchiveBin struct {
	Name        string            `json:"name"`
	Member      string            `json:"member"`
	SHA256      string            `json:"sha256,omitempty"`
	Version     string            `json:"version,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

func (materializer SetupMaterializer) MarshalJSON() ([]byte, error) {
	switch materializer.Kind {
	case "npm-package-set":
		return json.Marshal(struct {
			Kind      string          `json:"kind"`
			Artifacts []SetupArtifact `json:"artifacts"`
			Bins      []string        `json:"bins"`
			Launchers []SetupLauncher `json:"launchers,omitempty"`
		}{materializer.Kind, materializer.Artifacts, materializer.Bins, materializer.Launchers})
	case "archive-binary":
		return json.Marshal(struct {
			Kind     string                `json:"kind"`
			Platform string                `json:"platform,omitempty"`
			Artifact *SetupArchiveArtifact `json:"artifact"`
			Bin      *SetupArchiveBin      `json:"bin"`
		}{materializer.Kind, materializer.Platform, materializer.Artifact, materializer.Bin})
	default:
		type raw SetupMaterializer
		return json.Marshal(raw(materializer))
	}
}

type SetupOperation struct {
	ID                string            `json:"id"`
	SchemaVersion     int               `json:"schemaVersion"`
	SandboxID         string            `json:"sandboxId"`
	SandboxGeneration int64             `json:"sandboxGeneration"`
	ProfileID         string            `json:"profileId"`
	ProfileRevision   int64             `json:"profileRevision"`
	ProfileDigest     string            `json:"profileDigest"`
	Materializer      SetupMaterializer `json:"materializer"`
}

type Manifest struct {
	ServerID                       string                                 `json:"serverId"`
	DesiredRevision                int64                                  `json:"desiredRevision"`
	ImageDigest                    string                                 `json:"imageDigest"`
	Capacity                       Resources                              `json:"capacity"`
	Sandboxes                      []Sandbox                              `json:"sandboxes"`
	AccessGrants                   []AccessGrant                          `json:"accessGrants"`
	SetupOperations                []SetupOperation                       `json:"setupOperations,omitempty"`
	ContinuityRegistrations        []ContinuityRegistrationV1             `json:"continuityRegistrations,omitempty"`
	ContinuityOperations           []ContinuityOperationV1                `json:"continuityOperations,omitempty"`
	ManagedWorkspaceRequests       []ManagedWorkspaceRequestV1            `json:"managedWorkspaceRequests,omitempty"`
	ManagedServices                []ManagedServiceV1                     `json:"managedServices,omitempty"`
	ContinuityContinuations        []ContinuationManifestV1               `json:"continuityContinuations,omitempty"`
	ContinuityContinuationReleases []ContinuationReleaseManifestV1        `json:"continuityContinuationReleases,omitempty"`
	ContinuityRestores             []RestoreManifestV1                    `json:"continuityRestores,omitempty"`
	ContinuityHandoffs             []ContinuationHandoffManifestV1        `json:"continuityHandoffs,omitempty"`
	ContinuityHandoffReleases      []ContinuationHandoffReleaseManifestV1 `json:"continuityHandoffReleases,omitempty"`
	InsightsManagerPolicies        []InsightsManagerPolicyManifestV1      `json:"insightsManagerPolicies,omitempty"`
	InsightsManagerReviews         []InsightsManagerReviewManifestV1      `json:"insightsManagerReviews,omitempty"`
	InsightsTakeovers              []InsightsTakeoverManifestV1           `json:"insightsTakeovers,omitempty"`
}

type ItemError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

type SandboxReport struct {
	ID                 string     `json:"id"`
	ObservedState      string     `json:"observedState"`
	ObservedGeneration int64      `json:"observedGeneration"`
	ImageDigest        string     `json:"imageDigest,omitempty"`
	StartedAt          *time.Time `json:"startedAt,omitempty"`
	ExpiresAt          *time.Time `json:"expiresAt,omitempty"`
	LastError          *ItemError `json:"lastError,omitempty"`
}

type GrantReport struct {
	ID            string     `json:"id"`
	ObservedState string     `json:"observedState"`
	LastError     *ItemError `json:"lastError,omitempty"`
}

type SetupOperationReport struct {
	ID                string     `json:"id"`
	SandboxID         string     `json:"sandboxId"`
	SandboxGeneration int64      `json:"sandboxGeneration"`
	ProfileID         string     `json:"profileId"`
	ProfileRevision   int64      `json:"profileRevision"`
	ProfileDigest     string     `json:"profileDigest"`
	Status            string     `json:"status"`
	ReceiptDigest     string     `json:"receiptDigest,omitempty"`
	LastError         *ItemError `json:"lastError,omitempty"`
}

type Report struct {
	ServerID                       string                               `json:"serverId"`
	AppliedRevision                int64                                `json:"appliedRevision"`
	SupervisorVersion              string                               `json:"supervisorVersion"`
	ImageDigest                    string                               `json:"imageDigest,omitempty"`
	HostKeys                       []HostKey                            `json:"hostKeys,omitempty"`
	LastError                      *ItemError                           `json:"lastError,omitempty"`
	Sandboxes                      []SandboxReport                      `json:"sandboxes"`
	AccessGrants                   []GrantReport                        `json:"accessGrants"`
	SetupOperations                []SetupOperationReport               `json:"setupOperations"`
	ContinuitySources              []ContinuitySourceReportV1           `json:"continuitySources"`
	ContinuityRegistrations        []ContinuityRegistrationReportV1     `json:"continuityRegistrations"`
	ContinuityOperations           []ContinuityOperationReportV1        `json:"continuityOperations"`
	ManagedWorkspaceSelections     []ProjectCatalogReportV1             `json:"managedWorkspaceSelections"`
	ManagedServices                []ManagedServiceReportV1             `json:"managedServices"`
	ContinuityContinuations        []ContinuationReportV1               `json:"continuityContinuations"`
	ContinuityContinuationReleases []ContinuationReleaseReportV1        `json:"continuityContinuationReleases"`
	ContinuityRestores             []RestoreReportV1                    `json:"continuityRestores"`
	ContinuityHandoffs             []ContinuationHandoffReportV1        `json:"continuityHandoffs"`
	ContinuityHandoffReleases      []ContinuationHandoffReleaseReportV1 `json:"continuityHandoffReleases"`
	InsightsManagerPolicies        []InsightsManagerPolicyReportV1      `json:"insightsManagerPolicies"`
	InsightsManagerReviews         []InsightsManagerRunReportV1         `json:"insightsManagerReviews"`
	InsightsTakeovers              []InsightsTakeoverReportV1           `json:"insightsTakeovers"`
}

type HostKey struct {
	Algorithm   string `json:"algorithm,omitempty"`
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func validInsightsManagerSource(value InsightsManagerSourceV1) bool {
	return continuityIDPattern.MatchString(value.RegisteredSourceID) && continuityIDPattern.MatchString(value.WorkspaceEpoch) &&
		continuityIDPattern.MatchString(value.NativeSessionID) && continuityIDPattern.MatchString(value.ServiceRegistrationID) &&
		value.ServiceGeneration > 0 && value.SandboxGeneration > 0 && value.ProfileRevision > 0 && value.InstructionRevision > 0
}

func validInsightsManagerTarget(value InsightsManagerTargetV1) bool {
	if !continuityIDPattern.MatchString(value.TeamID) || !continuityIDPattern.MatchString(value.MemberID) {
		return false
	}
	hasTask := value.TaskID != nil || value.TaskAttempt != nil
	if hasTask && (value.TaskID == nil || value.TaskAttempt == nil || !continuityIDPattern.MatchString(*value.TaskID) || *value.TaskAttempt < 1) {
		return false
	}
	hasWork := value.WorkID != nil || value.WorkRevision != nil || value.BindingID != nil || value.BindingRevision != nil
	return !hasWork || value.WorkID != nil && value.WorkRevision != nil && value.BindingID != nil && value.BindingRevision != nil &&
		continuityIDPattern.MatchString(*value.WorkID) && *value.WorkRevision > 0 &&
		continuityIDPattern.MatchString(*value.BindingID) && *value.BindingRevision > 0
}

func validInsightsManagerProfile(value InsightsManagerProfileV1) bool {
	return value.ProfileID == "warpmetal-insights-manager" && value.ProfileRevision > 0 && setupDigestPattern.MatchString(value.ProfileDigest)
}

func validInsightsManagerBudget(value InsightsManagerBudgetV1) bool {
	return value.ModelRequests >= 1 && value.ModelRequests <= 2 && value.InputTokens >= 1 && value.InputTokens <= 16000 &&
		value.OutputTokens >= 1 && value.OutputTokens <= 2000
}

func validInsightsManagerLimits(value InsightsManagerEffectiveLimitsV1) bool {
	return value.SandboxDailyRuns >= 1 && value.SandboxDailyRuns <= 30 && value.SandboxHourlyRuns >= 1 && value.SandboxHourlyRuns <= 10 &&
		value.SessionRuns24h >= 1 && value.SessionRuns24h <= 3 && value.SessionCooldownSeconds >= 300 &&
		value.ServerConcurrentRuns >= 1 && value.ServerConcurrentRuns <= 2 && value.ServerHourlyStarts >= 1 && value.ServerHourlyStarts <= 20 &&
		value.PerRunModelRequests >= 1 && value.PerRunModelRequests <= 2 && value.PerRunInputTokens >= 1 && value.PerRunInputTokens <= 16000 &&
		value.PerRunOutputTokens >= 1 && value.PerRunOutputTokens <= 2000
}

func validInsightsManagerRule(value string) bool {
	return value == "repeated_identical_failure@1" || value == "repeated_identical_call@1" || value == "empty_result_loop@1" || value == "suspected_stall@1"
}

func validInsightsManagerRecipe(value string) bool {
	return value == "inspect_first_failure@1" || value == "check_repeated_operation@1" || value == "refine_query@1" || value == "inspect_active_phase@1"
}

func ValidateInsightsManagerPolicyManifest(value InsightsManagerPolicyManifestV1) error {
	if value.FormatVersion != 1 || !continuityIDPattern.MatchString(value.SandboxID) || value.SandboxGeneration < 1 ||
		value.PolicyRevision < 1 || (value.Mode != "off" && value.Mode != "recommend") || len(value.AllowedRules) > 8 ||
		value.DailyRunLimit < 1 || value.DailyRunLimit > 30 || value.DailyInputTokenLimit < 1 || value.DailyInputTokenLimit > 480000 ||
		value.DailyOutputTokenLimit < 1 || value.DailyOutputTokenLimit > 60000 || !validInsightsManagerLimits(value.EffectiveLimits) ||
		!validInsightsManagerProfile(value.ManagerProfile) || value.ValidUntil.IsZero() || value.RunGeneration < 1 || value.AutoSteerAvailable {
		return errors.New("invalid insights manager policy manifest")
	}
	seen := map[string]bool{}
	for _, rule := range value.AllowedRules {
		if !validInsightsManagerRule(rule) || seen[rule] {
			return errors.New("invalid insights manager policy rule")
		}
		seen[rule] = true
	}
	if value.Mode == "off" && len(value.AllowedRules) != 0 {
		return errors.New("off insights manager policy has rules")
	}
	return nil
}

func ValidateInsightsManagerReviewManifest(value InsightsManagerReviewManifestV1) error {
	if value.FormatVersion != 1 || !continuityIDPattern.MatchString(value.ReservationID) || !continuityIDPattern.MatchString(value.RunID) ||
		!continuityIDPattern.MatchString(value.FindingID) || value.FindingRevision < 1 || value.PolicyRevision < 1 ||
		!validInsightsManagerRule(value.RuleID) || !validInsightsManagerRecipe(value.RecipeID) ||
		!setupDigestPattern.MatchString(value.ProviderRouteDigest) || !validInsightsManagerProfile(value.ManagerProfile) ||
		!validInsightsManagerSource(value.Source) || !validInsightsManagerTarget(value.Target) || !validInsightsManagerBudget(value.Budget) ||
		value.ValidUntil.IsZero() {
		return errors.New("invalid insights manager review manifest")
	}
	if value.FindingEvidence != nil {
		if err := ValidateInsightsManagerFindingEvidence(*value.FindingEvidence, value); err != nil {
			return err
		}
	}
	return nil
}

// ValidateInsightsManagerFindingEvidence checks the bounded descriptor shape and
// its exact binding to the review manifest it authorizes: finding id/revision,
// rule and native session must match, the journal generation and observation
// window must be closed, and no unbounded reference list is admitted. The
// bounds follow the pinned paired schema (complete coverage, opaque ids,
// bounded string fields). It performs no store access; the caller decides
// whether to consume the authenticated snapshot or the canonical local
// observation.
func ValidateInsightsManagerFindingEvidence(value InsightsManagerFindingEvidenceV1, review InsightsManagerReviewManifestV1) error {
	if value.FindingID != review.FindingID || value.FindingRevision != review.FindingRevision || value.RuleID != review.RuleID ||
		value.NativeSessionID != review.Source.NativeSessionID || !managerEvidenceIDPattern.MatchString(value.JournalGeneration) ||
		value.FirstSequence < 1 || value.LastSequence < value.FirstSequence || value.Count < 1 || len(value.MatchedCallIDs) > 16 ||
		value.Coverage != "complete" || len(value.ToolCategory) > 32 || len(value.Phase) > 32 ||
		value.FirstObservedAt.IsZero() || value.LastObservedAt.IsZero() || value.LastObservedAt.Before(value.FirstObservedAt) {
		return errors.New("invalid insights manager finding evidence")
	}
	seen := map[string]bool{}
	for _, id := range value.MatchedCallIDs {
		if !managerEvidenceIDPattern.MatchString(id) || seen[id] {
			return errors.New("invalid insights manager finding evidence reference")
		}
		seen[id] = true
	}
	return nil
}

func ValidateInsightsTakeoverManifest(value InsightsTakeoverManifestV1) error {
	validAction := value.Action == "pause_manager_and_hold_member" && value.PredecessorOperationID == nil && value.HoldState == "active" ||
		value.Action == "resume_manager_and_release_member" && value.PredecessorOperationID != nil &&
			continuityIDPattern.MatchString(*value.PredecessorOperationID) && value.HoldState == "released"
	if value.FormatVersion != 1 || !continuityIDPattern.MatchString(value.OperationID) || !validAction ||
		!continuityIDPattern.MatchString(value.FindingID) || value.FindingRevision < 1 || value.PolicyRevision < 1 || value.RunGeneration < 1 ||
		!continuityIDPattern.MatchString(value.HoldID) || value.HoldRevision < 1 || !validInsightsManagerSource(value.Source) ||
		!validInsightsManagerTarget(value.Target) || value.ValidUntil.IsZero() {
		return errors.New("invalid insights takeover manifest")
	}
	return nil
}

func ValidateManifest(manifest Manifest, expectedServer string, lastRevision int64) error {
	if manifest.ServerID != expectedServer {
		return errors.New("manifest server identity differs from local registration")
	}
	if manifest.DesiredRevision < lastRevision {
		return errors.New("manifest revision moved backwards")
	}
	if manifest.DesiredRevision < 1 || len(manifest.Sandboxes) > 32 || len(manifest.AccessGrants) > 64 {
		return errors.New("manifest limits are invalid")
	}
	if !imagePattern.MatchString(manifest.ImageDigest) {
		return errors.New("immutable sandbox image digest is required")
	}
	seenNames := map[string]bool{}
	seenIDs := map[string]bool{}
	sandboxStates := map[string]string{}
	sandboxGenerations := map[string]int64{}
	allocated := Resources{}
	for _, sandbox := range manifest.Sandboxes {
		if !idPattern.MatchString(sandbox.ID) || !namePattern.MatchString(sandbox.Name) {
			return fmt.Errorf("invalid sandbox identity %q", sandbox.ID)
		}
		if seenIDs[sandbox.ID] || seenNames[sandbox.Name] {
			return errors.New("duplicate sandbox identity")
		}
		seenIDs[sandbox.ID] = true
		seenNames[sandbox.Name] = true
		sandboxStates[sandbox.ID] = sandbox.DesiredState
		sandboxGenerations[sandbox.ID] = sandbox.Generation
		if !validDesired[sandbox.DesiredState] || sandbox.Generation < 1 {
			return fmt.Errorf("invalid desired state for %s", sandbox.ID)
		}
		if sandbox.ImageDigest != "" && !imagePattern.MatchString(sandbox.ImageDigest) {
			return fmt.Errorf("invalid image digest for %s", sandbox.ID)
		}
		if sandbox.Resources.CPUMillicores < 1 || sandbox.Resources.MemoryMiB < 1 ||
			sandbox.Resources.WorkspaceDiskGiB < 1 || sandbox.Resources.PIDs < 1 {
			return fmt.Errorf("invalid resource snapshot for %s", sandbox.ID)
		}
		if sandbox.Lifetime == "persistent" {
			if sandbox.ExpiresInSeconds != nil || sandbox.ExpiresAt != nil {
				return fmt.Errorf("persistent sandbox %s has expiration", sandbox.ID)
			}
		} else if sandbox.Lifetime == "temporary" {
			if sandbox.ExpiresInSeconds == nil || *sandbox.ExpiresInSeconds < MinTemporarySeconds ||
				*sandbox.ExpiresInSeconds > MaxTemporarySeconds {
				return fmt.Errorf("temporary sandbox %s has invalid expiration", sandbox.ID)
			}
		} else {
			return fmt.Errorf("invalid lifetime for %s", sandbox.ID)
		}
		if sandbox.DesiredState != "deleted" {
			allocated.WorkspaceDiskGiB += sandbox.Resources.WorkspaceDiskGiB
			if sandbox.DesiredState == "running" {
				allocated.CPUMillicores += sandbox.Resources.CPUMillicores
				allocated.MemoryMiB += sandbox.Resources.MemoryMiB
			}
		}
	}
	if !allocated.Fits(manifest.Capacity) {
		return errors.New("manifest exceeds purchased runtime capacity")
	}
	if len(manifest.SetupOperations) > 32 {
		return errors.New("manifest exceeds setup operation limit")
	}
	if len(manifest.ContinuityRegistrations) > 64 || len(manifest.ContinuityOperations) > 64 {
		return errors.New("manifest exceeds continuity record limits")
	}
	registrationGroups := map[string][]ContinuityRegistrationV1{}
	for _, registration := range manifest.ContinuityRegistrations {
		generation, sandboxExists := sandboxGenerations[registration.Identity.SandboxID]
		// The registration identity's expectedRevision is the Work record revision
		// owned by the control plane; manifest.DesiredRevision is the separate,
		// server-wide manifest generation. validateContinuityIdentity enforces the
		// positive Work-revision fence, and these two domains are never equal by
		// contract.
		if err := ValidateContinuityRegistration(registration); err != nil || !sandboxExists ||
			generation != registration.Identity.SandboxGeneration {
			return errors.New("invalid continuity registration")
		}
		group := append(registrationGroups[registration.Binding.BindingID], registration)
		if len(group) > 2 {
			return errors.New("duplicate continuity registration")
		}
		registrationGroups[registration.Binding.BindingID] = group
	}
	registrations := map[string]ContinuityRegistrationV1{}
	for bindingID, group := range registrationGroups {
		switch {
		case len(group) == 1:
			registrations[bindingID] = group[0]
		case continuityRegistrationRevisionSuccession(group[0], group[1]):
			registrations[bindingID] = group[1]
		case continuityRegistrationRevisionSuccession(group[1], group[0]):
			registrations[bindingID] = group[0]
		default:
			return errors.New("duplicate continuity registration")
		}
	}
	seenContinuityOperations := map[string]bool{}
	for _, operation := range manifest.ContinuityOperations {
		registration, exists := registrations[operation.Binding.BindingID]
		if err := validateContinuityIdentity(operation.Identity); err != nil ||
			operation.FormatVersion != 1 || !continuityIDPattern.MatchString(operation.OperationID) ||
			operation.Action != "capture_checkpoint" ||
			!setupDigestPattern.MatchString(operation.RequestDigest) || operation.ScopeRevision < 1 ||
			seenContinuityOperations[operation.OperationID] || !exists ||
			!SameContinuityWorkFence(registration.Identity, operation.Identity) ||
			registration.Binding != operation.Binding ||
			registration.ScopeRevision != operation.ScopeRevision || registration.DesiredState != "active" ||
			!registration.ContinuityEnabled {
			return errors.New("invalid continuity operation")
		}
		hasTask := operation.Identity.TaskID != nil
		if operation.BoundaryKind == "initial" && hasTask ||
			operation.BoundaryKind == "task" && !hasTask ||
			operation.BoundaryKind != "initial" && operation.BoundaryKind != "task" && operation.BoundaryKind != "stopped" {
			return errors.New("invalid continuity boundary kind")
		}
		seenContinuityOperations[operation.OperationID] = true
	}
	seenSetupIDs := map[string]bool{}
	setupByID := map[string]SetupOperation{}
	for _, operation := range manifest.SetupOperations {
		if !setupIDPattern.MatchString(operation.ID) || seenSetupIDs[operation.ID] {
			return errors.New("invalid or duplicate setup operation identity")
		}
		seenSetupIDs[operation.ID] = true
		setupByID[operation.ID] = operation
		generation, exists := sandboxGenerations[operation.SandboxID]
		if !exists || generation != operation.SandboxGeneration {
			return fmt.Errorf("setup operation %s has an invalid sandbox generation", operation.ID)
		}
		if operation.SchemaVersion != 1 ||
			!setupIDPattern.MatchString(operation.ProfileID) ||
			operation.ProfileRevision < 1 ||
			!setupDigestPattern.MatchString(operation.ProfileDigest) {
			return fmt.Errorf("setup operation %s has an invalid immutable tuple", operation.ID)
		}
		var materializerErr error
		switch operation.Materializer.Kind {
		case "npm-package-set":
			materializerErr = validateNPMMaterializer(operation.Materializer)
		case "archive-binary":
			materializerErr = validateArchiveMaterializer(operation.Materializer)
		default:
			materializerErr = errors.New("unsupported materializer")
		}
		if materializerErr != nil {
			return fmt.Errorf("setup operation %s has an invalid materializer: %w", operation.ID, materializerErr)
		}
	}
	if len(manifest.ManagedWorkspaceRequests) > 32 || len(manifest.ManagedServices) > 32 {
		return errors.New("manifest exceeds managed service limits")
	}
	seenManagedWorkspaceServices := map[string]bool{}
	seenManagedServices := map[string]bool{}
	for _, request := range manifest.ManagedWorkspaceRequests {
		generation, exists := sandboxGenerations[request.SandboxID]
		if request.FormatVersion != 1 || request.Request != "create_default" ||
			!continuityIDPattern.MatchString(request.OperationID) || request.ActionRevision < 1 ||
			request.DesiredRevision < 1 || request.ServerID != expectedServer ||
			!continuityIDPattern.MatchString(request.TeamID) || !continuityIDPattern.MatchString(request.MemberID) ||
			!continuityIDPattern.MatchString(request.ServiceRegistrationID) ||
			!setupDigestPattern.MatchString(request.AllocationDigest) || !exists ||
			generation != request.SandboxGeneration || seenManagedWorkspaceServices[request.ServiceRegistrationID] {
			return errors.New("invalid managed workspace request")
		}
		seenManagedWorkspaceServices[request.ServiceRegistrationID] = true
	}
	for _, service := range manifest.ManagedServices {
		identity := service.Identity
		profile, profileExists := setupByID[service.Profile.SetupOperationID]
		generation, sandboxExists := sandboxGenerations[identity.SandboxID]
		validState := service.DesiredState == "active" || service.DesiredState == "paused" ||
			service.DesiredState == "stopped" || service.DesiredState == "retired"
		validAuthority := true
		if authority := service.Authority; authority != nil {
			validModel := authority.ModelID == nil || modelIDPattern.MatchString(*authority.ModelID)
			validAuthMode := authority.AuthMode == nil || *authority.AuthMode == "api_key" || *authority.AuthMode == "chatgpt_subscription"
			validAuthority = authority.TeamRevision >= 1 && authority.TeamRevision <= 2_000_000_000 &&
				providerIDPattern.MatchString(authority.ProviderID) && validModel && validAuthMode
		}
		// A terminal service whose box generation has advanced is retained
		// history: the generation filter has already removed its profile setup
		// operation from the manifest, so the generation equality and profile
		// equality checks can no longer hold for it. Tolerate exactly that
		// case (the box must still exist in the manifest and the service must
		// be terminal); active or current-generation services keep the strict
		// checks unchanged.
		retainedTerminal := (service.DesiredState == "stopped" || service.DesiredState == "retired") &&
			sandboxExists && generation > identity.SandboxGeneration
		// Only an entirely absent profile setup operation is tolerated for
		// that retained case; a present but mismatched profile is not.
		profileTolerated := retainedTerminal && !profileExists
		profileMatches := profileExists && profile.SandboxID == identity.SandboxID &&
			profile.SandboxGeneration == identity.SandboxGeneration &&
			profile.ProfileID == service.Profile.ProfileID &&
			profile.ProfileRevision == service.Profile.ProfileRevision &&
			profile.ProfileDigest == service.Profile.ProfileDigest
		if service.FormatVersion != 1 || !continuityIDPattern.MatchString(service.OperationID) ||
			service.ActionRevision < 1 || service.DesiredRevision < 1 ||
			!setupDigestPattern.MatchString(service.ConfigDigest) || !validState || !validAuthority ||
			(service.SessionMode != "create_initial" && service.SessionMode != "lookup_only") ||
			service.DesiredState != "active" && service.SessionMode != "lookup_only" ||
			identity.ServerID != expectedServer || !continuityIDPattern.MatchString(identity.TeamID) ||
			!continuityIDPattern.MatchString(identity.MemberID) || !continuityIDPattern.MatchString(identity.ServiceRegistrationID) ||
			identity.ExpectedServiceGeneration < 1 || identity.Instance != "default" ||
			(identity.Role != "worker" && identity.Role != "reviewer" && identity.Role != "manager") ||
			!sandboxExists || (generation != identity.SandboxGeneration && !retainedTerminal) ||
			(!profileMatches && !profileTolerated) ||
			service.Instructions.InstructionRevision < 1 || !setupDigestPattern.MatchString(service.Instructions.InstructionDigest) ||
			!continuityIDPattern.MatchString(service.Workspace.SelectionID) || !continuityIDPattern.MatchString(service.Workspace.ProjectID) ||
			!continuityIDPattern.MatchString(service.Workspace.WorkspaceEpoch) || service.Workspace.ScopeRevision < 1 ||
			service.Workspace.Designation != "team_project" || !setupDigestPattern.MatchString(service.Workspace.RootAttestation) ||
			seenManagedServices[identity.ServiceRegistrationID] {
			return errors.New("invalid managed service")
		}
		seenManagedServices[identity.ServiceRegistrationID] = true
	}
	if len(manifest.ContinuityContinuations) > 32 || len(manifest.ContinuityContinuationReleases) > 32 || len(manifest.ContinuityRestores) > 32 {
		return errors.New("manifest exceeds continuation limits")
	}
	seenS2Operations := map[string]bool{}
	for _, continuation := range manifest.ContinuityContinuations {
		if err := validateContinuationManifest(continuation, sandboxGenerations); err != nil || seenS2Operations[continuation.OperationID] {
			return errors.Join(errors.New("invalid continuation manifest"), err)
		}
		seenS2Operations[continuation.OperationID] = true
	}
	for _, release := range manifest.ContinuityContinuationReleases {
		if err := validateContinuationReleaseManifest(release, sandboxGenerations); err != nil || seenS2Operations[release.OperationID] {
			return errors.Join(errors.New("invalid continuation release manifest"), err)
		}
		seenS2Operations[release.OperationID] = true
	}
	for _, restore := range manifest.ContinuityRestores {
		if err := validateRestoreManifest(restore, sandboxGenerations); err != nil || seenS2Operations[restore.OperationID] {
			return errors.Join(errors.New("invalid restore manifest"), err)
		}
		seenS2Operations[restore.OperationID] = true
	}
	if len(manifest.ContinuityHandoffs) > 32 || len(manifest.ContinuityHandoffReleases) > 32 {
		return errors.New("manifest exceeds handoff limits")
	}
	for _, handoff := range manifest.ContinuityHandoffs {
		if err := validateContinuationHandoffManifest(handoff, sandboxGenerations); err != nil || seenS2Operations[handoff.OperationID] {
			return errors.Join(errors.New("invalid continuation handoff manifest"), err)
		}
		seenS2Operations[handoff.OperationID] = true
	}
	for _, release := range manifest.ContinuityHandoffReleases {
		if err := validateContinuationHandoffReleaseManifest(release, sandboxGenerations); err != nil || seenS2Operations[release.OperationID] {
			return errors.Join(errors.New("invalid continuation handoff release manifest"), err)
		}
		seenS2Operations[release.OperationID] = true
	}
	if len(manifest.InsightsManagerPolicies) > 32 || len(manifest.InsightsManagerReviews) > 100 || len(manifest.InsightsTakeovers) > 100 {
		return errors.New("manifest exceeds insights manager limits")
	}
	managerPolicies := map[string]InsightsManagerPolicyManifestV1{}
	for _, policy := range manifest.InsightsManagerPolicies {
		generation, exists := sandboxGenerations[policy.SandboxID]
		if err := ValidateInsightsManagerPolicyManifest(policy); err != nil || !exists || generation != policy.SandboxGeneration {
			return errors.Join(errors.New("invalid insights manager policy"), err)
		}
		if _, duplicate := managerPolicies[policy.SandboxID]; duplicate {
			return errors.New("duplicate insights manager policy")
		}
		managerPolicies[policy.SandboxID] = policy
	}
	seenManagerRuns := map[string]bool{}
	for _, review := range manifest.InsightsManagerReviews {
		if err := ValidateInsightsManagerReviewManifest(review); err != nil || seenManagerRuns[review.RunID] {
			return errors.Join(errors.New("invalid insights manager review"), err)
		}
		seenManagerRuns[review.RunID] = true
	}
	seenTakeovers := map[string]bool{}
	for _, takeover := range manifest.InsightsTakeovers {
		if err := ValidateInsightsTakeoverManifest(takeover); err != nil || seenTakeovers[takeover.OperationID] {
			return errors.Join(errors.New("invalid insights takeover"), err)
		}
		seenTakeovers[takeover.OperationID] = true
	}
	seenGrants := map[string]bool{}
	seenKeys := map[string]bool{}
	grantsPerSandbox := map[string]int{}
	for _, grant := range manifest.AccessGrants {
		if !idPattern.MatchString(grant.ID) || !seenIDs[grant.SandboxID] {
			return fmt.Errorf("invalid access grant %q", grant.ID)
		}
		if seenGrants[grant.ID] || (grant.DesiredState == "active" && seenKeys[grant.SSHFingerprint]) {
			return errors.New("duplicate access grant or key mapping")
		}
		if grant.DesiredState != "active" && grant.DesiredState != "revoked" {
			return fmt.Errorf("invalid grant state for %s", grant.ID)
		}
		if grant.DesiredState == "active" && sandboxStates[grant.SandboxID] == "deleted" {
			return fmt.Errorf("active grant targets deleted sandbox %s", grant.SandboxID)
		}
		seenGrants[grant.ID] = true
		if grant.DesiredState == "active" {
			seenKeys[grant.SSHFingerprint] = true
			grantsPerSandbox[grant.SandboxID]++
			if grantsPerSandbox[grant.SandboxID] > 8 {
				return fmt.Errorf("sandbox %s exceeds grant limit", grant.SandboxID)
			}
		}
	}
	return nil
}

func validateS2Identity(identity ContinuationIdentityV1, sandboxGenerations map[string]int64) bool {
	generation, exists := sandboxGenerations[identity.SandboxID]
	return continuityIDPattern.MatchString(identity.WorkID) && continuityIDPattern.MatchString(identity.ProjectID) &&
		continuityIDPattern.MatchString(identity.SandboxID) && continuityIDPattern.MatchString(identity.WorkspaceEpoch) &&
		identity.SandboxGeneration > 0 && identity.ExpectedRevision > 0 && exists && generation == identity.SandboxGeneration
}

func validateS2Binding(binding ContinuationBindingRefV1) bool {
	nativeProject := binding.NativeProjectID == "global" || regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(binding.NativeProjectID)
	return continuityIDPattern.MatchString(binding.BindingID) && binding.BindingRevision > 0 && binding.ScopeRevision > 0 &&
		continuityIDPattern.MatchString(binding.ServiceRegistrationID) && binding.ServiceGeneration > 0 &&
		continuityIDPattern.MatchString(binding.RegisteredSourceID) && continuityIDPattern.MatchString(binding.NativeSessionID) &&
		nativeProject && setupDigestPattern.MatchString(binding.NativeLocationDigest)
}

func validateS2Checkpoint(checkpoint ContinuationCheckpointRefV1) bool {
	return continuityIDPattern.MatchString(checkpoint.OperationID) && continuityIDPattern.MatchString(checkpoint.CheckpointID) &&
		setupDigestPattern.MatchString(checkpoint.ManifestDigest) && checkpoint.Bytes >= 0 && checkpoint.Bytes <= 268435456 &&
		checkpoint.ObjectCount >= 0 && checkpoint.ObjectCount <= 10000
}

func validateContinuationManifest(value ContinuationManifestV1, sandboxGenerations map[string]int64) error {
	target := value.Target
	if value.FormatVersion != 1 || value.Action != "prepare_continuation" || value.DesiredRevision < 1 ||
		!continuityIDPattern.MatchString(value.OperationID) || !validateS2Identity(value.Identity, sandboxGenerations) ||
		!validateS2Binding(value.Binding) || !validateS2Checkpoint(value.Checkpoint) ||
		!continuityIDPattern.MatchString(target.TeamID) || target.TeamRevision < 1 || target.PolicyRevision < 1 ||
		!continuityIDPattern.MatchString(target.MemberID) || target.SandboxID != value.Identity.SandboxID ||
		target.SandboxGeneration != value.Identity.SandboxGeneration ||
		target.ServiceRegistrationID != value.Binding.ServiceRegistrationID || target.ServiceGeneration != value.Binding.ServiceGeneration ||
		target.ServiceDesiredRevision < 1 || target.ServiceActionRevision < 1 ||
		!continuityIDPattern.MatchString(target.SelectionID) || target.ProjectID != value.Identity.ProjectID ||
		target.WorkspaceEpoch != value.Identity.WorkspaceEpoch || target.ScopeRevision != value.Binding.ScopeRevision ||
		!setupDigestPattern.MatchString(target.RootAttestation) || !continuityIDPattern.MatchString(target.ProfileID) ||
		target.ProfileRevision < 1 || !setupDigestPattern.MatchString(target.ProfileDigest) ||
		target.InstructionRevision < 1 || !setupDigestPattern.MatchString(target.InstructionDigest) ||
		(target.Role != "worker" && target.Role != "reviewer") || !setupDigestPattern.MatchString(value.Context.Digest) ||
		value.Context.Bytes < 0 || value.Context.Bytes > 32768 || value.Context.TokenUpperBound < 0 || value.Context.TokenUpperBound > 8192 {
		return errors.New("continuation tuple is invalid")
	}
	return nil
}

func validateContinuationReleaseManifest(value ContinuationReleaseManifestV1, sandboxGenerations map[string]int64) error {
	prepare := ContinuationManifestV1{
		FormatVersion: value.FormatVersion, OperationID: value.OperationID, Action: "prepare_continuation",
		DesiredRevision: value.DesiredRevision, Identity: value.Identity, Binding: value.Binding,
		Checkpoint: value.Checkpoint, Target: value.Target, Context: value.Context,
	}
	if value.Action != "release_continuation" || (value.Reason != "failed" && value.Reason != "superseded") ||
		validateContinuationManifest(prepare, sandboxGenerations) != nil {
		return errors.New("continuation release tuple is invalid")
	}
	return nil
}

func validateContinuationHandoffManifest(value ContinuationHandoffManifestV1, sandboxGenerations map[string]int64) error {
	lineage := value.Lineage
	target := value.TargetPolicy
	workspace := value.Workspace
	targetGeneration, targetExists := sandboxGenerations[target.SandboxID]
	validSourceTask := lineage.SourceTaskID == nil || continuityIDPattern.MatchString(*lineage.SourceTaskID)
	validTarget := targetExists && targetGeneration == target.SandboxGeneration &&
		continuityIDPattern.MatchString(target.TeamID) && target.TeamRevision > 0 && target.PolicyRevision > 0 &&
		continuityIDPattern.MatchString(target.MemberID) && (target.Role == "worker" || target.Role == "reviewer") &&
		continuityIDPattern.MatchString(target.ServiceRegistrationID) && target.ServiceGeneration > 0 &&
		target.ServiceDesiredRevision > 0 && target.ServiceActionRevision > 0 && target.ProfileID == "opencode" &&
		target.ProfileRevision > 0 && setupDigestPattern.MatchString(target.ProfileDigest) &&
		target.InstructionRevision > 0 && setupDigestPattern.MatchString(target.InstructionDigest)
	validWorkspace := false
	switch workspace.Mode {
	case "allocate_and_materialize":
		validWorkspace = value.HandoffKind == "reviewer" && target.Role == "reviewer" &&
			workspace.RestoreOperationID == nil && workspace.SelectionID == nil && workspace.ProjectID == nil &&
			workspace.WorkspaceEpoch == nil && workspace.ScopeRevision == nil && workspace.RootAttestation == nil &&
			lineage.RestoreOperationID == nil
	case "accepted_restore":
		validWorkspace = value.HandoffKind == "restored_target" && target.Role == "worker" &&
			workspace.RestoreOperationID != nil && workspace.SelectionID != nil && workspace.ProjectID != nil &&
			workspace.WorkspaceEpoch != nil && workspace.ScopeRevision != nil && workspace.RootAttestation != nil &&
			lineage.RestoreOperationID != nil && *workspace.RestoreOperationID == *lineage.RestoreOperationID &&
			continuityIDPattern.MatchString(*workspace.RestoreOperationID) &&
			continuityIDPattern.MatchString(*workspace.SelectionID) && continuityIDPattern.MatchString(*workspace.ProjectID) &&
			continuityIDPattern.MatchString(*workspace.WorkspaceEpoch) && *workspace.ScopeRevision > 0 &&
			setupDigestPattern.MatchString(*workspace.RootAttestation)
	}
	if value.FormatVersion != 1 || value.Action != "prepare_handoff" || value.DesiredRevision < 1 ||
		!continuityIDPattern.MatchString(value.OperationID) ||
		(value.HandoffKind != "reviewer" && value.HandoffKind != "restored_target") ||
		value.SessionMode != "create_separate" || !continuityIDPattern.MatchString(value.TargetWorkID) ||
		!continuityIDPattern.MatchString(value.MappingID) || !validateS2Identity(value.Identity, sandboxGenerations) ||
		!validateS2Binding(value.Binding) || !validateS2Checkpoint(value.Checkpoint) ||
		lineage.SourceWorkID != value.Identity.WorkID || lineage.SourceRevision != value.Identity.ExpectedRevision ||
		!validSourceTask || lineage.CheckpointOperationID != value.Checkpoint.OperationID ||
		!validTarget || !validWorkspace || !setupDigestPattern.MatchString(value.Context.Digest) ||
		value.Context.Bytes < 0 || value.Context.Bytes > 32768 ||
		value.Context.TokenUpperBound < 0 || value.Context.TokenUpperBound > 8192 {
		return errors.New("continuation handoff tuple is invalid")
	}
	return nil
}

func validContinuationHandoffReadyReport(manifest ContinuationHandoffManifestV1, report ContinuationHandoffReportV1) bool {
	if report.FormatVersion != manifest.FormatVersion || report.OperationID != manifest.OperationID ||
		report.Action != manifest.Action || report.DesiredRevision != manifest.DesiredRevision ||
		report.HandoffKind != manifest.HandoffKind || report.SessionMode != manifest.SessionMode ||
		report.TargetWorkID != manifest.TargetWorkID || report.MappingID != manifest.MappingID ||
		report.Identity != manifest.Identity || report.Binding != manifest.Binding || report.Checkpoint != manifest.Checkpoint ||
		!reflect.DeepEqual(report.Lineage, manifest.Lineage) || report.TargetPolicy != manifest.TargetPolicy ||
		!reflect.DeepEqual(report.WorkspaceRequest, manifest.Workspace) || report.ContextDigest != manifest.Context.Digest ||
		!setupDigestPattern.MatchString(report.ReceiptDigest) {
		return false
	}
	if report.Status == "failed" {
		return report.TargetWorkspace == nil && report.Session == nil && report.Baseline == nil &&
			report.ErrorCode != nil && continuityIDPattern.MatchString(*report.ErrorCode)
	}
	if report.Status != "ready" || report.ErrorCode != nil || report.TargetWorkspace == nil ||
		report.Session == nil || report.Baseline == nil {
		return false
	}
	workspace := report.TargetWorkspace
	session := report.Session
	baseline := report.Baseline
	return continuityIDPattern.MatchString(workspace.SelectionID) && continuityIDPattern.MatchString(workspace.ProjectID) &&
		continuityIDPattern.MatchString(workspace.WorkspaceEpoch) && workspace.ScopeRevision > 0 &&
		setupDigestPattern.MatchString(workspace.RootAttestation) && session.MappingID == manifest.MappingID &&
		continuityIDPattern.MatchString(session.RegisteredSourceID) && continuityIDPattern.MatchString(session.NativeSessionID) &&
		(session.NativeProjectID == "global" || regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(session.NativeProjectID)) &&
		setupDigestPattern.MatchString(session.NativeLocationDigest) && session.InstructionRevision == manifest.TargetPolicy.InstructionRevision &&
		session.InstructionDigest == manifest.TargetPolicy.InstructionDigest && session.InstructionApplied &&
		continuityIDPattern.MatchString(baseline.BaselineID) && setupDigestPattern.MatchString(baseline.BaselineDigest) &&
		baseline.NativeSessionID == session.NativeSessionID && baseline.ServiceGeneration == manifest.TargetPolicy.ServiceGeneration &&
		!baseline.ReadyAt.IsZero()
}

func validateContinuationHandoffReleaseManifest(value ContinuationHandoffReleaseManifestV1, sandboxGenerations map[string]int64) error {
	prepare := ContinuationHandoffManifestV1{
		FormatVersion: value.FormatVersion, OperationID: value.OperationID, Action: "prepare_handoff",
		DesiredRevision: value.PrepareDesiredRevision, HandoffKind: value.HandoffKind,
		SessionMode: value.SessionMode, TargetWorkID: value.TargetWorkID, MappingID: value.MappingID,
		Identity: value.Identity, Binding: value.Binding, Checkpoint: value.Checkpoint,
		Lineage: value.Lineage, TargetPolicy: value.TargetPolicy, Workspace: value.Workspace, Context: value.Context,
	}
	if value.Action != "release_handoff" || value.DesiredRevision <= value.PrepareDesiredRevision ||
		(value.Reason != "failed" && value.Reason != "superseded") ||
		validateContinuationHandoffManifest(prepare, sandboxGenerations) != nil {
		return errors.New("continuation handoff release tuple is invalid")
	}
	return nil
}

func validContinuationHandoffRelease(manifest ContinuationHandoffReleaseManifestV1, report ContinuationHandoffReleaseReportV1) bool {
	if !reflect.DeepEqual(report.ContinuationHandoffReleaseManifestV1, manifest) ||
		!setupDigestPattern.MatchString(report.ReceiptDigest) {
		return false
	}
	return report.Status == "released" && report.ErrorCode == nil ||
		report.Status == "failed" && report.ErrorCode != nil && continuityIDPattern.MatchString(*report.ErrorCode)
}

func validateRestoreManifest(value RestoreManifestV1, sandboxGenerations map[string]int64) error {
	if value.FormatVersion != 1 || value.Action != "restore_checkpoint" || value.DesiredRevision < 1 ||
		!continuityIDPattern.MatchString(value.OperationID) || !validateS2Identity(value.Identity, sandboxGenerations) ||
		!validateS2Binding(value.Binding) || !validateS2Checkpoint(value.Checkpoint) || value.Target.Mode != "create_new" ||
		value.Target.SandboxID != value.Identity.SandboxID || value.Target.SandboxGeneration != value.Identity.SandboxGeneration {
		return errors.New("restore tuple is invalid")
	}
	return nil
}

// SameContinuityWorkFence compares the Work-level continuity fence shared by a
// registration and a capture operation. A task-boundary operation adds the
// task/attempt pair to its identity; the registration carries the Work-level
// identity only, so the task pair is deliberately excluded from this
// comparison and validated separately by the boundary-kind rules.
func SameContinuityWorkFence(left, right ContinuityIdentityV1) bool {
	return left.WorkID == right.WorkID && left.ProjectID == right.ProjectID &&
		left.SandboxID == right.SandboxID && left.WorkspaceEpoch == right.WorkspaceEpoch &&
		left.SandboxGeneration == right.SandboxGeneration &&
		left.ExpectedRevision == right.ExpectedRevision
}

func validateContinuityIdentity(identity ContinuityIdentityV1) error {
	if !continuityIDPattern.MatchString(identity.WorkID) || !continuityIDPattern.MatchString(identity.ProjectID) ||
		!continuityIDPattern.MatchString(identity.SandboxID) || !continuityIDPattern.MatchString(identity.WorkspaceEpoch) ||
		identity.WorkspaceEpoch == "" || identity.SandboxGeneration < 1 || identity.ExpectedRevision < 1 ||
		(identity.TaskID == nil) != (identity.TaskAttempt == nil) ||
		identity.TaskAttempt != nil && (*identity.TaskAttempt < 1 || !continuityIDPattern.MatchString(*identity.TaskID)) {
		return errors.New("invalid continuity identity")
	}
	return nil
}

func validContinuityBinding(binding ContinuityBindingV1) bool {
	return binding.BindingRevision > 0 && continuityIDPattern.MatchString(binding.BindingID) &&
		continuityIDPattern.MatchString(binding.RegisteredSourceID) && continuityIDPattern.MatchString(binding.ServiceRegistrationID) &&
		continuityIDPattern.MatchString(binding.NativeSessionID) && continuityIDPattern.MatchString(binding.NativeProjectID) &&
		setupDigestPattern.MatchString(binding.NativeLocationDigest)
}

// ValidateContinuityRegistration validates one durable continuity registration
// tuple independently of a manifest. It is the exact structural gate the
// manifest validator applies to every registration entry, exported so the
// Runtime report projection can fail closed on a malformed or contradictory
// durable row instead of serializing it or silently omitting it.
func ValidateContinuityRegistration(registration ContinuityRegistrationV1) error {
	if validateContinuityIdentity(registration.Identity) != nil ||
		registration.FormatVersion != 1 || registration.ScopeRevision < 1 ||
		(registration.DesiredState != "active" && registration.DesiredState != "revoked") ||
		!validContinuityBinding(registration.Binding) {
		return errors.New("invalid continuity registration")
	}
	return nil
}

// continuityRegistrationRevisionSuccession reports whether a manifest carries
// the one binding-reactivation shape the backend producer emits: one durable
// binding row whose revision advanced by exactly one, with the superseded
// revision explicitly revoked and the successor active. Both entries must name
// the same Work-level identity fence, the successor scope must not regress,
// and every binding field except the advanced revision must be identical.
// Equal revisions, reversed revisions, a revision jump, two revoked or two
// active entries and any inconsistent identity or binding tuple never qualify;
// every other duplicate binding ID stays a fail-closed duplicate.
func continuityRegistrationRevisionSuccession(revoked, active ContinuityRegistrationV1) bool {
	if revoked.DesiredState != "revoked" || active.DesiredState != "active" {
		return false
	}
	if active.Binding.BindingRevision != revoked.Binding.BindingRevision+1 {
		return false
	}
	if active.ScopeRevision < revoked.ScopeRevision {
		return false
	}
	if !SameContinuityWorkFence(revoked.Identity, active.Identity) {
		return false
	}
	revokedBinding, activeBinding := revoked.Binding, active.Binding
	revokedBinding.BindingRevision, activeBinding.BindingRevision = 0, 0
	return revokedBinding == activeBinding
}

// EffectiveContinuityRegistrations resolves exactly one effective registration
// per binding ID the way ValidateManifest resolves a valid succession: a single
// entry stays itself, and the one revoked-predecessor / active-successor pair
// admitted by continuityRegistrationRevisionSuccession resolves to the active
// successor. Every other group shape - two active entries, two revoked entries,
// a non-succession duplicate, a reversed or skipped revision, an inconsistent
// work or binding fence, or more than two entries - is unsupported and returns
// an error so the acknowledgement boundary can fail closed before any write.
// The returned order is the first-seen binding order; callers that need a
// deterministic application order sort by binding ID.
func EffectiveContinuityRegistrations(registrations []ContinuityRegistrationV1) ([]ContinuityRegistrationV1, error) {
	seen := map[string]bool{}
	effective := make([]ContinuityRegistrationV1, 0, len(registrations))
	for _, registration := range registrations {
		bindingID := registration.Binding.BindingID
		if seen[bindingID] {
			continue
		}
		seen[bindingID] = true
		var group []ContinuityRegistrationV1
		for _, candidate := range registrations {
			if candidate.Binding.BindingID == bindingID {
				group = append(group, candidate)
			}
		}
		switch {
		case len(group) == 1:
			effective = append(effective, group[0])
		case len(group) == 2 && continuityRegistrationRevisionSuccession(group[0], group[1]):
			effective = append(effective, group[1])
		case len(group) == 2 && continuityRegistrationRevisionSuccession(group[1], group[0]):
			effective = append(effective, group[0])
		default:
			return nil, fmt.Errorf("continuity registration %s has an unsupported duplicate binding shape", bindingID)
		}
	}
	return effective, nil
}

func validateNPMMaterializer(materializer SetupMaterializer) error {
	if materializer.Platform != "" || materializer.Artifact != nil || materializer.Bin != nil ||
		len(materializer.Artifacts) < 1 || len(materializer.Artifacts) > 8 ||
		len(materializer.Bins) > 8 || len(materializer.Launchers) > 8 ||
		(len(materializer.Bins) == 0 && len(materializer.Launchers) == 0) {
		return errors.New("invalid npm materializer shape")
	}
	seenArtifacts := map[string]bool{}
	seenAliases := map[string]bool{}
	var aggregateSize int64
	for _, artifact := range materializer.Artifacts {
		if !setupIDPattern.MatchString(artifact.ID) || seenArtifacts[artifact.ID] ||
			!setupDigestPattern.MatchString(artifact.SHA256) ||
			artifact.Format != "npm-tgz" || artifact.SizeBytes < 1 ||
			artifact.SizeBytes > MaxSetupArtifactBytes ||
			!npmPackagePattern.MatchString(artifact.PackageName) ||
			!semverPattern.MatchString(artifact.PackageVersion) ||
			!npmPackagePattern.MatchString(artifact.InstallAs) ||
			seenAliases[artifact.InstallAs] {
			return errors.New("invalid npm artifact")
		}
		seenArtifacts[artifact.ID] = true
		seenAliases[artifact.InstallAs] = true
		aggregateSize += artifact.SizeBytes
		if aggregateSize > MaxSetupArtifactBytes {
			return errors.New("artifact size limit exceeded")
		}
		if err := validateSetupArtifactSource(artifact.Source); err != nil {
			return errors.New("invalid artifact source")
		}
	}
	seenBins := map[string]bool{}
	for _, bin := range materializer.Bins {
		if !npmBinPattern.MatchString(bin) || seenBins[bin] {
			return errors.New("invalid npm bin")
		}
		seenBins[bin] = true
	}
	for _, launcher := range materializer.Launchers {
		if !npmBinPattern.MatchString(launcher.Bin) || seenBins[launcher.Bin] ||
			launcher.Kind != "node-module" || !seenArtifacts[launcher.ArtifactID] ||
			!safeRelativePath(launcher.Entrypoint) ||
			len(launcher.Environment) != 1 || launcher.Environment["DISABLE_UPDATES"] != "1" {
			return errors.New("invalid npm launcher")
		}
		seenBins[launcher.Bin] = true
	}
	return nil
}

func validateArchiveMaterializer(materializer SetupMaterializer) error {
	if len(materializer.Artifacts) != 0 || len(materializer.Bins) != 0 ||
		len(materializer.Launchers) != 0 || materializer.Artifact == nil || materializer.Bin == nil {
		return errors.New("invalid archive materializer shape")
	}
	artifact := materializer.Artifact
	if !setupIDPattern.MatchString(artifact.ID) ||
		!setupDigestPattern.MatchString(artifact.SHA256) || artifact.Format != "tar-gz" ||
		artifact.SizeBytes < 1 || artifact.SizeBytes > MaxSetupArtifactBytes ||
		validateSetupArtifactSource(artifact.Source) != nil {
		return errors.New("invalid archive artifact")
	}
	if materializer.Platform != "" && materializer.Platform != "linux/amd64" {
		return errors.New("invalid archive platform")
	}
	if artifact.Integrity != "" {
		if !strings.HasPrefix(artifact.Integrity, "sha512-") {
			return errors.New("invalid archive integrity")
		}
		digest, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(artifact.Integrity, "sha512-"))
		if err != nil || len(digest) != 64 {
			return errors.New("invalid archive integrity")
		}
	}
	if !npmBinPattern.MatchString(materializer.Bin.Name) || !safeRelativePath(materializer.Bin.Member) {
		return errors.New("invalid archive bin")
	}
	if materializer.Bin.SHA256 != "" && !setupDigestPattern.MatchString(materializer.Bin.SHA256) {
		return errors.New("invalid archive bin digest")
	}
	if materializer.Bin.Version != "" && !semverPattern.MatchString(materializer.Bin.Version) {
		return errors.New("invalid archive bin version")
	}
	if len(materializer.Bin.Environment) > 8 {
		return errors.New("invalid archive bin environment")
	}
	for name, value := range materializer.Bin.Environment {
		if !environmentNamePattern.MatchString(name) || len(value) > 256 || strings.ContainsRune(value, '\x00') {
			return errors.New("invalid archive bin environment")
		}
	}
	// The richer backend archive contract is all-or-nothing so a caller cannot
	// accidentally omit a verification fence while selecting a platform.
	verified := materializer.Platform != "" || artifact.Integrity != "" || materializer.Bin.SHA256 != "" || materializer.Bin.Version != "" || len(materializer.Bin.Environment) != 0
	if verified && (materializer.Platform != "linux/amd64" || artifact.Integrity == "" || materializer.Bin.SHA256 == "" || materializer.Bin.Version == "" || len(materializer.Bin.Environment) == 0) {
		return errors.New("incomplete verified archive contract")
	}
	return nil
}

func safeRelativePath(value string) bool {
	if !relativePathPattern.MatchString(value) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validateSetupArtifactSource(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || len(value) > len("https://")+500 || parsed.Scheme != "https" ||
		parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" || parsed.User != nil ||
		strings.ContainsRune(value, '#') {
		return errors.New("artifact source must be an absolute HTTPS URL")
	}
	for _, character := range value[len("https://"):] {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._~:/?#[\\]@!$&'()*+,;=%-", character) {
			continue
		}
		return errors.New("artifact source contains an unsupported character")
	}
	return nil
}
