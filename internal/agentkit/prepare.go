package agentkit

// WP-211B prepare-stage orchestration: build the closed in-cell invocation from
// the application operation's saved v2 agentSetup, execute the packaged
// supervisor action through the cell exec binding, verify the bounded envelope,
// and persist the verified materialization receipt idempotently.
//
// Production default: the caller selects a venue; an empty/unknown venue means
// no materialization (the returned venue is nil). No credential, tool, MCP,
// session or first-task effect is ever created here, and the materializer runs
// offline with its own 30 s in-channel deadline.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// ContainerSandboxHome is the cell sandbox home the supervisor's project-root
// validation uses (the exec working directory is the same path).
const ContainerSandboxHome = "/home/agent"

// ExecSupervisor is the bounded cell exec binding for one fixed supervisor
// action (no shell, argv fixed by the Runtime, bounded stdout).
type ExecSupervisor func(context.Context, string, containers.ManagedSupervisorAction, []byte) ([]byte, []byte, error)

// MaterializationStore is the local durable verified-receipt store.
type MaterializationStore interface {
	AgentKitMaterialization(context.Context, string, string, int64) (*model.AgentKitMaterialization, error)
	PutAgentKitMaterialization(context.Context, model.AgentKitMaterialization) (bool, error)
}

// PrepareInput is the exact Runtime identity needed to build the invocation.
type PrepareInput struct {
	Operation   model.WorkspaceApplicationOperation
	Owner       model.ControllerOwner
	Workspace   model.ManagedServiceWorkspaceV1
	ProjectRoot string
}

// PrepareError is a typed fail-closed prepare-stage refusal. Codes are stable
// and closed; Detail is bounded and never contains request/kit content.
type PrepareError struct {
	Code   string
	Detail string
	Err    error
}

func (e *PrepareError) Error() string {
	if e.Detail != "" {
		return "agent kit prepare refused (" + e.Code + "): " + e.Detail
	}
	return "agent kit prepare refused (" + e.Code + ")"
}

func (e *PrepareError) Unwrap() error { return e.Err }

// Closed prepare-stage refusal codes.
const (
	PrepareKitMissing      = "agent_kit_kit_missing"
	PrepareRequestInvalid  = "agent_kit_request_invalid"
	PrepareExecFailed      = "agent_kit_exec_failed"
	PrepareExecTimeout     = "agent_kit_exec_timeout"
	PrepareEnvelopeInvalid = "agent_kit_envelope_invalid"
	PrepareVerification    = "agent_kit_verification_failed"
	PreparePersistence     = "agent_kit_persistence_conflict"
	PrepareBoundsExceeded  = "agent_kit_bounds_exceeded"
	PrepareUnavailable     = "agent_kit_unavailable"
)

func prepareRefuse(code, detail string, err error) *PrepareError {
	if len(detail) > 160 {
		detail = detail[:160]
	}
	return &PrepareError{Code: code, Detail: strings.ReplaceAll(detail, "\x00", ""), Err: err}
}

// PrepareErrorCode extracts the typed refusal code from an error chain.
func PrepareErrorCode(err error) (string, bool) {
	var prepare *PrepareError
	if errors.As(err, &prepare) {
		return prepare.Code, true
	}
	return "", false
}

// Materializer performs one prepare-stage materialization.
type Materializer struct {
	Exec  ExecSupervisor
	Store MaterializationStore
	Now   func() time.Time
}

func (m Materializer) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

// Prepare builds, executes, verifies and persists the materialization receipt.
// The bool reports whether a new first record was created; an already verified
// retry returns the retained record with created=false and does not re-exec.
func (m Materializer) Prepare(ctx context.Context, input PrepareInput, venue Venue) (model.AgentKitMaterialization, bool, error) {
	var empty model.AgentKitMaterialization
	if !validVenue(venue) || venue.AdoptionID == "" {
		return empty, false, prepareRefuse(PrepareUnavailable, "venue", errVenueDenied)
	}
	if m.Exec == nil || m.Store == nil {
		return empty, false, prepareRefuse(PrepareUnavailable, "dependency", nil)
	}
	if len(input.Operation.Configuration.AgentSetup) == 0 {
		// A retained v1 configuration declares no kit: declared-only, no-op.
		return empty, false, nil
	}
	target := Target{
		SandboxID:         input.Operation.SandboxID,
		SandboxGeneration: input.Operation.SandboxGeneration,
		SandboxRoot:       ContainerSandboxHome,
		ProjectRoot:       input.ProjectRoot,
		Workspace: TargetWorkspace{
			SelectionID:     input.Workspace.SelectionID,
			ProjectID:       input.Workspace.ProjectID,
			WorkspaceEpoch:  input.Workspace.WorkspaceEpoch,
			RootAttestation: input.Workspace.RootAttestation,
		},
	}
	if input.Owner.SandboxID != "" && input.Owner.SandboxID != input.Operation.SandboxID {
		return empty, false, prepareRefuse(PrepareRequestInvalid, "sandbox", nil)
	}
	request, err := BuildRequest(input.Operation, target, CompiledSnapshotPin(), venue)
	if err != nil {
		return empty, false, prepareRefuse(PrepareRequestInvalid, kitErrorDetail(err), err)
	}
	invocation, err := BuildInvocation(request, venue)
	if err != nil {
		return empty, false, prepareRefuse(PrepareRequestInvalid, kitErrorDetail(err), err)
	}
	raw, err := CanonicalInvocation(invocation)
	if err != nil {
		return empty, false, prepareRefuse(PrepareRequestInvalid, "canonical", err)
	}
	// Idempotency pre-check: a retained verified record is returned and the cell
	// is not re-executed. A different identity/digest fails closed.
	retained, err := m.Store.AgentKitMaterialization(ctx, request.MaterializationID,
		request.Target.SandboxID, request.Target.SandboxGeneration)
	if err != nil {
		return empty, false, prepareRefuse(PreparePersistence, "read", err)
	}
	if retained != nil {
		if retained.KitDigest != request.KitDigest ||
			retained.ClosureDigest != venue.ClosureDigest ||
			retained.AdoptionID != venue.AdoptionID ||
			retained.ConfigurationDigest != request.Configuration.ConfigurationDigest {
			return empty, false, prepareRefuse(PreparePersistence, "identity conflict", ErrMaterializationConflict)
		}
		// A retained record is only a valid idempotent retry when its persisted
		// envelope still independently verifies; tampered/inconsistent retained
		// evidence fails closed instead of being silently trusted.
		if _, err := VerifyInvocation(request, venue, retained.EnvelopeJSON); err != nil {
			return empty, false, prepareRefuse(PreparePersistence, "retained evidence", err)
		}
		return *retained, false, nil
	}
	envelope, diagnostic, err := m.Exec(ctx, input.Operation.SandboxID, containers.ManagedSupervisorMaterializeAgentKit, raw)
	if err != nil {
		code := PrepareExecFailed
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			code = PrepareExecTimeout
		}
		return empty, false, prepareRefuse(code, boundedDiagnostic(diagnostic), err)
	}
	if len(envelope) == 0 || len(envelope) > model.AgentKitMaterializationEnvelopeMaximum {
		return empty, false, prepareRefuse(PrepareBoundsExceeded, "envelope", nil)
	}
	result, err := VerifyInvocation(request, venue, envelope)
	if err != nil {
		return empty, false, prepareRefuse(PrepareVerification, kitErrorDetail(err), err)
	}
	skillDigests := make(map[string]string, len(result.Materialization.Skills))
	for _, skill := range result.Materialization.Skills {
		skillDigests[skill.ID] = skill.ContentDigest
	}
	record := model.AgentKitMaterialization{
		FormatVersion:                model.AgentKitMaterializationFormatVersion,
		MaterializationID:            request.MaterializationID,
		ApplicationOperationID:       input.Operation.OperationID,
		SandboxID:                    input.Operation.SandboxID,
		SandboxGeneration:            input.Operation.SandboxGeneration,
		ConfigurationID:              request.Configuration.ConfigurationID,
		ConfigurationRevision:        request.Configuration.ConfigurationRevision,
		ConfigurationDigest:          request.Configuration.ConfigurationDigest,
		KitDigest:                    request.KitDigest,
		AdoptionID:                   result.AdoptionID,
		Venue:                        result.Venue,
		ClosureDigest:                result.Closure.ClosureDigest,
		EnvelopeDigest:               result.EnvelopeDigest,
		MaterializationReceiptDigest: result.Materialization.ReceiptDigest,
		InstructionDigest:            result.Materialization.Instruction.SHA256,
		SkillContentDigests:          skillDigests,
		EnvelopeJSON:                 append(json.RawMessage(nil), envelope...),
		VerifiedAt:                   m.now().Format(time.RFC3339),
	}
	if err := record.Validate(); err != nil {
		return empty, false, prepareRefuse(PrepareVerification, "record", err)
	}
	created, err := m.Store.PutAgentKitMaterialization(ctx, record)
	if err != nil {
		return empty, false, prepareRefuse(PreparePersistence, "write", err)
	}
	log.Printf("agent kit materialization verified materializationId=%s operationId=%s kitDigest=%s closureDigest=%s receiptDigest=%s created=%t",
		record.MaterializationID, record.ApplicationOperationID, record.KitDigest,
		record.ClosureDigest, record.MaterializationReceiptDigest, created)
	return record, created, nil
}

// CompiledSnapshotPin is the compiled vendored-snapshot identity; it is the same
// value the materializer and the adoption record are pinned to.
func CompiledSnapshotPin() SnapshotPin {
	return SnapshotPin{
		CatalogID:      snapshotCatalogID,
		SourceRepo:     snapshotSourceRepo,
		ResolvedCommit: SnapshotCommit,
		ContentDigest:  SnapshotContentDigest,
	}
}

// ErrMaterializationConflict reports a retained/different verified record.
var ErrMaterializationConflict = errors.New("agent kit materialization record conflict")

func kitErrorDetail(err error) string {
	var typed *Error
	if errors.As(err, &typed) {
		if typed.Detail != "" {
			return typed.Code + ":" + typed.Detail
		}
		return typed.Code
	}
	return fmt.Sprintf("%T", err)
}

func boundedDiagnostic(diagnostic []byte) string {
	text := strings.TrimSpace(string(diagnostic))
	text = strings.ReplaceAll(text, "\x00", "")
	if len(text) > 120 {
		text = text[:120]
	}
	return text
}
