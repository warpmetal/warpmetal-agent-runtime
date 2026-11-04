package reconcile

// WP-211B prepare-stage agent-kit materialization call site.
//
// The call site is gated by exactly one compiled TEST venue record selected via
// WARPMETAL_RUNTIME_AGENT_KIT_VENUE (empty/unknown selects nothing -> production
// default no-op). The produced invocation is bounded and closed, the exec
// binding uses the fixed supervisor action argv (no shell), the envelope is
// independently verified (binding + compiled closure/adoption + digest + nested
// receipt), and the verified receipt is persisted idempotently by the
// deterministic materialization identity. Nothing here grants a credential,
// tool/MCP closure, session or first-task effect.

import (
	"context"
	"errors"
	"log"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/agentkit"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// controllerAgentKitBlocked is the closed local diagnostic code for a
// prepare-stage materialization refusal. It is stored on the parent row as the
// block reason; the wire report's lastError.code stays in the backend enum.
type controllerAgentKitError struct {
	Code string
	Err  error
}

func (e *controllerAgentKitError) Error() string {
	if e.Err == nil {
		return "agent kit prepare blocked: " + e.Code
	}
	return "agent kit prepare blocked: " + e.Code + ": " + e.Err.Error()
}

func (e *controllerAgentKitError) Unwrap() error { return e.Err }

func controllerAgentKitBlockedCode(err error) (string, bool) {
	var typed *controllerAgentKitError
	if errors.As(err, &typed) && typed.Code != "" {
		return typed.Code, true
	}
	var prepare *agentkit.PrepareError
	if errors.As(err, &prepare) && prepare.Code != "" {
		return prepare.Code, true
	}
	return "", false
}

// stageControllerAgentKit materializes one applied v2 agent kit in the target
// cell and persists the verified receipt. A nil venue is the production default
// and returns without any effect.
func (r *Reconciler) stageControllerAgentKit(ctx context.Context, op model.WorkspaceApplicationOperation, parent model.ControllerParentIntent, project workspacecatalog.RegisteredProject) error {
	venue, err := agentkit.VenueSelected()
	if err != nil {
		return &controllerAgentKitError{Code: "agent_kit_venue_denied", Err: err}
	}
	if venue == nil {
		// Production default: no materialization selected; the kit stays a
		// declared-only fact exactly as before WP-211B.
		return nil
	}
	if len(op.Configuration.AgentSetup) == 0 {
		// Retained v1 operation: no agentSetup declared, nothing to materialize.
		return nil
	}
	if r.ManagedRuntime == nil || r.Store == nil {
		return &controllerAgentKitError{Code: agentkit.PrepareUnavailable, Err: errors.New("agent kit materialization dependency pending")}
	}
	if project.ContainerRoot == "" {
		return &controllerAgentKitError{Code: agentkit.PrepareRequestInvalid, Err: errors.New("registered project container root missing")}
	}
	materializer := agentkit.Materializer{
		Exec: func(ctx context.Context, sandboxID string, action containers.ManagedSupervisorAction, request []byte) ([]byte, []byte, error) {
			return r.ManagedRuntime.ExecManagedSupervisor(ctx, sandboxID, action, request)
		},
		Store: r.Store,
		Now:   r.now,
	}
	record, created, err := materializer.Prepare(ctx, agentkit.PrepareInput{
		Operation:   op,
		Owner:       parent.Owner,
		Workspace:   parent.Workspace,
		ProjectRoot: project.ContainerRoot,
	}, *venue)
	if err != nil {
		code, _ := agentkit.PrepareErrorCode(err)
		if code == "" {
			code = "agent_kit_materialization_failed"
		}
		if !created {
			log.Printf("agent kit prepare blocked code=%s operationId=%s sandboxId=%s: %v", code, op.OperationID, op.SandboxID, err)
		}
		return &controllerAgentKitError{Code: code, Err: err}
	}
	if record.MaterializationID == "" {
		return nil
	}
	log.Printf("agent kit prepare complete materializationId=%s operationId=%s created=%t closureDigest=%s",
		record.MaterializationID, record.ApplicationOperationID, created, record.ClosureDigest)
	return nil
}
