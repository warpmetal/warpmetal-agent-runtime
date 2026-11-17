package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/boxcredentials"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providergateway"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// This file wires the existing scoped provider gateway lifecycle manager
// (internal/providergateway) and the Box credential opener
// (internal/boxcredentials) into the reconciler. The runtime wiring supplies the
// Executor: Phase P2d had none (a manifest that declares provider gateways
// failed the pass closed), and Phase P4a can supply the reviewed external
// provider executor (internal/providerexec). When it is absent the fail-closed
// behavior is unchanged. No credential material, envelope, ciphertext, tool
// argument or tool result is ever persisted, reported or logged here.

// errProviderGatewayNotEnabled is the fail-closed sentinel returned when the
// manifest requires provider gateways but the runtime wiring is incomplete.
var errProviderGatewayNotEnabled = errors.New(
	"provider gateway requirements are present but the provider gateway feature is not enabled",
)

// errProviderGatewayCloseFailed marks a gateway teardown failure. Closing is
// retried on the next pass; it never silently leaves a gateway behind.
var errProviderGatewayCloseFailed = errors.New("provider gateway teardown failed")

// ProviderGatewayHandle is one running scoped provider gateway. It is returned
// by Start; Close tears the gateway down, and a well-behaved implementation
// destroys the opened credential exactly once as part of that teardown.
type ProviderGatewayHandle interface {
	Close(context.Context) error
}

// ProviderGatewayManager is the narrow provider gateway lifecycle boundary the
// reconciler depends on. It is satisfied by ProviderGateways (the production
// adapter over *providergateway.Manager) and by test doubles.
//
// Start takes ownership of request.Credential on every path: a failed Start
// destroys it before returning, and a successful Start's handle destroys it
// exactly once when closed. Implementations must be safe for concurrent use.
type ProviderGatewayManager interface {
	Start(context.Context, providergateway.Request) (ProviderGatewayHandle, error)
	// Has reports whether a gateway is already running for the exact
	// (sandboxID, runID) pair. It makes a retried pass idempotent.
	Has(sandboxID, runID string) bool
	// CloseSandbox closes every gateway belonging to the sandbox.
	CloseSandbox(context.Context, string) error
}

// ProviderCredentialOpener opens one sealed Box credential by id, in memory
// only. It is satisfied by BoxCredentialOpener (the production adapter over
// *boxcredentials.Manager) and by test doubles. The returned credential is
// non-nil on success and is never persisted or logged.
type ProviderCredentialOpener interface {
	OpenCredential(credentialID string) (providergateway.Credential, error)
}

// ProviderGateways adapts the concrete provider gateway process manager to the
// reconciler's narrow lifecycle boundary.
type ProviderGateways struct {
	Manager *providergateway.Manager
}

// Start implements ProviderGatewayManager.
func (gateways ProviderGateways) Start(
	ctx context.Context,
	request providergateway.Request,
) (ProviderGatewayHandle, error) {
	if gateways.Manager == nil {
		return nil, errors.New("provider gateways: lifecycle manager is not configured")
	}
	handle, err := gateways.Manager.Start(ctx, request)
	if err != nil {
		return nil, err
	}
	if handle == nil {
		return nil, errors.New("provider gateways: lifecycle manager returned no gateway handle")
	}
	return handle, nil
}

// Has implements ProviderGatewayManager.
func (gateways ProviderGateways) Has(sandboxID, runID string) bool {
	return gateways.Manager != nil && gateways.Manager.Has(sandboxID, runID)
}

// CloseSandbox implements ProviderGatewayManager.
func (gateways ProviderGateways) CloseSandbox(ctx context.Context, sandboxID string) error {
	if gateways.Manager == nil {
		return nil
	}
	return gateways.Manager.CloseSandbox(ctx, sandboxID)
}

// BoxCredentialOpener adapts the P2 Box credential bridge to the reconciler's
// narrow opener. The credential is opened in memory and handed to the gateway
// manager, which owns its destruction; nothing is persisted.
type BoxCredentialOpener struct {
	Manager *boxcredentials.Manager
}

// OpenCredential implements ProviderCredentialOpener.
func (opener BoxCredentialOpener) OpenCredential(credentialID string) (providergateway.Credential, error) {
	if opener.Manager == nil {
		return nil, errors.New("provider credential opener: box credential bridge is not configured")
	}
	credential, err := opener.Manager.OpenCredential(credentialID, boxcredentials.OpenExpectations{})
	if err != nil {
		return nil, err
	}
	if credential == nil {
		return nil, errors.New("provider credential opener: box credential bridge returned no credential")
	}
	return credential, nil
}

// providerGatewayDependencies reports the first missing P2d wiring dependency,
// or nil when the feature is fully enabled.
func (r *Reconciler) providerGatewayDependencies() error {
	switch {
	case r.ProviderGateways == nil:
		return fmt.Errorf("%w: lifecycle manager is not configured", errProviderGatewayNotEnabled)
	case r.ProviderCredentials == nil:
		return fmt.Errorf("%w: box credential opener is not configured", errProviderGatewayNotEnabled)
	case r.ProviderExecutor == nil:
		return fmt.Errorf(
			"%w: tool executor is not configured (production provider execution is disabled)",
			errProviderGatewayNotEnabled,
		)
	}
	return nil
}

// providerGatewayErrorCode maps a gateway reconciliation error to the stable
// bounded sandbox error code persisted in local state and reported to the
// control plane.
func providerGatewayErrorCode(err error) string {
	switch {
	case errors.Is(err, errProviderGatewayNotEnabled):
		return "provider_gateway_not_enabled"
	case errors.Is(err, errProviderGatewayCloseFailed):
		return "provider_gateway_close_failed"
	default:
		return "provider_gateway_start_failed"
	}
}

// closeSandboxProviderGateways closes every gateway that belongs to the sandbox
// and releases the reconciler's retained run ids. It is the teardown used for
// stop, delete, generation change and omitted-sandbox transitions.
func (r *Reconciler) closeSandboxProviderGateways(ctx context.Context, sandboxID string) error {
	if err := r.closeProviderGatewaysForSandbox(ctx, sandboxID); err != nil {
		return fmt.Errorf("%w: %v", errProviderGatewayCloseFailed, err)
	}
	return nil
}

// closeProviderGatewaysForSandbox closes the sandbox's gateways through the
// manager (all of them) and closes every handle the reconciler retained for it.
// Handles are released before the calls are made, so a failed teardown is still
// retried through CloseSandbox on the next pass instead of blocking a restart.
func (r *Reconciler) closeProviderGatewaysForSandbox(ctx context.Context, sandboxID string) error {
	handles := r.takeProviderGatewayHandles(sandboxID)
	r.forgetProviderGatewayGeneration(sandboxID)
	var errs []error
	if r.ProviderGateways != nil {
		if err := r.ProviderGateways.CloseSandbox(ctx, sandboxID); err != nil {
			errs = append(errs, err)
		}
	}
	for _, handle := range handles {
		// The production handle is already closed by CloseSandbox; Close is
		// idempotent. Closing explicitly also covers managers that do not track
		// every started handle.
		if err := handle.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// closeProviderGateway closes one requirement's gateway by run id.
func (r *Reconciler) closeProviderGateway(ctx context.Context, sandboxID, runID string) error {
	handle := r.providerGatewayHandle(sandboxID, runID)
	if handle != nil {
		if err := handle.Close(ctx); err != nil {
			return err
		}
		r.dropProviderGatewayHandle(sandboxID, runID)
		return nil
	}
	// The reconciler has no handle for this run, but a gateway may still be
	// running (for example one adopted through Has before a restart). Fall back
	// to closing every gateway of the sandbox; the desired requirements are
	// re-started by the caller in this same pass.
	if r.ProviderGateways != nil && r.ProviderGateways.Has(sandboxID, runID) {
		return r.closeProviderGatewaysForSandbox(ctx, sandboxID)
	}
	return nil
}

// reconcileProviderGateways brings the sandbox's running gateways in line with
// the manifest requirements for this pass. previous is the requirement list the
// previous pass persisted; desired is the current manifest list (already
// persisted on local). The function is idempotent: a gateway that is already
// running for the exact (sandboxID, runID) pair is skipped, a requirement that
// disappeared or changed is closed and re-started, and no requirement is
// started twice across retried passes.
func (r *Reconciler) reconcileProviderGateways(
	ctx context.Context,
	local *state.LocalSandbox,
	previous, desired []model.ProviderGatewayRequirement,
	workspace string,
) error {
	if len(desired) == 0 {
		// Requirements disappeared (or never existed): release every gateway
		// and id this sandbox holds.
		if len(previous) == 0 && !r.hasProviderGatewayHandles(local.ID) {
			return nil
		}
		return r.closeSandboxProviderGateways(ctx, local.ID)
	}
	// The manifest requires gateways: all three dependencies must be wired
	// before the sandbox may be claimed ready. This is the explicit, bounded
	// fail-closed "feature not enabled" error.
	if err := r.providerGatewayDependencies(); err != nil {
		return err
	}

	previousByRun := make(map[string]model.ProviderGatewayRequirement, len(previous))
	for _, requirement := range previous {
		previousByRun[requirement.RunID] = requirement
	}
	desiredByRun := make(map[string]model.ProviderGatewayRequirement, len(desired))
	for _, requirement := range desired {
		desiredByRun[requirement.RunID] = requirement
	}
	// A tracked gateway is retained only when the previous and desired
	// requirements for that exact run id are identical. Anything else is a
	// replaced requirement and must not keep the old credential/tool allowlist.
	for _, runID := range r.providerGatewayRunIDs(local.ID) {
		wanted, wantedExists := desiredByRun[runID]
		previousRequirement, previousExists := previousByRun[runID]
		if wantedExists && previousExists &&
			model.SameProviderGatewayRequirements(
				[]model.ProviderGatewayRequirement{previousRequirement},
				[]model.ProviderGatewayRequirement{wanted},
			) {
			continue
		}
		if err := r.closeProviderGateway(ctx, local.ID, runID); err != nil {
			return fmt.Errorf("%w: run %q: %v", errProviderGatewayCloseFailed, runID, err)
		}
	}
	// Previous requirements that never produced a retained handle (so they are
	// only visible through Has) are closed here too, so a stale run id can
	// never survive a pass.
	for _, previousRequirement := range previous {
		wanted, wantedExists := desiredByRun[previousRequirement.RunID]
		if wantedExists && model.SameProviderGatewayRequirements(
			[]model.ProviderGatewayRequirement{previousRequirement},
			[]model.ProviderGatewayRequirement{wanted},
		) {
			continue
		}
		if r.providerGatewayHandle(local.ID, previousRequirement.RunID) != nil {
			continue
		}
		if err := r.closeProviderGateway(ctx, local.ID, previousRequirement.RunID); err != nil {
			return fmt.Errorf(
				"%w: run %q: %v", errProviderGatewayCloseFailed, previousRequirement.RunID, err,
			)
		}
	}
	// Start one scoped gateway per requirement, in manifest order.
	for _, requirement := range desired {
		if r.providerGatewayHandle(local.ID, requirement.RunID) != nil {
			continue
		}
		if r.ProviderGateways.Has(local.ID, requirement.RunID) {
			continue
		}
		handle, err := r.startProviderGateway(ctx, local, requirement, workspace)
		if err != nil {
			return fmt.Errorf("run %q: %w", requirement.RunID, err)
		}
		r.setProviderGatewayHandle(local.ID, requirement.RunID, handle)
	}
	return nil
}

// startProviderGateway opens one Box credential and starts its scoped gateway
// inside the sandbox workspace. The manager takes ownership of the credential on
// every path; the returned handle releases it on teardown.
func (r *Reconciler) startProviderGateway(
	ctx context.Context,
	local *state.LocalSandbox,
	requirement model.ProviderGatewayRequirement,
	workspace string,
) (ProviderGatewayHandle, error) {
	credential, err := r.ProviderCredentials.OpenCredential(requirement.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("open credential: %w", err)
	}
	if credential == nil {
		return nil, errors.New("open credential: opener returned no credential")
	}
	handle, err := r.ProviderGateways.Start(ctx, providergateway.Request{
		SandboxID:         local.ID,
		RunID:             requirement.RunID,
		WorkspaceHostRoot: workspace,
		// The sandbox workspace is mounted at /home/agent inside the
		// container, so the agent-facing MCP socket path is deterministic.
		ContainerRoot: providergateway.DefaultContainerRoot,
		ProviderID:    requirement.ProviderID,
		ConnectionID:  requirement.EffectiveConnectionID(),
		Tools:         providerGatewayTools(requirement.Tools),
		Executor:      r.ProviderExecutor,
		// An executor that declares its own per-call bound (the external
		// provider executor does) sets the gateway's call deadline to the same
		// bound, so an operator-configured executor timeout is not silently
		// shortened by the gateway default. A plain in-process executor keeps
		// the gateway default.
		ToolTimeout: providerGatewayToolTimeout(r.ProviderExecutor),
		Credential:  credential,
	})
	if err != nil {
		// The manager destroys the credential on every failed Start. Destroy is
		// idempotent, so this defensive call only covers an implementation that
		// violates the ownership contract and never leaks a live credential.
		credential.Destroy()
		return nil, fmt.Errorf("start gateway: %w", err)
	}
	return handle, nil
}

// providerGatewayToolTimeout returns the per-call bound the configured executor
// enforces, or zero when the executor does not declare one. Zero keeps the
// gateway's own default.
func providerGatewayToolTimeout(executor providergateway.Executor) time.Duration {
	if timeoutProvider, ok := executor.(providergateway.ToolTimeoutProvider); ok {
		return timeoutProvider.ToolTimeout()
	}
	return 0
}

// providerGatewayTools converts the validated manifest tool declarations into
// the gateway's declared tool list, detaching the raw schema bytes from the
// manifest authority snapshot.
func providerGatewayTools(tools []model.ProviderGatewayTool) []providergateway.Tool {
	converted := make([]providergateway.Tool, len(tools))
	for index := range tools {
		converted[index] = providergateway.Tool{
			Name:        tools[index].Name,
			Description: tools[index].Description,
			InputSchema: append(json.RawMessage(nil), tools[index].InputSchema...),
		}
	}
	return converted
}

// cloneProviderGatewayRequirements deep-copies a validated requirement list so
// the persisted local state can never alias the manifest authority snapshot.
func cloneProviderGatewayRequirements(
	requirements []model.ProviderGatewayRequirement,
) []model.ProviderGatewayRequirement {
	if len(requirements) == 0 {
		return nil
	}
	clone := make([]model.ProviderGatewayRequirement, len(requirements))
	for index := range requirements {
		clone[index] = requirements[index]
		if len(requirements[index].Tools) == 0 {
			continue
		}
		clone[index].Tools = make([]model.ProviderGatewayTool, len(requirements[index].Tools))
		copy(clone[index].Tools, requirements[index].Tools)
		for toolIndex := range clone[index].Tools {
			clone[index].Tools[toolIndex].InputSchema = append(
				json.RawMessage(nil), requirements[index].Tools[toolIndex].InputSchema...,
			)
		}
	}
	return clone
}

// providerGatewayHandle returns the handle retained for one exact run id.
func (r *Reconciler) providerGatewayHandle(sandboxID, runID string) ProviderGatewayHandle {
	r.providerGatewayMu.Lock()
	defer r.providerGatewayMu.Unlock()
	return r.providerGateways[sandboxID][runID]
}

// setProviderGatewayHandle retains the handle for a started gateway.
func (r *Reconciler) setProviderGatewayHandle(sandboxID, runID string, handle ProviderGatewayHandle) {
	r.providerGatewayMu.Lock()
	defer r.providerGatewayMu.Unlock()
	if r.providerGateways == nil {
		r.providerGateways = make(map[string]map[string]ProviderGatewayHandle)
	}
	runHandles := r.providerGateways[sandboxID]
	if runHandles == nil {
		runHandles = make(map[string]ProviderGatewayHandle)
		r.providerGateways[sandboxID] = runHandles
	}
	runHandles[runID] = handle
}

// dropProviderGatewayHandle releases one retained run id.
func (r *Reconciler) dropProviderGatewayHandle(sandboxID, runID string) {
	r.providerGatewayMu.Lock()
	defer r.providerGatewayMu.Unlock()
	runHandles := r.providerGateways[sandboxID]
	delete(runHandles, runID)
	if len(runHandles) == 0 {
		delete(r.providerGateways, sandboxID)
	}
}

// takeProviderGatewayHandles releases and returns every handle retained for the
// sandbox, including the sandbox entry itself.
func (r *Reconciler) takeProviderGatewayHandles(sandboxID string) []ProviderGatewayHandle {
	r.providerGatewayMu.Lock()
	defer r.providerGatewayMu.Unlock()
	runHandles := r.providerGateways[sandboxID]
	delete(r.providerGateways, sandboxID)
	if len(runHandles) == 0 {
		return nil
	}
	handles := make([]ProviderGatewayHandle, 0, len(runHandles))
	for _, handle := range runHandles {
		handles = append(handles, handle)
	}
	return handles
}

// providerGatewayRunIDs returns a snapshot of the run ids this reconciler
// retains a handle for.
func (r *Reconciler) providerGatewayRunIDs(sandboxID string) []string {
	r.providerGatewayMu.Lock()
	defer r.providerGatewayMu.Unlock()
	runHandles := r.providerGateways[sandboxID]
	if len(runHandles) == 0 {
		return nil
	}
	runIDs := make([]string, 0, len(runHandles))
	for runID := range runHandles {
		runIDs = append(runIDs, runID)
	}
	return runIDs
}

// hasProviderGatewayHandles reports whether the reconciler retains any handle
// for the sandbox.
func (r *Reconciler) hasProviderGatewayHandles(sandboxID string) bool {
	r.providerGatewayMu.Lock()
	defer r.providerGatewayMu.Unlock()
	return len(r.providerGateways[sandboxID]) > 0
}

// providerGatewayTrackedGeneration returns the sandbox generation whose
// gateways this reconciler has already transitioned, or zero when none.
func (r *Reconciler) providerGatewayTrackedGeneration(sandboxID string) int64 {
	r.providerGatewayMu.Lock()
	defer r.providerGatewayMu.Unlock()
	return r.providerGatewayGenerations[sandboxID]
}

// setProviderGatewayTrackedGeneration records the generation whose gateway
// transition has already been attempted. A retried pass in the same generation
// then continues with the gateways that are already running instead of closing
// and reopening them.
func (r *Reconciler) setProviderGatewayTrackedGeneration(sandboxID string, generation int64) {
	r.providerGatewayMu.Lock()
	defer r.providerGatewayMu.Unlock()
	if r.providerGatewayGenerations == nil {
		r.providerGatewayGenerations = make(map[string]int64)
	}
	r.providerGatewayGenerations[sandboxID] = generation
}

// forgetProviderGatewayGeneration releases the transition record for the
// sandbox so the next observed generation is reconciled from scratch.
func (r *Reconciler) forgetProviderGatewayGeneration(sandboxID string) {
	r.providerGatewayMu.Lock()
	defer r.providerGatewayMu.Unlock()
	delete(r.providerGatewayGenerations, sandboxID)
}
