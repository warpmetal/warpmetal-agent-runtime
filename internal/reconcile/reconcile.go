package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/access"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type Workspaces interface {
	Ensure(context.Context, string, int) (string, error)
	Destroy(context.Context, string) error
}

type Sessions interface {
	TerminateGrant(context.Context, string) error
	TerminateSandbox(context.Context, string) error
}

type Reconciler struct {
	Store        *state.Store
	Engine       containers.Engine
	Workspaces   Workspaces
	Access       access.Renderer
	Sessions     Sessions
	HostCapacity model.Resources
	ServerID     string
	Now          func() time.Time

	mu sync.Mutex
}

func (r *Reconciler) Reconcile(ctx context.Context, manifest model.Manifest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	lastRevision, err := r.Store.Revision(ctx)
	if err != nil {
		return err
	}
	if err := model.ValidateManifest(manifest, r.ServerID, lastRevision); err != nil {
		return err
	}
	if !requested(manifest.Sandboxes).Fits(r.HostCapacity) {
		return errors.New("desired sandboxes exceed detected host capacity")
	}
	setupSandboxes := make(map[string]bool, len(manifest.SetupOperations))
	for _, operation := range manifest.SetupOperations {
		setupSandboxes[operation.SandboxID] = true
	}
	for _, desired := range manifest.Sandboxes {
		if err := r.reconcileSandbox(ctx, desired, manifest.ImageDigest, setupSandboxes[desired.ID]); err != nil {
			return fmt.Errorf("reconcile sandbox %s: %w", desired.ID, err)
		}
	}
	if err := r.reconcileMissingSandboxes(ctx, manifest.Sandboxes); err != nil {
		return err
	}
	if err := r.reconcileGrants(ctx, manifest.AccessGrants); err != nil {
		return err
	}
	setupReady, err := r.reconcileSetupOperations(ctx, manifest)
	if err != nil {
		return err
	}
	if !setupReady {
		return nil
	}
	return r.Store.SetRevision(ctx, manifest.DesiredRevision)
}

func (r *Reconciler) reconcileMissingSandboxes(
	ctx context.Context,
	desired []model.Sandbox,
) error {
	desiredIDs := make(map[string]bool, len(desired))
	for _, sandbox := range desired {
		desiredIDs[sandbox.ID] = true
	}
	current, err := r.Store.Sandboxes(ctx)
	if err != nil {
		return err
	}
	for index := range current {
		local := &current[index]
		if desiredIDs[local.ID] {
			continue
		}
		if local.ObservedState != "deleted" {
			local.DesiredState = "deleted"
			if err := r.removeSandbox(ctx, local); err != nil {
				return fmt.Errorf("remove omitted sandbox %s: %w", local.ID, err)
			}
		}
		if err := r.Store.DeleteSandbox(ctx, local.ID); err != nil {
			return fmt.Errorf("prune sandbox tombstone %s: %w", local.ID, err)
		}
	}
	return nil
}

func (r *Reconciler) Expire(ctx context.Context) error {
	values, err := r.Store.Sandboxes(ctx)
	if err != nil {
		return err
	}
	current := r.now()
	for index := range values {
		value := &values[index]
		if value.Lifetime == "temporary" && value.ExpiresAt != nil &&
			!current.Before(*value.ExpiresAt) && value.ObservedState != "deleted" {
			value.DesiredState = "deleted"
			if err := r.removeSandbox(ctx, value); err != nil {
				return fmt.Errorf("expire sandbox %s: %w", value.ID, err)
			}
		}
	}
	return nil
}

func (r *Reconciler) Report(ctx context.Context, serverID, version string) (model.Report, error) {
	revision, err := r.Store.Revision(ctx)
	if err != nil {
		return model.Report{}, err
	}
	sandboxes, err := r.Store.Sandboxes(ctx)
	if err != nil {
		return model.Report{}, err
	}
	grants, err := r.Store.Grants(ctx)
	if err != nil {
		return model.Report{}, err
	}
	report := model.Report{
		ServerID:          serverID,
		AppliedRevision:   revision,
		SupervisorVersion: version,
		Sandboxes:         make([]model.SandboxReport, 0),
		AccessGrants:      make([]model.GrantReport, 0),
		SetupOperations:   make([]model.SetupOperationReport, 0),
	}
	for _, value := range sandboxes {
		item := model.SandboxReport{
			ID:                 value.ID,
			ObservedState:      value.ObservedState,
			ObservedGeneration: value.ObservedGeneration,
			ImageDigest:        value.ImageDigest,
			StartedAt:          value.StartedAt,
			ExpiresAt:          value.ExpiresAt,
		}
		if value.ErrorCode != "" {
			item.LastError = &model.ItemError{Code: value.ErrorCode, Message: value.ErrorMessage}
		}
		report.Sandboxes = append(report.Sandboxes, item)
	}
	for _, value := range grants {
		item := model.GrantReport{ID: value.ID, ObservedState: value.ObservedState}
		if value.ErrorCode != "" {
			item.LastError = &model.ItemError{Code: value.ErrorCode, Message: value.ErrorMessage}
		}
		report.AccessGrants = append(report.AccessGrants, item)
	}
	setupOperations, err := r.Store.SetupOperations(ctx)
	if err != nil {
		return model.Report{}, err
	}
	for _, value := range setupOperations {
		item := model.SetupOperationReport{
			ID:                value.ID,
			SandboxID:         value.SandboxID,
			SandboxGeneration: value.SandboxGeneration,
			ProfileID:         value.ProfileID,
			ProfileRevision:   value.ProfileRevision,
			ProfileDigest:     value.ProfileDigest,
			Status:            value.State,
			ReceiptDigest:     value.ReceiptDigest,
		}
		if value.ErrorCode != "" {
			item.LastError = &model.ItemError{Code: value.ErrorCode, Message: value.ErrorMessage}
		}
		report.SetupOperations = append(report.SetupOperations, item)
	}
	return report, nil
}

var setupReceiptDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type runnerSetupReceipt struct {
	ID                string                  `json:"id"`
	SandboxID         string                  `json:"sandboxId"`
	SandboxGeneration int64                   `json:"sandboxGeneration"`
	ProfileID         string                  `json:"profileId"`
	ProfileRevision   int64                   `json:"profileRevision"`
	ProfileDigest     string                  `json:"profileDigest"`
	ReceiptDigest     string                  `json:"receiptDigest"`
	Status            string                  `json:"status"`
	Provenance        *setupReceiptProvenance `json:"provenance,omitempty"`
	Error             *setupReceiptError      `json:"error,omitempty"`
}

type setupReceiptProvenance struct {
	Source         string `json:"source"`
	ArtifactSHA256 string `json:"artifactSha256"`
}

type setupReceiptError struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

func (r *Reconciler) reconcileSetupOperations(
	ctx context.Context,
	manifest model.Manifest,
) (bool, error) {
	desiredIDs := make(map[string]bool, len(manifest.SetupOperations))
	for _, desired := range manifest.SetupOperations {
		desiredIDs[desired.ID] = true
		request, err := json.Marshal(desired)
		if err != nil {
			return false, fmt.Errorf("encode setup operation %s: %w", desired.ID, err)
		}
		bodyDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(request))
		if err := r.Store.PutSetupOperation(ctx, state.LocalSetupOperation{
			ID:                desired.ID,
			SandboxID:         desired.SandboxID,
			SandboxGeneration: desired.SandboxGeneration,
			ProfileID:         desired.ProfileID,
			ProfileRevision:   desired.ProfileRevision,
			ProfileDigest:     desired.ProfileDigest,
			DesiredRevision:   manifest.DesiredRevision,
			BodyDigest:        bodyDigest,
			RequestJSON:       request,
			State:             "pending",
		}); err != nil {
			return false, fmt.Errorf("persist setup operation %s: %w", desired.ID, err)
		}
	}

	current, err := r.Store.SetupOperations(ctx)
	if err != nil {
		return false, err
	}
	for index := range current {
		operation := &current[index]
		if desiredIDs[operation.ID] || operation.State == "ready" ||
			operation.State == "failed" || operation.State == "cancelled" {
			continue
		}
		if err := r.Store.TransitionSetupOperation(
			ctx, operation.ID, "cancelled", nil, "", "",
		); err != nil {
			return false, fmt.Errorf("cancel omitted setup operation %s: %w", operation.ID, err)
		}
	}

	runnable := make([]state.LocalSetupOperation, 0, len(manifest.SetupOperations))
	newlyApplying := false
	for _, desired := range manifest.SetupOperations {
		operation, err := r.Store.SetupOperation(ctx, desired.ID)
		if err != nil {
			return false, err
		}
		if operation == nil {
			return false, fmt.Errorf("setup operation %s disappeared", desired.ID)
		}
		switch operation.State {
		case "ready":
			continue
		case "failed", "cancelled":
			return false, fmt.Errorf(
				"setup operation %s is terminal in state %s",
				operation.ID,
				operation.State,
			)
		}
		sandbox, err := r.Store.Sandbox(ctx, operation.SandboxID)
		if err != nil {
			return false, err
		}
		if sandbox == nil || sandbox.ObservedState != "running" ||
			sandbox.ObservedGeneration != operation.SandboxGeneration {
			return false, fmt.Errorf(
				"setup operation %s is waiting for its running sandbox generation",
				operation.ID,
			)
		}
		if operation.State == "pending" {
			if err := r.Store.TransitionSetupOperation(
				ctx, operation.ID, "applying", nil, "", "",
			); err != nil {
				return false, fmt.Errorf("start setup operation %s: %w", operation.ID, err)
			}
			newlyApplying = true
			continue
		}
		runnable = append(runnable, *operation)
	}
	if newlyApplying {
		return false, nil
	}
	if len(runnable) == 0 {
		return true, nil
	}
	if err := r.executeSetupOperation(ctx, runnable[0]); err != nil {
		return false, err
	}
	return len(runnable) == 1, nil
}

func (r *Reconciler) executeSetupOperation(
	ctx context.Context,
	operation state.LocalSetupOperation,
) error {
	executionContext, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	// Setup may arrive after creation, or resume after a daemon restart. Never
	// treat prior lifecycle readiness as proof of the current nested boundary.
	if err := r.Engine.Preflight(executionContext, operation.SandboxID); err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		transitionErr := r.Store.TransitionSetupOperation(
			ctx, operation.ID, "failed", nil, "nested_sandbox_preflight_failed", "nested sandbox preflight failed",
		)
		return errors.Join(fmt.Errorf("preflight setup operation %s: %w", operation.ID, err), transitionErr)
	}
	receiptJSON, _, err := r.Engine.ExecSetup(
		executionContext,
		operation.SandboxID,
		operation.RequestJSON,
	)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		transitionErr := r.Store.TransitionSetupOperation(
			ctx, operation.ID, "failed", nil, "setup_execution_failed", "setup runner failed",
		)
		return errors.Join(fmt.Errorf("execute setup operation %s: %w", operation.ID, err), transitionErr)
	}
	receipt, err := validateSetupReceipt(receiptJSON, operation)
	if err != nil {
		transitionErr := r.Store.TransitionSetupOperation(
			ctx, operation.ID, "failed", nil, "invalid_setup_receipt", "setup receipt was invalid",
		)
		return errors.Join(fmt.Errorf("validate setup operation %s receipt: %w", operation.ID, err), transitionErr)
	}
	if receipt.Status == "cancelled" {
		transitionErr := r.Store.TransitionSetupOperation(
			ctx, operation.ID, "cancelled", nil, "", "",
		)
		return errors.Join(
			fmt.Errorf("setup operation %s was cancelled by the runner", operation.ID),
			transitionErr,
		)
	}
	if receipt.Status == "failed" {
		code := "setup_failed"
		if receipt.Error != nil && receipt.Error.Code != "" {
			code = bounded(receipt.Error.Code, 80)
		}
		transitionErr := r.Store.TransitionSetupOperation(
			ctx, operation.ID, "failed", nil, code, "setup runner reported failure",
		)
		return errors.Join(
			fmt.Errorf("setup operation %s failed", operation.ID),
			transitionErr,
		)
	}
	if err := r.Store.TransitionSetupOperation(
		ctx, operation.ID, "ready", receiptJSON, "", "",
	); err != nil {
		return err
	}
	return nil
}

func validateSetupReceipt(payload []byte, operation state.LocalSetupOperation) (*runnerSetupReceipt, error) {
	if len(payload) == 0 || len(payload) > 64*1024 {
		return nil, errors.New("setup receipt size is invalid")
	}
	if err := rejectDuplicateJSONFields(payload); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var receipt runnerSetupReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("setup receipt contains trailing data")
	}
	if receipt.ID != operation.ID || receipt.SandboxID != operation.SandboxID ||
		receipt.SandboxGeneration != operation.SandboxGeneration ||
		receipt.ProfileID != operation.ProfileID ||
		receipt.ProfileRevision != operation.ProfileRevision ||
		receipt.ProfileDigest != operation.ProfileDigest {
		return nil, errors.New("setup receipt immutable tuple does not match")
	}
	if !setupReceiptDigestPattern.MatchString(receipt.ReceiptDigest) {
		return nil, errors.New("setup receipt digest is invalid")
	}
	canonical, err := canonicalUnsignedSetupReceipt(payload)
	if err != nil {
		return nil, err
	}
	expectedDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(canonical))
	if subtle.ConstantTimeCompare(
		[]byte(receipt.ReceiptDigest),
		[]byte(expectedDigest),
	) != 1 {
		return nil, errors.New("setup receipt digest does not authenticate its content")
	}
	if receipt.Status != "ready" && receipt.Status != "failed" && receipt.Status != "cancelled" {
		return nil, errors.New("setup receipt status is invalid")
	}
	if receipt.Provenance != nil &&
		(utf8.RuneCountInString(receipt.Provenance.Source) == 0 ||
			utf8.RuneCountInString(receipt.Provenance.Source) > 512 ||
			!setupReceiptDigestPattern.MatchString(receipt.Provenance.ArtifactSHA256)) {
		return nil, errors.New("setup receipt provenance is invalid")
	}
	if receipt.Error != nil &&
		(utf8.RuneCountInString(receipt.Error.Code) == 0 ||
			utf8.RuneCountInString(receipt.Error.Code) > 80 ||
			utf8.RuneCountInString(receipt.Error.Detail) > 500) {
		return nil, errors.New("setup receipt error is invalid")
	}
	if receipt.Status == "ready" && receipt.Error != nil {
		return nil, errors.New("ready setup receipt cannot contain an error")
	}
	if receipt.Status == "failed" && receipt.Error == nil {
		return nil, errors.New("failed setup receipt requires an error")
	}
	var objects map[string]json.RawMessage
	if err := json.Unmarshal(payload, &objects); err != nil {
		return nil, err
	}
	for _, field := range []string{"error", "provenance"} {
		if value, exists := objects[field]; exists && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("setup receipt %s must be an object", field)
		}
	}
	return &receipt, nil
}

func canonicalUnsignedSetupReceipt(payload []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode setup receipt for digest: %w", err)
	}
	delete(document, "receiptDigest")
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, fmt.Errorf("encode canonical setup receipt: %w", err)
	}
	return bytes.TrimSuffix(canonical.Bytes(), []byte("\n")), nil
}

func rejectDuplicateJSONFields(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := validateUniqueJSONValue(decoder); err != nil {
		return fmt.Errorf("setup receipt is not canonical JSON: %w", err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("setup receipt has trailing JSON token %v", token)
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

func (r *Reconciler) reconcileSandbox(
	ctx context.Context,
	desired model.Sandbox,
	imageDigest string,
	requiresSetup bool,
) error {
	local, err := r.Store.Sandbox(ctx, desired.ID)
	if err != nil {
		return err
	}
	isNew := local == nil
	if isNew {
		local = &state.LocalSandbox{
			ID:                 desired.ID,
			Name:               desired.Name,
			ObservedState:      "pending",
			ObservedGeneration: 0,
		}
	}
	local.Name = desired.Name
	local.DesiredState = desired.DesiredState
	local.Generation = desired.Generation
	local.Lifetime = desired.Lifetime
	local.ExpiresInSeconds = desired.ExpiresInSeconds
	local.Resources = desired.Resources
	targetImageDigest := desired.ImageDigest
	if targetImageDigest == "" {
		if local.ImageDigest != "" {
			targetImageDigest = local.ImageDigest
		} else {
			targetImageDigest = imageDigest
		}
	}
	// Pin a sandbox to the image used when it was first created. A new default
	// applies only to new sandboxes. Existing sandboxes change images only when
	// the control plane supplies an explicit per-sandbox digest and advances its
	// generation.
	if local.ImageDigest == "" {
		local.ImageDigest = targetImageDigest
	}
	refreshImage := local.ImageDigest != targetImageDigest
	if refreshImage && desired.Generation <= local.ObservedGeneration {
		return errors.New("sandbox image change requires a generation advance")
	}
	if local.StartedAt == nil && desired.StartedAt != nil {
		local.StartedAt = desired.StartedAt
	}
	if local.ExpiresAt == nil && desired.ExpiresAt != nil {
		local.ExpiresAt = desired.ExpiresAt
	}
	if local.Lifetime == "persistent" {
		local.ExpiresInSeconds = nil
		local.ExpiresAt = nil
	}
	if local.Lifetime == "temporary" && local.ExpiresAt != nil &&
		!r.now().Before(*local.ExpiresAt) {
		local.DesiredState = "deleted"
	}
	if err := r.Store.PutSandbox(ctx, *local); err != nil {
		return err
	}
	switch local.DesiredState {
	case "deleted":
		return r.removeSandbox(ctx, local)
	case "stopped":
		if refreshImage {
			workspace, err := r.Workspaces.Ensure(
				ctx,
				local.ID,
				local.Resources.WorkspaceDiskGiB,
			)
			if err != nil {
				return r.failSandbox(ctx, local, "workspace_create_failed", err)
			}
			local.ObservedState = "restarting"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
			if r.Sessions != nil {
				_ = r.Sessions.TerminateSandbox(ctx, local.ID)
			}
			if err := r.Engine.Replace(
				ctx,
				desired,
				workspace,
				targetImageDigest,
				false,
			); err != nil {
				return r.failSandbox(ctx, local, imageReplaceErrorCode(err), err)
			}
			local.ImageDigest = targetImageDigest
		}
		if local.ObservedState != "stopped" {
			local.ObservedState = "stopping"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
		}
		if r.Sessions != nil {
			_ = r.Sessions.TerminateSandbox(ctx, local.ID)
		}
		if err := r.Engine.Stop(ctx, local.ID); err != nil {
			return r.failSandbox(ctx, local, "container_stop_failed", err)
		}
		local.ObservedState = "stopped"
		local.ObservedGeneration = local.Generation
		return r.Store.PutSandbox(ctx, *local)
	case "running":
		if local.ObservedState == "deleted" && local.Lifetime == "temporary" {
			return nil
		}
		requiresNestedPreflight := requiresSetup && (refreshImage || local.ObservedState != "running" ||
			local.ObservedGeneration < local.Generation)
		workspace, err := r.Workspaces.Ensure(ctx, local.ID, local.Resources.WorkspaceDiskGiB)
		if err != nil {
			return r.failSandbox(ctx, local, "workspace_create_failed", err)
		}
		if refreshImage {
			local.ObservedState = "restarting"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
			if r.Sessions != nil {
				_ = r.Sessions.TerminateSandbox(ctx, local.ID)
			}
			if err := r.Engine.Replace(
				ctx,
				desired,
				workspace,
				targetImageDigest,
				true,
			); err != nil {
				return r.failSandbox(ctx, local, imageReplaceErrorCode(err), err)
			}
			local.ImageDigest = targetImageDigest
		} else if local.ObservedState == "running" && local.ObservedGeneration < local.Generation {
			local.ObservedState = "restarting"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
			if r.Sessions != nil {
				_ = r.Sessions.TerminateSandbox(ctx, local.ID)
			}
			if err := r.Engine.Restart(ctx, local.ID); err != nil {
				return r.failSandbox(ctx, local, "container_restart_failed", err)
			}
		} else if local.ObservedState == "stopped" {
			if err := r.Engine.Start(ctx, local.ID); err != nil {
				return r.failSandbox(ctx, local, "container_start_failed", err)
			}
		} else if local.ObservedState == "running" {
			if err := r.Engine.Ensure(ctx, desired, workspace, local.ImageDigest); err != nil {
				return r.failSandbox(ctx, local, "container_reconcile_failed", err)
			}
		} else if local.ObservedState != "running" {
			local.ObservedState = "creating"
			if err := r.Store.PutSandbox(ctx, *local); err != nil {
				return err
			}
			desired.ExpiresAt = local.ExpiresAt
			if err := r.Engine.Ensure(ctx, desired, workspace, local.ImageDigest); err != nil {
				return r.failSandbox(ctx, local, "container_create_failed", err)
			}
		}
		if requiresNestedPreflight {
			if err := r.Engine.Preflight(ctx, local.ID); err != nil {
				stopErr := r.Engine.Stop(ctx, local.ID)
				return r.failSandbox(
					ctx,
					local,
					"nested_sandbox_preflight_failed",
					errors.Join(err, stopErr),
				)
			}
		}
		started := r.now()
		if local.StartedAt == nil {
			local.StartedAt = &started
			if local.Lifetime == "temporary" && local.ExpiresInSeconds != nil {
				expires := started.Add(time.Duration(*local.ExpiresInSeconds) * time.Second)
				local.ExpiresAt = &expires
			}
		}
		local.ObservedState = "running"
		local.ObservedGeneration = local.Generation
		local.ErrorCode = ""
		local.ErrorMessage = ""
		if err := r.Store.PutSandbox(ctx, *local); err != nil {
			return err
		}
		return nil
	default:
		return errors.New("unsupported desired state")
	}
}

func imageReplaceErrorCode(err error) string {
	if errors.Is(err, containers.ErrImagePullFailed) {
		return "sandbox_image_pull_failed"
	}
	if errors.Is(err, containers.ErrImageRollbackFailed) {
		return "container_image_rollback_failed"
	}
	return "container_image_replace_failed"
}

func (r *Reconciler) removeSandbox(ctx context.Context, local *state.LocalSandbox) error {
	if local.ObservedState == "deleted" {
		return nil
	}
	local.ObservedState = "deleting"
	if err := r.Store.PutSandbox(ctx, *local); err != nil {
		return err
	}
	if r.Sessions != nil {
		_ = r.Sessions.TerminateSandbox(ctx, local.ID)
	}
	if err := r.Engine.Remove(ctx, local.ID); err != nil {
		return r.failSandbox(ctx, local, "container_delete_failed", err)
	}
	if err := r.Workspaces.Destroy(ctx, local.ID); err != nil {
		return r.failSandbox(ctx, local, "workspace_delete_failed", err)
	}
	local.ObservedState = "deleted"
	local.ObservedGeneration = local.Generation
	local.ErrorCode = ""
	local.ErrorMessage = ""
	return r.Store.PutSandbox(ctx, *local)
}

func (r *Reconciler) failSandbox(
	ctx context.Context,
	local *state.LocalSandbox,
	code string,
	err error,
) error {
	local.ObservedState = "failed"
	local.ErrorCode = code
	local.ErrorMessage = bounded(err.Error(), 300)
	if saveErr := r.Store.PutSandbox(ctx, *local); saveErr != nil {
		return errors.Join(err, saveErr)
	}
	return err
}

func (r *Reconciler) reconcileGrants(ctx context.Context, desired []model.AccessGrant) error {
	existing, err := r.Store.Grants(ctx)
	if err != nil {
		return err
	}
	desiredIDs := map[string]bool{}
	for _, grant := range desired {
		desiredIDs[grant.ID] = true
		value := state.LocalGrant{
			ID:            grant.ID,
			SandboxID:     grant.SandboxID,
			SSHPublicKey:  grant.SSHPublicKey,
			DesiredState:  grant.DesiredState,
			ObservedState: "pending",
		}
		for _, current := range existing {
			if current.ID == grant.ID {
				value.ObservedState = current.ObservedState
			}
		}
		if grant.DesiredState == "revoked" {
			value.ObservedState = "revoking"
			if r.Sessions != nil {
				if err := r.Sessions.TerminateGrant(ctx, grant.ID); err != nil {
					return err
				}
			}
		}
		if err := r.Store.PutGrant(ctx, value); err != nil {
			return err
		}
	}
	for _, current := range existing {
		if !desiredIDs[current.ID] && current.DesiredState == "active" {
			current.DesiredState = "revoked"
			current.ObservedState = "revoking"
			if r.Sessions != nil {
				if err := r.Sessions.TerminateGrant(ctx, current.ID); err != nil {
					return err
				}
			}
			if err := r.Store.PutGrant(ctx, current); err != nil {
				return err
			}
		}
	}
	all, err := r.Store.Grants(ctx)
	if err != nil {
		return err
	}
	if err := r.Access.Write(all); err != nil {
		for index := range all {
			if all[index].DesiredState == "active" {
				all[index].ObservedState = "failed"
				all[index].ErrorCode = "access_mapping_failed"
				all[index].ErrorMessage = bounded(err.Error(), 300)
				_ = r.Store.PutGrant(ctx, all[index])
			}
		}
		return err
	}
	for index := range all {
		if all[index].DesiredState == "active" {
			all[index].ObservedState = "applied"
		} else {
			all[index].ObservedState = "revoked"
		}
		all[index].ErrorCode = ""
		all[index].ErrorMessage = ""
		if err := r.Store.PutGrant(ctx, all[index]); err != nil {
			return err
		}
		if !desiredIDs[all[index].ID] && all[index].DesiredState == "revoked" {
			if err := r.Store.DeleteGrant(ctx, all[index].ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

func requested(sandboxes []model.Sandbox) model.Resources {
	value := model.Resources{}
	for _, sandbox := range sandboxes {
		if sandbox.DesiredState == "deleted" {
			continue
		}
		value.WorkspaceDiskGiB += sandbox.Resources.WorkspaceDiskGiB
		if sandbox.DesiredState == "running" {
			value.CPUMillicores += sandbox.Resources.CPUMillicores
			value.MemoryMiB += sandbox.Resources.MemoryMiB
		}
	}
	return value
}

func bounded(value string, maximum int) string {
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}
