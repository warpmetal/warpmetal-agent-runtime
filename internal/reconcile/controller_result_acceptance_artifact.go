package reconcile

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type childWorkflowOutcomeRuntime interface {
	ObserveCellWorkflowOutcome(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, workspacecatalog.RegisteredProject) (qualification.ChildWorkflowNativeCapture, error)
}

// Model-declared semantics only. Source references are allowed declarations,
// never proof that the child read a source or completed its business task.
type childDocumentMetadata struct {
	Type       string                          `json:"type"`
	SourceRefs []model.ControllerPlanReference `json:"sourceRefs"`
	Method     string                          `json:"method"`
}

func childDocumentFromNative(raw string, approved []model.ControllerPlanReference) (childDocumentMetadata, error) {
	var result childDocumentMetadata
	bad := errors.New("child document metadata refused")
	if len(raw) > 16384 || model.DecodePhysicalClosed([]byte(raw), &result) != nil || (result.Type != "document" && result.Type != "analysis") || result.SourceRefs == nil || len(approved) > 64 || result.Method == "" {
		return result, bad
	}
	refs, _ := json.Marshal(result.SourceRefs)
	method, _ := json.Marshal(result.Method)
	if workflowcontract.Validate(workflowcontract.Domain, "references", refs) != nil || workflowcontract.Validate(workflowcontract.Domain, "text", method) != nil {
		return result, bad
	}
	allowed := map[string]bool{}
	for _, ref := range approved {
		bytes, _ := json.Marshal(ref)
		if workflowcontract.Validate(workflowcontract.Domain, "reference", bytes) != nil {
			return result, bad
		}
		allowed[model.WorkspaceDigest(ref)] = true
	}
	seen := map[string]bool{}
	for _, ref := range result.SourceRefs {
		digest := model.WorkspaceDigest(ref)
		if !allowed[digest] || seen[digest] {
			return result, bad
		}
		seen[digest] = true
	}
	return result, nil
}

type completedChildArtifact struct {
	Outcome  qualification.ChildWorkflowNativeCapture
	Metadata childDocumentMetadata
	Upload   model.WorkflowArtifactReceipt
}

func completedChildArtifactClaim(binding json.RawMessage, capture model.ChildNativeResultCapture, metadata childDocumentMetadata) map[string]any {
	return map[string]any{"binding": binding, "generationDigest": capture.GenerationDigest, "preparedReceiptDigest": capture.Native.PreparedReceiptDigest, "grantDigest": capture.Native.GrantDigest, "inputId": capture.Native.InputID, "inputDigest": capture.Native.InputDigest, "terminalSeq": capture.Native.TerminalSeq, "terminal": capture.Terminal, "artifact": capture.Artifact, "metadata": metadata}
}

func (r *Reconciler) ensureCompletedChildArtifactLocked(ctx context.Context, owner controllerChildApplication, child ControllerFirstTaskChildResult, entry model.CellServiceV3) (*completedChildArtifact, error) {
	runtime, ok := r.ManagedRuntime.(childWorkflowOutcomeRuntime)
	if !ok {
		return nil, nil
	}
	if _, ok = r.ManagedRuntime.(childArtifactRuntime); !ok {
		return nil, ErrControllerFirstTaskAuthorityPending
	}
	if _, ok = r.ManagedControl.(childArtifactControl); !ok {
		return nil, ErrControllerFirstTaskAuthorityPending
	}
	view, err := r.currentCompletedChildAuthority(ctx, owner, child, entry)
	if err != nil {
		return nil, err
	}
	outcome, err := runtime.ObserveCellWorkflowOutcome(ctx, view.Sandbox, entry, view.Manifest, view.Input, view.Root)
	if err != nil {
		return nil, err
	}
	if outcome.Result == nil || outcome.Integration != nil || outcome.Reviewer != nil {
		return nil, ErrControllerFirstTaskAuthorityPending
	}
	capture := *outcome.Result
	if entry.Role != "worker" || entry.ExecutionGrant == nil || capture.ValidateFor(entry, capture.GenerationDigest, child.Binding, entry.ExecutionGrant.InputID, model.RawPhysicalDigest(view.Input)) != nil {
		return nil, state.ErrControllerActivityConflict
	}
	metadata, err := childDocumentFromNative(capture.Terminal.Text, outcome.ApprovedSourceReferences)
	if err != nil {
		return nil, err
	}
	// Current guard/log-cursor observations are rechecked above, not identities
	// whose harmless later movement could request a second output upload.
	claim := completedChildArtifactClaim(child.Binding, capture, metadata)
	var original qualification.ChildWorkflowNativeCapture
	if err = r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-artifact-outcome", claim, func() (any, error) { return outcome, nil }, &original); err != nil {
		return nil, err
	}
	call := model.WorkflowCaptureRequest{FormatVersion: 1, RequestID: "wfartifact_read_" + model.WorkspaceDigest(claim)[7:], Binding: child.Binding, Operation: model.WorkflowCapture{Kind: "observation", Reconciles: json.RawMessage("null"), Observation: mustWorkflowJSON(map[string]any{"type": "artifact_read", "sourcePath": capture.Artifact.SourcePath, "digest": capture.Artifact.Digest, "byteCount": capture.Artifact.ByteCount})}}
	var uploaded model.WorkflowArtifactReceipt
	err = r.ownedContinuationOnce(ctx, entry.PreparationID, "completion-artifact", claim, func() (any, error) {
		return r.readUploadApprovedChildArtifact(ctx, entry, call, metadata.Type, "text/plain", func(ctx context.Context, current model.CellServiceV3) (json.RawMessage, error) {
			fresh, e := r.currentCompletedChildAuthority(ctx, owner, child, current)
			if e != nil {
				return nil, e
			}
			return fresh.Fresh.BackendSnapshot, nil
		}, entry.PreparationID)
	}, &uploaded)
	if err != nil {
		return nil, err
	}
	return &completedChildArtifact{Outcome: original, Metadata: metadata, Upload: uploaded}, nil
}

func mustWorkflowJSON(value any) json.RawMessage {
	raw, err := model.WorkspaceCanonicalJSON(value)
	if err != nil {
		return nil
	}
	return raw
}
