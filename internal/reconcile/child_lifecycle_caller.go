package reconcile

import (
	"context"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// One explicit operation from the owning lifecycle caller. No poller, model text,
// arbitrary entry, implicit follow-up or retry drives these existing consumers.
func (r *Reconciler) RunApprovedChildLifecycleStep(ctx context.Context, preparationID, step string, call model.WorkflowCaptureRequest, purpose, contentType string) (any, error) {
	if r.Store == nil {
		return nil, errors.New("owning child lifecycle store absent")
	}
	var entry model.CellServiceV3
	current := r.currentAuthorityManifest()
	for _, actual := range current.CellEntriesV3 {
		if actual.PreparationID == preparationID {
			entry = actual
		}
	}
	if entry.PreparationID == "" || entry.LifecyclePhase != "execute" || entry.DesiredState != "active" {
		return nil, errors.New("owning current child absent")
	}
	var result any
	claim := map[string]any{"entry": entry, "runtimeRevision": current.DesiredRevision, "call": call, "purpose": purpose, "contentType": contentType}
	err := r.ownedContinuationOnce(ctx, preparationID, step+"-"+model.WorkspaceDigest(call)[7:39], claim, func() (any, error) {
		switch step {
		case "publish_mcp":
			if purpose != "" || contentType != "" {
				return nil, errors.New("publication selector refused")
			}
			if err := r.PublishApprovedChildEffect(ctx, entry, 0); err != nil {
				return nil, err
			}
			return map[string]string{"preparationId": preparationID, "state": "published"}, nil
		case "publish_script":
			if purpose != "" || contentType != "" {
				return nil, errors.New("publication selector refused")
			}
			if err := r.PublishApprovedChildEffect(ctx, entry, 1); err != nil {
				return nil, err
			}
			return map[string]string{"preparationId": preparationID, "state": "published"}, nil
		case "report_effect":
			return r.ReportApprovedChildEffect(ctx, entry, call)
		case "reviewer_source":
			return r.ReadApprovedReviewerSource(ctx, entry, call)
		case "artifact":
			return r.ReadUploadApprovedChildArtifact(ctx, entry, call, purpose, contentType)
		default:
			return nil, errors.New("owning child lifecycle step refused")
		}
	}, &result)
	return result, err
}
