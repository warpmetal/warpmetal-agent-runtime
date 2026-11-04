package containers

import (
	"context"
	"encoding/json"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

const ManagedSupervisorChildResultCapture ManagedSupervisorAction = "child-result-capture"
const ManagedSupervisorChildIntegrationCapture ManagedSupervisorAction = "child-integration-capture"

// Only the installed protected Supervisor can supply this capture. The request
// has no output path/body/receipt; the current signed child chooses all of them.
func (p Podman) captureCellProductResult(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current qualification.ChildProductControl) (model.ChildNativeResultCapture, error) {
	var empty model.ChildNativeResultCapture
	raw, err := p.captureCellProductWrite(ctx, box, entry, current, ManagedSupervisorChildResultCapture)
	if err != nil {
		return empty, err
	}
	q := current.Generation.Policy.Payload
	capture, err := model.DecodeChildNativeResultCapture(raw)
	if err != nil || capture.ValidateFor(entry, current.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest) != nil {
		return empty, qualification.ErrUntrusted
	}
	return capture, nil
}

func (p Podman) captureCellProductIntegration(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current qualification.ChildProductControl) (model.ChildNativeIntegrationCapture, error) {
	var empty model.ChildNativeIntegrationCapture
	raw, err := p.captureCellProductWrite(ctx, box, entry, current, ManagedSupervisorChildIntegrationCapture)
	if err != nil {
		return empty, err
	}
	q := current.Generation.Policy.Payload
	capture, err := model.DecodeChildNativeIntegrationCapture(raw)
	if err != nil || capture.ValidateFor(entry, current.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest) != nil {
		return empty, qualification.ErrUntrusted
	}
	return capture, nil
}

func (p Podman) captureCellProductWrite(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current qualification.ChildProductControl, action ManagedSupervisorAction) (json.RawMessage, error) {
	purpose := ""
	switch action {
	case ManagedSupervisorChildResultCapture:
		purpose = "coding_worker"
	case ManagedSupervisorChildIntegrationCapture:
		purpose = "integrator"
	}
	if purpose == "" || current.Generation.Policy == nil || current.Generation.Policy.Payload.Purpose != purpose {
		return nil, qualification.ErrUntrusted
	}
	request, _ := json.Marshal(map[string]any{"schemaVersion": 1, "sandboxId": box.ID, "instance": entry.Instance, "profileId": entry.Profile.ProfileID, "nativeSessionId": entry.NativeSessionID})
	output, _, err := p.ExecManagedSupervisor(ctx, box.ID, action, request)
	if err != nil || len(output) > 65536 || p.verifyQualificationMounts(ctx, box.ID) != nil {
		return nil, qualification.ErrUntrusted
	}
	var response struct {
		SchemaVersion int             `json:"schemaVersion"`
		Command       string          `json:"command"`
		Status        string          `json:"status"`
		Capture       json.RawMessage `json:"capture"`
	}
	if model.DecodePhysicalClosed(output, &response) != nil || response.SchemaVersion != 1 || response.Command != string(action) || response.Status != "observed" {
		return nil, qualification.ErrUntrusted
	}
	return response.Capture, nil
}

// Dispatch is closed by the current signed purpose; an integrator or reviewer
// never passes through the coding-result command or decoder.
func (p Podman) captureCellWorkflowNative(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current qualification.ChildProductControl) (qualification.ChildWorkflowNativeCapture, error) {
	var out qualification.ChildWorkflowNativeCapture
	if current.Generation.Policy == nil {
		return out, qualification.ErrUntrusted
	}
	approved, err := current.ApprovedSourceReferences()
	if err != nil {
		return out, err
	}
	out.ApprovedSourceReferences = approved
	q := current.Generation.Policy.Payload
	switch q.Purpose {
	case "coding_worker":
		value, err := p.captureCellProductResult(ctx, box, entry, current)
		if err != nil {
			return out, err
		}
		out.Result = &value
	case "integrator":
		value, err := p.captureCellProductIntegration(ctx, box, entry, current)
		if err != nil {
			return out, err
		}
		out.Integration = &value
	case "reviewer":
		request, _ := json.Marshal(map[string]any{"schemaVersion": 1, "sandboxId": box.ID, "instance": entry.Instance, "profileId": entry.Profile.ProfileID, "nativeSessionId": entry.NativeSessionID})
		raw, _, err := p.ExecManagedSupervisor(ctx, box.ID, ManagedSupervisorReviewerCapture, request)
		var response struct {
			SchemaVersion int             `json:"schemaVersion"`
			Command       string          `json:"command"`
			Status        string          `json:"status"`
			Capture       json.RawMessage `json:"capture"`
		}
		if err != nil || model.DecodePhysicalClosed(raw, &response) != nil || response.SchemaVersion != 1 || response.Command != string(ManagedSupervisorReviewerCapture) || response.Status != "observed" || q.ReviewDelivery == nil || p.verifyQualificationMounts(ctx, box.ID) != nil {
			return out, qualification.ErrUntrusted
		}
		capture, err := model.DecodeChildNativeReviewerCapture(response.Capture)
		if err != nil || capture.ValidateFor(entry, current.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest, q.ReviewDelivery.AssessmentPath) != nil {
			return out, qualification.ErrUntrusted
		}
		out.Reviewer = &capture
	default:
		return out, qualification.ErrUntrusted
	}
	return out, nil
}
