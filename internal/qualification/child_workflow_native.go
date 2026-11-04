package qualification

import (
	"encoding/json"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Only one purpose-specific protected capture may be present. The common
// native tuple is read from that capture, never accepted as a standalone proof.
type ChildWorkflowNativeCapture struct {
	Result      *model.ChildNativeResultCapture
	Integration *model.ChildNativeIntegrationCapture
	Reviewer    *model.ChildNativeReviewerCapture
	// Allowlist only. Neither a consumed reference nor evidence of a file read.
	ApprovedSourceReferences []model.ControllerPlanReference
}

// Project only the closed references from a control already verified by Store.
// The outcome reader rechecks that same current control before returning them.
func (c ChildProductControl) ApprovedSourceReferences() ([]model.ControllerPlanReference, error) {
	if c.Generation.Phase != "execute" || c.Generation.Policy == nil || len(c.Generation.Policy.Payload.SourceReads) > 64 {
		return nil, ErrUntrusted
	}
	out := make([]model.ControllerPlanReference, 0)
	seen := make(map[string]bool)
	for _, scope := range c.Generation.Policy.Payload.SourceReads {
		raw := childFields(scope.Grant)["reference"]
		var reference model.ControllerPlanReference
		if workflowcontract.Validate(workflowcontract.Domain, "reference", raw) != nil || json.Unmarshal(raw, &reference) != nil {
			return nil, ErrUntrusted
		}
		key := CanonicalDigest(reference)
		if !seen[key] {
			out = append(out, reference)
			seen[key] = true
		}
	}
	return out, nil
}

// Completion consumers share this version boundary. Authority and exact native
// completion are still independently checked by every owning consumer.
func childCompletionPolicy(q ChildProductPolicy) bool {
	return q.FormatVersion == 2 ||
		(q.FormatVersion == 3 && q.Purpose == "integrator" && q.Workload.Kind == "integration2" && q.Workload.TerminalOutput == "integration_candidate") ||
		(q.FormatVersion == 4 && q.Purpose == "reviewer" && q.Workload.Kind == "review1" && q.Workload.TerminalOutput == "review_evidence")
}

func (c ChildWorkflowNativeCapture) completion(entry model.CellServiceV3, control ChildProductControl) (model.ChildNativeExecution, string, []string, error) {
	var empty model.ChildNativeExecution
	if control.Generation.Policy == nil {
		return empty, "", nil, ErrUntrusted
	}
	q := control.Generation.Policy.Payload
	count := 0
	if c.Result != nil {
		count++
	}
	if c.Integration != nil {
		count++
	}
	if c.Reviewer != nil {
		count++
	}
	if count != 1 || !childCompletionPolicy(q) {
		return empty, "", nil, ErrUntrusted
	}
	switch q.Purpose {
	case "coding_worker":
		if c.Result == nil || q.Workload.Kind != "coding2" || q.Workload.TerminalOutput != "result" || c.Result.ValidateFor(entry, control.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest) != nil {
			return empty, "", nil, ErrUntrusted
		}
		return c.Result.Native, "worker", []string{c.Result.Effect.ResponseDigest, c.Result.Terminal.ResponseDigest}, nil
	case "integrator":
		if c.Integration == nil || q.Workload.Kind != "integration2" || q.Workload.TerminalOutput != "integration_candidate" || c.Integration.ValidateFor(entry, control.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest) != nil {
			return empty, "", nil, ErrUntrusted
		}
		return c.Integration.Native, "worker", []string{c.Integration.Effect.ResponseDigest, c.Integration.Terminal.ResponseDigest}, nil
	case "reviewer":
		if c.Reviewer == nil || q.Workload.Kind != "review1" || q.Workload.TerminalOutput != "review_evidence" || q.ReviewDelivery == nil || c.Reviewer.ValidateFor(entry, control.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest, q.ReviewDelivery.AssessmentPath) != nil {
			return empty, "", nil, ErrUntrusted
		}
		return c.Reviewer.Native, "reviewer", []string{c.Reviewer.ProviderResponseDigest}, nil
	}
	return empty, "", nil, ErrUntrusted
}

// Existing child success/report lineage, shared by role and facts consumers.
func childCompletionReport(entry model.CellServiceV3, report model.CellServiceReportV1, grant model.CellExecutionGrantV3, n model.ChildNativeExecution) bool {
	return sameProduct(grant, entry.ExecutionGrant) && report.FormatVersion == 3 && report.ObservedState == "ready" && report.DesiredState == "active" && !report.Exhausted && report.LastError == nil && report.OperationID == entry.OperationID && report.ActionRevision == entry.ActionRevision && report.ObservedDesiredRevision == entry.DesiredRevision && report.ServiceRegistrationID == entry.ServiceRegistrationID && report.ServiceGeneration == entry.ServiceGeneration && report.SandboxID == entry.SandboxID && report.SandboxGeneration == entry.SandboxGeneration && report.OwnerCellID == entry.OwnerCellID && report.OwnerRole == entry.OwnerRole && report.OwnerGeneration == entry.OwnerGeneration && report.Instance == entry.Instance && report.Role == entry.Role && report.Attempt == entry.Attempt && report.Fence == entry.Fence && report.NativeSessionID == n.SessionID && report.NativeProjectID == n.NativeProjectID && report.WorkspaceEpoch == entry.WorkspaceEpoch && report.Child != nil && report.Child.State == "terminal" && report.Child.Outcome != nil && *report.Child.Outcome == "succeeded" && !report.Child.Exhausted && report.Child.Attempt == entry.Attempt && report.Child.OperationID == entry.LaunchOperationID && report.Child.SessionID == n.SessionID && report.Child.MessageID == n.InputID && model.PhysicalDigestValid(report.ReceiptDigest)
}
