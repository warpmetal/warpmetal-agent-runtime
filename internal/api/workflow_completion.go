package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// These projections are read only after the authoritative closed Domain schema
// validates the original request. They do not create a role, result or decision.
type workflowCompletionRequest struct {
	RequestID    string          `json:"requestId"`
	Binding      json.RawMessage `json:"binding"`
	AssignmentID string          `json:"assignmentId"`
	Result       json.RawMessage `json:"result"`
	Target       json.RawMessage `json:"target"`
	Integration  json.RawMessage `json:"integration"`
	Disposition  string          `json:"disposition"`
}

func completionRequest(definition string, body json.RawMessage, lease string) (workflowCompletionRequest, string, error) {
	var call workflowCompletionRequest
	var binding struct {
		ExecutionID string `json:"executionId"`
	}
	if len(body) > 65536 || !validControllerLease(lease) || workflowcontract.Validate(workflowcontract.Domain, definition, body) != nil || json.Unmarshal(body, &call) != nil || json.Unmarshal(call.Binding, &binding) != nil || !managedServiceIDPattern.MatchString(binding.ExecutionID) {
		return call, "", errors.New("closed workflow completion request refused")
	}
	return call, binding.ExecutionID, nil
}

func (c Client) workflowCompletion(ctx context.Context, path, definition, requestID, lease string, body json.RawMessage) (json.RawMessage, error) {
	var response json.RawMessage
	if err := c.paidDomainClient().requestWithResponseLimit(ctx, http.MethodPost, controllerBridgePath+path, c.NodeToken, body, &response, true, requestID, lease, 65536); err != nil {
		return nil, err
	}
	if workflowcontract.Validate(workflowcontract.Domain, definition, response) != nil {
		return nil, errors.New("closed workflow completion receipt refused")
	}
	return response, nil
}

// ReportWorkflowResult submits the already captured worker result under its
// separately enrolled lease. The original requestId is the replay key.
func (c Client) ReportWorkflowResult(ctx context.Context, body json.RawMessage, lease string) (json.RawMessage, error) {
	call, execution, err := completionRequest("resultRequest", body, lease)
	if err != nil {
		return nil, err
	}
	raw, err := c.workflowCompletion(ctx, "executions/"+execution+"/results", "resultReceipt", call.RequestID, lease, body)
	if err != nil {
		return nil, err
	}
	var receipt struct {
		ExecutionID  string `json:"executionId"`
		AssignmentID string `json:"assignmentId"`
		ResultDigest string `json:"resultDigest"`
	}
	identity := map[string]any{"binding": call.Binding, "assignmentId": call.AssignmentID, "result": call.Result}
	if json.Unmarshal(raw, &receipt) != nil || receipt.ExecutionID != execution || receipt.AssignmentID != call.AssignmentID || receipt.ResultDigest != model.WorkspaceDigest(identity) {
		return nil, errors.New("worker result receipt association conflict")
	}
	return raw, nil
}

// ReportWorkflowReview preserves the reviewer's own captured assessment and its
// exact target/integration pins. Final acceptance uses the manager output action.
func (c Client) ReportWorkflowReview(ctx context.Context, body json.RawMessage, lease string) (json.RawMessage, error) {
	call, execution, err := completionRequest("reviewRequest", body, lease)
	if err != nil {
		return nil, err
	}
	var target struct {
		ResultID string `json:"resultId"`
	}
	if json.Unmarshal(call.Target, &target) != nil || !managedServiceIDPattern.MatchString(target.ResultID) {
		return nil, errors.New("review target refused")
	}
	raw, err := c.workflowCompletion(ctx, "results/"+target.ResultID+"/reviews", "reviewReceipt", call.RequestID, lease, body)
	if err != nil {
		return nil, err
	}
	var receipt struct {
		ReviewerExecutionID string          `json:"reviewerExecutionId"`
		ReviewDigest        string          `json:"reviewDigest"`
		Target              json.RawMessage `json:"target"`
		Integration         json.RawMessage `json:"integration"`
		Disposition         string          `json:"disposition"`
	}
	var identity map[string]json.RawMessage
	if json.Unmarshal(body, &identity) != nil {
		return nil, errors.New("review original refused")
	}
	delete(identity, "requestId")
	if json.Unmarshal(raw, &receipt) != nil || receipt.ReviewerExecutionID != execution || receipt.Disposition != call.Disposition || model.WorkspaceDigest(receipt.Target) != model.WorkspaceDigest(call.Target) || model.WorkspaceDigest(receipt.Integration) != model.WorkspaceDigest(call.Integration) || receipt.ReviewDigest != model.WorkspaceDigest(identity) {
		return nil, errors.New("review receipt association conflict")
	}
	return raw, nil
}
