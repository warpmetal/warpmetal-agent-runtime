package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

const workflowObservationPath = "/internal/runtime/workspace-workflow-observations"

func (c Client) WorkflowObservationOperation(ctx context.Context, call model.WorkflowCaptureRequest, revision int64) (model.WorkflowCaptureOperation, error) {
	var result model.WorkflowCaptureOperation
	raw, err := json.Marshal(call)
	if err != nil || len(raw) > 65536 || workflowcontract.Validate(workflowcontract.Producer, "operationRequest", raw) != nil || call.Operation.Kind != "observation" {
		return result, errors.New("workflow capture request refused")
	}
	var response json.RawMessage
	if err := c.planSourceClient().requestWithResponseLimit(ctx, http.MethodPost, workflowObservationPath+"/operations", c.NodeToken, call, &response, true, call.RequestID, "", 65536); err != nil {
		return result, err
	}
	if model.DecodeWorkflowCaptureOperation(response, &result) != nil || result.ValidateFor(call, fmt.Sprintf("%x", sha256.Sum256([]byte(c.NodeToken))), revision, time.Now()) != nil {
		return model.WorkflowCaptureOperation{}, errors.New("current workflow capture operation refused")
	}
	return result, nil
}

// Retain proof FIRST, then consume it through the unchanged observation request.
// Neither endpoint dispatches a native tool/model or retries a lost response.
func (c Client) ReportWorkflowObservation(ctx context.Context, envelope model.WorkflowObservationEnvelope) (model.WorkflowObservationReceipt, error) {
	var receipt model.WorkflowObservationReceipt
	p := envelope.Payload
	if envelope.Validate() != nil || p.NodeTokenHash != fmt.Sprintf("%x", sha256.Sum256([]byte(c.NodeToken))) {
		return receipt, errors.New("protected observation report refused")
	}
	deadline, err := time.Parse(time.RFC3339Nano, p.NotAfter)
	if err != nil || !time.Now().Before(deadline) {
		return receipt, errors.New("protected observation report expired")
	}
	var proof struct {
		FormatVersion int    `json:"formatVersion"`
		ProofID       string `json:"proofId"`
		ProofDigest   string `json:"proofDigest"`
		ExpiresAt     string `json:"expiresAt"`
	}
	var proofRaw json.RawMessage
	if err := c.planSourceClient().requestWithResponseLimit(ctx, http.MethodPost, workflowObservationPath+"/proofs", c.NodeToken, envelope, &proofRaw, true, "", "", 65536); err != nil {
		return receipt, err
	}
	if len(proofRaw) > 65536 || json.Unmarshal(proofRaw, &proof) != nil {
		return receipt, errors.New("observation proof retention refused")
	}
	proofExpiry, e1 := time.Parse(time.RFC3339Nano, proof.ExpiresAt)
	expiry, e2 := time.Parse(time.RFC3339Nano, p.NotAfter)
	if proof.FormatVersion != 1 || !managedServiceIDPattern.MatchString(proof.ProofID) || proof.ProofDigest != model.WorkspaceDigest(envelope) || e1 != nil || e2 != nil || !proofExpiry.Equal(expiry) || !time.Now().Before(proofExpiry) {
		return receipt, errors.New("observation proof retention conflict")
	}
	var call model.WorkflowObservationRequest
	var capture struct {
		Binding     json.RawMessage `json:"binding"`
		Reconciles  json.RawMessage `json:"reconciles"`
		Observation json.RawMessage `json:"observation"`
	}
	if json.Unmarshal(p.Request, &capture) != nil {
		return receipt, errors.New("observation request refused")
	}
	call = model.WorkflowObservationRequest{FormatVersion: 1, RequestID: p.RequestID, Binding: capture.Binding, Reconciles: capture.Reconciles, Observation: capture.Observation}
	var binding struct {
		ExecutionID string `json:"executionId"`
	}
	var observation struct {
		Type   string `json:"type"`
		Status string `json:"status"`
	}
	_ = json.Unmarshal(call.Binding, &binding)
	_ = json.Unmarshal(call.Observation, &observation)
	raw, err := json.Marshal(call)
	if err != nil || workflowcontract.Validate(workflowcontract.Domain, "observationRequest", raw) != nil || !managedServiceIDPattern.MatchString(binding.ExecutionID) {
		return receipt, errors.New("closed observation request refused")
	}
	var response json.RawMessage
	if err := c.planSourceClient().requestWithResponseLimit(ctx, http.MethodPost, workflowObservationPath+"/executions/"+binding.ExecutionID+"/receipts", c.NodeToken, call, &response, true, call.RequestID, "", 65536); err != nil {
		return receipt, err
	}
	if len(response) > 65536 || workflowcontract.Validate(workflowcontract.Domain, "observationReceipt", response) != nil || json.Unmarshal(response, &receipt) != nil || receipt.ExecutionID != binding.ExecutionID || receipt.Type != observation.Type || (observation.Status != "" && receipt.Status != observation.Status) || (observation.Status == "" && receipt.Status != "settled") {
		return model.WorkflowObservationReceipt{}, errors.New("observation receipt conflict")
	}
	return receipt, nil
}
