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
)

// Facts use the existing node-only operation route. An operation is a capture
// request, never execution authority or a claim that work has settled.
func (c Client) WorkflowFactsOperation(ctx context.Context, call model.WorkflowFactsRequest, revision int64) (model.WorkflowFactsOperation, error) {
	var result model.WorkflowFactsOperation
	raw, err := json.Marshal(call)
	if err != nil || len(raw) > 65536 || call.Validate() != nil {
		return result, errors.New("workflow facts request refused")
	}
	var response json.RawMessage
	if err = c.planSourceClient().requestWithResponseLimit(ctx, http.MethodPost, workflowObservationPath+"/operations", c.NodeToken, call, &response, true, call.RequestID, "", 65536); err != nil {
		return result, err
	}
	if model.DecodeWorkflowFactsOperation(response, &result) != nil || result.ValidateFor(call, fmt.Sprintf("%x", sha256.Sum256([]byte(c.NodeToken))), revision, time.Now()) != nil {
		return model.WorkflowFactsOperation{}, errors.New("current workflow facts operation refused")
	}
	return result, nil
}

// ReportWorkflowFacts only submits an existing producer envelope. Its protected
// native/current-state signer owns the completion or candidate observation.
func (c Client) ReportWorkflowFacts(ctx context.Context, envelope model.WorkflowFactsEnvelope) (model.WorkflowFactsReceipt, error) {
	var receipt model.WorkflowFactsReceipt
	raw, err := json.Marshal(envelope)
	p := envelope.Payload
	if err != nil || len(raw) > 65536 || envelope.Validate() != nil || p.NodeTokenHash != fmt.Sprintf("%x", sha256.Sum256([]byte(c.NodeToken))) {
		return receipt, errors.New("protected workflow facts refused")
	}
	expiry, err := time.Parse(time.RFC3339Nano, p.NotAfter)
	if err != nil || !time.Now().Before(expiry) {
		return receipt, errors.New("protected workflow facts expired")
	}
	var response json.RawMessage
	if err = c.planSourceClient().requestWithResponseLimit(ctx, http.MethodPost, workflowObservationPath+"/facts", c.NodeToken, envelope, &response, true, "", "", 65536); err != nil {
		return receipt, err
	}
	if model.DecodePhysicalClosed(response, &receipt) != nil || receipt.ValidateFor(envelope, time.Now()) != nil {
		return model.WorkflowFactsReceipt{}, errors.New("workflow facts retention conflict")
	}
	return receipt, nil
}
