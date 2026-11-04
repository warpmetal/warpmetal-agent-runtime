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

// Same authenticated node transport, but operation-specific proof cannot follow
// redirects, carry a parent lease, or expose a source-byte fetching route.
func (c Client) planSourceClient() Client {
	h := c.HTTP
	if h == nil {
		h = &http.Client{Timeout: 30 * time.Second}
	}
	copy := *h
	copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	c.HTTP = &copy
	return c
}
func (c Client) PlanSourceReadOperation(ctx context.Context, id string) (model.PlanSourceReadOperation, error) {
	var op model.PlanSourceReadOperation
	if !managedServiceIDPattern.MatchString(id) {
		return op, errors.New("invalid plan read identity")
	}
	var raw json.RawMessage
	if err := c.planSourceClient().request(ctx, http.MethodGet, "/internal/runtime/workspace-workflow/plan-source-read-operations/"+id, c.NodeToken, nil, &raw, true); err != nil {
		return op, err
	}
	if workflowcontract.Validate(workflowcontract.PlanGenesis, "readOperation", raw) != nil || json.Unmarshal(raw, &op) != nil || op.Validate() != nil || op.OperationID != id ||
		op.Reader.Producer.NodeTokenHash != fmt.Sprintf("%x", sha256.Sum256([]byte(c.NodeToken))) {
		return model.PlanSourceReadOperation{}, errors.New("current plan read operation conflict")
	}
	return op, nil
}
func (c Client) ReportPlanSourceRead(ctx context.Context, envelope model.PlanSourceReadEnvelope) (model.PlanSourceReadReceipt, error) {
	var receipt model.PlanSourceReadReceipt
	if envelope.Validate() != nil || envelope.Payload.NodeTokenHash != fmt.Sprintf("%x", sha256.Sum256([]byte(c.NodeToken))) {
		return receipt, errors.New("protected full-byte plan report refused")
	}
	var raw json.RawMessage
	if err := c.planSourceClient().requestWithKey(ctx, http.MethodPost, "/internal/runtime/workspace-workflow/plan-source-reads", c.NodeToken, envelope, &raw, true, envelope.Payload.RequestID); err != nil {
		return receipt, err
	}
	if workflowcontract.Validate(workflowcontract.PlanGenesis, "readReceipt", raw) != nil || json.Unmarshal(raw, &receipt) != nil || receipt.ValidateFor(envelope) != nil {
		return model.PlanSourceReadReceipt{}, errors.New("plan read receipt conflict")
	}
	return receipt, nil
}
