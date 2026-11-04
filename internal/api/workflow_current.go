package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Independent assignment-head selected backend facts; not an operation response.
func (c Client) WorkflowCurrentSnapshot(ctx context.Context, executionID string) (json.RawMessage, error) {
	var raw json.RawMessage
	if !managedServiceIDPattern.MatchString(executionID) {
		return nil, errors.New("current execution refused")
	}
	if err := c.planSourceClient().requestWithResponseLimit(ctx, http.MethodGet, workflowObservationPath+"/executions/"+executionID+"/current-snapshot", c.NodeToken, nil, &raw, true, "", "", 65536); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if model.DecodePhysicalClosed(raw, &fields) != nil || len(fields) != 10 {
		return nil, errors.New("independent current snapshot refused")
	}
	for _, k := range []string{"executionState", "executionReceiptDigest", "desiredState", "desiredRevision", "managedServiceReceiptDigest", "nativeContextDigest", "role", "grants", "children", "effects"} {
		if fields[k] == nil {
			return nil, errors.New("independent current snapshot incomplete")
		}
	}
	return append(json.RawMessage(nil), raw...), nil
}

// Signed control chooses ONLY the execution selector; the owning independent
// GET determines current facts. Store/ROOT methods separately verify all authority.
func (c Client) CurrentCellProductWorkflowSnapshot(ctx context.Context, entry model.CellServiceV3) (json.RawMessage, error) {
	d, err := c.ChildProductControl(ctx, entry.PreparationID)
	if err != nil {
		return nil, err
	}
	var control struct {
		Generation struct {
			Policy struct {
				Payload struct {
					Binding struct {
						ExecutionID, PreparationID, NativeSessionID, ServiceRegistrationID string
						SandboxGeneration                                                  int64
					} `json:"binding"`
				} `json:"payload"`
			} `json:"policy"`
		} `json:"generation"`
	}
	if json.Unmarshal(d.Bytes(), &control) != nil {
		return nil, errors.New("current binding selector refused")
	}
	b := control.Generation.Policy.Payload.Binding
	if b.PreparationID != entry.PreparationID || b.NativeSessionID != entry.NativeSessionID || b.ServiceRegistrationID != entry.ServiceRegistrationID || b.SandboxGeneration != entry.SandboxGeneration {
		return nil, errors.New("current binding selector changed")
	}
	return c.WorkflowCurrentSnapshot(ctx, b.ExecutionID)
}
