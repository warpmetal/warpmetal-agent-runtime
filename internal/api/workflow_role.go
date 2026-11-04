package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

func (c Client) WorkflowRoleEnrollmentOperation(ctx context.Context, call model.WorkflowRoleOperationRequest) (model.WorkflowRoleOperation, error) {
	var out model.WorkflowRoleOperation
	raw, err := json.Marshal(call)
	if err != nil || workflowcontract.Validate(workflowcontract.Producer, "enrollmentOperationRequest", raw) != nil {
		return out, errors.New("invalid workflow role operation request")
	}
	var original json.RawMessage
	if err = c.paidDomainClient().requestWithResponseLimit(ctx, http.MethodPost, controllerBridgePath+"enrollment-operations", c.NodeToken, call, &original, true, call.RequestID, "", 65536); err != nil {
		return out, err
	}
	if model.DecodePhysicalClosed(original, &out) != nil || out.Validate() != nil || !reflect.DeepEqual(out.Subject, call.Subject) {
		return model.WorkflowRoleOperation{}, errors.New("workflow role operation original conflict")
	}
	return out, nil
}
func (c Client) EnrollWorkflowRole(ctx context.Context, proof model.WorkflowRoleEnvelope) (model.WorkflowRoleEnrollment, error) {
	var out model.WorkflowRoleEnrollment
	if proof.Validate() != nil {
		return out, errors.New("invalid workflow role proof")
	}
	var original json.RawMessage
	if err := c.paidDomainClient().requestWithResponseLimit(ctx, http.MethodPost, controllerBridgePath+"enroll", c.NodeToken, proof, &original, true, proof.Payload.RequestID, "", 65536); err != nil {
		return out, err
	}
	if model.DecodePhysicalClosed(original, &out) != nil || out.Validate() != nil {
		return model.WorkflowRoleEnrollment{}, errors.New("workflow role enrollment original conflict")
	}
	return out, nil
}
