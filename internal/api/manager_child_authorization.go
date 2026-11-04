package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Existing typed PRODUCT POSTs, deliberately not readers. The owning caller
// provides independently signed originals; neither method GETs/re-signs a basis.
func (c Client) AcceptManagerChildProductPolicy(ctx context.Context, handle model.IntentHandle, body json.RawMessage, lease string) (json.RawMessage, error) {
	return c.acceptManagerChildPolicy(ctx, handle, body, lease, "product")
}

func (c Client) AcceptManagerChildPreparationPolicy(ctx context.Context, handle model.IntentHandle, body json.RawMessage, lease string) (json.RawMessage, error) {
	return c.acceptManagerChildPolicy(ctx, handle, body, lease, "prepare")
}
func (c Client) acceptManagerChildPolicy(ctx context.Context, handle model.IntentHandle, body json.RawMessage, lease, stage string) (json.RawMessage, error) {
	c = c.paidDomainClient()
	if !validControllerLease(lease) || !managedServiceIDPattern.MatchString(handle.HandleID) || workflowcontract.ValidateChildPublication("policyAcceptRequest", body) != nil {
		return nil, errors.New("signed typed PRODUCT acceptance refused")
	}
	var request struct {
		RequestID, Stage                         string
		PreparationPolicy, Policy, PolicyBinding json.RawMessage
	}
	if json.Unmarshal(body, &request) != nil || request.Stage != stage {
		return nil, errors.New("PRODUCT original stage refused")
	}
	var result json.RawMessage
	if err := c.requestWithWorkflowLease(ctx, http.MethodPost, controllerBridgePath+"manager-intents/"+handle.HandleID+"/product-policies", c.NodeToken, body, &result, true, request.RequestID, lease); err != nil {
		return nil, err
	}
	if workflowcontract.Validate(workflowcontract.ChildProduct, "policyAcceptReceipt", result) != nil {
		return nil, errors.New("PRODUCT acceptance receipt refused")
	}
	var receipt struct{ HandleID, PreparationID, Stage, PreparationPolicyDigest, PolicyDigest, PolicyBindingDigest string }
	_ = json.Unmarshal(result, &receipt)
	var preparation, policy, binding struct{ Payload json.RawMessage }
	_ = json.Unmarshal(request.PreparationPolicy, &preparation)
	_ = json.Unmarshal(request.Policy, &policy)
	_ = json.Unmarshal(request.PolicyBinding, &binding)
	var selected struct {
		Preparation struct{ PreparationID string }
	}
	_ = json.Unmarshal(preparation.Payload, &selected)
	if receipt.HandleID != handle.HandleID || receipt.PreparationID != selected.Preparation.PreparationID || receipt.Stage != stage || receipt.PreparationPolicyDigest != model.WorkspaceDigest(preparation.Payload) || stage == "product" && (receipt.PolicyDigest != model.WorkspaceDigest(policy.Payload) || receipt.PolicyBindingDigest != model.WorkspaceDigest(binding.Payload)) {
		return nil, errors.New("PRODUCT accepted original digest conflict")
	}
	return result, nil
}

func (c Client) ManagerChildGrantIntent(ctx context.Context, handle model.IntentHandle, call model.IntentGrantRequest, lease string) (json.RawMessage, error) {
	c = c.paidDomainClient()
	raw, _ := json.Marshal(call)
	if call.HandleID != handle.HandleID || workflowcontract.Validate(workflowcontract.Manager, "intentGrantRequest", raw) != nil || !validControllerLease(lease) || !managedServiceIDPattern.MatchString(handle.HandleID) {
		return nil, errors.New("PRODUCT grant-intent request refused")
	}
	var result json.RawMessage
	if err := c.requestWithWorkflowLease(ctx, http.MethodPost, controllerBridgePath+"manager-intents/"+handle.HandleID+"/grant-intents", c.NodeToken, call, &result, true, call.RequestID, lease); err != nil {
		return nil, err
	}
	if workflowcontract.ValidateChildPublication("grantIntent", result) != nil {
		return nil, errors.New("actual typed PRODUCT grant intent refused")
	}
	var intent struct {
		HandleID, PolicyDigest, GrantDigest string
		Assignment                          struct{ AssignmentDigest string }
		Grant                               model.CellExecutionGrantV3
	}
	_ = json.Unmarshal(result, &intent)
	if intent.HandleID != handle.HandleID || intent.PolicyDigest != call.ProductPolicyDigest || intent.Assignment.AssignmentDigest != call.AssignmentDigest || intent.Grant.PreparedReceiptDigest != call.PreparedReceiptDigest || intent.GrantDigest != model.WorkspaceDigest(intent.Grant) {
		return nil, errors.New("actual grant-intent association conflict")
	}
	return result, nil
}
