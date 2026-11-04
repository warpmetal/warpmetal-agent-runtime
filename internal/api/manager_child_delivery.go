package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Only F1's existing finite policy/activation/publication routes. Signing bases
// are explicitly unsigned, never transformed into authority by this caller.
func (c Client) ManagerChildPolicyIntent(ctx context.Context, h model.IntentHandle, stage, lease string) (json.RawMessage, error) {
	c = c.paidDomainClient()
	if !validControllerLease(lease) || !managedServiceIDPattern.MatchString(h.HandleID) || (stage != "prepare" && stage != "product") {
		return nil, errors.New("child policy intent selector refused")
	}
	suffix := "preparation-policy-intent"
	if stage == "product" {
		suffix = "product-policy-intent"
	}
	var raw json.RawMessage
	if err := c.planSourceClient().requestWithWorkflowLease(ctx, http.MethodGet, controllerBridgePath+"manager-intents/"+h.HandleID+"/"+suffix, c.NodeToken, nil, &raw, true, "", lease); err != nil {
		return nil, err
	}
	var intent struct{ HandleID, Stage string }
	if workflowcontract.ValidateChildPublication("policySigningIntent", raw) != nil || json.Unmarshal(raw, &intent) != nil || intent.HandleID != h.HandleID || intent.Stage != stage {
		return nil, errors.New("child policy intent original refused")
	}
	return raw, nil
}

func (c Client) ManagerChildActivationIntent(ctx context.Context, h model.IntentHandle, body json.RawMessage, lease string) (json.RawMessage, error) {
	c = c.paidDomainClient()
	if !validControllerLease(lease) || !managedServiceIDPattern.MatchString(h.HandleID) || workflowcontract.Validate(workflowcontract.ChildProduct, "activationIntentRequest", body) != nil {
		return nil, errors.New("child Authorization intent request refused")
	}
	var request struct {
		RequestID                string
		AuthorizationObservation json.RawMessage
	}
	_ = json.Unmarshal(body, &request)
	var raw json.RawMessage
	if err := c.planSourceClient().requestWithWorkflowLease(ctx, http.MethodPost, controllerBridgePath+"manager-intents/"+h.HandleID+"/activation-intents", c.NodeToken, body, &raw, true, request.RequestID, lease); err != nil {
		return nil, err
	}
	var response struct {
		HandleID                 string
		AuthorizationObservation json.RawMessage
	}
	if workflowcontract.ValidateChildPublication("activationSigningIntent", raw) != nil || json.Unmarshal(raw, &response) != nil || response.HandleID != h.HandleID || model.WorkspaceDigest(response.AuthorizationObservation) != model.WorkspaceDigest(request.AuthorizationObservation) {
		return nil, errors.New("child Authorization signing intent association refused")
	}
	return raw, nil
}

func (c Client) AcceptManagerChildActivation(ctx context.Context, h model.IntentHandle, body json.RawMessage, lease string) (json.RawMessage, error) {
	c = c.paidDomainClient()
	if !validControllerLease(lease) || !managedServiceIDPattern.MatchString(h.HandleID) || workflowcontract.ValidateChildPublication("activationAcceptRequest", body) != nil {
		return nil, errors.New("signed child activation request refused")
	}
	var request struct {
		RequestID  string
		Activation struct{ Payload json.RawMessage }
	}
	_ = json.Unmarshal(body, &request)
	var payload struct{ PreparationID string }
	_ = json.Unmarshal(request.Activation.Payload, &payload)
	var raw json.RawMessage
	if err := c.planSourceClient().requestWithWorkflowLease(ctx, http.MethodPost, controllerBridgePath+"manager-intents/"+h.HandleID+"/activations", c.NodeToken, body, &raw, true, request.RequestID, lease); err != nil {
		return nil, err
	}
	var receipt struct{ HandleID, PreparationID, ActivationDigest string }
	if workflowcontract.Validate(workflowcontract.ChildProduct, "activationAcceptReceipt", raw) != nil || json.Unmarshal(raw, &receipt) != nil || receipt.HandleID != h.HandleID || receipt.PreparationID != payload.PreparationID || receipt.ActivationDigest != model.WorkspaceDigest(request.Activation.Payload) {
		return nil, errors.New("accepted child activation original changed")
	}
	return raw, nil
}

func (c Client) PublishManagerChildControl(ctx context.Context, h model.IntentHandle, preparedID, phase string, body json.RawMessage, lease string) (json.RawMessage, error) {
	c = c.paidDomainClient()
	if !validControllerLease(lease) || !managedServiceIDPattern.MatchString(h.HandleID) || !managedServiceIDPattern.MatchString(preparedID) || (phase != "prepare" && phase != "execute") {
		return nil, errors.New("child publication selector refused")
	}
	definition, suffix := "intentPrepareRequest", "preparation-control-publications"
	if phase == "execute" {
		definition, suffix = "intentGrantRequest", "product-control-publications"
	}
	var request struct{ RequestID, HandleID string }
	if workflowcontract.Validate(workflowcontract.Manager, definition, body) != nil {
		return nil, errors.New("child publication request refused")
	}
	// Domain contract validation, followed by a narrow projection (closed DTO
	// decoders cannot be used for partial fields).
	if json.Unmarshal(body, &request) != nil || request.HandleID != h.HandleID {
		return nil, errors.New("child publication handle conflict")
	}
	var raw json.RawMessage
	if err := c.planSourceClient().requestWithWorkflowLease(ctx, http.MethodPost, controllerBridgePath+"manager-intents/"+h.HandleID+"/"+suffix, c.NodeToken, body, &raw, true, request.RequestID, lease); err != nil {
		return nil, err
	}
	var receipt struct{ PreparationID, Phase, State string }
	if workflowcontract.Validate(workflowcontract.ChildProduct, "publicationReceipt", raw) != nil || json.Unmarshal(raw, &receipt) != nil || receipt.PreparationID != preparedID || receipt.Phase != phase || receipt.State != "published" {
		return nil, errors.New("child publication UNKNOWN or conflict")
	}
	return raw, nil
}
