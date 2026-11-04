package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

const controllerBridgePath = "/internal/runtime/workspace-workflow/"

type ControllerPreparationRequest struct {
	ProviderPolicyDigest  string                        `json:"providerPolicyDigest,omitempty"`
	FormatVersion         int                           `json:"formatVersion"`
	RequestID             string                        `json:"requestId"`
	ServiceRegistrationID string                        `json:"serviceRegistrationId"`
	InputID               string                        `json:"inputId"`
	InputDigest           string                        `json:"inputDigest"`
	ModelSelection        model.WorkspaceModelSelection `json:"modelSelection"`
}
type ControllerPreparationResult struct {
	FormatVersion              int                            `json:"formatVersion,omitempty"`
	ApplicationRoleAgentDigest string                         `json:"applicationRoleAgentDigest,omitempty"`
	ApplicationConfigDigest    string                         `json:"applicationConfigDigest,omitempty"`
	IdentityAssociationDigest  string                         `json:"identityAssociationDigest,omitempty"`
	PreparationID              string                         `json:"preparationId"`
	State                      string                         `json:"state"`
	PreparedTuple              *model.ControllerPreparedTuple `json:"preparedTuple"`
}
type ControllerCredential struct {
	FormatVersion      int             `json:"formatVersion"`
	CredentialID       string          `json:"credentialId"`
	ConnectionID       string          `json:"connectionId"`
	ConnectionRevision int64           `json:"connectionRevision"`
	ProviderID         string          `json:"providerId"`
	AuthMode           string          `json:"authMode"`
	Material           json.RawMessage `json:"material"`
}
type ControllerPreparedEnvelope = model.ControllerPreparedEnvelope
type ControllerGrantEnvelope = model.ControllerGrantEnvelope

func (c Client) PrepareControllerActivity(ctx context.Context, call ControllerPreparationRequest) (ControllerPreparationResult, error) {
	c = c.paidDomainClient()
	var result ControllerPreparationResult
	if (call.FormatVersion != 1 && call.FormatVersion != 2) || !managedServiceIDPattern.MatchString(call.ServiceRegistrationID) || !managedServiceIDPattern.MatchString(call.InputID) || !managedServiceIDPattern.MatchString(call.RequestID) {
		return result, errors.New("invalid controller preparation identity")
	}
	if call.FormatVersion == 2 {
		raw, _ := json.Marshal(call)
		p := providerpolicy.Flash()
		if workflowcontract.Validate(workflowcontract.ControllerProvider, "controllerPreparationRequest2", raw) != nil || call.ModelSelection.Authority != (model.CellPreparedAuthorityV3{ProviderID: p.ProviderID, ModelID: p.ModelID, AuthMode: p.AuthMode}) {
			return result, errors.New("invalid provider preparation request")
		}
	} else if call.ProviderPolicyDigest != "" {
		return result, errors.New("provider policy in legacy preparation")
	}
	err := c.requestWithKey(ctx, http.MethodPost, controllerBridgePath+"controller-preparations", c.NodeToken, call, &result, true, call.RequestID)
	if err != nil {
		return result, err
	}
	if !managedServiceIDPattern.MatchString(result.PreparationID) || result.State != "native_admission_pending" {
		return ControllerPreparationResult{}, errors.New("controller preparation response conflict")
	}
	if call.FormatVersion == 2 {
		raw, _ := json.Marshal(result)
		if workflowcontract.Validate(workflowcontract.ControllerProvider, "controllerPreparationResponse2", raw) != nil || result.PreparedTuple == nil || result.PreparedTuple.Authority != call.ModelSelection.Authority || call.ModelSelection.CredentialBinding == nil || result.PreparedTuple.CredentialBinding != *call.ModelSelection.CredentialBinding || result.PreparedTuple.ServiceRegistrationID != call.ServiceRegistrationID || result.PreparedTuple.InputID != call.InputID || result.PreparedTuple.InputDigest != call.InputDigest {
			return ControllerPreparationResult{}, errors.New("provider preparation response conflict")
		}
	} else if result.FormatVersion != 0 || result.ApplicationRoleAgentDigest != "" || result.ApplicationConfigDigest != "" || result.IdentityAssociationDigest != "" {
		return ControllerPreparationResult{}, errors.New("provider response in legacy preparation")
	}
	return result, nil
}
func (c Client) ControllerCredential(ctx context.Context, preparationID string) (ControllerCredential, error) {
	c = c.paidDomainClient()
	var result ControllerCredential
	if !managedServiceIDPattern.MatchString(preparationID) {
		return result, errors.New("invalid controller preparation")
	}
	err := c.request(ctx, http.MethodGet, controllerBridgePath+"controller-preparations/"+preparationID+"/credential", c.NodeToken, nil, &result, true)
	if err != nil {
		return result, err
	}
	if result.FormatVersion != 3 || !managedServiceIDPattern.MatchString(result.CredentialID) || !managedServiceIDPattern.MatchString(result.ConnectionID) || result.ConnectionRevision < 1 || (result.ProviderID != "openai" && result.ProviderID != providerpolicy.Flash().ProviderID) || result.AuthMode != "api_key" || len(result.Material) == 0 {
		return ControllerCredential{}, errors.New("controller credential response conflict")
	}
	return result, nil
}
func (c Client) SubmitControllerPreparedReceipt(ctx context.Context, envelope ControllerPreparedEnvelope) (model.ControllerPreparedReceipt, error) {
	c = c.paidDomainClient()
	var receipt model.ControllerPreparedReceipt
	// This transport validates native wire facts. Executable model authority is
	// selected by the caller's current signed policy and independently by backend.
	raw, err := json.Marshal(envelope.Payload)
	var wire model.ControllerPreparedReceipt
	if err != nil || json.Unmarshal(raw, &wire) != nil {
		return receipt, errors.New("invalid controller receipt")
	}
	err = c.requestWithKey(ctx, http.MethodPost, controllerBridgePath+"controller-preparations/"+envelope.Payload.PreparationID+"/receipts", c.NodeToken, envelope, &receipt, true, envelope.Payload.PreparationID)
	return receipt, err
}
func (c Client) ReserveControllerActivity(ctx context.Context, envelope ControllerGrantEnvelope) (model.ControllerActivityGrant, error) {
	var result model.ControllerActivityGrant
	if !managedServiceIDPattern.MatchString(envelope.Payload.PreparationID) {
		return result, errors.New("invalid controller preparation")
	}
	err := c.paidDomainClient().requestWithKey(ctx, http.MethodPost, controllerBridgePath+"controller-preparations/"+envelope.Payload.PreparationID+"/grants", c.NodeToken, envelope, &result, true, envelope.Payload.GrantID)
	return result, err
}

// This GET selects independently approved context BEFORE input. Missing supplier
// is the backend's explicit409, never a consumer-chosen target or text-as-grant.
func validControllerLease(lease string) bool {
	return strings.HasPrefix(lease, "wfl_") && len(lease) <= 256 && !strings.ContainsAny(lease, "\r\n\x00")
}

func (c Client) ControllerWorkflowContext(ctx context.Context, preparationID, workflowLease string) (model.ControllerApprovedInputContext, error) {
	c = c.paidDomainClient()
	var result model.ControllerApprovedInputContext
	if !managedServiceIDPattern.MatchString(preparationID) || !validControllerLease(workflowLease) {
		return result, errors.New("invalid controller preparation")
	}
	err := c.requestWithWorkflowLease(ctx, http.MethodGet, controllerBridgePath+"controller-preparations/"+preparationID+"/workflow-context", c.NodeToken, nil, &result, true, "", workflowLease)
	if err != nil {
		return result, err
	}
	if result.PreparationID != preparationID {
		return model.ControllerApprovedInputContext{}, errors.New("controller approved context conflict")
	}
	return result, nil
}
func (c Client) AuthorizeControllerOutput(ctx context.Context, call model.ControllerOutputOperationRequest, workflowLease string) (model.ControllerOutputOperation, error) {
	c = c.paidDomainClient()
	var result model.ControllerOutputOperation
	if call.FormatVersion < 1 || call.FormatVersion > 4 || !managedServiceIDPattern.MatchString(call.RequestID) || !validControllerLease(workflowLease) {
		return result, errors.New("invalid output request")
	}
	raw, _ := json.Marshal(call)
	if len(raw) > 65536 {
		return result, errors.New("controller output request exceeds wire cap")
	}
	if call.FormatVersion >= 2 {
		document, definition := workflowcontract.Manager, "controllerOutputOperationRequest2"
		if call.FormatVersion == 3 {
			document, definition = workflowcontract.ControllerProvider, "controllerOutputOperationRequest3"
		}
		if call.FormatVersion == 4 {
			document, definition = workflowcontract.ManagerSingle, "controllerOutputOperationRequest4"
		}
		if err := workflowcontract.Validate(document, definition, raw); err != nil {
			return result, errors.New("invalid closed controller output request")
		}
	}
	err := c.requestWithWorkflowLease(ctx, http.MethodPost, controllerBridgePath+"controller-output-operations", c.NodeToken, call, &result, true, call.RequestID, workflowLease)
	if err != nil {
		return result, err
	}
	if result.FormatVersion != call.FormatVersion || result.RequestID != call.RequestID || result.Context.ContextID != call.ContextID {
		return model.ControllerOutputOperation{}, errors.New("controller output operation conflict")
	}
	return result, nil
}
func (c Client) ControllerOutputOperation(ctx context.Context, id, workflowLease string) (model.ControllerOutputOperation, error) {
	c = c.paidDomainClient()
	var result model.ControllerOutputOperation
	if !managedServiceIDPattern.MatchString(id) || !validControllerLease(workflowLease) {
		return result, errors.New("invalid output operation")
	}
	err := c.requestWithWorkflowLease(ctx, http.MethodGet, controllerBridgePath+"controller-output-operations/"+id, c.NodeToken, nil, &result, true, "", workflowLease)
	if err != nil {
		return result, err
	}
	if result.OperationID != id {
		return model.ControllerOutputOperation{}, errors.New("controller output operation conflict")
	}
	return result, nil
}
func (c Client) SubmitControllerOutputAction(ctx context.Context, envelope model.ControllerOutputEnvelope, workflowLease string) (json.RawMessage, error) {
	c = c.paidDomainClient()
	var result json.RawMessage
	p := envelope.Payload
	if !validControllerLease(workflowLease) || p.Purpose != "workspace_workflow_controller_output" ||
		!managedServiceIDPattern.MatchString(p.OperationID) || !managedServiceIDPattern.MatchString(p.RequestID) || envelope.KeyID == "" || envelope.Signature == "" {
		return nil, errors.New("protected controller action authority missing")
	}
	raw, e := json.Marshal(envelope)
	if e != nil || len(raw) > 65536 {
		return nil, errors.New("controller action envelope exceeds wire cap")
	}
	err := c.requestWithWorkflowLease(ctx, http.MethodPost, controllerBridgePath+"controller-output-operations/"+p.OperationID+"/actions", c.NodeToken, envelope, &result, true, p.RequestID, workflowLease)
	return result, err
}

type ControllerActivationSigningIntent struct {
	PayloadBasis json.RawMessage `json:"payloadBasis"`
	NotBefore    string          `json:"notBefore"`
}
type ControllerActivationEnvelope struct {
	Payload   qualification.ControllerActivation `json:"payload"`
	KeyID     string                             `json:"keyId"`
	Signature string                             `json:"signature"`
}
type ControllerActivationPublication struct {
	Activation        ControllerActivationEnvelope          `json:"activation"`
	HeaderObservation model.ControllerAuthorizationEnvelope `json:"headerObservation"`
}
type ControllerActivationReceipt struct {
	FormatVersion    int    `json:"formatVersion"`
	PreparationID    string `json:"preparationId"`
	ActivationDigest string `json:"activationDigest"`
	State            string `json:"state"`
}

func (c Client) ControllerActivationIntent(ctx context.Context, id string) (ControllerActivationSigningIntent, error) {
	var result ControllerActivationSigningIntent
	if !managedServiceIDPattern.MatchString(id) {
		return result, errors.New("invalid preparation")
	}
	err := c.paidDomainClient().request(ctx, http.MethodGet, controllerBridgePath+"controller-preparations/"+id+"/activation-intent", c.NodeToken, nil, &result, true)
	return result, err
}
func (c Client) PublishControllerActivation(ctx context.Context, call ControllerActivationPublication) (ControllerActivationReceipt, error) {
	var result ControllerActivationReceipt
	id := call.Activation.Payload.Admission.PreparedReceipt.PreparationID
	if !managedServiceIDPattern.MatchString(id) || call.HeaderObservation.Payload.PreparationID != id {
		return result, errors.New("invalid activation publication")
	}
	err := c.paidDomainClient().request(ctx, http.MethodPost, controllerBridgePath+"controller-preparations/"+id+"/activations", c.NodeToken, call, &result, true)
	if err == nil && (result.FormatVersion != 2 || result.PreparationID != id || result.ActivationDigest != model.WorkspaceDigest(call.Activation.Payload) || result.State != "published") {
		err = errors.New("controller activation publication pending or unknown")
	}
	return result, err
}

// ControllerParentCredential delivers the exact pinned provider connection
// material for one ready controller parent over the node-authenticated
// transport. A controller parent has no cell preparation lease, so the ordinary
// CellCredential route cannot serve it; this is the sole source the Runtime may
// use to issue the native controller-activity prepare before a Foreman chat
// bridge is spawned. The response is the frozen v3 credential union and is
// never persisted, logged or returned to a caller.
func (c Client) ControllerParentCredential(ctx context.Context, serviceRegistrationID string) (ControllerCredential, error) {
	c = c.paidDomainClient()
	var result ControllerCredential
	if !managedServiceIDPattern.MatchString(serviceRegistrationID) {
		return result, errors.New("invalid controller parent")
	}
	err := c.request(ctx, http.MethodPost, "/internal/runtime/controller-parent-credential",
		c.NodeToken, map[string]string{"serviceRegistrationId": serviceRegistrationID}, &result, true)
	if err != nil {
		return ControllerCredential{}, err
	}
	if result.FormatVersion != 3 || !managedServiceIDPattern.MatchString(result.CredentialID) ||
		result.ConnectionRevision < 1 || result.ProviderID != "openai" || result.AuthMode != "api_key" ||
		len(result.Material) == 0 {
		return ControllerCredential{}, errors.New("controller parent credential response conflict")
	}
	var material struct {
		Type string `json:"type"`
		Key  string `json:"key"`
	}
	if err := json.Unmarshal(result.Material, &material); err != nil || material.Type != "key" ||
		strings.TrimSpace(material.Key) == "" || len(material.Key) > 4096 {
		return ControllerCredential{}, errors.New("controller parent credential material conflict")
	}
	return result, nil
}
