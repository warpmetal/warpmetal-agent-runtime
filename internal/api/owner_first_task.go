package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// R53's one producer wire. Task consent is immutable input, not an execution
// grant, workflow lease or proof of installed applicability.
type OwnerFirstTaskOriginal struct {
	FormatVersion              int                   `json:"formatVersion"`
	FirstTaskID                string                `json:"firstTaskId"`
	SetupIntentID              string                `json:"setupIntentId"`
	RequestID                  string                `json:"requestId"`
	ApplicationID              string                `json:"applicationId"`
	ApplicationOperationID     string                `json:"applicationOperationId"`
	ApplicationOperationDigest string                `json:"applicationOperationDigest"`
	ConfigurationID            string                `json:"configurationId"`
	ConfigurationRevision      int64                 `json:"configurationRevision"`
	ConfigurationDigest        string                `json:"configurationDigest"`
	Owner                      model.ControllerOwner `json:"owner"`
	Parent                     struct {
		ServiceRegistrationID string                            `json:"serviceRegistrationId"`
		ServiceGeneration     int64                             `json:"serviceGeneration"`
		Role                  string                            `json:"role"`
		ConfigDigest          string                            `json:"configDigest"`
		DesiredRevision       int64                             `json:"desiredRevision"`
		NativeRegistration    model.ManagedNativeRegistrationV1 `json:"nativeRegistration"`
	} `json:"parent"`
	InputText             string                       `json:"inputText"`
	ParentActivityRequest ControllerPreparationRequest `json:"parentActivityRequest"`
	CreatedAt             string                       `json:"createdAt"`
	StatusURL             string                       `json:"statusUrl"`
}
type OwnerFirstTaskResponse struct {
	OwnerFirstTaskOriginal
	Status struct {
		State                 string  `json:"state"`
		PreparationID         *string `json:"preparationId"`
		PreparedReceiptDigest *string `json:"preparedReceiptDigest"`
		ActivityID            *string `json:"activityId"`
		ContextID             *string `json:"contextId"`
		OutputReceiptDigest   *string `json:"outputReceiptDigest"`
	} `json:"status"`
}

func (c Client) OwnerFirstTask(ctx context.Context, operationID string) (OwnerFirstTaskResponse, error) {
	var out OwnerFirstTaskResponse
	if !managedServiceIDPattern.MatchString(operationID) {
		return out, errors.New("invalid first-task application identity")
	}
	var raw json.RawMessage
	if err := c.planSourceClient().request(ctx, http.MethodGet, workspaceApplicationPath+operationID+"/first-task", c.NodeToken, nil, &raw, true); err != nil {
		return out, err
	}
	if workflowcontract.ValidateOwnerFirstTask("ownerFirstTaskResponse", raw) != nil || model.DecodePhysicalClosed(raw, &out) != nil {
		return OwnerFirstTaskResponse{}, errors.New("closed first-task response refused")
	}
	for _, id := range []string{out.FirstTaskID, out.SetupIntentID, out.RequestID, out.ApplicationID, out.ConfigurationID, out.Parent.ServiceRegistrationID} {
		if !managedServiceIDPattern.MatchString(id) {
			return OwnerFirstTaskResponse{}, errors.New("first-task identity refused")
		}
	}
	if (out.FormatVersion != 1 && out.FormatVersion != 2) || out.ApplicationOperationID != operationID || out.ConfigurationRevision < 1 || out.Parent.ServiceGeneration < 1 || out.Parent.DesiredRevision < 1 || out.Parent.Role != "orchestrator" || !model.PhysicalDigestValid(out.ApplicationOperationDigest) || !model.PhysicalDigestValid(out.ConfigurationDigest) || !model.PhysicalDigestValid(out.Parent.ConfigDigest) || !utf8.ValidString(out.InputText) || len(out.InputText) > 16384 || strings.TrimSpace(out.InputText) == "" || strings.ContainsRune(out.InputText, 0) || out.ParentActivityRequest.InputDigest != model.RawPhysicalDigest([]byte(out.InputText)) || out.ParentActivityRequest.ServiceRegistrationID != out.Parent.ServiceRegistrationID || out.StatusURL != "/internal/account/agent-workspace-setup-intents/"+out.SetupIntentID+"/tasks/"+out.FirstTaskID {
		return OwnerFirstTaskResponse{}, errors.New("first-task input/current identity conflict")
	}
	at, err := time.Parse(time.RFC3339Nano, out.CreatedAt)
	if err != nil || at.After(time.Now()) {
		return OwnerFirstTaskResponse{}, errors.New("first-task original timestamp refused")
	}
	request, _ := json.Marshal(out.ParentActivityRequest)
	document, definition := workflowcontract.Producer, "controllerPreparationRequest"
	if out.FormatVersion == 2 {
		document, definition = workflowcontract.ControllerProvider, "controllerPreparationRequest2"
	}
	if workflowcontract.Validate(document, definition, request) != nil {
		return OwnerFirstTaskResponse{}, errors.New("first-task parent request refused")
	}
	switch out.Status.State {
	case "accepted", "preparing", "prepared", "authorized", "output_accepted":
	default:
		return OwnerFirstTaskResponse{}, errors.New("first-task status is not completion")
	}
	for _, id := range []*string{out.Status.PreparationID, out.Status.ActivityID, out.Status.ContextID} {
		if id != nil && !managedServiceIDPattern.MatchString(*id) {
			return OwnerFirstTaskResponse{}, errors.New("first-task status identity refused")
		}
	}
	for _, d := range []*string{out.Status.PreparedReceiptDigest, out.Status.OutputReceiptDigest} {
		if d != nil && !model.PhysicalDigestValid(*d) {
			return OwnerFirstTaskResponse{}, errors.New("first-task status digest refused")
		}
	}
	return out, nil
}
