package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

func (c Client) ControllerStageInput(ctx context.Context, operationID, serviceID, allocationName string) (model.ControllerStageReadout, error) {
	var out model.ControllerStageReadout
	for _, id := range []string{operationID, serviceID, allocationName} {
		if !managedServiceIDPattern.MatchString(id) {
			return out, errors.New("invalid controller stage identity")
		}
	}
	var raw json.RawMessage
	path := workspaceApplicationPath + url.PathEscape(operationID) + "/controller-inputs/" + url.PathEscape(serviceID) + "/" + url.PathEscape(allocationName)
	if err := c.planSourceClient().request(ctx, http.MethodGet, path, c.NodeToken, nil, &raw, true); err != nil {
		return out, err
	}
	if workflowcontract.Validate(workflowcontract.ControllerStage, "controllerStageReadout1", raw) != nil || model.DecodePhysicalClosed(raw, &out) != nil || out.ApplicationOperationID != operationID || out.ServiceRegistrationID != serviceID || out.AllocationName != allocationName || out.DeclarationItemDigest != model.WorkspaceDigest(out.Item) {
		return model.ControllerStageReadout{}, errors.New("closed controller stage readout refused")
	}
	return out, nil
}
