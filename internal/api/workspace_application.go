package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

const workspaceApplicationPath = "/internal/runtime/workspace-workflow/application-operations/"

type WorkspaceApplicationAccepted struct {
	ApplicationID string `json:"applicationId"`
	State         string `json:"state"`
}

func (c Client) SubmitWorkspaceApplication(ctx context.Context, envelope model.WorkspaceApplicationEnvelope) (WorkspaceApplicationAccepted, error) {
	var accepted WorkspaceApplicationAccepted
	if err := envelope.Validate(); err != nil {
		return accepted, err
	}
	err := c.requestWithKey(ctx, http.MethodPost, "/internal/runtime/workspace-workflow/applications", c.NodeToken, envelope, &accepted, true, envelope.Payload.RequestID)
	if err != nil {
		return accepted, err
	}
	if !managedServiceIDPattern.MatchString(accepted.ApplicationID) || accepted.State != "applied" {
		return WorkspaceApplicationAccepted{}, errors.New("application acceptance response conflict")
	}
	return accepted, nil
}

// Exact operation-scoped opaque bundle transport. Approval comes from the current
// typed operation; ALL bytes/fields are subsequently verified by the installed
// protected materializer before any filesystem publication, not by this GET.
func (c Client) WorkspaceApplicationBundle(ctx context.Context, operationID string, ref model.ApprovedExpertiseProfile) (json.RawMessage, error) {
	if !managedServiceIDPattern.MatchString(operationID) || !managedServiceIDPattern.MatchString(ref.ProfileID) || ref.ProfileRevision < 1 || ref.ProfileRevision > 9007199254740991 {
		return nil, errors.New("invalid application bundle identity")
	}
	var result json.RawMessage
	path := workspaceApplicationPath + operationID + "/profiles/" + ref.ProfileID + "/" + strconv.FormatInt(ref.ProfileRevision, 10) + "/bundle"
	err := c.request(ctx, http.MethodGet, path, c.NodeToken, nil, &result, true)
	return result, err
}

func (c Client) WorkspaceApplicationOperation(ctx context.Context, operationID string) (model.WorkspaceApplicationOperation, error) {
	var result model.WorkspaceApplicationOperation
	if !managedServiceIDPattern.MatchString(operationID) {
		return result, errors.New("invalid application operation ID")
	}
	if err := c.request(ctx, http.MethodGet, workspaceApplicationPath+operationID, c.NodeToken, nil, &result, true); err != nil {
		return model.WorkspaceApplicationOperation{}, err
	}
	if result.OperationID != operationID {
		return model.WorkspaceApplicationOperation{}, errors.New("application operation ID conflict")
	}
	return result, nil
}

type WorkspaceApplicationInstructions struct {
	ServiceRegistrationID string `json:"serviceRegistrationId"`
	InstructionRevision   int64  `json:"instructionRevision"`
	InstructionDigest     string `json:"instructionDigest"`
	Content               string `json:"content"`
}

func (c Client) WorkspaceApplicationInstructions(ctx context.Context, operationID, serviceID string) (WorkspaceApplicationInstructions, error) {
	var result WorkspaceApplicationInstructions
	if !managedServiceIDPattern.MatchString(operationID) || !managedServiceIDPattern.MatchString(serviceID) {
		return result, errors.New("invalid application instruction ID")
	}
	if err := c.request(ctx, http.MethodGet, workspaceApplicationPath+operationID+"/roles/"+serviceID+"/instructions", c.NodeToken, nil, &result, true); err != nil {
		return result, err
	}
	if result.ServiceRegistrationID != serviceID || result.InstructionRevision < 1 || result.InstructionRevision > 9007199254740991 || !utf8.ValidString(result.Content) || len(result.Content) == 0 || len(result.Content) > 32768 || fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(result.Content))) != result.InstructionDigest {
		return WorkspaceApplicationInstructions{}, errors.New("application instruction bytes conflict")
	}
	return result, nil
}
