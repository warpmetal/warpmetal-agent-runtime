package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"net/http"
	"time"
)

// Minimal coordinated read-only F1 r20 transport. No workflow lease/credentials,
// caller body/query, redirects, implicit retry or domain/fullchild wire changes.
func (c Client) QualificationAccessContext(ctx context.Context, id string) (model.QualificationAccessContext, error) {
	var result model.QualificationAccessContext
	var raw json.RawMessage
	if !managedServiceIDPattern.MatchString(id) {
		return result, errors.New("qualification access selector refused")
	}
	if err := c.planSourceClient().requestWithResponseLimit(ctx, http.MethodGet, "/internal/runtime/agent-model-qualifications/"+id+"/access-context", c.NodeToken, nil, &raw, true, "", "", 65536); err != nil {
		return result, err
	}
	var fields map[string]json.RawMessage
	if model.DecodePhysicalClosed(raw, &result) != nil || json.Unmarshal(raw, &fields) != nil || result.Validate(id, time.Now()) != nil || (result.FormatVersion == 1 && len(fields) != 12) || (result.FormatVersion == 2 && workflowcontract.ValidateQualificationAccessProvider(raw) != nil) {
		return model.QualificationAccessContext{}, errors.New("current access context refused")
	}
	return result, nil
}
