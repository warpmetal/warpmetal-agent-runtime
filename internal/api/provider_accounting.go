package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

const providerAccountingPath = controllerBridgePath + "provider-accounting/"

// ProviderAccountingCurrent transports the backend's original prefix. It does
// not adopt that prefix as an independently observed Runtime ledger cut.
func (c Client) ProviderAccountingCurrent(ctx context.Context, authorityDigest string) (json.RawMessage, error) {
	if !model.PhysicalDigestValid(authorityDigest) {
		return nil, errors.New("invalid accounting authority")
	}
	var raw json.RawMessage
	if err := c.paidDomainClient().requestWithResponseLimit(ctx, http.MethodGet, providerAccountingPath+"current", c.NodeToken, nil, &raw, true, "", "", workflowcontract.ProviderReadbackMaximum); err != nil {
		return nil, err
	}
	if err := workflowcontract.ValidateProviderReadback(raw); err != nil {
		return nil, errors.New("invalid backend accounting prefix")
	}
	var body struct {
		AuthorityDigest string `json:"authorityDigest"`
	}
	if json.Unmarshal(raw, &body) != nil || body.AuthorityDigest != authorityDigest {
		return nil, errors.New("backend accounting authority conflict")
	}
	return model.WorkspaceCanonicalJSON(raw)
}

// AcceptProviderAccountingOpening sends the first independently signed pair;
// callers own local observation and retention. An exact replay is idempotent.
func (c Client) AcceptProviderAccountingOpening(ctx context.Context, opening json.RawMessage) (json.RawMessage, error) {
	var selected struct{ FormatVersion int }
	if json.Unmarshal(opening, &selected) == nil && selected.FormatVersion == 3 {
		if workflowcontract.Validate(workflowcontract.ProviderParticipantAccounting, "openingContribution3", opening) != nil {
			return nil, errors.New("invalid participant opening")
		}
		return c.providerParticipantOpening(ctx, http.MethodPost, opening)
	}
	if workflowcontract.Validate(workflowcontract.ProviderAccounting, "openingHandshake", opening) != nil {
		return nil, errors.New("invalid accounting opening")
	}
	return c.providerAccountingMutation(ctx, "opening", opening, "openingDigest", model.WorkspaceDigest(opening))
}

// The existing opening route returns its first contributions or single final
// handshake. Pending metadata never authorizes a reservation or local dispatch.
func (c Client) ProviderAccountingOpening(ctx context.Context) (json.RawMessage, error) {
	return c.providerParticipantOpening(ctx, http.MethodGet, nil)
}
func (c Client) providerParticipantOpening(ctx context.Context, method string, body json.RawMessage) (json.RawMessage, error) {
	var response controlPlaneBytes
	key := ""
	if len(body) > 0 {
		key = model.WorkspaceDigest(body)
	}
	if err := c.paidDomainClient().requestWithResponseLimit(ctx, method, providerAccountingPath+"opening", c.NodeToken, body, &response, true, key, "", 65536); err != nil {
		var failure *ResponseError
		if method == http.MethodGet && errors.As(err, &failure) && failure.Status == http.StatusConflict && failure.Code == "provider_accounting_opening_pending" {
			return nil, errors.Join(model.ErrProviderOpeningAbsent, err)
		}
		return nil, err
	}
	if workflowcontract.Validate(workflowcontract.ProviderParticipantAccounting, "openingResponse3", response.Bytes) != nil {
		return nil, errors.New("invalid participant opening response")
	}
	var value struct {
		Status        string
		Opening       json.RawMessage
		OpeningDigest string
	}
	_ = json.Unmarshal(response.Bytes, &value)
	if (value.Status == "pending" && response.Status != 200 && response.Status != 202) || (value.Status == "opened" && (response.Status != 200 && response.Status != 201 || value.OpeningDigest != model.WorkspaceDigest(value.Opening))) {
		return nil, errors.New("participant opening status conflict")
	}
	return model.WorkspaceCanonicalJSON(json.RawMessage(response.Bytes))
}

// SettleProviderAccountingOriginals preserves the producer's first signature
// and all three original bodies; no retry/redirect creates another dispatch.
func (c Client) SettleProviderAccountingOriginals(ctx context.Context, original json.RawMessage) (json.RawMessage, error) {
	if workflowcontract.ValidateProviderOriginals(original) != nil {
		return nil, errors.New("invalid original accounting settlement")
	}
	var body struct {
		Settlement struct {
			Payload struct {
				PhysicalID string `json:"physicalId"`
			} `json:"payload"`
		} `json:"settlement"`
	}
	if json.Unmarshal(original, &body) != nil {
		return nil, errors.New("invalid accounting settlement")
	}
	return c.providerAccountingMutation(ctx, "original-settlements", original, "physicalId", body.Settlement.Payload.PhysicalID)
}

func (c Client) providerAccountingMutation(ctx context.Context, route string, body json.RawMessage, identityField, identity string) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := c.paidDomainClient().requestWithResponseLimit(ctx, http.MethodPost, providerAccountingPath+route, c.NodeToken, body, &raw, true, model.WorkspaceDigest(body), "", 65536); err != nil {
		return nil, err
	}
	var response map[string]json.RawMessage
	if json.Unmarshal(raw, &response) != nil || len(response) != 2 || workflowcontract.Validate(workflowcontract.ProviderAccounting, "ledgerSnapshot", response["snapshot"]) != nil {
		return nil, errors.New("invalid accounting acknowledgement")
	}
	var accepted string
	if json.Unmarshal(response[identityField], &accepted) != nil || accepted != identity {
		return nil, errors.New("accounting acknowledgement conflict")
	}
	return model.WorkspaceCanonicalJSON(raw)
}
