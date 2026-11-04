package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type paidDomainTransport struct{ base http.RoundTripper }

func (t paidDomainTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	// Metadata still uses the existing authenticated Client. Disallow automatic
	// transport replay of a POST whose backend mapping may already be committed.
	call := request.Clone(request.Context())
	call.Close = true
	call.GetBody = nil
	response, err := t.base.RoundTrip(call)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 && (response.StatusCode != 200 && response.StatusCode != 201 || request.Method == http.MethodGet && response.StatusCode != 200) {
		response.Body.Close()
		return nil, &ResponseError{Status: response.StatusCode, Code: "unexpected_paid_domain_status"}
	}
	return response, nil
}
func (c Client) paidDomainClient() Client {
	selected := c.planSourceClient()
	copy := *selected.HTTP
	base := copy.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	copy.Transport = paidDomainTransport{base: base}
	selected.HTTP = &copy
	return selected
}

func (c Client) AdoptPaidCaseDomain(ctx context.Context, request model.PaidCaseDomainAdoptionRequest) (json.RawMessage, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	err := c.paidDomainClient().requestWithResponseLimit(ctx, http.MethodPost, controllerBridgePath+"paid-case-domains/adoptions", c.NodeToken, request, &raw, true, model.WorkspaceDigest(request), "", 65536)
	if err != nil {
		return nil, err
	}
	if workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidCaseDomainAdoptionEnvelope", raw) != nil {
		return nil, errors.New("invalid paid domain adoption response")
	}
	// Decode the HTTP JSON framing into the canonical WHOLE original envelope;
	// payload and FIRST signature are retained, never re-signed or reconstructed.
	canonical, err := model.WorkspaceCanonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	raw = canonical
	var reply struct {
		Payload struct{ CompleteInventoryEnvelopeDigest, DemandManifestDigest, RuntimeReadbackEnvelopeDigest string }
	}
	if json.Unmarshal(raw, &reply) != nil || reply.Payload.CompleteInventoryEnvelopeDigest != request.CompleteInventoryEnvelopeDigest || reply.Payload.DemandManifestDigest != request.DemandManifestDigest || reply.Payload.RuntimeReadbackEnvelopeDigest != model.WorkspaceDigest(request.RuntimeReadback) {
		return nil, errors.New("paid adoption original reference conflict")
	}
	return raw, nil
}
func (c Client) AcceptPaidCaseDomain(ctx context.Context, request model.PaidCaseDomainAcceptanceRequest) (json.RawMessage, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	err := c.paidDomainClient().requestWithResponseLimit(ctx, http.MethodPost, controllerBridgePath+"paid-case-domains/acceptances", c.NodeToken, request, &raw, true, model.WorkspaceDigest(request), "", 65536)
	if err != nil {
		return nil, err
	}
	if workflowcontract.Validate(workflowcontract.PaidCaseDomainAdoption, "paidCaseDomainAcceptanceEnvelope", raw) != nil || model.WorkspaceDigest(raw) != model.WorkspaceDigest(request.Acceptance) {
		return nil, errors.New("paid acceptance original envelope conflict")
	}
	canonical, err := model.WorkspaceCanonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	raw = canonical
	return raw, nil
}
