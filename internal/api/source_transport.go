package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Fixed node-authenticated r41 metadata GETs. No query/body/lease, redirects,
// fallback, retry, credential material or execution authority.
func (c Client) sourceTransportMetadata(ctx context.Context, id, target, phase string) (json.RawMessage, error) {
	if !managedServiceIDPattern.MatchString(id) {
		return nil, qualification.ErrUntrusted
	}
	family, suffix := "child-preparations/", "source-transport-prepare"
	if target == "controller_activity" {
		family = "controller-preparations/"
	}
	if phase == "execute" {
		suffix = "source-transport-control"
	}
	var raw json.RawMessage
	if err := c.planSourceClient().requestWithResponseLimit(ctx, http.MethodGet, controllerBridgePath+family+id+"/"+suffix, c.NodeToken, nil, &raw, true, "", "", 512*1024); err != nil {
		return nil, err
	}
	if _, err := qualification.DecodeSourceTransportMetadata(raw, target, id, phase); err != nil {
		return nil, err
	}
	return raw, nil
}
func (c Client) ChildSourceTransportPrepare(ctx context.Context, id string) (json.RawMessage, error) {
	return c.sourceTransportMetadata(ctx, id, "cell_session", "prepare")
}
func (c Client) ChildSourceTransportControl(ctx context.Context, id string) (json.RawMessage, error) {
	return c.sourceTransportMetadata(ctx, id, "cell_session", "execute")
}
func (c Client) ControllerSourceTransportPrepare(ctx context.Context, id string) (json.RawMessage, error) {
	return c.sourceTransportMetadata(ctx, id, "controller_activity", "prepare")
}
func (c Client) ControllerSourceTransportControl(ctx context.Context, id string) (json.RawMessage, error) {
	return c.sourceTransportMetadata(ctx, id, "controller_activity", "execute")
}

// Explicit SOURCE selection on the EXISTING published child control endpoint.
// Never retry/cast an ordinary PRODUCT response. Shape/selector checks are not
// authority: the owning caller must verify originals with the SOURCE57 consumer
// and separately complete the financial/native/OFFLINE gates before execution.
func (c Client) ChildSourceLocalPublishedControl(ctx context.Context, preparation string) (json.RawMessage, error) {
	if !managedServiceIDPattern.MatchString(preparation) {
		return nil, qualification.ErrUntrusted
	}
	var raw json.RawMessage
	if err := c.planSourceClient().requestWithResponseLimit(ctx, http.MethodGet, controllerBridgePath+"child-preparations/"+preparation+"/product-control", c.NodeToken, nil, &raw, true, "", "", 512*1024); err != nil {
		return nil, err
	}
	var control qualification.SourceLocalPublishedControl
	if workflowcontract.ValidateSourceLocalGrant("localPublishedControl", raw) != nil || json.Unmarshal(raw, &control) != nil || control.TargetKind != "cell_session" || control.PreparationID != preparation {
		return nil, qualification.ErrUntrusted
	}
	return raw, nil
}
