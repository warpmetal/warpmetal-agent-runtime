package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Node-only fixed delivery. No lease, source bytes, request body, redirects,
// fallback, publication, slot reservation or automatic retry.
func (c Client) ChildProductControl(ctx context.Context, preparation string) (model.ChildProductDelivery, error) {
	var empty model.ChildProductDelivery
	if !managedServiceIDPattern.MatchString(preparation) {
		return empty, errors.New("invalid product preparation")
	}
	var raw json.RawMessage
	if err := c.planSourceClient().request(ctx, http.MethodGet, "/internal/runtime/workspace-workflow/child-preparations/"+preparation+"/product-control", c.NodeToken, nil, &raw, true); err != nil {
		return empty, err
	}
	delivery, err := model.DecodeChildProductDelivery(raw)
	if err != nil || delivery.PreparationID() != preparation {
		return empty, errors.New("product control preparation conflict")
	}
	return delivery, nil
}

// Exact F1 canonical22:27 node-only original owner projection, AFTER committed
// publication. Its specific512KiB cap does not enlarge physical/ordinary wires.
// No source hook, lease, query/body, supplied phase, signer, redirect or retry.
func (c Client) ChildProductFacts(ctx context.Context, preparation string) (model.ChildProductOriginalFacts, error) {
	var empty model.ChildProductOriginalFacts
	if !managedServiceIDPattern.MatchString(preparation) {
		return empty, errors.New("invalid original fact preparation")
	}
	var raw json.RawMessage
	if err := c.planSourceClient().requestWithResponseLimit(ctx, http.MethodGet, "/internal/runtime/workspace-workflow/child-preparations/"+preparation+"/original-facts", c.NodeToken, nil, &raw, true, "", "", 512*1024); err != nil {
		return empty, err
	}
	facts, err := model.DecodeChildProductOriginalFacts(raw)
	if err != nil || facts.PreparationID() != preparation {
		return empty, errors.New("original child fact preparation conflict")
	}
	return facts, nil
}
func (c Client) ChildProductEffectControl(ctx context.Context, preparation string, ordinal int) (model.ChildProductEffectDelivery, error) {
	var empty model.ChildProductEffectDelivery
	if !managedServiceIDPattern.MatchString(preparation) || ordinal < 0 || ordinal > 1 {
		return empty, errors.New("invalid product effect selection")
	}
	var raw json.RawMessage
	if err := c.planSourceClient().request(ctx, http.MethodGet, fmt.Sprintf("/internal/runtime/workspace-workflow/child-preparations/%s/effects/%d/control", preparation, ordinal), c.NodeToken, nil, &raw, true); err != nil {
		return empty, err
	}
	delivery, err := model.DecodeChildProductEffectDelivery(raw)
	if err != nil || delivery.PreparationID() != preparation || delivery.Ordinal() != ordinal {
		return empty, errors.New("product effect preparation/ordinal conflict")
	}
	return delivery, nil
}
