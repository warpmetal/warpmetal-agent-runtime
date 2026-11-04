package model

import (
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Preserve the full owner-selected union, never flatten or expose a mutable
// extension map. Nested receipt/intent facts are schema-checked at ingress.
func (t *ControllerWorkflowTarget) UnmarshalJSON(raw []byte) error {
	var kind struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &kind); err != nil {
		return err
	}
	document, definition := workflowcontract.Manager, "controllerTarget2"
	if kind.Kind == "manager_work_intent" || kind.Kind == "manager_intent" {
		document, definition = workflowcontract.ManagerSingle, "controllerTarget3"
	}
	if kind.Kind == "advice_decision" {
		document, definition = workflowcontract.Producer, "controllerWorkflowTarget"
	}
	if err := workflowcontract.Validate(document, definition, raw); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	var result ControllerWorkflowTarget
	result.Kind = kind.Kind
	if err := json.Unmarshal(fields["role"], &result.Role); err != nil {
		return err
	}
	if err := json.Unmarshal(fields["resourceId"], &result.ResourceID); err != nil {
		return err
	}
	if value, present := fields["advice"]; present && string(value) != "null" {
		result.Advice = &value
	}
	// Common legacy variants keep their original comparable representation.
	if kind.Kind != "advice" && kind.Kind != "advice_decision" {
		canonical, err := WorkspaceCanonicalJSON(json.RawMessage(raw))
		if err != nil {
			return err
		}
		result.wire = canonical
		if result.Advice != nil {
			advice, err := WorkspaceCanonicalJSON(*result.Advice)
			if err != nil {
				return err
			}
			value := json.RawMessage(advice)
			result.Advice = &value
		}
	}
	*t = result
	return nil
}

func (t ControllerWorkflowTarget) MarshalJSON() ([]byte, error) {
	if t.wire != nil {
		var retained ControllerWorkflowTarget
		if err := json.Unmarshal(t.wire, &retained); err != nil {
			return nil, err
		}
		if t.Kind != retained.Kind || t.Role != retained.Role || !reflect.DeepEqual(t.ResourceID, retained.ResourceID) || !reflect.DeepEqual(t.Advice, retained.Advice) {
			return nil, errors.New("retained controller target changed")
		}
		return append([]byte(nil), t.wire...), nil
	}
	return json.Marshal(struct {
		Kind       string           `json:"kind"`
		Role       string           `json:"role"`
		ResourceID *string          `json:"resourceId"`
		Advice     *json.RawMessage `json:"advice"`
	}{t.Kind, t.Role, t.ResourceID, t.Advice})
}

// The parser uses only these independently selected retained facts; no fields
// are loaded from native output as workflow authority.
func (t ControllerWorkflowTarget) retainedFacts() (map[string]json.RawMessage, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	err = json.Unmarshal(raw, &fields)
	return fields, err
}
