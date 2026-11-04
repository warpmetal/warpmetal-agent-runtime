package qualification

import (
	"encoding/json"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Capture is returned only by the protected installed Supervisor. The signer
// requires payloads, never a consumer's historyComplete/log.synced assertion.
type ControllerCapture struct {
	NativeOutput model.ControllerOutputNativeReadback `json:"nativeOutput"`
	NativeLog    []json.RawMessage                    `json:"nativeLog"`
}
type controllerDurableEvent struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Created int64  `json:"created"`
	Durable struct {
		AggregateID string `json:"aggregateID"`
		Seq         int64  `json:"seq"`
		Version     int64  `json:"version"`
	} `json:"durable"`
	Data     json.RawMessage `json:"data"`
	Location json.RawMessage `json:"location,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

func (e controllerDurableEvent) ref() model.ControllerEventRef {
	return model.ControllerEventRef{ID: e.ID, Type: e.Type, Created: e.Created, Durable: e.Durable}
}

// Typed projection of actual versioned native DATA (which has other native
// fields such as step cost/tokens). The whole object is duplicate-free UTF-8;
// selected authority fields are never taken from a last-key-wins decoder.
func controllerData(raw []byte, value any) error {
	if !utf8.Valid(raw) || rejectDuplicates(raw) != nil {
		return ErrUntrusted
	}
	return json.Unmarshal(raw, value)
}

// Independently checks actual canonical durable DATA and the first owning
// terminal through the output snapshot cursor. Unknown metadata cannot be used
// as input/text/model authority; no flattened-output splitting is possible.
func (c ControllerCapture) Verify(input string, identity json.RawMessage, admission model.ControllerAdmission) (model.ControllerOutputLineage, error) {
	n := c.NativeOutput.Data.ControllerOutput
	if model.WorkspaceDigest(n.Identity) != model.WorkspaceDigest(identity) || !reflect.DeepEqual(n.Admission, admission) {
		return model.ControllerOutputLineage{}, ErrUntrusted
	}
	lineage, err := c.NativeOutput.Normalize(input)
	if err != nil {
		return lineage, err
	}
	if n.Current.LogCursor > 32767 || len(c.NativeLog) > 32769 {
		return lineage, ErrUntrusted
	}
	history := []controllerDurableEvent{}
	ids := map[string]bool{}
	for _, raw := range c.NativeLog {
		var kind struct {
			Type string `json:"type"`
		}
		if controllerData(raw, &kind) != nil {
			return lineage, ErrUntrusted
		}
		if kind.Type == "log.synced" {
			continue
		}
		var event controllerDurableEvent
		if decode(raw, &event) != nil || event.Data == nil || event.Durable.AggregateID != n.Lineage.SessionID || event.Durable.Seq != int64(len(history)) || event.Durable.Version < 1 || event.Created < 0 || event.Created > n.Current.ObservedAt || !strings.HasPrefix(event.ID, "evt_") || ids[event.ID] {
			return lineage, ErrUntrusted
		}
		var data struct {
			SessionID string `json:"sessionID"`
		}
		if controllerData(event.Data, &data) != nil || data.SessionID != n.Lineage.SessionID {
			return lineage, ErrUntrusted
		}
		ids[event.ID] = true
		history = append(history, event)
	}
	if int64(len(history)) != n.Current.LogCursor+1 {
		return lineage, ErrUntrusted
	}
	var created struct {
		ProjectID string `json:"projectID"`
		Location  struct {
			Directory   string  `json:"directory"`
			WorkspaceID *string `json:"workspaceID"`
		} `json:"location"`
		ParentID *string                     `json:"parentID"`
		Agent    string                      `json:"agent"`
		Model    model.ControllerNativeModel `json:"model"`
	}
	registration := admission.PreparedReceipt.PreparedTuple.NativeRegistration
	if len(history) == 0 || history[0].Type != "session.created" || history[0].Durable.Version != 1 || controllerData(history[0].Data, &created) != nil || created.ParentID != nil || created.Location.WorkspaceID != nil || created.ProjectID != registration.NativeProjectID || created.Agent != n.Lineage.Agent || created.Model.ProviderID != n.Lineage.Model.ProviderID || created.Model.ID != n.Lineage.Model.ID || (created.Model.Variant != nil && *created.Model.Variant != "default") || model.WorkspaceDigest(map[string]any{"directory": created.Location.Directory, "projectId": created.ProjectID, "workspaceId": nil}) != registration.NativeLocationDigest {
		return lineage, ErrUntrusted
	}
	refData := func(ref model.ControllerEventRef) (json.RawMessage, error) {
		if ref.Durable.Seq < 0 || ref.Durable.Seq >= int64(len(history)) || history[ref.Durable.Seq].ref() != ref {
			return nil, ErrUntrusted
		}
		return history[ref.Durable.Seq].Data, nil
	}
	e := n.Events
	refs := append([]model.ControllerEventRef{e.Enqueued, e.ExecutionStarted, e.Delivered, e.StepEnded, e.Terminal}, e.StepStarted...)
	for _, p := range e.TextParts {
		refs = append(refs, p.Started, p.Ended)
	}
	for _, ref := range refs {
		if _, err := refData(ref); err != nil {
			return lineage, err
		}
	}
	registered := false
	prepared := false
	for _, ev := range history[:n.Lineage.InputSeq] {
		if ev.Type == "session.forked" {
			return lineage, ErrUntrusted
		}
		if ev.Type == "session.controller.registered" {
			var d struct {
				Identity json.RawMessage `json:"identity"`
			}
			if controllerData(ev.Data, &d) != nil || model.WorkspaceDigest(d.Identity) != model.WorkspaceDigest(identity) {
				return lineage, ErrUntrusted
			}
			registered = true
		}
		if ev.Type == "session.controller.prepared" {
			var d struct {
				Receipt model.ControllerPreparedReceipt `json:"receipt"`
			}
			if controllerData(ev.Data, &d) != nil {
				return lineage, ErrUntrusted
			}
			prepared = reflect.DeepEqual(d.Receipt, admission.PreparedReceipt)
		}
		if ev.Type == "session.controller.revoked" {
			registered = false
			prepared = false
		}
	}
	if !registered || !prepared {
		return lineage, ErrUntrusted
	}
	var enqueued struct {
		InboxID string `json:"inboxID"`
		Item    struct {
			Type    string                     `json:"type"`
			Payload map[string]json.RawMessage `json:"payload"`
		} `json:"item"`
	}
	if controllerData(history[n.Lineage.InputSeq].Data, &enqueued) != nil || enqueued.InboxID != n.Lineage.InputID || enqueued.Item.Type != "user" {
		return lineage, ErrUntrusted
	}
	payload := enqueued.Item.Payload
	var text string
	var submitted model.ControllerAdmission
	var guard struct {
		FormatVersion int    `json:"formatVersion"`
		ContextSeq    *int64 `json:"contextSeq"`
	}
	if controllerData(payload["text"], &text) != nil || text != input || controllerData(payload["controllerBinding"], &submitted) != nil || !reflect.DeepEqual(submitted, admission) || controllerData(payload["guard"], &guard) != nil || guard.FormatVersion != 3 || !reflect.DeepEqual(guard.ContextSeq, n.Current.ContextSeq) {
		return lineage, ErrUntrusted
	}
	for key, value := range payload {
		switch key {
		case "text", "controllerBinding", "guard":
		case "files", "agents", "skills":
			var parts []json.RawMessage
			if decode(value, &parts) != nil || len(parts) != 0 {
				return lineage, ErrUntrusted
			}
		default:
			return lineage, ErrUntrusted
		}
	}
	var delivered struct {
		InboxID string `json:"inboxID"`
	}
	if controllerData(history[n.Lineage.DeliveredSeq].Data, &delivered) != nil || delivered.InboxID != n.Lineage.InputID {
		return lineage, ErrUntrusted
	}
	var step struct {
		AssistantMessageID string                      `json:"assistantMessageID"`
		Agent              string                      `json:"agent"`
		Model              model.ControllerNativeModel `json:"model"`
	}
	if controllerData(history[e.StepStarted[0].Durable.Seq].Data, &step) != nil || step.AssistantMessageID != n.Lineage.AssistantMessageID || step.Agent != n.Lineage.Agent || !reflect.DeepEqual(step.Model, n.Lineage.Model) {
		return lineage, ErrUntrusted
	}
	var ended struct {
		AssistantMessageID string `json:"assistantMessageID"`
		Finish             string `json:"finish"`
	}
	if controllerData(history[n.Lineage.StepEndedSeq].Data, &ended) != nil || ended.AssistantMessageID != step.AssistantMessageID || ended.Finish != "stop" {
		return lineage, ErrUntrusted
	}
	starts, ends, stepStarts, stepEnds := 0, 0, 0, 0
	terminalFound := false
	for _, ev := range history[n.Lineage.InputSeq+1:] {
		switch ev.Type {
		case "session.moved", "session.revert.staged", "session.revert.committed", "session.message.content.updated", "session.controller.registered", "session.controller.prepared", "session.controller.revoked", "session.model.updated", "session.agent.updated", "session.synthetic", "session.skill.activated", "session.forked":
			return lineage, ErrUntrusted
		}
		if ev.Type == "session.instructions.updated" {
			// Actual F2 packet refreshes only built-in environment/date hashes
			// between execution start and delivery; no user instructions/content.
			var data struct {
				Delta map[string]string `json:"delta"`
			}
			if controllerData(ev.Data, &data) != nil || ev.Durable.Version != 2 || ev.Durable.Seq <= n.Lineage.ExecutionStartedSeq || ev.Durable.Seq >= n.Lineage.DeliveredSeq || len(data.Delta) == 0 {
				return lineage, ErrUntrusted
			}
			for key, value := range data.Delta {
				if (key != "core/environment" && key != "core/date") || !rawHash.MatchString(value) {
					return lineage, ErrUntrusted
				}
			}
		}
		if ev.Durable.Seq <= n.Lineage.ExecutionStartedSeq {
			continue
		}
		if ev.Type == "session.execution.succeeded" || ev.Type == "session.execution.failed" || ev.Type == "session.execution.interrupted" {
			if terminalFound || ev.Type != "session.execution.succeeded" || ev.Durable.Seq != n.Lineage.ExecutionTerminalSeq {
				return lineage, ErrUntrusted
			}
			terminalFound = true
		}
		if ev.Type == "session.execution.started" || strings.HasPrefix(ev.Type, "session.tool.") || strings.HasPrefix(ev.Type, "session.shell.") || ev.Type == "session.step.failed" || ev.Type == "session.inbox.enqueued" {
			return lineage, ErrUntrusted
		}
		if ev.Type == "session.inbox.delivered" && ev.Durable.Seq != n.Lineage.DeliveredSeq {
			return lineage, ErrUntrusted
		}
		if ev.Type == "session.step.started" {
			stepStarts++
		}
		if ev.Type == "session.step.ended" {
			stepEnds++
		}
		if ev.Type == "session.text.started" {
			starts++
		}
		if ev.Type == "session.text.ended" {
			ends++
		}
	}
	if !terminalFound || stepStarts != len(e.StepStarted) || stepEnds != 1 || starts != len(e.TextParts) || ends != len(e.TextParts) {
		return lineage, ErrUntrusted
	}
	var output strings.Builder
	for _, part := range e.TextParts {
		var start struct {
			AssistantMessageID string `json:"assistantMessageID"`
			Ordinal            int64  `json:"ordinal"`
		}
		var end struct {
			AssistantMessageID string `json:"assistantMessageID"`
			Ordinal            int64  `json:"ordinal"`
			Text               string `json:"text"`
		}
		if controllerData(history[part.Started.Durable.Seq].Data, &start) != nil || controllerData(history[part.Ended.Durable.Seq].Data, &end) != nil || start.AssistantMessageID != step.AssistantMessageID || end.AssistantMessageID != step.AssistantMessageID || start.Ordinal != part.Ordinal || end.Ordinal != part.Ordinal || !model.ControllerTextValid(end.Text) || len(end.Text) > 16384-output.Len() {
			return lineage, ErrUntrusted
		}
		output.WriteString(end.Text)
	}
	if output.String() != n.Output.Text {
		return lineage, ErrUntrusted
	}
	return lineage, nil
}
