package model

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Identity remains exact raw native data. Executable root consumers compare it
// with independently observed registered intent/source/projection, not this DTO.
type ControllerNativeOutput struct {
	FormatVersion int                 `json:"formatVersion"`
	TargetKind    string              `json:"targetKind"`
	Identity      json.RawMessage     `json:"identity"`
	Admission     ControllerAdmission `json:"admission"`
	Lineage       struct {
		SessionID             string                `json:"sessionID"`
		InputID               string                `json:"inputID"`
		InputDigest           string                `json:"inputDigest"`
		InputUTF8Bytes        int                   `json:"inputUtf8Bytes"`
		InputSeq              int64                 `json:"inputSeq"`
		GrantID               string                `json:"grantId"`
		PreparationID         string                `json:"preparationId"`
		PreparedReceiptDigest string                `json:"preparedReceiptDigest"`
		ExecutionStartedSeq   int64                 `json:"executionStartedSeq"`
		DeliveredSeq          int64                 `json:"deliveredSeq"`
		AssistantMessageID    string                `json:"assistantMessageID"`
		Agent                 string                `json:"agent"`
		Model                 ControllerNativeModel `json:"model"`
		StepEndedSeq          int64                 `json:"stepEndedSeq"`
		ExecutionTerminalSeq  int64                 `json:"executionTerminalSeq"`
		OutputDigest          string                `json:"outputDigest"`
		OutputUTF8Bytes       int                   `json:"outputUtf8Bytes"`
		TextPartCount         int                   `json:"textPartCount"`
	} `json:"lineage"`
	Events ControllerOutputEventRefs `json:"events"`
	Output struct {
		Text string `json:"text"`
	} `json:"output"`
	Current struct {
		InputSeq             int64  `json:"inputSeq"`
		ContextSeq           *int64 `json:"contextSeq"`
		ExecutionStartedSeq  int64  `json:"executionStartedSeq"`
		ExecutionTerminalSeq int64  `json:"executionTerminalSeq"`
		Active               bool   `json:"active"`
		LogCursor            int64  `json:"logCursor"`
		ObservedAt           int64  `json:"observedAt"`
	} `json:"current"`
}
type ControllerNativeModel struct {
	ProviderID string  `json:"providerID"`
	ID         string  `json:"id"`
	Variant    *string `json:"variant,omitempty"`
}

func ControllerTextDigest(text string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(text)))
}
func ControllerTextValid(text string) bool {
	return utf8.ValidString(text) && len(text) > 0 && len(text) <= 16384 && !strings.ContainsRune(text, 0)
}

// F1 runtime.iso uses UTC second precision. Keep raw millisecond event refs
// unchanged and use those exact clocks (not truncated strings) for deadlines.
func ControllerOutputTimestamp(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05Z")
}

// Normalize checks deterministic cross-wire joins only; retained-log inspection,
// operator signatures, real model, current root/identity remain separate gates.
func (r ControllerOutputNativeReadback) Normalize(input string) (ControllerOutputLineage, error) {
	var out ControllerOutputLineage
	n := r.Data.ControllerOutput
	l, e, c := n.Lineage, n.Events, n.Current
	p, g := n.Admission.PreparedReceipt, n.Admission.Grant
	t := p.PreparedTuple
	bad := errors.New("controller native output mismatch")
	if n.FormatVersion != 1 || n.TargetKind != "controller_activity_output" || n.Admission.FormatVersion != 1 || n.Admission.TargetKind != "controller_activity" || p.validateWire() != nil ||
		!ControllerTextValid(input) || !ControllerTextValid(n.Output.Text) || l.Model.ProviderID != t.Authority.ProviderID || l.Model.ID != t.Authority.ModelID ||
		(l.Model.Variant != nil && *l.Model.Variant != "default") || l.Agent != "warpmetal-controller-"+t.Role || l.InputID != t.InputID ||
		l.InputDigest != t.InputDigest || l.InputDigest != ControllerTextDigest(input) || l.InputUTF8Bytes != len(input) ||
		l.OutputDigest != ControllerTextDigest(n.Output.Text) || l.OutputUTF8Bytes != len(n.Output.Text) || l.SessionID != t.NativeRegistration.NativeSessionID ||
		l.GrantID != g.GrantID || l.PreparationID != g.PreparationID || l.PreparationID != p.PreparationID || l.PreparedReceiptDigest != p.PreparedReceiptDigest ||
		g.PreparedReceiptDigest != p.PreparedReceiptDigest || g.FormatVersion != 1 || g.TargetKind != "controller_activity" ||
		l.TextPartCount < 1 || l.TextPartCount != len(e.TextParts) || len(e.StepStarted) != 1 || c.Active || c.ObservedAt < 0 ||
		c.InputSeq != l.InputSeq || c.ExecutionStartedSeq != l.ExecutionStartedSeq || c.ExecutionTerminalSeq != l.ExecutionTerminalSeq ||
		(c.ContextSeq != nil && *c.ContextSeq != l.InputSeq) || c.LogCursor < l.ExecutionTerminalSeq {
		return out, bad
	}
	refs := []ControllerEventRef{e.Enqueued, e.ExecutionStarted, e.Delivered, e.StepStarted[0]}
	types := []string{"session.inbox.enqueued", "session.execution.started", "session.inbox.delivered", "session.step.started"}
	for i, p := range e.TextParts {
		if p.Ordinal != int64(i) {
			return out, bad
		}
		refs = append(refs, p.Started, p.Ended)
		types = append(types, "session.text.started", "session.text.ended")
	}
	refs = append(refs, e.StepEnded, e.Terminal)
	types = append(types, "session.step.ended", "session.execution.succeeded")
	ids := map[string]bool{}
	seqs := map[int64]bool{}
	for i, ref := range refs {
		if !strings.HasPrefix(ref.ID, "evt_") || ref.Type != types[i] || ref.Created < 0 || ref.Created > c.ObservedAt || ref.Durable.AggregateID != l.SessionID || ref.Durable.Version != 1 || ref.Durable.Seq < 0 || ref.Durable.Seq > c.LogCursor || ids[ref.ID] || seqs[ref.Durable.Seq] || (i > 0 && ref.Durable.Seq <= refs[i-1].Durable.Seq) {
			return out, bad
		}
		ids[ref.ID] = true
		seqs[ref.Durable.Seq] = true
	}
	if e.Enqueued.Durable.Seq != l.InputSeq || e.ExecutionStarted.Durable.Seq != l.ExecutionStartedSeq || e.Delivered.Durable.Seq != l.DeliveredSeq || e.StepEnded.Durable.Seq != l.StepEndedSeq || e.Terminal.Durable.Seq != l.ExecutionTerminalSeq || e.StepEnded.Created > e.Terminal.Created {
		return out, bad
	}
	for _, s := range []string{g.DeadlineAt, g.ExpiresAt} {
		at, err := time.Parse(time.RFC3339Nano, s)
		if err != nil || !time.UnixMilli(e.Terminal.Created).Before(at) {
			return out, bad
		}
	}
	out.ControllerActivity = ControllerActivity{Admission: n.Admission, InputID: l.InputID, InputSeq: l.InputSeq, ExecutionStartedSeq: l.ExecutionStartedSeq}
	out.InputText = input
	out.ExecutionTerminalSeq = l.ExecutionTerminalSeq
	out.TerminalAt = ControllerOutputTimestamp(e.Terminal.Created)
	out.TerminalOutcome = "succeeded"
	out.AssistantMessageID = l.AssistantMessageID
	out.AssistantAgentID = l.Agent
	out.AssistantModel.ProviderID = l.Model.ProviderID
	out.AssistantModel.ID = l.Model.ID
	out.AssistantCompletedAt = ControllerOutputTimestamp(e.StepEnded.Created)
	out.AssistantFinish = "stop"
	out.OutputText = n.Output.Text
	out.OutputByteCount = len(n.Output.Text)
	out.OutputDigest = l.OutputDigest
	out.EventRefs = e
	return out, nil
}
