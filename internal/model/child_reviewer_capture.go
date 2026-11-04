package model

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// Exact fixed reviewer original capture. Assessment remains independent of a
// coding result or integrator output; none of these fields grant acceptance.
type ChildNativeReviewerCapture struct {
	GenerationDigest       string                  `json:"generationDigest"`
	BindingDigest          string                  `json:"bindingDigest"`
	InputID                string                  `json:"owningInputId"`
	InputDigest            string                  `json:"inputDigest"`
	AssistantMessageID     string                  `json:"assistantMessageId"`
	EnqueueSeq             int64                   `json:"enqueueSeq"`
	OwningStartSeq         int64                   `json:"owningStartSeq"`
	TerminalSeq            int64                   `json:"terminalSeq"`
	LogCursor              int64                   `json:"logCursor"`
	Current                ChildNativeCurrentState `json:"current"`
	StepStarted            json.RawMessage         `json:"stepStarted"`
	StepEnded              json.RawMessage         `json:"stepEnded"`
	TextStarted            json.RawMessage         `json:"textStarted"`
	TextEnded              json.RawMessage         `json:"textEnded"`
	AssessmentPath         string                  `json:"assessmentPath"`
	AssessmentDigest       string                  `json:"assessmentDigest"`
	AssessmentBytes        int                     `json:"assessmentBytes"`
	AssessmentBase64       string                  `json:"assessmentBase64"`
	OriginalResponseDigest string                  `json:"originalResponseDigest"`
	ProviderResponseDigest string                  `json:"providerResponseDigest"`
	Native                 ChildNativeExecution    `json:"native"`
}

func DecodeChildNativeReviewerCapture(raw []byte) (ChildNativeReviewerCapture, error) {
	var c ChildNativeReviewerCapture
	if DecodePhysicalClosed(raw, &c) != nil {
		return c, errors.New("child reviewer capture refused")
	}
	if _, e := c.Assessment(); e != nil {
		return c, e
	}
	return c, nil
}
func (c ChildNativeReviewerCapture) Assessment() ([]byte, error) {
	bad := errors.New("child reviewer original refused")
	raw, e := base64.StdEncoding.Strict().DecodeString(c.AssessmentBase64)
	n := c.Native
	if e != nil || len(raw) < 1 || len(raw) > 16384 || len(raw) != c.AssessmentBytes || RawPhysicalDigest(raw) != c.AssessmentDigest || !PhysicalDigestValid(c.ProviderResponseDigest) || !PhysicalDigestValid(c.OriginalResponseDigest) || !n.Current.Quiescent(n.InitialExecutionStartedSeq, n.TerminalSeq, n.LogCursor) || WorkspaceDigest(c.Current) != WorkspaceDigest(n.Current) || c.InputID != n.InputID || c.InputDigest != n.InputDigest || c.AssistantMessageID != n.AssistantMessageID || c.EnqueueSeq != n.EnqueueSeq || c.TerminalSeq != n.TerminalSeq || c.LogCursor != n.LogCursor || c.OwningStartSeq != n.Current.ExecutionStartedSeq {
		return nil, bad
	}
	prior := n.InitialExecutionStartedSeq
	for i, event := range []json.RawMessage{c.StepStarted, c.TextStarted, c.TextEnded, c.StepEnded} {
		var row struct {
			Seq  int64  `json:"seq"`
			Type string `json:"type"`
			Data struct {
				AssistantMessageID string `json:"assistantMessageID"`
				Text               string `json:"text"`
			} `json:"data"`
		}
		if json.Unmarshal(event, &row) != nil || row.Seq <= prior || row.Seq >= n.TerminalSeq || row.Data.AssistantMessageID != n.AssistantMessageID || row.Type != []string{"session.step.started", "session.text.started", "session.text.ended", "session.step.ended"}[i] || (i == 2 && row.Data.Text != string(raw)) {
			return nil, bad
		}
		prior = row.Seq
	}
	return raw, nil
}
func (c ChildNativeReviewerCapture) ValidateFor(entry CellServiceV3, generation string, binding json.RawMessage, inputID, inputDigest, path string) error {
	if _, e := c.Assessment(); e != nil {
		return e
	}
	if c.AssessmentPath != path {
		return errors.New("reviewer assessment path conflict")
	}
	// Reuse only the exact owning native tuple join, never coding semantics.
	tuple := ChildNativeResultCapture{GenerationDigest: c.GenerationDigest, BindingDigest: c.BindingDigest, Native: c.Native}
	return tuple.validateOwningInput(entry, generation, binding, inputID, inputDigest)
}
