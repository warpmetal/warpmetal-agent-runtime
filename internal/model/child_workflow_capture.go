package model

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Fixed protected coding capture. This is an original observation, never a role
// grant, result acceptance, or permission to select an artifact path.
type ChildNativeResultCapture struct {
	FormatVersion    int                  `json:"formatVersion"`
	Purpose          string               `json:"purpose"`
	GenerationDigest string               `json:"generationDigest"`
	BindingDigest    string               `json:"bindingDigest"`
	Workload         string               `json:"workload"`
	Native           ChildNativeExecution `json:"native"`
	Effect           struct {
		CallID          string `json:"callId"`
		Tool            string `json:"tool"`
		ArgumentsDigest string `json:"argumentsDigest"`
		CalledSeq       int64  `json:"calledSeq"`
		CompletedSeq    int64  `json:"completedSeq"`
		ResponseDigest  string `json:"responseDigest"`
		ClaimDigest     string `json:"claimDigest"`
	} `json:"effect"`
	Terminal struct {
		Text           string `json:"text"`
		Digest         string `json:"digest"`
		ByteCount      int    `json:"byteCount"`
		ResponseDigest string `json:"responseDigest"`
	} `json:"terminal"`
	Artifact ChildNativeFileSnapshot `json:"artifact"`
}

// Current native completion shared by closed, purpose-specific captures.
type ChildNativeExecution struct {
	SessionID                  string                  `json:"sessionId"`
	NativeProjectID            string                  `json:"nativeProjectId"`
	NativeLocationDigest       string                  `json:"nativeLocationDigest"`
	InputID                    string                  `json:"inputId"`
	InputDigest                string                  `json:"inputDigest"`
	AssistantMessageID         string                  `json:"assistantMessageId"`
	EnqueueSeq                 int64                   `json:"enqueueSeq"`
	InitialExecutionStartedSeq int64                   `json:"initialExecutionStartedSeq"`
	TerminalSeq                int64                   `json:"terminalSeq"`
	LogCursor                  int64                   `json:"logCursor"`
	Current                    ChildNativeCurrentState `json:"current"`
	PreparedReceiptDigest      string                  `json:"preparedReceiptDigest"`
	GrantDigest                string                  `json:"grantDigest"`
}

type ChildNativeFileSnapshot struct {
	SourcePath string `json:"sourcePath"`
	Digest     string `json:"digest"`
	ByteCount  int    `json:"byteCount"`
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
}

// Exact current native guard and pending-work observations from the same
// coherent SQLite read; a prior terminal event does not replace these fields.
type ChildNativeCurrentState struct {
	ExecutionStartedSeq  int64    `json:"executionStartedSeq"`
	ExecutionTerminalSeq int64    `json:"executionTerminalSeq"`
	PendingInboxIDs      []string `json:"pendingInboxIds"`
	PendingToolCallIDs   []string `json:"pendingToolCallIds"`
}

func (c ChildNativeCurrentState) Quiescent(initial, terminal, cursor int64) bool {
	return c.ExecutionStartedSeq >= initial && c.ExecutionStartedSeq < terminal && c.ExecutionTerminalSeq == terminal && terminal <= cursor && c.PendingInboxIDs != nil && len(c.PendingInboxIDs) == 0 && c.PendingToolCallIDs != nil && len(c.PendingToolCallIDs) == 0
}

// Distinct integration observation: its before-image is captured by the guarded
// effect and retained before writing, never inferred from the coding artifact.
type ChildNativeIntegrationCapture struct {
	ChildNativeResultCapture
	Before ChildNativeFileSnapshot `json:"before"`
}

func DecodeChildNativeResultCapture(raw []byte) (ChildNativeResultCapture, error) {
	var out ChildNativeResultCapture
	if len(raw) > 65536 || DecodePhysicalClosed(raw, &out) != nil || out.Validate() != nil {
		return ChildNativeResultCapture{}, errors.New("child native result capture refused")
	}
	return out, nil
}

func (c ChildNativeResultCapture) Validate() error {
	return c.validateWrite("child_native_result", "coding2")
}

func (c ChildNativeResultCapture) validateWrite(purpose, workload string) error {
	bad := errors.New("child native result capture conflict")
	n, e := c.Native, c.Effect
	if c.FormatVersion != 1 || c.Purpose != purpose || c.Workload != workload || e.Tool != "write" ||
		!utf8.ValidString(c.Terminal.Text) || c.Terminal.ByteCount != len(c.Terminal.Text) || c.Terminal.ByteCount < 1 || c.Terminal.ByteCount > 16384 ||
		c.Terminal.Digest != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(c.Terminal.Text))) || c.Artifact.ByteCount < 1 || c.Artifact.ByteCount > 8192 || c.Artifact.Device == 0 || c.Artifact.Inode == 0 || !n.Current.Quiescent(n.InitialExecutionStartedSeq, n.TerminalSeq, n.LogCursor) ||
		n.EnqueueSeq < 1 || n.InitialExecutionStartedSeq <= n.EnqueueSeq || e.CalledSeq <= n.InitialExecutionStartedSeq || e.CompletedSeq <= e.CalledSeq || n.TerminalSeq <= e.CompletedSeq || n.LogCursor < n.TerminalSeq || n.LogCursor > 32768 {
		return bad
	}
	for _, value := range []string{c.GenerationDigest, c.BindingDigest, n.NativeLocationDigest, n.InputDigest, n.PreparedReceiptDigest, n.GrantDigest, e.ArgumentsDigest, e.ResponseDigest, e.ClaimDigest, c.Terminal.Digest, c.Terminal.ResponseDigest, c.Artifact.Digest} {
		if !PhysicalDigestValid(value) {
			return bad
		}
	}
	for _, value := range []string{n.SessionID, n.InputID, n.AssistantMessageID, e.CallID} {
		if !PhysicalIDValid(value) {
			return bad
		}
	}
	if !cellNativeProjectPattern.MatchString(n.NativeProjectID) {
		return bad
	}
	path, _ := json.Marshal(c.Artifact.SourcePath)
	if workflowcontract.Validate(workflowcontract.Domain, "path", path) != nil {
		return bad
	}
	return nil
}

func (c ChildNativeResultCapture) ValidateFor(entry CellServiceV3, generation string, binding json.RawMessage, inputID, inputDigest string) error {
	if c.Validate() != nil {
		return errors.New("child native result capture conflict")
	}
	return c.validateOwningInput(entry, generation, binding, inputID, inputDigest)
}

func (c ChildNativeResultCapture) validateOwningInput(entry CellServiceV3, generation string, binding json.RawMessage, inputID, inputDigest string) error {
	var native struct {
		NativeSessionID      string `json:"nativeSessionId"`
		NativeProjectID      string `json:"nativeProjectId"`
		NativeLocationDigest string `json:"nativeLocationDigest"`
	}
	if entry.ExecutionGrant == nil || entry.PreparedReceiptDigest == nil || c.GenerationDigest != generation || c.BindingDigest != WorkspaceDigest(binding) ||
		json.Unmarshal(binding, &native) != nil || c.Native.SessionID != native.NativeSessionID || c.Native.NativeProjectID != native.NativeProjectID || c.Native.NativeLocationDigest != native.NativeLocationDigest ||
		c.Native.SessionID != entry.NativeSessionID || c.Native.NativeProjectID != entry.NativeProjectID || c.Native.InputID != inputID || c.Native.InputID != entry.ExecutionGrant.InputID || c.Native.InputDigest != inputDigest ||
		c.Native.PreparedReceiptDigest != *entry.PreparedReceiptDigest || c.Native.GrantDigest != WorkspaceDigest(entry.ExecutionGrant) {
		return errors.New("child native result owning input conflict")
	}
	return nil
}

func DecodeChildNativeIntegrationCapture(raw []byte) (ChildNativeIntegrationCapture, error) {
	var out ChildNativeIntegrationCapture
	if len(raw) > 65536 || DecodePhysicalClosed(raw, &out) != nil || out.Validate() != nil {
		return ChildNativeIntegrationCapture{}, errors.New("child native integration capture refused")
	}
	return out, nil
}

func (c ChildNativeIntegrationCapture) Validate() error {
	b := c.Before
	if c.validateWrite("child_native_integration", "integration2") != nil || b.SourcePath != c.Artifact.SourcePath || !PhysicalDigestValid(b.Digest) || b.Digest == c.Artifact.Digest || b.ByteCount < 0 || b.ByteCount > 8192 || b.Device == 0 || b.Inode == 0 {
		return errors.New("child native integration before-image conflict")
	}
	return nil
}

func (c ChildNativeIntegrationCapture) ValidateFor(entry CellServiceV3, generation string, binding json.RawMessage, inputID, inputDigest string) error {
	if c.Validate() != nil {
		return errors.New("child native integration capture conflict")
	}
	return c.validateOwningInput(entry, generation, binding, inputID, inputDigest)
}
