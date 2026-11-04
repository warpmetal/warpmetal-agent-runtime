package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type WorkflowArtifactReceipt = model.WorkflowArtifactReceipt

// Upload only whole protected own-Work bytes after a DISTINCT actual artifact
// ROOT read. No source/reviewer/author-read credit, caller pathname, model effect,
// generic executor, content rewrite, larger artifact-wire exception or retry.
func (c Client) UploadWorkflowArtifact(ctx context.Context, envelope model.WorkflowObservationEnvelope, read model.WorkflowObservationReceipt, content []byte, purpose, contentType string) (WorkflowArtifactReceipt, error) {
	var empty WorkflowArtifactReceipt
	bad := errors.New("own artifact read/upload refused")
	if envelope.Validate() != nil || len(content) > 16384 || envelope.Payload.NodeTokenHash != fmt.Sprintf("%x", sha256.Sum256([]byte(c.NodeToken))) || (purpose != "tool_output" && purpose != "review_evidence" && purpose != "document" && purpose != "analysis") {
		return empty, bad
	}
	expiry, err := time.Parse(time.RFC3339Nano, envelope.Payload.NotAfter)
	if err != nil || !time.Now().Before(expiry) || (purpose == "review_evidence" && envelope.Payload.NativeReceipt.Role != "reviewer") || ((purpose == "document" || purpose == "analysis") && envelope.Payload.NativeReceipt.Role != "worker") {
		return empty, bad
	}
	var request struct {
		Binding     json.RawMessage `json:"binding"`
		Observation struct {
			Type       string `json:"type"`
			SourcePath string `json:"sourcePath"`
			Digest     string `json:"digest"`
			ByteCount  int    `json:"byteCount"`
		} `json:"observation"`
	}
	if json.Unmarshal(envelope.Payload.Request, &request) != nil {
		return empty, bad
	}
	var binding struct {
		ExecutionID string `json:"executionId"`
	}
	_ = json.Unmarshal(request.Binding, &binding)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(content))
	if request.Observation.Type != "artifact_read" || request.Observation.Digest != digest || request.Observation.ByteCount != len(content) || read.ExecutionID != binding.ExecutionID || read.Status != "settled" || read.Type != "artifact_read" || !managedServiceIDPattern.MatchString(binding.ExecutionID) {
		return empty, bad
	}
	readRaw, _ := json.Marshal(read)
	if workflowcontract.Validate(workflowcontract.Domain, "observationReceipt", readRaw) != nil {
		return empty, bad
	}
	ref := map[string]string{"receiptId": read.ReceiptID, "receiptDigest": read.ReceiptDigest}
	refRaw, _ := json.Marshal(ref)
	id := "wfartifact_" + model.WorkspaceDigest(ref)[7:39]
	call := map[string]any{"formatVersion": 1, "requestId": id, "binding": request.Binding, "sourcePath": request.Observation.SourcePath, "purpose": purpose, "contentType": contentType, "byteCount": len(content), "digest": digest, "content": base64.StdEncoding.EncodeToString(content), "nativeReadReceipt": ref}
	raw, err := json.Marshal(call)
	if err != nil || len(raw) > 65536 || workflowcontract.Validate(workflowcontract.Domain, "artifactRequest", raw) != nil {
		return empty, bad
	}
	var response json.RawMessage
	if err = c.planSourceClient().requestWithResponseLimit(ctx, http.MethodPost, workflowObservationPath+"/executions/"+binding.ExecutionID+"/artifacts", c.NodeToken, call, &response, true, id, "", 65536); err != nil {
		return empty, err
	}
	var receipt WorkflowArtifactReceipt
	if workflowcontract.Validate(workflowcontract.Domain, "artifactReceipt", response) != nil || json.Unmarshal(response, &receipt) != nil || receipt.ExecutionID != binding.ExecutionID || receipt.SourcePath != request.Observation.SourcePath || receipt.Purpose != purpose || receipt.Digest != digest || receipt.ByteCount != len(content) || receipt.ContentType != contentType || model.WorkspaceDigest(receipt.NativeReadReceipt) != model.WorkspaceDigest(json.RawMessage(refRaw)) {
		return empty, errors.New("artifact upload receipt conflict")
	}
	return receipt, nil
}
