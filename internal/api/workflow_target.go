package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// ReadWorkflowResult preserves the owning result detail and verifies its exact
// assignment/body digest against the caller's assigned target. It grants no read
// credit: source-read receipts still require the separate protected reader.
func (c Client) ReadWorkflowResult(ctx context.Context, target json.RawMessage, lease string) (json.RawMessage, error) {
	bad := errors.New("assigned workflow result refused")
	var pin struct {
		ResultID       string `json:"resultId"`
		ResultRevision int64  `json:"resultRevision"`
		ResultDigest   string `json:"resultDigest"`
	}
	if !validControllerLease(lease) || workflowcontract.Validate(workflowcontract.Domain, "resultPin", target) != nil || json.Unmarshal(target, &pin) != nil {
		return nil, bad
	}
	var raw json.RawMessage
	if err := c.paidDomainClient().requestWithResponseLimit(ctx, http.MethodGet, controllerBridgePath+"results/"+pin.ResultID, c.NodeToken, nil, &raw, true, "", lease, 65536); err != nil {
		return nil, err
	}
	var detail struct {
		Receipt struct {
			ResultID       string `json:"resultId"`
			ResultRevision int64  `json:"resultRevision"`
			ResultDigest   string `json:"resultDigest"`
			ExecutionID    string `json:"executionId"`
			AssignmentID   string `json:"assignmentId"`
		} `json:"receipt"`
		Binding      json.RawMessage `json:"binding"`
		AssignmentID string          `json:"assignmentId"`
		Result       json.RawMessage `json:"result"`
	}
	if workflowcontract.Validate(workflowcontract.Domain, "resultDetail", raw) != nil || json.Unmarshal(raw, &detail) != nil {
		return nil, bad
	}
	var binding struct {
		ExecutionID string `json:"executionId"`
	}
	if json.Unmarshal(detail.Binding, &binding) != nil {
		return nil, bad
	}
	r := detail.Receipt
	if r.ResultID != pin.ResultID || r.ResultRevision != pin.ResultRevision || r.ResultDigest != pin.ResultDigest || r.ExecutionID != binding.ExecutionID || r.AssignmentID != detail.AssignmentID || r.ResultDigest != model.WorkspaceDigest(map[string]any{"binding": detail.Binding, "assignmentId": detail.AssignmentID, "result": detail.Result}) {
		return nil, bad
	}
	return raw, nil
}

// FetchWorkflowArtifact uses the requesting child's independently enrolled role
// and execution. The owning backend checks its assignment against the target
// manifest; Runtime then verifies the complete exact bytes. No path or URL comes
// from the artifact, and this fetch alone is not a native source-read receipt.
func (c Client) FetchWorkflowArtifact(ctx context.Context, execution string, reference json.RawMessage, lease string) ([]byte, error) {
	bad := errors.New("assigned workflow artifact refused")
	var ref struct {
		ArtifactID  string `json:"artifactId"`
		Digest      string `json:"digest"`
		ByteCount   int    `json:"byteCount"`
		ContentType string `json:"contentType"`
	}
	if !validControllerLease(lease) || !managedServiceIDPattern.MatchString(execution) || workflowcontract.Validate(workflowcontract.Domain, "artifactRef", reference) != nil || json.Unmarshal(reference, &ref) != nil || ref.ByteCount > 16384 {
		return nil, bad
	}
	var response controlPlaneBytes
	if err := c.paidDomainClient().requestWithResponseLimit(ctx, http.MethodGet, controllerBridgePath+"executions/"+execution+"/artifacts/"+ref.ArtifactID, c.NodeToken, nil, &response, true, "", lease, 16384); err != nil {
		return nil, err
	}
	raw := response.Bytes
	contentType, _, err := mime.ParseMediaType(response.ContentType)
	if err != nil || response.Status != http.StatusOK || contentType != ref.ContentType || response.ContentDigest != ref.Digest || len(raw) != ref.ByteCount || fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != ref.Digest {
		return nil, bad
	}
	return raw, nil
}
