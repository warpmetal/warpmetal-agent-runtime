package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// SOURCE transport extension of the existing runtime-route journey. The server
// supplies explicit contract fixtures, not real role enrollment or acceptance.
func TestWorkflowCompletionRoleTransportJourney(t *testing.T) {
	encode := func(v any) json.RawMessage {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	binding := map[string]any{"workId": "work_source", "workRevision": 1, "bindingId": "binding_source", "bindingRevision": 1, "executionId": "exec_worker", "preparationId": "prep_worker", "parentExecutionId": nil, "parentPacketId": nil, "packetId": "packet_source", "packetRevision": 1, "attempt": 1, "fence": strings.Repeat("b", 64), "serviceRegistrationId": "service_source", "serviceGeneration": 1, "sandboxGeneration": 1, "nativeSessionId": "ses_source", "nativeProjectId": "global", "nativeLocationDigest": digest, "projectId": "project_source", "workspaceEpoch": "epoch_source", "selectionId": "selection_source", "scopeRevision": 1, "rootAttestation": digest, "instructionRevision": 1, "instructionDigest": digest, "profileDigest": digest, "configDigest": digest}
	result := map[string]any{"outcome": "failed", "consumedRefs": []any{}, "mismatches": []any{}, "stateEvidence": []any{}, "outputs": []any{}, "effectReceipts": []any{}, "remainingWork": []any{"SOURCE failure evidence"}}
	resultBody := encode(map[string]any{"formatVersion": 1, "requestId": "request_result", "binding": binding, "assignmentId": "assignment_worker", "result": result})
	resultDigest := model.WorkspaceDigest(map[string]any{"binding": binding, "assignmentId": "assignment_worker", "result": result})
	resultReceipt := encode(map[string]any{"formatVersion": 1, "resultId": "result_source", "resultRevision": 1, "resultDigest": resultDigest, "executionId": "exec_worker", "assignmentId": "assignment_worker", "state": "reported", "createdAt": "2026-11-02T00:00:00Z"})
	reviewerBinding := map[string]any{}
	for k, v := range binding {
		reviewerBinding[k] = v
	}
	reviewerBinding["executionId"] = "exec_reviewer"
	target := map[string]any{"resultId": "result_source", "resultRevision": 1, "resultDigest": resultDigest}
	integration := map[string]any{"receiptId": "integration_source", "receiptDigest": digest}
	artifact := map[string]any{"artifactId": "artifact_source", "digest": digest, "byteCount": 1, "contentType": "text/plain"}
	review := map[string]any{"formatVersion": 1, "requestId": "request_review", "binding": reviewerBinding, "assignmentId": "assignment_reviewer", "target": target, "integration": integration, "reviewedArtifacts": []any{artifact}, "consumedRefs": []any{}, "disposition": "changes_required", "findings": []any{}, "evidence": []any{artifact}}
	reviewBody := encode(review)
	reviewIdentity := map[string]any{}
	for k, v := range review {
		if k != "requestId" {
			reviewIdentity[k] = v
		}
	}
	reviewReceipt := map[string]any{"formatVersion": 1, "reviewId": "review_source", "reviewDigest": model.WorkspaceDigest(reviewIdentity), "target": target, "integration": integration, "reviewerExecutionId": "exec_reviewer", "disposition": "changes_required", "createdAt": "2026-11-02T00:00:00Z"}
	for name, raw := range map[string]json.RawMessage{"resultRequest": resultBody, "resultReceipt": resultReceipt, "reviewRequest": reviewBody, "reviewReceipt": encode(reviewReceipt)} {
		if err := workflowcontract.Validate(workflowcontract.Domain, name, raw); err != nil {
			t.Fatalf("SOURCE %s: %v", name, err)
		}
	}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		wantPath, wantBody, wantLease, wantKey := controllerBridgePath+"executions/exec_worker/results", resultBody, "wfl_source_worker", "request_result"
		if calls > 2 {
			wantPath, wantBody, wantLease, wantKey = controllerBridgePath+"results/result_source/reviews", reviewBody, "wfl_source_reviewer", "request_review"
		}
		raw, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || r.URL.Path != wantPath || r.Header.Get("Authorization") != "Bearer rtn_source" || r.Header.Get("X-WarpMetal-Workflow-Lease") != wantLease || r.Header.Get("Idempotency-Key") != wantKey || model.WorkspaceDigest(json.RawMessage(raw)) != model.WorkspaceDigest(wantBody) {
			t.Errorf("completion route/auth/original mismatch")
		}
		w.Header().Set("Content-Type", "application/json")
		if calls <= 2 {
			_, _ = w.Write(resultReceipt)
			return
		}
		if calls == 4 {
			wrong := map[string]any{}
			for k, v := range reviewReceipt {
				wrong[k] = v
			}
			wrong["reviewerExecutionId"] = "exec_worker"
			_, _ = w.Write(encode(wrong))
			return
		}
		_, _ = w.Write(encode(reviewReceipt))
	}))
	defer server.Close()
	client := Client{Origin: server.URL, NodeToken: "rtn_source", HTTP: server.Client()}
	transport, ok := any(client).(interface {
		ReportWorkflowResult(context.Context, json.RawMessage, string) (json.RawMessage, error)
		ReportWorkflowReview(context.Context, json.RawMessage, string) (json.RawMessage, error)
	})
	if !ok {
		t.Fatal("normal Runtime client has no worker-result/reviewer-review completion transport")
	}
	for i := 0; i < 2; i++ {
		got, err := transport.ReportWorkflowResult(context.Background(), resultBody, "wfl_source_worker")
		if err != nil || model.WorkspaceDigest(got) != model.WorkspaceDigest(resultReceipt) {
			t.Fatalf("result original/replay: %v", err)
		}
	}
	got, err := transport.ReportWorkflowReview(context.Background(), reviewBody, "wfl_source_reviewer")
	if err != nil || model.WorkspaceDigest(got) != model.WorkspaceDigest(reviewReceipt) {
		t.Fatalf("review original: %v", err)
	}
	if _, err = transport.ReportWorkflowReview(context.Background(), reviewBody, "wfl_source_reviewer"); err == nil {
		t.Fatal("foreign execution receipt accepted")
	}
	if calls != 4 {
		t.Fatalf("unexpected dispatch/retry count %d", calls)
	}
	if _, err = transport.ReportWorkflowResult(context.Background(), resultBody, "wfl_source\nforeign"); err == nil || calls != 4 {
		t.Fatal("invalid role lease dispatched")
	}
	testWorkflowTargetReadTransport(t, binding, result, resultReceipt, target)
}

// The existing completion journey follows the separately enrolled integrator's
// actual result/artifact HTTP routes. Fixtures are explicit SOURCE data.
func testWorkflowTargetReadTransport(t *testing.T, binding, result map[string]any, receipt json.RawMessage, target map[string]any) {
	t.Helper()
	encode := func(v any) json.RawMessage {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	original := []byte("SOURCE target artifact\n")
	artifact := encode(map[string]any{"artifactId": "artifact_target", "digest": fmt.Sprintf("sha256:%x", sha256.Sum256(original)), "byteCount": len(original), "contentType": "text/plain"})
	detail := encode(map[string]any{"formatVersion": 1, "receipt": receipt, "binding": binding, "assignmentId": "assignment_worker", "result": result, "latestDecision": nil})
	calls := 0
	corrupt := false
	metadata := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer rtn_source" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "wfl_source_integrator" || r.URL.RawQuery != "" {
			t.Error("target read route/auth conflict")
		}
		switch r.URL.Path {
		case controllerBridgePath + "results/result_source":
			w.Header().Set("Content-Type", "application/json")
			if corrupt {
				var v map[string]any
				_ = json.Unmarshal(detail, &v)
				v["assignmentId"] = "assignment_foreign"
				_, _ = w.Write(encode(v))
				return
			}
			_, _ = w.Write(detail)
		case controllerBridgePath + "executions/exec_integrator/artifacts/artifact_target":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Content-Digest", fmt.Sprintf("sha256:%x", sha256.Sum256(original)))
			if metadata == "digest" {
				w.Header().Set("X-Content-Digest", "sha256:"+strings.Repeat("0", 64))
			}
			if metadata == "type" {
				w.Header().Set("Content-Type", "application/json")
			}
			if corrupt {
				_, _ = w.Write([]byte("foreign"))
				return
			}
			_, _ = w.Write(original)
		default:
			t.Error("unexpected target read path")
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := Client{Origin: server.URL, NodeToken: "rtn_source", HTTP: server.Client()}
	transport, ok := any(client).(interface {
		ReadWorkflowResult(context.Context, json.RawMessage, string) (json.RawMessage, error)
		FetchWorkflowArtifact(context.Context, string, json.RawMessage, string) ([]byte, error)
	})
	if !ok {
		t.Fatal("normal Runtime client has no assigned target result/artifact read transport")
	}
	got, err := transport.ReadWorkflowResult(context.Background(), encode(target), "wfl_source_integrator")
	if err != nil || model.WorkspaceDigest(got) != model.WorkspaceDigest(detail) {
		t.Fatalf("target original: %v", err)
	}
	bytes, err := transport.FetchWorkflowArtifact(context.Background(), "exec_integrator", artifact, "wfl_source_integrator")
	if err != nil || string(bytes) != string(original) {
		t.Fatalf("target bytes: %v", err)
	}
	corrupt = true
	if _, err = transport.ReadWorkflowResult(context.Background(), encode(target), "wfl_source_integrator"); err == nil {
		t.Fatal("foreign target body accepted")
	}
	if _, err = transport.FetchWorkflowArtifact(context.Background(), "exec_integrator", artifact, "wfl_source_integrator"); err == nil {
		t.Fatal("foreign artifact bytes accepted")
	}
	corrupt = false
	for _, mode := range []string{"digest", "type"} {
		metadata = mode
		if _, err = transport.FetchWorkflowArtifact(context.Background(), "exec_integrator", artifact, "wfl_source_integrator"); err == nil {
			t.Fatalf("mismatched artifact %s metadata accepted", mode)
		}
	}
	if calls != 6 {
		t.Fatalf("target retries: %d", calls)
	}
	if _, err = transport.FetchWorkflowArtifact(context.Background(), "../foreign", artifact, "wfl_source_integrator"); err == nil || calls != 6 {
		t.Fatal("invalid target path dispatched")
	}
}
