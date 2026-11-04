package qualification_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Consume the same actual loopback provider response/private files and complete
// native SQLite SOURCE window as the fixed Sandbox capture, not a second proof
// fixture. Native identities remain synthetic; no ROOT signature is asserted.
func testSourceChildResultCapture(t *testing.T, root string, w qualification.ChildProductWitness, current qualification.ChildProductControl) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "coding-result-capture.json"))
	if err != nil {
		t.Fatal("fixed native result capture absent", err)
	}
	if os.Getenv("WARPMETAL_CHILD_ROLE_PRODUCER_BOUNDARY") == "1" {
		var original struct {
			Native struct {
				SessionID            string `json:"sessionId"`
				NativeProjectID      string `json:"nativeProjectId"`
				NativeLocationDigest string `json:"nativeLocationDigest"`
			} `json:"native"`
		}
		if json.Unmarshal(raw, &original) != nil || original.Native.NativeProjectID == "" || original.Native.NativeLocationDigest == "" {
			t.Fatal("completed child capture lacks actual native project/location required by the exact service_source.native role proof")
		}
		var binding map[string]json.RawMessage
		if current.Generation.Policy == nil || json.Unmarshal(current.Generation.Policy.Payload.Binding, &binding) != nil {
			t.Fatal("current signed child binding absent")
		}
		// Backend's child native receipt is four fields, unlike the parent's five.
		// Workspace epoch remains the independent current lifecycle scope; actual
		// native project/location must come from the fixed SQLite capture above.
		native := map[string]any{"nativeSessionId": original.Native.SessionID, "nativeProjectId": original.Native.NativeProjectID, "nativeLocationDigest": original.Native.NativeLocationDigest, "workspaceEpoch": w.Entry.WorkspaceEpoch}
		pinned := map[string]json.RawMessage{}
		for _, k := range []string{"nativeSessionId", "nativeProjectId", "nativeLocationDigest", "workspaceEpoch"} {
			pinned[k] = binding[k]
		}
		if model.WorkspaceDigest(native) != model.WorkspaceDigest(pinned) {
			t.Fatal("actual native capture disagrees with current child service tuple")
		}
	}
	capture, err := model.DecodeChildNativeResultCapture(raw)
	if err != nil || current.Generation.Policy == nil {
		t.Fatal("typed native result capture refused", err)
	}
	q := current.Generation.Policy.Payload
	if q.Purpose != "coding_worker" || capture.ValidateFor(w.Entry, current.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest) != nil {
		t.Fatal("native result capture lost signed owning execution")
	}
	actual, err := os.ReadFile(filepath.Join(root, "work", capture.Artifact.SourcePath))
	if err != nil || len(actual) != capture.Artifact.ByteCount || qualification.Digest(actual) != capture.Artifact.Digest {
		t.Fatal("native result differs from whole own artifact bytes", err)
	}
	foreign := capture
	foreign.Native.SessionID = "ses_foreign_source"
	if foreign.ValidateFor(w.Entry, current.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest) == nil {
		t.Fatal("foreign native result adopted")
	}
	t.Log("same fresh signed child, two real loopback responses, completed native SOURCE SQLite write/terminal and exact own artifact joined; ROOT signature/native executable credit0")
}

// Extends the existing signed Store -> local TLS/HTTP -> original native file /
// SQLite journey. The backend operation supplier is explicitly SOURCE; it is
// not an enrollment proof or a substitute for current protected child capture.
func testSourceChildIntegrationCapture(t *testing.T, root string, w qualification.ChildProductWitness, current qualification.ChildProductControl, store qualification.Store) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "integration-result-capture.json"))
	if err != nil {
		t.Fatal("fixed integration capture absent", err)
	}
	capture, err := model.DecodeChildNativeIntegrationCapture(raw)
	if err != nil || current.Generation.Policy == nil {
		t.Fatal("typed integration capture refused", err)
	}
	q := current.Generation.Policy.Payload
	if q.Purpose != "integrator" || q.Workload.Kind != "integration2" || capture.ValidateFor(w.Entry, current.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest) != nil {
		t.Fatal("integration capture lost signed owning execution")
	}
	if _, err := model.DecodeChildNativeResultCapture(raw); err == nil {
		t.Fatal("integration was accepted as coding result")
	}
	key := model.WorkspaceDigest(map[string]string{"sessionId": capture.Native.SessionID, "inputId": capture.Native.InputID})
	before, err := os.ReadFile(filepath.Join(root, "ledger", "native-before-"+key[7:]+".body"))
	if err != nil || len(before) != capture.Before.ByteCount || qualification.Digest(before) != capture.Before.Digest {
		t.Fatal("integration original before bytes absent", err)
	}
	after, err := os.ReadFile(filepath.Join(root, "work", capture.Artifact.SourcePath))
	if err != nil || len(after) != capture.Artifact.ByteCount || qualification.Digest(after) != capture.Artifact.Digest || capture.Before.Digest == capture.Artifact.Digest {
		t.Fatal("integration actual after file drift", err)
	}
	artifactWitness := qualification.ChildWorkflowObservationWitness{Authority: store, Sandbox: model.Sandbox{ID: w.Entry.SandboxID, Generation: w.Entry.SandboxGeneration, Cell: true}, Product: w}
	if !qualification.SourceChildIntegrationArtifactAllowedForTest(artifactWitness, q, raw, capture.Artifact.SourcePath, capture.Artifact.Digest, int64(capture.Artifact.ByteCount)) {
		t.Fatal("owning artifact scope refuses the current signed integration capture; normal artifact signing is not reached")
	}
	if os.Getenv("WARPMETAL_CHILD_FACTS_BOUNDARY") == "1" {
		testSourceChildFactsTransport(t, root, w, current, capture)
	}
	if os.Getenv("WARPMETAL_CHILD_FINANCIAL_BOUNDARY") == "1" {
		qualification.SourceChildFinancialCompletionForTest(t, root, w, current, capture)
	}
	t.Log("distinct signed integration2, first original/before snapshot/completed native SOURCE write/final original/after artifact joined; no acceptance or ROOT signature")
}

func testSourceChildWorkflowRoleEnrollment(t *testing.T, w qualification.ChildProductWitness, current qualification.ChildProductControl) {
	t.Helper()
	if current.Generation.Policy == nil || current.Generation.Policy.Payload.Purpose != "coding_worker" || current.Generation.Activation == nil {
		t.Fatal("child role must follow the existing signed coding execution")
	}
	var scope struct {
		Owner model.ControllerOwner `json:"owner"`
	}
	var binding struct {
		WorkID                string `json:"workId"`
		ExecutionID           string `json:"executionId"`
		ServiceRegistrationID string `json:"serviceRegistrationId"`
		ServiceGeneration     int64  `json:"serviceGeneration"`
		NativeSessionID       string `json:"nativeSessionId"`
		NativeProjectID       string `json:"nativeProjectId"`
		NativeLocationDigest  string `json:"nativeLocationDigest"`
	}
	q := current.Generation.Policy.Payload
	if json.Unmarshal(q.Scope, &scope) != nil || json.Unmarshal(q.Binding, &binding) != nil || binding.WorkID == "" || binding.ExecutionID == "" || binding.NativeSessionID != w.Entry.NativeSessionID || w.Grant == nil || w.Grant.SessionID != binding.NativeSessionID {
		t.Fatal("signed child operation source lost its owning execution")
	}
	o := scope.Owner
	subject := model.WorkflowRoleSubject{AccountID: o.AccountID, TaskID: o.TaskID, ServerID: o.ServerID, SandboxID: o.SandboxID, SandboxGeneration: o.SandboxGeneration, CellID: o.CellID, Role: "worker", ControllerID: o.ControllerID, ControllerRevision: o.ControllerRevision, AuthorityRevision: o.AuthorityRevision, ServiceRegistrationID: binding.ServiceRegistrationID, ServiceGeneration: binding.ServiceGeneration, NativeSessionID: binding.NativeSessionID, WorkID: &binding.WorkID, ExecutionID: &binding.ExecutionID}
	call := model.WorkflowRoleOperationRequest{FormatVersion: 1, RequestID: "source_worker_enrollment_operation", Subject: subject}
	raw, err := json.Marshal(call)
	if err != nil || workflowcontract.Validate(workflowcontract.Producer, "enrollmentOperationRequest", raw) != nil {
		t.Fatal("current canonical execution-scoped enrollment request refused", err)
	}
	// Independent SOURCE service receipt/native context identities are declared
	// here, not borrowed as a producer witness or accepted enrollment receipt.
	op := model.WorkflowRoleOperation{FormatVersion: 1, OperationID: "wfroleop_source_child", Subject: subject, NativeContextDigest: model.WorkspaceDigest(map[string]any{"nativeSessionId": binding.NativeSessionID, "nativeProjectId": binding.NativeProjectID, "nativeLocationDigest": binding.NativeLocationDigest}), ManagedServiceReceiptDigest: model.WorkspaceDigest(map[string]any{"sourceService": binding.ServiceRegistrationID}), NodeTokenHash: w.Root.Producer.NodeTokenHash, ExpiresAt: time.Now().Add(90 * time.Second).UTC().Format(time.RFC3339Nano)}
	encoded, _ := json.Marshal(op)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &fields)
	delete(fields, "operationDigest")
	op.OperationDigest = model.WorkspaceDigest(fields)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		requests++
		var submitted model.WorkflowRoleOperationRequest
		if r.Method != http.MethodPost || r.URL.Path != "/internal/runtime/workspace-workflow/enrollment-operations" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer synthetic-node" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "" || r.Header.Get("Idempotency-Key") != call.RequestID || json.NewDecoder(r.Body).Decode(&submitted) != nil || model.WorkspaceDigest(submitted) != model.WorkspaceDigest(call) {
			t.Error("execution-scoped enrollment changed subject, operation, or node-only transport")
			rw.WriteHeader(http.StatusForbidden)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(op)
	}))
	defer server.Close()
	client := api.Client{Origin: server.URL, NodeToken: "synthetic-node", HTTP: server.Client()}
	received, err := client.WorkflowRoleEnrollmentOperation(context.Background(), call)
	if err != nil {
		t.Fatalf("signed child execution cannot obtain its canonical worker enrollment operation: %v (local TLS requests=%d)", err, requests)
	}
	if requests != 1 || model.WorkspaceDigest(received) != model.WorkspaceDigest(op) {
		t.Fatal("worker enrollment operation did not retain exact backend original")
	}
	// Role shape must remain disjoint: children require both own IDs; parents
	// cannot borrow them. The signed current child is tested above, not relabeled.
	for _, change := range []func(*model.WorkflowRoleSubject){
		func(s *model.WorkflowRoleSubject) { s.WorkID = nil },
		func(s *model.WorkflowRoleSubject) { s.ExecutionID = nil },
		func(s *model.WorkflowRoleSubject) { s.Role = "manager" },
	} {
		bad := op
		change(&bad.Subject)
		encoded, _ := json.Marshal(bad)
		_ = json.Unmarshal(encoded, &fields)
		delete(fields, "operationDigest")
		bad.OperationDigest = model.WorkspaceDigest(fields)
		if bad.Validate() == nil {
			t.Fatal("child scope was omitted or borrowed by a parent role")
		}
	}
	t.Log("canonical child role operation retained through one real local TLS POST; protected enrollment/capture still required")
}
