package reconcile

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// Extend the normal first-task TLS/SQLite/STATE journey. Native completion and
// this test-only signer are explicit SOURCE suppliers, not protected host proof.
func TestOwnerFirstTaskCompletedChildEnrollsThroughNormalReconcile(t *testing.T) {
	if os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET") == "" || os.Getenv("WARPMETAL_CONTROLLER_OUTPUT_SOURCE_FIXTURE") == "" {
		t.Skip("requires existing documented SOURCE journey originals")
	}
	t.Setenv("WARPMETAL_CHILD_COMPLETION_SOURCE", "1")
	runControllerParentSourceJourney(t, false, false, true, false, true, false, true, false, false)
}

func TestOwnerFirstTaskCompletedChildSettlesThroughNormalReconcile(t *testing.T) {
	if os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET") == "" || os.Getenv("WARPMETAL_CONTROLLER_OUTPUT_SOURCE_FIXTURE") == "" {
		t.Skip("requires existing documented SOURCE journey originals")
	}
	t.Setenv("WARPMETAL_CHILD_COMPLETION_SOURCE", "1")
	t.Setenv("WARPMETAL_CHILD_SETTLEMENT_SOURCE", "1")
	runControllerParentSourceJourney(t, false, false, true, false, true, false, true, false, false)
}

func TestOwnerFirstTaskChildSettlementLostAcknowledgementSurvivesChangedSnapshot(t *testing.T) {
	if os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET") == "" || os.Getenv("WARPMETAL_CONTROLLER_OUTPUT_SOURCE_FIXTURE") == "" {
		t.Skip("requires existing documented SOURCE journey originals")
	}
	t.Setenv("WARPMETAL_CHILD_COMPLETION_SOURCE", "1")
	t.Setenv("WARPMETAL_CHILD_SETTLEMENT_SOURCE", "1")
	t.Setenv("WARPMETAL_CHILD_SETTLEMENT_LOST_ACK_SOURCE", "1")
	runControllerParentSourceJourney(t, false, false, true, false, true, false, true, false, false)
}

func TestOwnerFirstTaskCompletedChildUploadsDocumentThroughNormalReconcile(t *testing.T) {
	if os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET") == "" || os.Getenv("WARPMETAL_CONTROLLER_OUTPUT_SOURCE_FIXTURE") == "" {
		t.Skip("requires existing documented SOURCE journey originals")
	}
	t.Setenv("WARPMETAL_CHILD_COMPLETION_SOURCE", "1")
	t.Setenv("WARPMETAL_CHILD_SETTLEMENT_SOURCE", "1")
	t.Setenv("WARPMETAL_CHILD_ARTIFACT_SOURCE", "1")
	runControllerParentSourceJourney(t, false, false, true, false, true, false, true, false, false)
}

func TestOwnerFirstTaskChildArtifactLostAcknowledgementSurvivesChangedSnapshot(t *testing.T) {
	if os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET") == "" || os.Getenv("WARPMETAL_CONTROLLER_OUTPUT_SOURCE_FIXTURE") == "" {
		t.Skip("requires existing documented SOURCE journey originals")
	}
	t.Setenv("WARPMETAL_CHILD_COMPLETION_SOURCE", "1")
	t.Setenv("WARPMETAL_CHILD_SETTLEMENT_SOURCE", "1")
	t.Setenv("WARPMETAL_CHILD_ARTIFACT_SOURCE", "1")
	t.Setenv("WARPMETAL_CHILD_ARTIFACT_LOST_ACK_SOURCE", "1")
	runControllerParentSourceJourney(t, false, false, true, false, true, false, true, false, false)
}

func TestOwnerFirstTaskCompletedChildReportsDocumentThroughNormalReconcile(t *testing.T) {
	if os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET") == "" || os.Getenv("WARPMETAL_CONTROLLER_OUTPUT_SOURCE_FIXTURE") == "" {
		t.Skip("requires existing documented SOURCE journey originals")
	}
	t.Setenv("WARPMETAL_CHILD_COMPLETION_SOURCE", "1")
	t.Setenv("WARPMETAL_CHILD_SETTLEMENT_SOURCE", "1")
	t.Setenv("WARPMETAL_CHILD_ARTIFACT_SOURCE", "1")
	t.Setenv("WARPMETAL_CHILD_RESULT_SOURCE", "1")
	runControllerParentSourceJourney(t, false, false, true, false, true, false, true, false, false)
}

func TestOwnerFirstTaskAcceptedResultSurvivesFactExpiry(t *testing.T) {
	t.Setenv("WARPMETAL_COMPLETED_FACT_EXPIRY_SOURCE", "1")
	TestOwnerFirstTaskCompletedChildReportsDocumentThroughNormalReconcile(t)
}

func TestOwnerFirstTaskChildResultLostAcknowledgementSurvivesChangedSnapshot(t *testing.T) {
	t.Setenv("WARPMETAL_CHILD_RESULT_LOST_ACK_SOURCE", "1")
	TestOwnerFirstTaskCompletedChildReportsDocumentThroughNormalReconcile(t)
}

type childCompletionSource struct {
	f                               *firstTaskChildTerminalFixture
	runtime                         *childCompletionSourceRuntime
	op                              model.WorkflowRoleOperation
	operations, proofs, enrollments int
	facts                           *childCompletionFactsSource
	artifact                        *childCompletionArtifactSource
	results                         int
	result                          *childCompletionResultSource
	later                           *laterControllerStageSource
}
type childCompletionSourceRuntime struct {
	*firstTaskChildTerminalRuntime
	source *childCompletionSource
}

func startChildCompletionSource(t *testing.T, f *firstTaskChildTerminalFixture) *childCompletionSource {
	t.Helper()
	// The predecessor fixture supplies only launch metadata. This additional
	// SOURCE availability flag exercises the completion owner; the protected
	// Podman signer/root measurement is deliberately not represented by it.
	project, err := f.r.Store.ManagedProject(context.Background(), f.entry.Workspace.SelectionID)
	if err != nil || project == nil {
		t.Fatal("SOURCE registered child metadata", err)
	}
	project.Report.Availability = "available"
	if err = f.r.Store.PutManagedProject(context.Background(), *project); err != nil {
		t.Fatal(err)
	}
	s := &childCompletionSource{f: f}
	s.runtime = &childCompletionSourceRuntime{firstTaskChildTerminalRuntime: f.r.ManagedRuntime.(*firstTaskChildTerminalRuntime), source: s}
	f.r.ManagedRuntime = s.runtime
	if os.Getenv("WARPMETAL_CHILD_SETTLEMENT_SOURCE") == "1" {
		s.facts = &childCompletionFactsSource{source: s}
		f.r.ManagedRuntime = &childCompletionFactsRuntime{childCompletionSourceRuntime: s.runtime, facts: s.facts}
		if os.Getenv("WARPMETAL_CHILD_ARTIFACT_SOURCE") == "1" {
			s.artifact = newChildCompletionArtifactSource(t, s)
			f.r.ManagedRuntime = &childCompletionArtifactRuntime{childCompletionFactsRuntime: f.r.ManagedRuntime.(*childCompletionFactsRuntime), artifact: s.artifact}
			if os.Getenv("WARPMETAL_CHILD_RESULT_SOURCE") == "1" {
				s.result = &childCompletionResultSource{source: s}
				f.r.ManagedRuntime = &childCompletionResultRuntime{childCompletionArtifactRuntime: f.r.ManagedRuntime.(*childCompletionArtifactRuntime), result: s.result}
			}
		}
	}
	return s
}

func (s *childCompletionSource) serve(w http.ResponseWriter, req *http.Request) bool {
	if s.later != nil && s.later.serve(w, req) {
		return true
	}
	if s.result != nil && s.result.serve(w, req) {
		return true
	}
	if s.artifact != nil && s.artifact.serve(w, req) {
		return true
	}
	if s.facts != nil && s.facts.serve(w, req) {
		return true
	}
	f := s.f
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch req.URL.Path {
	case "/internal/runtime/workspace-workflow/enrollment-operations":
		var call model.WorkflowRoleOperationRequest
		if req.Method != "POST" || json.NewDecoder(req.Body).Decode(&call) != nil || call.Subject.Role != "worker" || call.Subject.ExecutionID == nil || *call.Subject.ExecutionID != "source_child_execution" || call.Subject.WorkID == nil || *call.Subject.WorkID != "source_child_work" || call.Subject.ServiceRegistrationID != f.entry.ServiceRegistrationID || req.Header.Get("Idempotency-Key") != call.RequestID || req.Header.Get("X-WarpMetal-Workflow-Lease") != "" {
			f.t.Fatal("normal child role operation borrowed parent/foreign authority")
		}
		s.operations++
		s.op = model.WorkflowRoleOperation{FormatVersion: 1, OperationID: "wfroleop_source_completed_child", Subject: call.Subject, NativeContextDigest: model.WorkspaceDigest("source_current_native"), ManagedServiceReceiptDigest: model.WorkspaceDigest("source_current_receipt"), ExpiresAt: f.r.now().Add(4 * time.Minute).Format(time.RFC3339Nano)}
		// The accepted application owns the registered node/producer identity.
		app, err := f.r.Store.WorkspaceApplication(req.Context(), s.runtime.parents[0].ApplicationOperationID)
		if err != nil || app == nil {
			f.t.Fatal(err)
		}
		s.op.NodeTokenHash = app.Operation.Producer.NodeTokenHash
		s.op.OperationDigest = fixtureDigestField(s.op, "operationDigest")
		write(s.op)
	case "/internal/runtime/workspace-workflow/enroll":
		var proof model.WorkflowRoleEnvelope
		if req.Method != "POST" || json.NewDecoder(req.Body).Decode(&proof) != nil || proof.Validate() != nil || !reflect.DeepEqual(proof.Payload.Subject, s.op.Subject) || proof.Payload.OperationDigest != s.op.OperationDigest || req.Header.Get("Idempotency-Key") != proof.Payload.RequestID {
			f.t.Fatal("normal child role proof not owning original")
		}
		raw, _ := model.WorkspaceCanonicalJSON(proof.Payload)
		sum := sha256.Sum256(raw)
		sig, _ := base64.StdEncoding.DecodeString(proof.Signature)
		if !ecdsa.VerifyASN1(&s.runtime.key.PublicKey, sum[:], sig) {
			f.t.Fatal("SOURCE child role signature")
		}
		s.enrollments++
		write(model.WorkflowRoleEnrollment{FormatVersion: 1, RoleBindingID: "wrole_source_completed_child", RoleBindingRevision: 1, ExpiresAt: s.op.ExpiresAt, Lease: "wfl_source_completed_child"})
	default:
		return false
	}
	return true
}

func (s *childCompletionSourceRuntime) AttestCellWorkflowRole(ctx context.Context, op model.WorkflowRoleOperation, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject, snapshot json.RawMessage) (model.WorkflowRoleEnvelope, error) {
	f := s.source.f
	local, err := f.r.Store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || local == nil || local.Phase != "terminal" || f.backendDigest == nil || *f.backendDigest != local.Report.ReceiptDigest || !reflect.DeepEqual(entry, f.entry) || box.ID != entry.SandboxID || len(input) == 0 || len(snapshot) == 0 || root.Report.SelectionID != entry.Workspace.SelectionID {
		f.t.Fatal("SOURCE attester preceded current owning terminal/root", err)
	}
	s.source.proofs++
	var binding struct {
		NativeLocationDigest string `json:"nativeLocationDigest"`
	}
	_ = json.Unmarshal(f.actual.Binding, &binding)
	stamp := f.r.now().Format(time.RFC3339Nano)
	p := model.WorkflowRolePayload{FormatVersion: 1, Purpose: "workspace_workflow_role", RequestID: "wfrole_receipt_" + op.OperationDigest[7:39], TaskID: op.Subject.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: op.ManagedServiceReceiptDigest, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Subject: op.Subject, NativeContextDigest: op.NativeContextDigest, NativeReceipt: model.WorkflowRoleNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: entry.ServiceRegistrationID, ServiceGeneration: entry.ServiceGeneration, NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID, NativeLocationDigest: binding.NativeLocationDigest, Role: entry.Role, RootAttestation: entry.Workspace.RootAttestation, ObservedAt: stamp, Readback: model.WorkflowRoleReadback{Subject: op.Subject, NativeContextDigest: op.NativeContextDigest}}}
	app, err := f.r.Store.WorkspaceApplication(ctx, s.parents[0].ApplicationOperationID)
	if err != nil || app == nil {
		f.t.Fatal(err)
	}
	raw, _ := model.WorkspaceCanonicalJSON(p)
	sum := sha256.Sum256(raw)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, sum[:])
	return model.WorkflowRoleEnvelope{Payload: p, KeyID: app.Operation.Producer.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}, err
}

func (s *childCompletionSource) assertEnrolled(t *testing.T) {
	t.Helper()
	if s.operations != 1 || s.proofs != 1 || s.enrollments != 1 {
		t.Fatalf("normal completed child did not enroll exactly once: operations=%d proofs=%d enrollments=%d", s.operations, s.proofs, s.enrollments)
	}
	if s.facts != nil {
		s.facts.assertSettled(t)
	}
	if s.artifact != nil {
		s.artifact.assertUploaded(t)
	}
	if os.Getenv("WARPMETAL_CHILD_RESULT_SOURCE") == "1" && s.results != 1 {
		t.Fatalf("normal worker result absent/reissued: results=%d", s.results)
	}
}
