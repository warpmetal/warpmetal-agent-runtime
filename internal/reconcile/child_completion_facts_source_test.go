package reconcile

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// SOURCE signer only: this normal-caller journey tests invocation, exact wire,
// signature preservation and durable replay. It does not certify native
// quiescence, provider settlement, ROOT custody or the protected Podman signer.
type childCompletionFactsSource struct {
	source                      *childCompletionSource
	op                          model.WorkflowFactsOperation
	operations, proofs, reports int
}
type childCompletionFactsRuntime struct {
	*childCompletionSourceRuntime
	facts *childCompletionFactsSource
}

func (s *childCompletionFactsSource) serve(w http.ResponseWriter, req *http.Request) bool {
	f := s.source.f
	if req.URL.Path != "/internal/runtime/workspace-workflow-observations/operations" && req.URL.Path != "/internal/runtime/workspace-workflow-observations/facts" {
		return false
	}
	if req.Method != "POST" || req.Header.Get("X-WarpMetal-Workflow-Lease") != "" {
		f.t.Fatal("facts borrowed role authority")
	}
	w.Header().Set("Content-Type", "application/json")
	if req.URL.Path == "/internal/runtime/workspace-workflow-observations/operations" {
		var call model.WorkflowFactsRequest
		if json.NewDecoder(req.Body).Decode(&call) != nil || call.Validate() != nil || call.Operation.Kind != "execution_settlement" || model.WorkspaceDigest(call.Binding) != model.WorkspaceDigest(f.actual.Binding) || req.Header.Get("Idempotency-Key") != call.RequestID {
			f.t.Fatal("normal settlement request changed")
		}
		s.operations++
		app, err := f.r.Store.WorkspaceApplication(req.Context(), s.source.runtime.parents[0].ApplicationOperationID)
		if err != nil || app == nil {
			f.t.Fatal(err)
		}
		s.op = model.WorkflowFactsOperation{FormatVersion: 1, OperationID: "wfop_" + model.WorkspaceDigest(f.currentSnapshot())[7:], Binding: call.Binding, Operation: call.Operation, Snapshot: fixtureRaw(f.currentSnapshot()), NodeTokenHash: app.Operation.Producer.NodeTokenHash, RuntimeRevision: f.r.currentAuthorityManifest().DesiredRevision, ExpiresAt: f.r.now().Add(3 * time.Minute).Format(time.RFC3339Nano)}
		s.op.OperationDigest = fixtureDigestField(s.op, "operationDigest")
		_ = json.NewEncoder(w).Encode(s.op)
		return true
	}
	var proof model.WorkflowFactsEnvelope
	if json.NewDecoder(req.Body).Decode(&proof) != nil || proof.Validate() != nil || proof.Payload.OperationDigest != s.op.OperationDigest || model.WorkspaceDigest(proof.Payload.Binding) != model.WorkspaceDigest(f.actual.Binding) {
		f.t.Fatal("normal settlement proof changed")
	}
	body, _ := model.WorkspaceCanonicalJSON(proof.Payload)
	sum := sha256.Sum256(body)
	sig, _ := base64.StdEncoding.Strict().DecodeString(proof.Signature)
	if !ecdsa.VerifyASN1(&s.source.runtime.key.PublicKey, sum[:], sig) {
		f.t.Fatal("SOURCE settlement signature")
	}
	s.reports++
	if os.Getenv("WARPMETAL_CHILD_SETTLEMENT_LOST_ACK_SOURCE") == "1" {
		// The actual authenticated POST and original proof arrived; its ACK is
		// deliberately unavailable. No local journal state is seeded.
		http.Error(w, "SOURCE lost facts acknowledgement", http.StatusServiceUnavailable)
		return true
	}
	_ = json.NewEncoder(w).Encode(model.WorkflowFactsReceipt{FormatVersion: 1, ProofID: "facts_" + s.op.OperationDigest[7:], ProofDigest: model.WorkspaceDigest(proof), ExpiresAt: proof.Payload.NotAfter})
	return true
}

func (s *childCompletionFactsSource) assertLostAcknowledgement(t *testing.T, databasePath string, manifest model.Manifest, first error) {
	t.Helper()
	f := s.source.f
	ctx := context.Background()
	if first == nil || errors.Is(first, ErrControllerFirstTaskPending) || s.operations != 1 || s.proofs != 1 || s.reports != 1 {
		t.Fatal("lost report acknowledgement became success or missed actual POST", first, s.operations, s.proofs, s.reports)
	}
	f.effectStatus = "settled" // A new base snapshot cannot escape prior UNKNOWN.
	assertUnknown := func() {
		t.Helper()
		if err := f.r.Reconcile(ctx, manifest); !errors.Is(err, state.ErrOwnedContinuationUnknown) {
			t.Fatal("changed snapshot bypassed lost facts report acknowledgement", err)
		}
		if s.operations != 1 || s.proofs != 1 || s.reports != 1 {
			t.Fatal("UNKNOWN facts created another operation, signature or POST", s.operations, s.proofs, s.reports)
		}
	}
	assertUnknown()
	if err := f.r.Store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	f.r.Store = reopened
	f.r.ManagedCatalog.(*workspacecatalog.Catalog).State = reopened
	s.source.runtime.parentSourceRuntime.store = reopened
	assertUnknown()
}
func (s *childCompletionFactsRuntime) AttestCellWorkflowFacts(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, call model.WorkflowFactsRequest, op model.WorkflowFactsOperation, root workspacecatalog.RegisteredProject, independent json.RawMessage) (model.WorkflowFactsEnvelope, error) {
	f := s.facts.source.f
	local, err := f.r.Store.CellV3Execution(ctx, entry.PreparationID)
	if err != nil || local == nil || local.Phase != "terminal" || local.Report.Child == nil || local.Report.Child.Outcome == nil || *local.Report.Child.Outcome != "succeeded" || f.backendDigest == nil || *f.backendDigest != local.Report.ReceiptDigest || !reflect.DeepEqual(entry, f.entry) || box.ID != entry.SandboxID || len(input) == 0 || root.Report.Availability != "available" || model.WorkspaceDigest(independent) != model.WorkspaceDigest(f.currentSnapshot()) || !op.MatchesCurrentSnapshot(independent) || current.DesiredRevision != op.RuntimeRevision {
		f.t.Fatal("SOURCE settlement preceded current terminal/root/snapshot", err)
	}
	s.facts.proofs++
	var binding struct{ NativeLocationDigest string }
	_ = json.Unmarshal(f.actual.Binding, &binding)
	readback := map[string]any{"nativeSessionId": entry.NativeSessionID, "nativeRole": entry.Role, "snapshotDigest": model.WorkspaceDigest(independent), "quiescent": true, "effectsComplete": true, "descendantsComplete": true}
	stamp := f.r.now().Format(time.RFC3339Nano)
	native := model.WorkflowNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: entry.ServiceRegistrationID, ServiceGeneration: entry.ServiceGeneration, NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID, NativeLocationDigest: binding.NativeLocationDigest, Role: entry.Role, RootAttestation: root.Report.RootAttestation, ObservedAt: stamp, Readback: fixtureRaw(readback)}
	readback["nativeReceiptDigest"] = model.WorkspaceDigest(native)
	payload := model.WorkflowFactsPayload{FormatVersion: 1, Purpose: "workspace_workflow_facts", RequestID: call.RequestID, TaskID: s.facts.source.op.Subject.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: model.WorkspaceDigest("source_current_receipt"), NativeReceipt: native, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Binding: call.Binding, Readback: fixtureRaw(readback)}
	app, err := f.r.Store.WorkspaceApplication(ctx, s.parents[0].ApplicationOperationID)
	if err != nil || app == nil {
		f.t.Fatal(err)
	}
	body, _ := model.WorkspaceCanonicalJSON(payload)
	sum := sha256.Sum256(body)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, sum[:])
	return model.WorkflowFactsEnvelope{Payload: payload, KeyID: app.Operation.Producer.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}, err
}
func (s *childCompletionFactsSource) assertSettled(t *testing.T) {
	t.Helper()
	expected := 1
	if s.source.f.effectStatus == "settled" && s.source.results == 0 {
		expected = 2
	}
	if s.operations != expected || s.proofs != expected || s.reports != expected {
		t.Fatalf("normal completed child settlement missing/reissued: operations=%d proofs=%d reports=%d expected=%d", s.operations, s.proofs, s.reports, expected)
	}
}
