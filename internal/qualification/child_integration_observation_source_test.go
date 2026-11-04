package qualification_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

func integrationSourceKey(t *testing.T, root string) *ecdsa.PrivateKey {
	t.Helper()
	var packet struct {
		Private []byte `json:"producerPrivatePEM"`
	}
	raw, e := os.ReadFile(filepath.Join(root, "fixture.json"))
	if e != nil || json.Unmarshal(raw, &packet) != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(packet.Private)
	if block == nil {
		t.Fatal("SOURCE key absent")
	}
	v, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	return v.(*ecdsa.PrivateKey)
}
func integrationSourceVerifier(key *ecdsa.PrivateKey) func(model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error {
	return func(e model.WorkflowObservationEnvelope, r model.WorkflowObservationReceipt) error {
		body, _ := model.WorkspaceCanonicalJSON(e.Payload)
		sum := sha256.Sum256(body)
		sig, err := base64.StdEncoding.Strict().DecodeString(e.Signature)
		if err != nil || !ecdsa.VerifyASN1(&key.PublicKey, sum[:], sig) || e.Validate() != nil || r.ReceiptID == "" {
			return fmt.Errorf("SOURCE original signature/ACK refused")
		}
		return nil
	}
}

// Actual API/TLS boundaries; the backend state and ECDSA producer are expressly
// SOURCE suppliers. The callback observes the file AFTER the operation exists.
func integrationSourceObservation(t *testing.T, root string, w qualification.ChildProductWitness, c qualification.ChildProductControl, key *ecdsa.PrivateKey, label string, observation json.RawMessage, read func(model.WorkflowCaptureOperation) string) qualification.ChildSourceReadOriginal {
	t.Helper()
	raw := func(v any) json.RawMessage {
		b, e := model.WorkspaceCanonicalJSON(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	q := c.Generation.Policy.Payload
	call := model.WorkflowCaptureRequest{FormatVersion: 1, RequestID: "source_" + label, Binding: q.Binding, Operation: model.WorkflowCapture{Kind: "observation", Reconciles: json.RawMessage("null"), Observation: observation}}
	snapshot := raw(map[string]any{"desiredState": "active", "desiredRevision": w.Entry.DesiredRevision, "role": w.Entry.Role, "managedServiceReceiptDigest": qualification.Digest([]byte("SOURCE service receipt"))})
	op := model.WorkflowCaptureOperation{FormatVersion: 1, OperationID: "wfop_source_" + label, Binding: q.Binding, Operation: call.Operation, Snapshot: snapshot, NodeTokenHash: w.Root.Producer.NodeTokenHash, RuntimeRevision: w.Root.RuntimeRevision, ExpiresAt: time.Now().Add(90 * time.Second).UTC().Format(time.RFC3339Nano)}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw(op), &fields)
	delete(fields, "operationDigest")
	op.OperationDigest = model.WorkspaceDigest(fields)
	var binding struct{ ExecutionID, NativeSessionID, NativeProjectID, NativeLocationDigest string }
	_ = json.Unmarshal(q.Binding, &binding)
	var observed struct{ Type, Status string }
	_ = json.Unmarshal(observation, &observed)
	if observed.Status == "" {
		observed.Status = "settled"
	}
	var envelope model.WorkflowObservationEnvelope
	var receipt model.WorkflowObservationReceipt
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		calls++
		rw.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer synthetic-node" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "" {
			t.Error("SOURCE observation node transport")
			rw.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/internal/runtime/workspace-workflow-observations/operations":
			var got model.WorkflowCaptureRequest
			if json.NewDecoder(r.Body).Decode(&got) != nil || model.WorkspaceDigest(got) != model.WorkspaceDigest(call) {
				t.Error("operation changed")
				rw.WriteHeader(409)
				return
			}
			_ = json.NewEncoder(rw).Encode(op)
		case "/internal/runtime/workspace-workflow-observations/proofs":
			var got model.WorkflowObservationEnvelope
			if json.NewDecoder(r.Body).Decode(&got) != nil || model.WorkspaceDigest(got) != model.WorkspaceDigest(envelope) || integrationSourceVerifier(key)(got, model.WorkflowObservationReceipt{ReceiptID: "source_pre_ACK"}) != nil {
				t.Error("SOURCE first signed original changed")
				rw.WriteHeader(409)
				return
			}
			_ = json.NewEncoder(rw).Encode(map[string]any{"formatVersion": 1, "proofId": "source_proof_" + label, "proofDigest": model.WorkspaceDigest(got), "expiresAt": got.Payload.NotAfter})
		case "/internal/runtime/workspace-workflow-observations/executions/" + binding.ExecutionID + "/receipts":
			var got model.WorkflowObservationRequest
			if json.NewDecoder(r.Body).Decode(&got) != nil || model.WorkspaceDigest(got.Observation) != model.WorkspaceDigest(observation) || model.WorkspaceDigest(got.Binding) != model.WorkspaceDigest(q.Binding) {
				t.Error("observation request changed")
				rw.WriteHeader(409)
				return
			}
			receipt = model.WorkflowObservationReceipt{FormatVersion: 1, ReceiptID: "source_receipt_" + label, ReceiptDigest: model.WorkspaceDigest(got), ExecutionID: binding.ExecutionID, Type: observed.Type, Status: observed.Status, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
			_ = json.NewEncoder(rw).Encode(receipt)
		default:
			rw.WriteHeader(404)
		}
	}))
	defer server.Close()
	client := api.Client{Origin: server.URL, NodeToken: "synthetic-node", HTTP: server.Client()}
	selected, e := client.WorkflowObservationOperation(context.Background(), call, w.Root.RuntimeRevision)
	if e != nil {
		t.Fatal("SOURCE actual operation TLS", e)
	}
	stamp := read(selected)
	request := raw(map[string]any{"binding": q.Binding, "reconciles": nil, "observation": observation})
	native := model.WorkflowNativeReceipt{FormatVersion: 1, OperationID: selected.OperationID, OperationDigest: selected.OperationDigest, ServiceRegistrationID: w.Entry.ServiceRegistrationID, ServiceGeneration: w.Entry.ServiceGeneration, NativeSessionID: binding.NativeSessionID, NativeProjectID: binding.NativeProjectID, NativeLocationDigest: binding.NativeLocationDigest, Role: w.Entry.Role, RootAttestation: w.Root.Workspace.RootAttestation, ObservedAt: stamp, Readback: request}
	payload := model.WorkflowObservationPayload{FormatVersion: 1, Purpose: "workspace_workflow_observation", RequestID: call.RequestID, TaskID: w.Applicability.TaskID, NodeTokenHash: w.Root.Producer.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: selected.ExpiresAt, ManagedServiceReceiptDigest: qualification.Digest([]byte("SOURCE service receipt")), NativeReceipt: native, OperationID: selected.OperationID, OperationDigest: selected.OperationDigest, Request: request}
	body := raw(payload)
	sum := sha256.Sum256(body)
	signature, e := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if e != nil {
		t.Fatal(e)
	}
	envelope = model.WorkflowObservationEnvelope{Payload: payload, KeyID: w.Root.Producer.KeyID, Signature: base64.StdEncoding.EncodeToString(signature)}
	got, e := client.ReportWorkflowObservation(context.Background(), envelope)
	if e != nil || got != receipt || calls != 3 {
		t.Fatal("SOURCE proof/ACK transport", e, calls)
	}
	original := qualification.ChildSourceReadOriginal{Envelope: envelope, Receipt: got}
	if e = os.WriteFile(filepath.Join(root, "source-observation-"+label+".json"), raw(original), 0400); e != nil {
		t.Fatal(e)
	}
	return original
}

func prepareSourceIntegrationObservationCustody(t *testing.T, root, tree string, w qualification.ChildProductWitness, c qualification.ChildProductControl) {
	t.Helper()
	key := integrationSourceKey(t, root)
	reads := []qualification.ChildSourceReadOriginal{}
	captures := []qualification.WorkflowSourceCapture{}
	for i, scope := range c.Generation.Policy.Payload.SourceReads {
		var grant struct {
			Reference model.ControllerPlanReference `json:"reference"`
			ByteCount int                           `json:"byteCount"`
		}
		if json.Unmarshal(scope.Grant, &grant) != nil {
			t.Fatal("scope")
		}
		observation, _ := model.WorkspaceCanonicalJSON(map[string]any{"type": "source_read", "reference": grant.Reference, "observedDigest": grant.Reference.SourceDigest, "byteCount": grant.ByteCount})
		original := integrationSourceObservation(t, root, w, c, key, fmt.Sprintf("integration_read_%d", i), observation, func(op model.WorkflowCaptureOperation) string {
			read := qualification.SourceIntegrationReadForTest(t, root, w, c, scope, op)
			captures = append(captures, read)
			return read.ObservedAt
		})
		reads = append(reads, original)
	}
	bundle := qualification.SourceIntegrationCustodyForTest(t, root, w, c, reads, captures, integrationSourceVerifier(key))
	// Separate test-only publication. Do not invoke or bypass the ROOT exporter.
	if e := os.WriteFile(filepath.Join(root, "source-integration-custody.json"), bundle, 0400); e != nil {
		t.Fatal(e)
	}
	pub, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})
	if qualification.Digest(pubPEM) != w.Root.Producer.KeySHA256 {
		t.Fatal("SOURCE public pin drift")
	}
	published, e := os.ReadFile(filepath.Join(tree, "blobs", w.Root.Producer.KeySHA256[7:]))
	if e != nil || string(published) != string(pubPEM) {
		t.Fatal("existing Store producer public key differs", e)
	}
	t.Log("SOURCE own confined source reads + ECDSA first originals + TLS operation/proof/ACK6 retained; no protected producer/exporter")
}

func testSourceIntegrationObservationBoundary(t *testing.T, root string, w qualification.ChildProductWitness, current qualification.ChildProductControl) {
	t.Helper()
	key := integrationSourceKey(t, root)
	raw, e := os.ReadFile(filepath.Join(root, "integration-result-capture.json"))
	if e != nil {
		t.Fatal(e)
	}
	capture, e := model.DecodeChildNativeIntegrationCapture(raw)
	if e != nil {
		t.Fatal(e)
	}
	// Same actual local HTTP originals and SQLite financial closure. Prior prefix
	// remains declared SOURCE, never imported backend/live authority.
	qualification.SourceChildFinancialCompletionForTest(t, root, w, current, capture)
	if _, ok := any(containers.Podman{}).(interface {
		ObserveCellProductIntegration(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, workspacecatalog.RegisteredProject, json.RawMessage) (json.RawMessage, error)
	}); !ok {
		t.Fatal("current completed integrator has no owner-derived read-only observation for normal operation construction")
	}
	observation := qualification.SourceIntegrationObservationForTest(t, root, w, current, capture, integrationSourceVerifier(key))
	original := integrationSourceObservation(t, root, w, current, key, "terminal_integration", observation, func(op model.WorkflowCaptureOperation) string {
		again := qualification.SourceIntegrationObservationForTest(t, root, w, current, capture, integrationSourceVerifier(key))
		if model.WorkspaceDigest(again) != model.WorkspaceDigest(op.Operation.Observation) {
			t.Fatal("post-operation SOURCE observation changed before attestation")
		}
		return time.Now().UTC().Format(time.RFC3339Nano)
	})
	testSourceChildFactsTransport(t, root, w, current, capture, original)
	if os.Getenv("WARPMETAL_CHILD_COMPLETED_FACTS_BOUNDARY") == "1" {
		qualification.SourceCompletedFactsHistoryForTest(t, root, w, current, capture)
	}
	t.Log("SOURCE completed integration current target/before/after/own ACK → actual observation TLS3 → candidate TLS; no second result, manager acceptance, ROOT or native executable proof")
}
