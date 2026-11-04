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
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Same signed child/native-file journey, extended over actual TLS. Backend facts,
// lifecycle completion and producer signing are explicitly SOURCE suppliers;
// this test verifies typed transport, not protected production signing/readiness.
func testSourceChildFactsTransport(t *testing.T, root string, w qualification.ChildProductWitness, current qualification.ChildProductControl, capture model.ChildNativeIntegrationCapture, integration ...qualification.ChildSourceReadOriginal) {
	t.Helper()
	var packet struct {
		Private []byte `json:"producerPrivatePEM"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "fixture.json"))
	if err != nil || json.Unmarshal(raw, &packet) != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(packet.Private)
	if block == nil {
		t.Fatal("SOURCE signing key absent")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := parsed.(*ecdsa.PrivateKey)
	q := current.Generation.Policy.Payload
	node := fmt.Sprintf("%x", sha256.Sum256([]byte("synthetic-node")))
	total := 0
	for _, kind := range []string{"execution_settlement", "integration_candidate"} {
		t.Run("facts_transport_"+kind, func(t *testing.T) {
			selector := model.WorkflowFactsSelector{Kind: kind}
			snapshot := map[string]any{"executionState": "completed", "executionReceiptDigest": qualification.Digest([]byte("SOURCE lifecycle report")), "desiredState": "active", "desiredRevision": w.Entry.DesiredRevision, "managedServiceReceiptDigest": qualification.Digest([]byte("SOURCE native service receipt")), "nativeContextDigest": qualification.Digest([]byte("SOURCE native context")), "role": "worker", "grants": []any{}, "children": []any{}, "effects": []any{}}
			if kind == "integration_candidate" {
				selector.Receipt = &model.WorkflowReceiptRef{ReceiptID: "source_integration_receipt", ReceiptDigest: qualification.Digest([]byte("SOURCE integration receipt"))}
				snapshot["candidate"] = map[string]any{"receipt": selector.Receipt, "afterDigest": capture.Artifact.Digest}
				if len(integration) == 1 {
					prior := integration[0]
					var request struct {
						Observation map[string]json.RawMessage `json:"observation"`
					}
					if json.Unmarshal(prior.Envelope.Payload.Request, &request) != nil || prior.Receipt.Type != "integration" || prior.Receipt.Status != "settled" {
						t.Fatal("actual SOURCE integration predecessor absent")
					}
					selector.Receipt = &model.WorkflowReceiptRef{ReceiptID: prior.Receipt.ReceiptID, ReceiptDigest: prior.Receipt.ReceiptDigest}
					snapshot["candidate"] = map[string]any{"receipt": selector.Receipt, "target": request.Observation["target"], "targetBinding": request.Observation["targetBinding"], "artifacts": request.Observation["artifacts"], "afterDigest": capture.Artifact.Digest, "changedPaths": request.Observation["changedPaths"]}
				}

			}
			request := model.WorkflowFactsRequest{FormatVersion: 1, RequestID: "source_" + kind, Binding: q.Binding, Operation: selector}
			snapshotRaw, _ := json.Marshal(snapshot)
			op := model.WorkflowFactsOperation{FormatVersion: 1, OperationID: "wfop_source_" + kind, Binding: q.Binding, Operation: selector, Snapshot: snapshotRaw, NodeTokenHash: node, RuntimeRevision: w.Root.RuntimeRevision, ExpiresAt: time.Now().Add(90 * time.Second).UTC().Format(time.RFC3339Nano)}
			opRaw, _ := json.Marshal(op)
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(opRaw, &fields)
			delete(fields, "operationDigest")
			op.OperationDigest = model.WorkspaceDigest(fields)
			calls := 0
			var expected model.WorkflowFactsEnvelope
			server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				calls++
				total++
				if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer synthetic-node" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "" {
					t.Error("facts node-only transport changed")
					rw.WriteHeader(403)
					return
				}
				rw.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/internal/runtime/workspace-workflow-observations/operations":
					var got model.WorkflowFactsRequest
					if json.NewDecoder(r.Body).Decode(&got) != nil || model.WorkspaceDigest(got) != model.WorkspaceDigest(request) {
						t.Error("facts operation original changed")
						rw.WriteHeader(409)
						return
					}
					_ = json.NewEncoder(rw).Encode(op)
				case "/internal/runtime/workspace-workflow-observations/facts":
					var got model.WorkflowFactsEnvelope
					if json.NewDecoder(r.Body).Decode(&got) != nil || model.WorkspaceDigest(got) != model.WorkspaceDigest(expected) || got.Validate() != nil {
						t.Error("facts envelope changed")
						rw.WriteHeader(409)
						return
					}
					body, _ := model.WorkspaceCanonicalJSON(got.Payload)
					sum := sha256.Sum256(body)
					sig, e := base64.StdEncoding.Strict().DecodeString(got.Signature)
					if e != nil || !ecdsa.VerifyASN1(&key.PublicKey, sum[:], sig) {
						t.Error("SOURCE facts signature invalid")
						rw.WriteHeader(409)
						return
					}
					_ = json.NewEncoder(rw).Encode(model.WorkflowFactsReceipt{FormatVersion: 1, ProofID: "source_facts_proof", ProofDigest: model.WorkspaceDigest(got), ExpiresAt: got.Payload.NotAfter})
				default:
					t.Error("unexpected facts endpoint", r.URL.Path)
					rw.WriteHeader(404)
				}
			}))
			defer server.Close()
			client := api.Client{Origin: server.URL, NodeToken: "synthetic-node", HTTP: server.Client()}
			selected, err := client.WorkflowFactsOperation(context.Background(), request, w.Root.RuntimeRevision)
			if err != nil || selected.Operation.Kind != kind {
				t.Fatal("closed facts operation transport", err)
			}
			readback := map[string]any{"nativeSessionId": capture.Native.SessionID, "nativeRole": "worker", "snapshotDigest": model.WorkspaceDigest(snapshot)}
			if kind == "execution_settlement" {
				readback["quiescent"], readback["effectsComplete"], readback["descendantsComplete"] = true, true, true
			} else {
				readback["candidateDigest"] = capture.Artifact.Digest
			}
			readbackRaw, _ := json.Marshal(readback)
			now := time.Now().UTC().Format(time.RFC3339Nano)
			native := model.WorkflowNativeReceipt{FormatVersion: 1, OperationID: selected.OperationID, OperationDigest: selected.OperationDigest, ServiceRegistrationID: w.Entry.ServiceRegistrationID, ServiceGeneration: w.Entry.ServiceGeneration, NativeSessionID: capture.Native.SessionID, NativeProjectID: capture.Native.NativeProjectID, NativeLocationDigest: capture.Native.NativeLocationDigest, Role: "worker", RootAttestation: w.Root.Workspace.RootAttestation, ObservedAt: now, Readback: readbackRaw}
			readback["nativeReceiptDigest"] = model.WorkspaceDigest(native)
			outer, _ := json.Marshal(readback)
			payload := model.WorkflowFactsPayload{FormatVersion: 1, Purpose: "workspace_workflow_facts", RequestID: request.RequestID, TaskID: w.Applicability.TaskID, NodeTokenHash: node, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: now, NotAfter: selected.ExpiresAt, ManagedServiceReceiptDigest: snapshot["managedServiceReceiptDigest"].(string), NativeReceipt: native, OperationID: selected.OperationID, OperationDigest: selected.OperationDigest, Binding: q.Binding, Readback: outer}
			body, _ := model.WorkspaceCanonicalJSON(payload)
			sum := sha256.Sum256(body)
			sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
			if err != nil {
				t.Fatal(err)
			}
			expected = model.WorkflowFactsEnvelope{Payload: payload, KeyID: w.Root.Producer.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}
			receipt, err := client.ReportWorkflowFacts(context.Background(), expected)
			if err != nil || receipt.ProofDigest != model.WorkspaceDigest(expected) || calls != 2 {
				t.Fatal("closed facts retention transport", err)
			}
		})
	}
	if total != 4 {
		t.Fatal("facts retry/dispatch count", total)
	}
	t.Log("SOURCE typed settlement/candidate operations+facts over actual TLS4, no protected signer or observed quiescence claim")
}
