package reconcile

// SOURCE supplier for the existing current-stage normal journey. Native paid
// execution, target provenance and preprompt own-read custody are explicit
// fixture inputs. Real TLS, normal coordinator, STATE and first signed/ACK
// originals are exercised; the separate signed Store journey owns custody proof.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type currentStageCompletionSource struct {
	t                                                                                                      *testing.T
	runtime                                                                                                *currentStageTerminalSourceRuntime
	root                                                                                                   string
	observation                                                                                            json.RawMessage
	original                                                                                               completedChildIntegration
	facts                                                                                                  map[string]model.WorkflowFactsOperation
	capture                                                                                                model.WorkflowCaptureOperation
	operations, proofs, acknowledgements, retained, candidateOperations, candidateProofs, candidateReports int
	settlementOperations, settlementProofs, settlementReports                                              int
}

func newCurrentStageCompletionSource(t *testing.T, s *currentStageTerminalSourceRuntime, root string, intent map[string]any) *currentStageCompletionSource {
	t.Helper()
	f := s.terminal.fixture
	// Existing SOURCE availability supplier; no protected root verification.
	project, e := f.r.Store.ManagedProject(context.Background(), f.entry.Workspace.SelectionID)
	if e != nil || project == nil {
		t.Fatal("SOURCE completed project", e)
	}
	project.Report.Availability = "available"
	if e = f.r.Store.PutManagedProject(context.Background(), *project); e != nil {
		t.Fatal(e)
	}
	targetBinding := publicDeliveryMap(f.actual.Binding)
	for k, v := range map[string]any{"bindingId": "source_original_coding_binding", "executionId": "execution_source_current_stage", "preparationId": "source_original_coding_preparation", "serviceRegistrationId": "source_original_coding_service", "nativeSessionId": "ses_source_original_coding", "packetId": "packet_source_original_coding", "instructionDigest": model.WorkspaceDigest("SOURCE original coding instructions")} {
		targetBinding[k] = v
	}
	if s.author != nil {
		targetBinding = publicDeliveryMap(s.author.child.Binding)
	}
	before, after := []byte("SOURCE original document\n"), []byte("SOURCE integrated document\n")
	if e = os.WriteFile(filepath.Join(root, "source-integration-before.body"), before, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "source-integration-after.body"), after, 0600); e != nil {
		t.Fatal(e)
	}
	plan := sourceObject(intent["plan"])
	ref := plan["planRef"]
	// Own SOURCE read original, named as supplied history rather than a native
	// read inferred from metadata. Its exact ACK is consumed in this observation.
	read := map[string]any{"reference": ref, "readReceipt": map[string]any{"receiptId": "source_current_integrator_own_plan_read", "receiptDigest": model.WorkspaceDigest(map[string]any{"binding": f.actual.Binding, "reference": ref, "classification": "SOURCE preprompt own read ACK"})}}
	var assignment struct{ AssignmentID string }
	_ = json.Unmarshal(f.assignment, &assignment)
	observation := fixtureRaw(map[string]any{"type": "integration", "assignmentId": assignment.AssignmentID, "target": intent["target"], "targetBinding": targetBinding, "artifacts": []any{map[string]any{"artifactId": "source_original_document_artifact", "digest": model.RawPhysicalDigest(before), "byteCount": len(before), "contentType": "text/plain"}}, "consumedRefs": []any{read}, "beforeDigest": model.RawPhysicalDigest(before), "afterDigest": model.RawPhysicalDigest(after), "changedPaths": []string{"source/coding-result.txt"}, "outcome": "succeeded", "status": "settled"})
	if e = workflowcontract.Validate(workflowcontract.Domain, "observation", observation); e != nil {
		t.Fatal("current SOURCE integration observation", e)
	}
	if e = os.WriteFile(filepath.Join(root, "source-integration-terminal-suppliers.json"), fixtureRaw(map[string]any{"classification": "NEW SOURCE target/before/after/own read ACK, not protected/native or backend acceptance", "observation": observation}), 0600); e != nil {
		t.Fatal(e)
	}
	return &currentStageCompletionSource{t: t, runtime: s, root: root, observation: observation, facts: map[string]model.WorkflowFactsOperation{}}
}
func (s *currentStageCompletionSource) snapshot(candidate bool) json.RawMessage {
	fields := s.runtime.terminal.fixture.currentSnapshot()
	if candidate {
		if s.original.Receipt.ReceiptID == "" || s.retained != 1 {
			s.t.Fatal("candidate preceded first own acknowledged observation")
		}
		o := publicDeliveryMap(s.observation)
		fields["candidate"] = map[string]any{"receipt": model.WorkflowReceiptRef{ReceiptID: s.original.Receipt.ReceiptID, ReceiptDigest: s.original.Receipt.ReceiptDigest}, "target": o["target"], "targetBinding": o["targetBinding"], "artifacts": o["artifacts"], "afterDigest": o["afterDigest"], "changedPaths": o["changedPaths"]}
	}
	return fixtureRaw(fields)
}
func (s *currentStageCompletionSource) verify(payload any, keyID, signature string) {
	raw := fixtureRaw(payload)
	sum := sha256.Sum256(raw)
	sig, e := base64.StdEncoding.Strict().DecodeString(signature)
	if e != nil || keyID != s.runtime.application.Producer.KeyID || !ecdsa.VerifyASN1(&s.runtime.key.PublicKey, sum[:], sig) {
		s.t.Fatal("normal SOURCE signature original changed")
	}
}
func (s *currentStageCompletionSource) serve(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "/internal/runtime/workspace-workflow-observations"
	if r.URL.Path != prefix+"/operations" && r.URL.Path != prefix+"/facts" && r.URL.Path != prefix+"/proofs" && r.URL.Path != prefix+"/executions/source_child_execution/receipts" {
		return false
	}
	f := s.runtime.terminal.fixture
	// Cumulative stages share node routes, not child authority. Leave other
	// bindings to their original SOURCE supplier without changing their bytes.
	if r.URL.Path == prefix+"/operations" || r.URL.Path == prefix+"/facts" {
		var raw json.RawMessage
		if json.NewDecoder(r.Body).Decode(&raw) != nil {
			s.t.Fatal("SOURCE current facts body")
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var selected struct {
			Binding json.RawMessage
			Payload struct{ Binding json.RawMessage }
		}
		if json.Unmarshal(raw, &selected) != nil {
			s.t.Fatal("SOURCE current facts selector")
		}
		binding := selected.Binding
		if len(binding) == 0 {
			binding = selected.Payload.Binding
		}
		if model.WorkspaceDigest(binding) != model.WorkspaceDigest(f.actual.Binding) {
			return false
		}
	}
	if r.Method != "POST" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "" {
		s.t.Fatal("integration borrowed role authority")
	}
	w.Header().Set("Content-Type", "application/json")
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch r.URL.Path {
	case prefix + "/operations":
		var request struct {
			FormatVersion int
			RequestID     string
			Binding       json.RawMessage
			Operation     json.RawMessage
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.FormatVersion != 1 || model.WorkspaceDigest(request.Binding) != model.WorkspaceDigest(f.actual.Binding) || r.Header.Get("Idempotency-Key") != request.RequestID {
			s.t.Fatal("current normal operation binding changed")
		}
		var selector struct{ Kind string }
		_ = json.Unmarshal(request.Operation, &selector)
		expiry := f.r.now().Add(currentSourceFactsTTL()).Format(time.RFC3339Nano)
		if selector.Kind == "observation" {
			var capture model.WorkflowCapture
			publicDeliveryDecode(s.t, request.Operation, &capture)
			if model.WorkspaceDigest(capture.Observation) != model.WorkspaceDigest(s.observation) || string(capture.Reconciles) != "null" || s.settlementReports != 1 {
				s.t.Fatal("integration operation outran settlement/changed observation")
			}
			s.operations++
			s.capture = model.WorkflowCaptureOperation{FormatVersion: 1, OperationID: "wfop_source_current_integration", Binding: request.Binding, Operation: capture, Snapshot: s.snapshot(false), NodeTokenHash: s.runtime.application.Producer.NodeTokenHash, RuntimeRevision: f.entry.DesiredRevision, ExpiresAt: expiry}
			s.capture.OperationDigest = fixtureDigestField(s.capture, "operationDigest")
			write(s.capture)
			return true
		}
		var selected model.WorkflowFactsSelector
		publicDeliveryDecode(s.t, request.Operation, &selected)
		if selected.Kind != "execution_settlement" && selected.Kind != "integration_candidate" {
			s.t.Fatal("unexpected facts selector")
		}
		candidate := selected.Kind == "integration_candidate"
		if candidate {
			s.candidateOperations++
			if selected.Receipt == nil || selected.Receipt.ReceiptID != s.original.Receipt.ReceiptID || selected.Receipt.ReceiptDigest != s.original.Receipt.ReceiptDigest {
				s.t.Fatal("candidate selected foreign receipt")
			}
		} else {
			s.settlementOperations++
		}
		op := model.WorkflowFactsOperation{FormatVersion: 1, OperationID: "wfop_" + model.WorkspaceDigest(request)[7:], Binding: request.Binding, Operation: selected, Snapshot: s.snapshot(candidate), NodeTokenHash: s.runtime.application.Producer.NodeTokenHash, RuntimeRevision: f.entry.DesiredRevision, ExpiresAt: expiry}
		op.OperationDigest = fixtureDigestField(op, "operationDigest")
		s.facts[op.OperationID] = op
		write(op)
	case prefix + "/facts":
		var envelope model.WorkflowFactsEnvelope
		if json.NewDecoder(r.Body).Decode(&envelope) != nil || envelope.Validate() != nil {
			s.t.Fatal("current SOURCE facts envelope")
		}
		op, ok := s.facts[envelope.Payload.OperationID]
		if !ok || envelope.Payload.OperationDigest != op.OperationDigest {
			s.t.Fatal("facts unknown operation")
		}
		s.verify(envelope.Payload, envelope.KeyID, envelope.Signature)
		if op.Operation.Kind == "integration_candidate" {
			s.candidateReports++
		} else {
			s.settlementReports++
		}
		write(model.WorkflowFactsReceipt{FormatVersion: 1, ProofID: "facts_" + op.OperationID, ProofDigest: model.WorkspaceDigest(envelope), ExpiresAt: envelope.Payload.NotAfter})
	case prefix + "/proofs":
		var envelope model.WorkflowObservationEnvelope
		if json.NewDecoder(r.Body).Decode(&envelope) != nil || envelope.Validate() != nil || model.WorkspaceDigest(envelope) != model.WorkspaceDigest(s.original.Proof) {
			s.t.Fatal("integration first signed proof changed")
		}
		s.verify(envelope.Payload, envelope.KeyID, envelope.Signature)
		s.proofs++
		write(map[string]any{"formatVersion": 1, "proofId": "proof_source_current_integration", "proofDigest": model.WorkspaceDigest(envelope), "expiresAt": envelope.Payload.NotAfter})
	case prefix + "/executions/source_child_execution/receipts":
		var request model.WorkflowObservationRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || workflowcontract.Validate(workflowcontract.Domain, "observationRequest", fixtureRaw(request)) != nil || model.WorkspaceDigest(request.Observation) != model.WorkspaceDigest(s.observation) || model.WorkspaceDigest(request.Binding) != model.WorkspaceDigest(f.actual.Binding) || s.proofs != 1 {
			s.t.Fatal("integration first acknowledgement changed")
		}
		s.acknowledgements++
		s.original.Receipt = model.WorkflowObservationReceipt{FormatVersion: 1, ReceiptID: "receipt_source_current_integration", ReceiptDigest: model.WorkspaceDigest(request), ExecutionID: "source_child_execution", Type: "integration", Status: "settled", CreatedAt: f.r.now().Format(time.RFC3339Nano)}
		write(s.original.Receipt)
	default:
		s.t.Fatalf("unexpected integration SOURCE HTTP %s", r.URL.Path)
	}
	return true
}
func (s *currentStageTerminalSourceRuntime) checkCompleted(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject, base json.RawMessage) {
	f := s.terminal.fixture
	local, e := f.r.Store.CellV3Execution(ctx, entry.PreparationID)
	if e != nil || local == nil || local.Phase != "terminal" || local.Report.Child == nil || local.Report.Child.Outcome == nil || *local.Report.Child.Outcome != "succeeded" || f.backendDigest == nil || *f.backendDigest != local.Report.ReceiptDigest || !reflect.DeepEqual(entry, f.entry) || box.ID != entry.SandboxID || string(input) != f.resultInput || root.Report.Availability != "available" || current.DesiredRevision != entry.DesiredRevision || model.WorkspaceDigest(base) != model.WorkspaceDigest(f.currentSnapshot()) {
		s.completion.t.Fatal("SOURCE integration preceded current terminal/report/root/snapshot", e)
	}
}
func (s *currentStageTerminalSourceRuntime) AttestCellWorkflowFacts(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, call model.WorkflowFactsRequest, op model.WorkflowFactsOperation, root workspacecatalog.RegisteredProject, snapshot json.RawMessage) (model.WorkflowFactsEnvelope, error) {
	c := s.completion
	f := s.terminal.fixture
	s.checkCompleted(ctx, box, entry, current, input, root, fixtureRaw(f.currentSnapshot()))
	candidate := call.Operation.Kind == "integration_candidate"
	if !op.MatchesCurrentSnapshot(snapshot) || model.WorkspaceDigest(snapshot) != model.WorkspaceDigest(c.snapshot(candidate)) {
		c.t.Fatal("SOURCE independently reconstructed facts snapshot differs")
	}
	if candidate {
		c.candidateProofs++
	} else {
		c.settlementProofs++
	}
	readback := map[string]any{"nativeSessionId": entry.NativeSessionID, "nativeRole": entry.Role, "snapshotDigest": model.WorkspaceDigest(snapshot)}
	if candidate {
		readback["candidateDigest"] = publicDeliveryMap(c.observation)["afterDigest"]
	} else {
		readback["quiescent"], readback["effectsComplete"], readback["descendantsComplete"] = true, true, true
	}
	stamp := f.r.now().Format(time.RFC3339Nano)
	native := c.nativeReceipt(op.OperationID, op.OperationDigest, stamp, fixtureRaw(readback))
	readback["nativeReceiptDigest"] = model.WorkspaceDigest(native)
	payload := model.WorkflowFactsPayload{FormatVersion: 1, Purpose: "workspace_workflow_facts", RequestID: call.RequestID, TaskID: s.policy.Applicability.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: model.WorkspaceDigest("source_current_receipt"), NativeReceipt: native, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Binding: call.Binding, Readback: fixtureRaw(readback)}
	var proof model.WorkflowFactsEnvelope
	publicDeliveryDecode(c.t, sourceSigned(c.t, s.key, s.application.Producer.KeyID, payload), &proof)
	return proof, nil
}
func (c *currentStageCompletionSource) nativeReceipt(id, digest, stamp string, readback json.RawMessage) model.WorkflowNativeReceipt {
	f := c.runtime.terminal.fixture
	var binding struct{ NativeLocationDigest string }
	_ = json.Unmarshal(f.actual.Binding, &binding)
	return model.WorkflowNativeReceipt{FormatVersion: 1, OperationID: id, OperationDigest: digest, ServiceRegistrationID: f.entry.ServiceRegistrationID, ServiceGeneration: f.entry.ServiceGeneration, NativeSessionID: f.entry.NativeSessionID, NativeProjectID: f.entry.NativeProjectID, NativeLocationDigest: binding.NativeLocationDigest, Role: f.entry.Role, RootAttestation: f.entry.Workspace.RootAttestation, ObservedAt: stamp, Readback: readback}
}
func (s *currentStageTerminalSourceRuntime) AttestCellProductIntegration(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, root workspacecatalog.RegisteredProject, base json.RawMessage) (model.WorkflowObservationEnvelope, error) {
	s.checkCompleted(ctx, box, entry, current, input, root, base)
	c := s.completion
	// Independent post-operation owner observation, not copied from the request.
	observation, e := s.ObserveCellProductIntegration(ctx, box, entry, current, input, root, base)
	if e != nil || model.WorkspaceDigest(observation) != model.WorkspaceDigest(op.Operation.Observation) || !op.MatchesCurrentSnapshot(base) {
		c.t.Fatal("post-operation SOURCE owner observation changed", e)
	}
	inner := fixtureRaw(map[string]any{"binding": call.Binding, "reconciles": nil, "observation": observation})
	stamp := s.terminal.fixture.r.now().Format(time.RFC3339Nano)
	payload := model.WorkflowObservationPayload{FormatVersion: 1, Purpose: "workspace_workflow_observation", RequestID: call.RequestID, TaskID: s.policy.Applicability.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: model.WorkspaceDigest("source_current_receipt"), NativeReceipt: c.nativeReceipt(op.OperationID, op.OperationDigest, stamp, inner), OperationID: op.OperationID, OperationDigest: op.OperationDigest, Request: inner}
	publicDeliveryDecode(c.t, sourceSigned(c.t, s.key, s.application.Producer.KeyID, payload), &c.original.Proof)
	return c.original.Proof, nil
}
func (s *currentStageTerminalSourceRuntime) RetainCellProductObservationReceipt(_ context.Context, proof model.WorkflowObservationEnvelope, receipt model.WorkflowObservationReceipt) error {
	if s.review != nil {
		return s.review.artifactRuntime.RetainCellProductObservationReceipt(context.Background(), proof, receipt)
	}
	c := s.completion
	if model.WorkspaceDigest(proof) != model.WorkspaceDigest(c.original.Proof) || receipt != c.original.Receipt || c.acknowledgements != 1 {
		c.t.Fatal("retention replaced first proof/ACK")
	}
	c.retained++
	return os.WriteFile(filepath.Join(c.root, "source-integration-first-original.json"), fixtureRaw(c.original), 0600)
}
