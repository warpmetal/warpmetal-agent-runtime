package reconcile

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// Explicit SOURCE native metadata/signing; the artifact bytes are an actual
// temporary file. This is not a protected ROOT read or model-produced output.
type childCompletionArtifactSource struct {
	source                                                *childCompletionSource
	path                                                  string
	content                                               []byte
	capture                                               model.ChildNativeResultCapture
	file                                                  *model.ChildNativeFileSnapshot
	purpose                                               string
	approved                                              []model.ControllerPlanReference
	op                                                    model.WorkflowCaptureOperation
	proof                                                 model.WorkflowObservationEnvelope
	receipt                                               model.WorkflowObservationReceipt
	operations, reads, proofs, reports, retained, uploads int
}
type childCompletionArtifactRuntime struct {
	*childCompletionFactsRuntime
	artifact *childCompletionArtifactSource
}

func newChildCompletionArtifactSource(t *testing.T, source *childCompletionSource) *childCompletionArtifactSource {
	t.Helper()
	f := source.f
	s := &childCompletionArtifactSource{source: source, path: filepath.Join(t.TempDir(), "result.txt"), content: []byte("Explicit SOURCE document artifact.\n")}
	t.Cleanup(func() {
		t.Logf("artifact SOURCE boundary calls: operations=%d reads=%d proofs=%d reports=%d retained=%d uploads=%d", s.operations, s.reads, s.proofs, s.reports, s.retained, s.uploads)
	})
	if err := os.WriteFile(s.path, s.content, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	var assignment struct {
		Plan struct{ PlanRef model.ControllerPlanReference }
	}
	if json.Unmarshal(f.actual.AssignmentBody, &assignment) != nil {
		t.Fatal("SOURCE assignment")
	}
	s.approved = []model.ControllerPlanReference{assignment.Plan.PlanRef}
	var binding struct{ NativeLocationDigest string }
	_ = json.Unmarshal(f.actual.Binding, &binding)
	c := &s.capture
	c.FormatVersion, c.Purpose, c.Workload = 1, "child_native_result", "coding2"
	c.GenerationDigest, c.BindingDigest = model.WorkspaceDigest("SOURCE_generation"), model.WorkspaceDigest(f.actual.Binding)
	c.Native = model.ChildNativeExecution{SessionID: f.entry.NativeSessionID, NativeProjectID: f.entry.NativeProjectID, NativeLocationDigest: binding.NativeLocationDigest, InputID: f.entry.ExecutionGrant.InputID, InputDigest: model.RawPhysicalDigest([]byte("SOURCE input")), AssistantMessageID: "msg_source_result", EnqueueSeq: 1, InitialExecutionStartedSeq: 2, TerminalSeq: 6, LogCursor: 6, Current: model.ChildNativeCurrentState{ExecutionStartedSeq: 2, ExecutionTerminalSeq: 6, PendingInboxIDs: []string{}, PendingToolCallIDs: []string{}}, PreparedReceiptDigest: *f.entry.PreparedReceiptDigest, GrantDigest: model.WorkspaceDigest(f.entry.ExecutionGrant)}
	c.Effect.CallID, c.Effect.Tool = "call_source_result", "write"
	c.Effect.ArgumentsDigest, c.Effect.ResponseDigest, c.Effect.ClaimDigest = model.WorkspaceDigest("SOURCE_args"), model.WorkspaceDigest("SOURCE_first_response"), model.WorkspaceDigest("SOURCE_guard")
	c.Effect.CalledSeq, c.Effect.CompletedSeq = 3, 4
	c.Terminal.Text = string(fixtureRaw(map[string]any{"type": "document", "sourceRefs": []model.ControllerPlanReference{assignment.Plan.PlanRef}, "method": "Explicit SOURCE fixture metadata; no model-generated claim."}))
	c.Terminal.ByteCount, c.Terminal.Digest, c.Terminal.ResponseDigest = len(c.Terminal.Text), model.RawPhysicalDigest([]byte(c.Terminal.Text)), model.WorkspaceDigest("SOURCE_terminal_response")
	c.Artifact = model.ChildNativeFileSnapshot{SourcePath: "result.txt", Digest: model.RawPhysicalDigest(s.content), ByteCount: len(s.content), Device: uint64(stat.Dev), Inode: stat.Ino}
	if c.Validate() != nil {
		t.Fatal("SOURCE closed capture")
	}
	return s
}

// Separate file/transport fixture from coding terminal semantics; original
// document fixture defaults remain unchanged, reviewer supplies its own file.
func (s *childCompletionArtifactSource) artifactFile() model.ChildNativeFileSnapshot {
	if s.file != nil {
		return *s.file
	}
	return s.capture.Artifact
}
func (s *childCompletionArtifactSource) artifactPurpose() string {
	if s.purpose != "" {
		return s.purpose
	}
	return "document"
}

func (s *childCompletionArtifactSource) serve(w http.ResponseWriter, req *http.Request) bool {
	f := s.source.f
	base := "/internal/runtime/workspace-workflow-observations"
	if req.Method != "POST" || !strings.HasPrefix(req.URL.Path, base) {
		return false
	}
	if req.URL.Path == base+"/operations" {
		// Facts and observation use the same owning endpoint; inspect a copy.
		raw := json.RawMessage{}
		if json.NewDecoder(req.Body).Decode(&raw) != nil {
			f.t.Fatal("SOURCE operation body")
		}
		var kind struct{ Operation struct{ Kind string } }
		_ = json.Unmarshal(raw, &kind)
		if kind.Operation.Kind != "observation" {
			req.Body = io.NopCloser(bytes.NewReader(raw))
			return false
		}
		var call model.WorkflowCaptureRequest
		if model.DecodePhysicalClosed(raw, &call) != nil || model.WorkspaceDigest(call.Binding) != model.WorkspaceDigest(f.actual.Binding) {
			f.t.Fatal("SOURCE artifact operation binding")
		}
		var observed struct {
			Type, SourcePath, Digest string
			ByteCount                int
		}
		_ = json.Unmarshal(call.Operation.Observation, &observed)
		if observed.Type != "artifact_read" || observed.SourcePath != s.artifactFile().SourcePath || observed.Digest != s.artifactFile().Digest || observed.ByteCount != len(s.content) {
			f.t.Fatal("artifact path/body was not from native capture")
		}
		app, _ := f.r.Store.WorkspaceApplication(req.Context(), s.source.runtime.parents[0].ApplicationOperationID)
		s.op = model.WorkflowCaptureOperation{FormatVersion: 1, OperationID: "wfop_source_artifact", Binding: call.Binding, Operation: call.Operation, Snapshot: fixtureRaw(f.currentSnapshot()), NodeTokenHash: app.Operation.Producer.NodeTokenHash, RuntimeRevision: f.r.currentAuthorityManifest().DesiredRevision, ExpiresAt: f.r.now().Add(3 * time.Minute).Format(time.RFC3339Nano)}
		s.op.OperationDigest = fixtureDigestField(s.op, "operationDigest")
		s.operations++
		_ = json.NewEncoder(w).Encode(s.op)
		return true
	}
	if req.URL.Path == base+"/proofs" {
		var proof model.WorkflowObservationEnvelope
		if json.NewDecoder(req.Body).Decode(&proof) != nil || proof.Validate() != nil || model.WorkspaceDigest(proof) != model.WorkspaceDigest(s.proof) {
			f.t.Fatal("artifact original proof changed")
		}
		raw, _ := model.WorkspaceCanonicalJSON(proof.Payload)
		sum := sha256.Sum256(raw)
		sig, _ := base64.StdEncoding.Strict().DecodeString(proof.Signature)
		if !ecdsa.VerifyASN1(&s.source.runtime.key.PublicKey, sum[:], sig) {
			f.t.Fatal("artifact SOURCE signature")
		}
		s.proofs++
		_ = json.NewEncoder(w).Encode(map[string]any{"formatVersion": 1, "proofId": "proof_source_artifact", "proofDigest": model.WorkspaceDigest(proof), "expiresAt": proof.Payload.NotAfter})
		return true
	}
	if req.URL.Path == base+"/executions/"+f.actualExecution()+"/receipts" {
		var call model.WorkflowObservationRequest
		if json.NewDecoder(req.Body).Decode(&call) != nil || model.WorkspaceDigest(call.Binding) != model.WorkspaceDigest(f.actual.Binding) || model.WorkspaceDigest(call.Observation) != model.WorkspaceDigest(s.op.Operation.Observation) {
			f.t.Fatal("artifact observation original changed")
		}
		s.reports++
		s.receipt = model.WorkflowObservationReceipt{FormatVersion: 1, ReceiptID: "receipt_source_artifact", ReceiptDigest: model.WorkspaceDigest(call), ExecutionID: f.actualExecution(), Type: "artifact_read", Status: "settled", CreatedAt: f.r.now().Format(time.RFC3339Nano)}
		_ = json.NewEncoder(w).Encode(s.receipt)
		return true
	}
	if req.URL.Path == base+"/executions/"+f.actualExecution()+"/artifacts" {
		var call struct {
			RequestID, SourcePath, Purpose, ContentType, Digest, Content string
			Binding                                                      json.RawMessage
			ByteCount                                                    int
			NativeReadReceipt                                            model.WorkflowReceiptRef
		}
		if json.NewDecoder(req.Body).Decode(&call) != nil || call.Purpose != s.artifactPurpose() || call.SourcePath != s.artifactFile().SourcePath || call.Digest != s.artifactFile().Digest || call.ByteCount != len(s.content) || call.NativeReadReceipt.ReceiptID != s.receipt.ReceiptID || call.NativeReadReceipt.ReceiptDigest != s.receipt.ReceiptDigest || model.WorkspaceDigest(call.Binding) != model.WorkspaceDigest(f.actual.Binding) {
			f.t.Fatal("artifact upload lost actual read/owning path")
		}
		bytes, err := base64.StdEncoding.Strict().DecodeString(call.Content)
		if err != nil || string(bytes) != string(s.content) {
			f.t.Fatal("artifact content rewritten")
		}
		s.uploads++
		if os.Getenv("WARPMETAL_CHILD_ARTIFACT_LOST_ACK_SOURCE") == "1" {
			http.Error(w, "SOURCE lost artifact upload acknowledgement", http.StatusServiceUnavailable)
			return true
		}
		receipt := model.WorkflowArtifactReceipt{FormatVersion: 1, ArtifactID: "artifact_source_document", ExecutionID: f.actualExecution(), SourcePath: call.SourcePath, Purpose: call.Purpose, Digest: call.Digest, ByteCount: call.ByteCount, ContentType: call.ContentType, NativeReadReceipt: fixtureRaw(call.NativeReadReceipt), CreatedAt: f.r.now().Format(time.RFC3339Nano)}
		receipt.ArtifactReceiptDigest = fixtureDigestField(receipt, "artifactReceiptDigest")
		_ = json.NewEncoder(w).Encode(receipt)
		return true
	}
	return false
}
func (f *firstTaskChildTerminalFixture) actualExecution() string {
	var b struct{ ExecutionID string }
	_ = json.Unmarshal(f.actual.Binding, &b)
	return b.ExecutionID
}
func (s *childCompletionArtifactRuntime) ObserveCellWorkflowOutcome(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject) (qualification.ChildWorkflowNativeCapture, error) {
	c := s.artifact.capture
	c.Native.InputDigest = model.RawPhysicalDigest(input)
	return qualification.ChildWorkflowNativeCapture{Result: &c, ApprovedSourceReferences: s.artifact.approved}, nil
}
func (s *childCompletionArtifactRuntime) ReadCellProductArtifact(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
	a := s.artifact
	f := a.source.f
	content, err := os.ReadFile(a.path)
	if err != nil {
		return model.WorkflowObservationEnvelope{}, qualification.WorkflowSourceCapture{}, err
	}
	if string(content) != string(a.content) || !op.MatchesCurrentSnapshot(snapshot) {
		f.t.Fatal("SOURCE artifact/current read changed")
	}
	a.reads++
	stamp := f.r.now().Format(time.RFC3339Nano)
	request := fixtureRaw(map[string]any{"binding": call.Binding, "reconciles": nil, "observation": call.Operation.Observation})
	var binding struct{ NativeLocationDigest string }
	_ = json.Unmarshal(call.Binding, &binding)
	native := model.WorkflowNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: entry.ServiceRegistrationID, ServiceGeneration: entry.ServiceGeneration, NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID, NativeLocationDigest: binding.NativeLocationDigest, Role: entry.Role, RootAttestation: entry.Workspace.RootAttestation, ObservedAt: stamp, Readback: request}
	payload := model.WorkflowObservationPayload{FormatVersion: 1, Purpose: "workspace_workflow_observation", RequestID: call.RequestID, TaskID: s.source.op.Subject.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: model.WorkspaceDigest("source_current_receipt"), NativeReceipt: native, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Request: request}
	app, _ := f.r.Store.WorkspaceApplication(ctx, s.parents[0].ApplicationOperationID)
	raw, _ := model.WorkspaceCanonicalJSON(payload)
	sum := sha256.Sum256(raw)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, sum[:])
	a.proof = model.WorkflowObservationEnvelope{Payload: payload, KeyID: app.Operation.Producer.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}
	return a.proof, qualification.WorkflowSourceCapture{OperationDigest: op.OperationDigest, ScopeDigest: model.WorkspaceDigest("SOURCE_artifact_scope"), RootDevice: root.RootDevice, RootInode: root.RootInode, SourceDevice: a.artifactFile().Device, SourceInode: a.artifactFile().Inode, Bytes: content, ObservedAt: stamp}, err
}
func (s *childCompletionArtifactRuntime) RetainCellProductObservationReceipt(_ context.Context, envelope model.WorkflowObservationEnvelope, receipt model.WorkflowObservationReceipt) error {
	if model.WorkspaceDigest(envelope) != model.WorkspaceDigest(s.artifact.proof) || receipt != s.artifact.receipt {
		s.artifact.source.f.t.Fatal("artifact ACK changed before retention")
	}
	s.artifact.retained++
	return nil
}
func (s *childCompletionArtifactSource) assertUploaded(t *testing.T) {
	t.Helper()
	if s.operations != 1 || s.reads != 1 || s.proofs != 1 || s.reports != 1 || s.retained != 1 || s.uploads != 1 {
		t.Fatalf("normal document artifact absent/reissued: operations=%d reads=%d proofs=%d reports=%d retained=%d uploads=%d", s.operations, s.reads, s.proofs, s.reports, s.retained, s.uploads)
	}
}

func (s *childCompletionArtifactSource) assertForeignMetadataDenied(t *testing.T, manifest model.Manifest) {
	t.Helper()
	original := s.capture
	defer func() { s.capture = original }()
	foreign := s.approved[0]
	foreign.Path = "unapproved-source.txt"
	s.capture.Terminal.Text = string(fixtureRaw(map[string]any{"type": "document", "sourceRefs": []model.ControllerPlanReference{foreign}, "method": "SOURCE forbidden reference"}))
	s.capture.Terminal.Digest = model.RawPhysicalDigest([]byte(s.capture.Terminal.Text))
	s.capture.Terminal.ByteCount = len(s.capture.Terminal.Text)
	if err := s.source.f.r.Reconcile(context.Background(), manifest); err == nil || !strings.Contains(err.Error(), "child document metadata refused") {
		t.Fatal("unapproved model-declared reference escaped signed scope", err)
	}
	s.assertUploaded(t)
}

func (s *childCompletionArtifactSource) assertLostAcknowledgement(t *testing.T, databasePath string, manifest model.Manifest, first error) {
	t.Helper()
	f := s.source.f
	if first == nil || errors.Is(first, ErrControllerFirstTaskPending) {
		t.Fatal("lost artifact upload acknowledgement became success", first)
	}
	s.assertUploaded(t)
	f.effectStatus = "settled"
	assertUnknown := func() {
		t.Helper()
		if err := f.r.Reconcile(context.Background(), manifest); !errors.Is(err, state.ErrOwnedContinuationUnknown) {
			t.Fatal("artifact UNKNOWN bypassed by new snapshot", err)
		}
		s.assertUploaded(t)
		facts := s.source.facts
		if facts.operations != 1 || facts.proofs != 1 || facts.reports != 1 {
			t.Fatalf("pending artifact allowed new facts effects: operations=%d proofs=%d reports=%d", facts.operations, facts.proofs, facts.reports)
		}
		if s.source.operations != 1 || s.source.proofs != 1 || s.source.enrollments != 1 {
			t.Fatal("pending artifact reenrolled role")
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
