package reconcile

// The normal coordinator/TLS/SQLite path is real; prepared native identity,
// prior signed read custody and terminal capture are explicit SOURCE suppliers.
// The separate signed Store/preprompt journey owns those protected boundaries.
import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type currentStageReviewCompletionSource struct {
	t                *testing.T
	runtime          *currentStageTerminalSourceRuntime
	capture          model.ChildNativeReviewerCapture
	role             model.WorkflowRoleEnrollment
	reads            qualification.ReviewerReadOriginals
	artifact         *childCompletionArtifactSource
	artifactRuntime  *childCompletionArtifactRuntime
	reviews          int
	request, receipt json.RawMessage
}

func newCurrentStageReviewCompletionSource(t *testing.T, s *currentStageTerminalSourceRuntime, root string, intent map[string]any) *currentStageReviewCompletionSource {
	t.Helper()
	ctx := context.Background()
	f := s.terminal.fixture
	entry := f.entry
	local, e := f.r.Store.CellV3Execution(ctx, entry.PreparationID)
	if e != nil || local != nil {
		t.Fatal("SOURCE prepared originals must precede first execution", e)
	}
	project, e := f.r.Store.ManagedProject(ctx, entry.Workspace.SelectionID)
	if e != nil || project == nil {
		t.Fatal(e)
	}
	project.Report.Availability = "available"
	if e = f.r.Store.PutManagedProject(ctx, *project); e != nil {
		t.Fatal(e)
	}
	s.completion = &currentStageCompletionSource{t: t, runtime: s, root: root, facts: map[string]model.WorkflowFactsOperation{}}
	c := &currentStageReviewCompletionSource{t: t, runtime: s}
	assessment := []byte("{\"disposition\":\"approve\",\"findings\":[]}\n")
	if os.Getenv("WARPMETAL_REVIEW_TERMINAL_MODE") == "malformed" {
		assessment = []byte("{\"disposition\":\"approve\",\"findings\":[]} trailing")
	}
	path := filepath.Join(root, "source-review-assessment.json")
	if e = os.WriteFile(path, assessment, 0600); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	stat := info.Sys().(*syscall.Stat_t)
	var b struct{ WorkID, ExecutionID, NativeLocationDigest string }
	publicDeliveryDecode(t, f.actual.Binding, &b)
	generation := model.WorkspaceDigest(map[string]any{"classification": "SOURCE reviewer4 generation supplier", "entry": entry, "input": model.RawPhysicalDigest([]byte(f.resultInput))})
	n := model.ChildNativeExecution{SessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID, NativeLocationDigest: b.NativeLocationDigest, InputID: entry.ExecutionGrant.InputID, InputDigest: model.RawPhysicalDigest([]byte(f.resultInput)), AssistantMessageID: "msg_source_reviewer_assessment", EnqueueSeq: 1, InitialExecutionStartedSeq: 2, TerminalSeq: 8, LogCursor: 8, Current: model.ChildNativeCurrentState{ExecutionStartedSeq: 2, ExecutionTerminalSeq: 8, PendingInboxIDs: []string{}, PendingToolCallIDs: []string{}}, PreparedReceiptDigest: *entry.PreparedReceiptDigest, GrantDigest: model.WorkspaceDigest(entry.ExecutionGrant)}
	c.capture = model.ChildNativeReviewerCapture{GenerationDigest: generation, BindingDigest: model.WorkspaceDigest(f.actual.Binding), InputID: n.InputID, InputDigest: n.InputDigest, AssistantMessageID: n.AssistantMessageID, EnqueueSeq: n.EnqueueSeq, OwningStartSeq: 2, TerminalSeq: n.TerminalSeq, LogCursor: n.LogCursor, Current: n.Current, AssessmentPath: "output/review/assessment.json", AssessmentDigest: model.RawPhysicalDigest(assessment), AssessmentBytes: len(assessment), AssessmentBase64: base64.StdEncoding.EncodeToString(assessment), OriginalResponseDigest: model.WorkspaceDigest("SOURCE reviewer original response"), ProviderResponseDigest: model.WorkspaceDigest("SOURCE reviewer terminal response"), Native: n}
	events := []*json.RawMessage{&c.capture.StepStarted, &c.capture.TextStarted, &c.capture.TextEnded, &c.capture.StepEnded}
	for i, out := range events {
		data := map[string]any{"assistantMessageID": n.AssistantMessageID}
		if i == 2 {
			data["text"] = string(assessment)
		}
		*out = fixtureRaw(map[string]any{"seq": i + 3, "type": []string{"session.step.started", "session.text.started", "session.text.ended", "session.step.ended"}[i], "data": data})
	}
	if e = c.capture.ValidateFor(entry, generation, f.actual.Binding, n.InputID, n.InputDigest, c.capture.AssessmentPath); e != nil {
		t.Fatal("SOURCE reviewer closed capture", e)
	}
	source := &childCompletionSource{f: f}
	source.runtime = &childCompletionSourceRuntime{firstTaskChildTerminalRuntime: s.terminal, source: source}
	source.op.Subject.TaskID = s.application.TaskID
	file := model.ChildNativeFileSnapshot{SourcePath: c.capture.AssessmentPath, Digest: c.capture.AssessmentDigest, ByteCount: len(assessment), Device: uint64(stat.Dev), Inode: stat.Ino}
	c.artifact = &childCompletionArtifactSource{source: source, path: path, content: assessment, file: &file, purpose: "review_evidence"}
	c.artifactRuntime = &childCompletionArtifactRuntime{childCompletionFactsRuntime: &childCompletionFactsRuntime{childCompletionSourceRuntime: source.runtime}, artifact: c.artifact}
	stamp := f.r.now().Format(time.RFC3339Nano)
	expiry := f.r.now().Add(3 * time.Minute).Format(time.RFC3339Nano)
	subject := model.WorkflowRoleSubject{AccountID: s.application.AccountID, TaskID: s.application.TaskID, ServerID: s.application.ServerID, SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration, CellID: entry.OwnerCellID, Role: entry.Role, ControllerID: entry.ControllerID, ControllerRevision: entry.ControllerRevision, AuthorityRevision: entry.AuthorityRevision, ServiceRegistrationID: entry.ServiceRegistrationID, ServiceGeneration: entry.ServiceGeneration, NativeSessionID: entry.NativeSessionID, WorkID: &b.WorkID, ExecutionID: &b.ExecutionID}
	op := model.WorkflowRoleOperation{FormatVersion: 1, OperationID: "wfroleop_source_current_reviewer", Subject: subject, NativeContextDigest: model.WorkspaceDigest("source_current_native"), ManagedServiceReceiptDigest: model.WorkspaceDigest("source_current_receipt"), NodeTokenHash: s.application.Producer.NodeTokenHash, ExpiresAt: expiry}
	op.OperationDigest = fixtureDigestField(op, "operationDigest")
	payload := model.WorkflowRolePayload{FormatVersion: 1, Purpose: "workspace_workflow_role", RequestID: "source_prepared_reviewer_receipt", TaskID: subject.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: expiry, ManagedServiceReceiptDigest: op.ManagedServiceReceiptDigest, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Subject: subject, NativeContextDigest: op.NativeContextDigest, NativeReceipt: model.WorkflowRoleNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: entry.ServiceRegistrationID, ServiceGeneration: entry.ServiceGeneration, NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID, NativeLocationDigest: b.NativeLocationDigest, Role: entry.Role, RootAttestation: entry.Workspace.RootAttestation, ObservedAt: stamp, Readback: model.WorkflowRoleReadback{Subject: subject, NativeContextDigest: op.NativeContextDigest}}}
	var proof model.WorkflowRoleEnvelope
	publicDeliveryDecode(t, sourceSigned(t, s.key, s.application.Producer.KeyID, payload), &proof)
	c.role = model.WorkflowRoleEnrollment{FormatVersion: 1, RoleBindingID: "wrole_source_prepared_reviewer", RoleBindingRevision: 1, ExpiresAt: expiry, Lease: "wfl_source_prepared_reviewer"}
	if op.Validate() != nil || proof.Validate() != nil || c.role.Validate() != nil {
		t.Fatal("SOURCE first prepared role originals")
	}
	var plan model.ControllerPlanReference
	publicDeliveryDecode(t, sourceObject(intent["plan"])["planRef"], &plan)
	before, e := os.ReadFile(filepath.Join(root, "source-integration-before.body"))
	if e != nil {
		t.Fatal(e)
	}
	after, e := os.ReadFile(filepath.Join(root, "source-integration-after.body"))
	if e != nil {
		t.Fatal(e)
	}
	// Explicit upstream SOURCE metadata/read originals. Never inferred from the
	// model assessment; the independent preprompt test exercises real own GETs.
	contextText := sourceObject(sourceObject(intent["prepareBody"])["content"])["context"].(string)
	marker := "Approved full plan:\n"
	end := strings.Index(contextText, "\nOriginal target document:\n")
	if !strings.HasPrefix(contextText, marker) || end < len(marker) {
		t.Fatal("SOURCE full plan absent")
	}
	planBytes := []byte(contextText[len(marker):end])
	if model.RawPhysicalDigest(planBytes) != plan.SourceDigest {
		t.Fatal("SOURCE plan changed")
	}
	selection := qualification.ReviewerSourceSelection{Physical: []qualification.ChildApprovedSourceRead{{Reference: plan, ByteCount: len(planBytes)}, {Reference: model.ControllerPlanReference{Path: "source/coding-result.txt", SourceDigest: model.RawPhysicalDigest(after), Status: "accepted"}, ByteCount: len(after)}}, Artifact: qualification.ChildApprovedSourceRead{Reference: model.ControllerPlanReference{Path: "artifacts/source_original_document_artifact", SourceDigest: model.RawPhysicalDigest(before), Status: "accepted"}, ByteCount: len(before)}}
	claim := reviewerSourceClaim{entry, generation, n.InputDigest, selection}
	base := claim.base()
	for i, read := range append(append([]qualification.ChildApprovedSourceRead{}, selection.Physical...), selection.Artifact) {
		observation := fixtureRaw(map[string]any{"type": "source_read", "reference": read.Reference, "observedDigest": read.Reference.SourceDigest, "byteCount": read.ByteCount})
		inner := fixtureRaw(map[string]any{"binding": f.actual.Binding, "reconciles": nil, "observation": observation})
		id := "source_read_" + model.WorkspaceDigest(read)[7:]
		native := s.completion.nativeReceipt("wfop_"+id, model.WorkspaceDigest(map[string]any{"read": read, "binding": f.actual.Binding}), stamp, inner)
		p := model.WorkflowObservationPayload{FormatVersion: 1, Purpose: "workspace_workflow_observation", RequestID: id, TaskID: subject.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: expiry, ManagedServiceReceiptDigest: op.ManagedServiceReceiptDigest, NativeReceipt: native, OperationID: native.OperationID, OperationDigest: native.OperationDigest, Request: inner}
		var envelope model.WorkflowObservationEnvelope
		publicDeliveryDecode(t, sourceSigned(t, s.key, s.application.Producer.KeyID, p), &envelope)
		request := model.WorkflowObservationRequest{FormatVersion: 1, RequestID: id, Binding: f.actual.Binding, Reconciles: json.RawMessage("null"), Observation: observation}
		ack := model.WorkflowObservationReceipt{FormatVersion: 1, ReceiptID: "receipt_" + id, ReceiptDigest: model.WorkspaceDigest(request), ExecutionID: b.ExecutionID, Type: "source_read", Status: "settled", CreatedAt: stamp}
		if envelope.Validate() != nil || workflowcontract.Validate(workflowcontract.Domain, "observationReceipt", fixtureRaw(ack)) != nil {
			t.Fatal("SOURCE first read original shape")
		}
		original := qualification.ChildSourceReadOriginal{Envelope: envelope, Receipt: ack}
		if i < len(selection.Physical) {
			c.reads.Physical = append(c.reads.Physical, original)
		} else {
			c.reads.Artifact = original
		}
	}
	call := model.WorkflowRoleOperationRequest{FormatVersion: 1, RequestID: "wfreview_role_source_current", Subject: subject}
	fixtureComplete(t, f.r, entry.PreparationID, base+"-role-operation", call, op)
	fixtureComplete(t, f.r, entry.PreparationID, base+"-role-proof", op, proof)
	fixtureComplete(t, f.r, entry.PreparationID, base+"-role-enroll", proof, c.role)
	fixtureComplete(t, f.r, entry.PreparationID, base+"-complete", claim, c.reads)
	if e = f.r.pinReviewerSourceOriginal(ctx, claim); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "source-review-prepared-originals.json"), fixtureRaw(map[string]any{"classification": "NEW SOURCE first prepared role and own read custody supplier before dispatch; not ROOT or actual backend enrollment", "operation": op, "proof": proof, "enrollment": c.role, "reads": c.reads, "claim": claim}), 0600); e != nil {
		t.Fatal(e)
	}
	return c
}
func (c *currentStageReviewCompletionSource) serve(w http.ResponseWriter, r *http.Request) bool {
	if c.artifact.serve(w, r) {
		return true
	}
	f := c.runtime.terminal.fixture
	if r.Method != "POST" || r.URL.Path != "/internal/runtime/workspace-workflow/results/result_source_current_stage/reviews" {
		return false
	}
	var raw json.RawMessage
	if json.NewDecoder(r.Body).Decode(&raw) != nil || workflowcontract.Validate(workflowcontract.Domain, "reviewRequest", raw) != nil || r.Header.Get("X-WarpMetal-Workflow-Lease") != c.role.Lease {
		c.t.Fatal("normal review original/own prepared lease")
	}
	fields := publicDeliveryMap(raw)
	if fields["disposition"] != "approve" || len(fields["findings"].([]any)) != 0 || c.artifact.uploads != 1 || c.runtime.completion.settlementReports != 1 {
		c.t.Fatal("review outran evidence/settlement")
	}
	var refs []any
	publicDeliveryDecode(c.t, fields["consumedRefs"], &refs)
	if len(refs) != len(c.reads.Physical)+1 {
		c.t.Fatal("review lost own read originals")
	}
	for i, v := range append(append([]qualification.ChildSourceReadOriginal{}, c.reads.Physical...), c.reads.Artifact) {
		if model.WorkspaceDigest(sourceObject(refs[i])["readReceipt"]) != model.WorkspaceDigest(model.WorkflowReceiptRef{ReceiptID: v.Receipt.ReceiptID, ReceiptDigest: v.Receipt.ReceiptDigest}) {
			c.t.Fatal("review read original changed")
		}
	}
	c.request = raw
	c.reviews++
	if os.Getenv("WARPMETAL_REVIEW_TERMINAL_MODE") == "lost_ack" {
		http.Error(w, "SOURCE lost review ACK", 503)
		return true
	}
	delete(fields, "requestId")
	c.receipt = fixtureRaw(map[string]any{"formatVersion": 1, "reviewId": "review_source_current_reviewer", "reviewDigest": model.WorkspaceDigest(fields), "target": fields["target"], "integration": fields["integration"], "reviewerExecutionId": f.actualExecution(), "disposition": fields["disposition"], "createdAt": f.r.now().Format(time.RFC3339Nano)})
	if workflowcontract.Validate(workflowcontract.Domain, "reviewReceipt", c.receipt) != nil {
		c.t.Fatal("SOURCE review receipt")
	}
	_ = json.NewEncoder(w).Encode(c.receipt)
	return true
}
func (s *currentStageTerminalSourceRuntime) ObserveCellWorkflowOutcome(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject) (qualification.ChildWorkflowNativeCapture, error) {
	if s.review == nil {
		s.terminal.fixture.t.Fatal("SOURCE reviewer outcome unavailable")
	}
	s.checkCompleted(ctx, box, entry, current, input, root, fixtureRaw(s.terminal.fixture.currentSnapshot()))
	capture := s.review.capture
	return qualification.ChildWorkflowNativeCapture{Reviewer: &capture}, nil
}
func (s *currentStageTerminalSourceRuntime) ReadCellProductArtifact(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root workspacecatalog.RegisteredProject, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
	return s.review.artifactRuntime.ReadCellProductArtifact(ctx, box, entry, current, input, root, call, op, snapshot)
}
