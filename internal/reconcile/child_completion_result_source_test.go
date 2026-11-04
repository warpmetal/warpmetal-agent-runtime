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
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

type childCompletionResultSource struct {
	source    *childCompletionSource
	allowRead bool
	originals []qualification.ChildSourceReadOriginal
	body      json.RawMessage
}
type childCompletionResultRuntime struct {
	*childCompletionArtifactRuntime
	result *childCompletionResultSource
}

// Detached first own SOURCE receipt supplier for this coordinator test, never
// protected read credit. The separate published-control journey exercises file
// bytes/read/ACK ordering. These originals bind this exact child, not metadata.
func (s *childCompletionResultRuntime) ReadCellProductSourceReceipts(ctx context.Context, _ model.Sandbox, entry model.CellServiceV3, _ model.Manifest, _ []byte) ([]qualification.ChildSourceReadOriginal, error) {
	r := s.result
	if !r.allowRead {
		return []qualification.ChildSourceReadOriginal{}, nil
	}
	if r.originals != nil {
		return r.originals, nil
	}
	f := r.source.f
	ref := r.source.artifact.approved[0]
	stamp := f.r.now().UTC().Format(time.RFC3339Nano)
	request := fixtureRaw(map[string]any{"binding": f.actual.Binding, "reconciles": nil, "observation": map[string]any{"type": "source_read", "reference": ref, "observedDigest": ref.SourceDigest, "byteCount": 29}})
	var b struct{ NativeLocationDigest string }
	_ = json.Unmarshal(f.actual.Binding, &b)
	opID, opDigest := "wfop_source_consumed", model.WorkspaceDigest("explicit SOURCE prior read operation")
	native := model.WorkflowNativeReceipt{FormatVersion: 1, OperationID: opID, OperationDigest: opDigest, ServiceRegistrationID: entry.ServiceRegistrationID, ServiceGeneration: entry.ServiceGeneration, NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID, NativeLocationDigest: b.NativeLocationDigest, Role: "worker", RootAttestation: entry.Workspace.RootAttestation, ObservedAt: stamp, Readback: request}
	app, err := f.r.Store.WorkspaceApplication(ctx, s.parents[0].ApplicationOperationID)
	if err != nil {
		return nil, err
	}
	payload := model.WorkflowObservationPayload{FormatVersion: 1, Purpose: "workspace_workflow_observation", RequestID: "source_consumed_request", TaskID: r.source.op.Subject.TaskID, NodeTokenHash: app.Operation.Producer.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: f.r.now().Add(time.Minute).Format(time.RFC3339Nano), ManagedServiceReceiptDigest: model.WorkspaceDigest("source_current_receipt"), NativeReceipt: native, OperationID: opID, OperationDigest: opDigest, Request: request}
	raw, _ := model.WorkspaceCanonicalJSON(payload)
	sum := sha256.Sum256(raw)
	signature, err := ecdsa.SignASN1(rand.Reader, s.key, sum[:])
	if err != nil {
		return nil, err
	}
	envelope := model.WorkflowObservationEnvelope{Payload: payload, KeyID: app.Operation.Producer.KeyID, Signature: base64.StdEncoding.EncodeToString(signature)}
	if envelope.Validate() != nil {
		f.t.Fatal("SOURCE own read envelope shape")
	}
	receipt := model.WorkflowObservationReceipt{FormatVersion: 1, ReceiptID: "source_own_read_ack", ReceiptDigest: model.WorkspaceDigest("explicit SOURCE prior ACK"), ExecutionID: f.actualExecution(), Type: "source_read", Status: "settled", CreatedAt: stamp}
	r.originals = []qualification.ChildSourceReadOriginal{{Envelope: envelope, Receipt: receipt}}
	return r.originals, nil
}

func (s *childCompletionResultSource) serve(w http.ResponseWriter, req *http.Request) bool {
	f := s.source.f
	if req.URL.Path != "/internal/runtime/workspace-workflow/executions/"+f.actualExecution()+"/results" {
		return false
	}
	var body struct {
		FormatVersion int
		RequestID     string
		Binding       json.RawMessage
		AssignmentID  string
		Result        struct {
			Outcome      string
			ConsumedRefs []struct {
				Reference   model.ControllerPlanReference
				ReadReceipt model.WorkflowReceiptRef
			}
			Outputs []struct {
				Type, Method string
				SourceRefs   []model.ControllerPlanReference
				Output       struct {
					ArtifactID, Digest, ContentType string
					ByteCount                       int
				}
			}
			StateEvidence, EffectReceipts, RemainingWork []json.RawMessage
		}
	}
	var raw json.RawMessage
	if req.Method != "POST" || req.Header.Get("X-WarpMetal-Workflow-Lease") != "wfl_source_completed_child" || json.NewDecoder(req.Body).Decode(&raw) != nil || json.Unmarshal(raw, &body) != nil || model.WorkspaceDigest(body.Binding) != model.WorkspaceDigest(f.actual.Binding) || body.AssignmentID != "source_child_assignment" || req.Header.Get("Idempotency-Key") != body.RequestID {
		f.t.Fatal("normal worker result borrowed authority or changed original")
	}
	if body.Result.Outcome != "completed" || len(body.Result.ConsumedRefs) != 1 || len(body.Result.Outputs) != 1 || len(body.Result.StateEvidence) != 0 || len(body.Result.EffectReceipts) != 0 || len(body.Result.RemainingWork) != 0 {
		f.t.Fatal("normal result missing original evidence")
	}
	read := body.Result.ConsumedRefs[0]
	output := body.Result.Outputs[0]
	if read.Reference != s.source.artifact.approved[0] || read.ReadReceipt.ReceiptID != s.originals[0].Receipt.ReceiptID || read.ReadReceipt.ReceiptDigest != s.originals[0].Receipt.ReceiptDigest || output.Type != "document" || output.Output.ArtifactID != "artifact_source_document" || output.Output.Digest != s.source.artifact.capture.Artifact.Digest || output.Output.ByteCount != len(s.source.artifact.content) {
		f.t.Fatal("normal result invented read credit or artifact")
	}
	s.body = raw
	s.source.results++
	if os.Getenv("WARPMETAL_CHILD_RESULT_LOST_ACK_SOURCE") == "1" {
		http.Error(w, "SOURCE lost result acknowledgement", 503)
		return true
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	digest := model.WorkspaceDigest(map[string]json.RawMessage{"binding": fields["binding"], "assignmentId": fields["assignmentId"], "result": fields["result"]})
	_ = json.NewEncoder(w).Encode(map[string]any{"formatVersion": 1, "resultId": "result_source_document", "resultRevision": 1, "resultDigest": digest, "executionId": f.actualExecution(), "assignmentId": body.AssignmentID, "state": "reported", "createdAt": f.r.now().Format(time.RFC3339Nano)})
	return true
}

func (s *childCompletionResultSource) assertLostAcknowledgement(t *testing.T, path string, manifest model.Manifest, first error) {
	t.Helper()
	f := s.source.f
	if first == nil || errors.Is(first, ErrControllerFirstTaskPending) {
		t.Fatal("lost result ACK became success", first)
	}
	s.source.assertEnrolled(t)
	f.effectStatus = "settled"
	check := func() {
		t.Helper()
		if err := f.r.Reconcile(context.Background(), manifest); !errors.Is(err, state.ErrOwnedContinuationUnknown) {
			t.Fatal("result UNKNOWN bypassed by later snapshot", err)
		}
		s.source.artifact.assertUploaded(t)
		if s.source.results != 1 || s.source.operations != 1 || s.source.proofs != 1 || s.source.enrollments != 1 || s.source.facts.operations != 1 || s.source.facts.proofs != 1 || s.source.facts.reports != 1 {
			t.Fatal("pending result allowed another completion effect")
		}
	}
	check()
	if err := f.r.Store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	f.r.Store = reopened
	f.r.ManagedCatalog.(*workspacecatalog.Catalog).State = reopened
	s.source.runtime.parentSourceRuntime.store = reopened
	check()
}
