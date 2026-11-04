package reconcile

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

func (c *workerExecuteSourceControl) WorkflowObservationOperation(ctx context.Context, call model.WorkflowCaptureRequest, revision int64) (model.WorkflowCaptureOperation, error) {
	return c.client.WorkflowObservationOperation(ctx, call, revision)
}
func (c *workerExecuteSourceControl) ReportWorkflowObservation(ctx context.Context, envelope model.WorkflowObservationEnvelope) (model.WorkflowObservationReceipt, error) {
	return c.client.ReportWorkflowObservation(ctx, envelope)
}
func (c *workerExecuteSourceControl) CurrentCellProductWorkflowSnapshot(context.Context, model.CellServiceV3) (json.RawMessage, error) {
	return c.source.snapshot, nil
}

// Deliberately detached SOURCE signer, using the fresh fixture key. The complete
// file, signed proof, actual TLS ACK and retained originals are exercised; ROOT
// identity and protected custody remain the separate installed gate.
func (r *workerExecuteSourceRuntime) ReadCellProductApprovedSource(_ context.Context, _ model.Sandbox, entry model.CellServiceV3, _ model.Manifest, input []byte, root qualification.TrustedWorkspace, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
	s := r.source
	reference, expected := s.fixture.WorkerSourceReference, s.fixture.WorkerSourceBytes
	if s.integrator {
		var observation struct{ Reference model.ControllerPlanReference }
		if json.Unmarshal(call.Operation.Observation, &observation) != nil {
			return model.WorkflowObservationEnvelope{}, qualification.WorkflowSourceCapture{}, errors.New("SOURCE reference")
		}
		reference = observation.Reference
		expected = s.integrationBodies[reference.Path]
	}
	return r.readSourceFixture(entry, input, root, call, op, snapshot, reference, expected)
}

func (r *workerExecuteSourceRuntime) readSourceFixture(entry model.CellServiceV3, input []byte, root qualification.TrustedWorkspace, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage, reference model.ControllerPlanReference, expected []byte) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
	s := r.source
	raw, err := os.ReadFile(filepath.Join(root.HostRoot, reference.Path))
	if err != nil {
		return model.WorkflowObservationEnvelope{}, qualification.WorkflowSourceCapture{}, err
	}
	if !bytes.Equal(raw, expected) || !op.MatchesCurrentSnapshot(snapshot) || !bytes.Equal(input, s.fixture.Witness.Input) {
		return model.WorkflowObservationEnvelope{}, qualification.WorkflowSourceCapture{}, errors.New("SOURCE original source changed")
	}
	info, err := os.Stat(filepath.Join(root.HostRoot, reference.Path))
	if err != nil {
		return model.WorkflowObservationEnvelope{}, qualification.WorkflowSourceCapture{}, err
	}
	stat := info.Sys().(*syscall.Stat_t)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	request := fixtureRaw(map[string]any{"binding": call.Binding, "reconciles": nil, "observation": call.Operation.Observation})
	var binding struct{ NativeLocationDigest string }
	_ = json.Unmarshal(call.Binding, &binding)
	native := model.WorkflowNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: entry.ServiceRegistrationID, ServiceGeneration: entry.ServiceGeneration, NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID, NativeLocationDigest: binding.NativeLocationDigest, Role: entry.Role, RootAttestation: entry.Workspace.RootAttestation, ObservedAt: stamp, Readback: request}
	payload := model.WorkflowObservationPayload{FormatVersion: 1, Purpose: "workspace_workflow_observation", RequestID: call.RequestID, TaskID: s.fixture.Witness.Applicability.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: model.WorkspaceDigest("explicit SOURCE managed receipt"), NativeReceipt: native, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Request: request}
	block, _ := pem.Decode(s.fixture.ProducerPrivatePEM)
	if block == nil {
		return model.WorkflowObservationEnvelope{}, qualification.WorkflowSourceCapture{}, errors.New("SOURCE key absent")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return model.WorkflowObservationEnvelope{}, qualification.WorkflowSourceCapture{}, err
	}
	canonical, _ := model.WorkspaceCanonicalJSON(payload)
	sum := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), sum[:])
	if err != nil {
		return model.WorkflowObservationEnvelope{}, qualification.WorkflowSourceCapture{}, err
	}
	s.envelope = model.WorkflowObservationEnvelope{Payload: payload, KeyID: s.fixture.Witness.Root.Producer.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}
	s.reads++
	return s.envelope, qualification.WorkflowSourceCapture{OperationDigest: op.OperationDigest, ScopeDigest: model.WorkspaceDigest(reference), RootDevice: root.Device, RootInode: root.Inode, SourceDevice: uint64(stat.Dev), SourceInode: stat.Ino, Bytes: raw, ObservedAt: stamp}, nil
}
func (r *workerExecuteSourceRuntime) RetainCellProductSourceRead(_ context.Context, _ model.Sandbox, _ model.CellServiceV3, _ model.Manifest, _ []byte, envelope model.WorkflowObservationEnvelope, read qualification.WorkflowSourceCapture, receipt model.WorkflowObservationReceipt) error {
	s := r.source
	if model.WorkspaceDigest(envelope) != model.WorkspaceDigest(s.envelope) || receipt != s.receipt || !bytes.Equal(read.Bytes, s.fixture.WorkerSourceBytes) {
		return errors.New("SOURCE own read/ACK changed")
	}
	s.retained++
	return os.WriteFile(filepath.Join(s.root, "own-source-original.json"), fixtureRaw(qualification.ChildSourceReadOriginal{Envelope: envelope, Receipt: receipt}), 0600)
}
func (r *workerExecuteSourceRuntime) ReadCellProductSourceReceipts(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte) ([]qualification.ChildSourceReadOriginal, error) {
	raw, err := os.ReadFile(filepath.Join(r.source.root, "own-source-original.json"))
	if err != nil {
		return nil, err
	}
	var original qualification.ChildSourceReadOriginal
	if json.Unmarshal(raw, &original) != nil {
		return nil, errors.New("SOURCE original read decode")
	}
	return []qualification.ChildSourceReadOriginal{original}, nil
}

type workerSourceCatalog struct {
	*workspacecatalog.Catalog
	project workspacecatalog.RegisteredProject
}

func (c workerSourceCatalog) Resolve(context.Context, workspacecatalog.ResolveProjectRequest) (workspacecatalog.RegisteredProject, error) {
	return c.project, nil
}

func (s *workerExecuteSource) serveObservation(rw http.ResponseWriter, req *http.Request) bool {
	base := "/internal/runtime/workspace-workflow-observations"
	if req.Method != "POST" || !strings.HasPrefix(req.URL.Path, base) {
		return false
	}
	rw.Header().Set("Content-Type", "application/json")
	if req.URL.Path == base+"/operations" {
		var call model.WorkflowCaptureRequest
		if json.NewDecoder(req.Body).Decode(&call) != nil || model.WorkspaceDigest(call.Binding) != model.WorkspaceDigest(s.fixture.Witness.Binding) {
			s.t.Fatal("SOURCE operation binding")
		}
		token := s.sourceNodeToken
		if token == "" {
			token = "SOURCE_node"
		}
		s.op = model.WorkflowCaptureOperation{FormatVersion: 1, OperationID: "wfop_source_read_" + model.WorkspaceDigest(call)[7:39], Binding: call.Binding, Operation: call.Operation, Snapshot: s.snapshot, NodeTokenHash: strings.TrimPrefix(model.RawPhysicalDigest([]byte(token)), "sha256:"), RuntimeRevision: s.fixture.Witness.Root.RuntimeRevision, ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
		s.op.OperationDigest = fixtureDigestField(s.op, "operationDigest")
		s.operations++
		_ = json.NewEncoder(rw).Encode(s.op)
		return true
	}
	if req.URL.Path == base+"/proofs" {
		var original model.WorkflowObservationEnvelope
		if json.NewDecoder(req.Body).Decode(&original) != nil || model.WorkspaceDigest(original) != model.WorkspaceDigest(s.envelope) || original.Validate() != nil {
			s.t.Fatal("SOURCE first proof changed")
		}
		block, _ := pem.Decode(s.fixture.Witness.ProducerPEM)
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			s.t.Fatal(err)
		}
		raw, _ := model.WorkspaceCanonicalJSON(original.Payload)
		sum := sha256.Sum256(raw)
		sig, _ := base64.StdEncoding.Strict().DecodeString(original.Signature)
		if !ecdsa.VerifyASN1(key.(*ecdsa.PublicKey), sum[:], sig) {
			s.t.Fatal("SOURCE proof signature")
		}
		s.proofs++
		_ = json.NewEncoder(rw).Encode(map[string]any{"formatVersion": 1, "proofId": "proof_source_worker", "proofDigest": model.WorkspaceDigest(original), "expiresAt": original.Payload.NotAfter})
		return true
	}
	var binding struct{ ExecutionID string }
	_ = json.Unmarshal(s.fixture.Witness.Binding, &binding)
	if req.URL.Path == base+"/executions/"+binding.ExecutionID+"/receipts" {
		var call model.WorkflowObservationRequest
		if json.NewDecoder(req.Body).Decode(&call) != nil || model.WorkspaceDigest(call.Binding) != model.WorkspaceDigest(s.op.Binding) || model.WorkspaceDigest(call.Observation) != model.WorkspaceDigest(s.op.Operation.Observation) {
			s.t.Fatal("SOURCE ACK request changed")
		}
		s.receipt = model.WorkflowObservationReceipt{FormatVersion: 1, ReceiptID: "receipt_source_" + s.op.OperationDigest[7:39], ReceiptDigest: model.WorkspaceDigest(call), ExecutionID: binding.ExecutionID, Type: "source_read", Status: "settled", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		s.reports++
		_ = json.NewEncoder(rw).Encode(s.receipt)
		return true
	}
	return false
}
