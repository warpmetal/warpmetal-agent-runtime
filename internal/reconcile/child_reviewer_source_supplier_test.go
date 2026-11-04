package reconcile

// These suppliers exercise the normal coordinator over real TLS/files/SQLite.
// Fresh SOURCE native identity and ECDSA are explicit doubles of ROOT custody;
// neither the model fixtures nor these helpers grant installed authority.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
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

type reviewerSourceOriginals struct {
	TargetDetail                                json.RawMessage
	Artifact                                    json.RawMessage
	Reference                                   model.ControllerPlanReference
	TargetBase64, CandidateBase64, PacketBase64 []byte
}

func (r *reviewerPreparedSourceRuntime) control() qualification.ChildProductControl {
	var c qualification.ChildProductControl
	if json.Unmarshal(r.source.delivery.Bytes(), &c) != nil {
		r.source.t.Fatal("SOURCE current reviewer control")
	}
	return c
}
func (r *reviewerPreparedSourceRuntime) sourceKey() *ecdsa.PrivateKey {
	b, _ := pem.Decode(r.source.fixture.ProducerPrivatePEM)
	if b == nil {
		r.source.t.Fatal("SOURCE private signer absent")
	}
	k, e := x509.ParsePKCS8PrivateKey(b.Bytes)
	if e != nil {
		r.source.t.Fatal(e)
	}
	return k.(*ecdsa.PrivateKey)
}
func (r *reviewerPreparedSourceRuntime) verifyRole(proof model.WorkflowRoleEnvelope) {
	raw, _ := model.WorkspaceCanonicalJSON(proof.Payload)
	sum := sha256.Sum256(raw)
	sig, e := base64.StdEncoding.Strict().DecodeString(proof.Signature)
	if e != nil || proof.Validate() != nil || !ecdsa.VerifyASN1(&r.sourceKey().PublicKey, sum[:], sig) {
		r.source.t.Fatal("SOURCE role original signature")
	}
}
func (r *reviewerPreparedSourceRuntime) AttestPreparedCellWorkflowRole(ctx context.Context, op model.WorkflowRoleOperation, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, delivery model.ChildProductDelivery, root workspacecatalog.RegisteredProject, snapshot json.RawMessage) (model.WorkflowRoleEnvelope, error) {
	s := r.source
	local, e := r.store.CellV3Execution(ctx, entry.PreparationID)
	prepared, e2 := r.store.CellV3Operation(ctx, entry.PreparationID)
	if e != nil || e2 != nil || local != nil || prepared == nil || prepared.Phase != "reported" || prepared.Receipt != *s.fixture.Witness.ActualReceipt || op.Validate() != nil || op.Subject.Role != "reviewer" || box.ID != entry.SandboxID || root.Report.Availability != "available" || !bytes.Equal(input, s.fixture.Witness.Input) || model.WorkspaceDigest(snapshot) != model.WorkspaceDigest(s.snapshot) {
		return model.WorkflowRoleEnvelope{}, errors.New("SOURCE prepared owner/identity changed")
	}
	if e = s.verifyPublishedSource(entry, delivery, input); e != nil {
		return model.WorkflowRoleEnvelope{}, e
	}
	var binding struct{ NativeLocationDigest string }
	_ = json.Unmarshal(s.fixture.Witness.Binding, &binding)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	p := model.WorkflowRolePayload{FormatVersion: 1, Purpose: "workspace_workflow_role", RequestID: "wfrole_receipt_" + op.OperationDigest[7:39], TaskID: op.Subject.TaskID, NodeTokenHash: op.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: op.ManagedServiceReceiptDigest, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Subject: op.Subject, NativeContextDigest: op.NativeContextDigest, NativeReceipt: model.WorkflowRoleNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: entry.ServiceRegistrationID, ServiceGeneration: entry.ServiceGeneration, NativeSessionID: entry.NativeSessionID, NativeProjectID: entry.NativeProjectID, NativeLocationDigest: binding.NativeLocationDigest, Role: entry.Role, RootAttestation: entry.Workspace.RootAttestation, ObservedAt: stamp, Readback: model.WorkflowRoleReadback{Subject: op.Subject, NativeContextDigest: op.NativeContextDigest}}}
	var proof model.WorkflowRoleEnvelope
	if json.Unmarshal(sourceSigned(s.t, r.sourceKey(), s.fixture.Witness.Root.Producer.KeyID, p), &proof) != nil {
		s.t.Fatal("SOURCE proof decode")
	}
	r.identities++
	return proof, nil
}
func (r *reviewerPreparedSourceRuntime) ApprovedCellProductReviewerSources(_ context.Context, _ model.Sandbox, entry model.CellServiceV3, _ model.Manifest, input []byte, delivery model.ChildProductDelivery) (qualification.ReviewerSourceSelection, error) {
	if e := r.source.verifyPublishedSource(entry, delivery, input); e != nil {
		return qualification.ReviewerSourceSelection{}, e
	}
	r.source.selected++
	if !r.source.allowRead {
		return qualification.ReviewerSourceSelection{}, errors.New("SOURCE own reviewer read custody unavailable")
	}
	return r.control().ReviewerSources()
}
func (r *reviewerPreparedSourceRuntime) ApprovedCellProductSourceReads(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte) ([]qualification.ChildApprovedSourceRead, error) {
	if r.source.adopted == 0 {
		return nil, errors.New("SOURCE reviewer not adopted")
	}
	return nil, qualification.ErrWorkerSourceNotApplicable
}
func (r *reviewerPreparedSourceRuntime) ReadCellProductSource(_ context.Context, _ model.Sandbox, entry model.CellServiceV3, _ model.Manifest, input []byte, root qualification.TrustedWorkspace, _ model.ChildProductDelivery, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
	if r.enrollments != 1 {
		return model.WorkflowObservationEnvelope{}, qualification.WorkflowSourceCapture{}, errors.New("SOURCE read before own enrollment")
	}
	var obs struct{ Reference model.ControllerPlanReference }
	_ = json.Unmarshal(call.Operation.Observation, &obs)
	return r.readSourceFixture(entry, input, root, call, op, snapshot, obs.Reference, r.bodies[model.WorkspaceDigest(obs.Reference)])
}
func (r *reviewerPreparedSourceRuntime) RetainCellProductObservationReceipt(_ context.Context, p model.WorkflowObservationEnvelope, ack model.WorkflowObservationReceipt) error {
	if model.WorkspaceDigest(p) != model.WorkspaceDigest(r.source.envelope) || ack != r.source.receipt {
		return errors.New("SOURCE first ACK mismatch")
	}
	return nil
}
func (r *reviewerPreparedSourceRuntime) retain(reference model.ControllerPlanReference, p model.WorkflowObservationEnvelope, ack model.WorkflowObservationReceipt) error {
	raw := fixtureRaw(qualification.ChildSourceReadOriginal{Envelope: p, Receipt: ack})
	name := filepath.Join(r.source.root, "reviewer-own-"+model.WorkspaceDigest(reference)[7:]+".json")
	f, e := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(raw); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	r.source.retained++
	return nil
}
func (r *reviewerPreparedSourceRuntime) RetainCellProductReviewerRead(ctx context.Context, _ model.CellServiceV3, _ model.Manifest, _ []byte, _ model.ChildProductDelivery, p model.WorkflowObservationEnvelope, read qualification.WorkflowSourceCapture, ack model.WorkflowObservationReceipt) error {
	if e := r.RetainCellProductObservationReceipt(ctx, p, ack); e != nil {
		return e
	}
	var req struct {
		Observation struct{ Reference model.ControllerPlanReference }
	}
	_ = json.Unmarshal(p.Payload.Request, &req)
	if !bytes.Equal(read.Bytes, r.bodies[model.WorkspaceDigest(req.Observation.Reference)]) {
		return errors.New("SOURCE physical read bytes changed")
	}
	return r.retain(req.Observation.Reference, p, ack)
}
func (r *reviewerPreparedSourceRuntime) ReadCellProductReviewerArtifact(ctx context.Context, _ model.Sandbox, entry model.CellServiceV3, _ model.Manifest, input []byte, _ workspacecatalog.RegisteredProject, _ model.ChildProductDelivery, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage, fetch qualification.ReviewerArtifactTransport, lease string) (model.WorkflowObservationEnvelope, qualification.ReviewerArtifactCapture, error) {
	var empty model.WorkflowObservationEnvelope
	var no qualification.ReviewerArtifactCapture
	if r.enrollments != 1 || lease != "wfl_source_prepared_reviewer" {
		return empty, no, errors.New("SOURCE foreign read lease")
	}
	q := r.control().Generation.Policy.Payload
	var authority struct {
		Target, Artifact json.RawMessage
		Reference        model.ControllerPlanReference
		Binding          struct{ ExecutionID string }
	}
	_ = json.Unmarshal(q.ArtifactReads[0], &authority)
	detail, e := fetch.ReadWorkflowResult(ctx, authority.Target, lease)
	if e != nil {
		return empty, no, e
	}
	body, e := fetch.FetchWorkflowArtifact(ctx, authority.Binding.ExecutionID, authority.Artifact, lease)
	if e != nil {
		return empty, no, e
	}
	if model.WorkspaceDigest(detail) != model.WorkspaceDigest(r.originals.TargetDetail) || !bytes.Equal(body, r.originals.TargetBase64) {
		return empty, no, errors.New("SOURCE original artifact changed")
	}
	// Private original bytes are never read from the candidate's physical path.
	private := filepath.Join(r.source.root, "reviewer-private-original")
	if e = os.Mkdir(private, 0700); e != nil {
		return empty, no, e
	}
	leaf := filepath.Join(private, authority.Reference.Path)
	if e = os.MkdirAll(filepath.Dir(leaf), 0700); e != nil {
		return empty, no, e
	}
	if e = os.WriteFile(leaf, body, 0600); e != nil {
		return empty, no, e
	}
	st, e := os.Stat(private)
	if e != nil {
		return empty, no, e
	}
	id := st.Sys().(*syscall.Stat_t)
	proof, capture, e := r.readSourceFixture(entry, input, qualification.TrustedWorkspace{HostRoot: private, Device: uint64(id.Dev), Inode: id.Ino}, call, op, snapshot, authority.Reference, body)
	if e != nil {
		return empty, no, e
	}
	return proof, qualification.ReviewerArtifactCapture{OperationDigest: op.OperationDigest, EntryDigest: model.WorkspaceDigest(entry), GenerationDigest: r.source.delivery.GenerationDigest(), AuthorityDigest: model.WorkspaceDigest(q.ArtifactReads[0]), InputID: entry.ExecutionGrant.InputID, InputDigest: model.RawPhysicalDigest(input), TargetDetailDigest: model.WorkspaceDigest(detail), DirectoryDevice: uint64(id.Dev), DirectoryInode: id.Ino, BodyDevice: capture.SourceDevice, BodyInode: capture.SourceInode, Bytes: body, ObservedAt: capture.ObservedAt}, nil
}
func (r *reviewerPreparedSourceRuntime) RetainCellProductReviewerArtifact(ctx context.Context, _ model.Sandbox, _ model.CellServiceV3, _ model.Manifest, _ []byte, _ model.ChildProductDelivery, p model.WorkflowObservationEnvelope, read qualification.ReviewerArtifactCapture, ack model.WorkflowObservationReceipt) error {
	if e := r.RetainCellProductObservationReceipt(ctx, p, ack); e != nil {
		return e
	}
	if !bytes.Equal(read.Bytes, r.originals.TargetBase64) {
		return errors.New("SOURCE immutable original bytes changed")
	}
	var req struct {
		Observation struct{ Reference model.ControllerPlanReference }
	}
	_ = json.Unmarshal(p.Payload.Request, &req)
	return r.retain(req.Observation.Reference, p, ack)
}
func (r *reviewerPreparedSourceRuntime) ReadCellProductReviewerReceipts(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte, model.ChildProductDelivery) (qualification.ReviewerReadOriginals, error) {
	var out qualification.ReviewerReadOriginals
	selected, e := r.control().ReviewerSources()
	if e != nil {
		return out, e
	}
	read := func(ref model.ControllerPlanReference) (qualification.ChildSourceReadOriginal, error) {
		var v qualification.ChildSourceReadOriginal
		raw, e := os.ReadFile(filepath.Join(r.source.root, "reviewer-own-"+model.WorkspaceDigest(ref)[7:]+".json"))
		if e != nil {
			return v, e
		}
		e = model.DecodePhysicalClosed(raw, &v)
		return v, e
	}
	for _, v := range selected.Physical {
		own, e := read(v.Reference)
		if e != nil {
			return out, e
		}
		out.Physical = append(out.Physical, own)
	}
	out.Artifact, e = read(selected.Artifact.Reference)
	return out, e
}
func (r *reviewerPreparedSourceRuntime) AdoptCellProductControl(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, d model.ChildProductDelivery, input []byte) (string, error) {
	if e := r.source.verifyPublishedSource(entry, d, input); e != nil {
		return "", e
	}
	own, e := r.ReadCellProductReviewerReceipts(ctx, box, entry, current, input, d)
	if e != nil || len(own.Physical) != 2 || own.Artifact.Receipt.ReceiptID == "" || r.enrollments != 1 {
		return "", errors.New("SOURCE reviewer own read custody missing before strict adoption")
	}
	r.source.adopted++
	return d.GenerationDigest(), nil
}
func (r *reviewerPreparedSourceRuntime) serve(rw http.ResponseWriter, req *http.Request) bool {
	s := r.source
	if req.Header.Get("Authorization") != "Bearer synthetic-node" {
		return false
	}
	base := "/internal/runtime/workspace-workflow/"
	if req.Method == "GET" && req.Header.Get("X-WarpMetal-Workflow-Lease") == "wfl_source_prepared_reviewer" {
		q := r.control().Generation.Policy.Payload
		var a struct {
			Target   struct{ ResultID string }
			Artifact struct{ ArtifactID, Digest, ContentType string }
			Binding  struct{ ExecutionID string }
		}
		_ = json.Unmarshal(q.ArtifactReads[0], &a)
		switch req.URL.Path {
		case base + "results/" + a.Target.ResultID:
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write(r.originals.TargetDetail)
		case base + "executions/" + a.Binding.ExecutionID + "/artifacts/" + a.Artifact.ArtifactID:
			rw.Header().Set("Content-Type", a.Artifact.ContentType)
			rw.Header().Set("X-Content-Digest", a.Artifact.Digest)
			_, _ = rw.Write(r.originals.TargetBase64)
		default:
			return false
		}
		r.targetGets++
		return true
	}
	if req.Header.Get("X-WarpMetal-Workflow-Lease") != "" {
		return false
	}
	if req.Method == "POST" && req.URL.Path == base+"enrollment-operations" {
		var call model.WorkflowRoleOperationRequest
		if json.NewDecoder(req.Body).Decode(&call) != nil || call.Subject.Role != "reviewer" {
			s.t.Fatal("SOURCE reviewer role request")
		}
		var current struct{ NativeContextDigest, ManagedServiceReceiptDigest string }
		_ = json.Unmarshal(s.snapshot, &current)
		r.op = model.WorkflowRoleOperation{FormatVersion: 1, OperationID: "wfroleop_source_prepared_reviewer", Subject: call.Subject, NativeContextDigest: current.NativeContextDigest, ManagedServiceReceiptDigest: current.ManagedServiceReceiptDigest, NodeTokenHash: strings.TrimPrefix(model.RawPhysicalDigest([]byte("synthetic-node")), "sha256:"), ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
		r.op.OperationDigest = fixtureDigestField(r.op, "operationDigest")
		r.roleHTTP++
		_ = json.NewEncoder(rw).Encode(r.op)
		return true
	}
	if req.Method == "POST" && req.URL.Path == base+"enroll" {
		var p model.WorkflowRoleEnvelope
		if json.NewDecoder(req.Body).Decode(&p) != nil || p.Payload.OperationDigest != r.op.OperationDigest {
			s.t.Fatal("SOURCE reviewer proof")
		}
		r.verifyRole(p)
		r.enrollments++
		_ = json.NewEncoder(rw).Encode(model.WorkflowRoleEnrollment{FormatVersion: 1, RoleBindingID: "wrole_source_prepared_reviewer", RoleBindingRevision: 1, ExpiresAt: p.Payload.NotAfter, Lease: "wfl_source_prepared_reviewer"})
		return true
	}
	return s.serveObservation(rw, req)
}

var _ reviewerPublishedSourceRuntime = (*reviewerPreparedSourceRuntime)(nil)
