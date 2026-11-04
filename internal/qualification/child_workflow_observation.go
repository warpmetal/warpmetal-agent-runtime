package qualification

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// CurrentSnapshot is independently observed by the owning protected lifecycle/
// workflow consumer, NEVER copied from op.Snapshot. Workspace is independently
// resolved through registered workspace/installed-script catalog, not Root JSON.
// Missing any current supplier denies; this DTO neither installs nor accepts it.
type ChildWorkflowObservationWitness struct {
	Authority       Store
	Sandbox         model.Sandbox
	Product         ChildProductWitness
	CurrentSnapshot json.RawMessage
	Workspace       TrustedWorkspace
	// Initial reviewer source reads only: exact node delivery is verified without
	// adopting a native selector. This is never a dispatch/installed witness.
	SourceReadDelivery *model.ChildProductDelivery
	// Actual protected native/provider assessment supplied by the fixed installed
	// capture adapter; reviewer artifact signing denies when it is absent.
	OriginalAssessment []byte
	// Fixed native coding terminal/effect capture, not an arbitrary output DTO.
	// Current signed control and a separate actual ROOT file read remain required.
	OriginalResult *model.ChildNativeResultCapture
	// Independent integration execution with its retained before-image; it is
	// never normalized into a coding result or an acceptance decision.
	OriginalIntegration *model.ChildNativeIntegrationCapture
}

func childInteger(fields map[string]json.RawMessage, key string) int64 {
	var value int64
	if json.Unmarshal(fields[key], &value) != nil || value < 0 || value > 9007199254740991 {
		return -1
	}
	return value
}

func (p *Producer) childObservationPolicy(call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, w ChildWorkflowObservationWitness) (ChildProductPolicy, error) {
	var empty ChildProductPolicy
	now := time.Now()
	if p == nil || p.key == nil || op.ValidateFor(call, p.config.NodeTokenHash, w.Product.Root.RuntimeRevision, now) != nil ||
		!op.MatchesCurrentSnapshot(w.CurrentSnapshot) || len(w.CurrentSnapshot) == 0 ||
		w.Product.Root.Producer != (model.WorkspaceRegisteredProducer{KeyID: p.config.KeyID, KeySHA256: p.config.KeySHA256, ServerID: p.config.ServerID, NodeTokenHash: p.config.NodeTokenHash}) {
		return empty, ErrUntrusted
	}
	var q ChildProductPolicy
	if w.SourceReadDelivery != nil {
		if childString(childFields(op.Operation.Observation), "type") != "source_read" {
			return empty, ErrUntrusted
		}
		var err error
		q, err = w.Authority.ChildProductSourceReadPolicy(w.Sandbox, *w.SourceReadDelivery, w.Product, now)
		if err != nil {
			return empty, err
		}
	} else {
		c, err := w.Authority.ReadChildProduct(w.Sandbox, w.Product.Preparation.PreparationID, w.Product, now)
		if err != nil || c.Generation.Phase != "execute" || c.Generation.Policy == nil {
			return empty, ErrUntrusted
		}
		q = c.Generation.Policy.Payload
	}
	if !sameProduct(q.Binding, op.Binding) {
		return empty, ErrUntrusted
	}
	role := map[string]string{"coding_worker": "worker", "business_worker": "worker", "integrator": "worker", "reviewer": "reviewer"}[q.Purpose]
	snapshot := childFields(w.CurrentSnapshot)
	if role == "" || childString(snapshot, "role") != role || !hash.MatchString(childString(snapshot, "managedServiceReceiptDigest")) ||
		childString(snapshot, "desiredState") != "active" || childInteger(snapshot, "desiredRevision") != w.Product.Entry.DesiredRevision {
		return empty, ErrUntrusted
	}
	return q, nil
}

// A separate reviewer-bound actual ROOT full read. This does not append firstText,
// stage a foreign sourcefile, call a model, borrow genesis/parent Work or certify
// author compilation. Only existing source_read grant/reference wire is signed.
func (p *Producer) ReadChildProductSource(ctx context.Context, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, w ChildWorkflowObservationWitness) (model.WorkflowObservationEnvelope, WorkflowSourceCapture, error) {
	var empty model.WorkflowObservationEnvelope
	var noRead WorkflowSourceCapture
	q, err := p.childObservationPolicy(call, op, w)
	if err != nil {
		return empty, noRead, err
	}
	observed := childFields(op.Operation.Observation)
	if childString(observed, "type") != "source_read" {
		return empty, noRead, ErrUntrusted
	}
	var scope *ChildSourceReadScope
	for i := range q.SourceReads {
		r := &q.SourceReads[i]
		g := childFields(r.Grant)
		if sameProduct(g["reference"], observed["reference"]) {
			if scope != nil {
				return empty, noRead, ErrUntrusted
			}
			scope = r
		}
	}
	if scope == nil {
		return empty, noRead, ErrUntrusted
	}
	g, r := childFields(scope.Grant), childFields(scope.Root)
	ref := childFields(g["reference"])
	if childString(observed, "observedDigest") != childString(ref, "sourceDigest") || childInteger(observed, "byteCount") != childInteger(g, "byteCount") ||
		w.Workspace.WorkspaceDigest != childString(r, "rootAttestation") || childString(g, "rootGrantDigest") != CanonicalDigest(scope.Root) ||
		!sameProduct(w.Product.SourceRoots[childString(g, "rootGrantDigest")], scope.Root) {
		return empty, noRead, ErrUntrusted
	}
	// Re-observe the real root even on replay. No operation-selected host path.
	root, err := confinedRoot(w.Workspace.HostRoot, w.Workspace.Device, w.Workspace.Inode)
	if err != nil {
		return empty, noRead, err
	}
	root.Close()
	journal := producerPlanJournal{p}
	prior, found, err := p.replayChildObservation(op, w)
	if err != nil {
		return empty, noRead, err
	}
	if found {
		claim := canonicalBytes(map[string]any{"operationDigest": op.OperationDigest, "scopeDigest": CanonicalDigest(*scope), "rootDevice": w.Workspace.Device, "rootInode": w.Workspace.Inode})
		fence, fe := journal.load("workflow-observation-"+op.OperationID+"-fence.json", 16384)
		if fe != nil || string(fence) != string(claim) {
			return empty, noRead, ErrUntrusted
		}
		raw, err := journal.load("workflow-observation-"+op.OperationID+"-read.json", 65536)
		var back WorkflowSourceCapture
		if err != nil || decode(raw, &back) != nil || !bytesCanonical(raw, back) || back.OperationDigest != op.OperationDigest || back.ScopeDigest != CanonicalDigest(*scope) || back.RootDevice != w.Workspace.Device || back.RootInode != w.Workspace.Inode || Digest(back.Bytes) != childString(ref, "sourceDigest") || int64(len(back.Bytes)) != childInteger(g, "byteCount") {
			return empty, noRead, ErrUntrusted
		}
		return prior, back, nil
	}
	// Existing read without the FIRST envelope is interrupted signing, not rerun.
	if _, err = os.Lstat(p.config.EvidenceRoot + "/workflow-observation-" + op.OperationID + "-read.json"); !errors.Is(err, os.ErrNotExist) {
		return empty, noRead, ErrUntrusted
	}
	back, err := captureWorkflowSource(ctx, op, *scope, w.Workspace, journal)
	if err != nil {
		return empty, noRead, err
	}
	if _, err = p.childObservationPolicy(call, op, w); err != nil || ctx.Err() != nil {
		return empty, noRead, ErrUntrusted
	}
	envelope, err := p.sealChildObservation(call, op, w, back.ObservedAt)
	return envelope, back, err
}

// DISTINCT own-Work artifact_read: only an already signed exact tool output or
// review assessment path can be selected. A source grant/read is never relabeled
// into this operation, and no ArtifactRef/receipt is manufactured by the reader.
func (p *Producer) ReadChildProductArtifact(ctx context.Context, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, w ChildWorkflowObservationWitness) (model.WorkflowObservationEnvelope, WorkflowSourceCapture, error) {
	var empty model.WorkflowObservationEnvelope
	var noRead WorkflowSourceCapture
	q, err := p.childObservationPolicy(call, op, w)
	if err != nil {
		return empty, noRead, err
	}
	observed := childFields(op.Operation.Observation)
	path := childString(observed, "sourcePath")
	digest := childString(observed, "digest")
	count := childInteger(observed, "byteCount")
	allowed := false
	for _, tool := range q.Tools {
		if tool.OutputPath == path {
			allowed = true
		}
	}
	if q.Purpose == "reviewer" && q.ReviewDelivery != nil && q.ReviewDelivery.AssessmentPath == path {
		allowed = true
	}
	if q.Purpose == "coding_worker" || q.Purpose == "integrator" {
		allowed = childResultArtifactAllowed(w, q, path, digest, count)
	}
	if childString(observed, "type") != "artifact_read" || !allowed || count < 0 || count > 16384 || w.Workspace.WorkspaceDigest != q.Root.Workspace.RootAttestation {
		return empty, noRead, ErrUntrusted
	}
	if q.Purpose == "reviewer" && (len(w.OriginalAssessment) == 0 || int64(len(w.OriginalAssessment)) != count || Digest(w.OriginalAssessment) != digest) {
		return empty, noRead, ErrUntrusted
	}
	root, err := confinedRoot(w.Workspace.HostRoot, w.Workspace.Device, w.Workspace.Inode)
	if err != nil {
		return empty, noRead, err
	}
	root.Close()
	scopeDigest := CanonicalDigest(map[string]any{"kind": "own_child_output", "binding": q.Binding, "root": q.Root, "sourcePath": path})
	journal := producerPlanJournal{p}
	name := "workflow-observation-" + op.OperationID
	if previous, found, err := p.replayChildObservation(op, w); err != nil {
		return empty, noRead, err
	} else if found {
		fence, err := journal.load(name+"-fence.json", 16384)
		claim := canonicalBytes(map[string]any{"operationDigest": op.OperationDigest, "scopeDigest": scopeDigest, "rootDevice": w.Workspace.Device, "rootInode": w.Workspace.Inode})
		if err != nil || string(fence) != string(claim) {
			return empty, noRead, ErrUntrusted
		}
		back, err := captureWorkflowFile(ctx, op, path, int(count), digest, scopeDigest, w.Workspace, journal)
		if q.Purpose == "reviewer" && !bytes.Equal(back.Bytes, w.OriginalAssessment) {
			return empty, noRead, ErrUntrusted
		}
		return previous, back, err
	}
	if _, err = os.Lstat(p.config.EvidenceRoot + "/" + name + "-read.json"); !errors.Is(err, os.ErrNotExist) {
		return empty, noRead, ErrUntrusted
	}
	back, err := captureWorkflowFile(ctx, op, path, int(count), digest, scopeDigest, w.Workspace, journal)
	if err != nil {
		return empty, noRead, err
	}
	if ctx.Err() != nil {
		return empty, noRead, ErrUntrusted
	}
	if q.Purpose == "reviewer" && !bytes.Equal(back.Bytes, w.OriginalAssessment) {
		return empty, noRead, ErrUntrusted
	}
	envelope, err := p.sealChildObservation(call, op, w, back.ObservedAt)
	return envelope, back, err
}

// Operation-specific native tool proof already joined by protected Supervisor to
// consumed authority, SQLite DATA0..cursor, assistant context and original leaf.
// This method does NOT execute tools or accept arbitrary payloads/readbacks.
func (p *Producer) AttestChildProductEffect(call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, w ChildWorkflowObservationWitness, proof json.RawMessage) (model.WorkflowObservationEnvelope, error) {
	var empty model.WorkflowObservationEnvelope
	q, err := p.childObservationPolicy(call, op, w)
	if err != nil || q.Purpose != "business_worker" || len(proof) > 65536 {
		return empty, ErrUntrusted
	}
	fields := childFields(proof)
	snapshot := childFields(op.Snapshot)
	join := childFields(snapshot["childToolCaptureJoin"])
	kind := childString(childFields(op.Operation.Observation), "type")
	if kind != "mcp_read" && kind != "script_run" || workflowcontract.Validate(workflowcontract.Manager, "childToolCaptureJoin", snapshot["childToolCaptureJoin"]) != nil ||
		childString(join, "operationId") != op.OperationID || !sameProduct(join["binding"], op.Binding) || !sameProduct(fields["observation"], op.Operation.Observation) ||
		childString(fields, "permitDigest") != childString(join, "permitDigest") || childString(fields, "invocationApprovalDigest") != childString(join, "invocationApprovalDigest") ||
		childString(fields, "bindingDigest") != CanonicalDigest(q.Binding) || childString(fields, "owningInputId") != q.Instructions.InputID || childString(fields, "inputDigest") != q.Instructions.InputDigest ||
		!safeID.MatchString(childString(fields, "assistantMessageId")) || !safeID.MatchString(childString(fields, "nativeCallId")) || childInteger(fields, "enqueueSeq") < 1 || childInteger(fields, "owningStartSeq") <= childInteger(fields, "enqueueSeq") || childInteger(fields, "calledSeq") <= childInteger(fields, "owningStartSeq") || childInteger(fields, "logCursor") < childInteger(fields, "calledSeq") {
		return empty, ErrUntrusted
	}
	if previous, found, err := p.replayChildObservation(op, w); err != nil {
		return empty, err
	} else if found {
		fence, err := p.read("workflow-observation-"+op.OperationID+"-fence.json", 16384)
		if err != nil || string(fence) != string(canonicalBytes(map[string]string{"operationDigest": op.OperationDigest})) {
			return empty, ErrUntrusted
		}
		raw, err := p.read("workflow-observation-"+op.OperationID+"-effect.json", 65536)
		if err != nil || !sameProduct(json.RawMessage(raw), proof) {
			return empty, ErrUntrusted
		}
		return previous, nil
	}
	// Exclusive fence; interrupted capture/signature stays unknown, never retried.
	name := "workflow-observation-" + op.OperationID
	if p.create(name+"-fence.json", canonicalBytes(map[string]string{"operationDigest": op.OperationDigest})) != nil || p.create(name+"-effect.json", canonicalBytes(proof)) != nil {
		return empty, ErrUntrusted
	}
	return p.sealChildObservation(call, op, w, time.Now().UTC().Format(time.RFC3339Nano))
}

func (p *Producer) replayChildObservation(op model.WorkflowCaptureOperation, w ChildWorkflowObservationWitness) (model.WorkflowObservationEnvelope, bool, error) {
	var empty model.WorkflowObservationEnvelope
	name := "workflow-observation-" + op.OperationID + "-envelope.json"
	if _, err := os.Lstat(p.config.EvidenceRoot + "/" + name); errors.Is(err, os.ErrNotExist) {
		return empty, false, nil
	} else if err != nil {
		return empty, false, ErrUntrusted
	}
	raw, err := p.read(name, 65536)
	var previous model.WorkflowObservationEnvelope
	request := canonicalBytes(map[string]any{"binding": op.Binding, "reconciles": op.Operation.Reconciles, "observation": op.Operation.Observation})
	if err != nil || decode(raw, &previous) != nil || !bytesCanonical(raw, previous) || previous.Validate() != nil || previous.KeyID != p.config.KeyID || previous.Payload.OperationDigest != op.OperationDigest || previous.Payload.OperationID != op.OperationID || !sameProduct(previous.Payload.Request, json.RawMessage(request)) || previous.Payload.ManagedServiceReceiptDigest != childString(childFields(w.CurrentSnapshot), "managedServiceReceiptDigest") {
		return empty, false, ErrUntrusted
	}
	body, _ := model.WorkspaceCanonicalJSON(previous.Payload)
	sum := sha256.Sum256(body)
	sig, err := base64.StdEncoding.Strict().DecodeString(previous.Signature)
	if err != nil || !ecdsa.VerifyASN1(&p.key.PublicKey, sum[:], sig) {
		return empty, false, ErrUntrusted
	}
	return previous, true, nil
}

// Only after the unchanged node proof/receipt transports acknowledge the FIRST
// signed envelope. Durable private ACK storage permits ordinal1 lookup without
// inventing an accepted row or accepting an approval's receipt as physical truth.
func (p *Producer) verifyChildObservationReceipt(envelope model.WorkflowObservationEnvelope, receipt model.WorkflowObservationReceipt) error {
	if p == nil || p.key == nil || envelope.Validate() != nil || envelope.KeyID != p.config.KeyID || envelope.Payload.NodeTokenHash != p.config.NodeTokenHash || !safeID.MatchString(receipt.ReceiptID) {
		return ErrUntrusted
	}
	raw, err := p.read("workflow-observation-"+envelope.Payload.OperationID+"-envelope.json", 65536)
	if err != nil || !sameProduct(json.RawMessage(raw), envelope) {
		return ErrUntrusted
	}
	body, _ := model.WorkspaceCanonicalJSON(envelope.Payload)
	sum := sha256.Sum256(body)
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || !ecdsa.VerifyASN1(&p.key.PublicKey, sum[:], signature) {
		return ErrUntrusted
	}
	raw, err = json.Marshal(receipt)
	request := childFields(envelope.Payload.Request)
	observation := childFields(request["observation"])
	status := childString(observation, "status")
	if status == "" {
		status = "settled"
	}
	if err != nil || workflowcontract.Validate(workflowcontract.Domain, "observationReceipt", raw) != nil || receipt.ExecutionID != childString(childFields(request["binding"]), "executionId") || receipt.Type != childString(observation, "type") || receipt.Status != status {
		return ErrUntrusted
	}
	return nil
}

func (p *Producer) RetainChildObservationReceipt(envelope model.WorkflowObservationEnvelope, receipt model.WorkflowObservationReceipt) error {
	if err := p.verifyChildObservationReceipt(envelope, receipt); err != nil {
		return err
	}
	return p.append("workflow-observation-receipt-"+receipt.ReceiptID+".json", canonicalBytes(struct {
		Envelope model.WorkflowObservationEnvelope `json:"envelope"`
		Receipt  model.WorkflowObservationReceipt  `json:"receipt"`
	}{envelope, receipt}))
}

func (p *Producer) ChildEffectPredecessor(reference json.RawMessage, binding json.RawMessage) (ChildEffectPredecessor, error) {
	var empty ChildEffectPredecessor
	fields := childFields(reference)
	id := childString(fields, "receiptId")
	if p == nil || !safeID.MatchString(id) {
		return empty, ErrUntrusted
	}
	raw, err := p.read("workflow-observation-receipt-"+id+".json", 65536)
	var stored struct {
		Envelope model.WorkflowObservationEnvelope `json:"envelope"`
		Receipt  model.WorkflowObservationReceipt  `json:"receipt"`
	}
	if err != nil || decode(raw, &stored) != nil || !bytesCanonical(raw, stored) || stored.Receipt.ReceiptID != id || stored.Receipt.ReceiptDigest != childString(fields, "receiptDigest") || p.RetainChildObservationReceipt(stored.Envelope, stored.Receipt) != nil {
		return empty, ErrUntrusted
	}
	request := childFields(stored.Envelope.Payload.Request)
	if !sameProduct(request["binding"], binding) {
		return empty, ErrUntrusted
	}
	return ChildEffectPredecessor{Receipt: stored.Receipt, Binding: request["binding"], Observation: request["observation"]}, nil
}

func (p *Producer) sealChildObservation(call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, w ChildWorkflowObservationWitness, observedAt string) (model.WorkflowObservationEnvelope, error) {
	var empty model.WorkflowObservationEnvelope
	if _, err := p.childObservationPolicy(call, op, w); err != nil {
		return empty, err
	}
	now := time.Now()
	expiry, err := time.Parse(time.RFC3339Nano, op.ExpiresAt)
	if err != nil || !now.Before(expiry) {
		return empty, ErrUntrusted
	}
	// F1 requires issuedAt <= observedAt. Capture occurred after operation grant.
	issued := observedAt
	request := canonicalBytes(map[string]any{"binding": op.Binding, "reconciles": op.Operation.Reconciles, "observation": op.Operation.Observation})
	binding, snapshot := childFields(op.Binding), childFields(w.CurrentSnapshot)
	payload := model.WorkflowObservationPayload{FormatVersion: 1, Purpose: "workspace_workflow_observation", RequestID: call.RequestID, TaskID: w.Product.Applicability.TaskID, NodeTokenHash: p.config.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: issued, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: childString(snapshot, "managedServiceReceiptDigest"), OperationID: op.OperationID, OperationDigest: op.OperationDigest, Request: request,
		NativeReceipt: model.WorkflowNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: childString(binding, "serviceRegistrationId"), ServiceGeneration: childInteger(binding, "serviceGeneration"), NativeSessionID: childString(binding, "nativeSessionId"), NativeProjectID: childString(binding, "nativeProjectId"), NativeLocationDigest: childString(binding, "nativeLocationDigest"), Role: childString(snapshot, "role"), RootAttestation: childString(binding, "rootAttestation"), ObservedAt: observedAt, Readback: request}}
	body, err := model.WorkspaceCanonicalJSON(payload)
	if err != nil {
		return empty, err
	}
	sum := sha256.Sum256(body)
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, sum[:])
	if err != nil {
		return empty, err
	}
	envelope := model.WorkflowObservationEnvelope{Payload: payload, KeyID: p.config.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}
	if envelope.Validate() != nil {
		return empty, ErrUntrusted
	}
	if err = p.create("workflow-observation-"+op.OperationID+"-envelope.json", canonicalBytes(envelope)); err != nil {
		return empty, err
	}
	return envelope, nil
}
