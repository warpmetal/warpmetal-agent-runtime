package qualification

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type childFactsOriginals struct {
	Native    ChildWorkflowNativeCapture  `json:"native"`
	Current   json.RawMessage             `json:"current"`
	PaidCut   state.PaidLedgerCut         `json:"paidCut"`
	Execution *state.LocalCellV3Execution `json:"execution"`
}

// Opaque verified provenance. Only the protected producer can construct it;
// neither callers nor coordinator clocks choose its historical validation time.
type ChildCompletedFactsHistory struct {
	first            model.WorkflowFactsEnvelope
	originals        childFactsOriginals
	product          ChildProductWitness
	control          ChildProductControl
	provenanceDigest string
}

func (h ChildCompletedFactsHistory) NativeBinaryDigest() string {
	if h.control.Generation.Policy == nil {
		return ""
	}
	return h.control.Generation.Policy.Payload.Applicability.Native.BinarySHA256
}

func verifyCompletedFactsOriginal(first model.WorkflowFactsEnvelope, raw []byte, public *ecdsa.PublicKey, producer model.WorkspaceRegisteredProducer, entry model.CellServiceV3) (childFactsOriginals, time.Time, error) {
	var empty, original childFactsOriginals
	if public == nil || first.Validate() != nil || first.KeyID != producer.KeyID || first.Payload.NodeTokenHash != producer.NodeTokenHash || decode(raw, &original) != nil || !bytesCanonical(raw, original) || original.Execution == nil || original.Execution.Phase != "terminal" || original.Execution.PreparationID != entry.PreparationID {
		return empty, time.Time{}, ErrUntrusted
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(first.Signature)
	sum := sha256.Sum256(canonicalBytes(first.Payload))
	when, e := time.Parse(time.RFC3339Nano, first.Payload.IssuedAt)
	back := childFields(first.Payload.Readback)
	if err != nil || e != nil || !ecdsa.VerifyASN1(public, sum[:], sig) || childString(back, "snapshotDigest") != Digest(original.Current) || first.Payload.NativeReceipt.ObservedAt != first.Payload.IssuedAt || !sameProduct(original.Execution.Grant, entry.ExecutionGrant) {
		return empty, time.Time{}, ErrUntrusted
	}
	return original, when, nil
}

// first is only an exact locator. The FIRST root-owned envelope and originals
// are read again and their signature establishes the historical clock. No active
// Store API or caller-selected time is exposed by this completed-facts boundary.
func (p *Producer) ReadCompletedChildFactsHistory(ctx context.Context, authority Store, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, first model.WorkflowFactsEnvelope) (ChildCompletedFactsHistory, error) {
	var out ChildCompletedFactsHistory
	if p == nil || p.key == nil || !safeID.MatchString(first.Payload.OperationID) || rootPrivate(p.config.EvidenceRoot, true) != nil {
		return out, ErrUntrusted
	}
	name := "workflow-facts-" + first.Payload.OperationID
	raw, err := p.read(name+"-envelope.json", 65536)
	var retained model.WorkflowFactsEnvelope
	if err != nil || decodeClosed(raw, &retained) != nil || !bytesCanonical(raw, retained) || !sameProduct(retained, first) {
		return out, ErrUntrusted
	}
	evidence, err := p.read(name+"-originals.json", 2*1024*1024)
	if err != nil {
		return out, err
	}
	producer := model.WorkspaceRegisteredProducer{KeyID: p.config.KeyID, KeySHA256: p.config.KeySHA256, ServerID: p.config.ServerID, NodeTokenHash: p.config.NodeTokenHash}
	original, when, err := verifyCompletedFactsOriginal(retained, evidence, &p.key.PublicKey, producer, entry)
	if err != nil || when.After(time.Now()) {
		return out, ErrUntrusted
	}
	wraw, err := p.read("child-product-current-"+entry.PreparationID+".json", 512*1024)
	var w ChildProductWitness
	if err != nil || decode(wraw, &w) != nil || !bytesCanonical(wraw, w) || verifyReviewerFinalFacts(w, when) != nil || p.verifyChildProductInstallationAt(ctx, w, entry, current, input, when) != nil {
		return out, ErrUntrusted
	}
	control, err := authority.ReadChildProduct(box, entry.PreparationID, w, when)
	if err != nil || control.Generation.Policy == nil || control.Generation.Activation == nil || !sameProduct(control.Generation.Policy.Payload.Binding, retained.Payload.Binding) {
		return out, ErrUntrusted
	}
	n, role, _, err := original.Native.completion(entry, control)
	if err != nil || !childCompletionReport(entry, original.Execution.Report, original.Execution.Grant, n) || retained.Payload.NativeReceipt.Role != role || retained.Payload.NativeReceipt.NativeSessionID != n.SessionID || retained.Payload.NativeReceipt.NativeProjectID != n.NativeProjectID || retained.Payload.NativeReceipt.NativeLocationDigest != n.NativeLocationDigest || retained.Payload.NativeReceipt.RootAttestation != w.Root.Workspace.RootAttestation {
		return out, ErrUntrusted
	}
	again, e := p.read(name+"-originals.json", 2*1024*1024)
	latest, e2 := p.read("child-product-current-"+entry.PreparationID+".json", 512*1024)
	if e != nil || e2 != nil || !bytes.Equal(evidence, again) || !bytes.Equal(wraw, latest) || ctx.Err() != nil {
		return out, ErrUntrusted
	}
	return ChildCompletedFactsHistory{retained, original, w, control, CanonicalDigest(map[string]any{"first": retained, "originalsDigest": Digest(evidence), "witnessDigest": Digest(wraw)})}, nil
}

func completedNativeMatches(h ChildCompletedFactsHistory, current model.ChildCompletedCapture, now time.Time) (model.ChildNativeExecution, string, []string, error) {
	var empty model.ChildNativeExecution
	e := h.product.Entry
	if h.originals.Execution == nil || h.product.ActualReceipt == nil || current.ValidateFor(e, *h.product.ActualReceipt, h.originals.Execution.ParentSessionID, h.originals.Execution.WorktreeDir, now) != nil {
		return empty, "", nil, ErrUntrusted
	}
	n, role, responses, err := h.originals.Native.completion(e, h.control)
	if err != nil || !childCompletionReport(e, h.originals.Execution.Report, current.Grant, current.Native) {
		return empty, "", nil, ErrUntrusted
	}
	compared := current.Native
	compared.LogCursor = n.LogCursor
	if current.Native.LogCursor < n.LogCursor || !reflect.DeepEqual(compared, n) {
		return empty, "", nil, ErrUntrusted
	}
	return current.Native, role, responses, nil
}

type CompletedChildWorkflowFactsWitness struct {
	Authority       Store
	Sandbox         model.Sandbox
	Entry           model.CellServiceV3
	Manifest        model.Manifest
	Input           []byte
	CurrentSnapshot json.RawMessage
	Workspace       TrustedWorkspace
	Native          model.ChildCompletedCapture
	First           model.WorkflowFactsEnvelope
}

// Fresh node facts about an exact completed execution. Historical dispatch
// authority authenticates its provenance only; the new operation and current
// native/financial/report observations independently authorize this signature.
func (p *Producer) AttestCompletedChildWorkflowFacts(ctx context.Context, call model.WorkflowFactsRequest, op model.WorkflowFactsOperation, w CompletedChildWorkflowFactsWitness, financial *state.Store, caller state.PhysicalSubject) (model.WorkflowFactsEnvelope, error) {
	var empty model.WorkflowFactsEnvelope
	now := time.Now().UTC()
	if financial == nil {
		return empty, ErrUntrusted
	}
	h, err := p.ReadCompletedChildFactsHistory(ctx, w.Authority, w.Sandbox, w.Entry, w.Manifest, w.Input, w.First)
	if err != nil || op.ValidateFor(call, p.config.NodeTokenHash, w.Manifest.DesiredRevision, now) != nil || !sameProduct(call.Binding, h.first.Payload.Binding) {
		return empty, ErrUntrusted
	}
	n, role, responses, err := completedNativeMatches(h, w.Native, now)
	if err != nil || w.Workspace.WorkspaceDigest != h.product.Root.Workspace.RootAttestation || n.NativeLocationDigest != CanonicalDigest(map[string]any{"directory": w.Workspace.ContainerRoot, "projectId": n.NativeProjectID, "workspaceId": nil}) {
		return empty, ErrUntrusted
	}
	current, err := financial.CellV3Execution(ctx, w.Entry.PreparationID)
	if err != nil || !reflect.DeepEqual(current, h.originals.Execution) {
		return empty, ErrUntrusted
	}
	q := h.control.Generation.Policy.Payload
	snapshot, err := p.childFactsSnapshot(ChildWorkflowFactsWitness{Product: h.product, ExecutionReport: current.Report, ConsumedGrant: current.Grant, CurrentSnapshot: w.CurrentSnapshot}, q, n, role)
	if err != nil {
		return empty, err
	}
	cut, err := childFinancialCompletion(ctx, financial, h.product, h.control, caller, responses)
	if err != nil {
		return empty, err
	}
	root, err := confinedRoot(w.Workspace.HostRoot, w.Workspace.Device, w.Workspace.Inode)
	if err != nil {
		return empty, err
	}
	root.Close()
	candidate := ""
	if op.Operation.Kind == "integration_candidate" {
		capture := h.originals.Native.Integration
		if capture == nil || op.Operation.Receipt == nil {
			return empty, ErrUntrusted
		}
		prior, e := p.ChildEffectPredecessor(canonicalBytes(op.Operation.Receipt), q.Binding)
		observed := childFields(prior.Observation)
		if e != nil || childString(observed, "type") != "integration" || childString(observed, "status") != "settled" || childString(observed, "outcome") != "succeeded" || childString(observed, "assignmentId") != childString(childFields(q.Assignment), "assignmentId") || !sameProduct(observed["target"], childFields(q.Assignment)["target"]) || childString(observed, "beforeDigest") != capture.Before.Digest || childString(observed, "afterDigest") != capture.Artifact.Digest || !sameProduct(observed["changedPaths"], []string{capture.Artifact.SourcePath}) {
			return empty, ErrUntrusted
		}
		actual, e := readPlanSourceFile(ctx, w.Workspace, capture.Artifact.SourcePath, capture.Artifact.ByteCount, capture.Artifact.Digest)
		if e != nil || actual.device != capture.Artifact.Device || actual.inode != capture.Artifact.Inode {
			return empty, ErrUntrusted
		}
		candidate = capture.Artifact.Digest
		snapshot["candidate"] = canonicalBytes(map[string]any{"receipt": op.Operation.Receipt, "target": observed["target"], "targetBinding": observed["targetBinding"], "artifacts": observed["artifacts"], "afterDigest": candidate, "changedPaths": observed["changedPaths"]})
	}
	canonical := canonicalBytes(snapshot)
	if !op.MatchesCurrentSnapshot(canonical) {
		return empty, ErrUntrusted
	}
	back := map[string]any{"nativeSessionId": n.SessionID, "nativeRole": role, "snapshotDigest": Digest(canonical)}
	if op.Operation.Kind == "execution_settlement" {
		back["quiescent"] = true
		back["effectsComplete"] = true
		back["descendantsComplete"] = true
	} else {
		back["candidateDigest"] = candidate
	}
	stamp := now.Format(time.RFC3339Nano)
	native := model.WorkflowNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: w.Entry.ServiceRegistrationID, ServiceGeneration: w.Entry.ServiceGeneration, NativeSessionID: n.SessionID, NativeProjectID: n.NativeProjectID, NativeLocationDigest: n.NativeLocationDigest, Role: role, RootAttestation: w.Workspace.WorkspaceDigest, ObservedAt: stamp, Readback: canonicalBytes(back)}
	back["nativeReceiptDigest"] = CanonicalDigest(native)
	payload := model.WorkflowFactsPayload{FormatVersion: 1, Purpose: "workspace_workflow_facts", RequestID: call.RequestID, TaskID: h.product.Applicability.TaskID, NodeTokenHash: p.config.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: childString(snapshot, "managedServiceReceiptDigest"), NativeReceipt: native, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Binding: q.Binding, Readback: canonicalBytes(back)}
	latest, e := p.ReadCompletedChildFactsHistory(ctx, w.Authority, w.Sandbox, w.Entry, w.Manifest, w.Input, w.First)
	again, e2 := financial.CellV3Execution(ctx, w.Entry.PreparationID)
	paid, e3 := financial.PhysicalLedgerCut(ctx)
	if e != nil || e2 != nil || e3 != nil || h.provenanceDigest != latest.provenanceDigest || !reflect.DeepEqual(current, again) || !reflect.DeepEqual(cut, paid) || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	return p.sealChildFacts(op, payload, map[string]any{"firstEnvelopeDigest": CanonicalDigest(h.first), "provenanceDigest": h.provenanceDigest, "completed": w.Native, "current": json.RawMessage(canonical), "paidCut": cut, "execution": current})
}
