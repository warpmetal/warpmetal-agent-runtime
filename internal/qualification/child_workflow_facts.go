package qualification

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type ChildWorkflowFactsWitness struct {
	Authority       Store
	Sandbox         model.Sandbox
	Product         ChildProductWitness
	ExecutionReport model.CellServiceReportV1
	ConsumedGrant   model.CellExecutionGrantV3
	CurrentSnapshot json.RawMessage
	Workspace       TrustedWorkspace
	Native          ChildWorkflowNativeCapture
}

// This producer accepts no success booleans. Completion is independently read
// from protected current native DATA, the paid SQLite/original archive, local
// consumed lifecycle and the node's independent backend current snapshot.
func (p *Producer) AttestChildWorkflowFacts(ctx context.Context, call model.WorkflowFactsRequest, op model.WorkflowFactsOperation, w ChildWorkflowFactsWitness, financial *state.Store, caller state.PhysicalSubject) (model.WorkflowFactsEnvelope, error) {
	var empty model.WorkflowFactsEnvelope
	now := time.Now().UTC()
	if p == nil || p.key == nil || w.Product.Root.Producer != (model.WorkspaceRegisteredProducer{KeyID: p.config.KeyID, KeySHA256: p.config.KeySHA256, ServerID: p.config.ServerID, NodeTokenHash: p.config.NodeTokenHash}) || op.ValidateFor(call, p.config.NodeTokenHash, w.Product.Root.RuntimeRevision, now) != nil {
		return empty, ErrUntrusted
	}
	control, err := w.Authority.ReadChildProduct(w.Sandbox, w.Product.Entry.PreparationID, w.Product, now)
	if err != nil || control.Generation.Policy == nil || control.Generation.Activation == nil {
		return empty, ErrUntrusted
	}
	q := control.Generation.Policy.Payload
	n, role, responses, err := w.Native.completion(w.Product.Entry, control)
	if err != nil || role != w.Product.Entry.Role || !sameProduct(q.Binding, call.Binding) || !childCompletionReport(w.Product.Entry, w.ExecutionReport, w.ConsumedGrant, n) || !sameProduct(w.ConsumedGrant, control.Generation.Activation.Payload.Grant) || w.Workspace.WorkspaceDigest != w.Product.Root.Workspace.RootAttestation || n.NativeLocationDigest != CanonicalDigest(map[string]any{"directory": w.Workspace.ContainerRoot, "projectId": n.NativeProjectID, "workspaceId": nil}) {
		return empty, ErrUntrusted
	}
	snapshot, err := p.childFactsSnapshot(w, q, n, role)
	if err != nil {
		return empty, err
	}
	cut, err := childFinancialCompletion(ctx, financial, w.Product, control, caller, responses)
	if err != nil {
		return empty, err
	}
	// Always observe the actual registered root. Write captures also require a
	// fresh whole-file observation after the independent native capture.
	root, err := confinedRoot(w.Workspace.HostRoot, w.Workspace.Device, w.Workspace.Inode)
	if err != nil {
		return empty, err
	}
	root.Close()
	var artifact *model.ChildNativeFileSnapshot
	if w.Native.Result != nil {
		artifact = &w.Native.Result.Artifact
	}
	if w.Native.Integration != nil {
		artifact = &w.Native.Integration.Artifact
	}
	if artifact != nil {
		actual, e := readPlanSourceFile(ctx, w.Workspace, artifact.SourcePath, artifact.ByteCount, artifact.Digest)
		if e != nil || actual.device != artifact.Device || actual.inode != artifact.Inode {
			return empty, ErrUntrusted
		}
	}
	if w.Native.Reviewer != nil {
		raw, e := w.Native.Reviewer.Assessment()
		if e != nil {
			return empty, e
		}
		actual, e := readPlanSourceFile(ctx, w.Workspace, w.Native.Reviewer.AssessmentPath, len(raw), Digest(raw))
		if e != nil || Digest(actual.bytes) != Digest(raw) {
			return empty, ErrUntrusted
		}
	}
	if op.Operation.Kind == "integration_candidate" {
		if w.Native.Integration == nil || op.Operation.Receipt == nil {
			return empty, ErrUntrusted
		}
		prior, e := p.ChildEffectPredecessor(canonicalBytes(op.Operation.Receipt), q.Binding)
		if e != nil {
			return empty, e
		}
		observed := childFields(prior.Observation)
		capture := w.Native.Integration
		if childString(observed, "type") != "integration" || childString(observed, "status") != "settled" || childString(observed, "outcome") != "succeeded" || childString(observed, "assignmentId") != childString(childFields(q.Assignment), "assignmentId") || !sameProduct(observed["target"], childFields(q.Assignment)["target"]) || childString(observed, "beforeDigest") != capture.Before.Digest || childString(observed, "afterDigest") != capture.Artifact.Digest || !sameProduct(observed["changedPaths"], []string{capture.Artifact.SourcePath}) {
			return empty, ErrUntrusted
		}
		snapshot["candidate"] = canonicalBytes(map[string]any{"receipt": op.Operation.Receipt, "target": observed["target"], "targetBinding": observed["targetBinding"], "artifacts": observed["artifacts"], "afterDigest": capture.Artifact.Digest, "changedPaths": observed["changedPaths"]})
	}
	current := canonicalBytes(snapshot)
	if !op.MatchesCurrentSnapshot(current) {
		return empty, ErrUntrusted
	}
	before, err := financial.CellV3Execution(ctx, w.Product.Entry.PreparationID)
	if err != nil || before == nil || before.Phase != "terminal" || !sameProduct(before.Report, w.ExecutionReport) || !sameProduct(before.Grant, w.ConsumedGrant) {
		return empty, ErrUntrusted
	}
	readback := map[string]any{"nativeSessionId": n.SessionID, "nativeRole": role, "snapshotDigest": Digest(current)}
	if op.Operation.Kind == "execution_settlement" {
		readback["quiescent"] = true
		readback["effectsComplete"] = true
		readback["descendantsComplete"] = true
	} else {
		readback["candidateDigest"] = w.Native.Integration.Artifact.Digest
	}
	stamp := now.Format(time.RFC3339Nano)
	native := model.WorkflowNativeReceipt{FormatVersion: 1, OperationID: op.OperationID, OperationDigest: op.OperationDigest, ServiceRegistrationID: w.Product.Entry.ServiceRegistrationID, ServiceGeneration: w.Product.Entry.ServiceGeneration, NativeSessionID: n.SessionID, NativeProjectID: n.NativeProjectID, NativeLocationDigest: n.NativeLocationDigest, Role: role, RootAttestation: w.Workspace.WorkspaceDigest, ObservedAt: stamp, Readback: canonicalBytes(readback)}
	readback["nativeReceiptDigest"] = CanonicalDigest(native)
	payload := model.WorkflowFactsPayload{FormatVersion: 1, Purpose: "workspace_workflow_facts", RequestID: call.RequestID, TaskID: w.Product.Applicability.TaskID, NodeTokenHash: p.config.NodeTokenHash, BridgeVersion: "workspace-workflow-bridge-v1", IssuedAt: stamp, NotAfter: op.ExpiresAt, ManagedServiceReceiptDigest: childString(snapshot, "managedServiceReceiptDigest"), NativeReceipt: native, OperationID: op.OperationID, OperationDigest: op.OperationDigest, Binding: q.Binding, Readback: canonicalBytes(readback)}
	again, e := financial.PhysicalLedgerCut(ctx)
	execution, e2 := financial.CellV3Execution(ctx, w.Product.Entry.PreparationID)
	latest, e3 := w.Authority.ReadChildProduct(w.Sandbox, w.Product.Entry.PreparationID, w.Product, time.Now())
	if e != nil || e2 != nil || e3 != nil || !reflect.DeepEqual(cut, again) || !reflect.DeepEqual(before, execution) || !sameProduct(control, latest) || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	return p.sealChildFacts(op, payload, map[string]any{"native": w.Native, "current": json.RawMessage(current), "paidCut": cut, "execution": before})
}

func (p *Producer) childFactsSnapshot(w ChildWorkflowFactsWitness, q ChildProductPolicy, n model.ChildNativeExecution, role string) (map[string]json.RawMessage, error) {
	s := childFields(w.CurrentSnapshot)
	native := CanonicalDigest(map[string]any{"nativeSessionId": n.SessionID, "nativeProjectId": n.NativeProjectID, "nativeLocationDigest": n.NativeLocationDigest, "workspaceEpoch": w.ExecutionReport.WorkspaceEpoch})
	if len(s) != 10 || childString(s, "executionState") != "completed" || childString(s, "executionReceiptDigest") != w.ExecutionReport.ReceiptDigest || childString(s, "desiredState") != "active" || childInteger(s, "desiredRevision") != w.Product.Entry.DesiredRevision || childString(s, "role") != role || childString(s, "nativeContextDigest") != native || childString(s, "managedServiceReceiptDigest") != native {
		return nil, ErrUntrusted
	}
	var grants []struct {
		GrantID, State, Fence string
		Attempt               int64
	}
	if decode(s["grants"], &grants) != nil || len(grants) != 1 || grants[0].GrantID != w.ConsumedGrant.GrantID || grants[0].State != "consumed" || grants[0].Fence != w.Product.Entry.Fence || grants[0].Attempt != w.Product.Entry.Attempt {
		return nil, ErrUntrusted
	}
	var children []json.RawMessage
	if decode(s["children"], &children) != nil || children == nil || !q.Workload.DelegationDisabled || len(children) != 0 {
		return nil, ErrUntrusted
	}
	var effects []struct{ ReceiptID, ReceiptDigest, Status string }
	if decode(s["effects"], &effects) != nil || effects == nil {
		return nil, ErrUntrusted
	}
	// The selected child roster has no delegated child effects. Integrator's
	// independently acknowledged integration is the only permitted typed effect.
	if len(effects) > 1 || (q.Purpose != "integrator" && len(effects) != 0) {
		return nil, ErrUntrusted
	}
	for _, effect := range effects {
		if effect.Status != "settled" {
			return nil, ErrUntrusted
		}
		prior, e := p.ChildEffectPredecessor(canonicalBytes(model.WorkflowReceiptRef{ReceiptID: effect.ReceiptID, ReceiptDigest: effect.ReceiptDigest}), q.Binding)
		if e != nil || childString(childFields(prior.Observation), "type") != "integration" {
			return nil, ErrUntrusted
		}
	}
	return s, nil
}

func (p *Producer) sealChildFacts(op model.WorkflowFactsOperation, payload model.WorkflowFactsPayload, evidence any) (model.WorkflowFactsEnvelope, error) {
	var empty model.WorkflowFactsEnvelope
	if p == nil || p.key == nil || rootPrivate(p.config.EvidenceRoot, true) != nil {
		return empty, ErrUntrusted
	}
	name := "workflow-facts-" + op.OperationID
	if raw, err := p.read(name+"-envelope.json", 65536); err == nil {
		var prior model.WorkflowFactsEnvelope
		if decode(raw, &prior) != nil || prior.Validate() != nil || prior.KeyID != p.config.KeyID {
			return empty, ErrUntrusted
		}
		expected := payload
		expected.IssuedAt = prior.Payload.IssuedAt
		expected.NativeReceipt.ObservedAt = prior.Payload.NativeReceipt.ObservedAt
		back := childFields(expected.Readback)
		back["nativeReceiptDigest"] = canonicalBytes(CanonicalDigest(expected.NativeReceipt))
		expected.Readback = canonicalBytes(back)
		sig, e := base64.StdEncoding.Strict().DecodeString(prior.Signature)
		sum := sha256.Sum256(canonicalBytes(prior.Payload))
		if e != nil || !ecdsa.VerifyASN1(&p.key.PublicKey, sum[:], sig) || !sameProduct(expected, prior.Payload) {
			return empty, ErrUntrusted
		}
		return prior, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, ErrUntrusted
	}
	if err := p.create(name+"-originals.json", canonicalBytes(evidence)); err != nil {
		return empty, err
	}
	sum := sha256.Sum256(canonicalBytes(payload))
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, sum[:])
	if err != nil {
		return empty, err
	}
	envelope := model.WorkflowFactsEnvelope{Payload: payload, KeyID: p.config.KeyID, Signature: base64.StdEncoding.EncodeToString(sig)}
	if envelope.Validate() != nil {
		return empty, ErrUntrusted
	}
	if err = p.create(name+"-envelope.json", canonicalBytes(envelope)); err != nil {
		return empty, err
	}
	return envelope, nil
}
