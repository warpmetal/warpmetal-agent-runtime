package qualification

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// The before-image is an immutable pre-prompt stage original. Replaying the
// stage writer here would incorrectly compare the completed after-image with
// the target's old bytes. The current after-image is observed separately below.
func integrationObservationValue(ctx context.Context, w ChildProductWitness, c ChildProductControl, root TrustedWorkspace, capture model.ChildNativeIntegrationCapture, stage integrationStage, detail json.RawMessage, before []byte, reads []ChildSourceReadOriginal) (json.RawMessage, error) {
	target, err := c.IntegrationTarget()
	if err != nil || c.Generation.Policy == nil {
		return nil, ErrUntrusted
	}
	q := c.Generation.Policy.Payload
	expected, err := integrationStageClaim(w, c, root, detail, before)
	expected.SourceDevice, expected.SourceInode = stage.SourceDevice, stage.SourceInode
	if err != nil || expected != stage || stage.SourceDevice == 0 || stage.SourceInode == 0 || capture.ValidateFor(w.Entry, c.Descriptor.GenerationDigest, q.Binding, q.Instructions.InputID, q.Instructions.InputDigest) != nil ||
		capture.Before.SourcePath != stage.SourcePath || capture.Before.Digest != stage.SourceDigest || capture.Before.ByteCount != stage.ByteCount || capture.Before.Device != stage.SourceDevice || capture.Before.Inode != stage.SourceInode ||
		capture.Artifact.SourcePath != stage.SourcePath || len(reads) != len(q.SourceReads) || len(reads) == 0 {
		return nil, ErrUntrusted
	}
	actual, err := readPlanSourceFile(ctx, root, capture.Artifact.SourcePath, capture.Artifact.ByteCount, capture.Artifact.Digest)
	if err != nil || actual.device != capture.Artifact.Device || actual.inode != capture.Artifact.Inode {
		return nil, ErrUntrusted
	}
	// These are the owner's verified FIRST envelopes and ACKs, never model
	// sourceRefs. Require exactly the current signed scopes, without duplicates.
	consumed := make([]any, 0, len(reads))
	seen := make(map[string]bool)
	for i, scope := range q.SourceReads {
		original := reads[i]
		request := childFields(original.Envelope.Payload.Request)
		observation := childFields(request["observation"])
		reference := childFields(scope.Grant)["reference"]
		if original.Envelope.Validate() != nil || !sameProduct(request["binding"], q.Binding) || string(request["reconciles"]) != "null" || childString(observation, "type") != "source_read" || !sameProduct(observation["reference"], reference) ||
			childString(observation, "observedDigest") != childString(childFields(reference), "sourceDigest") || childInteger(observation, "byteCount") != childInteger(childFields(scope.Grant), "byteCount") ||
			original.Receipt.ExecutionID != childString(childFields(q.Binding), "executionId") || original.Receipt.Type != "source_read" || original.Receipt.Status != "settled" || seen[original.Receipt.ReceiptID] || workflowcontract.Validate(workflowcontract.Domain, "observationReceipt", canonicalBytes(original.Receipt)) != nil {
			return nil, ErrUntrusted
		}
		seen[original.Receipt.ReceiptID] = true
		consumed = append(consumed, map[string]any{"reference": reference, "readReceipt": model.WorkflowReceiptRef{ReceiptID: original.Receipt.ReceiptID, ReceiptDigest: original.Receipt.ReceiptDigest}})
	}
	d := q.IntegrationDelivery
	observation := canonicalBytes(map[string]any{"type": "integration", "assignmentId": childString(childFields(q.Assignment), "assignmentId"), "target": d.Target, "targetBinding": d.TargetBinding,
		"artifacts": []json.RawMessage{target.Artifact}, "consumedRefs": consumed, "beforeDigest": stage.SourceDigest, "afterDigest": capture.Artifact.Digest,
		"changedPaths": []string{capture.Artifact.SourcePath}, "outcome": "succeeded", "status": "settled"})
	if workflowcontract.Validate(workflowcontract.Domain, "observation", observation) != nil {
		return nil, ErrUntrusted
	}
	return observation, nil
}

// Load retained before originals independently of the current after-image. The
// loader is the existing protected journal; caller-owned reads have already
// passed their first-envelope/signature/ACK verifier.
func loadIntegrationObservation(ctx context.Context, w ChildProductWitness, c ChildProductControl, root TrustedWorkspace, capture model.ChildNativeIntegrationCapture, reads []ChildSourceReadOriginal, load func(string, int) ([]byte, error)) (json.RawMessage, []byte, error) {
	name := integrationStageName(w, c)
	raw, err := load(name+".json", 65536)
	var stage integrationStage
	if err != nil || decode(raw, &stage) != nil || !bytesCanonical(raw, stage) {
		return nil, nil, ErrUntrusted
	}
	detail, err := load(name+"-target.json", 65536)
	if err != nil {
		return nil, nil, err
	}
	before, err := load(name+"-target.body", 8192)
	if err != nil {
		return nil, nil, err
	}
	observed, err := integrationObservationValue(ctx, w, c, root, capture, stage, detail, before, reads)
	if err != nil {
		return nil, nil, ErrUntrusted
	}
	proof := canonicalBytes(map[string]any{"capture": capture, "stage": stage, "targetDetailDigest": Digest(detail), "sourceReads": reads, "observation": observed})
	return observed, proof, nil
}

type integrationCompletionObservation struct {
	control     ChildProductControl
	cut         state.PaidLedgerCut
	execution   *state.LocalCellV3Execution
	observation json.RawMessage
	proof       []byte
}

// Both readout and signing use current owner facts. Readout is not a grant or
// signature; the later attester calls this again after the operation exists.
func (p *Producer) readIntegrationCompletion(ctx context.Context, w ChildWorkflowFactsWitness, financial *state.Store, caller state.PhysicalSubject) (integrationCompletionObservation, error) {
	var empty integrationCompletionObservation
	c, err := p.currentIntegration(ctx, w.Authority, w.Sandbox, w.Product)
	if err != nil || c.Generation.Activation == nil || w.Native.Integration == nil {
		return empty, ErrUntrusted
	}
	q := c.Generation.Policy.Payload
	n, role, responses, err := w.Native.completion(w.Product.Entry, c)
	if err != nil || role != "worker" || !childCompletionReport(w.Product.Entry, w.ExecutionReport, w.ConsumedGrant, n) || !sameProduct(w.ConsumedGrant, c.Generation.Activation.Payload.Grant) {
		return empty, ErrUntrusted
	}
	if _, err = p.childFactsSnapshot(w, q, n, role); err != nil {
		return empty, err
	}
	cut, err := childFinancialCompletion(ctx, financial, w.Product, c, caller, responses)
	if err != nil {
		return empty, err
	}
	execution, err := financial.CellV3Execution(ctx, w.Product.Entry.PreparationID)
	if err != nil || execution == nil || execution.Phase != "terminal" || !sameProduct(execution.Report, w.ExecutionReport) || !sameProduct(execution.Grant, w.ConsumedGrant) {
		return empty, ErrUntrusted
	}
	reads, err := p.ReadIntegrationSourceReceipts(ctx, w.Product, c)
	if err != nil {
		return empty, err
	}
	observed, proof, err := loadIntegrationObservation(ctx, w.Product, c, w.Workspace, *w.Native.Integration, reads, p.read)
	if err != nil {
		return empty, err
	}
	return integrationCompletionObservation{c, cut, execution, observed, proof}, nil
}

func (p *Producer) recheckIntegrationCompletion(ctx context.Context, w ChildWorkflowFactsWitness, financial *state.Store, caller state.PhysicalSubject, original integrationCompletionObservation) error {
	again, err := p.readIntegrationCompletion(ctx, w, financial, caller)
	if err != nil || !reflect.DeepEqual(original, again) || ctx.Err() != nil {
		return ErrUntrusted
	}
	return nil
}

// ObserveChildProductIntegration exposes only the existing closed observation
// for a normal backend operation request. It creates no journal, signature,
// artifact, result or acceptance, and cannot replace the subsequent attester.
func (p *Producer) ObserveChildProductIntegration(ctx context.Context, w ChildWorkflowFactsWitness, financial *state.Store, caller state.PhysicalSubject) (json.RawMessage, error) {
	observed, err := p.readIntegrationCompletion(ctx, w, financial, caller)
	if err != nil {
		return nil, err
	}
	if err = p.recheckIntegrationCompletion(ctx, w, financial, caller, observed); err != nil {
		return nil, err
	}
	return observed.observation, nil
}

// Attest the existing integration observation wire. This neither creates a
// second result nor accepts the target. Current protected native completion,
// own paid originals, retained target/read custody and an independent current
// backend snapshot are all required before the first signed observation.
func (p *Producer) AttestChildProductIntegration(ctx context.Context, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, w ChildWorkflowFactsWitness, financial *state.Store, caller state.PhysicalSubject) (model.WorkflowObservationEnvelope, error) {
	var empty model.WorkflowObservationEnvelope
	ow := ChildWorkflowObservationWitness{Authority: w.Authority, Sandbox: w.Sandbox, Product: w.Product, CurrentSnapshot: w.CurrentSnapshot, Workspace: w.Workspace, OriginalIntegration: w.Native.Integration}
	q, err := p.childObservationPolicy(call, op, ow)
	if err != nil || q.FormatVersion != 3 || q.Purpose != "integrator" || string(op.Operation.Reconciles) != "null" || w.Native.Integration == nil {
		return empty, ErrUntrusted
	}
	observed, err := p.readIntegrationCompletion(ctx, w, financial, caller)
	if err != nil || !sameProduct(q, observed.control.Generation.Policy.Payload) || !sameProduct(observed.observation, op.Operation.Observation) {
		return empty, ErrUntrusted
	}
	proof := observed.proof
	fence := canonicalBytes(map[string]string{"operationDigest": op.OperationDigest})
	journal := "workflow-observation-" + op.OperationID
	previous, found, err := p.replayChildObservation(op, ow)
	if err != nil {
		return empty, err
	}
	if found {
		retainedFence, e1 := p.read(journal+"-fence.json", 16384)
		retainedProof, e2 := p.read(journal+"-effect.json", 512*1024)
		if e1 != nil || e2 != nil || string(retainedFence) != string(fence) || string(retainedProof) != string(proof) {
			return empty, ErrUntrusted
		}
	}
	if err = p.recheckIntegrationCompletion(ctx, w, financial, caller, observed); err != nil {
		return empty, err
	}
	if found {
		return previous, nil
	}
	// Interrupted signing owns this operation forever. Never replace an existing
	// fence/effect with a new capture or issue a second signature on recovery.
	if p.create(journal+"-fence.json", fence) != nil || p.create(journal+"-effect.json", proof) != nil {
		return empty, ErrUntrusted
	}
	return p.sealChildObservation(call, op, ow, time.Now().UTC().Format(time.RFC3339Nano))
}
