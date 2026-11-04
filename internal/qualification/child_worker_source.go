package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Only the published-control adapter may use this to skip the selected worker
// gate, after Store has verified the complete known control. Missing authority
// and malformed selected workers must never become a successful no-op.
var ErrWorkerSourceNotApplicable = errors.New("worker source read not applicable")

// Read metadata only, never source consumption or receipt credit.
type ChildApprovedSourceRead struct {
	Reference model.ControllerPlanReference
	ByteCount int
}

// Existing first originals. This wrapper is not a new signed document.
type ChildSourceReadOriginal struct {
	Envelope model.WorkflowObservationEnvelope `json:"envelope"`
	Receipt  model.WorkflowObservationReceipt  `json:"receipt"`
}

// Existing published-control reader, with the worker's additional immutable
// input join. Its SOURCE read receipt never asserts that a model executed.
func (p *Producer) ReadWorkerSource(ctx context.Context, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, w ChildWorkflowObservationWitness) (model.WorkflowObservationEnvelope, WorkflowSourceCapture, error) {
	var empty model.WorkflowObservationEnvelope
	var noRead WorkflowSourceCapture
	if w.SourceReadDelivery != nil {
		return empty, noRead, ErrUntrusted
	}
	c, err := w.Authority.ReadChildProduct(w.Sandbox, w.Product.Preparation.PreparationID, w.Product, time.Now())
	if err != nil {
		return empty, noRead, err
	}
	if _, err = c.ApprovedWorkerSourceReads(); err != nil {
		return empty, noRead, err
	}
	envelope, read, err := p.ReadChildProductSource(ctx, call, op, w)
	if err != nil {
		return empty, noRead, err
	}
	for _, scope := range c.Generation.Policy.Payload.SourceReads {
		if CanonicalDigest(scope) != read.ScopeDigest {
			continue
		}
		if workerSourceInputMatches(w.Product, c, scope, read.Bytes) != nil {
			return empty, noRead, ErrUntrusted
		}
		return envelope, read, nil
	}
	return empty, noRead, ErrUntrusted
}

func (c ChildProductControl) ApprovedWorkerSourceReads() ([]ChildApprovedSourceRead, error) {
	if c.Generation.Phase != "execute" || c.Generation.Policy == nil {
		return nil, ErrUntrusted
	}
	q := c.Generation.Policy.Payload
	expected := map[string]string{"coding_worker": "coding2", "business_worker": "business3", "integrator": "integration2", "reviewer": "review1"}[q.Purpose]
	knownVersion := q.FormatVersion == 1 || q.FormatVersion == 2 || (q.FormatVersion == 3 && q.Purpose == "integrator" && q.IntegrationDelivery != nil)
	if expected == "" || q.Workload.Kind != expected || !knownVersion || len(q.SourceReads) > 64 {
		return nil, ErrUntrusted
	}
	if q.FormatVersion == 1 || q.Purpose != "coding_worker" {
		return nil, ErrWorkerSourceNotApplicable
	}
	out := make([]ChildApprovedSourceRead, 0, len(q.SourceReads))
	seen := map[string]bool{}
	for _, scope := range q.SourceReads {
		g := childFields(scope.Grant)
		var reference model.ControllerPlanReference
		if workflowcontract.Validate(workflowcontract.Domain, "reference", g["reference"]) != nil || json.Unmarshal(g["reference"], &reference) != nil || reference.Status != "accepted" || childString(g, "use") != "tool_input" || !sameProduct(g["binding"], q.Binding) {
			return nil, ErrUntrusted
		}
		count := childInteger(g, "byteCount")
		key := CanonicalDigest(reference)
		if count < 1 || count > 16384 || seen[key] {
			return nil, ErrUntrusted // An ambiguous root is not a duplicate read.
		}
		seen[key] = true
		out = append(out, ChildApprovedSourceRead{Reference: reference, ByteCount: int(count)})
	}
	return out, nil
}

func workerSourceInputMatches(w ChildProductWitness, c ChildProductControl, scope ChildSourceReadScope, raw []byte) error {
	if _, err := c.ApprovedWorkerSourceReads(); err != nil {
		return err
	}
	q := c.Generation.Policy.Payload
	found := false
	for _, actual := range q.SourceReads {
		if sameProduct(scope, actual) {
			found = true
		}
	}
	g := childFields(scope.Grant)
	ref := childFields(g["reference"])
	if !found || int64(len(raw)) != childInteger(g, "byteCount") || Digest(raw) != childString(ref, "sourceDigest") || Digest(w.Input) != q.Instructions.InputDigest || w.Instructions.InputID != q.Instructions.InputID {
		return ErrUntrusted
	}
	// The original workflow packet is frozen before preparation. ROOT read ACKs
	// cannot append bytes or turn a reference-only context into model delivery.
	content := childFields(childFields(w.Intent)["prepareBody"])["content"]
	expected := canonicalBytes(map[string]any{"formatVersion": 1, "kind": "workspace_workflow_packet", "content": content})
	var input struct {
		Content struct {
			Context string `json:"context"`
		} `json:"content"`
	}
	if !bytes.Equal(w.Input, expected) || json.Unmarshal(w.Input, &input) != nil || !bytes.Contains([]byte(input.Content.Context), raw) {
		return ErrUntrusted
	}
	return nil
}

// The worker wrappers retain the same selected authority and private names.
func loadWorkerSourceOriginal(w ChildProductWitness, c ChildProductControl, scope ChildSourceReadScope, load func(string, int) ([]byte, error), verify func(model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error) (ChildSourceReadOriginal, error) {
	if _, err := c.ApprovedWorkerSourceReads(); err != nil {
		return ChildSourceReadOriginal{}, err
	}
	return loadChildSourceOriginal(w, c, scope, load, verify)
}
func (p *Producer) RetainWorkerSourceRead(ctx context.Context, w ChildProductWitness, c ChildProductControl, envelope model.WorkflowObservationEnvelope, read WorkflowSourceCapture, receipt model.WorkflowObservationReceipt) error {
	if _, err := c.ApprovedWorkerSourceReads(); err != nil {
		return err
	}
	return p.retainChildSourceRead(ctx, w, c, envelope, read, receipt)
}
func (p *Producer) ReadWorkerSourceReceipts(ctx context.Context, w ChildProductWitness, c ChildProductControl) ([]ChildSourceReadOriginal, error) {
	if _, err := c.ApprovedWorkerSourceReads(); err != nil {
		return nil, err
	}
	return p.readChildSourceReceipts(ctx, w, c)
}
