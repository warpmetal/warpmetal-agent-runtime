package qualification

import (
	"bytes"
	"context"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func childSourceInputMatches(w ChildProductWitness, c ChildProductControl, scope ChildSourceReadScope, raw []byte) error {
	if c.Generation.Policy != nil && c.Generation.Policy.Payload.FormatVersion == 3 {
		return integrationSourceInputMatches(w, c, scope, raw)
	}
	return workerSourceInputMatches(w, c, scope, raw)
}

func childSourceCustodySelected(c ChildProductControl) error {
	if c.Generation.Policy != nil && c.Generation.Policy.Payload.FormatVersion == 3 {
		_, err := c.IntegrationTarget()
		return err
	}
	_, err := c.ApprovedWorkerSourceReads()
	return err
}

type childSourceLink struct {
	EntryDigest      string `json:"entryDigest"`
	GenerationDigest string `json:"generationDigest"`
	InputID          string `json:"inputId"`
	InputDigest      string `json:"inputDigest"`
	ScopeDigest      string `json:"scopeDigest"`
	OperationID      string `json:"operationId"`
	ReceiptID        string `json:"receiptId"`
}

func childSourceLinkName(w ChildProductWitness, c ChildProductControl, scope ChildSourceReadScope) string {
	if c.Generation.Policy != nil && c.Generation.Policy.Payload.FormatVersion == 3 {
		return "integrator-source-" + w.Preparation.PreparationID + "-" + CanonicalDigest(scope)[7:] + ".json"
	}
	return "worker-source-" + w.Preparation.PreparationID + "-" + CanonicalDigest(scope)[7:] + ".json"
}

// The sole reader of the fixed private custody chain. Tests may exercise absent
// originals through their existing SOURCE journal; no signature is synthesized.
func loadChildSourceOriginal(w ChildProductWitness, c ChildProductControl, scope ChildSourceReadScope, load func(string, int) ([]byte, error), verify func(model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error) (ChildSourceReadOriginal, error) {
	var empty ChildSourceReadOriginal
	if err := childSourceCustodySelected(c); err != nil {
		return empty, err
	}
	raw, err := load(childSourceLinkName(w, c, scope), 65536)
	var link childSourceLink
	if err != nil || decode(raw, &link) != nil || !bytesCanonical(raw, link) || link.EntryDigest != CanonicalDigest(w.Entry) || link.GenerationDigest != c.Descriptor.GenerationDigest || link.InputID != w.Instructions.InputID || link.InputDigest != Digest(w.Input) || link.ScopeDigest != CanonicalDigest(scope) || !safeID.MatchString(link.OperationID) || !safeID.MatchString(link.ReceiptID) {
		return empty, ErrUntrusted
	}
	raw, err = load("workflow-observation-receipt-"+link.ReceiptID+".json", 65536)
	var original ChildSourceReadOriginal
	// Existing receipt storage uses lower-case envelope/receipt keys.
	if err != nil || decode(raw, &original) != nil || !bytesCanonical(raw, original) || original.Envelope.Payload.OperationID != link.OperationID || original.Receipt.ReceiptID != link.ReceiptID || verify(original.Envelope, original.Receipt) != nil {
		return empty, ErrUntrusted
	}
	raw, err = load("workflow-observation-"+link.OperationID+"-read.json", 65536)
	var read WorkflowSourceCapture
	if err != nil || decode(raw, &read) != nil || !bytesCanonical(raw, read) || read.OperationDigest != original.Envelope.Payload.OperationDigest || read.ScopeDigest != CanonicalDigest(scope) || read.RootDevice == 0 || read.RootInode == 0 || read.SourceDevice == 0 || read.SourceInode == 0 || read.ObservedAt != original.Envelope.Payload.NativeReceipt.ObservedAt || childSourceInputMatches(w, c, scope, read.Bytes) != nil {
		return empty, ErrUntrusted
	}
	fence, err := load("workflow-observation-"+link.OperationID+"-fence.json", 16384)
	if err != nil || !bytes.Equal(fence, canonicalBytes(map[string]any{"operationDigest": read.OperationDigest, "scopeDigest": read.ScopeDigest, "rootDevice": read.RootDevice, "rootInode": read.RootInode})) {
		return empty, ErrUntrusted
	}
	if childSourceOriginalMatches(w, c, scope, read, original) != nil {
		return empty, ErrUntrusted
	}
	return original, nil
}

func childSourceOriginalMatches(w ChildProductWitness, c ChildProductControl, scope ChildSourceReadScope, read WorkflowSourceCapture, original ChildSourceReadOriginal) error {
	if childSourceInputMatches(w, c, scope, read.Bytes) != nil || read.OperationDigest != original.Envelope.Payload.OperationDigest || read.ScopeDigest != CanonicalDigest(scope) || read.RootDevice == 0 || read.RootInode == 0 || read.SourceDevice == 0 || read.SourceInode == 0 || read.ObservedAt != original.Envelope.Payload.NativeReceipt.ObservedAt {
		return ErrUntrusted
	}
	q := c.Generation.Policy.Payload
	request := childFields(original.Envelope.Payload.Request)
	g := childFields(scope.Grant)
	expected := map[string]any{"type": "source_read", "reference": g["reference"], "observedDigest": childString(childFields(g["reference"]), "sourceDigest"), "byteCount": len(read.Bytes)}
	n := original.Envelope.Payload.NativeReceipt
	b := childFields(q.Binding)
	if !sameProduct(request["binding"], q.Binding) || !sameProduct(request["observation"], expected) || string(request["reconciles"]) != "null" || original.Receipt.Type != "source_read" || original.Receipt.Status != "settled" || n.Role != "worker" || n.NativeSessionID != childString(b, "nativeSessionId") || n.NativeProjectID != childString(b, "nativeProjectId") || n.NativeLocationDigest != childString(b, "nativeLocationDigest") || n.ServiceRegistrationID != w.Entry.ServiceRegistrationID || n.ServiceGeneration != w.Entry.ServiceGeneration {
		return ErrUntrusted
	}
	return nil
}

func (p *Producer) retainChildSourceRead(ctx context.Context, w ChildProductWitness, c ChildProductControl, envelope model.WorkflowObservationEnvelope, read WorkflowSourceCapture, receipt model.WorkflowObservationReceipt) error {
	if err := childSourceCustodySelected(c); err != nil {
		return err
	}
	request := childFields(envelope.Payload.Request)
	observed := childFields(request["observation"])
	for _, scope := range c.Generation.Policy.Payload.SourceReads {
		if !sameProduct(childFields(scope.Grant)["reference"], observed["reference"]) {
			continue
		}
		if ctx.Err() != nil || childSourceOriginalMatches(w, c, scope, read, ChildSourceReadOriginal{Envelope: envelope, Receipt: receipt}) != nil || p.RetainChildObservationReceipt(envelope, receipt) != nil {
			return ErrUntrusted
		}
		raw, err := p.read("workflow-observation-"+envelope.Payload.OperationID+"-read.json", 65536)
		if err != nil || !bytes.Equal(raw, canonicalBytes(read)) {
			return ErrUntrusted
		}
		link := childSourceLink{EntryDigest: CanonicalDigest(w.Entry), GenerationDigest: c.Descriptor.GenerationDigest, InputID: w.Instructions.InputID, InputDigest: Digest(w.Input), ScopeDigest: CanonicalDigest(scope), OperationID: envelope.Payload.OperationID, ReceiptID: receipt.ReceiptID}
		return p.append(childSourceLinkName(w, c, scope), canonicalBytes(link))
	}
	return ErrUntrusted
}

// The Store remains the current-authority owner; this helper neither signs nor
// publishes a new control or grants permission to prompt.
func (p *Producer) readChildSourceReceipts(ctx context.Context, w ChildProductWitness, c ChildProductControl) ([]ChildSourceReadOriginal, error) {
	if err := childSourceCustodySelected(c); err != nil {
		return nil, err
	}
	out := make([]ChildSourceReadOriginal, 0, len(c.Generation.Policy.Payload.SourceReads))
	for _, scope := range c.Generation.Policy.Payload.SourceReads {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		original, err := loadChildSourceOriginal(w, c, scope, p.read, p.verifyChildObservationReceipt)
		if err != nil {
			return nil, err
		}
		out = append(out, original)
	}
	return out, nil
}
