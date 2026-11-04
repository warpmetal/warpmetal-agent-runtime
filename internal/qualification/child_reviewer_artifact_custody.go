package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type reviewerArtifactLink struct {
	EntryDigest      string `json:"entryDigest"`
	GenerationDigest string `json:"generationDigest"`
	AuthorityDigest  string `json:"authorityDigest"`
	OperationID      string `json:"operationId"`
	ReceiptID        string `json:"receiptId"`
}

func reviewerArtifactLinkName(w ChildProductWitness, c ChildProductControl) string {
	return "reviewer-artifact-link-" + w.Preparation.PreparationID + "-" + CanonicalDigest(c.Generation.Policy.Payload.ArtifactReads[0])[7:] + ".json"
}
func reviewerArtifactOwnMatch(w ChildProductWitness, c ChildProductControl, read ReviewerArtifactCapture, own ChildSourceReadOriginal) error {
	if c.Generation.Policy == nil || c.Generation.Policy.Payload.FormatVersion != 4 || len(c.Generation.Policy.Payload.ArtifactReads) != 1 {
		return ErrUntrusted
	}
	q := c.Generation.Policy.Payload
	a := childFields(q.ArtifactReads[0])
	artifact := childFields(a["artifact"])
	p, n, r := own.Envelope.Payload, own.Envelope.Payload.NativeReceipt, own.Receipt
	b := childFields(q.Binding)
	request := childFields(p.Request)
	expected := map[string]any{"type": "source_read", "reference": a["reference"], "observedDigest": childString(artifact, "digest"), "byteCount": len(read.Bytes)}
	when, err := time.Parse(time.RFC3339Nano, read.ObservedAt)
	issued, ie := time.Parse(time.RFC3339Nano, p.IssuedAt)
	until, ue := time.Parse(time.RFC3339Nano, p.NotAfter)
	if err != nil || ie != nil || ue != nil || when.Before(issued) || !when.Before(until) || p.OperationDigest != read.OperationDigest || p.NativeReceipt.ObservedAt != read.ObservedAt || p.NodeTokenHash != w.Root.Producer.NodeTokenHash || own.Envelope.KeyID != w.Root.Producer.KeyID ||
		read.EntryDigest != CanonicalDigest(w.Entry) || read.GenerationDigest != c.Descriptor.GenerationDigest || read.AuthorityDigest != CanonicalDigest(q.ArtifactReads[0]) || read.InputID != q.Instructions.InputID || read.InputDigest != q.Instructions.InputDigest ||
		Digest(read.Bytes) != childString(artifact, "digest") || int64(len(read.Bytes)) != childInteger(artifact, "byteCount") || read.DirectoryDevice == 0 || read.DirectoryInode == 0 || read.BodyDevice == 0 || read.BodyInode == 0 ||
		!sameProduct(request["binding"], q.Binding) || !sameProduct(request["observation"], expected) || string(request["reconciles"]) != "null" || !sameProduct(n.Readback, p.Request) ||
		n.Role != "reviewer" || n.NativeSessionID != childString(b, "nativeSessionId") || n.NativeProjectID != childString(b, "nativeProjectId") || n.NativeLocationDigest != childString(b, "nativeLocationDigest") || n.RootAttestation != childString(b, "rootAttestation") || n.ServiceRegistrationID != w.Entry.ServiceRegistrationID || n.ServiceGeneration != w.Entry.ServiceGeneration || n.OperationID != p.OperationID || n.OperationDigest != p.OperationDigest ||
		r.ExecutionID != childString(b, "executionId") || r.Type != "source_read" || r.Status != "settled" || workflowcontract.Validate(workflowcontract.Domain, "observationReceipt", canonicalBytes(r)) != nil {
		return ErrUntrusted
	}
	return nil
}

func retainReviewerArtifactOriginal(w ChildProductWitness, c ChildProductControl, read ReviewerArtifactCapture, own ChildSourceReadOriginal, j reviewerArtifactJournal, verify func(model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error) error {
	if j == nil || verify == nil || reviewerArtifactOwnMatch(w, c, read, own) != nil || verify(own.Envelope, own.Receipt) != nil {
		return ErrUntrusted
	}
	op := model.WorkflowCaptureOperation{OperationID: own.Envelope.Payload.OperationID}
	name := reviewerArtifactName(w, c, op)
	raw, err := j.load(name+"-read.json", 65536)
	if err != nil || !bytes.Equal(raw, canonicalBytes(read)) {
		return ErrUntrusted
	}
	raw, err = j.load("workflow-observation-receipt-"+own.Receipt.ReceiptID+".json", 65536)
	if err != nil || !bytes.Equal(raw, canonicalBytes(own)) {
		return ErrUntrusted
	}
	link := reviewerArtifactLink{EntryDigest: CanonicalDigest(w.Entry), GenerationDigest: c.Descriptor.GenerationDigest, AuthorityDigest: read.AuthorityDigest, OperationID: own.Envelope.Payload.OperationID, ReceiptID: own.Receipt.ReceiptID}
	linkName := reviewerArtifactLinkName(w, c)
	if prior, err := j.load(linkName, 65536); err == nil {
		if !bytes.Equal(prior, canonicalBytes(link)) {
			return ErrUntrusted
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUntrusted
	}
	return j.create(linkName, canonicalBytes(link))
}

// First original custody only. No fetch, signing, ACK append or refreshed time.
// A settled historical read may outlive its short capture operation; its original
// time window is checked while current signed selection is checked separately.
func loadReviewerArtifactOriginal(ctx context.Context, w ChildProductWitness, c ChildProductControl, j reviewerArtifactJournal, verify func(model.WorkflowObservationEnvelope, model.WorkflowObservationReceipt) error) (model.ArtifactReviewReadWitness, ChildSourceReadOriginal, error) {
	var empty model.ArtifactReviewReadWitness
	var own ChildSourceReadOriginal
	if j == nil || verify == nil || c.Generation.Policy == nil || c.Generation.Policy.Payload.FormatVersion != 4 || len(c.Generation.Policy.Payload.ArtifactReads) != 1 || ctx.Err() != nil {
		return empty, own, ErrUntrusted
	}
	q := c.Generation.Policy.Payload
	raw, err := j.load(reviewerArtifactLinkName(w, c), 65536)
	var link reviewerArtifactLink
	if err != nil || decode(raw, &link) != nil || !bytesCanonical(raw, link) || link.EntryDigest != CanonicalDigest(w.Entry) || link.GenerationDigest != c.Descriptor.GenerationDigest || link.AuthorityDigest != CanonicalDigest(q.ArtifactReads[0]) || !safeID.MatchString(link.OperationID) || !safeID.MatchString(link.ReceiptID) {
		return empty, own, ErrUntrusted
	}
	raw, err = j.load("workflow-observation-receipt-"+link.ReceiptID+".json", 65536)
	if err != nil || decode(raw, &own) != nil || !bytesCanonical(raw, own) || own.Envelope.Payload.OperationID != link.OperationID || own.Receipt.ReceiptID != link.ReceiptID || verify(own.Envelope, own.Receipt) != nil {
		return empty, own, ErrUntrusted
	}
	name := reviewerArtifactName(w, c, model.WorkflowCaptureOperation{OperationID: link.OperationID})
	raw, err = j.load(name+"-operation.json", 65536)
	var op model.WorkflowCaptureOperation
	if err != nil || decode(raw, &op) != nil || !bytesCanonical(raw, op) || op.OperationID != link.OperationID || op.OperationDigest != own.Envelope.Payload.OperationDigest {
		return empty, own, ErrUntrusted
	}
	raw, err = j.load(name+"-read.json", 65536)
	var read ReviewerArtifactCapture
	if err != nil || decode(raw, &read) != nil || !bytesCanonical(raw, read) || reviewerArtifactOwnMatch(w, c, read, own) != nil {
		return empty, own, ErrUntrusted
	}
	when, err := time.Parse(time.RFC3339Nano, read.ObservedAt)
	if err != nil {
		return empty, own, ErrUntrusted
	}
	claim, err := reviewerArtifactClaimAt(op, w, c, when)
	if err != nil {
		return empty, own, ErrUntrusted
	}
	fence, err := j.load(name+"-claim.json", 16384)
	if err != nil || !bytes.Equal(fence, canonicalBytes(claim)) {
		return empty, own, ErrUntrusted
	}
	a := childFields(q.ArtifactReads[0])
	artifact := childFields(a["artifact"])
	body, err := j.readArtifact(ctx, name+"-body", int(childInteger(artifact, "byteCount")), childString(artifact, "digest"))
	detail, de := j.load(name+"-detail.json", 65536)
	if err != nil || de != nil || read.TargetDetailDigest != CanonicalDigest(json.RawMessage(detail)) || read.DirectoryDevice != body.DirectoryDevice || read.DirectoryInode != body.DirectoryInode || read.BodyDevice != body.device || read.BodyInode != body.inode || !bytes.Equal(read.Bytes, body.bytes) || verifyTargetArtifactOriginal(a["target"], a["targetBinding"], a["artifact"], detail, body.bytes) != nil || ctx.Err() != nil {
		return empty, own, ErrUntrusted
	}
	return model.ArtifactReviewReadWitness{Bytes: read.Bytes, ArtifactAuthority: q.ArtifactReads[0], NativeReceipt: canonicalBytes(own.Envelope.Payload.NativeReceipt), ReadReceipt: canonicalBytes(own.Receipt)}, own, nil
}
