package qualification

import (
	"bytes"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

var ErrIntegrationSourceNotApplicable = errors.New("integrator source delivery not applicable")

// Read metadata only. No current root, target body, staging or read credit.
type ChildIntegrationTarget struct {
	Target    json.RawMessage
	Artifact  json.RawMessage
	Reference model.ControllerPlanReference
	Reads     []ChildApprovedSourceRead
}

func (c ChildProductControl) IntegrationTarget() (ChildIntegrationTarget, error) {
	var out ChildIntegrationTarget
	if c.Generation.Phase != "execute" || c.Generation.Policy == nil {
		return out, ErrUntrusted
	}
	q := c.Generation.Policy.Payload
	if q.Purpose != "integrator" {
		if _, err := c.ApprovedWorkerSourceReads(); err == nil || err == ErrWorkerSourceNotApplicable {
			return out, ErrIntegrationSourceNotApplicable
		}
		return out, ErrUntrusted
	}
	if c.Generation.FormatVersion != 4 || q.FormatVersion != 3 || q.IntegrationDelivery == nil || q.Workload.Kind != "integration2" || len(q.SourceReads) > 64 {
		return out, ErrUntrusted
	}
	out.Target = q.IntegrationDelivery.Target
	for _, span := range q.IntegrationDelivery.Spans {
		out.Reads = append(out.Reads, ChildApprovedSourceRead{Reference: span.Reference, ByteCount: span.ByteCount})
		if span.Kind == "target_artifact" {
			if out.Artifact != nil {
				return ChildIntegrationTarget{}, ErrUntrusted
			}
			out.Artifact = span.Artifact
			out.Reference = span.Reference
		}
	}
	if out.Artifact == nil {
		return ChildIntegrationTarget{}, ErrUntrusted
	}
	return out, nil
}

func integrationSourceInputMatches(w ChildProductWitness, c ChildProductControl, scope ChildSourceReadScope, raw []byte) error {
	if _, err := c.IntegrationTarget(); err != nil {
		return err
	}
	q := c.Generation.Policy.Payload
	if verifyIntegrationProductInput(c.Generation.PreparationPolicy.Payload, q, w, time.Now()) != nil {
		return ErrUntrusted
	}
	for _, actual := range q.SourceReads {
		if !sameProduct(actual, scope) {
			continue
		}
		g := childFields(scope.Grant)
		for _, span := range q.IntegrationDelivery.Spans {
			if span.RootGrantDigest != childString(g, "rootGrantDigest") {
				continue
			}
			original, err := span.InputBytes(w.Input)
			if err == nil && bytes.Equal(original, raw) {
				return nil
			}
		}
	}
	return ErrUntrusted
}

// Signed input integrity is a prerequisite, never protected staging/read credit.
// The current registered source and first own read/ACK remain separate owners.
func verifyIntegrationProductInput(p ChildPreparationPolicy, q ChildProductPolicy, w ChildProductWitness, now time.Time) error {
	d := q.IntegrationDelivery
	if q.FormatVersion != 3 || p.FormatVersion != 2 || q.Purpose != "integrator" || q.Workload.Kind != "integration2" || len(q.Tools) != 0 || q.ReviewDelivery != nil || d == nil ||
		workflowcontract.ValidateChildIntegrator("productPolicy", canonicalBytes(q)) != nil || model.VerifyIntegrationInput(*d, w.Input, now) != nil ||
		d.Intent != q.Intent || !sameProduct(d.Binding, q.Binding) || !sameProduct(d.Assignment, q.Assignment) ||
		d.InputID != p.Instructions.InputID || d.InputDigest != p.Instructions.InputDigest || d.InputByteCount != p.Instructions.InputByteCount ||
		mustChildTime(d.NotAfter).After(mustChildTime(q.ExpiresAt)) {
		return ErrUntrusted
	}
	intent := childFields(p.Intent)
	body := childFields(intent["prepareBody"])
	content := childFields(body["content"])
	if !bytes.Equal(canonicalBytes(map[string]any{"formatVersion": 1, "kind": "workspace_workflow_packet", "content": json.RawMessage(body["content"])}), w.Input) || !sameProduct(intent["target"], d.Target) {
		return ErrUntrusted
	}
	packet := childFields(content["workflowPacket"])
	var plan model.ControllerPlanReference
	if decode(packet["planRef"], &plan) != nil {
		return ErrUntrusted
	}
	required := map[string]bool{CanonicalDigest(plan): true}
	var specimen struct {
		References   []model.ControllerPlanReference `json:"references"`
		ConsumerRefs []model.ControllerPlanReference `json:"consumerRefs"`
	}
	if json.Unmarshal(packet["specimen"], &specimen) != nil {
		return ErrUntrusted
	}
	for _, ref := range append(specimen.References, specimen.ConsumerRefs...) {
		required[CanonicalDigest(ref)] = true
	}
	var writeScope struct {
		Mode  string   `json:"mode"`
		Paths []string `json:"paths"`
	}
	if decode(packet["writeScope"], &writeScope) != nil || writeScope.Mode != "exclusive" || len(q.SourceReads) != len(d.Spans) || len(d.Spans) != len(required)+1 {
		return ErrUntrusted
	}
	seen := map[string]bool{}
	for _, span := range d.Spans {
		id := CanonicalDigest(span.Reference)
		if seen[id] {
			return ErrUntrusted
		}
		seen[id] = true
		if span.Kind == "packet_source" {
			if !required[id] {
				return ErrUntrusted
			}
			delete(required, id)
		}
		if span.Kind == "target_artifact" {
			allowed := false
			for _, prefix := range writeScope.Paths {
				if span.Reference.Path == prefix || strings.HasPrefix(span.Reference.Path, strings.TrimSuffix(prefix, "/")+"/") {
					allowed = true
				}
			}
			if !allowed || path.Clean(span.Reference.Path) != span.Reference.Path || strings.HasPrefix(span.Reference.Path, "/") || strings.HasPrefix(span.Reference.Path, "../") {
				return ErrUntrusted
			}
		}
		matches := 0
		for _, scope := range q.SourceReads {
			grant, root := childFields(scope.Grant), childFields(scope.Root)
			if childString(grant, "rootGrantDigest") != span.RootGrantDigest {
				continue
			}
			matches++
			var count int
			if workflowcontract.ValidateChildIntegrator("integrationSourceScope", canonicalBytes(scope)) != nil ||
				childString(grant, "use") != "integration_"+span.Kind || !sameProduct(grant["reference"], span.Reference) || !sameProduct(grant["artifact"], span.Artifact) ||
				json.Unmarshal(grant["byteCount"], &count) != nil || count != span.ByteCount || !sameProduct(grant["target"], d.Target) || !sameProduct(grant["targetBinding"], d.TargetBinding) ||
				!sameProduct(root["workspace"], q.Root.Workspace) || childString(root, "rootAttestation") != q.Root.Workspace.RootAttestation ||
				!sameProduct(root["producer"], q.Root.Producer) || childString(root, "candidateDescriptorDigest") != q.Root.CandidateDescriptorDigest ||
				mustChildTime(d.NotAfter).After(mustChildTime(childString(grant, "expiresAt"))) || mustChildTime(d.NotAfter).After(mustChildTime(childString(root, "expiresAt"))) {
				return ErrUntrusted
			}
			if span.Kind == "target_artifact" && childString(grant, "manifestDigest") != CanonicalDigest([]json.RawMessage{span.Artifact}) {
				return ErrUntrusted
			}
		}
		if matches != 1 {
			return ErrUntrusted
		}
	}
	if len(required) != 0 {
		return ErrUntrusted
	}
	return nil
}
