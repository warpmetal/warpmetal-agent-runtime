package qualification

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type childEffectControl struct {
	FormatVersion    int                    `json:"formatVersion"`
	PreparationID    string                 `json:"preparationId"`
	PolicyDigest     string                 `json:"policyDigest"`
	ActivationDigest string                 `json:"activationDigest"`
	Permit           json.RawMessage        `json:"permit"`
	Approval         json.RawMessage        `json:"approval"`
	SourceReads      []ChildSourceReadScope `json:"sourceReads"`
}

// Supplied from the owning accepted ROOT observation/report, not effect JSON or
// an author's file read. Receipt origin/first envelope must already be verified
// by that protected consumer. Publication itself cannot create this witness.
type ChildEffectPredecessor struct {
	Receipt     model.WorkflowObservationReceipt
	Binding     json.RawMessage
	Observation json.RawMessage
}

func childEffectMatchesPolicy(e childEffectControl, c ChildProductControl, previous *ChildEffectPredecessor, now time.Time) error {
	if c.Generation.Phase != "execute" || c.Generation.Policy == nil || c.Generation.Activation == nil {
		return ErrUntrusted
	}
	q, a := c.Generation.Policy.Payload, c.Generation.Activation.Payload
	p, g := childFields(e.Permit), childFields(e.Approval)
	ordinal := childInteger(p, "effectOrdinal")
	if q.Purpose != "business_worker" || ordinal < 0 || ordinal > 1 || len(q.Tools) <= int(ordinal) || e.PreparationID != c.Generation.PreparationID || e.PolicyDigest != CanonicalDigest(q) || e.ActivationDigest != CanonicalDigest(a) {
		return ErrUntrusted
	}
	t := q.Tools[ordinal]
	if t.EffectOrdinal != int(ordinal) || !sameProduct(p["binding"], q.Binding) || childString(p, "assignmentId") != childString(childFields(q.Assignment), "assignmentId") ||
		childString(p, "caseManifestDigest") != q.Case.CaseManifestDigest || childString(p, "definitionDigest") != CanonicalDigest(t.Definition) || childString(p, "approvalDigest") != CanonicalDigest(t.Approval) ||
		childString(p, "dataScope") != t.DataScope || childString(p, "outputPath") != t.OutputPath || !sameProduct(g["intent"], q.Intent) || childString(g, "allocationId") != q.Reservation.AllocationID ||
		childString(g, "kind") != t.Kind || childString(g, "permitDigest") != CanonicalDigest(e.Permit) || childString(g, "definitionDigest") != childString(p, "definitionDigest") || childString(g, "approvalDigest") != childString(p, "approvalDigest") ||
		childString(g, "installedWitnessDigest") != CanonicalDigest(t.InstalledWitness) || childString(g, "preparedReceiptDigest") != q.PreparedReceipt.PreparedReceiptDigest || childString(g, "assignmentDigest") != childString(childFields(q.Assignment), "assignmentDigest") ||
		childString(g, "executionGrantDigest") != CanonicalDigest(a.Grant) || childString(g, "productPolicyDigest") != CanonicalDigest(q) || childString(g, "dataScopeDigest") != childString(p, "dataScopeDigest") || childString(g, "expiresAt") != childString(p, "expiresAt") {
		return ErrUntrusted
	}
	expiry, err := time.Parse(time.RFC3339Nano, childString(p, "expiresAt"))
	policyExpiry, pe := time.Parse(time.RFC3339Nano, q.ExpiresAt)
	activationExpiry, ae := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	if err != nil || pe != nil || ae != nil || !now.Before(expiry) || expiry.After(policyExpiry) || expiry.After(activationExpiry) {
		return ErrUntrusted
	}
	var declared []string
	if json.Unmarshal(g["sourceGrantDigests"], &declared) != nil {
		return ErrUntrusted
	}
	required := append([]string(nil), t.InputReads...)
	if t.ScriptRead != nil {
		required = append(required, *t.ScriptRead)
	}
	if len(declared) != len(required) || len(e.SourceReads) != len(required) {
		return ErrUntrusted
	}
	seen := map[string]bool{}
	manifest := []json.RawMessage{}
	for _, read := range e.SourceReads {
		d := CanonicalDigest(read.Grant)
		found := false
		for _, r := range q.SourceReads {
			if sameProduct(r, read) {
				found = true
			}
		}
		if !found || seen[d] {
			return ErrUntrusted
		}
		seen[d] = true
		allowed := false
		for _, r := range required {
			if r == d {
				allowed = true
			}
		}
		if !allowed {
			return ErrUntrusted
		}
		grant := childFields(read.Grant)
		for _, raw := range []json.RawMessage{read.Grant, read.Root} {
			until, err := time.Parse(time.RFC3339Nano, childString(childFields(raw), "expiresAt"))
			if err != nil || expiry.After(until) {
				return ErrUntrusted
			}
		}
		if ordinal == 0 {
			if childString(grant, "use") != "tool_input" || bytes.Equal(grant["artifact"], []byte("null")) {
				return ErrUntrusted
			}
			manifest = append(manifest, grant["artifact"])
		} else if childString(grant, "use") != "installed_script" {
			return ErrUntrusted
		}
	}
	for _, d := range declared {
		if !seen[d] {
			return ErrUntrusted
		}
		delete(seen, d)
	}
	if len(seen) != 0 {
		return ErrUntrusted
	}
	if ordinal == 0 {
		if t.Kind != "mcp_read" || !bytes.Equal(g["predecessorReceipt"], []byte("null")) || previous != nil || t.DataScopeDigest == nil || childString(p, "dataScopeDigest") != *t.DataScopeDigest {
			return ErrUntrusted
		}
	} else {
		if t.Kind != "script_run" || previous == nil || previous.Receipt.Status != "settled" || previous.Receipt.Type != "mcp_read" || previous.Receipt.ExecutionID != childString(childFields(q.Binding), "executionId") || !sameProduct(previous.Binding, q.Binding) {
			return ErrUntrusted
		}
		observed := childFields(previous.Observation)
		if childString(observed, "type") != "mcp_read" || childString(observed, "status") != "settled" || childString(observed, "outcome") != "succeeded" || len(observed["output"]) == 0 || bytes.Equal(observed["output"], []byte("null")) ||
			!sameProduct(g["predecessorReceipt"], map[string]string{"receiptId": previous.Receipt.ReceiptID, "receiptDigest": previous.Receipt.ReceiptDigest}) {
			return ErrUntrusted
		}
		manifest = []json.RawMessage{observed["output"]}
	}
	if !sameProduct(p["inputManifest"], manifest) {
		return ErrUntrusted
	}
	b := childFields(q.Binding)
	scope := map[string]any{"dataScope": t.DataScope, "inputManifest": manifest}
	for _, key := range []string{"selectionId", "projectId", "workspaceEpoch", "rootAttestation", "scopeRevision"} {
		if b[key] != nil {
			scope[key] = b[key]
		}
	}
	if CanonicalDigest(scope) != childString(p, "dataScopeDigest") {
		return ErrUntrusted
	}
	return nil
}

// Fixed node effect publication under the already mounted readonly Store. No
// key, grant, tool, reservation, future artifact, or shared writable home is made.
func (s Store) AdoptChildProductEffect(box model.Sandbox, delivery model.ChildProductEffectDelivery, w ChildProductWitness, previous *ChildEffectPredecessor, now time.Time) error {
	c, err := s.ReadChildProduct(box, delivery.PreparationID(), w, now)
	if err != nil {
		return err
	}
	var e childEffectControl
	if workflowcontract.ValidateChildProduct("effectControl", delivery.Bytes()) != nil || decode(delivery.Bytes(), &e) != nil || childEffectMatchesPolicy(e, c, previous, now) != nil {
		return ErrUntrusted
	}
	tree, key, err := s.Paths(box.ID)
	if err != nil {
		return err
	}
	for _, rel := range []string{"product/effects", "product/effects/" + delivery.PreparationID()} {
		if s.childProductDirectory(filepath.Join(tree, rel), tree, key) != nil {
			return ErrUntrusted
		}
	}
	path := filepath.Join(tree, "product/effects", delivery.PreparationID(), strconv.Itoa(delivery.Ordinal())+".json")
	if _, err = os.Lstat(path); err == nil {
		raw, err := s.read(path, tree, key, 65536)
		if err != nil || !bytes.Equal(raw, canonicalBytes(e)) {
			return ErrUntrusted
		}
	} else if !os.IsNotExist(err) || s.childProductFile(path, canonicalBytes(e)) != nil || syncChildProductDirectory(filepath.Dir(path)) != nil {
		return ErrUntrusted
	}
	// A changed selector during publication cannot escape as current authority.
	again, err := s.ReadChildProduct(box, delivery.PreparationID(), w, now)
	if err != nil || again.Descriptor.GenerationDigest != c.Descriptor.GenerationDigest {
		return ErrUntrusted
	}
	return nil
}
