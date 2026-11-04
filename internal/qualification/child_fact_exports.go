package qualification

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"golang.org/x/sys/unix"
)

func DecodeOriginalChildProductFacts(f model.ChildProductOriginalFacts) (ChildProductAuthorityFacts, ChildProductInstalledFacts, ChildProductLifecycleFacts, error) {
	var a ChildProductAuthorityFacts
	var i ChildProductInstalledFacts
	var l ChildProductLifecycleFacts
	if decode(f.AuthorityBytes(), &a) != nil || decode(f.InstalledBytes(), &i) != nil || decode(f.LifecycleBytes(), &l) != nil {
		return a, i, l, ErrUntrusted
	}
	if len(l.ArtifactReviewReads) != 0 {
		return a, i, l, ErrUntrusted
	}
	// Compare JSON values, not whitespace/key ordering. Re-serialization through
	// the authoritative structs enforces exact owning names and required fields
	// without maintaining a competing field inventory at the node client.
	if !sameProduct(json.RawMessage(f.AuthorityBytes()), a) || !sameProduct(json.RawMessage(f.InstalledBytes()), i) || !sameProduct(json.RawMessage(f.LifecycleBytes()), l) {
		return a, i, l, ErrUntrusted
	}
	return a, i, l, nil
}

// Validate the three prospective originals together BEFORE publishing any fact.
// Installed archive/self adoption is deliberately still checked by the ordinary
// current-witness consumer, never manufactured by this exporting transition.
func (p *Producer) ExportOriginalChildProductFacts(ctx context.Context, entry model.CellServiceV3, current model.Manifest, authority ChildProductAuthorityFacts, installed ChildProductInstalledFacts, lifecycle ChildProductLifecycleFacts, input []byte, now time.Time) error {
	if p == nil {
		return ErrUntrusted
	}
	values := map[string][]byte{
		"child-product-authority-" + entry.PreparationID + ".json": canonicalBytes(authority),
		"child-product-installed-" + entry.PreparationID + ".json": canonicalBytes(installed),
		"child-product-lifecycle-" + entry.PreparationID + ".json": canonicalBytes(lifecycle),
	}
	// Native review fields never originate at a backend or SOURCE hook. They are
	// overlaid only from separately protected actual Runtime read/compiler owners.
	if len(lifecycle.ReviewReads) != 0 || len(lifecycle.ArtifactReviewReads) != 0 || lifecycle.ReviewCompilation != nil {
		return ErrUntrusted
	}
	w, _, err := assembleChildProductOwnerFacts(ctx, entry, input, func(name string, bound int) ([]byte, error) {
		raw, ok := values[name]
		if !ok || len(raw) > bound {
			return nil, ErrUntrusted
		}
		return raw, nil
	}, now)
	if err != nil || w.Root.RuntimeRevision != current.DesiredRevision || w.Applicability.ServerID != current.ServerID {
		return ErrUntrusted
	}
	public, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil || verifyChildEnvelope(authority.AcceptedPreparationEnvelope, authority.OperatorKeyID, public) != nil {
		return ErrUntrusted
	}
	if err = p.exportChildAuthorityFacts(ctx, entry, current, authority, installed.EvidenceClass, installed.ConfigDigest); err != nil {
		return err
	}
	if err = p.exportChildInstalledFacts(ctx, entry, current, installed); err != nil {
		return err
	}
	if err = p.retainReviewerCompilation(w); err != nil {
		return err
	}
	return p.exportChildLifecycleFacts(ctx, entry, lifecycle)
}

// These writers consume ORIGINAL committed owner exports, not signed PRODUCT
// fields. The installed observer keeps its original signature. The lifecycle
// writer independently joins Runtime's actual local receipt at its caller.
// Source admission still rechecks all three suppliers and complete installation.
func (p *Producer) exportChildAuthorityFacts(ctx context.Context, entry model.CellServiceV3, current model.Manifest, f ChildProductAuthorityFacts, evidenceClass, configDigest string) error {
	if p == nil || !safeID.MatchString(entry.PreparationID) || f.Root.RuntimeRevision != current.DesiredRevision || f.Root.RegisteredSourceID != entry.Workspace.SelectionID ||
		f.Root.Producer != (model.WorkspaceRegisteredProducer{KeyID: p.config.KeyID, KeySHA256: p.config.KeySHA256, ServerID: p.config.ServerID, NodeTokenHash: p.config.NodeTokenHash}) ||
		f.QualifiedApplicability.SandboxID != entry.SandboxID || f.QualifiedApplicability.SandboxGeneration != entry.SandboxGeneration ||
		f.Qualification.TupleDigest != CanonicalDigest(f.QualifiedApplicability) || !live(f.Qualification.ValidUntil, time.Now()) || !time.Now().Before(f.AuthorizedUntil) {
		return ErrUntrusted
	}
	authority, err := p.read("physical-gate-authority.json", 65536)
	if err != nil || validateChildFactFinancialAuthority(authority, f, evidenceClass, configDigest) != nil {
		return ErrUntrusted
	}
	if evidenceClass == "live" {
		original, _, err := p.CurrentLiveWindowAuthority(ctx, f.Case)
		if err != nil || !bytes.Equal(original, authority) {
			return ErrUntrusted
		}
	}
	envelope, err := p.read("physical-gate-demand-envelope.json", 65536)
	if err != nil || !sameProduct(json.RawMessage(envelope), f.AcceptedDemandEnvelope) {
		return ErrUntrusted
	}
	// The envelope itself is retained, never rebuilt from policy-selected fields.
	var selected ChildEnvelope[DemandManifest]
	public, err := p.read("physical-gate-operator.pem", 4096)
	operator := childFields(childFields(authority)["operator"])
	if err != nil || childString(operator, "keyId") != f.OperatorKeyID || childString(operator, "keySHA256") != strings.TrimPrefix(Digest(public), "sha256:") ||
		Digest(public) != f.Case.OperatorKeySHA256 || verifyChildEnvelope(envelope, f.OperatorKeyID, public) != nil || decode(envelope, &selected) != nil ||
		selected.Payload.validate(f.Case, time.Now()) != nil || !sameProduct(selected.Payload.SourceContinuation, f.SourceContinuation) {
		return ErrUntrusted
	}
	if childString(childFields(childFields(authority)["tupleInventory"]), "candidateInventoryDigest") != selected.Payload.CandidateInventoryDigest {
		return ErrUntrusted
	}
	if len(f.SourceContinuation) != 0 {
		if _, original, err := p.CurrentSourceContinuationAuthority(ctx, f.Case); err != nil || !sameProduct(json.RawMessage(original), f.AcceptedDemandEnvelope) || f.Qualification.QualificationID == sourcePredecessorID(f.SourceContinuation) {
			return ErrUntrusted
		}
	}
	return p.publishOwnedChildFact(ctx, "authority", entry.PreparationID, f, func(old []byte) bool {
		var previous ChildProductAuthorityFacts
		return decode(old, &previous) == nil && childAuthorityExportAdvance(previous, f)
	})
}

// Closed owner checks follow the protected file read. This does not select a
// path, confer current authority, publish facts or replace signer/root checks.
func validateChildFactFinancialAuthority(authority []byte, f ChildProductAuthorityFacts, evidenceClass, configDigest string) error {
	family, err := childFactBudgetContract(evidenceClass, f.SourceContinuation)
	if err != nil {
		return err
	}
	definition := "authority2"
	if f.Case.FormatVersion == 3 {
		if len(f.SourceContinuation) != 0 || f.Case.AccountingVersion != 2 || f.Case.ProviderPolicyDigest != providerpolicy.FlashDigest || !f.Case.typed() {
			return ErrUntrusted
		}
		family, definition = workflowcontract.BudgetProvider, "authority3"
	}
	if workflowcontract.Validate(family, definition, authority) != nil || Digest(authority) != configDigest ||
		childString(childFields(authority), "evidenceClass") != evidenceClass || !sameProduct(childFields(authority)["case"], f.Case) ||
		childString(childFields(authority), "caseId") != f.Case.CaseID || childString(childFields(authority), "caseManifestDigest") != f.Case.CaseManifestDigest || CanonicalDigest(childFields(authority)["tupleInventory"]) != f.Case.TupleInventoryDigest {
		return ErrUntrusted
	}
	return nil
}

func childFactBudgetContract(evidenceClass string, continuation json.RawMessage) (string, error) {
	if evidenceClass != "source" && evidenceClass != "live" {
		return "", ErrUntrusted
	}
	if len(continuation) == 0 {
		if evidenceClass == "live" {
			return workflowcontract.BudgetLiveWindow, nil
		}
		return workflowcontract.Budget, nil
	}
	if evidenceClass != "source" {
		return "", ErrUntrusted
	}
	return workflowcontract.BudgetSourceContinuation, nil
}

func childAuthorityExportAdvance(previous, next ChildProductAuthorityFacts) bool {
	if (!previous.ProductSigningNotBefore.IsZero() && !previous.ProductSigningNotBefore.Equal(next.ProductSigningNotBefore)) ||
		(!previous.ActivationSigningNotBefore.IsZero() && !previous.ActivationSigningNotBefore.Equal(next.ActivationSigningNotBefore)) {
		return false
	}
	previous.ProductSigningNotBefore = next.ProductSigningNotBefore
	previous.ActivationSigningNotBefore = next.ActivationSigningNotBefore
	return sameProduct(previous, next)
}

func sourcePredecessorID(raw json.RawMessage) string {
	var c SourceContinuation
	if decode(raw, &c) != nil {
		return ""
	}
	return c.Predecessor.QualificationID
}

func (p *Producer) exportChildInstalledFacts(ctx context.Context, entry model.CellServiceV3, current model.Manifest, f ChildProductInstalledFacts) error {
	if p == nil || p.key == nil || !safeID.MatchString(entry.PreparationID) {
		return ErrUntrusted
	}
	der, err := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	if err != nil {
		return err
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if !sameProduct(public, f.ProducerPEM) || verifyChildEnvelope(f.Observation, p.config.KeyID, public) != nil {
		return ErrUntrusted
	}
	var e ChildEnvelope[ChildInstalledInputObservation]
	if decode(f.Observation, &e) != nil || e.Payload.PreparationID != entry.PreparationID || e.Payload.Root.RuntimeRevision != current.DesiredRevision || e.Payload.Root.RegisteredSourceID != entry.Workspace.SelectionID || e.Payload.PreparedTupleDigest == "" {
		return ErrUntrusted
	}
	// Independently verified original signed installed observation and actual
	// current tuple; no future tools before actual assignment.
	tuple, err := entry.PreparedTuple()
	if err != nil || e.Payload.PreparedTupleDigest != CanonicalDigest(tuple) || e.Payload.ApplicabilityDigest != CanonicalDigest(f.Applicability) {
		return ErrUntrusted
	}
	return p.publishOwnedChildFact(ctx, "installed", entry.PreparationID, f, func(old []byte) bool {
		var previous ChildProductInstalledFacts
		var before ChildEnvelope[ChildInstalledInputObservation]
		return decode(old, &previous) == nil && decode(previous.Observation, &before) == nil && before.Payload.AssignmentDigest == nil && e.Payload.AssignmentDigest != nil && sameProduct(previous.Consumer, f.Consumer) && sameProduct(previous.Applicability, f.Applicability) && sameProduct(previous.ProducerPEM, f.ProducerPEM) && previous.EvidenceClass == f.EvidenceClass && previous.ConfigDigest == f.ConfigDigest && before.Payload.IntentDigest == e.Payload.IntentDigest && before.Payload.PreparedTupleDigest == e.Payload.PreparedTupleDigest && sameProduct(before.Payload.Inputs.Workload, e.Payload.Inputs.Workload)
	})
}

func (p *Producer) exportChildLifecycleFacts(ctx context.Context, entry model.CellServiceV3, f ChildProductLifecycleFacts) error {
	if p == nil || !safeID.MatchString(entry.PreparationID) {
		return ErrUntrusted
	}
	if f.ActualReceipt != nil && f.ActualReceipt.ValidateFor(entry) != nil {
		return ErrUntrusted
	}
	if f.Grant != nil && (entry.ExecutionGrant == nil || !sameProduct(f.Grant, entry.ExecutionGrant)) {
		return ErrUntrusted
	}
	// Re-reading empty backend-owned native slots must not erase originals already
	// enriched locally. Preserve only identical owning lifecycle joins; final
	// enrichment independently revalidates every retained native record/generation.
	if len(f.ReviewReads) == 0 && len(f.ArtifactReviewReads) == 0 && f.ReviewCompilation == nil {
		if raw, err := p.read("child-product-lifecycle-"+entry.PreparationID+".json", 512*1024); err == nil {
			var previous ChildProductLifecycleFacts
			if decode(raw, &previous) != nil {
				return ErrUntrusted
			}
			if len(previous.ReviewReads) != 0 || len(previous.ArtifactReviewReads) != 0 || previous.ReviewCompilation != nil {
				base := previous
				base.ReviewReads = f.ReviewReads
				base.ArtifactReviewReads = f.ArtifactReviewReads
				base.ReviewCompilation = nil
				if !sameProduct(base, f) {
					return ErrUntrusted
				}
				f.ReviewReads = previous.ReviewReads
				f.ArtifactReviewReads = previous.ArtifactReviewReads
				f.ReviewCompilation = previous.ReviewCompilation
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return p.publishOwnedChildFact(ctx, "lifecycle", entry.PreparationID, f, func(old []byte) bool {
		var previous ChildProductLifecycleFacts
		if decode(old, &previous) != nil {
			return false
		}
		// Monotone original joins. Missing future facts are not permission to
		// replace an already observed receipt/assignment/grant/ROOT observation.
		return (previous.ActualReceipt == nil || sameProduct(previous.ActualReceipt, f.ActualReceipt)) && (childWireAbsent(previous.Binding) || sameProduct(previous.Binding, f.Binding)) && (childWireAbsent(previous.Assignment) || sameProduct(previous.Assignment, f.Assignment)) && (previous.Grant == nil || sameProduct(previous.Grant, f.Grant)) && (previous.Authorization == nil || sameProduct(previous.Authorization, f.Authorization)) && (len(previous.ReviewReads) == 0 || sameProduct(previous.ReviewReads, f.ReviewReads)) && (len(previous.ArtifactReviewReads) == 0 || sameProduct(previous.ArtifactReviewReads, f.ArtifactReviewReads)) && (previous.ReviewCompilation == nil || sameProduct(previous.ReviewCompilation, f.ReviewCompilation))
	})
}

// Protected durable publication with digest-addressed originals. A retained
// interrupted stage is UNKNOWN, never silently deleted or reused as success.
func (p *Producer) publishOwnedChildFact(ctx context.Context, kind, id string, value any, advance func([]byte) bool) error {
	if p == nil || ctx.Err() != nil || !safeID.MatchString(id) || (kind != "authority" && kind != "installed" && kind != "lifecycle") {
		return ErrUntrusted
	}
	fd, err := unix.Open(filepath.Join(p.config.EvidenceRoot, "child-product-fact-publication.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if rootPrivate(filepath.Join(p.config.EvidenceRoot, "child-product-fact-publication.lock"), false) != nil || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return ErrUntrusted
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	raw := canonicalBytes(value)
	if len(raw) > 512*1024 {
		return ErrUntrusted
	}
	name := "child-product-" + kind + "-" + id + ".json"
	if _, err := os.Lstat(filepath.Join(p.config.EvidenceRoot, name)); err == nil {
		old, err := p.read(name, 512*1024)
		if err != nil {
			return err
		}
		if string(old) == string(raw) {
			return nil
		}
		if advance == nil || !advance(old) {
			return ErrUntrusted
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	digest := Digest(raw)[7:]
	if err := p.append("child-product-"+kind+"-"+id+"-"+digest+".json", raw); err != nil {
		return err
	}
	stage := "child-product-fact-stage-" + digest + ".json"
	if err := p.create(stage, raw); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := os.Rename(filepath.Join(p.config.EvidenceRoot, stage), filepath.Join(p.config.EvidenceRoot, name)); err != nil {
		return err
	}
	dir, err := os.Open(p.config.EvidenceRoot)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
