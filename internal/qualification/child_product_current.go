package qualification

import (
	"bytes"
	"context"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Fixed independently selected root-private current record; not an operator wire
// or an operation-derived installed pin. Source provenance/metadata is not enough:
// the SAME complete installed archive/build/self verifier must also pass.
func (p *Producer) CurrentChildProductWitness(ctx context.Context, entry model.CellServiceV3, current model.Manifest, input []byte) (ChildProductWitness, error) {
	var empty, w ChildProductWitness
	if p == nil || !safeID.MatchString(entry.PreparationID) || ctx.Err() != nil {
		return empty, ErrUntrusted
	}
	raw, err := p.read("child-product-current-"+entry.PreparationID+".json", 512*1024)
	if err != nil || decode(raw, &w) != nil || !bytesCanonical(raw, w) || verifyReviewerFinalFacts(w, time.Now()) != nil || p.verifyChildProductCurrentInstallation(ctx, w, entry, current, input) != nil {
		return empty, ErrUntrusted
	}
	again, err := p.read("child-product-current-"+entry.PreparationID+".json", 512*1024)
	if err != nil || !bytes.Equal(raw, again) {
		return empty, ErrUntrusted
	}
	return w, nil
}

func (p *Producer) verifyChildProductCurrentInstallation(ctx context.Context, w ChildProductWitness, entry model.CellServiceV3, current model.Manifest, input []byte) error {
	return p.verifyChildProductInstallationAt(ctx, w, entry, current, input, time.Now())
}

// The observation clock is private to the first signed completed-facts reader.
// Archive/self, manifest, baseline and current owner checks still run now.
func (p *Producer) verifyChildProductInstallationAt(ctx context.Context, w ChildProductWitness, entry model.CellServiceV3, current model.Manifest, input []byte, observationTime time.Time) error {
	if p == nil || ctx.Err() != nil || !sameProduct(w.Entry, entry) || w.Root.RuntimeRevision != current.DesiredRevision ||
		w.Root.Producer != (model.WorkspaceRegisteredProducer{KeyID: p.config.KeyID, KeySHA256: p.config.KeySHA256, ServerID: p.config.ServerID, NodeTokenHash: p.config.NodeTokenHash}) || !bytes.Equal(w.Input, input) {
		return ErrUntrusted
	}
	if len(w.SourceContinuation) != 0 {
		if w.InstalledInputs == nil || !hash.MatchString(w.InstalledFactsDigest) {
			return ErrUntrusted
		}
		b, _, err := p.CurrentPhysicalBaseline(ctx, current)
		if err != nil || !sameProduct(b.SourceContinuation, w.SourceContinuation) || b.Case != w.Case {
			return ErrUntrusted
		}
	}
	if w.InstalledInputs != nil {
		raw, err := p.read("child-product-installed-"+entry.PreparationID+".json", 512*1024)
		var facts ChildProductInstalledFacts
		if err != nil || Digest(raw) != w.InstalledFactsDigest || decode(raw, &facts) != nil || !bytesCanonical(raw, facts) {
			return ErrUntrusted
		}
		inputs, err := verifyChildInstalledInputs(facts, w, observationTime)
		if err != nil || !sameProduct(inputs, *w.InstalledInputs) {
			return ErrUntrusted
		}
		if facts.EvidenceClass == "live" {
			authority, _, err := p.CurrentLiveWindowAuthority(ctx, w.Case)
			f := childFields(authority)
			if err != nil || Digest(authority) != facts.ConfigDigest ||
				!sameProduct(f["backend"], w.Applicability.Backend) || !sameProduct(f["native"], w.Applicability.Native) ||
				!sameProduct(f["runtime"], w.Applicability.Runtime) || !sameProduct(f["sandbox"], w.Applicability.Sandbox) || childString(f, "profileBundleDigest") != w.Applicability.Profile.BundleDigest {
				return ErrUntrusted
			}
		}
		again, err := p.read("child-product-installed-"+entry.PreparationID+".json", 512*1024)
		if err != nil || !bytes.Equal(raw, again) {
			return ErrUntrusted
		}
	}
	reader, err := verifyCurrentPlanReaderArtifact(ctx, w.Applicability.TaskID, nil, &w.Applicability.Runtime, current, p.config, p.read, SelfBinaryDigest, p.verifyPlanReaderArchive)
	if err != nil || reader.CandidateDescriptorDigest != w.Root.CandidateDescriptorDigest || reader.CaseManifestDigest != w.Case.CaseManifestDigest {
		return ErrUntrusted
	}
	if w.Applicability.ServerID != current.ServerID {
		return ErrUntrusted
	}
	selected := false
	for _, box := range current.Sandboxes {
		if box.ID == entry.SandboxID && box.Generation == entry.SandboxGeneration && box.DesiredState == "running" {
			selected = true
		}
	}
	if !selected {
		return ErrUntrusted
	}
	return nil
}
