package qualification

import (
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// This proves only the signed selection and immutable input. Actual private
// target custody and this reviewer's read ACKs remain separate admission facts.
func verifyReviewerArtifactSelection(p ChildPreparationPolicy, q ChildProductPolicy, w ChildProductWitness, now time.Time) error {
	if p.FormatVersion != 2 || q.FormatVersion != 4 || q.Purpose != "reviewer" || q.Workload.Kind != "review1" ||
		q.ReviewDelivery == nil || q.ReviewDelivery.FormatVersion != 2 || len(q.ArtifactReads) != 1 ||
		workflowcontract.ValidateChildReviewer("artifactAuthority", q.ArtifactReads[0]) != nil {
		return ErrUntrusted
	}
	a := childFields(q.ArtifactReads[0])
	assignment := childFields(q.Assignment)
	if !sameProduct(a["binding"], q.Binding) || !sameProduct(a["assignmentId"], assignment["assignmentId"]) ||
		!sameProduct(a["target"], assignment["target"]) || !sameProduct(a["candidate"], q.ReviewDelivery.Candidate) ||
		!sameProduct(a["producer"], q.Root.Producer) || childString(a, "candidateDescriptorDigest") != q.Root.CandidateDescriptorDigest ||
		!live(childString(a, "expiresAt"), now) || mustChildTime(childString(a, "expiresAt")).After(mustChildTime(q.ExpiresAt)) ||
		w.ReviewCompilation == nil || childString(a, "manifestDigest") != w.ReviewCompilation.ManifestDigest {
		return ErrUntrusted
	}
	artifact := childFields(a["artifact"])
	ref := childFields(a["reference"])
	if childString(artifact, "digest") != childString(ref, "sourceDigest") {
		return ErrUntrusted
	}
	matched := 0
	for _, span := range q.ReviewDelivery.Spans {
		if span.Kind == "target_artifact" {
			if span.ArtifactAuthorityDigest != CanonicalDigest(q.ArtifactReads[0]) || span.RootGrantDigest != "" ||
				!sameProduct(a["reference"], span.Reference) || !sameProduct(a["artifact"], span.Artifact) ||
				childInteger(artifact, "byteCount") != int64(span.ByteCount) {
				return ErrUntrusted
			}
			matched++
		} else if span.ArtifactAuthorityDigest != "" {
			return ErrUntrusted
		}
	}
	if matched != 1 {
		return ErrUntrusted
	}
	return nil
}
