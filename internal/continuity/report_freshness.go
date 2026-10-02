package continuity

import (
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// StaleSourceSet is the report assembly's single freshness decision for one
// node report: the registered source IDs whose authentic stored observation is
// older than the shared SourceFreshness contract. Both the continuity source
// items and the manager capability items that reference those sources derive
// from this one decision, so a report can never combine an available source
// item with a fail-closed capability item (or the reverse).
type StaleSourceSet map[string]bool

// DecideStaleSourceSet evaluates the shared freshness contract exactly once per
// serialized source item. An item whose observation is on or inside the
// 120-second boundary is never stale: only a strictly older authentic
// observation is downgraded.
func DecideStaleSourceSet(sources []model.ContinuitySourceReportV1, now time.Time) StaleSourceSet {
	stale := StaleSourceSet{}
	for _, source := range sources {
		if now.Sub(source.LastObservedAt) > SourceFreshness {
			stale[source.RegisteredSourceID] = true
		}
	}
	return stale
}

// Stale reports whether the single freshness decision marked the source stale.
func (set StaleSourceSet) Stale(registeredSourceID string) bool {
	return set[registeredSourceID]
}

// DeriveSourceReport returns the serialized item derived from the shared
// decision. A stale source that is still serialized available is published as
// unavailable with the fail-closed source_unavailable reason the node API
// requires for every unavailable source, while its authentic observation
// timestamp and every identity, binding, revision and generation field are
// preserved; the local record is never mutated. A stale source that is already
// unavailable keeps its authentic reason untouched, and every item outside the
// decision is returned unchanged, so a genuinely fresh re-observation restores
// ordinary available reporting by itself.
func (set StaleSourceSet) DeriveSourceReport(report model.ContinuitySourceReportV1) model.ContinuitySourceReportV1 {
	if !set.Stale(report.RegisteredSourceID) || report.Availability != "available" {
		return report
	}
	reason := "source_unavailable"
	report.Availability = "unavailable"
	report.Reason = &reason
	return report
}
