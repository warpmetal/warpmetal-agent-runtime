package qualification

import (
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"time"
)

// Separate signed typed outer authority; never rewrite legacy inner activation,
// qualification prefix, descriptor1, shell2 or its historical reservation.
func (s Store) QualificationPhysicalAllocation(box model.Sandbox, c RealCase, tuple string, now time.Time) (DemandAllocation, error) {
	var empty DemandAllocation
	d, err := s.ReadTypedDemand(box, c, now)
	if err != nil {
		return empty, err
	}
	found := false
	for _, a := range d.all() {
		if a.Kind == "qualification" && a.TupleDigest == tuple && a.Scope.SandboxID == box.ID && a.Scope.SandboxGeneration == box.Generation {
			if found {
				return empty, ErrUntrusted
			}
			empty = a
			found = true
		}
	}
	if !found || empty.ModelRequests != 2 || empty.AccessRequests != 0 || empty.PreparationOrdinal < 1 {
		return DemandAllocation{}, ErrUntrusted
	}
	return empty, nil
}
