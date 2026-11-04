package qualification

import (
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"os"
	"path/filepath"
	"time"
)

// Private F3 root/control-owned projection of independently verified original
// signed outer demand and selected inner activation. No operator/domain wire
// change, new signer or descriptor1 conversion; only the owning gate may admit.
func (s Store) PublishQualificationPhysicalAllocation(box model.Sandbox, entry model.CellServiceV3, worktree string, c RealCase, now time.Time) error {
	boot, p, d, err := s.SelectedPolicy(box, entry, worktree, now)
	if err != nil || p.Run == nil {
		return ErrUntrusted
	}
	selected, err := s.ReadQualificationActivation(box, boot, p, d, now)
	if err != nil {
		return err
	}
	outer, err := s.QualificationPhysicalAllocation(box, c, p.Run.TupleDigest, now)
	if err != nil {
		return err
	}
	wire := map[string]any{"formatVersion": 1, "preparationId": entry.PreparationID, "authorityDigest": d.PolicyDigest, "tupleDigest": p.Run.TupleDigest, "innerDispatchStart": selected.Execution.DispatchStart, "firstPhysicalIndex": outer.FirstPhysicalIndex, "lastPhysicalIndex": outer.LastPhysicalIndex}
	tree, key, err := s.Paths(box.ID)
	if err != nil {
		return err
	}
	directory := filepath.Join(tree, "physical")
	if err = s.childProductDirectory(directory, tree, key); err != nil {
		return err
	}
	name := filepath.Join(directory, "qualification-"+entry.PreparationID+".json")
	raw := canonicalBytes(wire)
	if _, err = os.Lstat(name); os.IsNotExist(err) {
		if err = s.childProductFile(name, raw); err != nil {
			return err
		}
		return syncChildProductDirectory(directory)
	}
	original, err := s.read(name, tree, key, 65536)
	if err != nil || string(original) != string(raw) {
		return ErrUntrusted
	}
	return nil
}
