package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type ProviderOpeningControl interface {
	AcceptProviderAccountingOpening(context.Context, json.RawMessage) (json.RawMessage, error)
}

type providerOpeningInputs struct {
	authority, demand, backend json.RawMessage
	operator                   []byte
}

// Selection alone is not trust or authority. The initializer reopens every
// selected original through the existing protected Producer reader. Peeking
// avoids imposing a new key-read requirement on an unrelated legacy pass.
func ProviderAccountingSelected(config *ProducerConfig) (bool, error) {
	if config == nil {
		return false, nil
	}
	path := filepath.Join(config.EvidenceRoot, "physical-gate-authority.json")
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !st.Mode().IsRegular() || st.Size() > 65536 {
		return false, ErrUntrusted
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 65536 {
		return false, ErrUntrusted
	}
	var fields map[string]json.RawMessage
	if decode(raw, &fields) != nil {
		return false, ErrUntrusted
	}
	var version int
	if json.Unmarshal(fields["formatVersion"], &version) != nil {
		return false, ErrUntrusted
	}
	switch version {
	case 1, 2:
		return false, nil
	case 3, 5:
		return true, nil
	default:
		return false, ErrUntrusted
	}
}

func (p *Producer) providerOpeningInputs() (providerOpeningInputs, bool, error) {
	var in providerOpeningInputs
	if p == nil || p.key == nil {
		return in, false, ErrUntrusted
	}
	_, err := os.Lstat(filepath.Join(p.config.EvidenceRoot, "physical-gate-authority.json"))
	if errors.Is(err, os.ErrNotExist) {
		return in, false, nil
	}
	if err != nil {
		return in, false, ErrUntrusted
	}
	in.authority, err = p.read("physical-gate-authority.json", 65536)
	if err != nil {
		return in, false, err
	}
	var version struct {
		FormatVersion int `json:"formatVersion"`
	}
	if json.Unmarshal(in.authority, &version) != nil {
		return in, false, ErrUntrusted
	}
	if version.FormatVersion == 1 || version.FormatVersion == 2 {
		return in, false, nil
	}
	if version.FormatVersion != 3 && version.FormatVersion != 5 {
		return in, false, ErrUntrusted
	}
	if in.demand, err = p.read("physical-gate-demand-envelope.json", 65536); err != nil {
		return in, true, err
	}
	if in.operator, err = p.read("physical-gate-operator.pem", 4096); err != nil {
		return in, true, err
	}
	if in.backend, err = p.read("provider-backend-opening.json", 65536); err != nil {
		return in, true, err
	}
	return in, true, nil
}

// Fixed root-private handoff. No authority3 means historical behavior; an
// invalid present authority3 is a failure. The first pair is never regenerated
// on restart, UNKNOWN, account change or case mutation.
func (p *Producer) InitializeProviderAccounting(ctx context.Context, store *state.Store, control ProviderOpeningControl) error {
	in, selected, err := p.providerOpeningInputs()
	if err != nil || !selected {
		return err
	}
	if store == nil || control == nil {
		return ErrUntrusted
	}
	if sameProduct(childFields(in.authority)["formatVersion"], 5) {
		return p.initializeParticipantAccounting(ctx, store, control, in)
	}
	runtime, err := p.ObserveProviderOpening(ctx, store, in.authority, in.demand, in.backend, in.operator)
	if err != nil {
		return err
	}
	pair := canonicalBytes(map[string]any{"formatVersion": 2, "backend": in.backend, "runtime": runtime})
	first, err := store.PhysicalFact(ctx, "provider_opening_pair")
	if err != nil {
		return err
	}
	if len(first) > 0 {
		if !sameProduct(json.RawMessage(first), json.RawMessage(pair)) {
			return ErrUntrusted
		}
		return nil
	}
	if _, err = control.AcceptProviderAccountingOpening(ctx, pair); err != nil {
		return err
	}
	return store.AcceptProviderOpening(ctx, pair)
}

func (p *Producer) ProviderPhysicalCase(ctx context.Context, current model.Manifest, store *state.Store, b PhysicalBaseline) (state.PhysicalCase, error) {
	var empty state.PhysicalCase
	if (b.Case.FormatVersion != 3 && b.Case.FormatVersion != 5) || len(b.HistoryDigests) != 0 || len(b.SourceContinuation) != 0 || p.config.ServerID != current.ServerID {
		return empty, ErrUntrusted
	}
	in, selected, err := p.providerOpeningInputs()
	if err != nil || !selected {
		return empty, ErrUntrusted
	}
	if !sameProduct(childFields(in.authority)["case"], b.Case) {
		return empty, ErrUntrusted
	}
	retained, err := store.ProviderOpening(ctx)
	if err != nil {
		return empty, err
	}
	runtime, err := p.ObserveProviderOpening(ctx, store, in.authority, in.demand, in.backend, in.operator)
	if err != nil {
		return empty, err
	}
	if b.Case.FormatVersion == 5 {
		if err := p.AcceptProviderParticipantOpening(ctx, store, in.authority, in.demand, retained, in.operator); err != nil {
			return empty, err
		}
	} else if !sameProduct(retained, map[string]any{"formatVersion": 2, "backend": in.backend, "runtime": runtime}) {
		return empty, ErrUntrusted
	}
	anchor, err := store.PhysicalAnchor(ctx)
	if err != nil || anchor == nil || anchor.TaskID != b.TaskID || anchor.ServerID != current.ServerID || anchor.CaseDigest != b.Case.CaseManifestDigest {
		return empty, ErrUntrusted
	}
	return *anchor, nil
}
