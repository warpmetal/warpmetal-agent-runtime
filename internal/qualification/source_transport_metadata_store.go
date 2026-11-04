package qualification

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Runtime publishes VERIFIED metadata/originals, never local execution authority.
// Separate immutable phase files retain FIRST permission/adoption/case envelopes;
// no SOURCE carrier or grant is created while the local-grant wire is pending.
func (s Store) AdoptSourceTransportMetadata(box model.Sandbox, raw []byte, w SourceTransportMetadataWitness, now time.Time) error {
	m, err := VerifySourceTransportMetadata(raw, w, now)
	if err != nil || m.Applicability.SandboxID != box.ID || m.Applicability.SandboxGeneration != box.Generation {
		return ErrUntrusted
	}
	tree, key, err := s.Paths(box.ID)
	if err != nil {
		return ErrUntrusted
	}
	operator, err := s.read(key, tree, key, 4096)
	if err != nil || !bytes.Equal(operator, w.OperatorPEM) {
		return ErrUntrusted
	}
	for _, rel := range []string{"blobs", "source-transport", "source-transport/preparations"} {
		if s.childProductDirectory(filepath.Join(tree, rel), tree, key) != nil {
			return ErrUntrusted
		}
	}
	retain := func(name string, b []byte) error {
		if _, err := os.Lstat(name); os.IsNotExist(err) {
			if s.childProductFile(name, b) != nil || syncChildProductDirectory(filepath.Dir(name)) != nil {
				return ErrUntrusted
			}
			return nil
		}
		prior, err := s.read(name, tree, key, 512*1024)
		if err != nil || !bytes.Equal(prior, b) {
			return ErrUntrusted
		}
		return nil
	}
	pm := childFields(m.ProfileMetadata)
	for _, b := range [][]byte{canonicalBytes(pm["permission"]), canonicalBytes(pm["adoption"]), canonicalBytes(m.LocalCase), w.Authority, w.ProducerPEM} {
		if retain(filepath.Join(tree, "blobs", Digest(b)[7:]), b) != nil {
			return ErrUntrusted
		}
	}
	// Independent owner pin copied from registered config, not metadata keyId/PEM.
	trust := canonicalBytes(map[string]any{"formatVersion": 1, "authorityDigest": Digest(w.Authority), "producer": model.WorkspaceRegisteredProducer{KeyID: w.Producer.KeyID, KeySHA256: w.Producer.KeySHA256, ServerID: w.Producer.ServerID, NodeTokenHash: w.Producer.NodeTokenHash}})
	if retain(filepath.Join(tree, "source-transport", "authority.json"), trust) != nil {
		return ErrUntrusted
	}
	if m.Phase == "execute" {
		prior, err := s.read(filepath.Join(tree, "source-transport", "preparations", m.PreparationID+"-prepare.json"), tree, key, 512*1024)
		p, pe := DecodeSourceTransportMetadata(prior, m.TargetKind, m.PreparationID, "prepare")
		if err != nil || pe != nil || !sameProduct(p.ProfileMetadata, m.ProfileMetadata) || !sameProduct(p.LocalCase, m.LocalCase) || p.Entry != m.Entry || !sameProduct(p.PreparedTuple, m.PreparedTuple) || !sameProduct(p.Applicability, m.Applicability) || p.Qualification != m.Qualification {
			return ErrUntrusted
		}
	}
	name := filepath.Join(tree, "source-transport", "preparations", m.PreparationID+"-"+m.Phase+".json")
	if retain(name, canonicalBytes(json.RawMessage(raw))) != nil {
		return ErrUntrusted
	}
	return nil
}
