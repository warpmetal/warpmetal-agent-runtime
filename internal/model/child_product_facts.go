package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// F1 canonical22:27 additive readonly projection. Immutable ORIGINAL fragments,
// not signed PRODUCT fields, installed authority, a prepared receipt or gate ACK.
// The qualification owner subsequently decodes its exact existing fact structs.
type ChildProductOriginalFacts struct {
	preparationID, phase, generationDigest string
	authority, installed, lifecycle        []byte
}

func (f ChildProductOriginalFacts) PreparationID() string    { return f.preparationID }
func (f ChildProductOriginalFacts) Phase() string            { return f.phase }
func (f ChildProductOriginalFacts) GenerationDigest() string { return f.generationDigest }
func (f ChildProductOriginalFacts) AuthorityBytes() []byte {
	return append([]byte(nil), f.authority...)
}
func (f ChildProductOriginalFacts) InstalledBytes() []byte {
	return append([]byte(nil), f.installed...)
}
func (f ChildProductOriginalFacts) LifecycleBytes() []byte {
	return append([]byte(nil), f.lifecycle...)
}

func DecodeChildProductOriginalFacts(raw []byte) (ChildProductOriginalFacts, error) {
	var empty ChildProductOriginalFacts
	if len(raw) == 0 || len(raw) > 512*1024 || !utf8.Valid(raw) || rejectDuplicateJSONFields(raw) != nil {
		return empty, errors.New("original child fact projection framing refused")
	}
	var wire struct {
		FormatVersion    int             `json:"formatVersion"`
		PreparationID    string          `json:"preparationId"`
		Phase            string          `json:"phase"`
		GenerationDigest string          `json:"generationDigest"`
		Authority        json.RawMessage `json:"authority"`
		Installed        json.RawMessage `json:"installed"`
		Lifecycle        json.RawMessage `json:"lifecycle"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var keys map[string]json.RawMessage
	if d.Decode(&wire) != nil || d.Decode(new(any)) != io.EOF || json.Unmarshal(raw, &keys) != nil || len(keys) != 7 || wire.FormatVersion != 1 ||
		!PhysicalIDValid(wire.PreparationID) || (wire.Phase != "prepare" && wire.Phase != "execute") || !PhysicalDigestValid(wire.GenerationDigest) {
		return empty, errors.New("original child fact projection scope refused")
	}
	for _, name := range []string{"formatVersion", "preparationId", "phase", "generationDigest", "authority", "installed", "lifecycle"} {
		if keys[name] == nil {
			return empty, errors.New("original child fact projection fields refused")
		}
	}
	for _, part := range []json.RawMessage{wire.Authority, wire.Installed, wire.Lifecycle} {
		trimmed := bytes.TrimSpace(part)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return empty, errors.New("original child owning facts absent")
		}
	}
	return ChildProductOriginalFacts{preparationID: wire.PreparationID, phase: wire.Phase, generationDigest: wire.GenerationDigest,
		authority: append([]byte(nil), wire.Authority...), installed: append([]byte(nil), wire.Installed...), lifecycle: append([]byte(nil), wire.Lifecycle...)}, nil
}
