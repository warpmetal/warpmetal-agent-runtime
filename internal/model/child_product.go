package model

import (
	"encoding/json"
	"errors"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// Immutable complete frozen delivery, not a signature/current installed proof or
// activity grant. Raw components remain private until the protected Store joins
// signed bytes, installed qualification/applicability and actual V3 authority.
type ChildProductDelivery struct {
	raw              []byte
	preparationID    string
	phase            string
	generationDigest string
}

func (d ChildProductDelivery) Bytes() []byte            { return append([]byte(nil), d.raw...) }
func (d ChildProductDelivery) PreparationID() string    { return d.preparationID }
func (d ChildProductDelivery) Phase() string            { return d.phase }
func (d ChildProductDelivery) GenerationDigest() string { return d.generationDigest }

type ChildProductEffectDelivery struct {
	raw           []byte
	preparationID string
	ordinal       int
}

func (d ChildProductEffectDelivery) Bytes() []byte         { return append([]byte(nil), d.raw...) }
func (d ChildProductEffectDelivery) PreparationID() string { return d.preparationID }
func (d ChildProductEffectDelivery) Ordinal() int          { return d.ordinal }

func DecodeChildProductDelivery(raw []byte) (ChildProductDelivery, error) {
	var empty ChildProductDelivery
	var header struct {
		FormatVersion int `json:"formatVersion"`
		Generation    struct {
			Demand struct {
				Payload struct {
					SourceContinuation json.RawMessage `json:"sourceContinuation"`
				} `json:"payload"`
			} `json:"demand"`
		} `json:"generation"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return empty, errors.New("child product delivery refused")
	}
	validate := workflowcontract.ValidateChildProductVersion
	if len(header.Generation.Demand.Payload.SourceContinuation) != 0 {
		validate = workflowcontract.ValidateChildProductSourceContinuation
	}
	if validate(header.FormatVersion, "controlDelivery", raw) != nil {
		return empty, errors.New("child product delivery refused")
	}
	var selected struct {
		Descriptor struct {
			PreparationID           string  `json:"preparationId"`
			Phase                   string  `json:"phase"`
			GenerationDigest        string  `json:"generationDigest"`
			PreparedTupleDigest     string  `json:"preparedTupleDigest"`
			PreparationPolicyDigest string  `json:"preparationPolicyDigest"`
			PolicyDigest            *string `json:"policyDigest"`
		} `json:"descriptor"`
		Generation json.RawMessage `json:"generation"`
	}
	var generation struct {
		PreparationID     string `json:"preparationId"`
		Phase             string `json:"phase"`
		PreparationPolicy struct {
			Payload json.RawMessage `json:"payload"`
		} `json:"preparationPolicy"`
		Policy *struct {
			Payload json.RawMessage `json:"payload"`
		} `json:"policy"`
	}
	if json.Unmarshal(raw, &selected) != nil || json.Unmarshal(selected.Generation, &generation) != nil || selected.Descriptor.PreparationID != generation.PreparationID || selected.Descriptor.Phase != generation.Phase || WorkspaceDigest(selected.Generation) != selected.Descriptor.GenerationDigest || WorkspaceDigest(generation.PreparationPolicy.Payload) != selected.Descriptor.PreparationPolicyDigest {
		return empty, errors.New("child product generation integrity refused")
	}
	var preparation struct {
		Preparation struct {
			PreparationID       string          `json:"preparationId"`
			PreparedTuple       json.RawMessage `json:"preparedTuple"`
			PreparedTupleDigest string          `json:"preparedTupleDigest"`
			InputID             string          `json:"inputId"`
		} `json:"preparation"`
		Instructions struct {
			InputID string `json:"inputId"`
		} `json:"instructions"`
	}
	if json.Unmarshal(generation.PreparationPolicy.Payload, &preparation) != nil || preparation.Preparation.PreparationID != generation.PreparationID || preparation.Preparation.PreparedTupleDigest != selected.Descriptor.PreparedTupleDigest || WorkspaceDigest(preparation.Preparation.PreparedTuple) != selected.Descriptor.PreparedTupleDigest || preparation.Preparation.InputID != preparation.Instructions.InputID {
		return empty, errors.New("child product preparation integrity refused")
	}
	if generation.Phase == "execute" {
		if generation.Policy == nil || selected.Descriptor.PolicyDigest == nil || WorkspaceDigest(generation.Policy.Payload) != *selected.Descriptor.PolicyDigest {
			return empty, errors.New("full product policy integrity refused")
		}
		var policy struct {
			PreparationPolicyDigest string `json:"preparationPolicyDigest"`
		}
		if json.Unmarshal(generation.Policy.Payload, &policy) != nil || policy.PreparationPolicyDigest != selected.Descriptor.PreparationPolicyDigest {
			return empty, errors.New("product/preparation generation drift")
		}
	}
	return ChildProductDelivery{raw: append([]byte(nil), raw...), preparationID: generation.PreparationID, phase: generation.Phase, generationDigest: selected.Descriptor.GenerationDigest}, nil
}

func DecodeChildProductEffectDelivery(raw []byte) (ChildProductEffectDelivery, error) {
	var empty ChildProductEffectDelivery
	if workflowcontract.ValidateChildProduct("effectControl", raw) != nil {
		return empty, errors.New("child product effect delivery refused")
	}
	var selected struct {
		PreparationID string          `json:"preparationId"`
		Permit        json.RawMessage `json:"permit"`
		Approval      struct {
			PermitDigest string `json:"permitDigest"`
		} `json:"approval"`
	}
	var permit struct {
		EffectOrdinal int `json:"effectOrdinal"`
	}
	if json.Unmarshal(raw, &selected) != nil || json.Unmarshal(selected.Permit, &permit) != nil || WorkspaceDigest(selected.Permit) != selected.Approval.PermitDigest {
		return empty, errors.New("child product effect integrity refused")
	}
	return ChildProductEffectDelivery{append([]byte(nil), raw...), selected.PreparationID, permit.EffectOrdinal}, nil
}
