package state

// WP-211B local persistence for the verified in-cell agent-kit materialization
// receipt. The record is keyed by the deterministic materialization identity
// SCOPED TO THE WORKSPACE (sandbox + generation), so a reconcile retry of the
// same workspace reads the existing verified row instead of re-executing the
// cell materializer, while two cells on one node that share one account
// configuration/kit cannot read or overwrite each other's evidence. A
// conflicting different receipt for the same workspace fails closed.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

var ErrAgentKitMaterializationConflict = errors.New("agent kit materialization immutable state conflict")

func (s *Store) AgentKitMaterialization(ctx context.Context, materializationID, sandboxID string, sandboxGeneration int64) (*model.AgentKitMaterialization, error) {
	var envelope, skills []byte
	var record model.AgentKitMaterialization
	err := s.db.QueryRowContext(ctx, `SELECT operation_id,sandbox_id,sandbox_generation,configuration_id,
configuration_revision,configuration_digest,kit_digest,adoption_id,venue,closure_digest,envelope_digest,
receipt_digest,instruction_digest,skill_content_digests_json,envelope_json,verified_at
FROM agent_kit_materializations WHERE materialization_id=? AND sandbox_id=? AND sandbox_generation=?`,
		materializationID, sandboxID, sandboxGeneration).Scan(
		&record.ApplicationOperationID, &record.SandboxID, &record.SandboxGeneration,
		&record.ConfigurationID, &record.ConfigurationRevision, &record.ConfigurationDigest,
		&record.KitDigest, &record.AdoptionID, &record.Venue, &record.ClosureDigest,
		&record.EnvelopeDigest, &record.MaterializationReceiptDigest, &record.InstructionDigest,
		&skills, &envelope, &record.VerifiedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	record.FormatVersion = model.AgentKitMaterializationFormatVersion
	record.MaterializationID = materializationID
	record.EnvelopeJSON = envelope
	if err := json.Unmarshal(skills, &record.SkillContentDigests); err != nil {
		return nil, ErrAgentKitMaterializationConflict
	}
	if err := record.Validate(); err != nil {
		return nil, ErrAgentKitMaterializationConflict
	}
	return &record, nil
}

// PutAgentKitMaterialization inserts the first verified record and returns
// created=true; an existing equal record returns created=false; any differing
// record fails closed without overwriting the retained evidence.
func (s *Store) PutAgentKitMaterialization(ctx context.Context, record model.AgentKitMaterialization) (bool, error) {
	if err := record.Validate(); err != nil {
		return false, err
	}
	skills, err := json.Marshal(record.SkillContentDigests)
	if err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO agent_kit_materializations(
materialization_id,operation_id,sandbox_id,sandbox_generation,configuration_id,configuration_revision,
configuration_digest,kit_digest,adoption_id,venue,closure_digest,envelope_digest,receipt_digest,
instruction_digest,skill_content_digests_json,envelope_json,verified_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(materialization_id,sandbox_id,sandbox_generation) DO NOTHING`,
		record.MaterializationID, record.ApplicationOperationID, record.SandboxID,
		record.SandboxGeneration, record.ConfigurationID, record.ConfigurationRevision,
		record.ConfigurationDigest, record.KitDigest, record.AdoptionID, record.Venue,
		record.ClosureDigest, record.EnvelopeDigest, record.MaterializationReceiptDigest,
		record.InstructionDigest, skills, []byte(record.EnvelopeJSON), record.VerifiedAt,
	)
	if err != nil {
		return false, err
	}
	affected, _ := result.RowsAffected()
	if affected == 1 {
		return true, tx.Commit()
	}
	var retained model.AgentKitMaterialization
	var retainedEnvelope, retainedSkills []byte
	if err := tx.QueryRowContext(ctx, `SELECT operation_id,sandbox_id,sandbox_generation,configuration_id,
configuration_revision,configuration_digest,kit_digest,adoption_id,venue,closure_digest,envelope_digest,
receipt_digest,instruction_digest,skill_content_digests_json,envelope_json,verified_at
FROM agent_kit_materializations WHERE materialization_id=? AND sandbox_id=? AND sandbox_generation=?`,
		record.MaterializationID, record.SandboxID, record.SandboxGeneration).Scan(
		&retained.ApplicationOperationID, &retained.SandboxID, &retained.SandboxGeneration,
		&retained.ConfigurationID, &retained.ConfigurationRevision, &retained.ConfigurationDigest,
		&retained.KitDigest, &retained.AdoptionID, &retained.Venue, &retained.ClosureDigest,
		&retained.EnvelopeDigest, &retained.MaterializationReceiptDigest, &retained.InstructionDigest,
		&retainedSkills, &retainedEnvelope, &retained.VerifiedAt,
	); err != nil {
		return false, err
	}
	retained.FormatVersion = model.AgentKitMaterializationFormatVersion
	retained.MaterializationID = record.MaterializationID
	retained.EnvelopeJSON = retainedEnvelope
	if err := json.Unmarshal(retainedSkills, &retained.SkillContentDigests); err != nil {
		return false, ErrAgentKitMaterializationConflict
	}
	if !reflect.DeepEqual(retained, record) {
		return false, ErrAgentKitMaterializationConflict
	}
	return false, tx.Commit()
}

// AgentKitMaterializations lists retained verified records in deterministic
// materialization-id order (audit/diagnostic read; never authority).
func (s *Store) AgentKitMaterializations(ctx context.Context) ([]model.AgentKitMaterialization, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT materialization_id,sandbox_id,sandbox_generation
FROM agent_kit_materializations ORDER BY materialization_id,sandbox_id,sandbox_generation`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type key struct {
		id                string
		sandboxID         string
		sandboxGeneration int64
	}
	var keys []key
	for rows.Next() {
		var item key
		if err := rows.Scan(&item.id, &item.sandboxID, &item.sandboxGeneration); err != nil {
			return nil, err
		}
		keys = append(keys, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	records := make([]model.AgentKitMaterialization, 0, len(keys))
	for _, item := range keys {
		record, err := s.AgentKitMaterialization(ctx, item.id, item.sandboxID, item.sandboxGeneration)
		if err != nil {
			return nil, err
		}
		if record != nil {
			records = append(records, *record)
		}
	}
	return records, nil
}
