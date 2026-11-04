package state

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// Raw original files from the SAME protected native verifier read; not caller
// observations, current-clock summaries or backend reserve/actual adjustments.
type NativeSettlementOriginals struct {
	Journal, Request, Response, Completion, Transport, ProviderResponse []byte
	ProviderRequestID                                                   string
}

func nativeSettlementFactID(id string) string {
	return "native_settlement_" + paidOperationFactID(id)[15:]
}
func (s *Store) RetainNativeSettlementOriginals(ctx context.Context, id string, subject PhysicalSubject, e model.PhysicalSettlement, originals NativeSettlementOriginals) error {
	if !model.PhysicalIDValid(id) || e.Validate() != nil || len(originals.Journal) == 0 || len(originals.Journal) > 65536 || len(originals.Request) > 32768 || len(originals.Response) != e.ResponseByteCount || len(originals.Response) > 262144 || len(originals.Completion) == 0 || len(originals.Completion) > 65536 || model.RawPhysicalDigest(originals.Request) != e.RequestDigest || model.RawPhysicalDigest(originals.Response) != e.ResponseDigest || model.RawPhysicalDigest(originals.Completion) != e.EvidenceDigest {
		return ErrPhysicalConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	var o PhysicalOperation
	if tx.QueryRowContext(ctx, `SELECT operation_json FROM physical_gate_operations WHERE operation_id=?`, id).Scan(&raw) != nil || json.Unmarshal(raw, &o) != nil || o.Permit.Offline != nil || o.Permit.Caller != subject || o.Permit.Request.RequestDigest != e.RequestDigest || e.UsageUsdMicros > o.ReservedUsdMicros {
		return ErrPhysicalConflict
	}
	if len(originals.Request) == 0 && (o.Permit.Case.AccountingVersion != 2 || o.Permit.Request.Consumer != "access" || !model.PhysicalIDValid(originals.ProviderRequestID)) {
		return ErrPhysicalConflict
	}
	bodies := [][]byte{originals.Journal, originals.Request, originals.Response, originals.Completion}
	if len(originals.Transport) > 0 {
		if len(originals.Transport) > 1024 {
			return ErrPhysicalConflict
		}
		bodies = append(bodies, originals.Transport)
		var metadata struct {
			FormatVersion     int    `json:"formatVersion"`
			ProviderRequestID string `json:"providerRequestId"`
		}
		if len(originals.ProviderResponse) > 2048 || model.DecodePhysicalClosed(originals.ProviderResponse, &metadata) != nil || metadata.FormatVersion != 1 || metadata.ProviderRequestID != originals.ProviderRequestID || !model.PhysicalIDValid(metadata.ProviderRequestID) || len(metadata.ProviderRequestID) > 128 {
			return ErrPhysicalConflict
		}
		bodies = append(bodies, originals.ProviderResponse)
	}
	for _, body := range bodies {
		digest := model.RawPhysicalDigest(body)
		key := "native_original_" + digest[7:]
		if _, err = tx.ExecContext(ctx, `INSERT INTO physical_gate_facts VALUES(?,?) ON CONFLICT(fact_id) DO NOTHING`, key, body); err != nil {
			return err
		}
		var first []byte
		if tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, key).Scan(&first) != nil || !bytes.Equal(first, body) {
			return ErrPhysicalConflict
		}
	}
	fields := map[string]any{"journalDigest": model.RawPhysicalDigest(originals.Journal), "requestDigest": e.RequestDigest, "responseDigest": e.ResponseDigest, "completionDigest": e.EvidenceDigest, "settlement": e}
	if len(originals.Transport) > 0 {
		fields["transportDigest"] = model.RawPhysicalDigest(originals.Transport)
		fields["providerResponseDigest"] = model.RawPhysicalDigest(originals.ProviderResponse)
		completed := time.Now().UTC().Format(time.RFC3339Nano)
		var prior []byte
		if tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, nativeSettlementFactID(id)).Scan(&prior) == nil {
			var first map[string]json.RawMessage
			if json.Unmarshal(prior, &first) != nil || json.Unmarshal(first["completedAt"], &completed) != nil {
				return ErrPhysicalConflict
			}
		}
		fields["completedAt"] = completed
		if originals.ProviderRequestID != "" {
			fields["providerRequestId"] = originals.ProviderRequestID
		}
	}
	index, _ := json.Marshal(fields)
	if err = retainPaidFact(ctx, tx, nativeSettlementFactID(id), index); err != nil {
		return err
	}
	return tx.Commit()
}

// Only originals independently retained by the owning verifier are exposed.
// An RPC-supplied amount or a remote readback cannot synthesize this archive.
func (s *Store) NativeProviderOriginals(ctx context.Context, id string, e model.PhysicalSettlement) (NativeSettlementOriginals, string, error) {
	var out NativeSettlementOriginals
	raw, err := s.PhysicalFact(ctx, nativeSettlementFactID(id))
	if err != nil {
		return out, "", err
	}
	var index struct {
		JournalDigest, RequestDigest, ResponseDigest, CompletionDigest, TransportDigest, ProviderResponseDigest, CompletedAt, ProviderRequestID string
		Settlement                                                                                                                              model.PhysicalSettlement
	}
	if json.Unmarshal(raw, &index) != nil || index.Settlement != e || index.TransportDigest == "" {
		return out, "", ErrPhysicalConflict
	}
	for digest, target := range map[string]*[]byte{index.JournalDigest: &out.Journal, index.RequestDigest: &out.Request, index.ResponseDigest: &out.Response, index.CompletionDigest: &out.Completion, index.TransportDigest: &out.Transport, index.ProviderResponseDigest: &out.ProviderResponse} {
		if !model.PhysicalDigestValid(digest) {
			return out, "", ErrPhysicalConflict
		}
		value, err := s.PhysicalFact(ctx, "native_original_"+digest[7:])
		if err != nil || model.RawPhysicalDigest(value) != digest {
			return out, "", ErrPhysicalConflict
		}
		*target = value
	}
	if _, err = time.Parse(time.RFC3339Nano, index.CompletedAt); err != nil {
		return out, "", ErrPhysicalConflict
	}
	out.ProviderRequestID = index.ProviderRequestID
	return out, index.CompletedAt, nil
}
