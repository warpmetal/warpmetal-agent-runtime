package qualification

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type SourceOpening struct {
	LedgerID          string `json:"ledgerId"`
	PhysicalRequests  int    `json:"physicalRequests"`
	ModelRequests     int    `json:"modelRequests"`
	Turns             int    `json:"turns"`
	Preparations      int    `json:"preparations"`
	ReservedUSDMicros int64  `json:"reservedUsdMicros"`
	ActualUSDMicros   int64  `json:"actualUsdMicros"`
}
type SourcePredecessor struct {
	CaseID               string `json:"caseId"`
	ConfigDigest         string `json:"configDigest"`
	DemandManifestDigest string `json:"demandManifestDigest"`
	QualificationID      string `json:"qualificationId"`
	TupleDigest          string `json:"tupleDigest"`
	PreparationID        string `json:"preparationId"`
	ReservationID        string `json:"reservationId"`
	PreparationOrdinal   int    `json:"preparationOrdinal"`
	ModelDispatchStart   int    `json:"modelDispatchStart"`
}
type SourceAllocationJoin struct {
	AllocationID string `json:"allocationId"`
	JournalID    string `json:"journalId"`
	RecordDigest string `json:"recordDigest"`
}
type SourceContinuation struct {
	FormatVersion   int                    `json:"formatVersion"`
	Database        string                 `json:"database"`
	Opening         SourceOpening          `json:"opening"`
	OpeningDigest   string                 `json:"openingDigest"`
	Predecessor     SourcePredecessor      `json:"predecessor"`
	AllocationJoins []SourceAllocationJoin `json:"allocationJoins"`
}

func sourceContinuationOpening(raw json.RawMessage, c RealCase) (SourceOpening, error) {
	var continuation SourceContinuation
	if workflowcontract.Validate(workflowcontract.BudgetSourceContinuation, "sourceContinuation", raw) != nil || decode(raw, &continuation) != nil ||
		CanonicalDigest(continuation.Opening) != continuation.OpeningDigest || workflowcontract.Validate(workflowcontract.BudgetSourceContinuation, "sourceContinuationCase13", canonicalBytes(c)) != nil {
		return SourceOpening{}, ErrUntrusted
	}
	return continuation.Opening, nil
}

// Explicit SOURCE+metadata selection: no fallback to a permissive family. The
// protected original config and ORIGINAL signed demand are owning inputs, not
// constructed from RPC. This reads/verifies; it cannot issue finite authority.
func VerifySourceContinuationAuthorityDemand(authority, envelope, operatorPEM []byte, now time.Time) (DemandManifest, SourceContinuation, error) {
	var empty DemandManifest
	var continuation SourceContinuation
	if workflowcontract.Validate(workflowcontract.BudgetSourceContinuation, "authority2", authority) != nil {
		return empty, continuation, ErrUntrusted
	}
	fields := childFields(authority)
	if childString(fields, "evidenceClass") != "source" || fields["sourceContinuation"] == nil {
		return empty, continuation, ErrUntrusted
	}
	var c RealCase
	if decode(fields["case"], &c) != nil || childString(fields, "caseId") != c.CaseID || childString(fields, "caseManifestDigest") != c.CaseManifestDigest || CanonicalDigest(fields["tupleInventory"]) != c.TupleInventoryDigest {
		return empty, continuation, ErrUntrusted
	}
	operator := childFields(fields["operator"])
	// authority2 keyIdentity is a raw hex pin; typedCase carries a digest URI.
	if Digest(operatorPEM) != c.OperatorKeySHA256 || childString(operator, "keySHA256") != strings.TrimPrefix(Digest(operatorPEM), "sha256:") || verifyChildEnvelope(envelope, childString(operator, "keyId"), operatorPEM) != nil {
		return empty, continuation, ErrUntrusted
	}
	var signed ChildEnvelope[DemandManifest]
	if decode(envelope, &signed) != nil || !sameProduct(signed.Payload.SourceContinuation, fields["sourceContinuation"]) ||
		signed.Payload.validate(c, now) != nil || decode(fields["sourceContinuation"], &continuation) != nil {
		return empty, continuation, ErrUntrusted
	}
	if childString(childFields(fields["tupleInventory"]), "candidateInventoryDigest") != signed.Payload.CandidateInventoryDigest {
		return empty, continuation, ErrUntrusted
	}
	return signed.Payload, continuation, nil
}

// Full-byte owning opening/run/two journals, not new-authority reflection. This
// does not create rows, re-sign old history, reuse the old qualification or refund.
func verifyMeasuredSourceOpening(ctx context.Context, continuation SourceContinuation, load func(string, int) ([]byte, error)) error {
	if ctx.Err() != nil || load == nil {
		return ErrUntrusted
	}
	raw, err := load("source-continuation-original-opening.json", 65536)
	var observation struct {
		Database string        `json:"database"`
		Opening  SourceOpening `json:"opening"`
	}
	if err != nil || decode(raw, &observation) != nil || !bytesCanonical(raw, observation) || observation.Database != continuation.Database || !sameProduct(observation.Opening, continuation.Opening) || CanonicalDigest(observation.Opening) != continuation.OpeningDigest {
		return ErrUntrusted
	}
	opening := observation.Opening
	raw, err = load("source-continuation-original-predecessor.json", 65536)
	var run struct {
		State              string `json:"state"`
		CaseID             string `json:"caseId"`
		ConfigDigest       string `json:"configDigest"`
		QualificationID    string `json:"qualificationId"`
		TupleDigest        string `json:"tupleDigest"`
		PreparationID      string `json:"preparationId"`
		ReservationID      string `json:"reservationId"`
		PreparationOrdinal int    `json:"preparationOrdinal"`
		ModelDispatchStart int    `json:"modelDispatchStart"`
	}
	old := continuation.Predecessor
	if err != nil || decode(raw, &run) != nil || !bytesCanonical(raw, run) || run.State != "accepted" || run.CaseID != old.CaseID || run.ConfigDigest != old.ConfigDigest || run.QualificationID != old.QualificationID || run.TupleDigest != old.TupleDigest || run.PreparationID != old.PreparationID || run.ReservationID != old.ReservationID || run.PreparationOrdinal != old.PreparationOrdinal || run.ModelDispatchStart != old.ModelDispatchStart {
		return ErrUntrusted
	}
	for _, join := range continuation.AllocationJoins {
		if !safeID.MatchString(join.JournalID) {
			return ErrUntrusted
		}
		raw, err := load("source-continuation-original-journal-"+join.JournalID+".json", 65536)
		if err != nil || Digest(raw) != join.RecordDigest {
			return ErrUntrusted
		}
		fields := childFields(raw)
		if childString(fields, "subjectId") != old.QualificationID || childString(fields, "reservationId") != old.ReservationID || childString(fields, "configDigest") != old.ConfigDigest || childString(fields, "demandManifestDigest") != old.DemandManifestDigest || childString(fields, "ledgerId") != opening.LedgerID || childString(childFields(fields["allocation"]), "allocationId") != join.AllocationID {
			return ErrUntrusted
		}
	}
	return ctx.Err()
}

func (p *Producer) CurrentSourceContinuationAuthority(ctx context.Context, c RealCase) ([]byte, []byte, error) {
	if p == nil {
		return nil, nil, ErrUntrusted
	}
	authority, err := p.read("physical-gate-authority.json", 65536)
	if err != nil {
		return nil, nil, err
	}
	envelope, err := p.read("physical-gate-demand-envelope.json", 65536)
	if err != nil {
		return nil, nil, err
	}
	public, err := p.read("physical-gate-operator.pem", 4096)
	if err != nil {
		return nil, nil, err
	}
	_, continuation, err := VerifySourceContinuationAuthorityDemand(authority, envelope, public, time.Now())
	if err != nil || !sameProduct(childFields(authority)["case"], c) || verifyMeasuredSourceOpening(ctx, continuation, p.read) != nil {
		return nil, nil, ErrUntrusted
	}
	return authority, envelope, nil
}

// Protected per-demand selection, not a global pin/config or new grant. Caller
// measured the independent opening before this publication; normal signature and
// complete current installation checks remain separate mandatory boundaries.
func (s Store) EnrollSourceContinuationAuthority(box model.Sandbox, c RealCase, authority, envelope []byte) error {
	tree, key, err := s.Paths(box.ID)
	if err != nil {
		return err
	}
	public, err := s.read(key, tree, key, 4096)
	if err != nil {
		return err
	}
	_, _, err = VerifySourceContinuationAuthorityDemand(authority, envelope, public, time.Now())
	if err != nil || !sameProduct(childFields(authority)["case"], c) {
		return ErrUntrusted
	}
	parent := filepath.Join(tree, "snapshots", c.DemandManifestDigest[7:])
	if s.childProductDirectory(filepath.Join(tree, "snapshots"), tree, key) != nil || s.childProductDirectory(parent, tree, key) != nil {
		return ErrUntrusted
	}
	name := filepath.Join(parent, "source-authority.json")
	if _, err = os.Lstat(name); os.IsNotExist(err) {
		if s.childProductFile(name, authority) != nil || syncChildProductDirectory(parent) != nil {
			return ErrUntrusted
		}
	} else {
		raw, err := s.read(name, tree, key, 65536)
		if err != nil || string(raw) != string(authority) {
			return ErrUntrusted
		}
	}
	return nil
}

func validateChildGeneration(g ChildProductGeneration, raw []byte) error {
	if len(g.Demand.Payload.SourceContinuation) != 0 {
		return workflowcontract.ValidateChildProductSourceContinuation(g.FormatVersion, "controlGeneration", raw)
	}
	return workflowcontract.ValidateChildProductVersion(g.FormatVersion, "controlGeneration", raw)
}

// Discovery from ORIGINAL signed sidecars is not policy/installation acceptance.
// It selects only the independently enrolled family for the later full reader.
func (s Store) ControllerSourceContinuation(box model.Sandbox, policyDigest string) (RealCase, json.RawMessage, error) {
	var empty RealCase
	tree, key, err := s.Paths(box.ID)
	if err != nil || !hash.MatchString(policyDigest) {
		return empty, nil, ErrUntrusted
	}
	raw, err := s.signed(tree, key, "snapshots/"+policyDigest[7:]+"/policy", 131072)
	var header struct {
		FormatVersion int      `json:"formatVersion"`
		Case          RealCase `json:"case"`
	}
	if err != nil || Digest(raw) != policyDigest || json.Unmarshal(raw, &header) != nil {
		return empty, nil, ErrUntrusted
	}
	if header.FormatVersion != 5 || header.Case.FormatVersion != 2 {
		return header.Case, nil, nil
	}
	raw, err = s.signed(tree, key, "snapshots/"+header.Case.DemandManifestDigest[7:]+"/demand", 65536)
	var d DemandManifest
	if err != nil || decode(raw, &d) != nil || d.validate(header.Case, time.Now()) != nil {
		return empty, nil, ErrUntrusted
	}
	return header.Case, d.SourceContinuation, nil
}
