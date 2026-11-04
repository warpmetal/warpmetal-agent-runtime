package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

// These are PRIVATE verified owner facts, not producer/RPC schemas. Existing
// paid case/rows are immutable; local slots share its database and cap1 owner.
type OfflineSlot struct {
	Caller                                                                 PhysicalSubject
	PreparationID, SessionID, InputID, Oracle, Consumer                    string
	AuthorityDigest, AdmissionDigest, PreparedReceiptDigest, ControlDigest string
	ControlRevision                                                        int64
	RequestIndex, PreparationOrdinal, LocalDeliveryOrdinal                 int
}
type OfflineWindow struct {
	WindowID, CandidateDigest, FixtureDigest, OpeningDigest, ExpiresAt string
	Slots                                                              []OfflineSlot
}
type OfflineAdmission struct {
	WindowID, WindowDigest string
	Slot                   OfflineSlot
}

// CompleteOffline accepts this ONLY from the owning verified terminal consumer,
// never from the reverse RPC, cancel ACK, timer or plugin's response hook.
type OfflineTerminal struct {
	OperationID                                                                             string
	Caller                                                                                  PhysicalSubject
	PreparationID, SessionID, InputID, RequestDigest                                        string
	ControlRevision, TerminalRevision                                                       int64
	ControlDigest, TerminalDigest, EventsDigest, QuiescenceDigest, SocketDigest, ToolDigest string
}

func (s *Store) ensurePhysicalClassSchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(physical_gate_operations)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var def sql.NullString
		if err = rows.Scan(&cid, &name, &kind, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "evidence_class" {
			found = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if found {
		return nil
	}
	// Additive SQLite upgrade: no row, original JSON, key, index or owner rewritten.
	_, err = s.db.ExecContext(ctx, `ALTER TABLE physical_gate_operations ADD COLUMN evidence_class TEXT NOT NULL DEFAULT 'PAID' CHECK(evidence_class IN ('PAID','OFFLINE'))`)
	return err
}

type physicalQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func physicalOpening(ctx context.Context, q physicalQuery) (string, error) {
	var original [][]byte
	rows, err := q.QueryContext(ctx, `SELECT operation_json FROM physical_gate_operations ORDER BY rowid`)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return "", err
		}
		original = append(original, raw)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	var c []byte
	var owner string
	err = q.QueryRowContext(ctx, `SELECT case_json FROM physical_gate_case WHERE singleton=1`).Scan(&c)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	err = q.QueryRowContext(ctx, `SELECT operation_id FROM physical_gate_owner WHERE singleton=1`).Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	return model.WorkspaceDigest(struct {
		Case       []byte
		Operations [][]byte
		Owner      string
	}{c, original, owner}), nil
}
func (s *Store) PhysicalOpeningDigest(ctx context.Context) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	d, err := physicalOpening(ctx, tx)
	if err != nil {
		return "", err
	}
	return d, tx.Commit()
}
func validOfflineSlot(a OfflineSlot) bool {
	for _, id := range []string{a.PreparationID, a.SessionID, a.InputID, a.Caller.SandboxID, a.Caller.NativeInstance} {
		if !model.PhysicalIDValid(id) {
			return false
		}
	}
	for _, d := range []string{a.AuthorityDigest, a.AdmissionDigest, a.PreparedReceiptDigest, a.ControlDigest, a.Caller.NativeIdentityDigest} {
		if !model.PhysicalDigestValid(d) {
			return false
		}
	}
	return a.Caller.SandboxGeneration > 0 && a.ControlRevision > 0 && a.RequestIndex > 0 && a.PreparationOrdinal > 0 && a.LocalDeliveryOrdinal > 0 && ((a.Consumer == "product" && (a.Oracle == "http_cancel" || a.Oracle == "tool_cancel")) || (a.Consumer == "parent" && a.Oracle == "controller_deadline"))
}
func (p PhysicalPermit) validateOffline() bool {
	a := p.Offline
	return a != nil && model.PhysicalIDValid(a.WindowID) && model.PhysicalDigestValid(a.WindowDigest) && validOfflineSlot(a.Slot) && p.Request.Validate() == nil && p.Caller == a.Slot.Caller && p.Request.PreparationID == a.Slot.PreparationID && p.Request.Consumer == a.Slot.Consumer && p.Request.RequestIndex == a.Slot.RequestIndex && p.Request.OuterPhysicalIndex == a.Slot.LocalDeliveryOrdinal && p.Request.InnerPhysicalIndex == nil && p.Request.AuthorityDigest == a.Slot.AuthorityDigest
}
func readOfflineWindow(ctx context.Context, q physicalQuery, id string) (OfflineWindow, error) {
	var raw []byte
	var w OfflineWindow
	if q.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, "offline-window:"+id).Scan(&raw) != nil || json.Unmarshal(raw, &w) != nil {
		return w, ErrPhysicalConflict
	}
	return w, nil
}

// Private SAME-owner storage positioning; not a case/native/RPC ordinal. Window
// and operation JSON retain their original local selectors and digests unchanged.
type offlineWindowPosition struct{ DeliveryBase int }

func offlineStoragePosition(ctx context.Context, q physicalQuery, w OfflineWindow, slot OfflineSlot) (int, error) {
	var raw []byte
	var position offlineWindowPosition
	err := q.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, "offline-position:"+w.WindowID).Scan(&raw)
	legacy := errors.Is(err, sql.ErrNoRows)
	if legacy {
		// Older protected windows have no mapping. Preserve their exact originals;
		// old window ordinals were already cumulative. Never rewrite/backfill them.
		if len(w.Slots) != 3 {
			return 0, ErrPhysicalConflict
		}
		position.DeliveryBase = w.Slots[0].LocalDeliveryOrdinal - 1
	} else if err != nil || json.Unmarshal(raw, &position) != nil {
		return 0, ErrPhysicalConflict
	}
	if position.DeliveryBase < 0 || position.DeliveryBase%3 != 0 || len(w.Slots) != 3 {
		return 0, ErrPhysicalConflict
	}
	selected := 0
	for i, a := range w.Slots {
		ordinal := i + 1
		if legacy {
			ordinal += position.DeliveryBase
		}
		if a.LocalDeliveryOrdinal != ordinal || a.PreparationOrdinal != ordinal {
			return 0, ErrPhysicalConflict
		}
		if reflect.DeepEqual(a, slot) {
			selected = position.DeliveryBase + i + 1
		}
	}
	if selected == 0 {
		return 0, ErrPhysicalConflict
	}
	return selected, nil
}

func offlinePredecessorsTerminal(ctx context.Context, q physicalQuery) error {
	var owner string
	if err := q.QueryRowContext(ctx, `SELECT operation_id FROM physical_gate_owner WHERE singleton=1`).Scan(&owner); !errors.Is(err, sql.ErrNoRows) {
		return ErrPhysicalConflict
	}
	rows, err := q.QueryContext(ctx, `SELECT operation_json FROM physical_gate_operations WHERE evidence_class='OFFLINE'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var o PhysicalOperation
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &o) != nil || o.Permit.Offline == nil || o.Phase != "local-terminal" || o.LocalTerminal == nil || o.Settlement != nil || o.ReservedUsdMicros != PhysicalReservationUsdMicros {
			return ErrPhysicalConflict
		}
	}
	return rows.Err()
}
func (s *Store) AdoptOfflineWindow(ctx context.Context, w OfflineWindow) error {
	if !model.PhysicalIDValid(w.WindowID) || len(w.Slots) != 3 {
		return ErrPhysicalConflict
	}
	for _, d := range []string{w.CandidateDigest, w.FixtureDigest, w.OpeningDigest} {
		if !model.PhysicalDigestValid(d) {
			return ErrPhysicalConflict
		}
	}
	exp, err := time.Parse(time.RFC3339Nano, w.ExpiresAt)
	if err != nil || !exp.After(time.Now()) {
		return ErrPhysicalConflict
	}
	seen := map[string]bool{}
	preps, sessions, inputs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range w.Slots {
		if !validOfflineSlot(a) || seen[a.Oracle] || preps[a.PreparationID] || sessions[a.SessionID] || inputs[a.InputID] {
			return ErrPhysicalConflict
		}
		seen[a.Oracle] = true
		preps[a.PreparationID] = true
		sessions[a.SessionID] = true
		inputs[a.InputID] = true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// First statement takes SQLite's single cross-connection write lock.
	if _, err = tx.ExecContext(ctx, `UPDATE physical_gate_facts SET fact_id=fact_id`); err != nil {
		return err
	}
	var prior []byte
	err = tx.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, "offline-window:"+w.WindowID).Scan(&prior)
	if err == nil {
		var old OfflineWindow
		if json.Unmarshal(prior, &old) != nil || !reflect.DeepEqual(old, w) {
			return ErrPhysicalConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	opening, err := physicalOpening(ctx, tx)
	if err != nil || opening != w.OpeningDigest {
		return ErrPhysicalConflict
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM physical_gate_operations WHERE evidence_class='OFFLINE'`).Scan(&count) != nil {
		return ErrPhysicalConflict
	}
	// Signed selectors are case-local1/2/3. Only private storage positioning
	// appends to the cumulative durable domain; no public/native index is repinned.
	for i, a := range w.Slots {
		if a.LocalDeliveryOrdinal != i+1 || a.PreparationOrdinal != i+1 {
			return ErrPhysicalConflict
		}
	}
	// A declared but unused predecessor window cannot be discarded for headroom.
	var priorWindows int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM physical_gate_facts WHERE fact_id LIKE 'offline-window:%'`).Scan(&priorWindows) != nil || count != 3*priorWindows {
		return ErrPhysicalConflict
	}
	if err = offlinePredecessorsTerminal(ctx, tx); err != nil {
		return err
	}
	raw, _ := json.Marshal(w)
	if _, err = tx.ExecContext(ctx, `INSERT INTO physical_gate_facts(fact_id,fact_json) VALUES(?,?)`, "offline-window:"+w.WindowID, raw); err != nil {
		return err
	}
	position, _ := json.Marshal(offlineWindowPosition{DeliveryBase: count})
	if _, err = tx.ExecContext(ctx, `INSERT INTO physical_gate_facts(fact_id,fact_json) VALUES(?,?)`, "offline-position:"+w.WindowID, position); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) admitOffline(ctx context.Context, id string, p PhysicalPermit) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE physical_gate_facts SET fact_id=fact_id WHERE fact_id=?`, "offline-window:"+p.Offline.WindowID); err != nil {
		return err
	}
	w, err := readOfflineWindow(ctx, tx, p.Offline.WindowID)
	if err != nil || model.WorkspaceDigest(w) != p.Offline.WindowDigest {
		return ErrPhysicalConflict
	}
	exp, err := time.Parse(time.RFC3339Nano, w.ExpiresAt)
	if err != nil || !exp.After(time.Now()) {
		return ErrPhysicalConflict
	}
	selected := false
	for _, a := range w.Slots {
		if reflect.DeepEqual(a, p.Offline.Slot) {
			selected = true
		}
	}
	if !selected {
		return ErrPhysicalConflict
	}
	var active string
	if err = tx.QueryRowContext(ctx, `SELECT operation_id FROM physical_gate_owner WHERE singleton=1`).Scan(&active); !errors.Is(err, sql.ErrNoRows) {
		return ErrPhysicalConflict
	}
	var count, used int
	cumulative, err := offlineStoragePosition(ctx, tx, w, p.Offline.Slot)
	if err != nil || tx.QueryRowContext(ctx, `SELECT count(*) FROM physical_gate_operations WHERE evidence_class='OFFLINE'`).Scan(&count) != nil || cumulative != count+1 {
		return ErrPhysicalConflict
	}
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM physical_gate_operations WHERE preparation_id=?`, p.Request.PreparationID).Scan(&used) != nil || used != 0 {
		return ErrPhysicalConflict
	}
	o := PhysicalOperation{OperationID: id, Permit: p, Phase: "unknown", ReservedUsdMicros: PhysicalReservationUsdMicros}
	if err = insertPhysical(ctx, tx, o); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO physical_gate_owner VALUES(1,?)`, id); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) CompleteOffline(ctx context.Context, e OfflineTerminal) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE physical_gate_owner SET singleton=singleton WHERE singleton=1`); err != nil {
		return err
	}
	var raw []byte
	var o PhysicalOperation
	if tx.QueryRowContext(ctx, `SELECT operation_json FROM physical_gate_operations WHERE operation_id=?`, e.OperationID).Scan(&raw) != nil || json.Unmarshal(raw, &o) != nil || o.Permit.Offline == nil || o.Settlement != nil || o.ReservedUsdMicros != PhysicalReservationUsdMicros {
		return ErrPhysicalConflict
	}
	a := o.Permit.Offline.Slot
	if e.Caller != o.Permit.Caller || e.PreparationID != a.PreparationID || e.SessionID != a.SessionID || e.InputID != a.InputID || e.RequestDigest != o.Permit.Request.RequestDigest || e.ControlRevision < a.ControlRevision || e.TerminalRevision != e.ControlRevision {
		return ErrPhysicalConflict
	}
	for _, d := range []string{e.ControlDigest, e.TerminalDigest, e.EventsDigest, e.QuiescenceDigest, e.SocketDigest} {
		if !model.PhysicalDigestValid(d) {
			return ErrPhysicalConflict
		}
	}
	if a.Oracle == "tool_cancel" && !model.PhysicalDigestValid(e.ToolDigest) {
		return ErrPhysicalConflict
	}
	if o.LocalTerminal != nil {
		if o.Phase != "local-terminal" || !reflect.DeepEqual(o.LocalTerminal, &e) {
			return ErrPhysicalConflict
		}
		return tx.Commit()
	}
	var owner string
	if o.Phase != "unknown" || tx.QueryRowContext(ctx, `SELECT operation_id FROM physical_gate_owner WHERE singleton=1`).Scan(&owner) != nil || owner != e.OperationID {
		return ErrPhysicalConflict
	}
	o.Phase = "local-terminal"
	o.LocalTerminal = &e
	raw, _ = json.Marshal(o)
	if _, err = tx.ExecContext(ctx, `UPDATE physical_gate_operations SET operation_json=? WHERE operation_id=?`, raw, e.OperationID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM physical_gate_owner WHERE singleton=1 AND operation_id=?`, e.OperationID); err != nil {
		return err
	}
	return tx.Commit()
}
