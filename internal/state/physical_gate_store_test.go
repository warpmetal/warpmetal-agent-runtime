package state

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
)

func retainedPhysicalStore(t *testing.T, name string) *Store {
	t.Helper()
	base := os.Getenv("WARPMETAL_RUNTIME_GATE_SOURCE_EVIDENCE")
	if base == "" {
		t.Skip("requires approved retained SOURCE evidence root")
	}
	root, err := os.MkdirTemp(base, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE_PRIVATE_ARTIFACTS", root)
	s, err := Open(filepath.Join(root, "runtime.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func physicalSourceCase() PhysicalCase {
	return PhysicalCase{TaskID: "source_task", ServerID: "source_server", CaseDigest: model.WorkspaceDigest("source_case"), BaselineDigest: model.WorkspaceDigest("source_baseline"), Requests: 2, Preparations: 2, ModelRequests: 2, UsdMicros: 842000}
}
func physicalSourcePermit(c PhysicalCase, index int) PhysicalPermit {
	return PhysicalPermit{Case: c, Caller: PhysicalSubject{SandboxID: "source_box", SandboxGeneration: 1, NativeInstance: "source_native", NativeIdentityDigest: model.WorkspaceDigest("native")}, AllocationID: "source_allocation", PreparationOrdinal: 1, Request: model.PhysicalAdmitRequest{Consumer: "product", PreparationID: "source_preparation", RequestIndex: index, OuterPhysicalIndex: index, AuthorityDigest: model.WorkspaceDigest("authority"), RequestDigest: model.WorkspaceDigest("request")}}
}
func sourceSettlement(p PhysicalPermit) model.PhysicalSettlement {
	return model.PhysicalSettlement{RequestDigest: p.Request.RequestDigest, ResponseDigest: model.WorkspaceDigest("response"), ResponseByteCount: 1, HTTPStatus: 200, UsageUsdMicros: 7, EvidenceDigest: model.WorkspaceDigest("evidence")}
}

// Existing SQLite admission journey, extended for the named financial rule:
// settled cost releases only cash exposure, never a physical slot or UNKNOWN.
func TestPhysicalProviderRollingExposurePreservesLegacy(t *testing.T) {
	for _, successor := range []bool{true, false} {
		s := retainedPhysicalStore(t, "physical-provider-exposure-")
		c := physicalSourceCase()
		c.Requests, c.ModelRequests, c.AccessRequests, c.Preparations, c.UsdMicros = 19, 17, 2, 13, 3000000
		if successor {
			// Wire into the private case before the implementation exists; unknown
			// fields are ignored by old code, producing the actual eighth-call red.
			raw, _ := json.Marshal(c)
			var fields map[string]any
			_ = json.Unmarshal(raw, &fields)
			fields["AccountingVersion"] = 2
			fields["ProviderPolicyDigest"] = providerpolicy.FlashDigest
			raw, _ = json.Marshal(fields)
			_ = json.Unmarshal(raw, &c)
		}
		ctx := context.Background()
		if err := s.AdoptPhysicalLedger(ctx, c, nil); err != nil {
			t.Fatal(err)
		}
		allowed := 7
		if successor {
			allowed = 9
		}
		for i := 1; i <= allowed; i++ {
			p := physicalSourcePermit(c, i)
			id := fmt.Sprintf("source_request_%d", i)
			if err := s.AdmitPhysical(ctx, id, p); err != nil {
				t.Fatalf("successor=%v physical=%d: %v", successor, i, err)
			}
			next := physicalSourcePermit(c, i+1)
			if s.AdmitPhysical(ctx, "source_overlap", next) == nil {
				t.Fatal("UNKNOWN lost full hold")
			}
			e := sourceSettlement(p)
			e.UsageUsdMicros = 300000
			if err := s.SettlePhysical(ctx, id, p.Caller, e); err != nil {
				t.Fatal(err)
			}
		}
		if s.AdmitPhysical(ctx, "source_over_cap", physicalSourcePermit(c, allowed+1)) == nil {
			t.Fatal("rolling/gross cap exceeded", successor)
		}
		history, err := s.PhysicalHistory(ctx, c)
		if err != nil || len(history) != allowed {
			t.Fatal("physical slots refunded", err)
		}
	}
}

func TestPhysicalAccessZeroOrdinalSharesPrefixNotModelLane(t *testing.T) {
	s := retainedPhysicalStore(t, "physical-access-prefix-")
	ctx := context.Background()
	c := physicalSourceCase()
	c.ModelRequests = 1
	c.AccessRequests = 1
	c.Preparations = 1
	if err := s.AdoptPhysicalLedger(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	access := physicalSourcePermit(c, 1)
	access.Request.Consumer = "access"
	access.PreparationOrdinal = 0
	if err := s.AdmitPhysical(ctx, "source_access", access); err != nil {
		t.Fatal(err)
	}
	tooHigh := sourceSettlement(access)
	tooHigh.UsageUsdMicros = 421001
	if err := s.SettlePhysical(ctx, "source_access", access.Caller, tooHigh); err == nil {
		t.Fatal("over-reservation usage released owner")
	}
	modelPermit := physicalSourcePermit(c, 1)
	modelPermit.Request.OuterPhysicalIndex = 2
	if err := s.AdmitPhysical(ctx, "source_model", modelPermit); err == nil {
		t.Fatal("access unknown released singleton")
	}
	if err := s.SettlePhysical(ctx, "source_access", access.Caller, sourceSettlement(access)); err != nil {
		t.Fatal(err)
	}
	if err := s.AdmitPhysical(ctx, "source_model", modelPermit); err != nil {
		t.Fatal("access stole model preparation/request1", err)
	}
	h, err := s.PhysicalHistory(ctx, c)
	if err != nil || len(h) != 2 || h[0].ReservedUsdMicros+h[1].ReservedUsdMicros != 842000 {
		t.Fatal("reservation/prefix loss", err)
	}
}

func TestPhysicalBaselineCannotImportInvalidPrefixOrHeadroom(t *testing.T) {
	for _, kind := range []string{"limit", "request_gap", "preparation_gap", "after_unknown"} {
		t.Run(kind, func(t *testing.T) {
			s := retainedPhysicalStore(t, "physical-baseline-refusal-")
			c := physicalSourceCase()
			first := physicalSourcePermit(c, 1)
			second := physicalSourcePermit(c, 2)
			if kind == "limit" {
				c.Requests = 1
				c.ModelRequests = 1
				c.UsdMicros = 421000
				first.Case = c
				second.Case = c
			}
			if kind == "request_gap" {
				second.Request.RequestIndex = 3
			}
			if kind == "preparation_gap" {
				first.PreparationOrdinal = 2
				second.PreparationOrdinal = 2
			}
			e1, e2 := sourceSettlement(first), sourceSettlement(second)
			h := []PhysicalOperation{{OperationID: "source_first", Permit: first, Phase: "settled", ReservedUsdMicros: 421000, Settlement: &e1}, {OperationID: "source_second", Permit: second, Phase: "settled", ReservedUsdMicros: 421000, Settlement: &e2}}
			if kind == "after_unknown" {
				h[0].Phase = "unknown"
				h[0].Settlement = nil
			}
			if err := s.AdoptPhysicalLedger(context.Background(), c, h); err == nil {
				t.Fatal("invalid retained history became admission headroom", kind)
			}
		})
	}
}

func TestPhysicalParentPreservesGlobalModelRequestIndex(t *testing.T) {
	s := retainedPhysicalStore(t, "physical-parent-model-index-")
	ctx := context.Background()
	c := physicalSourceCase()
	c.Requests = 3
	c.ModelRequests = 2
	c.AccessRequests = 1
	c.UsdMicros = 1263000
	if err := s.AdoptPhysicalLedger(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	prior := physicalSourcePermit(c, 1)
	if err := s.AdmitPhysical(ctx, "source_prior", prior); err != nil {
		t.Fatal(err)
	}
	if err := s.SettlePhysical(ctx, "source_prior", prior.Caller, sourceSettlement(prior)); err != nil {
		t.Fatal(err)
	}
	access := physicalSourcePermit(c, 1)
	access.Request.Consumer = "access"
	access.Request.PreparationID = "source_access_preparation"
	access.Request.OuterPhysicalIndex = 2
	access.PreparationOrdinal = 0
	if err := s.AdmitPhysical(ctx, "source_access", access); err != nil {
		t.Fatal(err)
	}
	if err := s.SettlePhysical(ctx, "source_access", access.Caller, sourceSettlement(access)); err != nil {
		t.Fatal(err)
	}
	parent := physicalSourcePermit(c, 2)
	parent.Request.Consumer = "parent"
	parent.Request.PreparationID = "source_parent_preparation"
	parent.Request.OuterPhysicalIndex = 3
	parent.PreparationOrdinal = 2
	if err := s.AdmitPhysical(ctx, "source_parent", parent); err != nil {
		t.Fatal("parent frozen global model index was renumbered to local1", err)
	}
	if err := s.SettlePhysical(ctx, "source_parent", parent.Caller, sourceSettlement(parent)); err != nil {
		t.Fatal(err)
	}
	if err := s.AdmitPhysical(ctx, "source_parent_replay", parent); err == nil {
		t.Fatal("sole parent turn replayed")
	}
}

// A private owner-derived OFFLINE classification must never reach the paid
// settlement route, even with a perfectly valid paid-shaped request/response.
func TestPhysicalOfflineCannotSettleProviderUsage(t *testing.T) {
	s := retainedPhysicalStore(t, "physical-offline-paid-refusal-")
	ctx := context.Background()
	c := physicalSourceCase()
	if err := s.AdoptPhysicalLedger(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	p := physicalSourcePermit(c, 1)
	raw, _ := json.Marshal(p)
	var wire map[string]any
	_ = json.Unmarshal(raw, &wire)
	wire["Offline"] = map[string]any{"WindowID": "source_window", "InputID": "msg_source", "Oracle": "http_cancel"}
	raw, _ = json.Marshal(wire)
	_ = json.Unmarshal(raw, &p)
	if err := s.AdmitPhysical(ctx, "source_offline", p); err == nil {
		if s.SettlePhysical(ctx, "source_offline", p.Caller, sourceSettlement(p)) == nil {
			t.Fatal("OFFLINE operation accepted provider-usage settlement")
		}
	}
}

func TestPhysicalOfflineThreeSlotsRetainReserveAndUnknownAcrossReopen(t *testing.T) {
	s := retainedPhysicalStore(t, "physical-offline-three-")
	ctx := context.Background()
	c := physicalSourceCase()
	if err := s.AdoptPhysicalLedger(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	opening, err := s.PhysicalOpeningDigest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w := OfflineWindow{WindowID: "source_window", CandidateDigest: model.WorkspaceDigest("candidate"), FixtureDigest: model.WorkspaceDigest("fixture"), OpeningDigest: opening, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano)}
	for i, oracle := range []string{"http_cancel", "tool_cancel", "controller_deadline"} {
		p := physicalSourcePermit(c, 1)
		p.Request.PreparationID = "source_offline_" + oracle
		consumer := "product"
		if i == 2 {
			consumer = "parent"
		}
		w.Slots = append(w.Slots, OfflineSlot{Caller: p.Caller, PreparationID: p.Request.PreparationID, SessionID: "ses_" + oracle, InputID: "msg_" + oracle, Oracle: oracle, Consumer: consumer, RequestIndex: 1, PreparationOrdinal: i + 1, LocalDeliveryOrdinal: i + 1, AuthorityDigest: p.Request.AuthorityDigest, AdmissionDigest: model.WorkspaceDigest(oracle + "admission"), PreparedReceiptDigest: model.WorkspaceDigest(oracle + "receipt"), ControlDigest: model.WorkspaceDigest(oracle + "control"), ControlRevision: 1})
	}
	if err := s.AdoptOfflineWindow(ctx, w); err != nil {
		t.Fatal(err)
	}
	first := w.Slots[0]
	p := physicalSourcePermit(c, 1)
	p.Request.PreparationID = first.PreparationID
	p.Offline = &OfflineAdmission{WindowID: w.WindowID, WindowDigest: model.WorkspaceDigest(w), Slot: first}
	if err := s.AdmitPhysical(ctx, "source_local_1", p); err != nil {
		t.Fatal(err)
	}
	if s.SettlePhysical(ctx, "source_local_1", p.Caller, sourceSettlement(p)) == nil {
		t.Fatal("local response settled paid usage")
	}
	second := p
	second.Request.PreparationID = w.Slots[1].PreparationID
	second.Request.OuterPhysicalIndex = 2
	second.Offline = &OfflineAdmission{WindowID: w.WindowID, WindowDigest: model.WorkspaceDigest(w), Slot: w.Slots[1]}
	if s.AdmitPhysical(ctx, "source_local_2", second) == nil {
		t.Fatal("unknown local owner released")
	}
	terminal := OfflineTerminal{OperationID: "source_local_1", Caller: p.Caller, PreparationID: first.PreparationID, SessionID: first.SessionID, InputID: first.InputID, RequestDigest: p.Request.RequestDigest, ControlRevision: 2, TerminalRevision: 2, ControlDigest: model.WorkspaceDigest("cancel"), TerminalDigest: model.WorkspaceDigest("terminal"), EventsDigest: model.WorkspaceDigest("DATA0..cursor"), QuiescenceDigest: model.WorkspaceDigest("quiescence"), SocketDigest: model.WorkspaceDigest("socket-close")}
	wrong := terminal
	wrong.InputID = "msg_other"
	if s.CompleteOffline(ctx, wrong) == nil {
		t.Fatal("wrong input released owner")
	}
	if err := s.CompleteOffline(ctx, terminal); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteOffline(ctx, terminal); err != nil {
		t.Fatal("exact terminal replay", err)
	}
	if s.AdmitPhysical(ctx, "source_local_1_replay", p) == nil {
		t.Fatal("consumed delivery retried")
	}
	if err := s.AdmitPhysical(ctx, "source_local_2", second); err != nil {
		t.Fatal(err)
	}
	// Reopen the same real SQLite database; unknown operation and reservation must
	// survive, while the original paid case/history are neither reset nor extended.
	var filename string
	if s.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&filename) != nil {
		t.Fatal("database path")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	third := p
	third.Request.Consumer = "parent"
	third.Request.PreparationID = w.Slots[2].PreparationID
	third.Request.OuterPhysicalIndex = 3
	third.Offline = &OfflineAdmission{WindowID: w.WindowID, WindowDigest: model.WorkspaceDigest(w), Slot: w.Slots[2]}
	if reopened.AdmitPhysical(ctx, "source_local_3", third) == nil {
		t.Fatal("restart cleared UNKNOWN fence")
	}
	for _, id := range []string{"source_local_1", "source_local_2"} {
		o, e := reopened.PhysicalOperation(ctx, id)
		if e != nil || o == nil || o.ReservedUsdMicros != 421000 || o.Settlement != nil {
			t.Fatal("local reservation/provider classification lost", id, e)
		}
	}
	h, e := reopened.PhysicalHistory(ctx, c)
	if e != nil || len(h) != 0 {
		t.Fatal("local deliveries altered paid prefix", e)
	}
	terminal.OperationID = "source_local_2"
	terminal.PreparationID = w.Slots[1].PreparationID
	terminal.SessionID = w.Slots[1].SessionID
	terminal.InputID = w.Slots[1].InputID
	if reopened.CompleteOffline(ctx, terminal) == nil {
		t.Fatal("tool terminal without original late-effect evidence released")
	}
	terminal.ToolDigest = model.WorkspaceDigest("original tool process/late-effect")
	if err := reopened.CompleteOffline(ctx, terminal); err != nil {
		t.Fatal(err)
	}
	if err := reopened.AdmitPhysical(ctx, "source_local_3", third); err != nil {
		t.Fatal(err)
	}
	if reopened.AdmitPhysical(ctx, "source_local_4", third) == nil {
		t.Fatal("fourth local delivery admitted")
	}
	// The SECOND independently authorized case still selects LOCAL1/2/3. This
	// extends the same SQLite journey, not an integrated second attempt. Private
	// terminal inputs here are synthetic allocator facts, NOT capture/release proof.
	successor := w
	successor.WindowID = "source_window_successor"
	successor.Slots = append([]OfflineSlot(nil), w.Slots...)
	for i := range successor.Slots {
		successor.Slots[i].PreparationID += "_successor"
		successor.Slots[i].SessionID += "_successor"
		successor.Slots[i].InputID += "_successor"
	}
	successor.OpeningDigest, err = reopened.PhysicalOpeningDigest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.AdoptOfflineWindow(ctx, successor) == nil {
		t.Fatal("UNKNOWN predecessor allowed successor window")
	}
	if after, err := reopened.PhysicalOpeningDigest(ctx); err != nil || after != successor.OpeningDigest {
		t.Fatal("refusal changed opening/UNKNOWN owner", err)
	}
	terminal.OperationID = "source_local_3"
	terminal.Caller = third.Caller
	terminal.PreparationID = third.Request.PreparationID
	terminal.SessionID = w.Slots[2].SessionID
	terminal.InputID = w.Slots[2].InputID
	terminal.RequestDigest = third.Request.RequestDigest
	if err = reopened.CompleteOffline(ctx, terminal); err != nil {
		t.Fatal(err)
	}
	originals := map[string][]byte{}
	for _, id := range []string{"source_local_1", "source_local_2", "source_local_3"} {
		var raw []byte
		if err = reopened.db.QueryRowContext(ctx, `SELECT operation_json FROM physical_gate_operations WHERE operation_id=?`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		originals[id] = raw
	}
	var oldWindow []byte
	if err = reopened.db.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, "offline-window:"+w.WindowID).Scan(&oldWindow); err != nil {
		t.Fatal(err)
	}
	successor.OpeningDigest, err = reopened.PhysicalOpeningDigest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = reopened.AdoptOfflineWindow(ctx, successor); err != nil {
		t.Fatalf("independently authorized successor LOCAL1/2/3 refused: %v", err)
	}
	next := p
	next.Request.PreparationID = successor.Slots[0].PreparationID
	next.Request.OuterPhysicalIndex = 1
	next.Offline = &OfflineAdmission{WindowID: successor.WindowID, WindowDigest: model.WorkspaceDigest(successor), Slot: successor.Slots[0]}
	if err = reopened.AdmitPhysical(ctx, "source_successor_local_1", next); err != nil {
		t.Fatal("successor local1 must append cumulative storage4", err)
	}
	var storedIndex int
	if err = reopened.db.QueryRowContext(ctx, `SELECT outer_index FROM physical_gate_operations WHERE operation_id=?`, "source_successor_local_1").Scan(&storedIndex); err != nil || storedIndex != -4 {
		t.Fatal("private cumulative index", storedIndex, err)
	}
	for id, original := range originals {
		var after []byte
		if err = reopened.db.QueryRowContext(ctx, `SELECT operation_json FROM physical_gate_operations WHERE operation_id=?`, id).Scan(&after); err != nil || !bytes.Equal(after, original) {
			t.Fatal("predecessor original rewritten", id, err)
		}
		o, e := reopened.PhysicalOperation(ctx, id)
		if e != nil || o == nil || o.ReservedUsdMicros != 421000 || o.Settlement != nil || o.Phase != "local-terminal" {
			t.Fatal("predecessor exposure/terminal lost", id, e)
		}
	}
	var afterWindow []byte
	if err = reopened.db.QueryRowContext(ctx, `SELECT fact_json FROM physical_gate_facts WHERE fact_id=?`, "offline-window:"+w.WindowID).Scan(&afterWindow); err != nil || !bytes.Equal(afterWindow, oldWindow) {
		t.Fatal("predecessor window original rewritten", err)
	}
	newWindow, e := readOfflineWindow(ctx, reopened.db, successor.WindowID)
	if e != nil || newWindow.OpeningDigest != successor.OpeningDigest || newWindow.Slots[0].PreparationOrdinal != 1 || newWindow.Slots[2].LocalDeliveryOrdinal != 3 {
		t.Fatal("window-local selector/opening rewritten", e)
	}
	o, e := reopened.PhysicalOperation(ctx, "source_successor_local_1")
	if e != nil || o == nil || o.Permit.Request.OuterPhysicalIndex != 1 || o.Permit.Offline.Slot.LocalDeliveryOrdinal != 1 || o.Phase != "unknown" || o.ReservedUsdMicros != 421000 {
		t.Fatal("successor RPC/local ordinal/UNKNOWN lost", e)
	}
	if reopened.AdmitPhysical(ctx, "source_successor_replay", next) == nil {
		t.Fatal("successor preparation duplicate fence removed")
	}
	if h, e := reopened.PhysicalHistory(ctx, c); e != nil || len(h) != 0 {
		t.Fatal("successor altered paid history", e)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	readback, err := Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer readback.Close()
	position, e := offlineStoragePosition(ctx, readback.db, newWindow, newWindow.Slots[0])
	if e != nil || position != 4 {
		t.Fatal("cumulative mapping did not survive reopen", position, e)
	}
	for id, original := range originals {
		var after []byte
		if e = readback.db.QueryRowContext(ctx, `SELECT operation_json FROM physical_gate_operations WHERE operation_id=?`, id).Scan(&after); e != nil || !bytes.Equal(after, original) {
			t.Fatal("reopened predecessor original changed", id, e)
		}
	}
	nextUnknown, e := readback.PhysicalOperation(ctx, "source_successor_local_1")
	if e != nil || nextUnknown == nil || nextUnknown.Phase != "unknown" || nextUnknown.ReservedUsdMicros != 421000 {
		t.Fatal("reopened successor UNKNOWN/exposure lost", e)
	}
	nextSecond := next
	nextSecond.Request.PreparationID = successor.Slots[1].PreparationID
	nextSecond.Request.OuterPhysicalIndex = 2
	nextSecond.Offline = &OfflineAdmission{WindowID: successor.WindowID, WindowDigest: model.WorkspaceDigest(successor), Slot: successor.Slots[1]}
	if readback.AdmitPhysical(ctx, "source_successor_local_2", nextSecond) == nil {
		t.Fatal("reopen released successor UNKNOWN cap")
	}
	t.Log("SOURCE allocator only: independent synthetic windows local1/2/3 map cumulative1..3 then4; old JSON/window/opening/reserve retained; normal terminal/installed/provider/real attempt proof=0")
}

func TestPhysicalOfflineUpgradePreservesLegacyOriginalsAndUnknownOwner(t *testing.T) {
	base := os.Getenv("WARPMETAL_RUNTIME_GATE_SOURCE_EVIDENCE")
	if base == "" {
		t.Skip("requires approved retained SOURCE evidence root")
	}
	root, err := os.MkdirTemp(base, "physical-offline-legacy-upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE_PRIVATE_ARTIFACTS", root)
	filename := filepath.Join(root, "runtime.db")
	old, err := sql.Open("sqlite", filename)
	if err != nil {
		t.Fatal(err)
	}
	// Actual pre-additive private schema, not a new-format database masquerading
	// as an upgrade. Original rows include a still-owned UNKNOWN operation.
	_, err = old.Exec(`
CREATE TABLE physical_gate_processes (identity_digest TEXT PRIMARY KEY,registration_json BLOB NOT NULL);
CREATE TABLE physical_gate_facts (fact_id TEXT PRIMARY KEY,fact_json BLOB NOT NULL);
CREATE TABLE physical_gate_case (singleton INTEGER PRIMARY KEY CHECK(singleton=1),case_json BLOB NOT NULL);
CREATE TABLE physical_gate_operations (operation_id TEXT PRIMARY KEY,outer_index INTEGER UNIQUE NOT NULL,request_lane TEXT NOT NULL CHECK(request_lane IN ('access','model')),preparation_id TEXT NOT NULL,request_index INTEGER NOT NULL,operation_json BLOB NOT NULL,UNIQUE(request_lane,preparation_id,request_index));
CREATE TABLE physical_gate_owner (singleton INTEGER PRIMARY KEY CHECK(singleton=1),operation_id TEXT NOT NULL REFERENCES physical_gate_operations(operation_id));`)
	if err != nil {
		t.Fatal(err)
	}
	c := physicalSourceCase()
	caseRaw, _ := json.Marshal(c)
	permit := physicalSourcePermit(c, 1)
	op := PhysicalOperation{OperationID: "source_legacy_unknown", Permit: permit, Phase: "unknown", ReservedUsdMicros: 421000}
	opRaw, _ := json.MarshalIndent(op, "", " ") // Retain exact bytes, not merely equivalent values.
	if _, err = old.Exec(`INSERT INTO physical_gate_case VALUES(1,?)`, caseRaw); err != nil {
		t.Fatal(err)
	}
	if _, err = old.Exec(`INSERT INTO physical_gate_operations VALUES(?,1,'model',?,1,?)`, op.OperationID, permit.Request.PreparationID, opRaw); err != nil {
		t.Fatal(err)
	}
	if _, err = old.Exec(`INSERT INTO physical_gate_owner VALUES(1,?)`, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var gotCase, gotOp []byte
	var owner, class, journal string
	var sync int
	if s.db.QueryRow(`SELECT case_json FROM physical_gate_case WHERE singleton=1`).Scan(&gotCase) != nil || s.db.QueryRow(`SELECT operation_json,evidence_class FROM physical_gate_operations WHERE operation_id=?`, op.OperationID).Scan(&gotOp, &class) != nil || s.db.QueryRow(`SELECT operation_id FROM physical_gate_owner WHERE singleton=1`).Scan(&owner) != nil {
		t.Fatal("legacy rows lost")
	}
	if !bytes.Equal(caseRaw, gotCase) || !bytes.Equal(opRaw, gotOp) || owner != op.OperationID || class != "PAID" {
		t.Fatal("migration rewrote originals/class/owner")
	}
	if s.db.QueryRow(`PRAGMA journal_mode`).Scan(&journal) != nil || s.db.QueryRow(`PRAGMA synchronous`).Scan(&sync) != nil || journal != "wal" || sync != 2 {
		t.Fatal("WAL/FULL durability lost", journal, sync)
	}
	if s.AdmitPhysical(context.Background(), "source_after_unknown", physicalSourcePermit(c, 2)) == nil {
		t.Fatal("upgrade released unknown ownership")
	}
	h, err := s.PhysicalHistory(context.Background(), c)
	if err != nil || len(h) != 1 || h[0].Phase != "unknown" || h[0].ReservedUsdMicros != 421000 {
		t.Fatal("upgrade reset retained prefix/reserve", err)
	}
}
