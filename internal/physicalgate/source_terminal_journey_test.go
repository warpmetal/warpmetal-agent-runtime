package physicalgate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// Actual owning TLS connection/read/write/EOF/close + SAME SQLite release. Native
// current/key/installed/kernel readers are explicit detached SOURCE suppliers;
// the production reader must use ProcessRegistry, never this test's PID claims.
func testOwnedSourceOfflineTerminal(t *testing.T) {
	ctx := context.Background()
	base := os.Getenv("WARPMETAL_RUNTIME_GATE_SOURCE_EVIDENCE")
	root, err := os.MkdirTemp(base, "offline-terminal-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE terminal", root)
	store, err := state.Open(filepath.Join(root, "runtime.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = (SourceTerminalConsumer{Store: store}).ForPreparation(ctx, "unrelated_preparation", true); err != nil {
		t.Fatal("unrelated native cancellation required financial ledger", err)
	}
	h := func(s string) string { return model.RawPhysicalDigest([]byte(s)) }
	c := state.PhysicalCase{TaskID: "task", ServerID: "server", CaseDigest: h("case"), BaselineDigest: h("baseline"), Requests: 1, ModelRequests: 1, Preparations: 1, UsdMicros: 421000}
	if err = store.AdoptPhysicalLedger(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	opening, err := store.PhysicalOpeningDigest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	subject := state.PhysicalSubject{SandboxID: "box", SandboxGeneration: 1, NativeInstance: "default", NativeIdentityDigest: h("native")}
	admission, _ := json.Marshal(map[string]any{"formatVersion": 3, "targetKind": "cell_session", "preparedReceipt": map[string]any{"preparedReceiptDigest": h("receipt")}, "grant": map[string]any{"grantId": "detached_grant"}})
	w := state.OfflineWindow{WindowID: "window", CandidateDigest: h("candidate"), FixtureDigest: h("fixture"), OpeningDigest: opening, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano)}
	for i, oracle := range []string{"http_cancel", "tool_cancel", "controller_deadline"} {
		consumer := "product"
		if i == 2 {
			consumer = "parent"
		}
		w.Slots = append(w.Slots, state.OfflineSlot{Caller: subject, PreparationID: "prep_" + oracle, SessionID: "ses_" + oracle, InputID: "msg_" + oracle, Oracle: oracle, Consumer: consumer, RequestIndex: 1, PreparationOrdinal: i + 1, LocalDeliveryOrdinal: i + 1, AuthorityDigest: h("authority"), AdmissionDigest: model.WorkspaceDigest(json.RawMessage(admission)), PreparedReceiptDigest: h("receipt"), ControlDigest: h("control1"), ControlRevision: 1})
	}
	if err = store.AdoptOfflineWindow(ctx, w); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"model":"synthetic","stream":true}`)
	p := state.PhysicalPermit{Case: c, Caller: subject, Request: model.PhysicalAdmitRequest{Consumer: "product", PreparationID: w.Slots[0].PreparationID, RequestIndex: 1, OuterPhysicalIndex: 1, AuthorityDigest: h("authority"), RequestDigest: model.RawPhysicalDigest(body)}, PreparationOrdinal: 1, AllocationID: "local", Offline: &state.OfflineAdmission{WindowID: w.WindowID, WindowDigest: model.WorkspaceDigest(w), Slot: w.Slots[0]}}
	if err = store.AdmitPhysical(ctx, "owning_local", p); err != nil {
		t.Fatal(err)
	}
	listener := NewSourceListener(store)
	if err = listener.Expect(ctx, "owning_local", h("Bearer synthetic-only"), []byte("data: ")); err != nil {
		t.Fatal(err)
	}
	fixture := httptest.NewTLSServer(listener)
	defer fixture.Close()
	request, _ := http.NewRequest(http.MethodPost, fixture.URL+"/v1/responses", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer synthetic-only")
	request.Header.Set("Content-Type", "application/json")
	response, err := fixture.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 6)
	if _, err = io.ReadFull(response.Body, first); err != nil {
		t.Fatal(err)
	}
	// Merely observing a prefix/ACK cannot release an active owning socket.
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err = listener.Exchange(short, "owning_local"); err == nil {
		t.Fatal("open socket became a closed receipt")
	}
	reader := &sourceTerminalTestReader{subject: subject, slot: w.Slots[0], pre: true, admission: admission, listener: listener, noSocket: true}
	consumer := SourceTerminalConsumer{Store: store, Listener: listener, Reader: reader}
	if err = consumer.BeforeCancel(ctx, "owning_local"); err == nil {
		t.Fatal("unowned TLS receipt became registered native socket proof")
	}
	reader.noSocket = false
	if err = consumer.BeforeCancel(ctx, "owning_local"); err != nil {
		t.Fatal(err)
	}
	reader.pre = false
	response.Body.Close()
	exchange, err := listener.Exchange(ctx, "owning_local")
	if err != nil {
		t.Fatal(err)
	}
	if string(exchange.RequestBody) != string(body) || string(exchange.ResponsePrefix) != "data: " || exchange.CloseCause != "peer_closed" {
		t.Fatal("owning socket originals incomplete")
	}
	if err = NewSourceListener(store).Expect(ctx, "owning_local", h("Bearer synthetic-only"), []byte("data: ")); err == nil {
		t.Fatal("restart recreated original request/socket ownership")
	}
	reader.gap = true
	if err = consumer.Complete(ctx, "owning_local"); err == nil {
		t.Fatal("gapped DATA released UNKNOWN")
	}
	o, _ := store.PhysicalOperation(ctx, "owning_local")
	if o.Phase != "unknown" || o.ReservedUsdMicros != 421000 {
		t.Fatal("refusal changed owner/exposure")
	}
	reader.gap = false
	reader.changedInput = true
	if err = consumer.Complete(ctx, "owning_local"); err == nil {
		t.Fatal("changed original input released UNKNOWN")
	}
	reader.changedInput = false
	reader.guardDrift = true
	if err = consumer.Complete(ctx, "owning_local"); err == nil {
		t.Fatal("changed current guard escaped bounded quiescence")
	}
	reader.guardDrift = false
	reader.reads = 0
	reader.currentMissing = true
	if err = consumer.Complete(ctx, "owning_local"); err == nil {
		t.Fatal("missing independent current originals released")
	}
	reader.currentMissing = false
	if err = consumer.Complete(ctx, "owning_local"); err != nil {
		t.Fatal(err)
	}
	o, _ = store.PhysicalOperation(ctx, "owning_local")
	if o.Phase != "local-terminal" || o.Settlement != nil || o.ReservedUsdMicros != 421000 || o.LocalTerminal == nil {
		t.Fatal("verified normal consumer changed financial witness", o)
	}
}

type sourceTerminalTestReader struct {
	subject                  state.PhysicalSubject
	slot                     state.OfflineSlot
	gap, currentMissing      bool
	pre                      bool
	admission                []byte
	changedInput, guardDrift bool
	reads                    int
	listener                 *SourceListener
	noSocket                 bool
}

func (r *sourceTerminalTestReader) Kernel(context.Context, state.PhysicalOperation, []ProcessIdentity) (SourceKernelCut, error) {
	cut := SourceKernelCut{Caller: r.subject, RegistrationDigest: model.WorkspaceDigest("detached registration"), Native: ProcessIdentity{PID: 90, StartTime: 1}, ObservedAt: time.Now()}
	if r.pre && !r.noSocket {
		x, err := r.listener.Snapshot(context.Background(), "owning_local")
		if err != nil {
			return cut, err
		}
		cut.NativeConnections = []SourceTCPConnection{{LocalAddress: x.RemoteAddress, RemoteAddress: x.LocalAddress, Inode: "300", State: "01", OriginalRow: "detached kernel row"}}
		cut.SocketOriginals = map[int][]string{90: {"5=socket:[300]"}}
	}
	return cut, nil
}
func (r *sourceTerminalTestReader) Native(_ context.Context, o state.PhysicalOperation) (SourceNativeTerminal, error) {
	r.reads++
	rows := []json.RawMessage{}
	for i, kind := range []string{"session.created", "session.inbox.enqueued", "session.execution.started", "session.inbox.delivered", "session.execution.interrupted"} {
		data := map[string]any{"sessionID": r.slot.SessionID}
		if i == 1 || i == 3 {
			data["inboxID"] = r.slot.InputID
		}
		if i == 4 {
			data["reason"] = "user"
		}
		if i == 1 {
			data["item"] = map[string]any{"type": "user", "payload": map[string]any{"text": "original input e\u0301\r\n", "guard": map[string]any{"cellGrant": map[string]any{"grantId": "detached_grant"}}}}
			if r.changedInput {
				data["item"].(map[string]any)["payload"].(map[string]any)["text"] = "normalized input é\n"
			}
		}
		row, _ := json.Marshal(map[string]any{"id": "evt_" + kind, "type": kind, "created": 100 + i, "durable": map[string]any{"aggregateID": r.slot.SessionID, "seq": i, "version": 1}, "data": data})
		rows = append(rows, row)
	}
	if r.gap {
		rows = append(rows[:3], rows[4:]...)
	}
	cursor := 4
	var terminal any = 4
	if r.pre {
		rows = rows[:4]
		cursor = 3
		terminal = nil
	}
	marker, _ := json.Marshal(map[string]any{"type": "log.synced", "aggregateID": r.slot.SessionID, "seq": cursor})
	rows = append(rows, marker)
	log := []byte{}
	for _, row := range rows {
		log = append(log, append(append([]byte("data: "), row...), []byte("\n\n")...)...)
	}
	var contextSeq any
	if r.guardDrift {
		contextSeq = r.reads
	}
	guard, _ := json.Marshal(map[string]any{"data": map[string]any{"formatVersion": 1, "nativeGuardVersion": "warpmetal.atomic-input.v1", "sessionID": r.slot.SessionID, "inputSeq": 1, "executionStartedSeq": 2, "executionTerminalSeq": terminal, "contextSeq": contextSeq, "active": r.pre, "observedAt": time.Now().UnixMilli(), "logCursor": cursor}})
	active := []byte(`{"data":{}}`)
	if r.pre {
		active, _ = json.Marshal(map[string]any{"data": map[string]any{r.slot.SessionID: map[string]any{"active": true}}})
	}
	return SourceNativeTerminal{Log: log, Guard: guard, Active: active, Inbox: []byte(`{"data":[]}`), Basis: SourceInputBasis{Admission: r.admission, InputDigest: model.RawPhysicalDigest([]byte("original input e\u0301\r\n"))}}, nil
}
func (r *sourceTerminalTestReader) Current(_ context.Context, o state.PhysicalOperation, evidence SourceTerminalEvidence) (SourceCurrentTerminal, error) {
	if r.currentMissing {
		return SourceCurrentTerminal{}, ErrPrerequisite
	}
	return SourceCurrentTerminal{Caller: r.subject, PreparationID: r.slot.PreparationID, SessionID: r.slot.SessionID, InputID: r.slot.InputID, PreparedReceiptDigest: r.slot.PreparedReceiptDigest, ControlRevision: 2, TerminalRevision: 2, ControlOriginal: []byte("detached independently verified signed control"), TerminalOriginal: []byte("detached independently verified signed terminal"), Evidence: evidence}, nil
}
