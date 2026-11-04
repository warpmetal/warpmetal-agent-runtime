package physicalgate

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type SourceKernelCut struct {
	Caller             state.PhysicalSubject
	RegistrationDigest string
	Native             ProcessIdentity
	Descendants        []ProcessIdentity
	TrackedExited      []ProcessIdentity
	StatOriginals      map[int]string
	SocketOriginals    map[int][]string
	NativeConnections  []SourceTCPConnection
	ObservedAt         time.Time
}
type SourceInputBasis struct {
	InputDigest string
	Admission   []byte
}
type SourceNativeTerminal struct {
	Log, Guard, Active, Inbox []byte
	ToolOriginals             []byte
	Basis                     SourceInputBasis
}
type sourcePreCancel struct {
	Kernel SourceKernelCut
	Native SourceNativeTerminal
}
type SourceTerminalEvidence struct {
	EventsDigest, QuiescenceDigest, SocketDigest string
	StartedEventID, TerminalEventID              string
}

// A protected independently verifying current-original reader supplies this,
// never the selection/grant's own reflected currentControl or PID fields.
type SourceCurrentTerminal struct {
	Caller                                                   state.PhysicalSubject
	PreparationID, SessionID, InputID, PreparedReceiptDigest string
	ControlRevision, TerminalRevision                        int64
	ControlOriginal, TerminalOriginal                        []byte
	Evidence                                                 SourceTerminalEvidence
}
type SourceTerminalReader interface {
	Kernel(context.Context, state.PhysicalOperation, []ProcessIdentity) (SourceKernelCut, error)
	Native(context.Context, state.PhysicalOperation) (SourceNativeTerminal, error)
	Current(context.Context, state.PhysicalOperation, SourceTerminalEvidence) (SourceCurrentTerminal, error)
}
type SourceTerminalConsumer struct {
	Store    *state.Store
	Listener *SourceListener
	Reader   SourceTerminalReader
}

func sourceCaptureKey(id string) string {
	return "source_pre_cancel_" + model.RawPhysicalDigest([]byte(id))[7:]
}

// Called by the normal cancel/output owner BEFORE interruption can erase tools.
// No replacement of a previously captured process generation, even on replay.
func (c SourceTerminalConsumer) BeforeCancel(ctx context.Context, id string) error {
	if c.Store == nil || c.Reader == nil {
		return ErrPrerequisite
	}
	o, err := c.Store.PhysicalOperation(ctx, id)
	if err != nil || o == nil || o.Permit.Offline == nil || o.Phase != "unknown" {
		return ErrPrerequisite
	}
	prior, err := c.Store.PhysicalFact(ctx, sourceCaptureKey(id))
	if err != nil {
		return err
	}
	if prior != nil {
		return nil
	}
	native, err := c.Reader.Native(ctx, *o)
	if err != nil {
		return err
	}
	if _, err = verifySourceNative(native, *o, false); err != nil {
		return err
	}
	cut, err := c.Reader.Kernel(ctx, *o, nil)
	if err != nil || cut.Caller != o.Permit.Caller || !model.PhysicalDigestValid(cut.RegistrationDigest) || cut.Native.PID < 1 || cut.Native.StartTime < 1 || cut.ObservedAt.IsZero() {
		return ErrPrerequisite
	}
	if c.Listener == nil || c.Listener.store != c.Store {
		return ErrPrerequisite
	}
	exchange, err := c.Listener.Snapshot(ctx, id)
	if err != nil {
		return err
	}
	if o.Permit.Offline.Slot.Oracle != "tool_cancel" && !sourceNativeOwnsSocket(cut, exchange) {
		return ErrPrerequisite
	}
	if o.Permit.Offline.Slot.Oracle == "tool_cancel" {
		if err = verifySourcePreCancelTool(native.ToolOriginals, cut, o.Permit.Offline.Slot.SessionID); err != nil {
			return err
		}
	}
	raw, _ := json.Marshal(sourcePreCancel{Kernel: cut, Native: native})
	return c.Store.RetainPhysicalFact(ctx, sourceCaptureKey(id), raw)
}

type sourceDurableEvent struct {
	ID, Type string
	Created  int64
	Durable  struct {
		AggregateID  string
		Seq, Version int64
	}
	Data               json.RawMessage
	Location, Metadata json.RawMessage
}

func sourceObject(raw []byte) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if !utf8.Valid(raw) || model.DecodePhysicalClosed(raw, &fields) != nil || fields == nil {
		return nil, ErrPrerequisite
	}
	return fields, nil
}

func sourceGuardStable(first, second []byte) bool {
	a, e := sourceData(first)
	if e != nil {
		return false
	}
	b, e := sourceData(second)
	if e != nil {
		return false
	}
	af, e := sourceObject(a)
	if e != nil {
		return false
	}
	bf, e := sourceObject(b)
	if e != nil {
		return false
	}
	var aa, ba int64
	if json.Unmarshal(af["observedAt"], &aa) != nil || json.Unmarshal(bf["observedAt"], &ba) != nil || ba < aa {
		return false
	}
	delete(af, "observedAt")
	delete(bf, "observedAt")
	return model.WorkspaceDigest(af) == model.WorkspaceDigest(bf)
}
func sourceData(raw []byte) (json.RawMessage, error) {
	fields, err := sourceObject(raw)
	if err != nil || len(fields) != 1 || fields["data"] == nil {
		return nil, ErrPrerequisite
	}
	return fields["data"], nil
}

func sourceFields(raw []byte, required, optional string) (map[string]json.RawMessage, error) {
	fields, err := sourceObject(raw)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, name := range strings.Fields(required) {
		if fields[name] == nil {
			return nil, ErrPrerequisite
		}
		allowed[name] = true
	}
	for _, name := range strings.Fields(optional) {
		allowed[name] = true
	}
	for name := range fields {
		if !allowed[name] {
			return nil, ErrPrerequisite
		}
	}
	return fields, nil
}

// Check every original durable DATA envelope0..log.synced, the original owning
// input/start/delivery, exact cancel/deadline terminal, and current quiescence.
// This accepts no collector stable/quiescent booleans or ACK-as-terminal.
func verifySourceNative(n SourceNativeTerminal, o state.PhysicalOperation, terminalRequired bool) ([]byte, error) {
	if len(n.Log) == 0 || len(n.Log) > 65536 {
		return nil, ErrPrerequisite
	}
	frames := bytes.Split(bytes.ReplaceAll(n.Log, []byte("\r\n"), []byte("\n")), []byte("\n\n"))
	rows := []json.RawMessage{}
	for _, frame := range frames {
		if len(frame) == 0 {
			continue
		}
		lines := [][]byte{}
		for _, line := range bytes.Split(frame, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("data:")) {
				lines = append(lines, bytes.TrimPrefix(bytes.TrimPrefix(line, []byte("data:")), []byte(" ")))
			} else if len(line) > 0 && !bytes.HasPrefix(line, []byte(":")) && !bytes.HasPrefix(line, []byte("event:")) && !bytes.HasPrefix(line, []byte("id:")) {
				return nil, ErrPrerequisite
			}
		}
		if len(lines) == 0 {
			return nil, ErrPrerequisite
		}
		raw := bytes.Join(lines, []byte("\n"))
		if _, err := sourceObject(raw); err != nil {
			return nil, err
		}
		rows = append(rows, raw)
	}
	if !bytes.HasSuffix(n.Log, []byte("\n\n")) || len(rows) < 2 || len(rows) > 32769 {
		return nil, ErrPrerequisite
	}
	var marker struct {
		Type, AggregateID string
		Seq               int64
	}
	if _, err := sourceFields(rows[len(rows)-1], "type aggregateID seq", ""); err != nil {
		return nil, err
	}
	if model.DecodePhysicalClosed(rows[len(rows)-1], &marker) != nil || marker.Type != "log.synced" || marker.AggregateID != o.Permit.Offline.Slot.SessionID || marker.Seq != int64(len(rows)-2) {
		return nil, ErrPrerequisite
	}
	guardData, err := sourceData(n.Guard)
	if err != nil {
		return nil, err
	}
	var guard struct {
		FormatVersion                                                  int
		NativeGuardVersion, SessionID                                  string
		InputSeq, ExecutionStartedSeq, ExecutionTerminalSeq, LogCursor *int64
		ContextSeq                                                     *int64
		Active                                                         bool
		ObservedAt                                                     int64
	}
	guardFields, err := sourceFields(guardData, "formatVersion nativeGuardVersion sessionID inputSeq executionStartedSeq executionTerminalSeq contextSeq active observedAt logCursor", "")
	if err != nil {
		return nil, err
	}
	if model.DecodePhysicalClosed(guardData, &guard) != nil || len(guardFields) != 10 || guard.FormatVersion != 1 || guard.NativeGuardVersion != "warpmetal.atomic-input.v1" || guard.SessionID != marker.AggregateID || guard.Active == terminalRequired || guard.InputSeq == nil || guard.ExecutionStartedSeq == nil || (terminalRequired && guard.ExecutionTerminalSeq == nil) || (!terminalRequired && guard.ExecutionTerminalSeq != nil) || guard.LogCursor == nil || *guard.LogCursor != marker.Seq || guard.ObservedAt <= 0 || guard.ObservedAt > time.Now().UnixMilli() {
		return nil, ErrPrerequisite
	}
	events := []sourceDurableEvent{}
	ids := map[string]bool{}
	for seq, raw := range rows[:len(rows)-1] {
		var e sourceDurableEvent
		fields, err := sourceFields(raw, "id type created durable data", "location metadata")
		if err != nil {
			return nil, err
		}
		if _, err = sourceFields(fields["durable"], "aggregateID seq version", ""); err != nil {
			return nil, err
		}
		if model.DecodePhysicalClosed(raw, &e) != nil || !strings.HasPrefix(e.ID, "evt_") || ids[e.ID] || e.Durable.Seq != int64(seq) || e.Durable.Version < 1 || e.Durable.AggregateID != marker.AggregateID || e.Created < 0 || e.Created > guard.ObservedAt {
			return nil, ErrPrerequisite
		}
		fields, err = sourceObject(e.Data)
		var session string
		if err != nil || json.Unmarshal(fields["sessionID"], &session) != nil || session != marker.AggregateID {
			return nil, ErrPrerequisite
		}
		ids[e.ID] = true
		events = append(events, e)
	}
	i, s, t := *guard.InputSeq, *guard.ExecutionStartedSeq, marker.Seq
	if terminalRequired {
		t = *guard.ExecutionTerminalSeq
	}
	if i < 0 || !(i < s && s <= t) || t != marker.Seq || t >= int64(len(events)) || events[0].Type != "session.created" || events[i].Type != "session.inbox.enqueued" || events[s].Type != "session.execution.started" {
		return nil, ErrPrerequisite
	}
	inputFields, _ := sourceObject(events[i].Data)
	var input string
	if json.Unmarshal(inputFields["inboxID"], &input) != nil || input != o.Permit.Offline.Slot.InputID {
		return nil, ErrPrerequisite
	}
	// Input and unchanged inner grant join the owning Store's actual preparation
	// and admission basis. They are not inferred from an event ID or collector ACK.
	admission, err := sourceObject(n.Basis.Admission)
	if err != nil || len(admission) != 4 || model.WorkspaceDigest(json.RawMessage(n.Basis.Admission)) != o.Permit.Offline.Slot.AdmissionDigest || !model.PhysicalDigestValid(n.Basis.InputDigest) {
		return nil, ErrPrerequisite
	}
	receipt, err := sourceObject(admission["preparedReceipt"])
	var receiptDigest string
	if err != nil || json.Unmarshal(receipt["preparedReceiptDigest"], &receiptDigest) != nil || receiptDigest != o.Permit.Offline.Slot.PreparedReceiptDigest {
		return nil, ErrPrerequisite
	}
	item, err := sourceObject(inputFields["item"])
	var itemType string
	if err != nil || json.Unmarshal(item["type"], &itemType) != nil || itemType != "user" {
		return nil, ErrPrerequisite
	}
	payload, err := sourceObject(item["payload"])
	var text string
	if err != nil || json.Unmarshal(payload["text"], &text) != nil || model.RawPhysicalDigest([]byte(text)) != n.Basis.InputDigest {
		return nil, ErrPrerequisite
	}
	if o.Permit.Request.Consumer == "parent" {
		if payload["controllerBinding"] == nil || model.WorkspaceDigest(json.RawMessage(payload["controllerBinding"])) != model.WorkspaceDigest(json.RawMessage(n.Basis.Admission)) {
			return nil, ErrPrerequisite
		}
	} else {
		inputGuard, err := sourceObject(payload["guard"])
		if err != nil || inputGuard["cellGrant"] == nil || model.WorkspaceDigest(json.RawMessage(inputGuard["cellGrant"])) != model.WorkspaceDigest(json.RawMessage(admission["grant"])) {
			return nil, ErrPrerequisite
		}
	}
	delivered := 0
	for seq := s + 1; seq <= t; seq++ {
		e := events[seq]
		fields, _ := sourceObject(e.Data)
		if e.Type == "session.inbox.delivered" {
			var id string
			if json.Unmarshal(fields["inboxID"], &id) != nil || id != input || (terminalRequired && seq >= t) {
				return nil, ErrPrerequisite
			}
			delivered++
		}
		if e.Type == "session.inbox.enqueued" || strings.HasPrefix(e.Type, "session.controller.") || e.Type == "session.forked" || e.Type == "session.model.updated" || e.Type == "session.agent.updated" || e.Type == "session.moved" {
			return nil, ErrPrerequisite
		}
		if seq < t && (e.Type == "session.execution.started" || e.Type == "session.execution.succeeded" || e.Type == "session.execution.failed" || e.Type == "session.execution.interrupted") {
			return nil, ErrPrerequisite
		}
	}
	terminal := events[t]
	fields, _ := sourceObject(terminal.Data)
	if delivered != 1 {
		return nil, ErrPrerequisite
	}
	if terminalRequired {
		if o.Permit.Offline.Slot.Oracle == "controller_deadline" {
			var failure struct{ Type, Message string }
			if terminal.Type != "session.execution.failed" || model.DecodePhysicalClosed(fields["error"], &failure) != nil || failure.Type != "unknown" || failure.Message != "controller_deadline_expired" {
				return nil, ErrPrerequisite
			}
		} else {
			var reason string
			if terminal.Type != "session.execution.interrupted" || json.Unmarshal(fields["reason"], &reason) != nil || reason != "user" {
				return nil, ErrPrerequisite
			}
		}
	}
	active, err := sourceData(n.Active)
	if err != nil {
		return nil, err
	}
	var sessions map[string]json.RawMessage
	if model.DecodePhysicalClosed(active, &sessions) != nil || sessions == nil || (terminalRequired && sessions[marker.AggregateID] != nil) || (!terminalRequired && sessions[marker.AggregateID] == nil) {
		return nil, ErrPrerequisite
	}
	inbox, err := sourceData(n.Inbox)
	if err != nil {
		return nil, err
	}
	var pending []json.RawMessage
	if model.DecodePhysicalClosed(inbox, &pending) != nil || pending == nil || len(pending) != 0 {
		return nil, ErrPrerequisite
	}
	if !terminalRequired {
		return rows[s], nil
	}
	return rows[t], nil
}

// ONLY this verified owning consumer invokes CompleteOffline in production. A
// current-original failure does not inhibit cancellation/capture and never clears
// UNKNOWN, releases cash, rewrites an opening or consumes another local slot.
func (c SourceTerminalConsumer) Complete(ctx context.Context, id string) error {
	if c.Store == nil || c.Reader == nil || c.Listener == nil || c.Listener.store != c.Store {
		return ErrPrerequisite
	}
	o, err := c.Store.PhysicalOperation(ctx, id)
	if err != nil || o == nil || o.Permit.Offline == nil || o.Phase != "unknown" {
		return ErrPrerequisite
	}
	raw, err := c.Store.PhysicalFact(ctx, sourceCaptureKey(id))
	var capture sourcePreCancel
	if err != nil || model.DecodePhysicalClosed(raw, &capture) != nil || capture.Kernel.Caller != o.Permit.Caller {
		return ErrPrerequisite
	}
	before := capture.Kernel
	started, err := verifySourceNative(capture.Native, *o, false)
	if err != nil {
		return err
	}
	exchange, err := c.Listener.Exchange(ctx, id)
	if err != nil || exchange.RequestDigest != o.Permit.Request.RequestDigest || exchange.WindowDigest != o.Permit.Offline.WindowDigest || exchange.AcceptedAt.IsZero() || exchange.ClosedAt.Before(exchange.PrefixAt) {
		return ErrPrerequisite
	}
	if o.Permit.Offline.Slot.Oracle != "tool_cancel" && !before.ObservedAt.Before(exchange.ClosedAt) {
		return ErrPrerequisite
	}
	first, err := c.Reader.Native(ctx, *o)
	if err != nil {
		return err
	}
	terminal, err := verifySourceNative(first, *o, true)
	if err != nil {
		return err
	}
	preRows := bytes.Split(capture.Native.Log, []byte("\n\n"))
	postRows := bytes.Split(first.Log, []byte("\n\n"))
	if len(postRows) < len(preRows) || !reflect.DeepEqual(preRows[:len(preRows)-2], postRows[:len(preRows)-2]) || !reflect.DeepEqual(capture.Native.Basis, first.Basis) {
		return ErrPrerequisite
	}
	cut, err := c.Reader.Kernel(ctx, *o, before.Descendants)
	if err != nil || cut.Caller != before.Caller || cut.RegistrationDigest != before.RegistrationDigest || !reflect.DeepEqual(cut.Native, before.Native) || len(cut.Descendants) != 0 || !reflect.DeepEqual(cut.TrackedExited, before.Descendants) {
		return ErrPrerequisite
	}
	if !sourceNativeClosedSocket(cut, exchange) {
		return ErrPrerequisite
	}
	// A second real read after the bounded observation interval, not a hash/ACK.
	delay := 250 * time.Millisecond
	if o.Permit.Offline.Slot.Oracle == "tool_cancel" {
		delay = 31 * time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	second, err := c.Reader.Native(ctx, *o)
	if err != nil {
		return err
	}
	if _, err = verifySourceNative(second, *o, true); err != nil {
		return err
	}
	if !bytes.Equal(first.Log, second.Log) || !bytes.Equal(first.Active, second.Active) || !bytes.Equal(first.Inbox, second.Inbox) || !reflect.DeepEqual(first.Basis, second.Basis) || !sourceGuardStable(first.Guard, second.Guard) {
		return ErrPrerequisite
	}
	last, err := c.Reader.Kernel(ctx, *o, before.Descendants)
	if err != nil || last.Caller != before.Caller || last.RegistrationDigest != before.RegistrationDigest || !reflect.DeepEqual(last.Native, before.Native) || len(last.Descendants) != 0 || !reflect.DeepEqual(last.TrackedExited, before.Descendants) || last.ObservedAt.Before(cut.ObservedAt.Add(delay)) {
		return ErrPrerequisite
	}
	if !sourceNativeClosedSocket(last, exchange) {
		return ErrPrerequisite
	}
	// Tool proof must additionally join the pre-cancel shell/original output,
	// tracked descendant exits and late-effect bytes. Until that reader supplies
	// these originals this branch MUST stay UNKNOWN, never use shell.remove/404.
	if o.Permit.Offline.Slot.Oracle == "tool_cancel" {
		return ErrPrerequisite
	}
	quiescence, _ := json.Marshal(struct {
		Native []SourceNativeTerminal
		Kernel []SourceKernelCut
	}{[]SourceNativeTerminal{first, second}, []SourceKernelCut{cut, last}})
	socket := sourceSocketOriginal(exchange)
	var startEvent, endEvent sourceDurableEvent
	if model.DecodePhysicalClosed(started, &startEvent) != nil || model.DecodePhysicalClosed(terminal, &endEvent) != nil {
		return ErrPrerequisite
	}
	evidence := SourceTerminalEvidence{EventsDigest: model.RawPhysicalDigest(first.Log), QuiescenceDigest: model.RawPhysicalDigest(quiescence), SocketDigest: model.RawPhysicalDigest(socket), StartedEventID: startEvent.ID, TerminalEventID: endEvent.ID}
	for _, original := range [][]byte{first.Log, quiescence, socket, terminal} {
		d := model.RawPhysicalDigest(original)
		if err = c.Store.RetainPhysicalFact(ctx, "source_original_"+d[7:], original); err != nil {
			return err
		}
	}
	current, err := c.Reader.Current(ctx, *o, evidence)
	if err != nil {
		return err
	}
	a := o.Permit.Offline.Slot
	if current.Caller != o.Permit.Caller || current.PreparationID != a.PreparationID || current.SessionID != a.SessionID || current.InputID != a.InputID || current.PreparedReceiptDigest != a.PreparedReceiptDigest || current.ControlRevision < a.ControlRevision || current.TerminalRevision != current.ControlRevision || len(current.ControlOriginal) == 0 || len(current.TerminalOriginal) == 0 || current.Evidence != evidence {
		return ErrPrerequisite
	}
	// Re-read actual owning listener after the late-effect interval. Reconnects /
	// retries invalidate the first receipt rather than replacing its RED evidence.
	if _, err = c.Listener.Exchange(ctx, id); err != nil {
		return err
	}
	for _, original := range [][]byte{first.Log, quiescence, socket, current.ControlOriginal, current.TerminalOriginal, terminal} {
		d := model.RawPhysicalDigest(original)
		if err = c.Store.RetainPhysicalFact(ctx, "source_original_"+d[7:], original); err != nil {
			return err
		}
	}
	e := state.OfflineTerminal{OperationID: id, Caller: o.Permit.Caller, PreparationID: a.PreparationID, SessionID: a.SessionID, InputID: a.InputID, RequestDigest: o.Permit.Request.RequestDigest, ControlRevision: current.ControlRevision, TerminalRevision: current.TerminalRevision, ControlDigest: model.RawPhysicalDigest(current.ControlOriginal), TerminalDigest: model.RawPhysicalDigest(current.TerminalOriginal), EventsDigest: model.RawPhysicalDigest(first.Log), QuiescenceDigest: model.RawPhysicalDigest(quiescence), SocketDigest: model.RawPhysicalDigest(socket)}
	return c.Listener.complete(ctx, id, e)
}

func (c SourceTerminalConsumer) ForPreparation(ctx context.Context, preparation string, before bool) error {
	if c.Store == nil {
		return ErrPrerequisite
	}
	o, err := c.Store.PhysicalOwner(ctx)
	if err != nil {
		return err
	}
	if o == nil {
		return nil
	}
	if o.Permit.Offline == nil || o.Permit.Request.PreparationID != preparation {
		return nil
	}
	if before {
		return c.BeforeCancel(ctx, o.OperationID)
	}
	return c.Complete(ctx, o.OperationID)
}
