package qualification_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type accountingGatePendingSource struct {
	ParticipantID, OperationID, OperationDigest, FirstEnvelopeDigest string
	Evidence                                                         model.PhysicalSettlement
}

func accountingPendingPath(root string, index int) string {
	return filepath.Join(root, fmt.Sprintf("pending-gate-%d.json", index))
}

// Private SOURCE test observation, not a new journal or Runtime authority. All
// bytes must already exist in the actual SQLite first-original owner records.
func retainAccountingGatePendingSource(t *testing.T, store *state.Store, root, participant string, index int, id string, evidence model.PhysicalSettlement, originals state.NativeSettlementOriginals) {
	t.Helper()
	ctx := context.Background()
	o, err := store.PhysicalOperation(ctx, id)
	if err != nil || o == nil || o.Phase != "unknown" || o.Permit.Request.OuterPhysicalIndex != index {
		t.Fatal("missing real pending operation", err)
	}
	actual, _, err := store.NativeProviderOriginals(ctx, id, evidence)
	if err != nil || !reflect.DeepEqual(actual, originals) {
		t.Fatal("pending own original custody", err)
	}
	first, err := store.PhysicalFact(ctx, "provider_settlement_"+model.RawPhysicalDigest([]byte(id))[7:])
	if err != nil || len(first) == 0 {
		t.Fatal("pending first producer signature", err)
	}
	raw, err := model.WorkspaceCanonicalJSON(accountingGatePendingSource{participant, id, model.WorkspaceDigest(*o), model.WorkspaceDigest(json.RawMessage(first)), evidence})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(accountingPendingPath(root, index), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("pending SOURCE observation is immutable", err)
	}
	_, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal("retain pending SOURCE observation", writeErr, syncErr, closeErr)
	}
	if err := os.WriteFile(filepath.Join(root, "provider-settlement-envelope.json"), first, 0600); err != nil {
		t.Fatal("export exact first pending envelope", err)
	}
}

func runProviderAccountingRecoverySource(t *testing.T, store *state.Store, producer *qualification.Producer, client api.Client, raw []byte) {
	t.Helper()
	var packet struct {
		Root, ParticipantID                                   string
		PhysicalIndex, ExpectedGlobalPhysicalRequests         int
		ExpectedLocalIndicesBefore, ExpectedLocalIndicesAfter []int
		Authority                                             json.RawMessage
		Demand                                                json.RawMessage
		OperatorPublicKeyBase64                               string
	}
	if json.Unmarshal(raw, &packet) != nil || packet.PhysicalIndex < 1 || packet.ParticipantID == "" {
		t.Fatal("invalid own recovery SOURCE packet")
	}
	saved, err := os.ReadFile(accountingPendingPath(packet.Root, packet.PhysicalIndex))
	var pending accountingGatePendingSource
	if err != nil || model.DecodePhysicalClosed(saved, &pending) != nil || pending.ParticipantID != packet.ParticipantID {
		t.Fatal("first retained own pending original unavailable", err)
	}
	ctx := context.Background()
	operator, err := base64.StdEncoding.Strict().DecodeString(packet.OperatorPublicKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	checkAccountingLocalRows(t, store, packet.ExpectedLocalIndicesBefore, packet.ParticipantID)
	actual, err := store.PhysicalOperation(ctx, pending.OperationID)
	if err != nil || actual == nil || model.WorkspaceDigest(*actual) != pending.OperationDigest || actual.Phase != "unknown" || actual.Permit.Request.OuterPhysicalIndex != packet.PhysicalIndex {
		t.Fatal("reopened local UNKNOWN differs from first original", err)
	}
	originals, _, err := store.NativeProviderOriginals(ctx, pending.OperationID, pending.Evidence)
	if err != nil {
		t.Fatal("actual first local HTTP originals missing", err)
	}
	firstBefore, err := store.PhysicalFact(ctx, "provider_settlement_"+model.RawPhysicalDigest([]byte(pending.OperationID))[7:])
	if err != nil || model.WorkspaceDigest(json.RawMessage(firstBefore)) != pending.FirstEnvelopeDigest {
		t.Fatal("actual first local producer envelope missing", err)
	}
	current, err := client.ProviderAccountingCurrent(ctx, model.WorkspaceDigest(packet.Authority))
	var prefix model.ProviderAccountingPrefix
	if err != nil || json.Unmarshal(current, &prefix) != nil || len(prefix.Reservations) != packet.ExpectedGlobalPhysicalRequests {
		t.Fatal("actual global advance not observed", err)
	}
	matched := false
	for _, first := range prefix.Settlements {
		if model.WorkspaceDigest(first) == pending.FirstEnvelopeDigest {
			matched = true
		}
	}
	if !matched {
		t.Fatal("backend does not retain own exact first settlement")
	}
	exportAccountingReadbackSource(t, producer, store, client, packet.Authority, packet.Demand, operator, packet.Root, "runtime-readback-before-recovery.json")
	owner, err := store.PhysicalOwner(ctx)
	if err != nil || owner == nil || owner.OperationID != pending.OperationID || owner.ReservedUsdMicros != 421000 {
		t.Fatal("global advancement released own UNKNOWN", err)
	}
	c := actual.Permit.Caller
	a := &accountingGateSource{authority: packet.Authority, demand: packet.Demand, operator: operator, store: store, producer: producer, client: client, caller: physicalgate.Caller{SandboxID: c.SandboxID, SandboxGeneration: c.SandboxGeneration, NativeInstance: c.NativeInstance, NativeIdentityDigest: c.NativeIdentityDigest}, permit: actual.Permit, originals: originals, evidence: pending.Evidence, lost: true}
	endpoint, err := os.MkdirTemp("/tmp", "wm-fin-recover-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE recovery endpoint", endpoint)
	socket := filepath.Join(endpoint, "recover.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	go (physicalgate.Server{Store: store, Authority: a}).Serve(listener)
	call := func(action string, body any) model.PhysicalRPCResponse {
		encoded, _ := json.Marshal(body)
		reply, err := physicalgate.Call(ctx, socket, model.PhysicalRPCRequest{FormatVersion: 1, Action: action, OperationID: pending.OperationID, Body: encoded})
		if err != nil {
			t.Fatal(action, err)
		}
		return reply
	}
	if got := call("admit", actual.Permit.Request); got.Status != "refused" {
		t.Fatal("recovery redispatched old request")
	}
	if got := call("settle", pending.Evidence); got.Status != "settled" {
		t.Fatal("exact own original replay did not recover", got.Status)
	}
	first, err := store.PhysicalFact(ctx, "provider_settlement_"+model.RawPhysicalDigest([]byte(pending.OperationID))[7:])
	if err != nil || !bytes.Equal(first, firstBefore) {
		t.Fatal("own first settlement signature replaced", err)
	}
	if got := call("admit", actual.Permit.Request); got.Status != "refused" {
		t.Fatal("recovered slot replayed provider request")
	}
	checkAccountingLocalRows(t, store, packet.ExpectedLocalIndicesAfter, packet.ParticipantID)
	if err := os.WriteFile(filepath.Join(packet.Root, "provider-settlement-envelope.json"), first, 0600); err != nil {
		t.Fatal(err)
	}
	exportAccountingReadbackSource(t, producer, store, client, packet.Authority, packet.Demand, operator, packet.Root, "runtime-readback.json")
	t.Log("same SQLite/first original recovered after observed global advance; zero new provider supplier calls or local operation rows")
}
