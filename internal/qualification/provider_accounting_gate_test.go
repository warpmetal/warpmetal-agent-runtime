package qualification_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/physicalgate"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/providerpolicy"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

type accountingGateSource struct {
	store             *state.Store
	producer          *qualification.Producer
	client            api.Client
	permit            state.PhysicalPermit
	caller            physicalgate.Caller
	originals         state.NativeSettlementOriginals
	evidence          model.PhysicalSettlement
	lost              bool
	authority, demand json.RawMessage
	operator          []byte
}

func (a *accountingGateSource) Authenticate(_ context.Context, p physicalgate.Peer) (physicalgate.Caller, error) {
	if p.PID != os.Getpid() || p.UID != uint32(os.Getuid()) {
		return physicalgate.Caller{}, physicalgate.ErrPrerequisite
	}
	return a.caller, nil
}
func (a *accountingGateSource) AuthorizeAdmission(ctx context.Context, c physicalgate.Caller, r model.PhysicalAdmitRequest) (state.PhysicalPermit, error) {
	if c != a.caller || !reflect.DeepEqual(r, a.permit.Request) {
		return state.PhysicalPermit{}, physicalgate.ErrPrerequisite
	}
	opening, err := a.store.ProviderOpening(ctx)
	if err != nil {
		return state.PhysicalPermit{}, err
	}
	var pair struct {
		Backend struct {
			Payload struct {
				AuthorityDigest string `json:"authorityDigest"`
			} `json:"payload"`
		} `json:"backend"`
	}
	_ = json.Unmarshal(opening, &pair)
	prefix, err := a.client.ProviderAccountingCurrent(ctx, pair.Backend.Payload.AuthorityDigest)
	if err != nil {
		return state.PhysicalPermit{}, err
	}
	if a.permit.Case.ProviderPolicyDigest == providerpolicy.ParticipantDigest {
		return a.producer.BindProviderParticipantReservation(ctx, a.store, a.authority, a.demand, prefix, a.operator, a.permit)
	}
	return a.store.BindProviderReservation(ctx, a.permit, prefix)
}
func (a *accountingGateSource) VerifyAdmissionOriginals(_ context.Context, _ physicalgate.Caller, _ string, p state.PhysicalPermit) error {
	if model.RawPhysicalDigest(a.originals.Request) != p.Request.RequestDigest {
		return physicalgate.ErrPrerequisite
	}
	return nil
}
func (a *accountingGateSource) SettleProviderAccountingOriginals(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	ack, err := a.client.SettleProviderAccountingOriginals(ctx, raw)
	if err == nil && !a.lost {
		a.lost = true
		return nil, errors.New("SOURCE deliberately lost backend settlement ACK")
	}
	return ack, err
}
func (a *accountingGateSource) VerifySettlement(ctx context.Context, c physicalgate.Caller, o state.PhysicalOperation, e model.PhysicalSettlement) error {
	if c != a.caller || e != a.evidence || len(a.originals.Response) == 0 {
		return physicalgate.ErrPrerequisite
	}
	if err := a.store.RetainNativeSettlementOriginals(ctx, o.OperationID, c.Subject(), e, a.originals); err != nil {
		return err
	}
	return a.producer.SettleProviderPhysical(ctx, a.store, a, o, e)
}

func runProviderAccountingGateSource(t *testing.T, raw []byte) {
	t.Helper()
	var packet struct {
		Root                       string                       `json:"root"`
		Producer                   qualification.ProducerConfig `json:"producer"`
		Authority                  json.RawMessage              `json:"authority"`
		Demand                     json.RawMessage              `json:"demand"`
		OperatorPublicKeyBase64    string                       `json:"operatorPublicKeyBase64"`
		PreparationID              string                       `json:"preparationId"`
		Consumer                   string                       `json:"consumer"`
		RequestIndex               int                          `json:"requestIndex"`
		PhysicalIndex              int                          `json:"physicalIndex"`
		InnerPhysicalIndex         *int                         `json:"innerPhysicalIndex"`
		NativeSessionID            *string                      `json:"nativeSessionId"`
		NativeInputID              *string                      `json:"nativeInputId"`
		RequestBase64              string                       `json:"requestBase64"`
		ResponseBase64             string                       `json:"responseBase64"`
		Transport                  json.RawMessage              `json:"transport"`
		ProviderRequestID          string                       `json:"providerRequestId"`
		ParticipantID              string                       `json:"participantId"`
		GateMode                   string                       `json:"gateMode"`
		ExpectedLocalIndicesBefore []int                        `json:"expectedLocalIndicesBefore"`
		ExpectedLocalIndicesAfter  []int                        `json:"expectedLocalIndicesAfter"`
	}
	if json.Unmarshal(raw, &packet) != nil || !filepath.IsAbs(packet.Root) {
		t.Fatal("invalid source gate packet")
	}
	if packet.GateMode != "" && packet.GateMode != "complete" && packet.GateMode != "hold" && packet.GateMode != "recover" && packet.GateMode != "readback" {
		t.Fatal("unknown SOURCE gate phase")
	}
	if packet.ParticipantID != "" {
		checkAccountingParticipantSource(t, packet.Authority, packet.Producer, packet.ParticipantID)
	}
	origin := os.Getenv("WARPMETAL_ACCOUNTING_BACKEND_ORIGIN")
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || (parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1") {
		t.Fatal("explicit local HTTPS fixture required")
	}
	pem, err := os.ReadFile(os.Getenv("WARPMETAL_ACCOUNTING_CA_PEM"))
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(pem) {
		t.Fatal("fixture CA")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	defer transport.CloseIdleConnections()
	client := api.Client{Origin: origin, NodeToken: os.Getenv("WARPMETAL_ACCOUNTING_NODE_TOKEN"), HTTP: &http.Client{Transport: transport}}
	producer, err := qualification.SourceAccountingProducerForTest(packet.Producer)
	if err != nil {
		t.Fatal("source producer", err)
	}
	ctx := context.Background()
	dbPath := filepath.Join(packet.Root, "runtime.db")
	store, err := state.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if packet.GateMode == "recover" {
		runProviderAccountingRecoverySource(t, store, producer, client, raw)
		return
	}
	prefix, err := client.ProviderAccountingCurrent(ctx, model.WorkspaceDigest(packet.Authority))
	if err != nil {
		t.Fatal("current backend prefix", err)
	}
	var current model.ProviderAccountingPrefix
	_ = json.Unmarshal(prefix, &current)
	operator, operatorErr := base64.StdEncoding.Strict().DecodeString(packet.OperatorPublicKeyBase64)
	if packet.ParticipantID != "" {
		if operatorErr != nil || len(packet.Demand) == 0 {
			t.Fatal("missing original participant demand/operator")
		}
		err = producer.AcceptProviderParticipantOpening(ctx, store, packet.Authority, packet.Demand, current.Opening, operator)
	} else {
		err = store.AcceptProviderOpening(ctx, current.Opening)
	}
	if err != nil {
		t.Fatal("same independent opening", err)
	}
	if packet.ParticipantID != "" {
		checkAccountingLocalRows(t, store, packet.ExpectedLocalIndicesBefore, packet.ParticipantID)
	}
	if packet.GateMode == "readback" {
		if packet.ParticipantID == "" {
			t.Fatal("participant readback requires exact original scope")
		}
		exportAccountingReadbackSource(t, producer, store, client, packet.Authority, packet.Demand, operator, packet.Root, "runtime-readback.json")
		checkAccountingLocalRows(t, store, packet.ExpectedLocalIndicesAfter, packet.ParticipantID)
		if len(current.Reservations) == 21 {
			anchor, err := store.PhysicalAnchor(ctx)
			if err != nil || anchor == nil {
				t.Fatal(err)
			}
			history, err := store.PhysicalHistory(ctx, *anchor)
			if err != nil || len(history) == 0 {
				t.Fatal(err)
			}
			p := history[len(history)-1].Permit
			p.Request.OuterPhysicalIndex = 22
			if store.AdmitPhysical(ctx, "source_slot22_refusal", p) == nil {
				t.Fatal("slot22 admitted outside immutable21")
			}
			checkAccountingLocalRows(t, store, packet.ExpectedLocalIndicesAfter, packet.ParticipantID)
		}
		t.Log("actual producer global/local signed readback only; no local dispatch or supplier HTTP")
		return
	}
	if packet.PhysicalIndex < 1 || packet.PhysicalIndex > len(current.Reservations) {
		t.Fatal("missing actual backend reservation")
	}
	var reservation model.ProviderReservation
	_ = json.Unmarshal(current.Reservations[packet.PhysicalIndex-1], &reservation)
	if packet.ParticipantID != "" {
		var selected struct{ ParticipantID string }
		if json.Unmarshal(current.Reservations[packet.PhysicalIndex-1], &selected) != nil || selected.ParticipantID != packet.ParticipantID {
			t.Fatal("backend reservation belongs to another participant")
		}
	}
	anchor, err := store.PhysicalAnchor(ctx)
	if err != nil || anchor == nil {
		t.Fatal("own independent anchor", err)
	}
	requestBytes, err := base64.StdEncoding.DecodeString(packet.RequestBase64)
	if err != nil {
		t.Fatal(err)
	}
	responseBytes, err := base64.StdEncoding.DecodeString(packet.ResponseBase64)
	if err != nil {
		t.Fatal(err)
	}
	caller := physicalgate.Caller{SandboxID: "source_native_box", SandboxGeneration: 1, NativeInstance: "source_native", NativeIdentityDigest: model.WorkspaceDigest("explicit detached SOURCE process identity")}
	if packet.ParticipantID != "" {
		var envelope struct {
			Payload struct {
				Allocations []qualification.DemandAllocation
			}
		}
		_ = json.Unmarshal(packet.Demand, &envelope)
		matched := false
		for _, allocation := range envelope.Payload.Allocations {
			if allocation.AllocationID == reservation.AllocationID {
				caller.SandboxID = allocation.Scope.SandboxID
				caller.SandboxGeneration = allocation.Scope.SandboxGeneration
				matched = true
			}
		}
		if !matched {
			t.Fatal("SOURCE native role has no exact allocation")
		}
	}
	request := model.PhysicalAdmitRequest{Consumer: packet.Consumer, PreparationID: packet.PreparationID, RequestIndex: packet.RequestIndex, OuterPhysicalIndex: packet.PhysicalIndex, InnerPhysicalIndex: packet.InnerPhysicalIndex, AuthorityDigest: model.WorkspaceDigest("SOURCE signed role scope supplier"), RequestDigest: model.RawPhysicalDigest(requestBytes)}
	admission, _ := model.WorkspaceCanonicalJSON(request)
	id := "pg_" + model.WorkspaceDigest(request)[7:]
	a := &accountingGateSource{authority: packet.Authority, demand: packet.Demand, operator: operator, store: store, producer: producer, client: client, caller: caller, permit: state.PhysicalPermit{Case: *anchor, Caller: caller.Subject(), Request: request, AllocationID: reservation.AllocationID, PreparationOrdinal: reservation.PreparationOrdinal, Provider: &state.ProviderAdmission{NativeSessionID: packet.NativeSessionID, NativeInputID: packet.NativeInputID}}, originals: state.NativeSettlementOriginals{Journal: admission, Request: requestBytes, Transport: packet.Transport}}
	endpoint, err := os.MkdirTemp("/tmp", "wm-fin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE Unix endpoint", endpoint)
	var listener *net.UnixListener
	serve := func(name string) string {
		socket := filepath.Join(endpoint, name)
		var err error
		listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		listener.SetUnlinkOnClose(false)
		go (physicalgate.Server{Store: store, Authority: a}).Serve(listener)
		return socket
	}
	socket := serve("first.sock")
	defer func() { _ = listener.Close() }()
	call := func(action string, body any) model.PhysicalRPCResponse {
		raw, _ := json.Marshal(body)
		reply, err := physicalgate.Call(ctx, socket, model.PhysicalRPCRequest{FormatVersion: 1, Action: action, OperationID: id, Body: raw})
		if err != nil {
			t.Fatal(action, err)
		}
		return reply
	}
	if got := call("admit", request); got.Status != "admitted" {
		t.Fatal("actual Unix admission", got.Status)
	}
	if got := call("admit", request); got.Status != "refused" {
		t.Fatal("UNKNOWN allowed second dispatch")
	}
	// Actual local HTTP, with a declared provider supplier and no external request.
	httpCalls := 0
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls++
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, requestBytes) {
			t.Error("final source body changed")
		}
		w.Header().Set("X-Request-Id", packet.ProviderRequestID)
		w.WriteHeader(200)
		_, _ = w.Write(responseBytes)
	}))
	defer fixture.Close()
	method := "POST"
	if packet.Consumer == "access" {
		method = "GET"
	}
	req, _ := http.NewRequestWithContext(ctx, method, fixture.URL, bytes.NewReader(requestBytes))
	response, err := fixture.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || httpCalls != 1 {
		t.Fatal("source HTTP terminal", err)
	}
	ids := response.Header.Values("X-Request-Id")
	if len(ids) != 1 || !model.PhysicalIDValid(ids[0]) {
		t.Fatal("actual safe HTTP request ID absent")
	}
	a.originals.ProviderRequestID = ids[0]
	a.originals.ProviderResponse, _ = model.WorkspaceCanonicalJSON(map[string]any{"formatVersion": 1, "providerRequestId": ids[0]})
	cost := int64(0)
	if packet.Consumer != "access" {
		_, cost, err = physicalgate.ProviderResponseUsage(anchor.ProviderPolicyDigest, observed, response.StatusCode)
		if err != nil {
			t.Fatal(err)
		}
	}
	completion, _ := model.WorkspaceCanonicalJSON(map[string]any{"requestDigest": request.RequestDigest, "responseDigest": model.RawPhysicalDigest(observed), "responseByteCount": len(observed), "httpStatus": response.StatusCode, "usageUsdMicros": cost})
	a.originals.Response, a.originals.Completion = observed, completion
	a.evidence = model.PhysicalSettlement{RequestDigest: request.RequestDigest, ResponseDigest: model.RawPhysicalDigest(observed), ResponseByteCount: len(observed), HTTPStatus: response.StatusCode, UsageUsdMicros: cost, EvidenceDigest: model.RawPhysicalDigest(completion)}
	if got := call("settle", a.evidence); got.Status != "refused" || !a.lost {
		t.Fatal("lost backend ACK did not retain UNKNOWN", got.Status)
	}
	if got := call("status", map[string]any{}); got.Status != "unknown" {
		t.Fatal("backend acceptance released local owner without ACK")
	}
	if packet.GateMode == "hold" {
		retainAccountingGatePendingSource(t, store, packet.Root, packet.ParticipantID, packet.PhysicalIndex, id, a.evidence, a.originals)
		if packet.ParticipantID != "" {
			checkAccountingLocalRows(t, store, packet.ExpectedLocalIndicesAfter, packet.ParticipantID)
		}
		exportAccountingReadbackSource(t, producer, store, client, packet.Authority, packet.Demand, operator, packet.Root, "runtime-readback.json")
		t.Log("own first signed settlement accepted by backend; deliberate lost ACK leaves actual local UNKNOWN for separate peer progress/recovery phase")
		return
	}
	_ = listener.Close()
	_ = store.Close()
	store, err = state.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	a.store = store
	socket = serve("reopened.sock")
	if got := call("settle", a.evidence); got.Status != "settled" {
		t.Fatal("exact originals reconciliation after reopen", got.Status)
	}
	first, err := store.PhysicalFact(ctx, "provider_settlement_"+model.RawPhysicalDigest([]byte(id))[7:])
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(packet.Root, "provider-settlement-envelope.json"), first, 0600); err != nil {
		t.Fatal(err)
	}
	var original struct {
		Payload struct {
			ProviderRequestID string `json:"providerRequestId"`
		} `json:"payload"`
	}
	if json.Unmarshal(first, &original) != nil || original.Payload.ProviderRequestID != ids[0] {
		t.Fatal("signed settlement substituted SSE response.id for actual HTTP request ID")
	}
	if got := call("admit", request); got.Status != "refused" {
		t.Fatal("settled slot replayed provider request")
	}
	if packet.ParticipantID != "" {
		checkAccountingLocalRows(t, store, packet.ExpectedLocalIndicesAfter, packet.ParticipantID)
		exportAccountingReadbackSource(t, producer, store, client, packet.Authority, packet.Demand, operator, packet.Root, "runtime-readback.json")
	}
	t.Log("actual Unix+SQLite+local HTTP+backend HTTPS/PG; immutable IDs, UNKNOWN/lost ACK/reopen, exact settlement; provider supplier/process/role authority synthetic; external calls0")
}
