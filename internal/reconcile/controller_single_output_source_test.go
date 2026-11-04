package reconcile

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// Unchanged backend HTTP/PG originals cross the actual Runtime TLS/SQLite
// consumers. Their native/provider suppliers remain SOURCE; expired originals
// are decoder/history evidence and cannot authorize fresh execution.
func testCurrentSingleParentOutputSource(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("WARPMETAL_SINGLE_OUTPUT_SOURCE"))
	var packet struct {
		Policy      qualification.ChildEnvelope[qualification.ControllerPolicy]
		Activation  qualification.ChildEnvelope[qualification.ControllerActivation]
		Operation   json.RawMessage
		Request     model.ControllerOutputOperationRequest
		Proof       model.ControllerOutputEnvelope
		Receipt     json.RawMessage
		Handle      model.IntentHandle
		Declaration struct {
			Payload struct {
				Inputs []qualification.ControllerDeclaredInput
			}
		}
	}
	if err != nil || json.Unmarshal(raw, &packet) != nil {
		t.Fatal("original parent output SOURCE packet", err)
	}
	var original struct {
		OperationID string                               `json:"operationId"`
		Context     model.ControllerApprovedInputContext `json:"context"`
	}
	if json.Unmarshal(packet.Operation, &original) != nil || packet.Policy.Payload.FormatVersion != 6 || packet.Activation.Payload.FormatVersion != 4 || original.Context.FormatVersion != 4 || packet.Policy.Payload.ValidateContext(original.Context) != nil {
		t.Fatal("current signed policy/context source join")
	}
	prepared := packet.Activation.Payload.Admission.PreparedReceipt
	if prepared.Validate() == nil || prepared.ValidateProvider(packet.Policy.Payload.ProviderPolicyDigest) != nil || prepared.PreparedTuple.ValidateControllerPolicyIdentity(packet.Policy.Payload.NativeIdentity()) != nil {
		t.Fatal("legacy executable receipt rule or paired native identity changed")
	}
	if os.Getenv("WARPMETAL_SINGLE_DECLARATION_GATE") == "1" {
		matched := 0
		for _, item := range packet.Declaration.Payload.Inputs {
			if model.WorkspaceDigest(item) == original.Context.DeclarationItemDigest {
				matched++
				if !item.MatchesContext(original.Context) {
					t.Fatal("current declaration4 does not match independently returned context4")
				}
			}
		}
		if matched != 1 {
			t.Fatal("original single declaration item missing")
		}
	}
	var preparedOriginal *model.ControllerPreparedEnvelope
	if source := os.Getenv("WARPMETAL_SINGLE_PREPARED_SOURCE"); source != "" {
		body, e := os.ReadFile(source)
		var original struct {
			PreparedEnvelope model.ControllerPreparedEnvelope `json:"preparedEnvelope"`
		}
		if e != nil || json.Unmarshal(body, &original) != nil || model.WorkspaceDigest(original.PreparedEnvelope.Payload) != model.WorkspaceDigest(prepared) {
			t.Fatal("same-lane original prepared envelope", e)
		}
		preparedOriginal = &original.PreparedEnvelope
	}
	ctx := context.Background()
	store, err := state.Open(filepath.Join(t.TempDir(), "controller-source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for stage, value := range map[state.ControllerActivityStage]json.RawMessage{state.ControllerOutputOperation: packet.Operation, state.ControllerActionReceipt: packet.Receipt} {
		if err = store.PinControllerActivityStage(ctx, prepared.PreparationID, stage, value); err != nil {
			t.Fatal("retain original parent output", err)
		}
	}
	proofBytes, _ := json.Marshal(packet.Proof)
	if err = store.PinControllerActivityStage(ctx, prepared.PreparationID, state.ControllerOutputEnvelope, proofBytes); err != nil {
		t.Fatal("retain original signed proof", err)
	}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer rtn_source" || (r.URL.Path != "/internal/runtime/workspace-workflow/controller-preparations/"+prepared.PreparationID+"/receipts" && r.Header.Get("X-WarpMetal-Workflow-Lease") != "wfl_source_single") {
			t.Error("parent output transport lost owner authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/internal/runtime/workspace-workflow/controller-output-operations/"+original.OperationID:
			_, _ = w.Write(packet.Operation)
		case r.Method == "GET" && r.URL.Path == "/internal/runtime/workspace-workflow/manager-intents/"+packet.Handle.HandleID:
			_ = json.NewEncoder(w).Encode(packet.Handle)
		case preparedOriginal != nil && r.Method == "POST" && r.URL.Path == "/internal/runtime/workspace-workflow/controller-preparations/"+prepared.PreparationID+"/receipts":
			var body model.ControllerPreparedEnvelope
			if json.NewDecoder(r.Body).Decode(&body) != nil || model.WorkspaceDigest(body) != model.WorkspaceDigest(preparedOriginal) || r.Header.Get("Idempotency-Key") != prepared.PreparationID {
				t.Error("original prepared envelope changed")
			}
			_ = json.NewEncoder(w).Encode(prepared)
		case r.Method == "POST" && r.URL.Path == "/internal/runtime/workspace-workflow/controller-output-operations":
			var body json.RawMessage
			if json.NewDecoder(r.Body).Decode(&body) != nil || model.WorkspaceDigest(body) != model.WorkspaceDigest(packet.Request) || r.Header.Get("Idempotency-Key") != packet.Request.RequestID {
				t.Error("original output request changed")
			}
			_, _ = w.Write(packet.Operation)
		case r.Method == "POST" && r.URL.Path == "/internal/runtime/workspace-workflow/controller-output-operations/"+original.OperationID+"/actions":
			var proof model.ControllerOutputEnvelope
			if json.NewDecoder(r.Body).Decode(&proof) != nil || model.WorkspaceDigest(proof) != model.WorkspaceDigest(packet.Proof) {
				t.Error("original signed proof changed")
			}
			_, _ = w.Write(packet.Receipt)
		default:
			t.Error("unexpected parent output transport")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client := api.Client{Origin: server.URL, NodeToken: "rtn_source", HTTP: server.Client()}
	op, err := client.ControllerOutputOperation(ctx, original.OperationID, "wfl_source_single")
	if err != nil {
		t.Fatal("actual output4 client rejects current original", err)
	}
	if model.WorkspaceDigest(op) != model.WorkspaceDigest(packet.Operation) {
		t.Fatal("output4 signed application/native fields lost")
	}
	authorized, err := client.AuthorizeControllerOutput(ctx, packet.Request, "wfl_source_single")
	if err != nil || model.WorkspaceDigest(authorized) != model.WorkspaceDigest(op) {
		t.Fatal("original output4 request/operation", err)
	}
	receipt, err := client.SubmitControllerOutputAction(ctx, packet.Proof, "wfl_source_single")
	if err != nil || model.WorkspaceDigest(receipt) != model.WorkspaceDigest(packet.Receipt) || calls != 3 {
		t.Fatal("original output proof/receipt2 transport", err)
	}
	r := &Reconciler{Store: store, ManagedControl: client}
	_, _, _, selected, handle, err := r.acceptedManagerChild(ctx, prepared.PreparationID, "member", "wfl_source_single")
	expires, _ := time.Parse(time.RFC3339Nano, packet.Handle.NotAfter)
	if calls != 4 || selected.Ref != packet.Handle.Intent {
		t.Fatal("normal accepted single member did not reach exact handle", err)
	}
	if time.Now().Before(expires) {
		if err != nil || handle != packet.Handle {
			t.Fatal("current single handle join", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "manager intent current association conflict") {
		t.Fatal("expired original gained current authority", err)
	}
	if _, _, _, _, _, err = r.acceptedManagerChild(ctx, prepared.PreparationID, "second", "wfl_source_single"); err == nil || calls != 4 {
		t.Fatal("single receipt supplied a second child")
	}
	if preparedOriginal != nil {
		ack, e := client.SubmitControllerPreparedReceipt(ctx, *preparedOriginal)
		if e != nil || model.WorkspaceDigest(ack) != model.WorkspaceDigest(prepared) || calls != 5 {
			t.Fatal("current paired native receipt1 transport", e)
		}
	}
	t.Log("SOURCE TLS/SQLite original retention and Policy6/native receipt1/context4/output4/single member; expiry preserved; no native execution or fresh child authority")
}

// The backend's retained activation-intent GET is the only signing-basis input.
// This offline consumer gate never derives a basis from the signed activation,
// re-signs a body, changes signed times, or grants current execution authority.
func testCurrentParentOperatorDeliverySource(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("WARPMETAL_PARENT_OPERATOR_SOURCE"))
	var packet struct {
		Policy      qualification.ControllerPolicy      `json:"policy"`
		Context     []json.RawMessage                   `json:"context"`
		Intent      []json.RawMessage                   `json:"activationIntentResponse"`
		Prepared    model.ControllerPreparedEnvelope    `json:"preparedEnvelope"`
		Grant       model.ControllerGrantEnvelope       `json:"grant_envelope"`
		Publication api.ControllerActivationPublication `json:"activation_body"`
	}
	if err != nil || json.Unmarshal(raw, &packet) != nil || len(packet.Context) != 3 || len(packet.Intent) != 3 || string(packet.Intent[0]) != "200" || string(packet.Context[0]) != "200" {
		t.Fatal("original backend activation-intent SOURCE packet", err)
	}
	var current model.ControllerApprovedInputContext
	if json.Unmarshal(packet.Context[1], &current) != nil || current.FormatVersion != 4 || packet.Policy.FormatVersion != 6 || packet.Policy.ValidateContext(current) != nil || packet.Policy.ValidatePreparedReceipt(packet.Prepared.Payload) != nil {
		t.Fatal("same-lane current policy/context/prepared authority")
	}
	a := packet.Publication.Activation.Payload
	header := packet.Publication.HeaderObservation.Payload
	if a.FormatVersion != 4 || !reflect.DeepEqual(a.Admission.PreparedReceipt, packet.Prepared.Payload) || a.Admission.Grant != packet.Grant.Payload || a.GrantEnvelopeDigest != model.WorkspaceDigest(packet.Grant) || header.PreparationID != packet.Prepared.Payload.PreparationID || header.PreparedReceiptDigest != packet.Prepared.Payload.PreparedReceiptDigest || header.AuthorizationSHA256 != a.AuthorizationSHA256 {
		t.Fatal("same-lane activation/grant/independent header join")
	}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/internal/runtime/workspace-workflow/controller-preparations/"+packet.Prepared.Payload.PreparationID+"/activation-intent" || r.Header.Get("Authorization") != "Bearer rtn_source" {
			t.Error("activation-intent transport authority drift")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(packet.Intent[1])
	}))
	defer server.Close()
	client := api.Client{Origin: server.URL, NodeToken: "rtn_source", HTTP: server.Client()}
	intent, err := client.ControllerActivationIntent(context.Background(), packet.Prepared.Payload.PreparationID)
	if err != nil || calls != 1 || model.WorkspaceDigest(intent) != model.WorkspaceDigest(packet.Intent[1]) {
		t.Fatal("original activation-intent4 TLS consumer", err)
	}
	at, err := time.Parse(time.RFC3339Nano, a.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := qualification.ControllerActivationFromSigningBasis(intent.PayloadBasis, intent.NotBefore, header.AuthorizationSHA256, packet.Policy, current, at)
	if err != nil {
		t.Fatal("actual basis4 rejected under same-lane Policy6/context4", err)
	}
	// The backend commits an earliest signing time; the separate operator may
	// sign later. Compare every other field without rewriting either original.
	var expectedFields, joinedFields map[string]json.RawMessage
	expectedBytes, _ := json.Marshal(a)
	joinedBytes, _ := json.Marshal(joined)
	_ = json.Unmarshal(expectedBytes, &expectedFields)
	_ = json.Unmarshal(joinedBytes, &joinedFields)
	delete(expectedFields, "issuedAt")
	delete(joinedFields, "issuedAt")
	earliest, timeErr := time.Parse(time.RFC3339Nano, intent.NotBefore)
	if timeErr != nil || earliest.After(at) || joined.IssuedAt != intent.NotBefore || model.WorkspaceDigest(expectedFields) != model.WorkspaceDigest(joinedFields) {
		t.Fatal("signing basis changed fields outside independent operator issuedAt")
	}
	expired, err := time.Parse(time.RFC3339Nano, packet.Policy.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = qualification.ControllerActivationFromSigningBasis(intent.PayloadBasis, intent.NotBefore, header.AuthorizationSHA256, packet.Policy, current, expired.Add(time.Second)); err == nil {
		t.Fatal("expired original signing basis gained current authority")
	}
	var wrong map[string]json.RawMessage
	if json.Unmarshal(intent.PayloadBasis, &wrong) != nil {
		t.Fatal("basis shape")
	}
	wrong["identityAssociationDigest"], _ = json.Marshal(model.WorkspaceDigest("foreign association"))
	changed, _ := model.WorkspaceCanonicalJSON(wrong)
	if _, err = qualification.ControllerActivationFromSigningBasis(changed, intent.NotBefore, header.AuthorizationSHA256, packet.Policy, current, at); err == nil {
		t.Fatal("foreign application/native association accepted")
	}
	t.Log("SOURCE actual TLS original basis4 joins unchanged Policy6/context4/receipt1/grant/header; expiry and foreign association refused; no root signer or native execution")
}

// Only successful original HTTP responses are replayed as transport suppliers.
// Failed child acceptance rows never become policy or publication authority.
type childIssuerHTTPOriginal struct {
	Method, Path      string
	Status            int
	Request, Response json.RawMessage
}

func testCurrentChildIssuerSource(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("WARPMETAL_CHILD_ISSUER_SOURCE"))
	var rows []childIssuerHTTPOriginal
	if err != nil || json.Unmarshal(raw, &rows) != nil {
		t.Fatal("actual child issuer originals", err)
	}
	var handle model.IntentHandle
	var intent json.RawMessage
	path := ""
	replays := 0
	for _, row := range rows {
		if row.Method != "GET" || row.Status != 200 {
			continue
		}
		if strings.HasSuffix(row.Path, "/preparation-policy-intent") {
			if intent == nil {
				intent = row.Response
				path = row.Path
			} else if model.WorkspaceDigest(intent) != model.WorkspaceDigest(row.Response) {
				t.Fatal("backend original replay changed")
			}
			replays++
		} else {
			var candidate model.IntentHandle
			if model.DecodeManagerContract("intentHandle", row.Response, &candidate) == nil && row.Path == "/internal/runtime/workspace-workflow/manager-intents/"+candidate.HandleID {
				handle = candidate
			}
		}
	}
	if handle.HandleID == "" || path != "/internal/runtime/workspace-workflow/manager-intents/"+handle.HandleID+"/preparation-policy-intent" || intent == nil || replays < 2 {
		t.Fatal("successful child intent/replay originals missing")
	}
	calls := 0
	served := intent
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != path || r.Header.Get("Authorization") != "Bearer rtn_source" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "wfl_source_child" {
			t.Error("child intent owner transport drift")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(served)
	}))
	defer server.Close()
	client := api.Client{Origin: server.URL, NodeToken: "rtn_source", HTTP: server.Client()}
	for i := 0; i < 2; i++ {
		got, e := client.ManagerChildPolicyIntent(context.Background(), handle, "prepare", "wfl_source_child")
		if e != nil || model.WorkspaceDigest(got) != model.WorkspaceDigest(intent) {
			t.Fatal("actual child policySigningIntent2 consumer", e)
		}
	}
	if calls != 2 {
		t.Fatal("child intent replay effect count")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(intent, &fields)
	fields["extraAuthority"] = json.RawMessage(`true`)
	unknown, _ := json.Marshal(fields)
	delete(fields, "extraAuthority")
	fields["formatVersion"] = json.RawMessage(`3`)
	unsupported, _ := json.Marshal(fields)
	duplicate := append([]byte(`{"formatVersion":2,`), []byte(strings.TrimSpace(string(intent)))[1:]...)
	for _, malformed := range [][]byte{unknown, unsupported, duplicate} {
		served = malformed
		if _, e := client.ManagerChildPolicyIntent(context.Background(), handle, "prepare", "wfl_source_child"); e == nil {
			t.Fatal("ambiguous or unsupported child intent gained authority")
		}
	}
	t.Log("SOURCE actual TLS original child preparation-policy intent2/replay; failed acceptance excluded, no signed publication or execution claim")
	testSuccessfulChildIssuerOriginals(t, handle, rows)
}
