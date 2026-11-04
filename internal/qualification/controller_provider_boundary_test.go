package qualification_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// Extends the signed source export through the existing immutable Store. Only
// ancestor ownership uses the existing test-build supplier; signatures, payload
// ownership/modes, first-byte files and A/N/current witness joins remain real.
func TestControllerProviderSignedStoreBoundary(t *testing.T) {
	if path := os.Getenv("WARPMETAL_ADVISORY_NATIVE_SOURCE"); path != "" {
		t.Run("advisory_native_original", func(t *testing.T) { checkAdvisoryNativeOriginal(t, path) })
	}
	if path := os.Getenv("WARPMETAL_CONTROLLER_STAGE_SOURCE"); path != "" {
		t.Run("current_stage_original", func(t *testing.T) { qualification.CheckControllerStagePublicSourceForTest(t, path) })
	}
	if legacy := os.Getenv("WARPMETAL_OPERATOR_LEGACY_SOURCE"); legacy != "" {
		t.Run("public_operator_delivery", func(t *testing.T) {
			qualification.CheckControllerPublicDeliverySourceForTest(t, legacy, os.Getenv("WARPMETAL_OPERATOR_CURRENT_SOURCE"), os.Getenv("WARPMETAL_OPERATOR_SOURCE_EVIDENCE"))
		})
	}
	path := os.Getenv("WARPMETAL_CONTROLLER_PROVIDER_PACKET")
	if path == "" {
		t.Skip("fresh SOURCE signed controller packet required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var packet struct {
		AuthoritySynthetic bool                                `json:"authoritySynthetic"`
		LiveAuthorized     bool                                `json:"liveAuthorized"`
		Application        model.WorkspaceApplicationOperation `json:"application"`
		Authority          json.RawMessage                     `json:"authority"`
		Parents            map[string]struct {
			Context json.RawMessage `json:"context"`
			Policy  struct {
				Payload json.RawMessage `json:"payload"`
			} `json:"policy"`
			Prepared   model.ControllerPreparedReceipt `json:"prepared"`
			Activation struct {
				Payload struct {
					IssuedAt string `json:"issuedAt"`
				} `json:"payload"`
			} `json:"activation"`
		} `json:"parents"`
	}
	if err := json.Unmarshal(raw, &packet); err != nil || !packet.AuthoritySynthetic || packet.LiveAuthorized {
		t.Fatal("SOURCE packet decode", err)
	}
	store := qualification.SourceBoundaryStoreForTest(filepath.Join(filepath.Dir(path), "store"), uint32(os.Getuid()))
	for role, original := range packet.Parents {
		var selected qualification.ControllerPolicy
		if err := json.Unmarshal(original.Policy.Payload, &selected); err != nil {
			t.Fatal("signed Policy6 decoder", err)
		}
		var shape struct {
			IdentityAssociation model.ControllerIdentityAssociation `json:"identityAssociation"`
			Applicability       qualification.Applicability         `json:"applicability"`
		}
		if err := json.Unmarshal(original.Policy.Payload, &shape); err != nil {
			t.Fatal(err)
		}
		a := shape.IdentityAssociation
		// Explicit SOURCE installed content closure; the independently accepted
		// operation is distinct from the applicability engine setup recipe.
		if err := a.ValidateAccepted(packet.Application, a.Application.ApplicationID, a.Application.ReceiptDigest, packet.Application.MaterializerDigest, a.NativeIdentity); err != nil {
			t.Fatal("SOURCE accepted application", err)
		}
		w := qualification.ControllerPolicyWitness{Applicability: shape.Applicability, Identity: a.ApplicationIdentity, Application: qualification.ControllerApplication{OperationID: a.Application.OperationID, OperationDigest: a.Application.OperationDigest, ApplicationID: a.Application.ApplicationID, ReceiptDigest: a.Application.ReceiptDigest}, ApplicationConfigurationDigest: packet.Application.ConfigurationDigest, WorkspaceMaterializerDigest: packet.Application.MaterializerDigest}
		qualification.CheckControllerFirstTaskProviderSourceForTest(t, packet.Authority, selected, w)
		box := model.Sandbox{ID: shape.Applicability.SandboxID, Generation: shape.Applicability.SandboxGeneration, Cell: true}
		// Freeze this offline source test at its original creation time; never edit
		// expired signed times or claim that an expired packet can execute now.
		at, err := time.Parse(time.RFC3339Nano, original.Activation.Payload.IssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		p, err := store.ReadControllerPolicy(box, model.WorkspaceDigest(original.Policy.Payload), w, at)
		if err != nil {
			t.Fatal(role, "signed Policy6 Store", err)
		}
		wrongClosure := w
		wrongClosure.WorkspaceMaterializerDigest = p.Applicability.Profile.MaterializerDigest
		if _, e := store.ReadControllerPolicy(box, model.WorkspaceDigest(original.Policy.Payload), wrongClosure, at); e == nil {
			t.Fatal("engine setup recipe became independent workspace-content closure")
		}
		if _, err = store.ReadControllerActivation(box, p, original.Prepared, at); err != nil {
			t.Fatal(role, "signed Activation4 Store", err)
		}
		var current model.ControllerApprovedInputContext
		if err := json.Unmarshal(original.Context, &current); err != nil {
			t.Fatal("signed Context3 decoder", err)
		}
		if err := p.ValidateContext(current); err != nil {
			t.Fatal("signed Policy6 Context3 join", err)
		}
		// Actual TLS client boundary; backend preparation is a named SOURCE
		// supplier. Its tuple is the signed N, never the raw application's A.
		calls := 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {
			calls++
			var call map[string]any
			if request.Method != "POST" || request.URL.Path != "/internal/runtime/workspace-workflow/controller-preparations" || request.Header.Get("Authorization") != "Bearer source-node" || json.NewDecoder(request.Body).Decode(&call) != nil || call["providerPolicyDigest"] != p.ProviderPolicyDigest {
				t.Error("closed SOURCE preparation request drift")
				rw.WriteHeader(400)
				return
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{"formatVersion": 2, "preparationId": original.Prepared.PreparationID, "state": "native_admission_pending", "preparedTuple": original.Prepared.PreparedTuple, "applicationRoleAgentDigest": a.ApplicationIdentity.Intent.RoleAgentDigest, "applicationConfigDigest": a.ApplicationIdentity.Intent.ConfigDigest, "identityAssociationDigest": a.AssociationDigest})
		}))
		client := api.Client{Origin: server.URL, NodeToken: "source-node", HTTP: server.Client()}
		requestBytes, _ := json.Marshal(map[string]any{"formatVersion": 2, "requestId": "source_prepare_" + role, "serviceRegistrationId": a.ApplicationIdentity.Intent.ServiceRegistrationID, "inputId": original.Prepared.PreparedTuple.InputID, "inputDigest": original.Prepared.PreparedTuple.InputDigest, "modelSelection": a.ApplicationIdentity.Projection.ModelSelection, "providerPolicyDigest": p.ProviderPolicyDigest})
		var call api.ControllerPreparationRequest
		if err := json.Unmarshal(requestBytes, &call); err != nil {
			t.Fatal(err)
		}
		result, err := client.PrepareControllerActivity(context.Background(), call)
		server.Close()
		if err != nil || calls != 1 || result.PreparedTuple == nil || model.WorkspaceDigest(result.PreparedTuple) != model.WorkspaceDigest(original.Prepared.PreparedTuple) {
			t.Fatal("SOURCE preparation2 TLS boundary", err, "calls", calls)
		}
		wrong := w
		wrong.Identity.Source.Source.NativeSessionID = "ses_wrong_source"
		if _, err = store.ReadControllerPolicy(box, model.WorkspaceDigest(original.Policy.Payload), wrong, at); err == nil {
			t.Fatal("borrowed current session accepted")
		}
		if base := os.Getenv("WARPMETAL_CONTROLLER_HISTORY_SOURCE_EVIDENCE"); base != "" {
			end, e := time.Parse(time.RFC3339Nano, p.ExpiresAt)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = store.ReadControllerPolicy(box, model.WorkspaceDigest(original.Policy.Payload), w, end.Add(time.Second)); e == nil {
				t.Fatal("expired policy admitted for a new effect")
			}
			if e = os.MkdirAll(base, 0700); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(base, "controller-history-"+role+".db")
			// Retained predecessor schema and raw SOURCE rows, including the
			// no-ACK dispatch fence. These are storage specimens, not new authority.
			legacy, e := sql.Open("sqlite", path)
			if e != nil {
				t.Fatal(e)
			}
			_, e = legacy.Exec(`CREATE TABLE IF NOT EXISTS controller_activity_journal (
 preparation_id TEXT NOT NULL,
 stage TEXT NOT NULL CHECK(stage IN ('approved-context','installed-applicability','native-prepared','header-observed','grant-original','activated','prompt-dispatch','output-operation','output-envelope','action-receipt')),
 data_json BLOB NOT NULL, PRIMARY KEY(preparation_id,stage));`)
			if e != nil {
				legacy.Close()
				t.Fatal(e)
			}
			preparedBytes, _ := model.WorkspaceCanonicalJSON(original.Prepared)
			legacyRows := map[string][]byte{"approved-context": original.Context, "native-prepared": preparedBytes, "activated": []byte(`{"source":"predecessor activation original"}`), "prompt-dispatch": []byte(`{"dispatched":true}`)}
			for stage, value := range legacyRows {
				if _, e = legacy.Exec(`INSERT INTO controller_activity_journal(preparation_id,stage,data_json) VALUES(?,?,?) ON CONFLICT(preparation_id,stage) DO NOTHING`, original.Prepared.PreparationID, stage, value); e != nil {
					legacy.Close()
					t.Fatal(e)
				}
			}
			legacy.Close()
			journal, e := state.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			ctx := context.Background()
			for stage, expected := range legacyRows {
				value, err := journal.ControllerActivityStage(ctx, original.Prepared.PreparationID, state.ControllerActivityStage(stage))
				if err != nil || string(value) != string(expected) {
					journal.Close()
					t.Fatal("predecessor byte/fence migration changed", stage, err)
				}
			}
			if e = journal.FenceControllerActivityPrompt(ctx, original.Prepared.PreparationID); e == nil {
				journal.Close()
				t.Fatal("unknown predecessor dispatch reissued")
			}
			if e = journal.PinControllerActivityStage(ctx, original.Prepared.PreparationID, state.ControllerApprovedContext, original.Context); e != nil {
				t.Fatal(e)
			}
			// The first red creates the predecessor CHECK/table and original bytes;
			// the same retained database exercises the scoped stage migration.
			stage := state.ControllerActivityStage("verified-policy")
			policyBytes, _ := model.WorkspaceCanonicalJSON(p)
			e = journal.PinControllerActivityStage(ctx, original.Prepared.PreparationID, stage, policyBytes)
			if e != nil {
				journal.Close()
				t.Fatal("verified policy history stage refused", e)
			}
			if e = journal.Close(); e != nil {
				t.Fatal(e)
			}
			journal, e = state.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			history, e := journal.ControllerActivityStage(ctx, original.Prepared.PreparationID, stage)
			var retained qualification.ControllerPolicy
			if e != nil || json.Unmarshal(history, &retained) != nil || model.WorkspaceDigest(json.RawMessage(history)) != current.PolicyDigest || retained.ValidateContext(current) != nil || retained.ValidatePreparedReceipt(original.Prepared) != nil || retained.IdentityAssociation.ValidateAccepted(packet.Application, a.Application.ApplicationID, a.Application.ReceiptDigest, packet.Application.MaterializerDigest, a.NativeIdentity) != nil {
				journal.Close()
				t.Fatal("expired read-only history lost original A/N/context joins", e)
			}
			retained.Applicability.Runtime.Version = "mutated"
			changed, _ := model.WorkspaceCanonicalJSON(retained)
			if e = journal.PinControllerActivityStage(ctx, original.Prepared.PreparationID, stage, changed); e == nil {
				journal.Close()
				t.Fatal("verified history replaced")
			}
			prior, e := journal.ControllerActivityStage(ctx, original.Prepared.PreparationID, state.ControllerApprovedContext)
			journal.Close()
			if e != nil || string(prior) != string(original.Context) {
				t.Fatal("prior context bytes changed during stage migration")
			}
			t.Log(role, "SOURCE read-only history survives policy expiry/reopen with original A/N joins; fresh effect still denied")
		}
		t.Log(role, "real signed Store policy and activation selected; borrowed session refused; SOURCE clock frozen")
	}
}

// The draft supplies public SOURCE originals only. This checks the unchanged
// native normalization/identity boundary, not Policy7 admission or ROOT custody.
func checkAdvisoryNativeOriginal(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	var packet struct {
		Classification string `json:"classification"`
		Policy         struct {
			FormatVersion       int                                 `json:"formatVersion"`
			IdentityAssociation model.ControllerIdentityAssociation `json:"identityAssociation"`
		} `json:"policy"`
		InputText      string                               `json:"inputText"`
		NativeReadback model.ControllerOutputNativeReadback `json:"nativeReadback"`
		Lineage        model.ControllerOutputLineage        `json:"lineage"`
	}
	if err != nil || json.Unmarshal(raw, &packet) != nil || packet.Classification == "" || packet.Policy.FormatVersion != 7 {
		t.Fatal("advisory public SOURCE packet", err)
	}
	a := packet.Policy.IdentityAssociation
	if err = a.ValidateIntegrity(); err != nil {
		t.Fatal("advisory A7/N6 original pair", err)
	}
	n := packet.NativeReadback.Data.ControllerOutput
	var observed model.ControllerIdentity
	if json.Unmarshal(n.Identity, &observed) != nil || !reflect.DeepEqual(observed, a.NativeIdentity) || n.Admission.PreparedReceipt.PreparedTuple.ValidateControllerPolicyIdentity(observed) != nil {
		t.Fatal("exact original native identity is not the policy association N6")
	}
	lineage, err := packet.NativeReadback.Normalize(packet.InputText)
	if err != nil || !reflect.DeepEqual(lineage, packet.Lineage) {
		t.Fatal("advisory native original normalization", err)
	}
	changed := packet.NativeReadback
	changed.Data.ControllerOutput.Output.Text += " changed"
	if _, err = changed.Normalize(packet.InputText); err == nil {
		t.Fatal("changed native terminal bytes borrowed the original output digest")
	}
	if err = n.Admission.PreparedReceipt.PreparedTuple.ValidateControllerPolicyIdentity(a.ApplicationIdentity); err == nil {
		t.Fatal("application A7 substituted for exact native N6")
	}
	t.Log("SOURCE advisory original: exact N6/lineage PASS; changed text digest and A7 substitution denied; no Policy7 admission/ROOT/native/provider claim")
}
