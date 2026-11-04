package reconcile

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Only successful, unchanged HTTP/PG producer originals enter these actual TLS
// consumers. Expired historical values are decoder evidence, never fresh grants.
func testSuccessfulChildIssuerOriginals(t *testing.T, handle model.IntentHandle, rows []childIssuerHTTPOriginal) {
	for _, row := range rows {
		if row.Status < 200 || row.Status >= 300 {
			continue
		}
		name := ""
		switch {
		case row.Method == "POST" && strings.HasSuffix(row.Path, "/product-policies"):
			var request struct{ Stage string }
			if json.Unmarshal(row.Request, &request) != nil {
				t.Fatal("actual policy accept request")
			}
			name = request.Stage + "-accept2"
		case row.Method == "POST" && strings.HasSuffix(row.Path, "/grant-intents"):
			name = "grant-intent2"
		case row.Method == "POST" && strings.HasSuffix(row.Path, "/activation-intents"):
			name = "activation-intent2"
		case row.Method == "POST" && strings.HasSuffix(row.Path, "/activations"):
			name = "activation-accept2"
		case row.Method == "GET" && strings.HasSuffix(row.Path, "/product-policy-intent"):
			name = "product-intent2"
		case row.Method == "GET" && strings.HasSuffix(row.Path, "/product-control"):
			var wire struct{ Descriptor struct{ Phase string } }
			if json.Unmarshal(row.Response, &wire) != nil {
				t.Fatal("actual control phase")
			}
			name = wire.Descriptor.Phase + "-control3"
		case row.Method == "GET" && strings.HasSuffix(row.Path, "/original-facts"):
			var wire struct{ Phase string }
			_ = json.Unmarshal(row.Response, &wire)
			name = wire.Phase + "-original-facts"
		case row.Method == "POST" && strings.HasSuffix(row.Path, "/preparation-control-publications"):
			name = "prepare-publication"
		case row.Method == "POST" && strings.HasSuffix(row.Path, "/product-control-publications"):
			name = "execute-publication"
		case row.Method == "POST" && strings.HasSuffix(row.Path, "/grants"):
			name = "admission"
		default:
			continue
		}
		t.Run(name, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				lease := "wfl_source_child"
				if strings.HasSuffix(name, "-control3") || strings.HasSuffix(name, "-original-facts") {
					lease = ""
				}
				if r.Method != row.Method || r.URL.Path != row.Path || r.Header.Get("Authorization") != "Bearer rtn_source" || r.Header.Get("X-WarpMetal-Workflow-Lease") != lease {
					t.Error("child original owning transport changed")
					w.WriteHeader(400)
					return
				}
				if r.Method == "POST" {
					var body json.RawMessage
					if json.NewDecoder(r.Body).Decode(&body) != nil || model.WorkspaceDigest(body) != model.WorkspaceDigest(row.Request) {
						t.Error("child signed request original changed")
						w.WriteHeader(400)
						return
					}
					var request struct{ RequestID string }
					_ = json.Unmarshal(body, &request)
					if r.Header.Get("Idempotency-Key") != request.RequestID {
						t.Error("child original request ID changed")
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(row.Status)
				_, _ = w.Write(row.Response)
			}))
			defer server.Close()
			client := api.Client{Origin: server.URL, NodeToken: "rtn_source", HTTP: server.Client()}
			var got json.RawMessage
			var err error
			switch name {
			case "prepare-accept2":
				got, err = client.AcceptManagerChildPreparationPolicy(context.Background(), handle, row.Request, "wfl_source_child")
			case "product-accept2":
				got, err = client.AcceptManagerChildProductPolicy(context.Background(), handle, row.Request, "wfl_source_child")
			case "product-intent2":
				got, err = client.ManagerChildPolicyIntent(context.Background(), handle, "product", "wfl_source_child")
			case "grant-intent2":
				var call model.IntentGrantRequest
				if json.Unmarshal(row.Request, &call) != nil {
					t.Fatal("actual grant call")
				}
				got, err = client.ManagerChildGrantIntent(context.Background(), handle, call, "wfl_source_child")
			case "activation-intent2":
				got, err = client.ManagerChildActivationIntent(context.Background(), handle, row.Request, "wfl_source_child")
			case "activation-accept2":
				got, err = client.AcceptManagerChildActivation(context.Background(), handle, row.Request, "wfl_source_child")
			case "prepare-control3", "execute-control3":
				parts := strings.Split(row.Path, "/")
				preparation := parts[len(parts)-2]
				var delivery model.ChildProductDelivery
				delivery, err = client.ChildProductControl(context.Background(), preparation)
				got = delivery.Bytes()
			case "prepare-original-facts", "execute-original-facts":
				parts := strings.Split(row.Path, "/")
				var facts model.ChildProductOriginalFacts
				facts, err = client.ChildProductFacts(context.Background(), parts[len(parts)-2])
				if err == nil {
					var a qualification.ChildProductAuthorityFacts
					var i qualification.ChildProductInstalledFacts
					var l qualification.ChildProductLifecycleFacts
					a, i, l, err = qualification.DecodeOriginalChildProductFacts(facts)
					got = fixtureRaw(map[string]any{"formatVersion": 1, "preparationId": facts.PreparationID(), "phase": facts.Phase(), "generationDigest": facts.GenerationDigest(), "authority": a, "installed": i, "lifecycle": l})
				}
			case "prepare-publication", "execute-publication":
				var receipt struct{ PreparationID, Phase string }
				_ = json.Unmarshal(row.Response, &receipt)
				got, err = client.PublishManagerChildControl(context.Background(), handle, receipt.PreparationID, receipt.Phase, row.Request, "wfl_source_child")
			case "admission":
				// Reuse only same-lane original association/assignment and request
				// fields. This is transport history, not fresh manager authority.
				var prepared model.ActualPreparationAssociation
				var assignment json.RawMessage
				for _, original := range rows {
					if original.Status < 200 || original.Status >= 300 {
						continue
					}
					if strings.HasSuffix(original.Path, "/prepared-association") {
						_ = json.Unmarshal(original.Response, &prepared)
					}
					if strings.HasSuffix(original.Path, "/workflow-assignment") {
						assignment = original.Response
					}
				}
				var request model.IntentGrantRequest
				var original model.ChildAdmissionAssociation
				if json.Unmarshal(row.Request, &request) != nil || json.Unmarshal(row.Response, &original) != nil {
					t.Fatal("actual admission originals")
				}
				selected := model.ManagerIntentSelection{Ref: handle.Intent, Owner: handle.Owner, AllocationID: handle.AllocationID, GrantRequestID: request.RequestID}
				var admission model.ChildAdmissionAssociation
				admission, err = client.GrantManagerIntent(context.Background(), handle, selected, prepared, assignment, request.ProductPolicyDigest, "wfl_source_child")
				got = fixtureRaw(admission)
			}
			if err != nil || model.WorkspaceDigest(got) != model.WorkspaceDigest(row.Response) {
				t.Fatal("successful backend child original consumer refused", err)
			}
			if calls != 1 {
				t.Fatal("child original unexpected transport retry", calls)
			}
		})
	}
}
