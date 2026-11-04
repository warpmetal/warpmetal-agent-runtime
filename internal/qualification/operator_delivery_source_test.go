package qualification

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

// This test-only adapter invokes the SAME public-original validators after an
// explicit SOURCE metadata boundary. It cannot read private Producer paths,
// construct a Producer, sign, publish, or grant execution authority.
func CheckControllerPublicDeliverySourceForTest(t *testing.T, legacy, current, evidence string) {
	t.Helper()
	type specimen struct {
		policy            ControllerPolicy
		prepared          model.ControllerPreparedReceipt
		context           model.ControllerApprovedInputContext
		grant, activation json.RawMessage
		public, authority []byte
		producer          model.WorkspaceRegisteredProducer
	}
	var examples []specimen
	if legacy != "" {
		var p struct {
			Application       model.WorkspaceApplicationOperation
			OperatorPublicPEM []byte
			Parents           map[string]struct {
				Policy            ChildEnvelope[ControllerPolicy]
				Prepared          model.ControllerPreparedReceipt
				Context           model.ControllerApprovedInputContext
				Grant, Activation json.RawMessage
			}
		}
		raw, err := os.ReadFile(legacy)
		if err != nil || json.Unmarshal(raw, &p) != nil {
			t.Fatal("retained legacy public originals", err)
		}
		anchor, err := os.ReadFile(filepath.Join(filepath.Dir(legacy), "evidence", "physical-gate-authority.json"))
		if err != nil {
			t.Fatal(err)
		}
		v := p.Parents["manager"]
		examples = append(examples, specimen{v.Policy.Payload, v.Prepared, v.Context, v.Grant, v.Activation, p.OperatorPublicPEM, anchor, p.Application.Producer})
	}
	if current != "" {
		var p struct {
			Policy      ControllerPolicy
			Prepared    model.ControllerPreparedEnvelope `json:"preparedEnvelope"`
			Context     []json.RawMessage
			Grant       json.RawMessage                      `json:"grant_envelope"`
			Publication struct{ Activation json.RawMessage } `json:"activation_body"`
			Application model.WorkspaceApplicationOperation
		}
		raw, err := os.ReadFile(current)
		if err != nil || json.Unmarshal(raw, &p) != nil || len(p.Context) != 3 {
			t.Fatal("actual backend public originals", err)
		}
		var c model.ControllerApprovedInputContext
		if json.Unmarshal(p.Context[1], &c) != nil {
			t.Fatal("actual context4")
		}
		anchor, err := os.ReadFile(filepath.Join(filepath.Dir(current), "q43-authority.json"))
		if err != nil {
			t.Fatal(err)
		}
		public, err := os.ReadFile(filepath.Join(filepath.Dir(current), "q43-operator-public.pem"))
		if err != nil {
			t.Fatal(err)
		}
		examples = append(examples, specimen{p.Policy, p.Prepared.Payload, c, p.Grant, p.Publication.Activation, public, anchor, p.Application.Producer})
	}
	for _, v := range examples {
		name := "legacy_authority2_policy5"
		if v.policy.FormatVersion == 6 {
			name = "current_authority3_policy6"
		}
		t.Run(name, func(t *testing.T) {
			root, err := os.MkdirTemp(evidence, "operator-public-source-")
			if err != nil {
				t.Fatal(err)
			}
			s := SourceBoundaryStoreForTest(root, uint32(os.Getuid()))
			box := model.Sandbox{ID: v.prepared.PreparedTuple.Owner.SandboxID, Generation: v.prepared.PreparedTuple.Owner.SandboxGeneration}
			tree, key, err := s.Paths(box.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.MkdirAll(tree, 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.MkdirAll(filepath.Dir(key), 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(key, v.public, 0400); err != nil {
				t.Fatal(err)
			}
			config := ProducerConfig{KeyID: v.producer.KeyID, KeySHA256: v.producer.KeySHA256, ServerID: v.producer.ServerID, NodeTokenHash: v.producer.NodeTokenHash}
			storeKey, err := s.read(key, tree, key, 4096)
			if err != nil {
				t.Fatal(err)
			}
			id, err := verifyOperatorDeliveryPin(config, v.policy.Case, v.authority, v.public, storeKey)
			if err != nil {
				t.Fatal("public delivery authority selector refused", err)
			}
			if err = controllerGrantDeliveryContext(box, v.policy, v.prepared, v.context); err != nil {
				t.Fatal("current policy native receipt grant selector refused", err)
			}
			if err = controllerActivationDeliveryContext(v.policy, v.prepared, v.context); err != nil {
				t.Fatal("current policy native receipt activation selector refused", err)
			}
			var original ChildEnvelope[ControllerActivation]
			if json.Unmarshal(v.activation, &original) != nil {
				t.Fatal("original activation")
			}
			at, err := time.Parse(time.RFC3339Nano, original.Payload.IssuedAt)
			if err != nil {
				t.Fatal(err)
			}
			for leaf, body := range map[string]json.RawMessage{"controller-activity-grant-" + v.prepared.PreparationID + ".json": v.grant, "controller-activation-envelope-" + v.prepared.PreparationID + ".json": v.activation} {
				if err = os.WriteFile(filepath.Join(tree, leaf), canonicalBytes(body), 0400); err != nil {
					t.Fatal(err)
				}
			}
			if err = os.Chmod(tree, 0500); err != nil {
				t.Fatal(err)
			}
			grantRaw, err := s.readExpectedPublicOriginal(box.ID, "controller-activity-grant-"+v.prepared.PreparationID+".json", 65536)
			if err != nil {
				t.Fatal(err)
			}
			grant, err := verifyControllerGrantDelivery(grantRaw, id, v.public, v.policy, v.prepared, v.context, at)
			if err != nil || CanonicalDigest(grant) != CanonicalDigest(v.grant) {
				t.Fatal("original signed grant delivery", err)
			}
			activationRaw, err := s.readExpectedPublicOriginal(box.ID, "controller-activation-envelope-"+v.prepared.PreparationID+".json", 131072)
			if err != nil {
				t.Fatal(err)
			}
			activation, err := verifyControllerActivationDelivery(activationRaw, id, v.public, v.policy, v.prepared, v.context, at)
			if err != nil || CanonicalDigest(activation) != CanonicalDigest(v.activation) {
				t.Fatal("original signed activation delivery", err)
			}
			wrong := config
			wrong.KeyID = id
			if _, err = verifyOperatorDeliveryPin(wrong, v.policy.Case, v.authority, v.public, storeKey); err == nil {
				t.Fatal("operator became producer")
			}
			if _, err = verifyControllerGrantDelivery(grantRaw, "wrong_operator", v.public, v.policy, v.prepared, v.context, at); err == nil {
				t.Fatal("envelope-selected independent signer accepted")
			}
			end, err := time.Parse(time.RFC3339Nano, v.policy.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = verifyControllerActivationDelivery(activationRaw, id, v.public, v.policy, v.prepared, v.context, end.Add(time.Second)); err == nil {
				t.Fatal("expired public activation accepted")
			}
			t.Log("SOURCE same validators, original signatures/public files and current policy joins; root custody detached", root)
			if v.policy.FormatVersion == 5 {
				facts := ChildProductAuthorityFacts{Case: v.policy.Case}
				class := childString(childFields(v.authority), "evidenceClass")
				// This retained parent SOURCE fixture intentionally has a
				// placeholder tuple inventory pin. Public delivery signatures
				// above pass, but it never supplied valid child financial facts.
				if err := validateChildFactFinancialAuthority(v.authority, facts, class, Digest(v.authority)); err == nil {
					t.Fatal("legacy malformed tuple inventory was admitted")
				}
			}
		})
	}
	if source := os.Getenv("WARPMETAL_FIRST_TASK_APPLICABILITY_SOURCE"); source != "" {
		t.Run("current_first_task_applicability", func(t *testing.T) {
			// Actual same-lane backend originals, never a case2 retag or a
			// fake CurrentPhysicalBaseline. The preceding public delivery
			// subtest verifies the unchanged operator signatures. This tests
			// only the closed inventory owner after that SOURCE boundary.
			var original struct {
				Application model.WorkspaceApplicationOperation
				Policy      ControllerPolicy
				Publication struct {
					Activation ChildEnvelope[ControllerActivation]
				} `json:"activation_body"`
			}
			raw, err := os.ReadFile(source)
			if err != nil || json.Unmarshal(raw, &original) != nil || original.Application.Validate() != nil || original.Policy.FormatVersion != 6 || original.Policy.IdentityAssociation == nil {
				t.Fatal("actual current accepted application/policy SOURCE originals", err)
			}
			p, app := original.Policy, original.Application
			a := p.IdentityAssociation
			// Explicit SOURCE installed workspace-content closure supplier,
			// obtained from the independently retained accepted application.
			// The qualification applicability profile pin is the DIFFERENT
			// engine setup recipe; it is not this installed closure argument.
			// Actual protected current closure measurement remains unproven.
			installedWorkspaceClosure := app.MaterializerDigest
			if a.ValidateAccepted(app, a.Application.ApplicationID, a.Application.ReceiptDigest, installedWorkspaceClosure, a.NativeIdentity) != nil {
				t.Fatal("actual accepted application A/N association")
			}
			anchor, err := os.ReadFile(filepath.Join(filepath.Dir(source), "q43-authority.json"))
			if err != nil || workflowcontract.Validate(workflowcontract.BudgetProvider, "authority3", anchor) != nil || !sameProduct(childFields(anchor)["case"], p.Case) || CanonicalDigest(childFields(anchor)["tupleInventory"]) != p.Case.TupleInventoryDigest {
				t.Fatal("actual authority3/current policy inventory pins", err)
			}
			public, err := os.ReadFile(filepath.Join(filepath.Dir(source), "q43-operator-public.pem"))
			config := ProducerConfig{KeyID: app.Producer.KeyID, KeySHA256: app.Producer.KeySHA256, ServerID: app.Producer.ServerID, NodeTokenHash: app.Producer.NodeTokenHash}
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifyOperatorDeliveryPin(config, p.Case, anchor, public, public)
			if err != nil {
				t.Fatal("actual independent operator/producer pin", err)
			}
			var inventory struct {
				Tuples []struct {
					Consumers []struct {
						SourceID, ConfigurationDigest string
						Profile                       model.ManagedServiceProfileV1
					}
				}
			}
			if json.Unmarshal(childFields(anchor)["tupleInventory"], &inventory) != nil {
				t.Fatal("actual current inventory shape")
			}
			seen, matching := map[string]bool{}, 0
			for _, tuple := range inventory.Tuples {
				for _, consumer := range tuple.Consumers {
					if seen[consumer.SourceID] {
						t.Fatal("canonical authority3 duplicate source consumer")
					}
					seen[consumer.SourceID] = true
					if consumer.SourceID == a.ApplicationIdentity.Intent.ServiceRegistrationID {
						matching++
						if consumer.ConfigurationDigest != app.ConfigurationDigest || consumer.ConfigurationDigest == a.ApplicationIdentity.Intent.ConfigDigest || consumer.ConfigurationDigest == a.NativeIdentity.Intent.ConfigDigest || consumer.Profile != a.ApplicationIdentity.Intent.Profile || consumer.Profile == a.NativeIdentity.Intent.Profile {
							t.Fatal("actual inventory did not distinguish workspace configuration/A profile from normalized N")
						}
					}
				}
			}
			if matching != 1 {
				t.Fatal("current parent must have one authoritative inventory consumer", matching)
			}
			w := ControllerPolicyWitness{Applicability: p.Applicability, Identity: a.ApplicationIdentity, Application: p.ApplicationReference(), ApplicationConfigurationDigest: app.ConfigurationDigest, WorkspaceMaterializerDigest: installedWorkspaceClosure}
			t.Log("actual authority3 + current accepted app/A7N6 verified; one unique parent consumer; workspace config differs from A/N; SOURCE filesystem/root only")
			selected, err := controllerApplicabilityFromInventory(childFields(anchor)["tupleInventory"], p.Case, w)
			if err != nil {
				t.Fatal("current inventory rejected actual workspace configuration / A-profile", err)
			}
			if sameProduct(selected, p.Applicability) || validateControllerFirstTaskApplicability(selected, p.Case, w) == nil {
				t.Fatal("historical synthetic tuple became current private installed applicability")
			}
			wrong := w
			wrong.ApplicationConfigurationDigest = a.ApplicationIdentity.Intent.ConfigDigest
			if _, err = controllerApplicabilityFromInventory(childFields(anchor)["tupleInventory"], p.Case, wrong); err == nil {
				t.Fatal("composed configuration substituted for accepted workspace configuration")
			}
			// Duplicate consumers remain forbidden even with a recomputed
			// SOURCE digest; allocation names cannot create a second service.
			var duplicate map[string]any
			_ = json.Unmarshal(childFields(anchor)["tupleInventory"], &duplicate)
			tuple := duplicate["tuples"].([]any)[0].(map[string]any)
			consumers := tuple["consumers"].([]any)
			tuple["consumers"] = append(consumers, consumers[0])
			badCase := p.Case
			badCase.TupleInventoryDigest = CanonicalDigest(duplicate)
			if _, err = controllerApplicabilityFromInventory(canonicalBytes(duplicate), badCase, w); err == nil {
				t.Fatal("duplicate inventory consumer admitted")
			}
			t.Log("actual inventory configuration/A-profile selection passes; wrong config/duplicate consumer denied; historical tuple remains unadmitted; no protected baseline")
		})
	}
	if source := os.Getenv("WARPMETAL_CHILD_FINANCIAL_SOURCE"); source != "" {
		t.Run("current_child_financial_authority3", func(t *testing.T) {
			raw, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			var rows []struct {
				Method, Path string
				Status       int
				Response     json.RawMessage
			}
			if json.Unmarshal(raw, &rows) != nil {
				t.Fatal("actual child HTTP originals")
			}
			anchor, err := os.ReadFile(filepath.Join(filepath.Dir(source), "q43-authority.json"))
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, row := range rows {
				if row.Method != "GET" || !strings.HasSuffix(row.Path, "/original-facts") || row.Status != 200 {
					continue
				}
				original, err := model.DecodeChildProductOriginalFacts(row.Response)
				if err != nil {
					t.Fatal("actual original facts framing", err)
				}
				a, installed, _, err := DecodeOriginalChildProductFacts(original)
				if err != nil {
					t.Fatal("actual original owner facts", err)
				}
				if a.Case.FormatVersion != 3 || installed.EvidenceClass != "source" {
					t.Fatal("wrong source financial specimen")
				}
				if err = validateChildFactFinancialAuthority(anchor, a, installed.EvidenceClass, installed.ConfigDigest); err != nil {
					t.Fatal("actual authority3 financial facts selector refused", err)
				}
				if validateChildFactFinancialAuthority(anchor, a, "live", installed.ConfigDigest) == nil || validateChildFactFinancialAuthority(anchor, a, installed.EvidenceClass, model.WorkspaceDigest("wrong-authority")) == nil {
					t.Fatal("authority provenance/config pin mismatch accepted")
				}
				wrong := a
				wrong.Case.ProviderPolicyDigest = model.WorkspaceDigest("foreign-provider")
				if validateChildFactFinancialAuthority(anchor, wrong, installed.EvidenceClass, installed.ConfigDigest) == nil {
					t.Fatal("foreign provider case accepted")
				}
				count++
			}
			if count != 2 {
				t.Fatal("missing actual prepare/execute original facts", count)
			}
			t.Log("actual same-lane authority3 + two original-facts bodies; public SOURCE selector only, no root custody")
		})
	}
}

// Test-only adapter for the existing external signed Store journey. This shares
// the actual selection/admission predicates without constructing a baseline.
func CheckControllerFirstTaskProviderSourceForTest(t *testing.T, authority json.RawMessage, p ControllerPolicy, w ControllerPolicyWitness) {
	t.Helper()
	inventory := childFields(authority)["tupleInventory"]
	app, err := controllerApplicabilityFromInventory(inventory, p.Case, w)
	if err != nil || !sameProduct(app, p.Applicability) || validateControllerFirstTaskApplicability(app, p.Case, w) != nil {
		t.Fatal("fresh current SOURCE inventory/applicability", err)
	}
	wrong := w
	wrong.ApplicationConfigurationDigest = w.Identity.Intent.ConfigDigest
	if _, err := controllerApplicabilityFromInventory(inventory, p.Case, wrong); err == nil {
		t.Fatal("fresh current composed configuration became workspace configuration")
	}
	changed := app
	changed.Runtime.Version = "0.1.52"
	if validateControllerFirstTaskApplicability(changed, p.Case, w) == nil {
		t.Fatal("current private candidate accepted legacy runtime version")
	}
	t.Log("fresh current private applicability SOURCE selector passes; protected baseline/self/installed custody not supplied")
}

// Reuses the public-original signature boundary. ROOT paths and process custody
// are not detached inside production; this adapter invokes only the pure owner
// verifier at the original SOURCE observation time.
func CheckControllerStagePublicSourceForTest(t *testing.T, path string) {
	t.Helper()
	var p struct {
		Case              RealCase
		Demand            ChildEnvelope[DemandManifest]
		OperatorPublicPEM []byte
		Parent            model.ControllerParentIntent
		Readout           model.ControllerStageReadout
		Declaration       json.RawMessage
		ObservedAt        string
	}
	raw, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(raw, &p) != nil {
		t.Fatal("current stage public SOURCE originals", e)
	}
	at, e := time.Parse(time.RFC3339Nano, p.ObservedAt)
	if e != nil {
		t.Fatal(e)
	}
	if verifyChildEnvelope(canonicalBytes(p.Demand), p.Demand.KeyID, p.OperatorPublicPEM) != nil {
		t.Fatal("current signed demand SOURCE original")
	}
	item, e := verifyControllerStageDeclaration(p.Declaration, p.OperatorPublicPEM, p.Case, p.Demand.Payload, p.Parent, p.Readout, at)
	if e != nil || CanonicalDigest(item) != p.Readout.DeclarationItemDigest {
		t.Fatal("current stage signed declaration selection", e)
	}
	wrong := p.Readout
	wrong.AllocationName = "manager_review"
	if _, e = verifyControllerStageDeclaration(p.Declaration, p.OperatorPublicPEM, p.Case, p.Demand.Payload, p.Parent, wrong, at); e == nil {
		t.Fatal("discovery metadata substituted signed allocation")
	}
	wrong = p.Readout
	wrong.Item = json.RawMessage(`{}`)
	wrong.DeclarationItemDigest = CanonicalDigest(wrong.Item)
	if _, e = verifyControllerStageDeclaration(p.Declaration, p.OperatorPublicPEM, p.Case, p.Demand.Payload, p.Parent, wrong, at); e == nil {
		t.Fatal("discovery metadata substituted signed item")
	}
	if _, e = verifyControllerStageDeclaration(p.Declaration, p.OperatorPublicPEM, p.Case, p.Demand.Payload, p.Parent, p.Readout, at.Add(2*time.Minute)); e == nil {
		t.Fatal("expired signed declaration granted a fresh effect")
	}
	t.Log("exact signed current declaration/demand + closed node readout; changed item/allocation and expiry denied; protected ROOT custody unverified")
}
