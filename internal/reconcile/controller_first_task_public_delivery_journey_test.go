package reconcile

// One extension of the existing owner journey. The separate ephemeral SOURCE
// operator supplies public files; Runtime never calls it. Protected reads,
// signatures, HTTP owning POSTs, SQLite fences and immutable exports are real.
// Prepared parent/output, qualification, native header/Authorization observations
// and backend commitment are named upstream SOURCE suppliers, not installed facts.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
)

type firstTaskDeliveryParent struct {
	prepared  model.ControllerPreparedReceipt
	context   model.ControllerApprovedInputContext
	text      string
	operation model.ControllerOutputOperation
	output    model.ControllerOutputEnvelope
	action    json.RawMessage
}
type firstTaskPublicDeliveryFixture struct {
	f                                                                 *firstTaskChildTerminalFixture
	root, tree, key, evidence                                         string
	store                                                             qualification.Store
	producer                                                          *qualification.Producer
	operator                                                          *ecdsa.PrivateKey // test manager custody ONLY, never a production config
	operatorPEM                                                       []byte
	app                                                               model.WorkspaceApplicationOperation
	native                                                            *parentSourceRuntime
	caseValue                                                         qualification.RealCase
	demand                                                            qualification.DemandManifest
	policies                                                          map[string]qualification.ControllerPolicy
	grants                                                            map[string]model.ControllerGrantEnvelope
	activations                                                       map[string]api.ControllerActivationEnvelope
	preparePayload, productPayload, bindingPayload, activationPayload json.RawMessage
	prepareRequest, productRequest, activationRequest                 json.RawMessage
	templates                                                         map[string]any
	calls                                                             map[string]int
	accepted                                                          map[string]json.RawMessage
	authorization                                                     qualification.ChildEnvelope[qualification.ChildAuthorizationObservation]
}

func publicDeliveryMap(v any) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(fixtureRaw(v), &m)
	return m
}
func publicDeliveryDecode(t *testing.T, v any, out any) {
	t.Helper()
	if err := json.Unmarshal(fixtureRaw(v), out); err != nil {
		t.Fatal(err)
	}
}
func sourcePublicPEM(key *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
func sourceSigned(t *testing.T, key *ecdsa.PrivateKey, id string, payload any) json.RawMessage {
	t.Helper()
	sum := sha256.Sum256(fixtureRaw(payload))
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return fixtureRaw(map[string]any{"payload": payload, "keyId": id, "signature": base64.StdEncoding.EncodeToString(sig)})
}
func (d *firstTaskPublicDeliveryFixture) writeOriginal(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	parent := filepath.Dir(path)
	if strings.HasPrefix(path, d.tree+"/") {
		for p := parent; strings.HasPrefix(p, d.tree); p = filepath.Dir(p) {
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				if err = os.Chmod(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
		}
		defer func() {
			for p := parent; strings.HasPrefix(p, d.tree); p = filepath.Dir(p) {
				if err := os.Chmod(p, 0500); err != nil {
					t.Fatal(err)
				}
			}
		}()
	}
	if err := os.MkdirAll(parent, 0700); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	// Test manager copy, not Runtime repair; first-byte files are never overwritten.
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(path, d.tree+"/") {
		if err = os.Chmod(parent, 0500); err != nil {
			t.Fatal(err)
		}
	}
}
func (f *firstTaskChildTerminalFixture) configurePublicDelivery(t *testing.T, native *parentSourceRuntime, app model.WorkspaceApplicationOperation, base map[string]any) {
	f.configurePublicDeliveryDocuments(t, native, app, base)
	d := f.delivery
	config := qualification.ProducerConfig{KeyID: app.Producer.KeyID, KeySHA256: app.Producer.KeySHA256, ServerID: app.ServerID, NodeTokenHash: app.Producer.NodeTokenHash, KeyPath: filepath.Join(d.root, "source-producer.pem"), EvidenceRoot: d.evidence}
	var err error
	d.producer, err = qualification.NewProducer(&config, app.ServerID, app.Producer.NodeTokenHash)
	if err != nil {
		t.Fatal("SOURCE root metadata supplier required, never installed trust", err)
	}
}

// Signed SOURCE inputs only. No protected Runtime producer, admission, output or
// workflow acceptance is created by this test-only document supplier.
func (f *firstTaskChildTerminalFixture) configurePublicDeliveryDocumentBase(t *testing.T, native *parentSourceRuntime, app model.WorkspaceApplicationOperation, base map[string]any) {
	t.Helper()
	root, err := os.MkdirTemp(os.Getenv("WARPMETAL_PRODUCT_SOURCE_EVIDENCE"), "firsttask-public-delivery-")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	d := &firstTaskPublicDeliveryFixture{f: f, root: root, evidence: filepath.Join(root, "evidence"), native: native, app: app, policies: map[string]qualification.ControllerPolicy{}, grants: map[string]model.ControllerGrantEnvelope{}, activations: map[string]api.ControllerActivationEnvelope{}, calls: map[string]int{}, accepted: map[string]json.RawMessage{}}
	f.delivery = d
	packet := filepath.Join(root, "unsigned-shapes.json")
	out, err := exec.Command("python3", "-B", "../qualification/testdata/child_product_boundary_fixture.py", "../workflowcontract/schema", os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET"), packet, "--normal-firsttask-delivery-templates").CombinedOutput()
	if err != nil {
		t.Fatalf("existing SOURCE shape supplier: %v %s", err, out)
	}
	raw, err := os.ReadFile(packet)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &d.templates); err != nil {
		t.Fatal(err)
	}
	d.operator, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d.operatorPEM = sourcePublicPEM(d.operator)
	d.store = qualification.Store{Root: filepath.Join(root, "store"), MappedUID: uint32(os.Getuid())}
	d.tree, d.key, err = d.store.Paths(app.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(d.tree, 0700); err != nil {
		t.Fatal(err)
	}
	d.writeOriginal(t, d.key, d.operatorPEM, 0400)
	if err = os.Mkdir(d.evidence, 0700); err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(native.key)
	producerKey := filepath.Join(root, "source-producer.pem")
	d.writeOriginal(t, producerKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600)
}

func (f *firstTaskChildTerminalFixture) configurePublicDeliveryDocuments(t *testing.T, native *parentSourceRuntime, app model.WorkspaceApplicationOperation, base map[string]any) {
	f.configurePublicDeliveryDocumentBase(t, native, app, base)
	d := f.delivery
	var err error
	var demand qualification.DemandManifest
	prepare := d.templates["prepare"].(map[string]any)["generation"].(map[string]any)
	publicDeliveryDecode(t, prepare["demand"].(map[string]any)["payload"], &demand)
	demand.CaseID = "source_delivery_case"
	demand.AccountScopeDigest = model.WorkspaceDigest(native.parents[0].Owner)
	demand.DeclaredAt = native.now().Add(-time.Second).Format(time.RFC3339Nano)
	demand.NotAfter = native.now().Add(4 * time.Minute).Format(time.RFC3339Nano)
	childAllocation := base["target"].(map[string]any)["members"].(map[string]any)["first"].(map[string]any)["allocationId"].(string)
	demand.AllocationList = nil
	for i, spec := range []struct {
		id, kind          string
		first, last, prep int
	}{{"source_access", "access", 1, 1, 0}, {"source_qualification", "qualification", 2, 3, 1}, {"source_orchestrator", "parent", 4, 4, 2}, {"source_manager", "parent", 5, 5, 3}, {childAllocation, "coding_worker", 6, 7, 4}, {"source_business", "business_worker", 8, 10, 5}} {
		count := spec.last - spec.first + 1
		models, access := count, 0
		if spec.kind == "access" {
			models, access = 0, 1
		}
		demand.AllocationList = append(demand.AllocationList, qualification.DemandAllocation{Name: fmt.Sprintf("source_%d", i), AllocationID: spec.id, Kind: spec.kind, Scope: native.parents[0].Owner, SourceID: spec.id, ScopeDigest: demand.AccountScopeDigest, TupleDigest: model.WorkspaceDigest("source_qualified_tuple"), DependsOn: []string{}, PreparationOrdinal: spec.prep, FirstPhysicalIndex: spec.first, LastPhysicalIndex: spec.last, ModelRequests: models, AccessRequests: access, USDMicros: int64(count) * qualification.RequestMicros})
	}
	d.demand = demand
	d.caseValue = qualification.RealCase{FormatVersion: 2, CaseID: demand.CaseID, CaseManifestDigest: demand.CaseManifestDigest, LedgerID: demand.LedgerID, Requests: 10, ModelRequests: 9, AccessRequests: 1, Preparations: 5, QualificationTuples: 1, USDMicros: 4210000, PhysicalCeiling: 10, USDCeilingMicros: 4210000, PricingDigest: qualification.PricingDigest(), OperatorKeySHA256: qualification.Digest(d.operatorPEM), DemandManifestDigest: model.WorkspaceDigest(demand), TupleInventoryDigest: demand.TupleInventoryDigest, ControlsDigest: model.WorkspaceDigest(demand.Controls)}
	authority := d.templates["authorityTemplate"].(map[string]any)
	authority["case"] = d.caseValue
	authority["caseId"] = d.caseValue.CaseID
	authority["caseManifestDigest"] = d.caseValue.CaseManifestDigest
	authority["usdLimitMicros"] = 4210000
	authority["requestLimit"] = 10
	authority["turnLimit"] = 9
	authority["evidenceClass"] = "source"
	authority["ledgerReconciliation"] = nil
	authority["evidenceRoot"] = d.evidence
	authority["operator"] = map[string]any{"keyId": "source_independent_operator", "keyPath": "/SOURCE/independent-operator-not-runtime.pem", "keySHA256": qualification.Digest(d.operatorPEM)[7:]}
	authority["producer"] = map[string]any{"keyId": app.Producer.KeyID, "keyPath": filepath.Join(d.root, "source-producer.pem"), "keySHA256": app.Producer.KeySHA256[7:], "nodeTokenHash": app.Producer.NodeTokenHash}
	if err = workflowcontract.Validate(workflowcontract.Budget, "authority2", fixtureRaw(authority)); err != nil {
		t.Fatal("SOURCE authority shape", err)
	}
	d.writeOriginal(t, filepath.Join(d.evidence, "physical-gate-authority.json"), fixtureRaw(authority), 0600)
	d.writeOriginal(t, filepath.Join(d.evidence, "physical-gate-operator.pem"), d.operatorPEM, 0600)
	demandEnvelope := sourceSigned(t, d.operator, "source_independent_operator", demand)
	fields := publicDeliveryMap(demandEnvelope)
	sig, _ := base64.StdEncoding.DecodeString(fields["signature"].(string))
	demandRoot := filepath.Join(d.tree, "snapshots", d.caseValue.DemandManifestDigest[7:])
	d.writeOriginal(t, filepath.Join(demandRoot, "demand.json"), fixtureRaw(demand), 0400)
	d.writeOriginal(t, filepath.Join(demandRoot, "demand.sig"), sig, 0400)
	t.Log("retained SOURCE normal public delivery", d.root, "separate SOURCE operator; root/qualification/native/backend upstream suppliers")
}
func (d *firstTaskPublicDeliveryFixture) applicability(t *testing.T, parent model.ControllerParentIntent) qualification.Applicability {
	t.Helper()
	var a qualification.Applicability
	publicDeliveryDecode(t, d.templates["witness"].(map[string]any)["Applicability"], &a)
	a.AccountID = parent.Owner.AccountID
	a.TaskID = parent.Owner.TaskID
	a.ServerID = parent.Owner.ServerID
	a.SandboxID = parent.Owner.SandboxID
	a.SandboxGeneration = parent.Owner.SandboxGeneration
	a.Connection = *d.app.Dependencies.Roles[0].Projection.ModelSelection.CredentialBinding
	a.Profile.SetupOperationID = parent.Profile.SetupOperationID
	a.Profile.ProfileID = parent.Profile.ProfileID
	a.Profile.Revision = parent.Profile.ProfileRevision
	a.Profile.ProfileDigest = parent.Profile.ProfileDigest
	a.Profile.BundleDigest = d.app.Dependencies.Roles[0].Projection.ApprovedProfile.BundleDigest
	a.Model.AdapterVersion = "source-controller-adapter"
	return a
}
func (d *firstTaskPublicDeliveryFixture) parentContext(t *testing.T, parent model.ControllerParentIntent, prep model.ControllerPreparedReceipt, c model.ControllerApprovedInputContext) model.ControllerApprovedInputContext {
	t.Helper()
	w, err := d.f.r.controllerActivityCurrentWitness(context.Background(), parent.ServiceRegistrationID, d.applicability(t, parent), false)
	if err != nil {
		t.Fatal(err)
	}
	a := d.demand.AllocationList[2]
	if parent.Role == "manager" {
		a = d.demand.AllocationList[3]
	}
	p := qualification.ControllerPolicy{FormatVersion: 5, TargetKind: "controller_activity", Mode: "real_provider", Purpose: "controller_activity", Case: d.caseValue, Applicability: w.Installed.Applicability, Identity: w.Installed.Identity, Application: w.Installed.Application, AllocationID: a.AllocationID, ExpiresAt: d.demand.NotAfter}
	d.policies[parent.Role] = p
	raw := sourceSigned(t, d.operator, "source_independent_operator", p)
	fields := publicDeliveryMap(raw)
	sig, _ := base64.StdEncoding.DecodeString(fields["signature"].(string))
	path := filepath.Join(d.tree, "snapshots", model.WorkspaceDigest(p)[7:])
	d.writeOriginal(t, filepath.Join(path, "policy.json"), fixtureRaw(p), 0400)
	d.writeOriginal(t, filepath.Join(path, "policy.sig"), sig, 0400)
	if err = os.Chmod(filepath.Dir(path), 0500); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(d.tree, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(d.tree, "revocations"), 0500); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	if err = os.Chmod(d.tree, 0500); err != nil {
		t.Fatal(err)
	}
	c.CaseID = d.caseValue.CaseID
	c.CaseManifestDigest = d.caseValue.CaseManifestDigest
	c.PolicyDigest = model.WorkspaceDigest(p)
	c.DemandManifestDigest = d.caseValue.DemandManifestDigest
	c.AllocationID = a.AllocationID
	c.PhysicalIndex = a.FirstPhysicalIndex
	c.PreparationOrdinal = a.PreparationOrdinal
	c.ContextDigest = fixtureDigestField(c, "contextDigest")
	return c
}
func (f *firstTaskChildTerminalFixture) finishPublicDeliverySetup(t *testing.T, native *parentSourceRuntime, app model.WorkspaceApplicationOperation) {
	t.Helper()
	d := f.delivery
	for role, p := range f.deliveryParents {
		header := model.ControllerAuthorizationObservation{FormatVersion: 1, TargetKind: "controller_authorization", PreparationID: p.prepared.PreparationID, PreparedReceiptDigest: p.prepared.PreparedReceiptDigest, AuthorizationSHA256: model.WorkspaceDigest("source-header-" + role)}
		var envelope model.ControllerAuthorizationEnvelope
		publicDeliveryDecode(t, sourceSigned(t, native.key, app.Producer.KeyID, header), &envelope)
		if err := f.r.Store.PinControllerActivityStage(context.Background(), p.prepared.PreparationID, state.ControllerHeaderObserved, fixtureRaw(envelope)); err != nil {
			t.Fatal(err)
		}
	}
	if err := filepath.Walk(d.tree, func(path string, st os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if st.IsDir() {
			return os.Chmod(path, 0500)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	d.prepareChildBasis(t)
	f.r.ManagedRuntime = &firstTaskPublicDeliveryRuntime{firstTaskChildTerminalRuntime: f.r.ManagedRuntime.(*firstTaskChildTerminalRuntime), delivery: d}
}

// The runtime adapter reads only public data and delegates to production readers.
type firstTaskPublicDeliveryRuntime struct {
	*firstTaskChildTerminalRuntime
	delivery *firstTaskPublicDeliveryFixture
}

func (s *firstTaskPublicDeliveryRuntime) ReadControllerFirstTaskApplicability(_ context.Context, _ model.Manifest, w qualification.ControllerPolicyWitness) (qualification.Applicability, error) {
	return s.delivery.applicability(s.fixture.t, w.Identity.Intent), nil
}
func (s *firstTaskPublicDeliveryRuntime) VerifyControllerPolicy(_ context.Context, box model.Sandbox, digest string, w qualification.ControllerPolicyWitness) (qualification.ControllerPolicy, error) {
	p, err := s.delivery.store.ReadControllerPolicy(box, digest, w, s.now())
	if err != nil {
		return p, fmt.Errorf("SOURCE protected policy %s: %w", w.Identity.Intent.Role, err)
	}
	return p, nil
}
func (s *firstTaskPublicDeliveryRuntime) ReadControllerActivation(_ context.Context, box model.Sandbox, p qualification.ControllerPolicy, r model.ControllerPreparedReceipt, retained bool) (qualification.ControllerActivation, error) {
	if retained {
		return s.delivery.store.ReadControllerRetainedActivation(box, p, r, s.now())
	}
	return s.delivery.store.ReadControllerActivation(box, p, r, s.now())
}
func (s *firstTaskPublicDeliveryRuntime) ReadControllerGrantOriginal(_ context.Context, r model.ControllerPreparedReceipt, w qualification.ControllerOutputWitness) (model.ControllerGrantEnvelope, error) {
	g, err := s.delivery.producer.ReadControllerGrantDelivery(s.delivery.store, w.Sandbox, w.Policy, r, w.ApprovedContext, s.now())
	if err != nil {
		return g, fmt.Errorf("SOURCE protected grant %s: %w", r.PreparedTuple.Role, err)
	}
	return g, nil
}
func (s *firstTaskPublicDeliveryRuntime) ReadControllerActivationOriginal(_ context.Context, r model.ControllerPreparedReceipt, w qualification.ControllerOutputWitness) (api.ControllerActivationEnvelope, error) {
	a, e := s.delivery.producer.ReadControllerActivationDelivery(s.delivery.store, w.Sandbox, w.Policy, r, w.ApprovedContext, s.now())
	return api.ControllerActivationEnvelope{Payload: a.Payload, KeyID: a.KeyID, Signature: a.Signature}, e
}
func (s *firstTaskPublicDeliveryRuntime) ExportControllerActivationHandoff(_ context.Context, r model.ControllerPreparedReceipt, _ qualification.ControllerOutputWitness, raw []byte) error {
	return s.delivery.producer.ExportControllerActivationHandoff(r.PreparationID, raw)
}
func (s *firstTaskPublicDeliveryRuntime) AdoptPublishedControllerActivation(_ context.Context, r model.ControllerPreparedReceipt, w qualification.ControllerOutputWitness, a api.ControllerActivationEnvelope) error {
	return s.delivery.producer.AdoptPublishedControllerActivation(s.delivery.store, w.Sandbox, w.Policy, r, w.ApprovedContext, qualification.ChildEnvelope[qualification.ControllerActivation]{Payload: a.Payload, KeyID: a.KeyID, Signature: a.Signature}, s.now())
}
func (s *firstTaskPublicDeliveryRuntime) ReadChildPolicyOriginal(_ context.Context, b model.Sandbox, h model.IntentHandle, id, stage string, intent json.RawMessage) (json.RawMessage, error) {
	return s.delivery.producer.ReadChildPolicyDelivery(s.delivery.store, b, h, id, stage, intent, s.now())
}
func (s *firstTaskPublicDeliveryRuntime) ReadChildActivationOriginal(_ context.Context, b model.Sandbox, h model.IntentHandle, c qualification.RealCase, intent json.RawMessage) (json.RawMessage, error) {
	return s.delivery.producer.ReadChildActivationDelivery(s.delivery.store, b, h, c, intent, s.now())
}
func (s *firstTaskPublicDeliveryRuntime) ExportChildSigningIntent(_ context.Context, _ model.Sandbox, h model.IntentHandle, stage string, raw []byte) error {
	return s.delivery.producer.ExportChildSigningIntent(h.HandleID, stage, raw)
}
func (s *firstTaskPublicDeliveryRuntime) ExecManagedSupervisor(ctx context.Context, box string, action containers.ManagedSupervisorAction, raw []byte) ([]byte, []byte, error) {
	if action == containers.ManagedSupervisorControllerPrompt {
		var call struct {
			Admission model.ControllerAdmission
			Text      string
		}
		_ = json.Unmarshal(raw, &call)
		role := call.Admission.PreparedReceipt.PreparedTuple.Role
		p := s.fixture.deliveryParents[role]
		if call.Text != p.text || s.delivery.calls[role+"/activations"] != 1 {
			return nil, nil, fmt.Errorf("SOURCE prompt outran public activation")
		}
		s.delivery.calls[role+"/prompt"]++
		return fixtureRaw(map[string]any{"schemaVersion": 1, "command": "controller-prompt", "status": "admitted", "nativeAdmission": call.Admission}), nil, nil
	}
	return s.firstTaskChildTerminalRuntime.ExecManagedSupervisor(ctx, box, action, raw)
}

func (d *firstTaskPublicDeliveryFixture) serve(w http.ResponseWriter, r *http.Request) bool {
	const bridge = "/internal/runtime/workspace-workflow/"
	for role, p := range d.f.deliveryParents {
		prefix := bridge + "controller-preparations/" + p.prepared.PreparationID + "/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(r.URL.Path, prefix)
		d.calls[role+"/"+suffix]++
		switch suffix {
		case "workflow-context":
			if r.Header.Get("X-WarpMetal-Workflow-Lease") != "wfl_source_"+role {
				d.f.t.Fatal("parent lease not obtained by normal enrollment")
			}
			_ = json.NewEncoder(w).Encode(p.context)
		case "grants":
			var got model.ControllerGrantEnvelope
			_ = json.NewDecoder(r.Body).Decode(&got)
			if r.Method != "POST" || !reflect.DeepEqual(got, d.grants[role]) {
				d.f.t.Fatal("reserve changed independent grant")
			}
			_ = json.NewEncoder(w).Encode(got.Payload)
		case "activation-intent":
			if d.calls[role+"/grants"] != 1 {
				d.f.t.Fatal("signing basis before reserve")
			}
			a := d.parentActivation(role)
			basis := publicDeliveryMap(a)
			delete(basis, "authorizationSha256")
			delete(basis, "issuedAt")
			_ = json.NewEncoder(w).Encode(api.ControllerActivationSigningIntent{PayloadBasis: fixtureRaw(basis), NotBefore: d.native.now().Format(time.RFC3339Nano)})
		case "activations":
			var call api.ControllerActivationPublication
			_ = json.NewDecoder(r.Body).Decode(&call)
			if r.Method != "POST" || !reflect.DeepEqual(call.Activation, d.activations[role]) || call.HeaderObservation.Payload.AuthorizationSHA256 != call.Activation.Payload.AuthorizationSHA256 {
				d.f.t.Fatal("publication changed separate header/operator originals")
			}
			_ = json.NewEncoder(w).Encode(api.ControllerActivationReceipt{FormatVersion: 2, PreparationID: p.prepared.PreparationID, ActivationDigest: model.WorkspaceDigest(call.Activation.Payload), State: "published"})
		default:
			d.f.t.Fatal("unexpected parent delivery route", suffix)
		}
		return true
	}
	return d.serveChild(w, r)
}
func (d *firstTaskPublicDeliveryFixture) parentActivation(role string) qualification.ControllerActivation {
	p := d.f.deliveryParents[role]
	g := d.grants[role].Payload
	return qualification.ControllerActivation{FormatVersion: 3, TargetKind: "controller_activity", Mode: "real_provider", Purpose: "controller_activity", PolicyDigest: p.context.PolicyDigest, Admission: model.ControllerAdmission{FormatVersion: 1, TargetKind: "controller_activity", PreparedReceipt: p.prepared, Grant: g}, GrantEnvelopeDigest: model.WorkspaceDigest(d.grants[role]), AuthorizationSHA256: model.WorkspaceDigest("source-header-" + role), PreparationIndex: p.context.PreparationOrdinal, IssuedAt: d.native.now().Format(time.RFC3339Nano), AllocationID: p.context.AllocationID, DemandManifestDigest: d.caseValue.DemandManifestDigest, ContextDigest: p.context.ContextDigest}
}

func (f *firstTaskChildTerminalFixture) runPublicDelivery(t *testing.T, j *managerPolicyJourney) {
	t.Helper()
	d := f.delivery
	ctx := context.Background()
	passIndex := 0
	pass := func() {
		t.Helper()
		passIndex++
		if err := j.reconciler.Reconcile(ctx, j.manifest); err != nil {
			t.Fatal("normal SOURCE public-delivery pass", passIndex, d.calls, err)
		}
	}
	pass() // BOTH normal enroll responses retained; no grant leaf yet.
	for _, role := range []string{"orchestrator", "manager"} {
		p := f.deliveryParents[role]
		g := model.ControllerActivityGrant{FormatVersion: 1, TargetKind: "controller_activity", GrantID: "source_grant_" + role, PreparationID: p.prepared.PreparationID, PreparedReceiptDigest: p.prepared.PreparedReceiptDigest, ReservationID: "source_reservation_" + role, CaseID: d.caseValue.CaseID, CaseManifestDigest: d.caseValue.CaseManifestDigest, PolicyDigest: p.context.PolicyDigest, RequestIndex: p.context.PhysicalIndex, PhysicalIndex: p.context.PhysicalIndex, MaxInputTokens: 1000, MaxOutputTokens: 1000, MaxUSDMicros: 2000, DeadlineAt: d.native.now().Add(110 * time.Second).Format(time.RFC3339Nano), ExpiresAt: d.native.now().Add(115 * time.Second).Format(time.RFC3339Nano)}
		var grant model.ControllerGrantEnvelope
		publicDeliveryDecode(t, sourceSigned(t, d.operator, "source_independent_operator", g), &grant)
		d.grants[role] = grant
		if role == "orchestrator" {
			d.checkIndependentSignerRefusal(t, p)
		}
		d.writeOriginal(t, filepath.Join(d.tree, "controller-activity-grant-"+p.prepared.PreparationID+".json"), fixtureRaw(d.grants[role]), 0400)
		pass()
		raw, err := os.ReadFile(filepath.Join(d.evidence, "controller-activation-handoff-"+p.prepared.PreparationID+".json"))
		if err != nil {
			t.Fatal("normal owner failed to export handoff", err)
		}
		var handoff ControllerParentSigningHandoff
		publicDeliveryDecode(t, json.RawMessage(raw), &handoff)
		a, err := qualification.ControllerActivationFromSigningBasis(handoff.Intent.PayloadBasis, handoff.Intent.NotBefore, handoff.HeaderObservation.Payload.AuthorizationSHA256, d.policies[role], p.context, d.native.now())
		if err != nil {
			t.Fatal(err)
		}
		var signed api.ControllerActivationEnvelope
		publicDeliveryDecode(t, sourceSigned(t, d.operator, "source_independent_operator", a), &signed)
		d.activations[role] = signed
		d.writeOriginal(t, filepath.Join(d.tree, "controller-activation-envelope-"+p.prepared.PreparationID+".json"), fixtureRaw(signed), 0400)
		pass()
		if d.calls[role+"/grants"] != 2 || d.calls[role+"/activation-intent"] != 1 || d.calls[role+"/activations"] != 1 || d.calls[role+"/prompt"] != 1 {
			t.Fatal("parent normal reserve/replay/handoff/publication/prompt absent", role, d.calls)
		}
		got, err := d.store.ReadControllerActivation(model.Sandbox{ID: d.app.SandboxID, Generation: d.app.SandboxGeneration}, d.policies[role], p.prepared, d.native.now())
		if err != nil || !reflect.DeepEqual(got, a) {
			t.Fatal("normal signed sidecar adoption not readable", err)
		}
	}
	d.runChild(t, j, pass)
}

// Read-only malicious SOURCE delivery, inside this journey, before the normal
// reserve. A producer-signed grant cannot masquerade as an operator original.
// Preserve its first bytes in a separate SOURCE store; never corrupt/repair the
// genuine delivery slot or call a prepare/admit/helper from the test.
func (d *firstTaskPublicDeliveryFixture) checkIndependentSignerRefusal(t *testing.T, p firstTaskDeliveryParent) {
	t.Helper()
	before := fixtureRaw(d.calls)
	s := qualification.Store{Root: filepath.Join(d.root, "producer-forgery-store"), MappedUID: uint32(os.Getuid())}
	tree, key, err := s.Paths(d.app.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	d.writeOriginal(t, key, d.operatorPEM, 0400)
	d.writeOriginal(t, filepath.Join(tree, "controller-activity-grant-"+p.prepared.PreparationID+".json"), sourceSigned(t, d.native.key, "source_independent_operator", d.grants["orchestrator"].Payload), 0400)
	if err = os.Chmod(tree, 0500); err != nil {
		t.Fatal(err)
	}
	box := model.Sandbox{ID: d.app.SandboxID, Generation: d.app.SandboxGeneration}
	if _, err = d.producer.ReadControllerGrantDelivery(s, box, d.policies["orchestrator"], p.prepared, p.context, d.native.now()); !errors.Is(err, qualification.ErrUntrusted) || errors.Is(err, qualification.ErrOperatorDeliveryPending) {
		t.Fatal("producer signature became independent grant/pending", err)
	}
	changed := d.policies["orchestrator"]
	changed.Case.OperatorKeySHA256 = d.app.Producer.KeySHA256
	context := p.context
	context.PolicyDigest = model.WorkspaceDigest(changed)
	if _, err = d.producer.ReadControllerGrantDelivery(d.store, box, changed, p.prepared, context, d.native.now()); !errors.Is(err, qualification.ErrUntrusted) || errors.Is(err, qualification.ErrOperatorDeliveryPending) {
		t.Fatal("current independent pin drift became grant/pending", err)
	}
	if !bytes.Equal(before, fixtureRaw(d.calls)) {
		t.Fatal("read-only independent signer refusal performed owning HTTP")
	}
}

func (d *firstTaskPublicDeliveryFixture) prepareChildBasis(t *testing.T) {
	t.Helper()
	f := d.f
	// Exactly the existing r328 native/domain SOURCE data shape. No SQLite prepared,
	// policy, grant or admission row is inserted: ordinary prepare/report owns it.
	receipt := cellV3TestReceipt(t, f.entry)
	tuple := receipt.PreparedTuple
	binding := map[string]any{"workId": "source_child_work", "workRevision": 1, "bindingId": "source_child_binding", "bindingRevision": 1, "executionId": "source_child_execution", "preparationId": f.entry.PreparationID, "parentExecutionId": nil, "parentPacketId": nil, "packetId": f.entry.ParentIdentity.PacketID, "packetRevision": 1, "attempt": f.entry.Attempt, "fence": f.entry.Fence, "serviceRegistrationId": f.entry.ServiceRegistrationID, "serviceGeneration": f.entry.ServiceGeneration, "sandboxGeneration": f.entry.SandboxGeneration, "nativeSessionId": f.entry.NativeSessionID, "nativeProjectId": f.entry.NativeProjectID, "nativeLocationDigest": model.WorkspaceDigest("source_child_location"), "projectId": f.entry.Workspace.ProjectID, "workspaceEpoch": f.entry.WorkspaceEpoch, "selectionId": f.entry.Workspace.SelectionID, "scopeRevision": f.entry.Workspace.ScopeRevision, "rootAttestation": f.entry.Workspace.RootAttestation, "instructionRevision": f.entry.Instructions.InstructionRevision, "instructionDigest": f.entry.Instructions.InstructionDigest, "profileDigest": f.entry.Profile.ProfileDigest, "configDigest": f.entry.ConfigDigest}
	plan := f.deliveryParents["manager"].context.Plan
	body := map[string]any{"formatVersion": 1, "requestId": f.selected.AssignmentRequestID, "binding": binding, "purpose": "implement", "plan": plan, "target": nil}
	f.actual = model.ActualPreparationAssociation{FormatVersion: 1, HandleID: f.handle.HandleID, Intent: f.handle.Intent, PreparationID: f.entry.PreparationID, PreparedReceipt: receipt, Binding: fixtureRaw(binding), AssignmentBody: fixtureRaw(body)}
	f.actual.AssociationDigest = fixtureDigestField(f.actual, "associationDigest")
	if err := f.actual.ValidateIntegrity(); err != nil {
		t.Fatal(err)
	}
	f.assignment = fixtureRaw(map[string]any{"formatVersion": 1, "assignmentId": "source_child_assignment", "assignmentDigest": model.WorkspaceDigest(body), "executionId": "source_child_execution", "purpose": "implement", "plan": plan, "target": nil, "createdAt": d.native.now().Format(time.RFC3339Nano)})
	prep := publicDeliveryMap(d.templates["prepare"].(map[string]any)["generation"].(map[string]any)["preparationPolicy"].(map[string]any)["payload"])
	member := publicDeliveryMap(f.deliveryParents["manager"].context.Target)["members"].(map[string]any)["first"]
	prep["case"] = d.caseValue
	prep["handle"] = f.handle
	prep["intent"] = member
	prep["scope"] = member.(map[string]any)["scope"]
	root := prep["root"].(map[string]any)
	root["producer"] = d.app.Producer
	root["workspace"] = member.(map[string]any)["scope"].(map[string]any)["workspace"]
	prep["preparation"] = map[string]any{"preparationId": f.entry.PreparationID, "preparedTuple": tuple, "preparedTupleDigest": model.WorkspaceDigest(tuple), "sessionId": f.entry.NativeSessionID, "inputId": "msg_source_input"}
	prep["issuedAt"] = d.native.now().Format(time.RFC3339Nano)
	prep["expiresAt"] = d.native.now().Add(115 * time.Second).Format(time.RFC3339Nano)
	allocation := d.demand.AllocationList[4]
	reservation := qualification.ChildReservation{ReservationID: "source_child_reservation", LedgerID: d.caseValue.LedgerID, AllocationID: f.handle.AllocationID, DemandManifestDigest: d.caseValue.DemandManifestDigest, PreparationOrdinal: allocation.PreparationOrdinal, FirstPhysicalIndex: allocation.FirstPhysicalIndex, LastPhysicalIndex: allocation.LastPhysicalIndex, ModelRequests: 2, AccessRequests: 0, USDMicros: 2 * qualification.RequestMicros}
	prep["reservation"] = reservation
	d.preparePayload = fixtureRaw(prep)
	product := publicDeliveryMap(d.templates["execute"].(map[string]any)["generation"].(map[string]any)["policy"].(map[string]any)["payload"])
	for _, key := range []string{"case", "scope", "root", "applicability", "qualification", "reservation", "budget", "workload", "instructions", "issuedAt", "expiresAt"} {
		product[key] = prep[key]
	}
	product["intent"] = f.handle.Intent
	product["preparationPolicyDigest"] = model.WorkspaceDigest(d.preparePayload)
	product["preparedReceipt"] = receipt
	product["binding"] = f.actual.Binding
	product["assignment"] = f.assignment
	d.productPayload = fixtureRaw(product)
	var assigned struct{ AssignmentDigest string }
	_ = json.Unmarshal(f.assignment, &assigned)
	d.bindingPayload = fixtureRaw(qualification.ChildPolicyBinding{FormatVersion: 1, Purpose: "coding_worker", Case: d.caseValue, AllocationID: f.handle.AllocationID, Intent: f.handle.Intent, PolicyDigest: model.WorkspaceDigest(d.productPayload), PreparedReceiptDigest: receipt.PreparedReceiptDigest, AssignmentDigest: assigned.AssignmentDigest, ModelRequests: 2, USDMicros: 2 * qualification.RequestMicros, ExpiresAt: prep["expiresAt"].(string)})
	for _, spec := range []struct {
		definition string
		raw        json.RawMessage
	}{{"preparationPolicy", d.preparePayload}, {"productPolicy", d.productPayload}, {"productPolicyBinding", d.bindingPayload}} {
		d.writeOriginal(t, filepath.Join(d.root, "unsigned-child-"+spec.definition+".json"), spec.raw, 0600)
		if err := workflowcontract.Validate(workflowcontract.Budget, spec.definition, spec.raw); err != nil {
			t.Fatal("SOURCE unsigned child basis", spec.definition, err)
		}
	}
}
func (d *firstTaskPublicDeliveryFixture) childIntent(stage string) json.RawMessage {
	payload, binding := d.preparePayload, json.RawMessage("null")
	if stage == "product" {
		payload, binding = d.productPayload, d.bindingPayload
	}
	return fixtureRaw(map[string]any{"formatVersion": 1, "handleId": d.f.handle.HandleID, "stage": stage, "payload": payload, "policyBinding": binding, "notBefore": d.native.now().Format(time.RFC3339Nano)})
}
func (d *firstTaskPublicDeliveryFixture) serveChild(w http.ResponseWriter, r *http.Request) bool {
	prefix := "/internal/runtime/workspace-workflow/manager-intents/" + d.f.handle.HandleID + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(r.URL.Path, prefix)
	if suffix == "preparations" {
		if d.calls["manager/prompt"] != 1 || d.calls["orchestrator/prompt"] != 1 {
			d.f.t.Fatal("child acceptance supplier outran BOTH normal parent delivery")
		}
		return false
	}
	if suffix == "prepared-association" {
		return false
	}
	if r.Header.Get("X-WarpMetal-Workflow-Lease") != "wfl_source_manager" {
		d.f.t.Fatal("child delivery borrowed unissued lease")
	}
	d.calls[suffix]++
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch suffix {
	case "preparation-policy-intent":
		write(d.childIntent("prepare"))
	case "product-policy-intent":
		if d.f.nativePrepares != 1 || d.f.assigns != 1 {
			d.f.t.Fatal("PRODUCT basis before real normal prepare/report/assignment")
		}
		write(d.childIntent("product"))
	case "product-policies":
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		fields := publicDeliveryMap(raw)
		stage := fields["stage"].(string)
		expected := d.prepareRequest
		if stage == "product" {
			expected = d.productRequest
		}
		if r.Method != "POST" || !bytes.Equal(fixtureRaw(raw), expected) || r.Header.Get("Idempotency-Key") != fields["requestId"] {
			d.f.t.Fatal("owning policy POST changed independent whole request")
		}
		d.accepted[stage] = append(json.RawMessage(nil), expected...)
		var policy, binding any
		if stage == "product" {
			policy = model.WorkspaceDigest(d.productPayload)
			binding = model.WorkspaceDigest(d.bindingPayload)
		}
		write(map[string]any{"formatVersion": 1, "handleId": d.f.handle.HandleID, "preparationId": d.f.entry.PreparationID, "stage": stage, "preparationPolicyDigest": model.WorkspaceDigest(d.preparePayload), "policyDigest": policy, "policyBindingDigest": binding, "state": "committed_publication_pending"})
	case "preparation-control-publications", "product-control-publications":
		phase := "prepare"
		if suffix == "product-control-publications" {
			phase = "execute"
		}
		if r.Method != "POST" || len(d.accepted["prepare"]) == 0 || phase == "execute" && len(d.accepted["activation"]) == 0 {
			d.f.t.Fatal("publication before independent policy/activation acceptance")
		}
		write(map[string]any{"formatVersion": 1, "preparationId": d.f.entry.PreparationID, "phase": phase, "generationDigest": model.WorkspaceDigest("source-published-" + phase), "state": "published"})
	case "grant-intents":
		if len(d.accepted["product"]) == 0 {
			d.f.t.Fatal("grant intent before independent PRODUCT policy")
		}
		entry := cellV3TestExecute(d.f.t, d.f.entry, d.f.actual.PreparedReceipt)
		entry.ExecutionGrant.ExpiresAt = d.native.now().Add(115 * time.Second).Format(time.RFC3339Nano)
		var binding struct{ AssignmentDigest string }
		_ = json.Unmarshal(d.f.assignment, &binding)
		write(map[string]any{"formatVersion": 1, "handleId": d.f.handle.HandleID, "preparationAssociationDigest": d.f.actual.AssociationDigest, "policyDigest": model.WorkspaceDigest(d.productPayload), "policyBindingDigest": model.WorkspaceDigest(d.bindingPayload), "assignment": d.f.assignment, "reservation": publicDeliveryMap(d.preparePayload)["reservation"], "grant": entry.ExecutionGrant, "grantDigest": model.WorkspaceDigest(entry.ExecutionGrant), "notBefore": d.native.now().Format(time.RFC3339Nano), "expiresAt": entry.ExecutionGrant.ExpiresAt, "state": "committed_activation_pending"})
	case "activation-intents":
		var request struct {
			AuthorizationObservation qualification.ChildEnvelope[qualification.ChildAuthorizationObservation]
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		if r.Method != "POST" || !reflect.DeepEqual(request.AuthorizationObservation, d.authorization) || d.calls["authorization-native"] != 1 {
			d.f.t.Fatal("activation intent invented/replaced native Authorization")
		}
		entry := cellV3TestExecute(d.f.t, d.f.entry, d.f.actual.PreparedReceipt)
		entry.ExecutionGrant.ExpiresAt = d.native.now().Add(115 * time.Second).Format(time.RFC3339Nano)
		var assigned struct{ AssignmentDigest string }
		_ = json.Unmarshal(d.f.assignment, &assigned)
		a := publicDeliveryMap(d.templates["execute"].(map[string]any)["generation"].(map[string]any)["activation"].(map[string]any)["payload"])
		for k, v := range map[string]any{"caseId": d.caseValue.CaseID, "caseManifestDigest": d.caseValue.CaseManifestDigest, "demandManifestDigest": d.caseValue.DemandManifestDigest, "allocationId": d.f.handle.AllocationID, "intent": d.f.handle.Intent, "preparationId": d.f.entry.PreparationID, "preparationPolicyDigest": model.WorkspaceDigest(d.preparePayload), "preparedTupleDigest": model.WorkspaceDigest(d.f.actual.PreparedReceipt.PreparedTuple), "preparedReceiptDigest": d.f.actual.PreparedReceipt.PreparedReceiptDigest, "assignmentDigest": assigned.AssignmentDigest, "policyDigest": model.WorkspaceDigest(d.productPayload), "policyBindingDigest": model.WorkspaceDigest(d.bindingPayload), "reservation": publicDeliveryMap(d.preparePayload)["reservation"], "grant": entry.ExecutionGrant, "grantDigest": model.WorkspaceDigest(entry.ExecutionGrant), "authorizationObservationDigest": model.WorkspaceDigest(d.authorization), "authorizationSha256": d.authorization.Payload.AuthorizationSHA256, "issuedAt": d.native.now().Format(time.RFC3339Nano), "expiresAt": entry.ExecutionGrant.ExpiresAt} {
			a[k] = v
		}
		d.activationPayload = fixtureRaw(a)
		write(map[string]any{"formatVersion": 1, "handleId": d.f.handle.HandleID, "payload": d.activationPayload, "authorizationObservation": d.authorization, "notBefore": d.native.now().Format(time.RFC3339Nano)})
	case "activations":
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		if r.Method != "POST" || !bytes.Equal(fixtureRaw(raw), d.activationRequest) {
			d.f.t.Fatal("owning activation POST changed SOURCE operator original")
		}
		d.accepted["activation"] = raw
		write(map[string]any{"formatVersion": 1, "handleId": d.f.handle.HandleID, "preparationId": d.f.entry.PreparationID, "activationDigest": model.WorkspaceDigest(d.activationPayload), "state": "committed_publication_pending"})
	default:
		d.f.t.Fatal("unexpected child delivery route", suffix)
	}
	return true
}
func (s *firstTaskPublicDeliveryRuntime) ObserveCellProductAuthorization(ctx context.Context, _ model.Sandbox, entry model.CellServiceV3, _ model.Manifest, _ []byte, reader containers.ChildAuthorizationIntentSource) (qualification.ChildEnvelope[qualification.ChildAuthorizationObservation], error) {
	d := s.delivery
	first, err := reader.ReadCurrentChildAuthorizationIntent(ctx, entry.PreparationID)
	if err != nil {
		return d.authorization, err
	}
	second, err := reader.ReadCurrentChildAuthorizationIntent(ctx, entry.PreparationID)
	if err != nil || model.WorkspaceDigest(first) != model.WorkspaceDigest(second) {
		return d.authorization, fmt.Errorf("SOURCE native Authorization lost current owner originals: %w", err)
	}
	request := publicDeliveryMap(d.productRequest)
	if model.WorkspaceDigest(first.Policy) != model.WorkspaceDigest(request["policy"]) || model.WorkspaceDigest(first.PolicyBinding) != model.WorkspaceDigest(request["policyBinding"]) {
		return d.authorization, fmt.Errorf("SOURCE Authorization saw changed original policy")
	}
	d.calls["authorization-native"]++
	var root qualification.ChildRootScope
	publicDeliveryDecode(s.fixture.t, publicDeliveryMap(d.productPayload)["root"], &root)
	observed := qualification.ChildAuthorizationObservation{FormatVersion: 1, Purpose: "child_product_authorization", TaskID: d.app.TaskID, NodeTokenHash: d.app.Producer.NodeTokenHash, PreparationID: entry.PreparationID, PreparedReceiptDigest: s.fixture.actual.PreparedReceipt.PreparedReceiptDigest, AuthorizationSHA256: model.WorkspaceDigest("source-native-header"), Root: root, ObservedAt: s.now().Format(time.RFC3339Nano)}
	publicDeliveryDecode(s.fixture.t, sourceSigned(s.fixture.t, s.key, d.app.Producer.KeyID, observed), &d.authorization)
	return d.authorization, nil
}
func (d *firstTaskPublicDeliveryFixture) runChild(t *testing.T, j *managerPolicyJourney, pass func()) {
	t.Helper()
	f := d.f
	readIntent := func(stage string) json.RawMessage {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(d.evidence, "child-"+stage+"-policy-intent-"+f.handle.HandleID+".json"))
		if err != nil {
			t.Fatal("normal child signing intent not exported", stage, err)
		}
		return raw
	}
	prepareIntent := publicDeliveryMap(readIntent("prepare"))
	prepareEnvelope := sourceSigned(t, d.operator, "source_independent_operator", prepareIntent["payload"])
	d.prepareRequest = fixtureRaw(map[string]any{"formatVersion": 1, "requestId": f.selected.PrepareRequestID, "stage": "prepare", "preparationPolicy": prepareEnvelope, "policy": nil, "policyBinding": nil})
	d.writeOriginal(t, filepath.Join(d.tree, "child-prepare-policy-request-"+f.handle.HandleID+".json"), d.prepareRequest, 0400)
	pass() // Policy acceptance/publication, without direct native/helper dispatch.
	if d.calls["preparation-control-publications"] != 1 || f.nativePrepares != 0 {
		t.Fatal("prepare control did not precede ordinary V3 manifest")
	}
	j.manifest.CellEntriesV3 = []model.CellServiceV3{f.entry}
	pass()
	if f.nativePrepares != 1 || f.assigns != 1 {
		t.Fatal("normal receipt/report/assignment absent", f.nativePrepares, f.assigns)
	}
	productIntent := publicDeliveryMap(readIntent("product"))
	d.productRequest = fixtureRaw(map[string]any{"formatVersion": 1, "requestId": f.selected.GrantRequestID, "stage": "product", "preparationPolicy": prepareEnvelope, "policy": sourceSigned(t, d.operator, "source_independent_operator", productIntent["payload"]), "policyBinding": sourceSigned(t, d.operator, "source_independent_operator", productIntent["policyBinding"])})
	d.writeOriginal(t, filepath.Join(d.tree, "child-product-policy-request-"+f.handle.HandleID+".json"), d.productRequest, 0400)
	pass()
	raw, err := os.ReadFile(filepath.Join(d.evidence, "child-activation-intent-"+f.handle.HandleID+".json"))
	if err != nil {
		t.Fatal("normal Authorization activation basis missing", err)
	}
	activationIntent := publicDeliveryMap(json.RawMessage(raw))
	d.activationRequest = fixtureRaw(map[string]any{"formatVersion": 1, "requestId": f.selected.GrantRequestID, "activation": sourceSigned(t, d.operator, "source_independent_operator", activationIntent["payload"]), "authorizationObservation": activationIntent["authorizationObservation"]})
	d.writeOriginal(t, filepath.Join(d.tree, "child-activation-request-"+f.handle.HandleID+".json"), d.activationRequest, 0400)
	pass()
	before := publicDeliveryMap(d.calls)
	pass()
	if !reflect.DeepEqual(before, publicDeliveryMap(d.calls)) {
		t.Fatal("settled delivery reissued HTTP signing/owning calls", before, d.calls)
	}
	if f.nativeExecutes != 0 || d.calls["product-policies"] != 2 || d.calls["grant-intents"] != 1 || d.calls["activation-intents"] != 1 || d.calls["activations"] != 1 || d.calls["authorization-native"] != 1 || d.calls["product-control-publications"] != 1 {
		t.Fatal("fresh child normal policy/Authorization/activation/publication absent", d.calls)
	}
	for _, step := range []string{"prepare-policy", "prepare-control-publication", "product-policy", "grant-intent", "authorization-originals", "authorization-observation", "activation-intent", "activation", "execute-control-publication"} {
		claim, err := f.r.Store.OwnedContinuationClaim(context.Background(), f.handle.HandleID, step)
		if err != nil || len(claim) == 0 {
			t.Fatal("normal delivery did not own durable step", step, err)
		}
		if result, err := f.r.Store.OwnedContinuationResult(context.Background(), f.handle.HandleID, step, claim); err != nil || len(result) == 0 {
			t.Fatal("normal delivery completion UNKNOWN", step, err)
		}
	}
	if !bytes.Equal(fixtureRaw(publicDeliveryMap(d.accepted["product"])["preparationPolicy"]), prepareEnvelope) {
		t.Fatal("PRODUCT changed earlier signed preparation envelope")
	}
	if err := os.WriteFile(filepath.Join(d.root, "public-delivery-result.json"), fixtureRaw(map[string]any{"evidenceClass": "source", "calls": d.calls, "nativePrepareCount": f.nativePrepares, "nativeExecuteCount": f.nativeExecutes, "operatorPublicSHA256": qualification.Digest(d.operatorPEM), "producerPublicSHA256": d.app.Producer.KeySHA256, "limits": []string{"SOURCE root UID/root-write compiler supplier", "prepared parent and accepted parent output SOURCE upstream fixtures", "qualified/installed/native header/Authorization/backend commitment SOURCE suppliers", "no provider or installed all-four acceptance"}}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("SOURCE normal public-delivery gate crossed; ordinary V3 execute/terminal remains covered separately by r328, not rerun")
}
