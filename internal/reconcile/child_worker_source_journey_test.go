package reconcile

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/api"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// This extends the normal V3 execute journey. The signed control is freshly
// generated SOURCE, not backend publication. Installed-owner exports, ROOT
// adoption and native execution are explicit SOURCE suppliers; TLS and SQLite
// are real. No production verifier receives a SOURCE switch.
type workerExecuteSource struct {
	t                         *testing.T
	root                      string
	integrator                bool
	integrationBodies         map[string][]byte
	targetGets, stages, seals int
	fixture                   struct {
		AuthoritySynthetic    bool                              `json:"authoritySynthetic"`
		LiveAuthorized        bool                              `json:"liveAuthorized"`
		WorkerSourceBoundary  bool                              `json:"workerSourceBoundary"`
		Execute               json.RawMessage                   `json:"execute"`
		Witness               qualification.ChildProductWitness `json:"witness"`
		PrepareEntry          model.CellServiceV3               `json:"prepareEntry"`
		OperatorPEM           []byte                            `json:"operatorPEM"`
		WorkerSourceBytes     []byte                            `json:"workerSourceBytes"`
		WorkerSourceReference model.ControllerPlanReference     `json:"workerSourceReference"`
		IntegrationOriginals  struct {
			TargetDetail json.RawMessage
			Artifact     json.RawMessage
			Reference    model.ControllerPlanReference
			TargetBase64 []byte
			PacketBase64 []byte
		}
		ManagerSourceApplication struct {
			Operation model.WorkspaceApplicationOperation
			Envelope  json.RawMessage
		}
		ProducerPrivatePEM []byte `json:"producerPrivatePEM"`
	}
	delivery                                     model.ChildProductDelivery
	facts                                        model.ChildProductOriginalFacts
	adopted, exported, selected                  int
	allowRead                                    bool
	sourceNodeToken                              string // Empty preserves the original worker/integrator client.
	operations, reads, proofs, reports, retained int
	op                                           model.WorkflowCaptureOperation
	envelope                                     model.WorkflowObservationEnvelope
	receipt                                      model.WorkflowObservationReceipt
	snapshot                                     json.RawMessage
}
type workerExecuteSourceControl struct {
	*cellTestControl
	client api.Client
	source *workerExecuteSource
}

func (c *workerExecuteSourceControl) ChildProductControl(ctx context.Context, id string) (model.ChildProductDelivery, error) {
	return c.client.ChildProductControl(ctx, id)
}

func (c *workerExecuteSourceControl) ChildProductFacts(context.Context, string) (model.ChildProductOriginalFacts, error) {
	return c.source.facts, nil
}

type workerExecuteSourceRuntime struct {
	*cellTestRuntime
	source *workerExecuteSource
}

func (*workerExecuteSourceRuntime) NeedsCellProductControl(context.Context, model.Sandbox, model.CellServiceV3) (bool, error) {
	return true, nil
}
func (r *workerExecuteSourceRuntime) ExportCellProductFacts(_ context.Context, entry model.CellServiceV3, current model.Manifest, a qualification.ChildProductAuthorityFacts, i qualification.ChildProductInstalledFacts, l qualification.ChildProductLifecycleFacts, input []byte) error {
	s := r.source
	if model.WorkspaceDigest(entry) != model.WorkspaceDigest(s.fixture.Witness.Entry) || !bytes.Equal(input, s.fixture.Witness.Input) || a.Root.RuntimeRevision != current.DesiredRevision || l.ActualReceipt == nil {
		return errors.New("SOURCE owner export changed")
	}
	s.exported++
	return nil
}
func (r *workerExecuteSourceRuntime) AdoptCellProductControl(_ context.Context, _ model.Sandbox, entry model.CellServiceV3, _ model.Manifest, d model.ChildProductDelivery, input []byte) (string, error) {
	s := r.source
	if err := s.verifyPublishedSource(entry, d, input); err != nil {
		return "", err
	}
	s.adopted++
	return d.GenerationDigest(), nil
}
func (s *workerExecuteSource) verifyPublishedSource(entry model.CellServiceV3, d model.ChildProductDelivery, input []byte) error {
	if !bytes.Equal(d.Bytes(), s.delivery.Bytes()) || !bytes.Equal(input, s.fixture.Witness.Input) || model.WorkspaceDigest(entry) != model.WorkspaceDigest(s.fixture.Witness.Entry) || s.exported == 0 {
		return errors.New("SOURCE adoption changed")
	}
	// Verify the actual original generated envelope signatures. This does not
	// stand in for the protected Store or independently installed owner checks.
	var wire struct {
		Generation struct{ PreparationPolicy, Demand, PolicyBinding, Policy, Activation json.RawMessage }
	}
	if json.Unmarshal(d.Bytes(), &wire) != nil {
		return errors.New("SOURCE generation")
	}
	block, _ := pem.Decode(s.fixture.OperatorPEM)
	if block == nil {
		return errors.New("SOURCE public key")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	key, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("SOURCE key type")
	}
	for _, raw := range []json.RawMessage{wire.Generation.PreparationPolicy, wire.Generation.Demand, wire.Generation.PolicyBinding, wire.Generation.Policy, wire.Generation.Activation} {
		var e struct {
			Payload   json.RawMessage
			Signature string
		}
		if json.Unmarshal(raw, &e) != nil {
			return errors.New("SOURCE envelope")
		}
		canonical, err := model.WorkspaceCanonicalJSON(e.Payload)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(canonical)
		sig, err := base64.StdEncoding.Strict().DecodeString(e.Signature)
		if err != nil || !ecdsa.VerifyASN1(key, sum[:], sig) {
			return errors.New("SOURCE original signature")
		}
	}
	return nil
}
func (r *workerExecuteSourceRuntime) ApprovedCellProductSourceReads(_ context.Context, _ model.Sandbox, _ model.CellServiceV3, _ model.Manifest, _ []byte) ([]qualification.ChildApprovedSourceRead, error) {
	s := r.source
	s.selected++
	if s.adopted == 0 {
		return nil, errors.New("SOURCE read before adoption")
	}
	if !s.allowRead {
		return nil, errors.New("SOURCE own source read unavailable")
	}
	return []qualification.ChildApprovedSourceRead{{Reference: s.fixture.WorkerSourceReference, ByteCount: len(s.fixture.WorkerSourceBytes)}}, nil
}

func testCellV3PublishedWorkerSourceBeforeDispatch(t *testing.T) {
	testCellV3PublishedSourceBeforeDispatch(t, false)
}

func testCellV3PublishedIntegratorSourceBeforeDispatch(t *testing.T) {
	testCellV3PublishedSourceBeforeDispatch(t, true)
}

func testCellV3PublishedSourceBeforeDispatch(t *testing.T, integrator bool) {
	base := os.Getenv("WARPMETAL_PRODUCT_SOURCE_EVIDENCE")
	predecessor := os.Getenv("WARPMETAL_REVISION13_OUTPUT_PACKET")
	if base == "" || predecessor == "" {
		t.Fatal("requires explicit retained SOURCE evidence and existing revision13 supplier")
	}
	root, err := os.MkdirTemp(base, "normal-worker-source-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained SOURCE_PRIVATE_ARTIFACTS", root)
	packet := filepath.Join(root, "fixture.json")
	args := []string{"-B", "../qualification/testdata/child_product_boundary_fixture.py", "../workflowcontract/schema", predecessor, packet, "--flash-provider-boundary", "--coding-result-boundary", "--worker-source-read-boundary"}
	if integrator {
		args = append(args[:6], "--integration-result-boundary", "--integration-delivery-boundary")
	}
	cmd := exec.Command("python3", args...)
	if integrator {
		cmd.Env = append(os.Environ(), "WARPMETAL_INTEGRATOR_MANAGER_SOURCE=1")
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh SOURCE fixture: %v %s", err, out)
	}
	s := &workerExecuteSource{t: t, root: root, integrator: integrator, integrationBodies: map[string][]byte{}, snapshot: fixtureRaw(map[string]any{"explicitSourceSnapshot": "before worker dispatch"})}
	raw, err := os.ReadFile(packet)
	if err != nil || json.Unmarshal(raw, &s.fixture) != nil || !s.fixture.AuthoritySynthetic || s.fixture.LiveAuthorized || (!integrator && !s.fixture.WorkerSourceBoundary) {
		t.Fatal("SOURCE fixture classification")
	}
	s.delivery, err = model.DecodeChildProductDelivery(s.fixture.Execute)
	if err != nil {
		t.Fatal(err)
	}
	w := s.fixture.Witness
	entry := w.Entry
	// These prospective owner DTOs are explicitly detached SOURCE suppliers;
	// they are not represented as independently observed backend owner facts.
	a := qualification.ChildProductAuthorityFacts{OperatorKeyID: w.OperatorKeyID, QualifiedApplicability: w.QualifiedApplicability, Qualification: w.Qualification, Case: w.Case, Scope: w.Scope, Intent: w.Intent, Handle: w.Handle, Root: w.Root, SigningNotBefore: w.SigningNotBefore, ProductSigningNotBefore: w.ProductSigningNotBefore, ActivationSigningNotBefore: w.ActivationSigningNotBefore, AuthorizedUntil: w.AuthorizedUntil, AcceptedPreparationEnvelope: w.AcceptedPreparationEnvelope, AcceptedDemandEnvelope: w.AcceptedDemandEnvelope}
	i := qualification.ChildProductInstalledFacts{EvidenceClass: "source", ConfigDigest: entry.ConfigDigest, Applicability: w.Applicability, ProducerPEM: w.ProducerPEM}
	l := qualification.ChildProductLifecycleFacts{ActualReceipt: w.ActualReceipt, Binding: w.Binding, Assignment: w.Assignment, Grant: w.Grant, Authorization: w.Authorization, ReviewReads: w.ReviewReads, ReviewCompilation: w.ReviewCompilation}
	s.facts, err = model.DecodeChildProductOriginalFacts(fixtureRaw(map[string]any{"formatVersion": 1, "preparationId": entry.PreparationID, "phase": "execute", "generationDigest": s.delivery.GenerationDigest(), "authority": a, "installed": i, "lifecycle": l}))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") == "Bearer SOURCE_node" && (s.serveIntegrationTarget(rw, req) || s.serveObservation(rw, req)) {
			return
		}
		if req.Method != "GET" || req.URL.Path != "/internal/runtime/workspace-workflow/child-preparations/"+entry.PreparationID+"/product-control" || req.Header.Get("Authorization") != "Bearer SOURCE_node" {
			t.Error("unexpected SOURCE delivery transport")
			http.Error(rw, "refused", 403)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write(s.fixture.Execute)
	}))
	defer server.Close()
	control := &workerExecuteSourceControl{cellTestControl: &cellTestControl{instruction: model.ManagedServiceInstructionV1{InstructionRevision: entry.Instructions.InstructionRevision, InstructionDigest: entry.Instructions.InstructionDigest, Content: string(w.Input), ExpiresAt: time.Now().Add(time.Minute)}}, client: api.Client{Origin: server.URL, NodeToken: "SOURCE_node", HTTP: server.Client()}, source: s}
	dbPath := filepath.Join(root, "runtime.sqlite3")
	store, err := state.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	ctx := context.Background()
	if err = store.PutCellV3Operation(ctx, state.LocalCellV3Operation{Entry: s.fixture.PrepareEntry, Phase: "pending"}); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "work")
	if err = store.PutCellV3NativeContext(ctx, s.fixture.PrepareEntry, "ses_source_parent", work); err != nil {
		t.Fatal(err)
	}
	if err = store.UpdateCellV3Operation(ctx, state.LocalCellV3Operation{Entry: s.fixture.PrepareEntry, Phase: "reported", Receipt: *w.ActualReceipt, PreparedReceiptDigest: w.ActualReceipt.PreparedReceiptDigest}); err != nil {
		t.Fatal(err)
	}
	setup := model.SetupOperation{ID: entry.Profile.SetupOperationID, SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration, ProfileID: entry.Profile.ProfileID, ProfileRevision: entry.Profile.ProfileRevision, ProfileDigest: entry.Profile.ProfileDigest}
	seedReadyProfile(t, store, setup)
	if err = store.PutSandbox(ctx, state.LocalSandbox{ID: entry.SandboxID, Generation: entry.SandboxGeneration, ObservedGeneration: entry.SandboxGeneration, ObservedState: "running", ImageDigest: w.Applicability.Sandbox.RegistryManifestDigest}); err != nil {
		t.Fatal(err)
	}
	seedCellProjectForServer(t, store, cellV2View(entry), work, w.Applicability.ServerID)
	outcome := "succeeded"
	result := managedCellResultV1{SchemaVersion: 1, Status: "applied", RuntimeContractVersion: model.CellExecutionContractVersion, OperationID: entry.LaunchOperationID, SessionID: entry.NativeSessionID, MessageID: entry.ExecutionGrant.InputID, State: "terminal", Outcome: &outcome, Attempt: entry.Attempt}
	response := jsonMap(t, result)
	response["guardReceipt"] = map[string]any{"formatVersion": 1, "sessionID": entry.NativeSessionID, "inboxID": entry.ExecutionGrant.InputID, "guardID": entry.ExecutionGrant.GrantID, "bindingDigest": w.ActualReceipt.BindingDigest, "state": "delivered", "admittedAt": 1, "availableAt": 2, "settledAt": nil, "refusalCode": nil, "logCursor": 2}
	runtime := &workerExecuteSourceRuntime{cellTestRuntime: &cellTestRuntime{started: true, result: fixtureRaw(response)}, source: s}
	r := newCellReconciler(t, store, control, runtime)
	if integrator {
		r.ManagedRuntime = &integratorExecuteSourceRuntime{workerExecuteSourceRuntime: runtime}
	}
	r.Now = time.Now
	current := model.Manifest{ServerID: w.Applicability.ServerID, DesiredRevision: w.Root.RuntimeRevision, CellEntriesV3: []model.CellServiceV3{entry}}
	if integrator {
		seedIntegratorSourceApplication(t, r, s, &current)
	}
	r.setCurrentAuthority(current)
	err = r.reconcileCellServiceV3ExecuteCurrent(ctx, entry, &current)
	execution, readErr := store.CellV3Execution(ctx, entry.PreparationID)
	if err == nil || readErr != nil || execution != nil || len(runtime.calls) != 0 || s.adopted != 1 || (!integrator && s.selected != 1) {
		t.Fatalf("missing own source read did not block before native claim: err=%v execution=%v nativeCalls=%d adopted=%d selected=%d", err, execution != nil, len(runtime.calls), s.adopted, s.selected)
	}
	// The original signed input/control remains unchanged. Catalog metadata and
	// signing are SOURCE suppliers; actual whole source bytes are read below.
	reference, body := s.fixture.WorkerSourceReference, s.fixture.WorkerSourceBytes
	if integrator {
		target := s.integrationTarget()
		for _, read := range target.Reads {
			if read.Reference != target.Reference {
				reference = read.Reference
				body = s.fixture.IntegrationOriginals.PacketBase64
				s.integrationBodies[reference.Path] = body
			}
		}
		s.integrationBodies[target.Reference.Path] = s.fixture.IntegrationOriginals.TargetBase64
		if err := os.MkdirAll(filepath.Join(work, filepath.Dir(target.Reference.Path)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	leaf := filepath.Join(work, reference.Path)
	if os.MkdirAll(filepath.Dir(leaf), 0700) != nil || os.WriteFile(leaf, body, 0600) != nil {
		t.Fatal("SOURCE file provision")
	}
	info, err := os.Stat(work)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	project := workspacecatalog.RegisteredProject{Report: model.ProjectCatalogReportV1{FormatVersion: 1, SelectionID: entry.Workspace.SelectionID, ProjectID: entry.Workspace.ProjectID, WorkspaceEpoch: entry.Workspace.WorkspaceEpoch, SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration, RootAttestation: entry.Workspace.RootAttestation, Availability: "available"}, HostRoot: work, ContainerRoot: work, ScopeRevision: entry.Workspace.ScopeRevision, RootDevice: uint64(stat.Dev), RootInode: stat.Ino}
	for _, raw := range w.SourceRoots {
		var source struct{ RegisteredSourceID string }
		_ = json.Unmarshal(raw, &source)
		if err = store.PutContinuitySource(ctx, state.LocalContinuitySource{Report: model.ContinuitySourceReportV1{FormatVersion: 1, RegisteredSourceID: source.RegisteredSourceID, Availability: "available", ProjectID: entry.Workspace.ProjectID, WorkspaceEpoch: entry.Workspace.WorkspaceEpoch, ScopeRevision: entry.Workspace.ScopeRevision, SandboxID: entry.SandboxID, SandboxGeneration: entry.SandboxGeneration}, Root: work, Instance: entry.Instance, Lifecycle: "running", LifecycleRevision: 1}); err != nil {
			t.Fatal(err)
		}
	}
	r.ManagedCatalog = workerSourceCatalog{Catalog: &workspacecatalog.Catalog{State: store}, project: project}
	s.allowRead = true
	count := 1
	if integrator {
		count = 2
	}
	runtime.onCall = func() {
		if s.retained != count || s.reports != count || s.reads != count || (integrator && (s.stages != 1 || s.seals != 1 || s.targetGets != 2)) {
			t.Fatal("native dispatched before exact own ACK")
		}
		if integrator {
			if err := os.WriteFile(filepath.Join(work, s.fixture.IntegrationOriginals.Reference.Path), []byte("SOURCE integrator after-image\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = r.reconcileCellServiceV3ExecuteCurrent(ctx, entry, &current); err != nil {
		t.Fatal("SOURCE own read did not release exact native dispatch", err)
	}
	if len(runtime.calls) != 1 || s.operations != count || s.reads != count || s.proofs != count || s.reports != count || s.retained != count || (integrator && (s.stages != 1 || s.seals != 1 || s.targetGets != 2)) {
		t.Fatalf("SOURCE source dispatch counts: native=%d op=%d read=%d proof=%d report=%d retain=%d", len(runtime.calls), s.operations, s.reads, s.proofs, s.reports, s.retained)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	r.Store = store
	s.snapshot = fixtureRaw(map[string]any{"explicitSourceSnapshot": "after worker terminal"})
	if err = r.reconcileCellServiceV3ExecuteCurrent(ctx, entry, &current); err != nil {
		t.Fatal("SOURCE same SQLite reopen", err)
	}
	if len(runtime.calls) != 1 || s.operations != count || s.reads != count || s.proofs != count || s.reports != count || s.retained != count || (integrator && (s.stages != 1 || s.seals != 1 || s.targetGets != 2)) {
		t.Fatal("SOURCE reopen repeated a read/report/dispatch")
	}
	t.Log("normal PRODUCT SOURCE adoption; actual TLS/SQLite/file bytes; first own SOURCE proof+ACK before one native SOURCE dispatch; same SQLite reopen no repeated effects; protected ROOT/backend publication/native proof not claimed")
}
