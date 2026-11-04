package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workflowcontract"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/qualification"
)

// Same normal V3 SOURCE journey, a separately signed integrator successor. This
// workload is deliberately not primary coding; an unrelated worker read denial
// cannot serve as the integrator preprompt oracle.
type integratorExecuteSourceRuntime struct{ *workerExecuteSourceRuntime }

func (r *integratorExecuteSourceRuntime) ApprovedCellProductSourceReads(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte) ([]qualification.ChildApprovedSourceRead, error) {
	if r.source.adopted == 0 {
		return nil, errors.New("SOURCE integrator before adoption")
	}
	return nil, qualification.ErrWorkerSourceNotApplicable
}

func (s *workerExecuteSource) integrationTarget() qualification.ChildIntegrationTarget {
	var wire struct {
		Generation qualification.ChildProductGeneration
	}
	if err := json.Unmarshal(s.fixture.Execute, &wire); err != nil {
		s.t.Fatal(err)
	}
	target, err := (qualification.ChildProductControl{Generation: wire.Generation}).IntegrationTarget()
	if err != nil {
		s.t.Fatal(err)
	}
	return target
}
func (r *integratorExecuteSourceRuntime) IntegrationCellProductTarget(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte) (qualification.ChildIntegrationTarget, error) {
	s := r.source
	s.selected++
	if s.adopted == 0 || !s.allowRead {
		return qualification.ChildIntegrationTarget{}, errors.New("SOURCE own integration custody unavailable")
	}
	return s.integrationTarget(), nil
}
func (c *workerExecuteSourceControl) ReadWorkflowResult(ctx context.Context, target json.RawMessage, lease string) (json.RawMessage, error) {
	return c.client.ReadWorkflowResult(ctx, target, lease)
}
func (c *workerExecuteSourceControl) FetchWorkflowArtifact(ctx context.Context, id string, ref json.RawMessage, lease string) ([]byte, error) {
	return c.client.FetchWorkflowArtifact(ctx, id, ref, lease)
}
func (s *workerExecuteSource) serveIntegrationTarget(w http.ResponseWriter, r *http.Request) bool {
	if !s.integrator || r.Method != "GET" || r.Header.Get("X-WarpMetal-Workflow-Lease") != "wfl_source_manager" {
		return false
	}
	var target struct{ ResultID string }
	var artifact struct{ ArtifactID, Digest, ContentType string }
	var binding struct{ ExecutionID string }
	_ = json.Unmarshal(s.integrationTarget().Target, &target)
	_ = json.Unmarshal(s.fixture.IntegrationOriginals.Artifact, &artifact)
	_ = json.Unmarshal(s.fixture.Witness.Binding, &binding)
	switch r.URL.Path {
	case "/internal/runtime/workspace-workflow/results/" + target.ResultID:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.fixture.IntegrationOriginals.TargetDetail)
	case "/internal/runtime/workspace-workflow/executions/" + binding.ExecutionID + "/artifacts/" + artifact.ArtifactID:
		w.Header().Set("Content-Type", artifact.ContentType)
		w.Header().Set("X-Content-Digest", artifact.Digest)
		_, _ = w.Write(s.fixture.IntegrationOriginals.TargetBase64)
	default:
		return false
	}
	s.targetGets++
	return true
}

// Deliberately detached SOURCE stage supplier: the confined production writer
// has its own same signed Store boundary. No ROOT/key/admission is substituted.
func (r *integratorExecuteSourceRuntime) StageCellProductIntegrationTarget(_ context.Context, _ model.Sandbox, _ model.CellServiceV3, _ model.Manifest, _ []byte, root qualification.TrustedWorkspace, detail json.RawMessage, body []byte) error {
	s := r.source
	if s.targetGets != 2 || model.WorkspaceDigest(detail) != model.WorkspaceDigest(s.fixture.IntegrationOriginals.TargetDetail) || !bytes.Equal(body, s.fixture.IntegrationOriginals.TargetBase64) {
		return errors.New("SOURCE target transport changed")
	}
	f, err := os.OpenFile(filepath.Join(root.HostRoot, s.fixture.IntegrationOriginals.Reference.Path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(body); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	s.stages++
	return nil
}
func (r *integratorExecuteSourceRuntime) ReadCellProductIntegrationSource(ctx context.Context, box model.Sandbox, entry model.CellServiceV3, current model.Manifest, input []byte, root qualification.TrustedWorkspace, call model.WorkflowCaptureRequest, op model.WorkflowCaptureOperation, snapshot json.RawMessage) (model.WorkflowObservationEnvelope, qualification.WorkflowSourceCapture, error) {
	if r.source.stages != 1 {
		return model.WorkflowObservationEnvelope{}, qualification.WorkflowSourceCapture{}, errors.New("SOURCE integration read before stage")
	}
	return r.ReadCellProductApprovedSource(ctx, box, entry, current, input, root, call, op, snapshot)
}
func (r *integratorExecuteSourceRuntime) RetainCellProductIntegrationSourceRead(_ context.Context, _ model.Sandbox, _ model.CellServiceV3, _ model.Manifest, _ []byte, envelope model.WorkflowObservationEnvelope, read qualification.WorkflowSourceCapture, receipt model.WorkflowObservationReceipt) error {
	s := r.source
	var request struct {
		Observation struct{ Reference model.ControllerPlanReference }
	}
	if json.Unmarshal(envelope.Payload.Request, &request) != nil || model.WorkspaceDigest(envelope) != model.WorkspaceDigest(s.envelope) || receipt != s.receipt || !bytes.Equal(read.Bytes, s.integrationBodies[request.Observation.Reference.Path]) {
		return errors.New("SOURCE own integrator ACK changed")
	}
	raw := fixtureRaw(qualification.ChildSourceReadOriginal{Envelope: envelope, Receipt: receipt})
	f, err := os.OpenFile(filepath.Join(s.root, "integration-own-"+model.WorkspaceDigest(request.Observation.Reference)[7:]+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	s.retained++
	return nil
}
func (r *integratorExecuteSourceRuntime) ReadCellProductIntegrationSourceReceipts(context.Context, model.Sandbox, model.CellServiceV3, model.Manifest, []byte) ([]qualification.ChildSourceReadOriginal, error) {
	s := r.source
	out := []qualification.ChildSourceReadOriginal{}
	for _, read := range s.integrationTarget().Reads {
		raw, err := os.ReadFile(filepath.Join(s.root, "integration-own-"+model.WorkspaceDigest(read.Reference)[7:]+".json"))
		if err != nil {
			return nil, err
		}
		var original qualification.ChildSourceReadOriginal
		if json.Unmarshal(raw, &original) != nil {
			return nil, errors.New("SOURCE first ACK decode")
		}
		out = append(out, original)
	}
	return out, nil
}
func (r *integratorExecuteSourceRuntime) SealCellProductIntegrationDelivery(_ context.Context, _ model.Sandbox, _ model.CellServiceV3, _ model.Manifest, _ []byte, root qualification.TrustedWorkspace) error {
	s := r.source
	raw, err := os.ReadFile(filepath.Join(root.HostRoot, s.fixture.IntegrationOriginals.Reference.Path))
	if err != nil || s.retained != 2 || !bytes.Equal(raw, s.fixture.IntegrationOriginals.TargetBase64) {
		return errors.New("SOURCE seal lacks first ACK/before bytes")
	}
	s.seals++
	return nil
}

func seedIntegratorSourceApplication(t *testing.T, r *Reconciler, s *workerExecuteSource, current *model.Manifest) {
	t.Helper()
	ctx := context.Background()
	op := s.fixture.ManagerSourceApplication.Operation
	if err := op.Validate(); err != nil {
		t.Fatal("SOURCE valid application operation", err)
	}
	if err := workflowcontract.Validate(workflowcontract.Producer, "applicationEnvelope", s.fixture.ManagerSourceApplication.Envelope); err != nil {
		t.Fatal("SOURCE application envelope shape", err)
	}
	if err := r.Store.PutWorkspaceApplication(ctx, op); err != nil {
		t.Fatal(err)
	}
	if err := r.Store.PinWorkspaceApplicationEnvelope(ctx, op.OperationID, s.fixture.ManagerSourceApplication.Envelope); err != nil {
		t.Fatal(err)
	}
	if err := r.Store.AcceptWorkspaceApplication(ctx, op.OperationID, "source_application", s.fixture.ManagerSourceApplication.Envelope); err != nil {
		t.Fatal(err)
	}
	d := op.Dependencies.Roles[0]
	p := model.ControllerParentIntent{FormatVersion: 2, TargetKind: "controller_parent", OperationID: "source_manager_operation", ActionRevision: 1, DesiredRevision: 1, DesiredState: "active", SessionMode: "create_initial", Owner: d.Binding.Owner, Role: d.Binding.Role, ServiceRegistrationID: d.Binding.ServiceRegistrationID, ServiceGeneration: 1, Profile: d.Profile, Instructions: d.Instructions, Workspace: d.Workspace, ApplicationOperationID: op.OperationID, ConnectionRevisionDigest: op.ConnectionRevisionDigest, ModelAuthorityDigest: op.ModelAuthorityDigest, RoleAgentDigest: model.WorkspaceDigest(d.Projection), RuntimeContractVersion: "0.1.52"}
	p.Instance = fmt.Sprintf("parent-manager-%x", sha256.Sum256([]byte(p.ServiceRegistrationID)))[:len("parent-manager-")+12]
	p.ConfigDigest = fixtureDigestField(p, "configDigest")
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := op.ParentDependency(p); err != nil {
		t.Fatal(err)
	}
	current.ParentServices = []model.ControllerParentIntent{p}
	r.firstTaskManagerAuthority = &controllerFirstTaskAuthority{operationDigest: op.OperationDigest, parent: p, applicability: s.fixture.Witness.Applicability, lease: "wfl_source_manager"}
}
