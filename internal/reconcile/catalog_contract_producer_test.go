package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/containers"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// catalogContractProducerInput is a test-only cross-repository protocol. It
// lets the backend HTTP/PostgreSQL producer journey compose its exact manifests
// with Runtime's real persistent workspace catalog instead of inventing
// attestations in either repository.
type catalogContractProducerInput struct {
	Action           string                           `json:"action"`
	StateDirectory   string                           `json:"stateDirectory"`
	WorkspaceRequest *model.ManagedWorkspaceRequestV1 `json:"workspaceRequest"`
	ManagedService   *model.ManagedServiceV1          `json:"managedService"`
	ServerID         string                           `json:"serverId"`
	Version          string                           `json:"version"`
	Sandbox          *catalogProducerSandbox          `json:"sandbox"`
	TeamProject      *model.ManagedWorkspaceRequestV1 `json:"teamProject"`
	Handoff          *catalogProducerHandoff          `json:"handoff"`
	Restore          *catalogProducerRestore          `json:"restore"`
	MaterializeSteps []string                         `json:"materializeSteps"`
	// r734 frozen contract fields (serialized names are authoritative): the
	// complete real backend manifest and one actual active service id ordered
	// before the later stopped services.
	Manifest                   *model.Manifest `json:"manifest"`
	EnrollmentFailureServiceID string          `json:"enrollmentFailureServiceId"`
}

type catalogProducerSandbox struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Generation int64           `json:"generation"`
	Lifetime   string          `json:"lifetime"`
	Resources  model.Resources `json:"resources"`
}

type catalogProducerHandoff struct {
	OperationID           string `json:"operationId"`
	Anchor                string `json:"anchor"`
	ServerID              string `json:"serverId"`
	TeamID                string `json:"teamId"`
	MemberID              string `json:"memberId"`
	SandboxID             string `json:"sandboxId"`
	SandboxGeneration     int64  `json:"sandboxGeneration"`
	ServiceRegistrationID string `json:"serviceRegistrationId"`
}

type catalogProducerRestore struct {
	OperationID       string `json:"operationId"`
	Anchor            string `json:"anchor"`
	ServerID          string `json:"serverId"`
	SandboxID         string `json:"sandboxId"`
	SandboxGeneration int64  `json:"sandboxGeneration"`
}

type catalogContractProducerOutput struct {
	Action          string                         `json:"action"`
	ResolveStatus   string                         `json:"resolveStatus"`
	ScopeRevision   int64                          `json:"scopeRevision"`
	WorkspaceReport model.ProjectCatalogReportV1   `json:"workspaceReport"`
	Report          *model.Report                  `json:"report"`
	CatalogReports  []model.ProjectCatalogReportV1 `json:"catalogReports"`
	HandoffReport   *model.ProjectCatalogReportV1  `json:"handoffReport"`
	RestoreReport   *model.ProjectCatalogReportV1  `json:"restoreReport"`
	CatalogPhases   map[string]string              `json:"catalogPhases"`
	// r734 frozen contract outputs for managed-stop-after-active-failure.
	ManagedServiceReports []model.ManagedServiceReportV1 `json:"managedServiceReports"`
	AppliedRevision       int64                          `json:"appliedRevision"`
	ReconcileFatal        string                         `json:"reconcileFatal"`
	StopInvocations       int                            `json:"stopInvocations"`
}

func TestManagedWorkspaceCatalogContractProducer(t *testing.T) {
	inputPath := os.Getenv("WARPMETAL_CATALOG_CONTRACT_INPUT")
	outputPath := os.Getenv("WARPMETAL_CATALOG_CONTRACT_OUTPUT")
	if inputPath == "" && outputPath == "" {
		t.Skip("cross-repository catalog producer is not requested")
	}
	if !filepath.IsAbs(inputPath) || !filepath.IsAbs(outputPath) {
		t.Fatal("catalog producer input and output paths must be absolute")
	}

	payload, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	var input catalogContractProducerInput
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		t.Fatal(err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(input.StateDirectory) {
		t.Fatal("catalog producer state directory must be absolute")
	}
	info, err := os.Stat(input.StateDirectory)
	if err != nil || !info.IsDir() {
		t.Fatalf("catalog producer state directory is unavailable: %v", err)
	}

	store, err := state.Open(filepath.Join(input.StateDirectory, "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	catalog := &workspacecatalog.Catalog{State: store, Now: func() time.Time { return time.Now().UTC() }}
	reconciler := &Reconciler{Store: store, ManagedCatalog: catalog}

	var output catalogContractProducerOutput
	switch input.Action {
	case "create":
		if input.WorkspaceRequest == nil || input.ManagedService != nil {
			t.Fatal("create requires only workspaceRequest")
		}
		request := *input.WorkspaceRequest
		// r744: mirror the real Runtime, which anchors each managed project at
		// its own sandbox workspace root (Workspaces.Ensure(sandboxID)), so one
		// state directory can hold the distinct projects of a mixed manifest.
		anchor := filepath.Join(input.StateDirectory, "workspace", request.SandboxID)
		if err := os.MkdirAll(anchor, 0700); err != nil {
			t.Fatal(err)
		}
		project, err := catalog.EnsureDefault(context.Background(), workspacecatalog.DefaultProjectRequest{
			Anchor: anchor, ServerID: request.ServerID, TeamID: request.TeamID, MemberID: request.MemberID,
			SandboxID: request.SandboxID, SandboxGeneration: request.SandboxGeneration,
			ServiceRegistrationID: request.ServiceRegistrationID, AllocationDigest: request.AllocationDigest,
		})
		if err != nil {
			if errors.Is(err, workspacecatalog.ErrProjectChanged) {
				t.Fatalf("create service=%s sandbox=%q generation=%d team=%s anchor=%s allocation=%s: %v",
					request.ServiceRegistrationID, request.SandboxID, request.SandboxGeneration, request.TeamID, anchor, request.AllocationDigest, err)
			}
			t.Fatal(err)
		}
		output = catalogContractProducerOutput{
			Action: "create", ResolveStatus: "created", ScopeRevision: project.ScopeRevision, WorkspaceReport: project.Report,
		}
	case "rebind":
		if input.ManagedService == nil || input.WorkspaceRequest != nil {
			t.Fatal("rebind requires only managedService")
		}
		service := *input.ManagedService
		if _, err := reconciler.resolveManagedProject(context.Background(), service); err == nil ||
			err.Error() != "managed project was rebound; wait for the current catalog attestation" {
			t.Fatalf("first actual managed project resolve = %v, want rebound attestation pending", err)
		}
		record, err := store.ManagedProject(context.Background(), service.Workspace.SelectionID)
		if err != nil || record == nil {
			t.Fatalf("managed project unavailable after rebind: %#v %v", record, err)
		}
		if record.Report.SelectionID != service.Workspace.SelectionID || record.Report.ProjectID != service.Workspace.ProjectID ||
			record.Report.WorkspaceEpoch != service.Workspace.WorkspaceEpoch || record.ConfigDigest != service.ConfigDigest {
			t.Fatal("actual managed project rebind changed identity or omitted config")
		}
		output = catalogContractProducerOutput{
			Action: "rebind", ResolveStatus: "rebound", ScopeRevision: record.ScopeRevision, WorkspaceReport: record.Report,
		}
	case "resolve":
		if input.ManagedService == nil || input.WorkspaceRequest != nil {
			t.Fatal("resolve requires only managedService")
		}
		service := *input.ManagedService
		project, resolveErr := reconciler.resolveManagedProject(context.Background(), service)
		if resolveErr == nil {
			output = catalogContractProducerOutput{
				Action: "resolve", ResolveStatus: "resolved", ScopeRevision: project.ScopeRevision, WorkspaceReport: project.Report,
			}
			break
		}
		record, stateErr := store.ManagedProject(context.Background(), service.Workspace.SelectionID)
		if stateErr != nil || record == nil {
			t.Fatalf("managed project unavailable after failed actual resolve: %#v %v", record, stateErr)
		}
		status := ""
		switch {
		case resolveErr.Error() == "managed project was rebound; wait for the current catalog attestation":
			status = "rebound_attestation_pending"
		case errors.Is(resolveErr, workspacecatalog.ErrProjectChanged):
			catalogTupleMatches := record.Report.ProjectID == service.Workspace.ProjectID &&
				record.Report.WorkspaceEpoch == service.Workspace.WorkspaceEpoch &&
				record.Report.SandboxID == service.Identity.SandboxID &&
				record.Report.SandboxGeneration == service.Identity.SandboxGeneration &&
				record.ConfigDigest == service.ConfigDigest
			if catalogTupleMatches && record.Report.RootAttestation != service.Workspace.RootAttestation {
				status = "root_attestation_mismatch"
			} else {
				status = "project_changed"
			}
		default:
			t.Fatal(resolveErr)
		}
		output = catalogContractProducerOutput{
			Action: "resolve", ResolveStatus: status, ScopeRevision: record.ScopeRevision, WorkspaceReport: record.Report,
		}
	case "materialize-report":
		if input.Sandbox == nil || input.ServerID == "" || input.Handoff == nil || input.Restore == nil ||
			len(input.MaterializeSteps) == 0 {
			t.Fatal("materialize-report requires sandbox, serverId, handoff, restore and materializeSteps")
		}
		sandbox := *input.Sandbox
		if err := store.PutSandbox(context.Background(), state.LocalSandbox{
			ID: sandbox.ID, Name: sandbox.Name, DesiredState: "running", ObservedState: "running",
			Generation: sandbox.Generation, ObservedGeneration: sandbox.Generation,
			Lifetime: sandbox.Lifetime, Resources: sandbox.Resources,
			ImageDigest: "registry.example/sandbox@sha256:" + strings.Repeat("a", 64),
		}); err != nil {
			t.Fatal(err)
		}
		if input.TeamProject != nil {
			anchor := filepath.Join(input.StateDirectory, "workspace")
			if err := os.Mkdir(anchor, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				t.Fatal(err)
			}
			request := *input.TeamProject
			if _, err := catalog.EnsureDefault(context.Background(), workspacecatalog.DefaultProjectRequest{
				Anchor: anchor, ServerID: request.ServerID, TeamID: request.TeamID, MemberID: request.MemberID,
				SandboxID: request.SandboxID, SandboxGeneration: request.SandboxGeneration,
				ServiceRegistrationID: request.ServiceRegistrationID, AllocationDigest: request.AllocationDigest,
			}); err != nil {
				t.Fatal(err)
			}
		}
		handoffRequest := workspacecatalog.HandoffProjectRequest{
			OperationID: input.Handoff.OperationID, Anchor: input.Handoff.Anchor, ServerID: input.Handoff.ServerID,
			TeamID: input.Handoff.TeamID, MemberID: input.Handoff.MemberID, SandboxID: input.Handoff.SandboxID,
			SandboxGeneration: input.Handoff.SandboxGeneration, ServiceRegistrationID: input.Handoff.ServiceRegistrationID,
		}
		restoreRequest := workspacecatalog.RestoreProjectRequest{
			OperationID: input.Restore.OperationID, Anchor: input.Restore.Anchor, ServerID: input.Restore.ServerID,
			SandboxID: input.Restore.SandboxID, SandboxGeneration: input.Restore.SandboxGeneration,
		}
		var handoffReport, restoreReport *model.ProjectCatalogReportV1
		for _, step := range input.MaterializeSteps {
			switch step {
			case "handoff-begin":
				record, err := catalog.BeginHandoffAllocation(context.Background(), handoffRequest)
				if err != nil {
					t.Fatalf("handoff begin: %v", err)
				}
				report := record.Report
				handoffReport = &report
			case "handoff-allocate":
				project, err := catalog.AllocateHandoff(context.Background(), handoffRequest)
				if err != nil {
					t.Fatalf("handoff allocate: %v", err)
				}
				report := project.Report
				handoffReport = &report
			case "handoff-ready":
				project, err := catalog.CompleteHandoff(context.Background(), handoffRequest.OperationID)
				if err != nil {
					t.Fatalf("handoff ready: %v", err)
				}
				report := project.Report
				handoffReport = &report
			case "restore-begin":
				record, err := catalog.BeginRestoreAllocation(context.Background(), restoreRequest)
				if err != nil {
					t.Fatalf("restore begin: %v", err)
				}
				report := record.Report
				restoreReport = &report
			case "restore-allocate":
				project, err := catalog.AllocateRestore(context.Background(), restoreRequest)
				if err != nil {
					t.Fatalf("restore allocate: %v", err)
				}
				report := project.Report
				restoreReport = &report
			case "restore-ready":
				project, err := catalog.CompleteRestore(context.Background(), restoreRequest.OperationID)
				if err != nil {
					t.Fatalf("restore ready: %v", err)
				}
				report := project.Report
				restoreReport = &report
			default:
				t.Fatalf("unsupported materialize step %q", step)
			}
		}
		version := input.Version
		if version == "" {
			version = "0.1.30-catalog-producer"
		}
		report, err := reconciler.Report(context.Background(), input.ServerID, version)
		if err != nil {
			t.Fatalf("runtime report: %v", err)
		}
		catalogReports, err := catalog.Reports(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		projects, err := store.ManagedProjects(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		phases := make(map[string]string, len(projects))
		for _, project := range projects {
			phases[project.Report.SelectionID] = project.Phase
		}
		output = catalogContractProducerOutput{
			Action: "materialize-report", ResolveStatus: "reported",
			Report: &report, CatalogReports: catalogReports,
			HandoffReport: handoffReport, RestoreReport: restoreReport,
			CatalogPhases: phases,
		}
	case "managed-stop-after-active-failure":
		if input.Manifest == nil {
			t.Fatal("managed-stop-after-active-failure requires manifest")
		}
		manifest := *input.Manifest
		serverID := manifest.ServerID
		if serverID == "" {
			t.Fatal("managed-stop-after-active-failure requires manifest.serverId")
		}
		lastRevision, err := store.Revision(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := model.ValidateManifest(manifest, serverID, lastRevision); err != nil {
			t.Fatalf("managed-stop-after-active-failure rejected an invalid manifest: %v", err)
		}
		now := time.Date(2026, 9, 27, 17, 0, 30, 0, time.UTC)
		// Durable RF state comes from the legitimate backend manifest through the
		// same production store paths the reconciler reads.
		for _, setup := range manifest.SetupOperations {
			seedReadyProfile(t, store, setup)
		}
		for _, sandbox := range manifest.Sandboxes {
			if err := store.PutSandbox(context.Background(), state.LocalSandbox{
				ID: sandbox.ID, Name: sandbox.Name, DesiredState: "running", ObservedState: "running",
				Generation: sandbox.Generation, ObservedGeneration: sandbox.Generation,
				Lifetime: sandbox.Lifetime, Resources: sandbox.Resources, ImageDigest: manifest.ImageDigest,
			}); err != nil {
				t.Fatal(err)
			}
		}
		// Workspace records are composed by prior bridge actions; refuse a test
		// setup gap honestly instead of inventing identities or attestations.
		for _, service := range manifest.ManagedServices {
			record, err := store.ManagedProject(context.Background(), service.Workspace.SelectionID)
			if err != nil || record == nil {
				t.Fatalf("managed-stop-after-active-failure requires the workspace record for %s (run the catalog create/resolve bridge action first): %v", service.Identity.ServiceRegistrationID, err)
			}
		}
		fixture := loadProducerFixture(t)
		version := input.Version
		if version == "" {
			version = "0.1.30-catalog-producer"
		}
		runtimeFake := &fakeManagedRuntime{store: store, fixture: fixture}
		control := &bridgeFailingControl{fixture: fixture, failureServiceID: input.EnrollmentFailureServiceID}
		reconciler := &Reconciler{Store: store, ManagedCatalog: catalog, ManagedControl: control, ManagedRuntime: runtimeFake, Now: func() time.Time { return now }}
		_, fatal := reconciler.reconcileManagedServices(context.Background(), manifest)
		appliedRevision, err := store.Revision(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		report, err := reconciler.Report(context.Background(), serverID, version)
		if err != nil {
			t.Fatalf("runtime report: %v", err)
		}
		stopInvocations := 0
		for _, invocation := range runtimeFake.invocations {
			if invocation.action == string(containers.ManagedSupervisorStop) {
				stopInvocations++
			}
		}
		output = catalogContractProducerOutput{
			Action: "managed-stop-after-active-failure", ResolveStatus: "reconciled",
			Report: &report, ManagedServiceReports: report.ManagedServices,
			AppliedRevision: appliedRevision, StopInvocations: stopInvocations,
		}
		if fatal != nil {
			output.ReconcileFatal = fatal.Error()
		}
	default:
		t.Fatalf("unsupported catalog producer action %q", input.Action)
	}

	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(outputPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
}

// bridgeFailingControl is the r734 test-only driver for the
// managed-stop-after-active-failure bridge action under the frozen contract.
// Enrollment fails with the real control-plane-shaped error only for the single
// named active service; every other call uses the captured fixture responses.
// It never fabricates a native idle, a stop receipt or a consumer validation.
type bridgeFailingControl struct {
	fixture          producerFixture
	failureServiceID string
}

func (control *bridgeFailingControl) ManagedServiceEndpoint() string {
	return "https://api.warpmetal.example"
}

func (control *bridgeFailingControl) ManagedServiceEnrollment(_ context.Context, serviceID string, _ model.ManagedServiceFetchRequestV1) (model.ManagedServiceEnrollmentV1, error) {
	if control.failureServiceID != "" && serviceID == control.failureServiceID {
		return model.ManagedServiceEnrollmentV1{}, errors.New("control-plane response 401 (enrollment_rejected)")
	}
	if serviceID != control.fixture.ServiceManifest.Identity.ServiceRegistrationID {
		return model.ManagedServiceEnrollmentV1{}, errors.New("enrollment fixture unavailable for service")
	}
	return control.fixture.EnrollmentResponse, nil
}

func (control *bridgeFailingControl) ManagedServiceInstructions(_ context.Context, serviceID string, _ model.ManagedServiceFetchRequestV1) (model.ManagedServiceInstructionV1, error) {
	if serviceID != control.fixture.ServiceManifest.Identity.ServiceRegistrationID {
		return model.ManagedServiceInstructionV1{}, errors.New("instruction fixture unavailable for service")
	}
	return control.fixture.InstructionResponse, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("catalog producer input contains multiple JSON values")
		}
		return err
	}
	return nil
}
