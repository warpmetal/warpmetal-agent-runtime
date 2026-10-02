package model

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type managedValidationFixture struct {
	SetupManifest            SetupOperation            `json:"setupManifest"`
	WorkspaceRequestManifest ManagedWorkspaceRequestV1 `json:"workspaceRequestManifest"`
	ServiceManifest          ManagedServiceV1          `json:"serviceManifest"`
}

func TestManagedServiceRevisionsAreIndependentOfGlobalManifestRevision(t *testing.T) {
	fixture := loadManagedValidationFixture(t)
	manifest := managedValidationManifest(fixture)
	manifest.DesiredRevision = 91
	if err := ValidateManifest(manifest, manifest.ServerID, 90); err != nil {
		t.Fatalf("independent service revisions rejected: %v", err)
	}
}

func TestTeamOperationMayBeSharedByDistinctMemberServices(t *testing.T) {
	fixture := loadManagedValidationFixture(t)
	manifest := managedValidationManifest(fixture)

	secondSandbox := manifest.Sandboxes[0]
	secondSandbox.ID = "sbx_managedservice00000002"
	secondSandbox.Name = "member-two"
	manifest.Sandboxes = append(manifest.Sandboxes, secondSandbox)
	manifest.Capacity = manifest.Capacity.Add(secondSandbox.Resources)

	secondSetup := fixture.SetupManifest
	secondSetup.ID = "setup-managed-service-0002"
	secondSetup.SandboxID = secondSandbox.ID
	manifest.SetupOperations = append(manifest.SetupOperations, secondSetup)

	secondWorkspace := fixture.WorkspaceRequestManifest
	secondWorkspace.MemberID = "tmem_managedservice0002"
	secondWorkspace.SandboxID = secondSandbox.ID
	secondWorkspace.ServiceRegistrationID = "service_managedservice0002"
	manifest.ManagedWorkspaceRequests = append(manifest.ManagedWorkspaceRequests, secondWorkspace)

	secondService := fixture.ServiceManifest
	secondService.Identity.MemberID = secondWorkspace.MemberID
	secondService.Identity.SandboxID = secondSandbox.ID
	secondService.Identity.ServiceRegistrationID = secondWorkspace.ServiceRegistrationID
	secondService.Profile.SetupOperationID = secondSetup.ID
	secondService.Workspace.SelectionID = "selection_managedservice0002"
	secondService.Workspace.ProjectID = "project_managedservice0002"
	secondService.Workspace.WorkspaceEpoch = "epoch_managedservice0002"
	manifest.ManagedServices = append(manifest.ManagedServices, secondService)

	if err := ValidateManifest(manifest, manifest.ServerID, 0); err != nil {
		t.Fatalf("shared Team operation rejected across distinct services: %v", err)
	}
}

func TestRuntimeConsumesActualBackendWorkspaceServiceAndPauseManifests(t *testing.T) {
	// The HTTP/PostgreSQL lifecycle exports its actual refreshed manifest for
	// the cross-repository gate; the ordinary strict decoder/validator consume it.
	refreshPath := os.Getenv("AGENT_MANAGEMENT_REFRESH_MANIFEST")
	if refreshPath == "" {
		refreshPath = filepath.Join("..", "api", "testdata", "managed-service-refresh-backend-wire.json")
	}
	{
		payload, err := os.ReadFile(refreshPath)
		if err != nil {
			t.Fatal(err)
		}
		var refreshed Manifest
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&refreshed); err != nil {
			t.Fatal(err)
		}
		if err := ValidateManifest(refreshed, "srv_managed-start", 0); err != nil {
			t.Fatalf("actual backend refreshed manifest rejected: %v", err)
		}
	}
	payload, err := os.ReadFile(filepath.Join("..", "api", "testdata", "managed-service-backend-wire.json"))
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Workspace        json.RawMessage `json:"workspaceManifest"`
		Service          json.RawMessage `json:"serviceManifest"`
		Pause            json.RawMessage `json:"pauseManifest"`
		ChangedAuthority json.RawMessage `json:"changedAuthorityManifest"`
	}
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	lastRevision := int64(0)
	for _, item := range []struct {
		name    string
		payload json.RawMessage
	}{{"workspace", wire.Workspace}, {"service", wire.Service}, {"pause", wire.Pause}, {"changed-authority", wire.ChangedAuthority}} {
		t.Run(item.name, func(t *testing.T) {
			var manifest Manifest
			decoder := json.NewDecoder(bytes.NewReader(item.payload))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&manifest); err != nil {
				t.Fatal(err)
			}
			if err := ValidateManifest(manifest, "srv_s1m-wire", lastRevision); err != nil {
				t.Fatalf("actual backend %s manifest rejected: %v", item.name, err)
			}
			lastRevision = manifest.DesiredRevision
		})
	}
}

func loadManagedValidationFixture(t *testing.T) managedValidationFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "api", "testdata", "agent-managed-service-v1.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture managedValidationFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func managedValidationManifest(fixture managedValidationFixture) Manifest {
	resources := Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 128}
	return Manifest{
		ServerID: fixture.ServiceManifest.Identity.ServerID, DesiredRevision: fixture.ServiceManifest.DesiredRevision,
		ImageDigest: "registry.example/sandbox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Capacity:    resources,
		Sandboxes: []Sandbox{{
			ID: fixture.ServiceManifest.Identity.SandboxID, Name: "member-one", Resources: resources,
			Lifetime: "persistent", DesiredState: "running", Generation: fixture.ServiceManifest.Identity.SandboxGeneration,
		}},
		SetupOperations:          []SetupOperation{fixture.SetupManifest},
		ManagedWorkspaceRequests: []ManagedWorkspaceRequestV1{fixture.WorkspaceRequestManifest},
		ManagedServices:          []ManagedServiceV1{fixture.ServiceManifest},
	}
}

func TestRetainedTerminalServiceToleratesAdvancedSandboxGeneration(t *testing.T) {
	fixture := loadManagedValidationFixture(t)
	manifest := managedValidationManifest(fixture)
	if len(manifest.ManagedServices) != 1 {
		t.Fatalf("fixture services = %d", len(manifest.ManagedServices))
	}
	// A terminal service retained after its box generation has advanced: the
	// generation filter has already removed its profile setup operation, so
	// the generation equality and profile equality checks can no longer hold.
	manifest.ManagedServices[0].DesiredState = "stopped"
	manifest.ManagedServices[0].SessionMode = "lookup_only"
	manifest.Sandboxes[0].Generation++
	manifest.Sandboxes[0].DesiredState = "deleted"
	manifest.SetupOperations = nil
	manifest.ManagedWorkspaceRequests = nil
	if err := ValidateManifest(manifest, manifest.ServerID, 0); err != nil {
		t.Fatalf("retained terminal stale-generation service rejected: %v", err)
	}
	// The tolerance must not extend to an active service.
	active := manifest
	active.ManagedServices = append([]ManagedServiceV1(nil), manifest.ManagedServices...)
	active.ManagedServices[0].DesiredState = "active"
	active.ManagedServices[0].SessionMode = "create_initial"
	if err := ValidateManifest(active, active.ServerID, 0); err == nil {
		t.Fatal("active stale-generation service without its profile was tolerated")
	}
	// Nor to a terminal service that still sits on the current generation.
	current := manifest
	current.ManagedServices = append([]ManagedServiceV1(nil), manifest.ManagedServices...)
	current.Sandboxes = append([]Sandbox(nil), manifest.Sandboxes...)
	current.Sandboxes[0].Generation = current.ManagedServices[0].Identity.SandboxGeneration
	if err := ValidateManifest(current, current.ServerID, 0); err == nil {
		t.Fatal("terminal current-generation service without its profile was tolerated")
	}
	// Only an entirely absent profile operation is tolerated for the retained
	// case; a present but mismatched profile stays strict.
	mismatched := manifest
	mismatched.ManagedServices = append([]ManagedServiceV1(nil), manifest.ManagedServices...)
	consistentSetup := fixture.SetupManifest
	consistentSetup.SandboxGeneration = manifest.Sandboxes[0].Generation
	mismatched.SetupOperations = []SetupOperation{consistentSetup}
	mismatched.ManagedServices[0].Profile.ProfileDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if err := ValidateManifest(mismatched, mismatched.ServerID, 0); err == nil {
		t.Fatal("present mismatched profile was tolerated for a retained terminal service")
	}
	// Identity checks stay strict for the retained case as well.
	foreign := manifest
	foreign.ManagedServices = append([]ManagedServiceV1(nil), manifest.ManagedServices...)
	foreign.ManagedServices[0].Identity.Instance = "replica"
	if err := ValidateManifest(foreign, foreign.ServerID, 0); err == nil {
		t.Fatal("retained terminal service with a foreign identity was tolerated")
	}
}
