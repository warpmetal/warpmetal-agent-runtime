package model

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The frozen backend fixture pairs a continuity registration whose
// identity.expectedRevision is the Work record revision (1) with operation
// records carrying the same Work fence. A runtime manifest's DesiredRevision
// is an unrelated server-wide generation and must never be compared with it.
type continuityRevisionFixture struct {
	Registration ContinuityRegistrationV1 `json:"registrationManifest"`
	Operation    ContinuityOperationV1    `json:"operationManifest"`
}

func loadContinuityRevisionFixture(t *testing.T) continuityRevisionFixture {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "api", "testdata", "agent-continuity-v1.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture continuityRevisionFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func continuityRevisionManifest(fixture continuityRevisionFixture) Manifest {
	resources := Resources{CPUMillicores: 500, MemoryMiB: 1024, WorkspaceDiskGiB: 10, PIDs: 256}
	return Manifest{
		ServerID:        "srv_continuity0001",
		DesiredRevision: 30,
		ImageDigest:     "registry.example/sandbox@sha256:" + strings.Repeat("a", 64),
		Capacity:        Resources{CPUMillicores: 1000, MemoryMiB: 2048, WorkspaceDiskGiB: 20},
		Sandboxes: []Sandbox{{
			ID: fixture.Operation.Identity.SandboxID, Name: "continuity-worker", Size: "small",
			Resources: resources, Lifetime: "persistent", DesiredState: "running",
			Generation: fixture.Operation.Identity.SandboxGeneration,
		}},
		ContinuityRegistrations: []ContinuityRegistrationV1{fixture.Registration},
		ContinuityOperations:    []ContinuityOperationV1{fixture.Operation},
	}
}

func TestContinuityRegistrationWorkRevisionIsIndependentOfManifestRevision(t *testing.T) {
	fixture := loadContinuityRevisionFixture(t)
	if fixture.Registration.Identity.ExpectedRevision != 1 {
		t.Fatalf("frozen backend fixture work revision = %d, want 1", fixture.Registration.Identity.ExpectedRevision)
	}
	manifest := continuityRevisionManifest(fixture)
	if manifest.DesiredRevision != 30 {
		t.Fatalf("test manifest revision = %d, want 30", manifest.DesiredRevision)
	}
	if err := ValidateManifest(manifest, manifest.ServerID, 29); err != nil {
		t.Fatalf("Work revision 1 under manifest revision 30 was rejected: %v", err)
	}
	// Advancing an unrelated server revision must preserve the same Work,
	// binding and registration identity.
	manifest.DesiredRevision = 31
	if err := ValidateManifest(manifest, manifest.ServerID, 30); err != nil {
		t.Fatalf("Work registration did not survive an unrelated manifest advance: %v", err)
	}
	if fixture.Registration.Identity.ExpectedRevision != 1 ||
		fixture.Registration.Binding.BindingID != fixture.Operation.Binding.BindingID {
		t.Fatalf("registration identity drifted: %#v %#v", fixture.Registration, fixture.Operation)
	}
}

func TestRuntimeConsumesActualBackendContinuityRegistrationManifest(t *testing.T) {
	// The HTTP/PostgreSQL producer journey exports its actual runtime manifest
	// for the cross-repository gate; the ordinary strict decoder and validator
	// consume it unchanged. The exported registration pins Work revision 1 while
	// the server manifest has already advanced to revision 3.
	payload, err := os.ReadFile(filepath.Join("..", "api", "testdata", "continuity-registration-backend-wire.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.ContinuityRegistrations) != 1 {
		t.Fatalf("actual backend fixture registrations = %d, want 1", len(manifest.ContinuityRegistrations))
	}
	registration := manifest.ContinuityRegistrations[0]
	if registration.Identity.ExpectedRevision != 1 {
		t.Fatalf("actual backend fixture Work revision = %d, want 1", registration.Identity.ExpectedRevision)
	}
	if manifest.DesiredRevision <= registration.Identity.ExpectedRevision {
		t.Fatalf("actual backend fixture does not exercise independent revision domains: manifest=%d work=%d",
			manifest.DesiredRevision, registration.Identity.ExpectedRevision)
	}
	if err := ValidateManifest(manifest, manifest.ServerID, manifest.DesiredRevision-1); err != nil {
		t.Fatalf("actual backend continuity registration manifest rejected: %v", err)
	}
}

func TestContinuityOperationMayAddTaskPairToWorkFence(t *testing.T) {
	fixture := loadContinuityRevisionFixture(t)
	manifest := continuityRevisionManifest(fixture)
	taskID := "task_continuity0001"
	attempt := int64(1)
	manifest.ContinuityOperations[0].Identity.TaskID = &taskID
	manifest.ContinuityOperations[0].Identity.TaskAttempt = &attempt
	manifest.ContinuityOperations[0].BoundaryKind = "task"
	if err := ValidateManifest(manifest, manifest.ServerID, 29); err != nil {
		t.Fatalf("task-boundary operation rejected: %v", err)
	}
	// A different Work fence on the task operation still fails closed.
	foreign := manifest.ContinuityOperations[0]
	foreign.Identity.WorkID = "work_foreign0001"
	manifest.ContinuityOperations[0] = foreign
	if err := ValidateManifest(manifest, manifest.ServerID, 29); err == nil {
		t.Fatal("foreign task-boundary operation was accepted")
	}
}

// TestContinuityRegistrationRevisionSuccessionIsExactAndFailClosed is the C1
// gate: the backend's binding reactivation keeps one binding row and advances
// its revision, so the manifest legitimately carries the revoked predecessor
// and the active successor under one binding ID. Only that exact, ordered and
// tuple-consistent succession is admissible; every other duplicate stays
// fail-closed.
func TestContinuityRegistrationRevisionSuccessionIsExactAndFailClosed(t *testing.T) {
	fixture := loadContinuityRevisionFixture(t)
	predecessor := fixture.Registration
	predecessor.DesiredState = "revoked"
	successor := fixture.Registration
	successor.Binding.BindingRevision++
	base := continuityRevisionManifest(fixture)
	validate := func(registrations []ContinuityRegistrationV1, operations []ContinuityOperationV1) error {
		candidate := base
		candidate.ContinuityRegistrations = registrations
		candidate.ContinuityOperations = operations
		return ValidateManifest(candidate, candidate.ServerID, 29)
	}
	if err := validate([]ContinuityRegistrationV1{predecessor, successor}, nil); err != nil {
		t.Fatalf("backend revision succession was rejected: %v", err)
	}
	if err := validate([]ContinuityRegistrationV1{successor, predecessor}, nil); err != nil {
		t.Fatalf("order-independent revision succession was rejected: %v", err)
	}
	// The effective entry for operations is the active successor: an operation
	// bound to the successor passes, one bound to the revoked predecessor does
	// not.
	successorOperation := fixture.Operation
	successorOperation.Binding.BindingRevision = successor.Binding.BindingRevision
	if err := validate([]ContinuityRegistrationV1{predecessor, successor}, []ContinuityOperationV1{successorOperation}); err != nil {
		t.Fatalf("successor-bound operation was rejected: %v", err)
	}
	if err := validate([]ContinuityRegistrationV1{predecessor, successor}, []ContinuityOperationV1{fixture.Operation}); err == nil {
		t.Fatal("revoked-predecessor-bound operation was accepted")
	}
	rejected := []struct {
		name   string
		mutate func(*ContinuityRegistrationV1)
	}{
		{"equal_revision", func(value *ContinuityRegistrationV1) {
			value.Binding.BindingRevision = predecessor.Binding.BindingRevision
		}},
		{"revision_jump", func(value *ContinuityRegistrationV1) {
			value.Binding.BindingRevision = predecessor.Binding.BindingRevision + 2
		}},
		{"inconsistent_binding_tuple", func(value *ContinuityRegistrationV1) {
			value.Binding.RegisteredSourceID = "source_succession0001"
		}},
		{"inconsistent_work_fence", func(value *ContinuityRegistrationV1) {
			value.Identity.WorkID = "work_succession0001"
		}},
		{"scope_regression", func(value *ContinuityRegistrationV1) {
			value.ScopeRevision = predecessor.ScopeRevision - 1
		}},
		{"two_revoked", func(value *ContinuityRegistrationV1) {
			value.DesiredState = "revoked"
		}},
	}
	for _, test := range rejected {
		t.Run(test.name, func(t *testing.T) {
			candidate := successor
			test.mutate(&candidate)
			err := validate([]ContinuityRegistrationV1{predecessor, candidate}, nil)
			if err == nil || !strings.Contains(err.Error(), "duplicate continuity registration") {
				t.Fatalf("ambiguous succession was accepted: %v", err)
			}
		})
	}
	t.Run("two_active", func(t *testing.T) {
		active := predecessor
		active.DesiredState = "active"
		err := validate([]ContinuityRegistrationV1{active, successor}, nil)
		if err == nil || !strings.Contains(err.Error(), "duplicate continuity registration") {
			t.Fatalf("two active revisions were accepted: %v", err)
		}
	})
	t.Run("identical_revision_duplicate", func(t *testing.T) {
		duplicate := fixture.Registration
		err := validate([]ContinuityRegistrationV1{fixture.Registration, duplicate}, nil)
		if err == nil || !strings.Contains(err.Error(), "duplicate continuity registration") {
			t.Fatalf("identical revision duplicate was accepted: %v", err)
		}
	})
	t.Run("three_entries", func(t *testing.T) {
		err := validate([]ContinuityRegistrationV1{predecessor, successor, successor}, nil)
		if err == nil || !strings.Contains(err.Error(), "duplicate continuity registration") {
			t.Fatalf("three binding entries were accepted: %v", err)
		}
	})
}

func TestContinuityRegistrationRejectsForeignFences(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"zero-work-revision", func(manifest *Manifest) {
			manifest.ContinuityRegistrations[0].Identity.ExpectedRevision = 0
		}},
		{"sandbox-generation-mismatch", func(manifest *Manifest) {
			manifest.ContinuityRegistrations[0].Identity.SandboxGeneration = 5
			manifest.ContinuityOperations[0].Identity.SandboxGeneration = 5
		}},
		{"unknown-sandbox", func(manifest *Manifest) {
			manifest.ContinuityRegistrations[0].Identity.SandboxID = "sbx_continuity999999999999"
			manifest.ContinuityOperations[0].Identity.SandboxID = "sbx_continuity999999999999"
		}},
		{"operation-scope-mismatch", func(manifest *Manifest) {
			manifest.ContinuityOperations[0].ScopeRevision++
		}},
		{"foreign-operation-binding", func(manifest *Manifest) {
			manifest.ContinuityOperations[0].Binding.BindingID = "binding_foreign0001"
		}},
		{"work-identity-mismatch", func(manifest *Manifest) {
			manifest.ContinuityOperations[0].Identity.WorkID = "work_foreign0001"
		}},
		{"foreign-operation-sandbox", func(manifest *Manifest) {
			manifest.ContinuityOperations[0].Identity.SandboxID = "sbx_continuity000000000002"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := continuityRevisionManifest(loadContinuityRevisionFixture(t))
			test.mutate(&manifest)
			if err := ValidateManifest(manifest, manifest.ServerID, 29); err == nil {
				t.Fatalf("manifest with %s was accepted; foreign continuity fence must fail closed", test.name)
			}
		})
	}
}
