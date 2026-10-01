package state

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
)

func TestHostContinuityRegistryPersistsExactSourceRegistrationAndLifecycleFence(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	sources, err := store.ContinuitySources(ctx)
	if err != nil || len(sources) != 0 {
		t.Fatalf("fresh source authority=%#v err=%v; source rows must come from S1.M", sources, err)
	}
	identity := model.ContinuityIdentityV1{WorkID: "work_registry0001", ProjectID: "project_registry0001", SandboxID: "sbx_registry000000000001", WorkspaceEpoch: "epoch_registry0001", SandboxGeneration: 3, ExpectedRevision: 1}
	binding := model.ContinuityBindingV1{BindingID: "binding_registry0001", BindingRevision: 4, RegisteredSourceID: "source_registry0001", ServiceRegistrationID: "service_registry0001", NativeSessionID: "ses_registry0001", NativeProjectID: "native_project_registry0001", NativeLocationDigest: "sha256:6666666666666666666666666666666666666666666666666666666666666666"}
	source := LocalContinuitySource{Report: model.ContinuitySourceReportV1{FormatVersion: 1, RegisteredSourceID: binding.RegisteredSourceID, ServiceRegistrationID: binding.ServiceRegistrationID, ServiceGeneration: 2, ProjectID: identity.ProjectID, SandboxID: identity.SandboxID, SandboxGeneration: identity.SandboxGeneration, WorkspaceEpoch: identity.WorkspaceEpoch, NativeSessionID: binding.NativeSessionID, NativeProjectID: binding.NativeProjectID, NativeLocationDigest: binding.NativeLocationDigest, ScopeRevision: 6, Role: "worker", ProfileRevision: 5, InstructionRevision: 7, Availability: "available", LastObservedAt: time.Now().UTC()}, Root: t.TempDir(), Instance: "worker", Lifecycle: "stopped", LifecycleRevision: 11, NoAdmittedExecution: true}
	if err := store.PutContinuitySource(ctx, source); err != nil {
		t.Fatal(err)
	}
	registration := LocalContinuityRegistration{Manifest: model.ContinuityRegistrationV1{FormatVersion: 1, DesiredState: "active", ContinuityEnabled: true, ScopeRevision: 6, Identity: identity, Binding: binding}, ObservedStatus: "verified", ServiceGeneration: 2, ReceiptDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := store.PutContinuityRegistration(ctx, registration); err != nil {
		t.Fatal(err)
	}
	gotSource, err := store.ContinuitySource(ctx, binding.RegisteredSourceID)
	if err != nil || gotSource == nil || gotSource.Root != source.Root || gotSource.Instance != "worker" || !gotSource.NoAdmittedExecution {
		t.Fatalf("source=%#v err=%v", gotSource, err)
	}
	gotRegistration, err := store.ContinuityRegistration(ctx, binding.BindingID)
	if err != nil || gotRegistration == nil || gotRegistration.ObservedStatus != "verified" || gotRegistration.Manifest.Binding != binding {
		t.Fatalf("registration=%#v err=%v", gotRegistration, err)
	}
	if err := store.AdvanceContinuityLifecycle(ctx, binding.RegisteredSourceID, 11, "running"); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceContinuityLifecycle(ctx, binding.RegisteredSourceID, 11, "stopped"); err == nil {
		t.Fatal("stale lifecycle owner advanced the source")
	}
	gotSource, err = store.ContinuitySource(ctx, binding.RegisteredSourceID)
	if err != nil || gotSource == nil || gotSource.Lifecycle != "running" || gotSource.LifecycleRevision != 12 {
		t.Fatalf("advanced source=%#v err=%v", gotSource, err)
	}
	stale := *gotSource
	fresh := stale
	fresh.Report.LastObservedAt = stale.Report.LastObservedAt.Add(time.Second)
	fresh.NoAdmittedExecution = false
	if err := store.PutContinuitySource(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkContinuitySourceIdle(ctx, stale); err != nil {
		t.Fatal(err)
	}
	gotSource, err = store.ContinuitySource(ctx, binding.RegisteredSourceID)
	if err != nil || gotSource.NoAdmittedExecution || !gotSource.Report.LastObservedAt.Equal(fresh.Report.LastObservedAt) {
		t.Fatalf("stale idle callback overwrote fresh authority: %#v %v", gotSource, err)
	}
	if err := store.MarkContinuitySourceIdle(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	gotSource, err = store.ContinuitySource(ctx, binding.RegisteredSourceID)
	if err != nil || !gotSource.NoAdmittedExecution || !gotSource.Report.LastObservedAt.Equal(fresh.Report.LastObservedAt) {
		t.Fatalf("current idle callback did not preserve observation: %#v %v", gotSource, err)
	}
	if err := store.AdvanceContinuityLifecycle(ctx, binding.RegisteredSourceID, 12, "stopped"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkContinuitySourceIdle(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	gotSource, err = store.ContinuitySource(ctx, binding.RegisteredSourceID)
	if err != nil || gotSource.Lifecycle != "stopped" || gotSource.LifecycleRevision != 13 {
		t.Fatalf("stale idle callback undid a lifecycle fence: %#v %v", gotSource, err)
	}
}
