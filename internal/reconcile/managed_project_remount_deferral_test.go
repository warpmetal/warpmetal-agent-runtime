package reconcile

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/workspacecatalog"
)

// remountedProjectAttestation mirrors the host-private root attestation the
// catalog derives from a managed-project record. The journey needs it to seed
// the deployed pre-remount record exactly as Runtime attested it while the
// workspace image was still carried by its original loop device; the production
// catalog re-derives the same value from the same fields before it re-attests
// the record, so a divergence in the domain fails this journey instead of
// passing silently.
func remountedProjectAttestation(record state.LocalManagedProject) string {
	payload, _ := json.Marshal(struct {
		SelectionID, ProjectID, WorkspaceEpoch, SandboxID, ServiceRegistrationID, AllocationDigest, ConfigDigest string
		SandboxGeneration                                                                                        int64
		AnchorDevice, AnchorInode, RootDevice, RootInode                                                         uint64
		AnchorMount, RootMount                                                                                   string
		ScopeRevision                                                                                            int64
	}{record.Report.SelectionID, record.Report.ProjectID, record.Report.WorkspaceEpoch, record.Report.SandboxID, stringValue(record.Report.ServiceRegistrationID), record.AllocationDigest, record.ConfigDigest, record.Report.SandboxGeneration, record.AnchorDevice, record.AnchorInode, record.RootDevice, record.RootInode, record.AnchorMount, record.RootMount, record.ScopeRevision})
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// remountedManagedProject is the live pre-remount shape at the reconcile
// boundary: the deployed record of a team project whose workspace ext4 image an
// authorized host repair re-mounted onto a new loop device (exactly the
// runtime's own documented Workspaces.Ensure behaviour), with the manifest
// still carrying the attestation the backend ratified before the remount.
type remountedManagedProject struct {
	record       state.LocalManagedProject
	attestation  string
	serviceID    string
	anchorDevice uint64
	anchorInode  uint64
	rootInode    uint64
}

// seedRemountedManagedProject turns the journey's freshly allocated project
// into the live pre-remount shape: the deployed record for that exact project
// (same selectionId, projectId, workspaceEpoch, sandbox generation, container
// root, service identity, config and allocation digest, anchor and project-root
// objects) as an earlier runtime wrote it while the workspace image was still
// carried by its original loop device, with the manifest still carrying the
// attestation the backend ratified before the re-mount. adjust may change the
// record before it is seeded.
func seedRemountedManagedProject(t *testing.T, journey *managerPolicyJourney, adjust func(*state.LocalManagedProject)) remountedManagedProject {
	t.Helper()
	ctx := context.Background()
	projects, err := journey.store.ManagedProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var allocated *state.LocalManagedProject
	for index := range projects {
		if projects[index].Report.SelectionID == journey.fixture.ServiceManifest.Workspace.SelectionID {
			allocated = &projects[index]
		}
	}
	if allocated == nil || allocated.Phase != "ready" || allocated.Report.RootAttestation == "" ||
		allocated.AnchorDevice == 0 || allocated.AnchorInode == 0 || allocated.RootInode == 0 ||
		allocated.AnchorDevice != allocated.RootDevice {
		t.Fatalf("journey project is not an attested single-image root: %#v", allocated)
	}
	record := *allocated
	record.AnchorDevice, record.RootDevice = allocated.AnchorDevice+1, allocated.RootDevice+1
	if adjust != nil {
		adjust(&record)
	}
	record.Report.RootAttestation = remountedProjectAttestation(record)
	replaceDeployedManagedProjectRow(t, journey, record)
	return remountedManagedProject{
		record: record, attestation: record.Report.RootAttestation,
		serviceID:    stringValue(record.Report.ServiceRegistrationID),
		anchorDevice: allocated.AnchorDevice, anchorInode: allocated.AnchorInode, rootInode: allocated.RootInode,
	}
}

// replaceDeployedManagedProjectRow replaces the record the current allocation
// just wrote with the deployed pre-remount record for the same selection. The
// deployed runtime wrote that row while the workspace image was still carried
// by its original loop device; the store's immutable identity fence
// deliberately refuses to rewrite the freshly allocated row's device, so the
// journey replaces the row exactly as the earlier runtime left it.
func replaceDeployedManagedProjectRow(t *testing.T, journey *managerPolicyJourney, record state.LocalManagedProject) {
	t.Helper()
	database, err := sql.Open("sqlite", journey.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(context.Background(),
		`DELETE FROM managed_workspace_projects WHERE selection_id=?`, record.Report.SelectionID); err != nil {
		t.Fatal(err)
	}
	if err := journey.store.PutManagedProject(context.Background(), record); err != nil {
		t.Fatalf("seed the deployed pre-remount record: %v", err)
	}
}

// remountManifest keeps every identity of the journey's managed service exactly
// as the fixture carries it and selects the deployed project with the given
// workspace root attestation, the way the backend manifest does.
func remountManifest(journey *managerPolicyJourney, remount remountedManagedProject, attestation string) model.Manifest {
	manifest := journey.manifest
	service := journey.fixture.ServiceManifest
	service.Workspace.SelectionID = remount.record.Report.SelectionID
	service.Workspace.ProjectID = remount.record.Report.ProjectID
	service.Workspace.WorkspaceEpoch = remount.record.Report.WorkspaceEpoch
	service.Workspace.RootAttestation = attestation
	manifest.ManagedServices = []model.ManagedServiceV1{service}
	return manifest
}

func storedManagedProjectRecord(t *testing.T, store *state.Store, selectionID string) state.LocalManagedProject {
	t.Helper()
	record, err := store.ManagedProject(context.Background(), selectionID)
	if err != nil || record == nil {
		t.Fatalf("managed project %s = %#v, %v", selectionID, record, err)
	}
	return *record
}

func storedManagedServiceRow(t *testing.T, store *state.Store, serviceID string) *state.LocalManagedService {
	t.Helper()
	row, err := store.ManagedService(context.Background(), serviceID)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// journeyCatalog exposes the journey's real workspace catalog so a test can
// inject the narrow host-observation seams the darwin test host cannot provide.
func journeyCatalog(t *testing.T, journey *managerPolicyJourney) *workspacecatalog.Catalog {
	t.Helper()
	catalog, ok := journey.reconciler.ManagedCatalog.(*workspacecatalog.Catalog)
	if !ok {
		t.Fatalf("journey catalog is %T", journey.reconciler.ManagedCatalog)
	}
	return catalog
}

// seedDeployedManagedServiceRow writes the exact deployed row of the service
// the remount journeys defer: the service that was running before the host
// repair re-mounted its workspace image. The row must be byte-unchanged after
// every deferred or fatal pass.
func seedDeployedManagedServiceRow(t *testing.T, journey *managerPolicyJourney) {
	t.Helper()
	manifest := journey.fixture.ServiceManifest
	if err := journey.store.PutManagedServiceIntent(context.Background(), state.LocalManagedService{
		Manifest: manifest, Phase: "ready",
		ProcessInstance:   model.ManagedServiceProcessInstance(manifest.Identity.Instance, manifest.Identity.ExpectedServiceGeneration),
		Port:              managedServicePort,
		ServiceGeneration: manifest.Identity.ExpectedServiceGeneration,
	}); err != nil {
		t.Fatal(err)
	}
}

func publishedWorkspaceSelection(t *testing.T, report model.Report, selectionID string) *model.ProjectCatalogReportV1 {
	t.Helper()
	for index := range report.ManagedWorkspaceSelections {
		if report.ManagedWorkspaceSelections[index].SelectionID == selectionID {
			return &report.ManagedWorkspaceSelections[index]
		}
	}
	return nil
}

// assertRemountRecordReattested asserts the record adopted the live device
// without any other durable, allocation, config or path field moving.
func assertRemountRecordReattested(t *testing.T, before state.LocalManagedProject, after state.LocalManagedProject, remount remountedManagedProject) {
	t.Helper()
	if after.Report.RootAttestation == before.Report.RootAttestation {
		t.Fatalf("remount observation did not re-attest the root: %#v", after.Report)
	}
	if after.AnchorDevice != remount.anchorDevice || after.RootDevice != remount.anchorDevice {
		t.Fatalf("remount observation kept the superseded device: %#v", after)
	}
	if after.AnchorInode != remount.anchorInode || after.RootInode != remount.rootInode ||
		after.SupersededRootAttestation != before.Report.RootAttestation ||
		after.ImageIdentity != before.ImageIdentity ||
		after.Report.SelectionID != before.Report.SelectionID || after.Report.ProjectID != before.Report.ProjectID ||
		after.Report.WorkspaceEpoch != before.Report.WorkspaceEpoch || after.Report.SandboxID != before.Report.SandboxID ||
		after.Report.SandboxGeneration != before.Report.SandboxGeneration ||
		stringValue(after.Report.ServiceRegistrationID) != remount.serviceID ||
		after.Report.Designation != before.Report.Designation || after.Report.Label != before.Report.Label ||
		after.Report.Availability != "available" || after.Report.Reason != nil ||
		!after.Report.LastObservedAt.Equal(before.Report.LastObservedAt) ||
		after.Phase != "ready" || after.ScopeRevision != before.ScopeRevision ||
		after.ServerID != before.ServerID || after.TeamID != before.TeamID || after.MemberID != before.MemberID ||
		after.AllocationDigest != before.AllocationDigest || after.ConfigDigest != before.ConfigDigest ||
		after.Anchor != before.Anchor || after.HostRoot != before.HostRoot || after.ContainerRoot != before.ContainerRoot {
		t.Fatalf("remount observation changed more than the loop device: before=%#v after=%#v", before, after)
	}
}

// TestReconcileDefersRemountedWorkspaceAttestationAndStillAdvancesThePass
// reproduces the live wedge and is the exact pre-fix RED: an authorized host
// repair re-mounted the workspace ext4 image of the unchanged workspace image
// on a new loop device, so the deployed managed-project record no longer names
// the live device, and before the fix this pass aborted with `managed project
// changed`, so the workspace report never carried the re-attested root and the
// backend could never ratify it. The journey also moves the image's
// modification time exactly as every write through the mounted filesystem
// does, so it proves the re-observation compares the durable object identity
// (device, inode, size) and never the legitimately moving mtime. The managed
// service must stay fail-closed and byte-unchanged (no intent, no supervisor
// execution, no local advancement) while the same pass re-observes the root,
// publishes the re-attested root through the ordinary workspace report for
// backend ratification, reconciles the sandbox loop and still advances the
// applied revision. The deferred reason is deliberately dropped once the rest
// of the pass succeeds: retryability is inherent, so success returns no error
// at all.
func TestReconcileDefersRemountedWorkspaceAttestationAndStillAdvancesThePass(t *testing.T) {
	journey := newManagerPolicyJourney(t)
	remount := seedRemountedManagedProject(t, journey, nil)
	manifest := remountManifest(journey, remount, remount.attestation)
	ctx := context.Background()
	// The host can name the loop backing file of the live device, so the
	// re-observation must additionally prove the device carries exactly the
	// record's per-sandbox image path.
	journeyCatalog(t, journey).LoopBacking = func(uint64) (string, error) {
		return journey.imagePath, nil
	}
	seedDeployedManagedServiceRow(t, journey)
	before := storedManagedServiceRow(t, journey.store, remount.serviceID)
	if before == nil {
		t.Fatal("journey service row was not seeded")
	}
	beforeRecord := storedManagedProjectRecord(t, journey.store, remount.record.Report.SelectionID)
	// Same image object, only its modification time moved: the runtime's own
	// Git bootstrap and every agent/service write through the mounted image
	// legitimately move the file's mtime without replacing the object, so by
	// the time the documented remount happens the recorded mtime is stale.
	moved := time.Date(2027, 1, 1, 0, 0, 0, 123456789, time.UTC)
	if err := os.Chtimes(journey.imagePath, moved, moved); err != nil {
		t.Fatal(err)
	}
	live, err := os.Stat(journey.imagePath)
	if err != nil {
		t.Fatal(err)
	}
	if beforeRecord.ImageIdentity.ModifiedUnixNano == 0 || live.ModTime().UnixNano() == beforeRecord.ImageIdentity.ModifiedUnixNano {
		t.Fatalf("test did not move the recorded image mtime: recorded %d, live %d", beforeRecord.ImageIdentity.ModifiedUnixNano, live.ModTime().UnixNano())
	}

	if err := journey.reconciler.Reconcile(ctx, manifest); err != nil {
		t.Fatalf("re-mounted workspace aborted the whole reconcile: %v", err)
	}

	// The deferred managed service is exactly where it was: the deployed row is
	// byte-unchanged (still blocked on the ratified root, no dispatch, no
	// control-plane action).
	if after := storedManagedServiceRow(t, journey.store, remount.serviceID); !reflect.DeepEqual(before, after) {
		t.Fatalf("deferred managed service changed: before=%#v after=%#v", before, after)
	}
	if runtime, ok := journey.reconciler.ManagedRuntime.(*fakeManagedRuntime); !ok || len(runtime.invocations) != 0 {
		t.Fatalf("deferred managed service reached the sandbox supervisor: %#v", journey.reconciler.ManagedRuntime)
	}
	if len(journey.control.enrollments) != 0 || len(journey.control.instructions) != 0 {
		t.Fatalf("deferred managed service reached the control plane: %#v %#v", journey.control.enrollments, journey.control.instructions)
	}

	// The pass continued: the sandbox loop reconciled its box and the root was
	// re-observed to the live device without moving any durable object.
	if engine, ok := journey.reconciler.Engine.(*contractEngine); !ok || engine.ensured != 1 {
		t.Fatalf("deferred pass did not reconcile the sandbox loop: %#v", journey.reconciler.Engine)
	}
	record := storedManagedProjectRecord(t, journey.store, remount.record.Report.SelectionID)
	assertRemountRecordReattested(t, beforeRecord, record, remount)
	if record.SupersededRootAttestation != remount.attestation {
		t.Fatalf("re-observation did not keep the pre-remount attestation host-private: %#v", record)
	}

	// The ordinary workspace report publishes the re-attested root for backend
	// ratification and the applied revision advanced.
	report, err := journey.reconciler.Report(ctx, journey.reconciler.ServerID, "test")
	if err != nil {
		t.Fatal(err)
	}
	published := publishedWorkspaceSelection(t, report, remount.record.Report.SelectionID)
	if published == nil || published.RootAttestation != record.Report.RootAttestation ||
		published.Availability != "available" || published.Reason != nil {
		t.Fatalf("workspace report did not publish the re-attested root: %#v", published)
	}
	// The superseded pre-remount attestation is host-private provenance: it
	// must never appear in a published report and it never admits anything.
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "Superseded") || strings.Contains(string(payload), "superseded") {
		t.Fatalf("published report leaked host-private remount provenance: %s", payload)
	}
	if revision, err := journey.store.Revision(ctx); err != nil || revision != manifest.DesiredRevision {
		t.Fatalf("deferred pass did not advance the applied revision to %d: %d, %v", manifest.DesiredRevision, revision, err)
	}
}

// TestReconcileResumesRemountedWorkspaceServiceOnceTheManifestCarriesTheRatifiedRoot
// proves the other half of the invariant: after the backend accepted the
// workspace report that carried the re-attested root and issued a manifest
// carrying that exact authority (same selectionId, projectId, workspaceEpoch,
// sandbox generation, container root, service identity and backing image), the
// service proceeds on the ordinary path.
func TestReconcileResumesRemountedWorkspaceServiceOnceTheManifestCarriesTheRatifiedRoot(t *testing.T) {
	journey := newManagerPolicyJourney(t)
	remount := seedRemountedManagedProject(t, journey, nil)
	manifest := remountManifest(journey, remount, remount.attestation)
	ctx := context.Background()

	if err := journey.reconciler.Reconcile(ctx, manifest); err != nil {
		t.Fatalf("re-mounted workspace aborted the whole reconcile: %v", err)
	}
	record := storedManagedProjectRecord(t, journey.store, remount.record.Report.SelectionID)
	if record.Report.RootAttestation == remount.attestation {
		t.Fatalf("remount pass did not re-attest the root: %#v", record.Report)
	}

	ratified := remountManifest(journey, remount, record.Report.RootAttestation)
	ratified.ManagedServices[0].Workspace.ScopeRevision = remount.record.ScopeRevision + 1
	if err := journey.reconciler.Reconcile(ctx, ratified); err != nil {
		t.Fatalf("ratified manifest did not let the service proceed: %v", err)
	}
	service := storedManagedServiceRow(t, journey.store, remount.serviceID)
	if service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" || service.ErrorCode != "" {
		t.Fatalf("ratified manifest did not reach the service: %#v", service)
	}
	if len(journey.control.enrollments) != 1 || len(journey.control.instructions) != 1 {
		t.Fatalf("ratified manifest did not reconcile the service boundary: %#v %#v", journey.control.enrollments, journey.control.instructions)
	}
	runtime, ok := journey.reconciler.ManagedRuntime.(*fakeManagedRuntime)
	if !ok || len(runtime.invocations) == 0 {
		t.Fatalf("ratified manifest never dispatched the sandbox supervisor: %#v", journey.reconciler.ManagedRuntime)
	}
	if revision, err := journey.store.Revision(ctx); err != nil || revision != ratified.DesiredRevision {
		t.Fatalf("ratified pass did not advance the applied revision to %d: %d, %v", ratified.DesiredRevision, revision, err)
	}
}

// TestReconcileKeepsAChangedWorkspaceProjectTupleFatal is the security negative
// for the immutable workspace/project tuple: a manifest that still selects the
// deployed record but carries a different projectId/workspaceEpoch stays an
// ordinary project change. The pass aborts with `managed project changed`, the
// service is never classified as the documented remount, never admitted or
// executed, and the applied revision never advances.
func TestReconcileKeepsAChangedWorkspaceProjectTupleFatal(t *testing.T) {
	journey := newManagerPolicyJourney(t)
	remount := seedRemountedManagedProject(t, journey, nil)
	manifest := remountManifest(journey, remount, remount.attestation)
	manifest.ManagedServices[0].Workspace.ProjectID = "project_remountchanged0001"
	manifest.ManagedServices[0].Workspace.WorkspaceEpoch = "epoch_remountchanged0001"
	ctx := context.Background()
	seedDeployedManagedServiceRow(t, journey)
	before := storedManagedServiceRow(t, journey.store, remount.serviceID)
	if before == nil {
		t.Fatal("journey service row was not seeded")
	}

	err := journey.reconciler.Reconcile(ctx, manifest)
	if err == nil || !strings.Contains(err.Error(), "managed project changed") {
		t.Fatalf("changed workspace/project tuple was not fatal: %v", err)
	}
	if errors.Is(err, workspacecatalog.ErrManagedProjectRemountAttestation) {
		t.Fatalf("changed workspace/project tuple was classified as the documented remount: %v", err)
	}
	if after := storedManagedServiceRow(t, journey.store, remount.serviceID); !reflect.DeepEqual(before, after) {
		t.Fatalf("fatal tuple change admitted the managed service: before=%#v after=%#v", before, after)
	}
	if runtime, ok := journey.reconciler.ManagedRuntime.(*fakeManagedRuntime); !ok || len(runtime.invocations) != 0 {
		t.Fatalf("fatal tuple change executed the managed service: %#v", journey.reconciler.ManagedRuntime)
	}
	if len(journey.control.enrollments) != 0 || len(journey.control.instructions) != 0 {
		t.Fatalf("fatal tuple change reached the control plane: %#v %#v", journey.control.enrollments, journey.control.instructions)
	}
	if revision, err := journey.store.Revision(ctx); err != nil || revision != 0 {
		t.Fatalf("fatal tuple change advanced the applied revision: %d, %v", revision, err)
	}
}

// assertFatalUntouchedRemount proves a pass that refused to re-attest the
// record stayed completely fail-closed: the record is byte-unchanged (no
// re-attestation, no superseded provenance), the deployed service row is
// byte-unchanged and never dispatched or enrolled, the ordinary workspace
// report still carries only the pre-remount authority, and the applied
// revision never advanced.
func assertFatalUntouchedRemount(t *testing.T, journey *managerPolicyJourney, ctx context.Context, remount remountedManagedProject, beforeRecord state.LocalManagedProject, beforeService *state.LocalManagedService, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "managed project changed") {
		t.Fatalf("refused re-attestation was not fatal: %v", err)
	}
	if errors.Is(err, workspacecatalog.ErrManagedProjectRemountAttestation) {
		t.Fatalf("refused re-attestation was classified as the documented remount: %v", err)
	}
	after := storedManagedProjectRecord(t, journey.store, remount.record.Report.SelectionID)
	if !reflect.DeepEqual(beforeRecord, after) {
		t.Fatalf("refused re-attestation rewrote the record: before=%#v after=%#v", beforeRecord, after)
	}
	if after.Report.RootAttestation != remount.attestation || after.SupersededRootAttestation != "" {
		t.Fatalf("refused re-attestation moved root authority: %#v", after)
	}
	if beforeService == nil {
		t.Fatal("deployed service row was not seeded")
	}
	if afterService := storedManagedServiceRow(t, journey.store, remount.serviceID); !reflect.DeepEqual(beforeService, afterService) {
		t.Fatalf("refused re-attestation admitted the service: before=%#v after=%#v", beforeService, afterService)
	}
	if runtime, ok := journey.reconciler.ManagedRuntime.(*fakeManagedRuntime); !ok || len(runtime.invocations) != 0 {
		t.Fatalf("refused re-attestation executed the service: %#v", journey.reconciler.ManagedRuntime)
	}
	if len(journey.control.enrollments) != 0 || len(journey.control.instructions) != 0 {
		t.Fatalf("refused re-attestation reached the control plane: %#v %#v", journey.control.enrollments, journey.control.instructions)
	}
	if revision, revErr := journey.store.Revision(ctx); revErr != nil || revision != 0 {
		t.Fatalf("refused re-attestation advanced the applied revision: %d, %v", revision, revErr)
	}
	report, reportErr := journey.reconciler.Report(ctx, journey.reconciler.ServerID, "test")
	if reportErr != nil {
		t.Fatal(reportErr)
	}
	published := publishedWorkspaceSelection(t, report, remount.record.Report.SelectionID)
	if published == nil || published.RootAttestation != remount.attestation {
		t.Fatalf("refused re-attestation published new root authority: %#v", published)
	}
	payload, jsonErr := json.Marshal(report)
	if jsonErr != nil {
		t.Fatal(jsonErr)
	}
	if strings.Contains(string(payload), "Superseded") || strings.Contains(string(payload), "superseded") {
		t.Fatalf("refused re-attestation leaked host-private remount provenance: %s", payload)
	}
}

// TestReconcileKeepsADifferentBackingImageFatalDespiteIdenticalInodes is the
// adversarial negative for the backing-image identity fence. The live anchor
// and project root are still the exact recorded directory objects (identical
// inodes) on one new device, exactly as the documented remount looks, but the
// device does not carry the recorded workspace image: either the image file at
// the record's host-private path is a different object, or the device is backed
// by a different path entirely. mkfs.ext4 reproduces the same inode numbers on
// a different image, so inode equality alone must never qualify. The two
// subtests are the enforcement proof of the two required mechanisms: the
// persisted image object and the host-reported loop backing path. The whole
// pass must abort fatally with the ordinary project-change reason: no
// re-attestation, no remount classification, no deferred service, no available
// publication and no revision advance.
func TestReconcileKeepsADifferentBackingImageFatalDespiteIdenticalInodes(t *testing.T) {
	t.Run("different backing image object", func(t *testing.T) {
		journey := newManagerPolicyJourney(t)
		remount := seedRemountedManagedProject(t, journey, nil)
		manifest := remountManifest(journey, remount, remount.attestation)
		ctx := context.Background()
		// Replace the image file at the record's own path with a different
		// object: everything the remount classifier compared before (anchor
		// inode, root inode, single new device) is unchanged.
		if err := os.Remove(journey.imagePath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(journey.imagePath, []byte("a different workspace image\n"), 0600); err != nil {
			t.Fatal(err)
		}
		seedDeployedManagedServiceRow(t, journey)
		beforeRecord := storedManagedProjectRecord(t, journey.store, remount.record.Report.SelectionID)
		beforeService := storedManagedServiceRow(t, journey.store, remount.serviceID)

		err := journey.reconciler.Reconcile(ctx, manifest)
		assertFatalUntouchedRemount(t, journey, ctx, remount, beforeRecord, beforeService, err)
	})

	t.Run("different backing image path", func(t *testing.T) {
		journey := newManagerPolicyJourney(t)
		remount := seedRemountedManagedProject(t, journey, nil)
		manifest := remountManifest(journey, remount, remount.attestation)
		ctx := context.Background()
		// The recorded image object is unchanged, but the live device is
		// backed by a different path than the record's per-sandbox image.
		journeyCatalog(t, journey).LoopBacking = func(uint64) (string, error) {
			return journey.imagePath + "-other", nil
		}
		seedDeployedManagedServiceRow(t, journey)
		beforeRecord := storedManagedProjectRecord(t, journey.store, remount.record.Report.SelectionID)
		beforeService := storedManagedServiceRow(t, journey.store, remount.serviceID)

		err := journey.reconciler.Reconcile(ctx, manifest)
		assertFatalUntouchedRemount(t, journey, ctx, remount, beforeRecord, beforeService, err)
	})
}

// registeredProjectManifest keeps every identity of the journey's managed
// service exactly as the fixture carries it and selects the given managed
// project record with the given workspace root attestation, the way a backend
// manifest does.
func registeredProjectManifest(journey *managerPolicyJourney, record state.LocalManagedProject, attestation string) model.Manifest {
	manifest := journey.manifest
	service := journey.fixture.ServiceManifest
	service.Workspace.SelectionID = record.Report.SelectionID
	service.Workspace.ProjectID = record.Report.ProjectID
	service.Workspace.WorkspaceEpoch = record.Report.WorkspaceEpoch
	service.Workspace.RootAttestation = attestation
	manifest.ManagedServices = []model.ManagedServiceV1{service}
	return manifest
}

// registeredManagedReport is the report of a service that completed its
// ordinary start: the native registration is the retained session/process fact
// that an adoption must never replace.
func registeredManagedReport(manifest model.ManagedServiceV1) model.ManagedServiceReportV1 {
	return model.ManagedServiceReportV1{
		FormatVersion: 1, OperationID: manifest.OperationID, ActionRevision: manifest.ActionRevision,
		ObservedDesiredRevision: manifest.DesiredRevision, ConfigDigest: manifest.ConfigDigest, ObservedState: "ready",
		Identity: manifest.Identity, ServiceGeneration: manifest.Identity.ExpectedServiceGeneration,
		ProfileStatus: "ready", WorkspaceStatus: "ready", EnrollmentStatus: "ready", WorkerStatus: "ready",
		InstructionApplied: true, InstructionRevision: manifest.Instructions.InstructionRevision,
		InstructionDigest: manifest.Instructions.InstructionDigest,
		NativeRegistration: &model.ManagedNativeRegistrationV1{
			RegisteredSourceID: managedSourceID(manifest.Identity.ServiceRegistrationID),
			WorkspaceEpoch:     manifest.Workspace.WorkspaceEpoch,
			NativeSessionID:    "ses_registered_remount_0001", NativeProjectID: strings.Repeat("a", 40),
			NativeLocationDigest: "sha256:" + strings.Repeat("b", 64),
		},
		ReceiptDigest: "sha256:" + strings.Repeat("c", 64),
	}
}

// seedRegisteredRemountServiceRow writes the deployed row of the service the
// A5 remount journeys re-observe, exactly as the ordinary start path left it:
// ready, with the creation dispatched, the native registration report and the
// given stored manifest (the pre-remount authority the backend ratified).
func seedRegisteredRemountServiceRow(t *testing.T, journey *managerPolicyJourney, manifest model.ManagedServiceV1) state.LocalManagedService {
	t.Helper()
	ctx := context.Background()
	if err := journey.store.PutManagedServiceIntent(ctx, state.LocalManagedService{
		Manifest: manifest, Phase: "pending",
		ProcessInstance:   model.ManagedServiceProcessInstance(manifest.Identity.Instance, manifest.Identity.ExpectedServiceGeneration),
		Port:              managedServicePort,
		ServiceGeneration: manifest.Identity.ExpectedServiceGeneration,
	}); err != nil {
		t.Fatal(err)
	}
	if err := journey.store.MarkManagedServiceCreationDispatched(ctx, manifest.Identity.ServiceRegistrationID, manifest.ConfigDigest); err != nil {
		t.Fatal(err)
	}
	report := registeredManagedReport(manifest)
	if err := journey.store.UpdateManagedService(ctx, manifest.Identity.ServiceRegistrationID, "ready", &report, ""); err != nil {
		t.Fatal(err)
	}
	row := storedManagedServiceRow(t, journey.store, manifest.Identity.ServiceRegistrationID)
	if row == nil || !row.CreationDispatched {
		t.Fatalf("deployed service row was not seeded: %#v", row)
	}
	return *row
}

// registeredRemountJourney runs the documented A5 sequence at the real
// boundary: the deployed ready service row carrying the stored (pre-remount)
// manifest, the pass that re-observes the remounted root and keeps the service
// deferred, and the backend-ratified manifest whose only differences are the
// workspace scope advancing exactly one and the root changing to the record's
// current (ratified) attestation. The pre-ratification deferral is asserted to
// leave the row byte-unchanged, including its timestamp.
func registeredRemountJourney(t *testing.T) (*managerPolicyJourney, remountedManagedProject, state.LocalManagedService, model.ManagedServiceV1, state.LocalManagedProject) {
	t.Helper()
	journey := newManagerPolicyJourney(t)
	ctx := context.Background()
	remount := seedRemountedManagedProject(t, journey, nil)
	journeyCatalog(t, journey).LoopBacking = func(uint64) (string, error) { return journey.imagePath, nil }
	stored := remountManifest(journey, remount, remount.attestation)
	before := seedRegisteredRemountServiceRow(t, journey, stored.ManagedServices[0])
	seeded := rawManagedServiceColumns(t, journey, remount.serviceID)
	if err := journey.reconciler.Reconcile(ctx, stored); err != nil {
		t.Fatalf("pre-ratification pass aborted: %v", err)
	}
	if runtime, ok := journey.reconciler.ManagedRuntime.(*fakeManagedRuntime); !ok || len(runtime.invocations) != 0 {
		t.Fatalf("pre-ratification deferral executed the service: %#v", journey.reconciler.ManagedRuntime)
	}
	if deferred := rawManagedServiceColumns(t, journey, remount.serviceID); !reflect.DeepEqual(seeded, deferred) {
		t.Fatalf("pre-ratification deferral moved the retained row: before=%v after=%v", seeded, deferred)
	}
	record := storedManagedProjectRecord(t, journey.store, remount.record.Report.SelectionID)
	if record.SupersededRootAttestation != remount.attestation {
		t.Fatalf("re-observation did not retain the pre-remount authority: %#v", record)
	}
	ratified := remountManifest(journey, remount, record.Report.RootAttestation)
	ratified.ManagedServices[0].Workspace.ScopeRevision = before.Manifest.Workspace.ScopeRevision + 1
	return journey, remount, before, ratified.ManagedServices[0], record
}

// rawManagedServiceColumns reads the retained managed-service row exactly as
// stored, including the ordinary write timestamp.
func rawManagedServiceColumns(t *testing.T, journey *managerPolicyJourney, serviceID string) map[string]string {
	t.Helper()
	database, err := sql.Open("sqlite", journey.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var manifest, phase, process, report, errorCode, updatedAt string
	var dispatched, generation, port int64
	if err := database.QueryRowContext(context.Background(),
		`SELECT manifest_json,phase,process_instance,port,creation_dispatched,service_generation,COALESCE(report_json,''),error_code,updated_at FROM managed_services WHERE service_registration_id=?`,
		serviceID).Scan(&manifest, &phase, &process, &port, &dispatched, &generation, &report, &errorCode, &updatedAt); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"manifest_json": manifest, "phase": phase, "process_instance": process,
		"port": fmt.Sprint(port), "creation_dispatched": fmt.Sprint(dispatched),
		"service_generation": fmt.Sprint(generation), "report_json": report,
		"error_code": errorCode, "updated_at": updatedAt,
	}
}

// rawManagedProjectColumns reads the retained managed-project row exactly as
// stored, including the ordinary write timestamp.
func rawManagedProjectColumns(t *testing.T, journey *managerPolicyJourney, selectionID string) map[string]string {
	t.Helper()
	database, err := sql.Open("sqlite", journey.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var report, private, updatedAt string
	if err := database.QueryRowContext(context.Background(),
		`SELECT report_json,private_json,updated_at FROM managed_workspace_projects WHERE selection_id=?`,
		selectionID).Scan(&report, &private, &updatedAt); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"report_json": report, "private_json": private, "updated_at": updatedAt}
}

// assertRefusedServiceUntouched proves a refused adoption never dispatched the
// service, never reached the control plane and left the retained row
// byte-unchanged, including its ordinary write timestamp.
func assertRefusedServiceUntouched(t *testing.T, journey *managerPolicyJourney, serviceID string, before map[string]string) {
	t.Helper()
	if runtime, ok := journey.reconciler.ManagedRuntime.(*fakeManagedRuntime); !ok || len(runtime.invocations) != 0 {
		t.Fatalf("refused adoption executed the service: %#v", journey.reconciler.ManagedRuntime)
	}
	if len(journey.control.enrollments) != 0 || len(journey.control.instructions) != 0 {
		t.Fatalf("refused adoption reached the control plane: %#v %#v", journey.control.enrollments, journey.control.instructions)
	}
	if after := rawManagedServiceColumns(t, journey, serviceID); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused adoption moved the retained row: before=%v after=%v", before, after)
	}
}

// TestReconcileAdoptsTheRegisteredRemountAuthorityAtUnchangedActionRevision is
// the A22P journey: after the A5 re-observation and backend ratification, the
// deployed ready service adopts the manifest whose only differences are the
// workspace scope advancing exactly one and the root changing to the record's
// current (ratified) attestation, and then proceeds through the ordinary path
// without duplicating creation, replacing the retained native
// session/process, or rewriting the managed-project record.
func TestReconcileAdoptsTheRegisteredRemountAuthorityAtUnchangedActionRevision(t *testing.T) {
	journey, remount, before, incoming, record := registeredRemountJourney(t)
	ctx := context.Background()
	assertRemountRecordAuthority := func() {
		if record.Phase != "ready" || record.Report.Availability != "available" ||
			record.Report.RootAttestation != incoming.Workspace.RootAttestation ||
			record.SupersededRootAttestation == "" || record.SupersededRootAttestation != before.Manifest.Workspace.RootAttestation ||
			record.ImageIdentity == (state.ManagedProjectImageIdentity{}) || record.AnchorDevice == 0 || record.AnchorDevice != record.RootDevice {
			t.Fatalf("journey record is not the stated remount authority: %#v", record)
		}
	}
	assertRemountRecordAuthority()
	if before.Manifest.Workspace.ScopeRevision != incoming.Workspace.ScopeRevision-1 ||
		before.Manifest.Workspace.RootAttestation == incoming.Workspace.RootAttestation {
		t.Fatalf("journey manifest did not advance exactly one scope step: %#v -> %#v", before.Manifest.Workspace, incoming.Workspace)
	}
	manifest := remountManifest(journey, remount, record.Report.RootAttestation)
	manifest.ManagedServices[0] = incoming
	recordRowBefore := rawManagedProjectColumns(t, journey, remount.record.Report.SelectionID)

	if err := journey.reconciler.Reconcile(ctx, manifest); err != nil {
		t.Fatalf("ratified manifest did not let the service proceed: %v", err)
	}
	service := storedManagedServiceRow(t, journey.store, remount.serviceID)
	if service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" || service.ErrorCode != "" ||
		service.Manifest.Workspace.ScopeRevision != incoming.Workspace.ScopeRevision ||
		service.Manifest.Workspace.RootAttestation != incoming.Workspace.RootAttestation {
		t.Fatalf("ratified manifest did not reach the service: %#v", service)
	}
	if !service.CreationDispatched || service.ServiceGeneration != incoming.Identity.ExpectedServiceGeneration {
		t.Fatalf("adoption duplicated creation or moved the service generation: %#v", service)
	}
	if len(journey.control.enrollments) != 1 || len(journey.control.instructions) != 1 {
		t.Fatalf("ratified manifest did not reconcile the service boundary: %#v %#v", journey.control.enrollments, journey.control.instructions)
	}
	if runtime, ok := journey.reconciler.ManagedRuntime.(*fakeManagedRuntime); !ok || len(runtime.invocations) == 0 {
		t.Fatalf("ratified manifest never dispatched the sandbox supervisor: %#v", journey.reconciler.ManagedRuntime)
	}
	if revision, err := journey.store.Revision(ctx); err != nil || revision != manifest.DesiredRevision {
		t.Fatalf("ratified pass did not advance the applied revision to %d: %d, %v", manifest.DesiredRevision, revision, err)
	}
	if after := rawManagedProjectColumns(t, journey, remount.record.Report.SelectionID); !reflect.DeepEqual(recordRowBefore, after) {
		t.Fatalf("adoption rewrote the managed-project record: before=%v after=%v", recordRowBefore, after)
	}
}

// TestReconcileKeepsEveryOtherSameRevisionChangeFatal covers the refused
// same-revision changes: they stay fatal, the service is never executed and the
// retained row never moves, not even its ordinary write timestamp.
func TestReconcileKeepsEveryOtherSameRevisionChangeFatal(t *testing.T) {
	subtests := []struct {
		name   string
		mutate func(model.ManagedServiceV1) model.ManagedServiceV1
		// storeConflict is true when the refusal must come from the store's
		// immutable-identity guard; false accepts any earlier fatal refusal.
		storeConflict bool
	}{
		{"one unrelated same-revision field change (operationId)", func(m model.ManagedServiceV1) model.ManagedServiceV1 {
			m.OperationID = "op_managed_start_0002"
			return m
		}, true},
		{"unrelated config digest change (no digest escape hatch)", func(m model.ManagedServiceV1) model.ManagedServiceV1 {
			m.ConfigDigest = "sha256:" + strings.Repeat("7", 64)
			return m
		}, false},
		{"scope jump greater than one", func(m model.ManagedServiceV1) model.ManagedServiceV1 { m.Workspace.ScopeRevision++; return m }, true},
		{"scope regression", func(m model.ManagedServiceV1) model.ManagedServiceV1 { m.Workspace.ScopeRevision -= 2; return m }, true},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			journey, remount, _, incoming, record := registeredRemountJourney(t)
			ctx := context.Background()
			manifest := remountManifest(journey, remount, record.Report.RootAttestation)
			manifest.ManagedServices[0] = subtest.mutate(incoming)
			before := rawManagedServiceColumns(t, journey, remount.serviceID)
			err := journey.reconciler.Reconcile(ctx, manifest)
			if err == nil {
				t.Fatalf("negative was adopted")
			}
			if subtest.storeConflict && !errors.Is(err, state.ErrManagedServiceConflict) {
				t.Fatalf("negative was not the store immutable-identity conflict: %v", err)
			}
			assertRefusedServiceUntouched(t, journey, remount.serviceID, before)
		})
	}
}

// TestReconcileKeepsAMissingSupersededRootFatal is the negative for the A5
// provenance tie: the incoming manifest carries the project record's current
// root at a one-step scope advance, but the record retains no superseded
// remount authority (and the stored row carries an authority the record never
// superseded). The store must refuse it as an immutable identity conflict,
// never dispatch the service and never move the retained row.
func TestReconcileKeepsAMissingSupersededRootFatal(t *testing.T) {
	journey := newManagerPolicyJourney(t)
	ctx := context.Background()
	record := storedManagedProjectRecord(t, journey.store, journey.fixture.ServiceManifest.Workspace.SelectionID)
	if record.Phase != "ready" || record.Report.Availability != "available" || record.SupersededRootAttestation != "" {
		t.Fatalf("journey record is not an unremounted ready project: %#v", record)
	}
	stored := registeredProjectManifest(journey, record, "sha256:"+strings.Repeat("8", 64))
	before := seedRegisteredRemountServiceRow(t, journey, stored.ManagedServices[0])
	beforeRow := rawManagedServiceColumns(t, journey, before.Manifest.Identity.ServiceRegistrationID)

	ratified := registeredProjectManifest(journey, record, record.Report.RootAttestation)
	ratified.ManagedServices[0].Workspace.ScopeRevision = before.Manifest.Workspace.ScopeRevision + 1
	err := journey.reconciler.Reconcile(ctx, ratified)
	if err == nil || !errors.Is(err, state.ErrManagedServiceConflict) {
		t.Fatalf("missing superseded root was not the immutable identity conflict: %v", err)
	}
	assertRefusedServiceUntouched(t, journey, before.Manifest.Identity.ServiceRegistrationID, beforeRow)
}

// TestReconcileKeepsAnArbitraryIncomingRootFatal is the negative for an
// incoming root that matches neither the stored root nor the project record's
// current root: the ordinary project-change refusal stays fatal (never the
// documented remount), the service is never dispatched and the retained row
// never moves, not even its ordinary write timestamp.
func TestReconcileKeepsAnArbitraryIncomingRootFatal(t *testing.T) {
	journey, remount, before, _, record := registeredRemountJourney(t)
	ctx := context.Background()
	manifest := remountManifest(journey, remount, record.Report.RootAttestation)
	manifest.ManagedServices[0].Workspace.ScopeRevision = before.Manifest.Workspace.ScopeRevision + 1
	manifest.ManagedServices[0].Workspace.RootAttestation = "sha256:" + strings.Repeat("5", 64)
	beforeRow := rawManagedServiceColumns(t, journey, remount.serviceID)

	err := journey.reconciler.Reconcile(ctx, manifest)
	if err == nil || !strings.Contains(err.Error(), "managed project changed") {
		t.Fatalf("arbitrary incoming root was not the ordinary project change: %v", err)
	}
	if errors.Is(err, workspacecatalog.ErrManagedProjectRemountAttestation) {
		t.Fatalf("arbitrary incoming root was classified as the documented remount: %v", err)
	}
	assertRefusedServiceUntouched(t, journey, remount.serviceID, beforeRow)
}

// TestReconcileKeepsTheStoredAuthorityTieAndTheManifestOnlyWrite proves the
// last two guards: a stored root that is not the record's retained superseded
// provenance stays fatal, a manifest still carrying that stored authority stays
// a bounded remount deferral (never an adoption), and the ordinary store
// adoption changes only manifest_json and the ordinary write timestamp while
// the creation-dispatched flag, service generation, phase and retained native
// registration stay exactly as they were.
func TestReconcileKeepsTheStoredAuthorityTieAndTheManifestOnlyWrite(t *testing.T) {
	t.Run("stored root is not the record's superseded provenance", func(t *testing.T) {
		journey := newManagerPolicyJourney(t)
		ctx := context.Background()
		remount := seedRemountedManagedProject(t, journey, nil)
		journeyCatalog(t, journey).LoopBacking = func(uint64) (string, error) { return journey.imagePath, nil }
		other := remountManifest(journey, remount, "sha256:"+strings.Repeat("9", 64))
		before := seedRegisteredRemountServiceRow(t, journey, other.ManagedServices[0])
		beforeRow := rawManagedServiceColumns(t, journey, before.Manifest.Identity.ServiceRegistrationID)
		stored := remountManifest(journey, remount, remount.attestation)
		if err := journey.reconciler.Reconcile(ctx, stored); err != nil {
			t.Fatalf("pre-ratification pass aborted: %v", err)
		}
		record := storedManagedProjectRecord(t, journey.store, remount.record.Report.SelectionID)
		ratified := remountManifest(journey, remount, record.Report.RootAttestation)
		ratified.ManagedServices[0].Workspace.ScopeRevision = before.Manifest.Workspace.ScopeRevision + 1
		err := journey.reconciler.Reconcile(ctx, ratified)
		if err == nil || !errors.Is(err, state.ErrManagedServiceConflict) {
			t.Fatalf("wrong stored authority was not the immutable identity conflict: %v", err)
		}
		assertRefusedServiceUntouched(t, journey, remount.serviceID, beforeRow)
	})

	t.Run("manifest still carrying the stored authority stays deferred", func(t *testing.T) {
		journey, remount, before, incoming, record := registeredRemountJourney(t)
		ctx := context.Background()
		incoming.Workspace.RootAttestation = before.Manifest.Workspace.RootAttestation
		manifest := remountManifest(journey, remount, record.Report.RootAttestation)
		manifest.ManagedServices[0] = incoming
		beforeRow := rawManagedServiceColumns(t, journey, remount.serviceID)
		if err := journey.reconciler.Reconcile(ctx, manifest); err != nil {
			t.Fatalf("unratified-root manifest aborted the pass: %v", err)
		}
		assertRefusedServiceUntouched(t, journey, remount.serviceID, beforeRow)
	})

	t.Run("adoption write moves only manifest_json and updated_at", func(t *testing.T) {
		journey, remount, before, incoming, _ := registeredRemountJourney(t)
		ctx := context.Background()
		storedRow := rawManagedServiceColumns(t, journey, remount.serviceID)
		if err := journey.store.PutManagedServiceIntent(ctx, state.LocalManagedService{
			Manifest: incoming, Phase: "pending",
			ProcessInstance:   before.ProcessInstance,
			Port:              before.Port,
			ServiceGeneration: before.ServiceGeneration,
		}); err != nil {
			t.Fatalf("adoption refused: %v", err)
		}
		adoptedRow := rawManagedServiceColumns(t, journey, remount.serviceID)
		if adoptedRow["creation_dispatched"] != "1" {
			t.Fatalf("adoption reset the creation-dispatched flag: %v", adoptedRow["creation_dispatched"])
		}
		if storedRow["phase"] != adoptedRow["phase"] || storedRow["report_json"] != adoptedRow["report_json"] ||
			storedRow["error_code"] != adoptedRow["error_code"] || storedRow["process_instance"] != adoptedRow["process_instance"] ||
			storedRow["port"] != adoptedRow["port"] || storedRow["service_generation"] != adoptedRow["service_generation"] {
			t.Fatalf("adoption moved an execution or history field: before=%v after=%v", storedRow, adoptedRow)
		}
		if storedRow["updated_at"] == adoptedRow["updated_at"] {
			t.Fatalf("ordinary write timestamp did not move")
		}
		if storedRow["manifest_json"] == adoptedRow["manifest_json"] {
			t.Fatalf("manifest_json did not change")
		}
		var adopted model.ManagedServiceV1
		if err := json.Unmarshal([]byte(adoptedRow["manifest_json"]), &adopted); err != nil {
			t.Fatal(err)
		}
		if adopted.Workspace.ScopeRevision != incoming.Workspace.ScopeRevision ||
			adopted.Workspace.RootAttestation != incoming.Workspace.RootAttestation {
			t.Fatalf("adopted manifest did not carry the ratified workspace fields: %#v", adopted.Workspace)
		}
		var retained model.ManagedServiceReportV1
		if err := json.Unmarshal([]byte(storedRow["report_json"]), &retained); err != nil {
			t.Fatal(err)
		}
		if retained.NativeRegistration == nil || retained.NativeRegistration.NativeSessionID != "ses_registered_remount_0001" {
			t.Fatalf("deployed row did not retain its native registration: %#v", retained.NativeRegistration)
		}
	})
}

// TestPutManagedServiceIntentDecidesOnTheDurableProjectAuthority proves the
// adoption can never rest on the caller's manifest: the reconcile path
// resolved this exact manifest against the record's ratified authority, but the
// record moves before the store call (its retained superseded provenance is
// gone). The identical call is refused and the retained service row stays
// byte-unchanged, because the predicate is evaluated against the durable
// managed-project record inside the same store transaction that would write the
// manifest.
func TestPutManagedServiceIntentDecidesOnTheDurableProjectAuthority(t *testing.T) {
	journey, remount, before, incoming, record := registeredRemountJourney(t)
	ctx := context.Background()
	database, err := sql.Open("sqlite", journey.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	moved := record
	moved.SupersededRootAttestation = ""
	private, err := json.Marshal(moved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`UPDATE managed_workspace_projects SET private_json=? WHERE selection_id=?`, private, record.Report.SelectionID); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	beforeRow := rawManagedServiceColumns(t, journey, remount.serviceID)

	err = journey.store.PutManagedServiceIntent(ctx, state.LocalManagedService{
		Manifest: incoming, Phase: "pending",
		ProcessInstance: before.ProcessInstance, Port: before.Port, ServiceGeneration: before.ServiceGeneration,
	})
	if err == nil || !errors.Is(err, state.ErrManagedServiceConflict) {
		t.Fatalf("stale caller authority was admitted: %v", err)
	}
	if after := rawManagedServiceColumns(t, journey, remount.serviceID); !reflect.DeepEqual(beforeRow, after) {
		t.Fatalf("refused stale-authority adoption moved the retained row: before=%v after=%v", beforeRow, after)
	}
}
