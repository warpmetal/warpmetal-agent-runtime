package reconcile

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

// preA5RemountJourney is the live A25 journey state: the deployed managed
// service row and its managed-project record after the documented workspace
// remount was re-attested by the ordinary A5 re-observation, but before the
// durable image identity of the unchanged workspace image was ever bound. The
// pre-A5 runtime the deployed row was written by did not have the field, so the
// record still carries the exactly zero identity while every current authority
// the A25 bind requires is present: the recorded anchor and project root are
// still the exact live directory objects on the unchanged recorded device, the
// workspace image path derives canonically, the host can prove the loop backing
// of that device names exactly that path, and the image is the same regular
// file object the catalog bound at creation.
type preA5RemountJourney struct {
	journey  *managerPolicyJourney
	remount  remountedManagedProject
	incoming model.ManagedServiceV1
	record   state.LocalManagedProject
	image    state.ManagedProjectImageIdentity
}

// newPreA5RemountJourney runs the documented A5 sequence against a deployed row
// that predates the durable image identity and returns the state the backend's
// already-ratified continuation manifest arrives in. The A5 pass must re-attest
// the root to the live device, keep the record's zero identity exactly as the
// pre-A5 runtime left it, and keep the still-unratified service deferred and
// byte-unchanged (asserted here so every A25 journey starts from a proven
// fail-closed deferral, not from an assumed one).
func newPreA5RemountJourney(t *testing.T) preA5RemountJourney {
	t.Helper()
	journey := newManagerPolicyJourney(t)
	ctx := context.Background()
	// The creation path binds the durable identity of the real workspace image
	// object; it is the exact object the A25 bind must observe again.
	allocated := storedManagedProjectRecord(t, journey.store, journey.fixture.ServiceManifest.Workspace.SelectionID)
	image := allocated.ImageIdentity
	if image == (state.ManagedProjectImageIdentity{}) {
		t.Fatalf("journey creation did not bind the workspace image identity: %#v", allocated)
	}
	remount := seedRemountedManagedProject(t, journey, func(record *state.LocalManagedProject) {
		record.ImageIdentity = state.ManagedProjectImageIdentity{}
	})
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
	if record.Phase != "ready" || record.Report.Availability != "available" ||
		record.SupersededRootAttestation != remount.attestation ||
		record.ImageIdentity != (state.ManagedProjectImageIdentity{}) {
		t.Fatalf("the deployed pre-A5 row did not survive the re-observation: %#v", record)
	}
	ratified := remountManifest(journey, remount, record.Report.RootAttestation)
	ratified.ManagedServices[0].Workspace.ScopeRevision = before.Manifest.Workspace.ScopeRevision + 1
	return preA5RemountJourney{
		journey: journey, remount: remount,
		incoming: ratified.ManagedServices[0], record: record, image: image,
	}
}

// bindManifest is the manifest the backend issued before it ratified the
// documented remount: it still selects the deployed project with the
// pre-remount authority the A5 re-observation superseded, so the deferred
// service must stay untouched while the ordinary re-observation binds the
// durable image identity.
func (pre preA5RemountJourney) bindManifest() model.Manifest {
	return remountManifest(pre.journey, pre.remount, pre.remount.attestation)
}

// ratifiedManifest is the manifest the backend issues once it accepted the
// workspace report that carried the re-attested root: the same service and the
// same deployed project tuple, with the workspace scope advanced exactly one
// step and the root changed to the record's current (ratified) attestation.
func (pre preA5RemountJourney) ratifiedManifest() model.Manifest {
	manifest := remountManifest(pre.journey, pre.remount, pre.record.Report.RootAttestation)
	manifest.ManagedServices[0] = pre.incoming
	return manifest
}

// rewriteDurableManagedProjectRow replaces the durable managed-project row with
// the given record exactly as another runtime could have written it, including
// mutations the current store's immutable fence would refuse. It is the
// test-side seam for preparing deployed rows a current runtime never writes.
func rewriteDurableManagedProjectRow(t *testing.T, journey *managerPolicyJourney, record state.LocalManagedProject) {
	t.Helper()
	private, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	report, err := json.Marshal(record.Report)
	if err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", journey.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(context.Background(),
		`UPDATE managed_workspace_projects SET report_json=?, private_json=? WHERE selection_id=?`,
		report, private, record.Report.SelectionID); err != nil {
		t.Fatal(err)
	}
}

// assertOnlyDurableImageIdentityBound proves the A25 write moved nothing but
// the durable image identity plus the ordinary write timestamp: every other
// retained byte of the private record, and the whole published catalog report,
// must be exactly what the pre-A5 runtime wrote, and the bound identity must
// name the exact durable object of the live workspace image, never a zero,
// fabricated or stale observation.
func assertOnlyDurableImageIdentityBound(t *testing.T, before, after map[string]string, live state.ManagedProjectImageIdentity) {
	t.Helper()
	if before["report_json"] != after["report_json"] {
		t.Fatalf("the bind moved the published catalog report: before=%s after=%s", before["report_json"], after["report_json"])
	}
	if before["updated_at"] == after["updated_at"] {
		t.Fatalf("the ordinary write timestamp did not move")
	}
	var beforeFields, afterFields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(before["private_json"]), &beforeFields); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(after["private_json"]), &afterFields); err != nil {
		t.Fatal(err)
	}
	if len(beforeFields) != len(afterFields) {
		t.Fatalf("the bind changed the durable record shape: %v -> %v", beforeFields, afterFields)
	}
	for key, raw := range beforeFields {
		if key == "ImageIdentity" {
			continue
		}
		if !bytes.Equal(raw, afterFields[key]) {
			t.Fatalf("the bind moved durable field %s: before=%s after=%s", key, raw, afterFields[key])
		}
	}
	var previous state.ManagedProjectImageIdentity
	if err := json.Unmarshal(beforeFields["ImageIdentity"], &previous); err != nil {
		t.Fatal(err)
	}
	if previous != (state.ManagedProjectImageIdentity{}) {
		t.Fatalf("the deployed record was not the pre-A5 zero identity: %#v", previous)
	}
	var bound state.ManagedProjectImageIdentity
	if err := json.Unmarshal(afterFields["ImageIdentity"], &bound); err != nil {
		t.Fatal(err)
	}
	if bound == (state.ManagedProjectImageIdentity{}) || !bound.SameDurableObject(live) {
		t.Fatalf("the bind did not record the exact live workspace image object: %#v, want %#v", bound, live)
	}
}

// TestReconcileBindsThePreA5DurableImageIdentityAndThenAdoptsTheRatifiedRemountAuthority
// is the A25 journey. A ready team project re-attested by the documented
// workspace remount still carries the exactly zero durable image identity a
// pre-A5 runtime left, so the A22R predicate correctly refuses the
// backend-ratified service adoption and no ordinary path ever backfills it.
// The extended re-observation must bind that identity only after the complete
// current authority is freshly re-proven, and the bind must move nothing but
// the identity and the ordinary write timestamp. The already-ratified adoption
// then proceeds through the unchanged A22R path while the retained native
// session/process/history facts stay as they were and creation is never
// dispatched a second time.
func TestReconcileBindsThePreA5DurableImageIdentityAndThenAdoptsTheRatifiedRemountAuthority(t *testing.T) {
	pre := newPreA5RemountJourney(t)
	ctx := context.Background()

	// The still-unratified manifest first: the ordinary re-observation binds the
	// durable image identity of the unchanged, freshly re-proven mounted root,
	// while the deployed service stays deferred and byte-unchanged.
	deferredRow := rawManagedServiceColumns(t, pre.journey, pre.remount.serviceID)
	projectRow := rawManagedProjectColumns(t, pre.journey, pre.record.Report.SelectionID)
	if err := pre.journey.reconciler.Reconcile(ctx, pre.bindManifest()); err != nil {
		t.Fatalf("image identity bind pass aborted: %v", err)
	}
	assertOnlyDurableImageIdentityBound(t, projectRow, rawManagedProjectColumns(t, pre.journey, pre.record.Report.SelectionID), pre.image)
	assertRefusedServiceUntouched(t, pre.journey, pre.remount.serviceID, deferredRow)
	bound := storedManagedProjectRecord(t, pre.journey.store, pre.record.Report.SelectionID)
	if !bound.ImageIdentity.SameDurableObject(pre.image) || bound.Report.RootAttestation != pre.record.Report.RootAttestation ||
		bound.SupersededRootAttestation != pre.record.SupersededRootAttestation || bound.Phase != "ready" {
		t.Fatalf("the bind did not preserve the re-attested record authority: %#v", bound)
	}

	// The backend-ratified manifest then adopts through the ordinary A22R path:
	// the only workspace differences are the one-step scope advance and the root
	// that now equals the record's bound attestation.
	serviceRow := rawManagedServiceColumns(t, pre.journey, pre.remount.serviceID)
	projectRow = rawManagedProjectColumns(t, pre.journey, pre.record.Report.SelectionID)
	manifest := pre.ratifiedManifest()
	if err := pre.journey.reconciler.Reconcile(ctx, manifest); err != nil {
		t.Fatalf("ratified manifest did not let the service proceed: %v", err)
	}
	if after := rawManagedProjectColumns(t, pre.journey, pre.record.Report.SelectionID); !reflect.DeepEqual(projectRow, after) {
		t.Fatalf("the adoption rewrote the bound managed-project record: before=%v after=%v", projectRow, after)
	}
	service := storedManagedServiceRow(t, pre.journey.store, pre.remount.serviceID)
	if service == nil || service.Phase != "ready" || service.Report.ObservedState != "ready" || service.ErrorCode != "" ||
		service.Manifest.Workspace.RootAttestation != pre.incoming.Workspace.RootAttestation ||
		service.Manifest.Workspace.ScopeRevision != pre.incoming.Workspace.ScopeRevision {
		t.Fatalf("ratified manifest did not reach the service: %#v", service)
	}
	afterRow := rawManagedServiceColumns(t, pre.journey, pre.remount.serviceID)
	for _, column := range []string{"creation_dispatched", "service_generation", "process_instance", "port"} {
		if afterRow[column] != serviceRow[column] {
			t.Fatalf("the ratified adoption moved the retained execution field %s: before=%v after=%v", column, serviceRow, afterRow)
		}
	}
	if afterRow["phase"] != "ready" {
		t.Fatalf("the ratified adoption did not keep the completed service phase: %v", afterRow["phase"])
	}
	if runtime, ok := pre.journey.reconciler.ManagedRuntime.(*fakeManagedRuntime); !ok || runtime.startCalls != 1 {
		t.Fatalf("the ratified adoption did not dispatch creation exactly once: %#v", pre.journey.reconciler.ManagedRuntime)
	}
	if len(pre.journey.control.enrollments) != 1 || len(pre.journey.control.instructions) != 1 {
		t.Fatalf("ratified manifest did not reconcile the service boundary: %#v %#v", pre.journey.control.enrollments, pre.journey.control.instructions)
	}
	var retained model.ManagedServiceReportV1
	if err := json.Unmarshal([]byte(afterRow["report_json"]), &retained); err != nil {
		t.Fatal(err)
	}
	if retained.NativeRegistration == nil || retained.NativeRegistration.NativeSessionID != "ses_managedservice0001" || retained.WorkspaceStatus != "ready" {
		t.Fatalf("the adopted service did not retain one native session: %#v", retained.NativeRegistration)
	}
	if revision, err := pre.journey.store.Revision(ctx); err != nil || revision != manifest.DesiredRevision {
		t.Fatalf("ratified pass did not advance the applied revision to %d: %d, %v", manifest.DesiredRevision, revision, err)
	}
}

// preA5ImageIdentityMutation is one fail-closed boundary of the A25 bind: a
// mutation of the freshly re-proven authority that must leave the durable
// record byte-identical and its identity exactly zero.
type preA5ImageIdentityMutation struct {
	name   string
	mutate func(t *testing.T, pre preA5RemountJourney)
}

func preA5ImageIdentityMutations() []preA5ImageIdentityMutation {
	recordMutation := func(name string, mutate func(record *state.LocalManagedProject)) preA5ImageIdentityMutation {
		return preA5ImageIdentityMutation{name: name, mutate: func(t *testing.T, pre preA5RemountJourney) {
			t.Helper()
			record := pre.record
			mutate(&record)
			rewriteDurableManagedProjectRow(t, pre.journey, record)
		}}
	}
	return []preA5ImageIdentityMutation{
		recordMutation("record is no longer ready", func(record *state.LocalManagedProject) {
			// An observed (refresh-discovered) record is still an attested
			// record shape no ordinary resume path ever advances.
			record.Phase = "observed"
		}),
		recordMutation("record is no longer a team project", func(record *state.LocalManagedProject) {
			record.Report.Designation = "continuity-handoff"
		}),
		recordMutation("record is no longer available", func(record *state.LocalManagedProject) {
			record.Report.Availability = "unavailable"
		}),
		recordMutation("record no longer self-attests", func(record *state.LocalManagedProject) {
			record.Report.RootAttestation = "sha256:" + strings.Repeat("e", 64)
		}),
		{name: "loop backing is unavailable", mutate: func(t *testing.T, pre preA5RemountJourney) {
			t.Helper()
			journeyCatalog(t, pre.journey).LoopBacking = func(uint64) (string, error) {
				return "", errors.New("loop backing file unavailable")
			}
		}},
		{name: "loop backing names a different image", mutate: func(t *testing.T, pre preA5RemountJourney) {
			t.Helper()
			journeyCatalog(t, pre.journey).LoopBacking = func(uint64) (string, error) {
				return pre.journey.imagePath + "-other", nil
			}
		}},
		{name: "workspace image is missing", mutate: func(t *testing.T, pre preA5RemountJourney) {
			t.Helper()
			if err := os.Remove(pre.journey.imagePath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "workspace image is a symlink", mutate: func(t *testing.T, pre preA5RemountJourney) {
			t.Helper()
			target := filepath.Join(filepath.Dir(pre.journey.imagePath), "workspace-other.ext4")
			if err := os.WriteFile(target, []byte("another workspace image\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(pre.journey.imagePath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, pre.journey.imagePath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "workspace image is not a regular file", mutate: func(t *testing.T, pre preA5RemountJourney) {
			t.Helper()
			if err := os.Remove(pre.journey.imagePath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(pre.journey.imagePath, 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "workspace image identity is zero-size", mutate: func(t *testing.T, pre preA5RemountJourney) {
			t.Helper()
			if err := os.Remove(pre.journey.imagePath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(pre.journey.imagePath, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "project root is no longer the recorded object", mutate: func(t *testing.T, pre preA5RemountJourney) {
			t.Helper()
			if err := os.Rename(pre.record.HostRoot, pre.record.HostRoot+"-moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(pre.record.HostRoot, 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "anchor is no longer the recorded object", mutate: func(t *testing.T, pre preA5RemountJourney) {
			t.Helper()
			if err := os.Rename(pre.record.Anchor, pre.record.Anchor+"-moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(pre.record.Anchor, "projects", filepath.Base(pre.record.HostRoot)), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "anchor no longer derives the workspace image", mutate: func(t *testing.T, pre preA5RemountJourney) {
			t.Helper()
			// The documented Workspaces.Ensure layout names the mountpoint
			// anchor "workspace". An anchor under any other mountpoint name is
			// the legacy anchor whose image cannot be derived, even though a
			// real workspace image file sits right next to it: the bind must
			// never guess the image from a neighbouring file.
			moved := pre.record.Anchor + "-mount"
			if err := os.Rename(pre.record.Anchor, moved); err != nil {
				t.Fatal(err)
			}
			record := pre.record
			record.Anchor = moved
			record.HostRoot = filepath.Join(moved, "projects", filepath.Base(pre.record.HostRoot))
			rewriteDurableManagedProjectRow(t, pre.journey, record)
		}},
	}
}

// TestReconcileRefusesEveryUnprovenImageIdentityBindWithoutWriting is the
// fail-closed boundary of the A25 bind: a record that cannot freshly re-prove
// the complete current authority stays exactly as the pre-A5 runtime left it
// (identity still zero, every durable byte identical), so the ordinary resolve
// keeps refusing it and no unproven identity can ever admit the ratified
// managed service.
func TestReconcileRefusesEveryUnprovenImageIdentityBindWithoutWriting(t *testing.T) {
	for _, mutation := range preA5ImageIdentityMutations() {
		t.Run(mutation.name, func(t *testing.T) {
			pre := newPreA5RemountJourney(t)
			mutation.mutate(t, pre)
			before := rawManagedProjectColumns(t, pre.journey, pre.record.Report.SelectionID)
			_ = pre.journey.reconciler.Reconcile(context.Background(), pre.bindManifest())
			after := rawManagedProjectColumns(t, pre.journey, pre.record.Report.SelectionID)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("unproven bind wrote the durable record: before=%v after=%v", before, after)
			}
			record := storedManagedProjectRecord(t, pre.journey.store, pre.record.Report.SelectionID)
			if record.ImageIdentity != (state.ManagedProjectImageIdentity{}) {
				t.Fatalf("unproven bind recorded an image identity: %#v", record.ImageIdentity)
			}
		})
	}
}

// TestReconcileNeverRefreshesOrReplacesAnExistingDurableImageIdentity proves
// the one-way nature of the bind: an already-bound identity is immutable even
// when the live image object behind the same derived path is a different file
// object, so the observation must never refresh or replace it.
func TestReconcileNeverRefreshesOrReplacesAnExistingDurableImageIdentity(t *testing.T) {
	pre := newPreA5RemountJourney(t)
	ctx := context.Background()
	bound := pre.record
	bound.ImageIdentity = pre.image
	rewriteDurableManagedProjectRow(t, pre.journey, bound)
	if err := os.Remove(pre.journey.imagePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pre.journey.imagePath, []byte("a different workspace image\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before := rawManagedProjectColumns(t, pre.journey, pre.record.Report.SelectionID)

	if err := pre.journey.reconciler.Reconcile(ctx, pre.bindManifest()); err != nil {
		t.Fatalf("deferred pass aborted: %v", err)
	}
	if after := rawManagedProjectColumns(t, pre.journey, pre.record.Report.SelectionID); !reflect.DeepEqual(before, after) {
		t.Fatalf("an existing durable image identity was refreshed or replaced: before=%v after=%v", before, after)
	}
	record := storedManagedProjectRecord(t, pre.journey.store, pre.record.Report.SelectionID)
	if !record.ImageIdentity.SameDurableObject(pre.image) {
		t.Fatalf("the retained identity moved off the attested image object: %#v", record.ImageIdentity)
	}
}
