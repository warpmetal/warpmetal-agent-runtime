package workspacecatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

func TestEnsureDefaultTeamProjectCreatesOnlyNewEmptyOwnedRootAndReplaysStableIdentity(t *testing.T) {
	anchor := t.TempDir()
	if err := os.WriteFile(filepath.Join(anchor, ".warpmetal"), []byte("credential sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	store := openCatalogStore(t)
	catalog := Catalog{State: store, Now: func() time.Time { return time.Date(2026, 9, 27, 18, 0, 0, 0, time.UTC) }}
	request := defaultProjectRequest(anchor)

	created, err := catalog.EnsureDefault(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	wantRoot := filepath.Join(anchor, "projects", request.TeamID)
	if created.HostRoot != wantRoot || created.ContainerRoot != "/home/agent/projects/"+request.TeamID {
		t.Fatalf("registered roots = %q / %q", created.HostRoot, created.ContainerRoot)
	}
	if created.Report.FormatVersion != 1 || created.Report.Designation != "team_project" ||
		created.Report.Availability != "available" || created.Report.Reason != nil ||
		!strings.HasPrefix(created.Report.SelectionID, "selection_") ||
		!strings.HasPrefix(created.Report.ProjectID, "project_") ||
		!strings.HasPrefix(created.Report.WorkspaceEpoch, "epoch_") ||
		!strings.HasPrefix(created.Report.RootAttestation, "sha256:") {
		t.Fatalf("default project report = %#v", created.Report)
	}
	assertOrdinaryGitRepository(t, created.HostRoot)
	if got, err := os.ReadFile(filepath.Join(anchor, ".warpmetal")); err != nil || string(got) != "credential sentinel" {
		t.Fatalf("default project changed managed state: %q %v", got, err)
	}

	replayed, err := catalog.EnsureDefault(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replayed.Report, created.Report) || replayed.HostRoot != created.HostRoot || replayed.ContainerRoot != created.ContainerRoot {
		t.Fatalf("default project replay drifted:\n first=%#v\nreplay=%#v", created, replayed)
	}
	payload, err := json.Marshal(created.Report)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{anchor, "hostRoot", "containerRoot", "relativeRoot", "device", "inode"} {
		if strings.Contains(string(payload), private) {
			t.Fatalf("catalog report leaked host-private root fact %q: %s", private, payload)
		}
	}
}

func TestEnsureDefaultTeamProjectRefusesExistingSymlinkedOrManagedRootsWithoutGitInit(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, string, DefaultProjectRequest) string{
		"existing target": func(t *testing.T, anchor string, request DefaultProjectRequest) string {
			t.Helper()
			target := filepath.Join(anchor, "projects", request.TeamID)
			if err := os.MkdirAll(target, 0700); err != nil {
				t.Fatal(err)
			}
			return target
		},
		"symlinked projects": func(t *testing.T, anchor string, _ DefaultProjectRequest) string {
			t.Helper()
			outside := t.TempDir()
			if err := os.Symlink(outside, filepath.Join(anchor, "projects")); err != nil {
				t.Fatal(err)
			}
			return outside
		},
		"managed state collision": func(t *testing.T, anchor string, request DefaultProjectRequest) string {
			t.Helper()
			target := filepath.Join(anchor, "projects", request.TeamID)
			if err := os.MkdirAll(target, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, ".warpmetal"), []byte("must survive"), 0600); err != nil {
				t.Fatal(err)
			}
			return target
		},
	} {
		t.Run(name, func(t *testing.T) {
			anchor := t.TempDir()
			request := defaultProjectRequest(anchor)
			protected := prepare(t, anchor, request)
			catalog := Catalog{State: openCatalogStore(t)}
			if _, err := catalog.EnsureDefault(context.Background(), request); !errors.Is(err, ErrUnsafeProjectRoot) {
				t.Fatalf("unsafe existing root error = %v", err)
			}
			if _, err := os.Lstat(filepath.Join(protected, ".git")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe existing root was initialized: %v", err)
			}
		})
	}
}

func TestEnsureDefaultGitInitializationCannotBeRedirectedByRootReplacement(t *testing.T) {
	anchor := t.TempDir()
	request := defaultProjectRequest(anchor)
	replacement := t.TempDir()
	sentinel := filepath.Join(replacement, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	var original string
	catalog := Catalog{State: openCatalogStore(t), BeforeGit: func() {
		root := filepath.Join(anchor, "projects", request.TeamID)
		original = root + ".recorded"
		if err := os.Rename(root, original); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(replacement, root); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := catalog.EnsureDefault(context.Background(), request); !errors.Is(err, ErrProjectChanged) {
		t.Fatalf("replacement race = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(replacement, ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement target was initialized: %v", err)
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "unchanged" {
		t.Fatalf("replacement target changed: %q %v", got, err)
	}
	assertOrdinaryGitRepository(t, original)
}

func TestEnsureDefaultDoesNotPublishReadyWhenDurabilitySyncFails(t *testing.T) {
	anchor := t.TempDir()
	request := defaultProjectRequest(anchor)
	store := openCatalogStore(t)
	catalog := Catalog{State: store, Sync: func(*os.File) error { return errors.New("injected fsync failure") }}
	if _, err := catalog.EnsureDefault(context.Background(), request); err == nil {
		t.Fatal("fsync failure was ignored")
	}
	record, err := store.ManagedProjectForTeam(context.Background(), request.SandboxID, request.SandboxGeneration, request.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil || record.Phase == "ready" || record.Report.Availability == "available" {
		t.Fatalf("failed publication became ready: %#v", record)
	}
}

func TestResolveRejectsRootReplacementConfigGenerationAndEpochRaces(t *testing.T) {
	anchor := t.TempDir()
	store := openCatalogStore(t)
	catalog := Catalog{State: store}
	request := defaultProjectRequest(anchor)
	registered, err := catalog.EnsureDefault(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	resolve := ResolveProjectRequest{SelectionID: registered.Report.SelectionID, ProjectID: registered.Report.ProjectID, WorkspaceEpoch: registered.Report.WorkspaceEpoch, SandboxID: request.SandboxID, SandboxGeneration: request.SandboxGeneration, ServiceRegistrationID: request.ServiceRegistrationID, ConfigDigest: request.ConfigDigest}
	if _, err := catalog.Resolve(context.Background(), resolve); err != nil {
		t.Fatal(err)
	}

	original := registered.HostRoot + ".original"
	if err := os.Rename(registered.HostRoot, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(registered.HostRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Resolve(context.Background(), resolve); !errors.Is(err, ErrProjectChanged) {
		t.Fatalf("replacement root resolve = %v", err)
	}
	resolve.WorkspaceEpoch = "epoch_wrong0001"
	if _, err := catalog.Resolve(context.Background(), resolve); !errors.Is(err, ErrProjectChanged) {
		t.Fatalf("stale epoch resolve = %v", err)
	}
	resolve.WorkspaceEpoch = registered.Report.WorkspaceEpoch
	resolve.SandboxGeneration++
	if _, err := catalog.Resolve(context.Background(), resolve); !errors.Is(err, ErrProjectChanged) {
		t.Fatalf("stale sandbox generation resolve = %v", err)
	}
	resolve.SandboxGeneration = request.SandboxGeneration
	resolve.ConfigDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := catalog.Resolve(context.Background(), resolve); !errors.Is(err, ErrProjectChanged) {
		t.Fatalf("stale config resolve = %v", err)
	}
}

func TestExplicitRebindPreservesAllocatedStorageIdentity(t *testing.T) {
	anchor := t.TempDir()
	catalog := Catalog{State: openCatalogStore(t)}
	request := defaultProjectRequest(anchor)
	created, err := catalog.EnsureDefault(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	reboundRequest := request
	reboundRequest.ServiceRegistrationID = "service_catalog0002"
	reboundRequest.ConfigDigest = "sha256:" + strings.Repeat("b", 64)
	if _, err := catalog.EnsureDefault(context.Background(), reboundRequest); !errors.Is(err, ErrProjectChanged) {
		t.Fatalf("implicit rebind = %v", err)
	}
	reboundRequest.RebindSelectionID = created.Report.SelectionID
	rebound, err := catalog.EnsureDefault(context.Background(), reboundRequest)
	if err != nil {
		t.Fatal(err)
	}
	if rebound.Report.SelectionID != created.Report.SelectionID || rebound.Report.ProjectID != created.Report.ProjectID ||
		rebound.Report.WorkspaceEpoch != created.Report.WorkspaceEpoch || rebound.HostRoot != created.HostRoot {
		t.Fatalf("explicit rebind replaced storage identity: %#v -> %#v", created, rebound)
	}
}

func TestEnsureDefaultResumesOnlyRecordedCreatedInode(t *testing.T) {
	anchor := t.TempDir()
	request := defaultProjectRequest(anchor)
	root := filepath.Join(anchor, "projects", request.TeamID)
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	anchorFile, anchorIdentity, err := openDirectoryNoFollow(anchor)
	if err != nil {
		t.Fatal(err)
	}
	anchorFile.Close()
	rootFile, rootIdentity, err := openDirectoryNoFollow(root)
	if err != nil {
		t.Fatal(err)
	}
	rootFile.Close()
	store := openCatalogStore(t)
	record := state.LocalManagedProject{
		Report:   model.ProjectCatalogReportV1{FormatVersion: 1, SelectionID: "selection_resume0001", ProjectID: "project_resume0001", WorkspaceEpoch: "epoch_resume0001", SandboxID: request.SandboxID, SandboxGeneration: request.SandboxGeneration, ServiceRegistrationID: stringPointer(request.ServiceRegistrationID), Designation: "team_project", Label: request.TeamID, Availability: "unavailable", Reason: stringPointer("initializing"), LastObservedAt: time.Now().UTC()},
		ServerID: request.ServerID, TeamID: request.TeamID, MemberID: request.MemberID, AllocationDigest: request.AllocationDigest, ConfigDigest: request.ConfigDigest,
		Anchor: anchor, HostRoot: root, ContainerRoot: "/home/agent/projects/" + request.TeamID, Phase: "created",
		AnchorDevice: anchorIdentity.Device, AnchorInode: anchorIdentity.Inode, AnchorMount: anchorIdentity.Mount,
		RootDevice: rootIdentity.Device, RootInode: rootIdentity.Inode, RootMount: rootIdentity.Mount,
	}
	record.Report.RootAttestation = attest(record)
	if err := store.PutManagedProject(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	resumed, err := (Catalog{State: store}).EnsureDefault(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Report.SelectionID != record.Report.SelectionID || resumed.Report.WorkspaceEpoch != record.Report.WorkspaceEpoch {
		t.Fatalf("recovery replaced allocation: %#v", resumed.Report)
	}
	assertOrdinaryGitRepository(t, root)
}

func TestAllocateRestoreCreatesOneDurableNewEmptyLeafAndReplaysByOperation(t *testing.T) {
	anchor := t.TempDir()
	statePath := filepath.Join(t.TempDir(), "runtime.sqlite3")
	store, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	catalog := Catalog{State: store, Now: func() time.Time { return time.Date(2026, 9, 27, 19, 0, 0, 0, time.UTC) }}
	request := RestoreProjectRequest{
		OperationID: "op_restore_catalog0001", Anchor: anchor, ServerID: "srv_catalog0001",
		SandboxID: "sbx_catalog000000000001", SandboxGeneration: 3,
	}
	allocated, err := catalog.AllocateRestore(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if allocated.Report.Designation != "continuity-materialization" || allocated.Report.Availability == "available" ||
		allocated.Report.ServiceRegistrationID != nil {
		t.Fatalf("restore allocation was published as an operational source: %#v", allocated.Report)
	}
	entries, err := os.ReadDir(allocated.HostRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("new restore leaf was not empty before materialization: %#v", entries)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	replayed, err := (Catalog{State: reopened}).AllocateRestore(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.HostRoot != allocated.HostRoot || !reflect.DeepEqual(replayed.Report, allocated.Report) {
		t.Fatalf("restore replay allocated a second target:\nfirst=%#v\nreplay=%#v", allocated, replayed)
	}
	projects, err := reopened.ManagedProjects(context.Background())
	if err != nil || len(projects) != 1 {
		t.Fatalf("durable restore allocation count = %d, %v", len(projects), err)
	}
}

func TestCatalogClassifiesExistingRootsWithoutAdoptingOrInitializingThem(t *testing.T) {
	anchor := t.TempDir()
	projects := filepath.Join(anchor, "projects")
	if err := os.Mkdir(projects, 0700); err != nil {
		t.Fatal(err)
	}
	noGit := filepath.Join(projects, "plain")
	unborn := filepath.Join(projects, "unborn")
	ready := filepath.Join(projects, "ready")
	for _, root := range []string{noGit, unborn, ready} {
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, unborn, "init", "--quiet", "--initial-branch=main")
	runGit(t, ready, "init", "--quiet", "--initial-branch=main")
	runGit(t, ready, "-c", "user.name=WarpMetal Runtime", "-c", "user.email=runtime@localhost", "commit", "--quiet", "--allow-empty", "-m", "Initial project")
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(projects, "escape")); err != nil {
		t.Fatal(err)
	}

	catalog := Catalog{State: openCatalogStore(t)}
	reports, err := catalog.Refresh(context.Background(), RefreshRequest{Anchor: anchor, SandboxID: "sbx_catalog000000000001", SandboxGeneration: 3, Limit: 16})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, report := range reports {
		got[report.Label] = report.Availability + ":" + stringValue(report.Reason)
	}
	if got["plain"] != "unavailable:no_git" || got["unborn"] != "unavailable:unborn" || got["ready"] != "available:" || got["escape"] != "unavailable:unsafe_root" {
		t.Fatalf("catalog capabilities = %#v", got)
	}
	if _, err := os.Lstat(filepath.Join(noGit, ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("catalog initialized an existing directory: %v", err)
	}
}

func TestCatalogRejectsSymlinkedGitControlMetadata(t *testing.T) {
	anchor := t.TempDir()
	projects := filepath.Join(anchor, "projects")
	if err := os.Mkdir(projects, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(projects, "linked-config")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init", "--quiet", "--initial-branch=main")
	runGit(t, root, "-c", "user.name=WarpMetal Runtime", "-c", "user.email=runtime@localhost", "commit", "--quiet", "--allow-empty", "-m", "Initial project")
	config := filepath.Join(root, ".git", "config")
	outside := filepath.Join(t.TempDir(), "config")
	contents, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, contents, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, config); err != nil {
		t.Fatal(err)
	}
	reports, err := (Catalog{State: openCatalogStore(t)}).Refresh(context.Background(), RefreshRequest{Anchor: anchor, SandboxID: "sbx_catalog000000000001", SandboxGeneration: 3, Limit: 16})
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].Availability != "unavailable" || stringValue(reports[0].Reason) != "unsafe_root" {
		t.Fatalf("linked Git metadata capability = %#v", reports)
	}
}

func TestCatalogLimitFailsBeforeObservingOrRegisteringEntries(t *testing.T) {
	anchor := t.TempDir()
	projects := filepath.Join(anchor, "projects")
	if err := os.Mkdir(projects, 0700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 17; index++ {
		if err := os.Mkdir(filepath.Join(projects, fmt.Sprintf("project-%02d", index)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	catalog := Catalog{State: openCatalogStore(t)}
	_, err := catalog.Refresh(context.Background(), RefreshRequest{Anchor: anchor, SandboxID: "sbx_catalog000000000001", SandboxGeneration: 3, Limit: 16})
	if !errors.Is(err, ErrCatalogLimit) {
		t.Fatalf("catalog overflow = %v", err)
	}
}

func defaultProjectRequest(anchor string) DefaultProjectRequest {
	return DefaultProjectRequest{Anchor: anchor, ServerID: "srv_catalog0001", TeamID: "team_catalog0001", MemberID: "tmem_catalog0001", SandboxID: "sbx_catalog000000000001", SandboxGeneration: 3, ServiceRegistrationID: "service_catalog0001", AllocationDigest: "sha256:" + strings.Repeat("c", 64), ConfigDigest: "sha256:" + strings.Repeat("a", 64)}
}

func openCatalogStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func assertOrdinaryGitRepository(t *testing.T, root string) {
	t.Helper()
	runGit(t, root, "rev-parse", "--verify", "HEAD")
	if info, err := os.Lstat(filepath.Join(root, ".git")); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("default root has unsupported Git metadata: %#v %v", info, err)
	}
	if info, err := os.Lstat(filepath.Join(root, ".git", "index")); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("default root has no ordinary index: %#v %v", info, err)
	}
}

func runGit(t *testing.T, root string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %s: %v", arguments, output, err)
	}
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
