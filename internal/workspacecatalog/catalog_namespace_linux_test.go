//go:build linux

package workspacecatalog

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

const (
	workspaceNamespaceGate  = "WARPMETAL_REAL_MOUNT_NAMESPACE_TEST"
	workspaceNamespacePhase = "WARPMETAL_MOUNT_NAMESPACE_PHASE"
	workspaceNamespaceRoot  = "WARPMETAL_MOUNT_NAMESPACE_ROOT"
	workspaceOwnerGate      = "WARPMETAL_REAL_WORKSPACE_OWNER_TEST"
	workspaceOwnerChildRoot = "WARPMETAL_WORKSPACE_OWNER_CHILD_ROOT"
	workspaceOwnerChildGit  = "WARPMETAL_WORKSPACE_OWNER_CHILD_GIT"
	workspaceHostUID        = 997
	workspaceHostGID        = 987
)

// TestCatalogRootsWorkForMappedWorkspaceOwner exercises the Linux permission
// boundary used by Podman's keep-id mapping. Runtime allocates as root, while
// the worker runs as the host UID/GID that owns the trusted workspace anchor.
// This test must run as root in an isolated Linux test container.
func TestCatalogRootsWorkForMappedWorkspaceOwner(t *testing.T) {
	if root := os.Getenv(workspaceOwnerChildRoot); root != "" {
		probeMappedOwner(t, root, os.Getenv(workspaceOwnerChildGit) == "1")
		return
	}
	if os.Getenv(workspaceOwnerGate) != "1" {
		t.Skip("real workspace owner journey requires an explicit privileged Linux gate")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real workspace owner journey requires root in a private test container")
	}
	previousUmask := syscall.Umask(0027) // packaged warpmetald.service execution policy
	t.Cleanup(func() { syscall.Umask(previousUmask) })
	shared := t.TempDir()
	if err := os.Chmod(filepath.Dir(shared), 0711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0711); err != nil {
		t.Fatal(err)
	}
	store := openWorkspaceNamespaceStore(t, shared)
	defer store.Close()
	catalog := Catalog{State: store}
	for _, name := range []string{"default", "restore", "handoff"} {
		t.Run(name, func(t *testing.T) {
			anchor := filepath.Join(shared, name)
			if err := os.Mkdir(anchor, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(anchor, workspaceHostUID, workspaceHostGID); err != nil {
				t.Fatal(err)
			}
			var project RegisteredProject
			var err error
			switch name {
			case "default":
				project, err = catalog.EnsureDefault(context.Background(), namespaceDefaultRequest(anchor, "owner", "c"))
			case "restore":
				project, err = catalog.AllocateRestore(context.Background(), restoreNamespaceRequest(anchor))
			case "handoff":
				project, err = catalog.AllocateHandoff(context.Background(), handoffNamespaceRequest(anchor))
			}
			if err != nil {
				t.Fatal(err)
			}
			if name != "default" {
				// The real continuity controller materializes a verified
				// checkpoint before publishing these leaves. Seed only the
				// ordinary Git layout here so the catalog completion boundary
				// is exercised without claiming to test checkpoint ownership.
				root, _, err := openDirectoryNoFollow(project.HostRoot)
				if err != nil {
					t.Fatal(err)
				}
				err = initializeGit(context.Background(), root, catalog.now())
				root.Close()
				if err != nil {
					t.Fatal(err)
				}
				if err := filepath.WalkDir(project.HostRoot, func(path string, entry os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if entry.Type()&os.ModeSymlink != 0 {
						return ErrUnsafeProjectRoot
					}
					return os.Chown(path, workspaceHostUID, workspaceHostGID)
				}); err != nil {
					t.Fatal(err)
				}
				if name == "restore" {
					project, err = catalog.CompleteRestore(context.Background(), restoreNamespaceRequest(anchor).OperationID)
				} else {
					project, err = catalog.CompleteHandoff(context.Background(), handoffNamespaceRequest(anchor).OperationID)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			assertMappedOwnerCanWrite(t, project.HostRoot, true)
		})
	}
}

// An installed pre-fix catalog record has the correct inode/attestation but
// root-owned 0700 generated directories. Resolving that exact record must
// repair access without changing its durable identity or user work.
func TestCatalogRepairsOnlyAttestedLegacyBootstrap(t *testing.T) {
	if os.Getenv(workspaceOwnerGate) != "1" {
		t.Skip("real workspace owner journey requires an explicit privileged Linux gate")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real workspace owner journey requires root in a private test container")
	}
	previousUmask := syscall.Umask(0027) // packaged warpmetald.service execution policy
	t.Cleanup(func() { syscall.Umask(previousUmask) })
	shared := t.TempDir()
	if err := os.Chmod(filepath.Dir(shared), 0711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0711); err != nil {
		t.Fatal(err)
	}
	anchor := filepath.Join(shared, "legacy")
	if err := os.Mkdir(anchor, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(anchor, workspaceHostUID, workspaceHostGID); err != nil {
		t.Fatal(err)
	}
	store := openWorkspaceNamespaceStore(t, shared)
	defer store.Close()
	catalog := Catalog{State: store}
	request := namespaceDefaultRequest(anchor, "legacy", "d")
	project, err := catalog.EnsureDefault(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	before := namespaceRecordForTeam(t, store, request)
	identity := immutableNamespaceRecord(*before)
	// Restrict the fixture to the ordinary empty Git bootstrap created by
	// Runtime. No external repository or arbitrary worktree is traversed.
	if err := filepath.WalkDir(filepath.Join(project.HostRoot, ".git"), func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, 0, 0)
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{project.HostRoot, filepath.Join(anchor, "projects")} {
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := catalog.Resolve(context.Background(), resolveForRecord(*before)); err != nil {
		t.Fatalf("resolve attested legacy bootstrap: %v", err)
	}
	assertNamespaceRecordImmutable(t, store, before.Report.SelectionID, identity)
	assertMappedOwnerCanWrite(t, project.HostRoot, true)
}

func TestCatalogRefusesLegacyRepairWhenWorktreeContainsUnattributedContent(t *testing.T) {
	if os.Getenv(workspaceOwnerGate) != "1" {
		t.Skip("real workspace owner journey requires an explicit privileged Linux gate")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real workspace owner journey requires root in a private test container")
	}
	previousUmask := syscall.Umask(0027) // packaged warpmetald.service execution policy
	t.Cleanup(func() { syscall.Umask(previousUmask) })
	shared := t.TempDir()
	anchor := filepath.Join(shared, "unattributed")
	if err := os.Mkdir(anchor, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(anchor, workspaceHostUID, workspaceHostGID); err != nil {
		t.Fatal(err)
	}
	store := openWorkspaceNamespaceStore(t, shared)
	defer store.Close()
	catalog := Catalog{State: store}
	request := namespaceDefaultRequest(anchor, "unattributed", "e")
	project, err := catalog.EnsureDefault(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(project.HostRoot, "user-work.txt")
	if err := os.WriteFile(foreign, []byte("preserve this exact user work\n"), 0600); err != nil {
		t.Fatal(err)
	}
	beforeFile, err := os.Stat(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(project.HostRoot, 0, 0); err != nil {
		t.Fatal(err)
	}
	record := namespaceRecordForTeam(t, store, request)
	if _, err := catalog.Resolve(context.Background(), resolveForRecord(*record)); !errors.Is(err, ErrProjectChanged) {
		t.Fatalf("unattributed legacy content was repaired: %v", err)
	}
	afterFile, err := os.Stat(foreign)
	if err != nil || !os.SameFile(beforeFile, afterFile) {
		t.Fatalf("unattributed file identity changed: %v", err)
	}
	content, err := os.ReadFile(foreign)
	if err != nil || string(content) != "preserve this exact user work\n" {
		t.Fatalf("unattributed file content changed: %q, %v", content, err)
	}
	info, err := os.Stat(project.HostRoot)
	if err != nil {
		t.Fatal(err)
	}
	if stat := info.Sys().(*syscall.Stat_t); stat.Uid != 0 || stat.Gid != 0 {
		t.Fatalf("rejected legacy root ownership changed to %d:%d", stat.Uid, stat.Gid)
	}
	t.Run("unsafe_root_mode", func(t *testing.T) {
		if err := os.Chmod(project.HostRoot, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := catalog.Resolve(context.Background(), resolveForRecord(*record)); !errors.Is(err, ErrProjectChanged) {
			t.Fatalf("unsafe legacy root mode was accepted: %v", err)
		}
		info, err := os.Stat(project.HostRoot)
		if err != nil || info.Mode().Perm() != 0755 {
			t.Fatalf("rejected legacy root mode changed: %v", err)
		}
	})
}

func assertMappedOwnerCanWrite(t *testing.T, root string, gitProject bool) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestCatalogRootsWorkForMappedWorkspaceOwner$", "-test.v")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: workspaceHostUID, Gid: workspaceHostGID}}
	git := "0"
	if gitProject {
		git = "1"
	}
	command.Env = append(os.Environ(), workspaceOwnerChildRoot+"="+root, workspaceOwnerChildGit+"="+git)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("mapped host UID/GID cannot traverse and write %s: %v\n%s", root, err, output)
	}
}

func probeMappedOwner(t *testing.T, root string, gitProject bool) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "worker-probe.txt"), []byte("owner probe\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !gitProject {
		return
	}
	if _, err := os.ReadFile(filepath.Join(root, ".git", "HEAD")); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(root, ".git", "index.lock")
	if err := os.WriteFile(lock, []byte("lock probe\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	objectDirectory := filepath.Join(root, ".git", "objects", "ff")
	if err := os.Mkdir(objectDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(objectDirectory, "owner-probe"), []byte("object probe\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

// TestCatalogIdentitySurvivesMountNamespaceRestart is a privileged Linux
// journey. Each child runs in a fresh mount namespace and bind-mounts the same
// host-controlled anchor onto itself, matching systemd ReadWritePaths across
// service restarts. Production must preserve the durable object identity while
// continuing to reject a nested root or Git bind mount.
func TestCatalogIdentitySurvivesMountNamespaceRestart(t *testing.T) {
	if phase := os.Getenv(workspaceNamespacePhase); phase != "" {
		runWorkspaceNamespacePhase(t, phase, os.Getenv(workspaceNamespaceRoot))
		return
	}
	if os.Getenv(workspaceNamespaceGate) != "1" {
		t.Skip("real mount namespace journey requires an explicit privileged Linux gate")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real mount namespace journey requires root in a private test container")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Fatal("real mount namespace journey requires util-linux unshare")
	}

	shared := t.TempDir()
	runWorkspaceNamespaceChild(t, shared, "initialize")
	for _, phase := range []string{
		"ready_resolve",
		"ready_replay",
		"ready_refresh",
		"created_resume",
		"restore_replay",
		"handoff_replay",
		"nested_root_rejected",
		"nested_git_rejected",
	} {
		phase := phase
		t.Run(phase, func(t *testing.T) {
			runWorkspaceNamespaceChild(t, shared, phase)
		})
	}
}

func runWorkspaceNamespaceChild(t *testing.T, shared, phase string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(
		"unshare", "--mount", "--propagation", "private", "--",
		executable, "-test.run=^TestCatalogIdentitySurvivesMountNamespaceRestart$", "-test.v",
	)
	command.Env = append(os.Environ(), workspaceNamespacePhase+"="+phase, workspaceNamespaceRoot+"="+shared)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("mount namespace phase %s: %v\n%s", phase, err, output)
	}
}

func runWorkspaceNamespacePhase(t *testing.T, phase, shared string) {
	t.Helper()
	if shared == "" || !filepath.IsAbs(shared) {
		t.Fatal("invalid shared journey root")
	}
	if phase == "initialize" {
		initializeWorkspaceNamespaceJourney(t, shared)
		return
	}

	store := openWorkspaceNamespaceStore(t, shared)
	defer store.Close()
	catalog := Catalog{State: store}
	switch phase {
	case "ready_resolve":
		record := namespaceRecordForTeam(t, store, readyNamespaceRequest(filepath.Join(shared, "ready")))
		bindFreshNamespaceAnchor(t, record.Anchor, record.AnchorMount)
		assertNamespaceClone(t, *record)
		if _, err := catalog.Resolve(context.Background(), resolveForRecord(*record)); err != nil {
			t.Fatalf("resolve across mount namespace restart: %v", err)
		}
	case "ready_replay":
		request := readyNamespaceRequest(filepath.Join(shared, "ready"))
		record := namespaceRecordForTeam(t, store, request)
		before := immutableNamespaceRecord(*record)
		bindFreshNamespaceAnchor(t, record.Anchor, record.AnchorMount)
		assertNamespaceClone(t, *record)
		if _, err := catalog.EnsureDefault(context.Background(), request); err != nil {
			t.Fatalf("default replay across mount namespace restart: %v", err)
		}
		assertNamespaceRecordImmutable(t, store, record.Report.SelectionID, before)
	case "ready_refresh":
		request := readyNamespaceRequest(filepath.Join(shared, "ready"))
		record := namespaceRecordForTeam(t, store, request)
		before := immutableNamespaceRecord(*record)
		bindFreshNamespaceAnchor(t, record.Anchor, record.AnchorMount)
		assertNamespaceClone(t, *record)
		reports, err := catalog.Refresh(context.Background(), RefreshRequest{
			Anchor: record.Anchor, SandboxID: request.SandboxID, SandboxGeneration: request.SandboxGeneration, Limit: 8,
		})
		if err != nil {
			t.Fatalf("refresh across mount namespace restart: %v", err)
		}
		if len(reports) != 1 || reports[0].SelectionID != record.Report.SelectionID ||
			reports[0].RootAttestation != record.Report.RootAttestation || reports[0].Availability != "available" {
			t.Fatalf("refreshed report changed durable identity: %#v", reports)
		}
		assertNamespaceRecordImmutable(t, store, record.Report.SelectionID, before)
	case "created_resume":
		request := createdNamespaceRequest(filepath.Join(shared, "created"))
		record := namespaceRecordForTeam(t, store, request)
		before := immutableNamespaceRecord(*record)
		bindFreshNamespaceAnchor(t, record.Anchor, record.AnchorMount)
		assertNamespaceClone(t, *record)
		resumed, err := catalog.EnsureDefault(context.Background(), request)
		if err != nil {
			t.Fatalf("created project resume across mount namespace restart: %v", err)
		}
		if resumed.Report.SelectionID != record.Report.SelectionID || resumed.Report.ProjectID != record.Report.ProjectID ||
			resumed.Report.WorkspaceEpoch != record.Report.WorkspaceEpoch || resumed.Report.RootAttestation != record.Report.RootAttestation {
			t.Fatalf("created project resume changed durable identity: %#v", resumed.Report)
		}
		assertNamespaceRecordImmutable(t, store, record.Report.SelectionID, before)
	case "restore_replay":
		request := restoreNamespaceRequest(filepath.Join(shared, "restore"))
		record := namespaceRecordForAllocation(t, store, "restore:"+request.OperationID)
		before := immutableNamespaceRecord(*record)
		bindFreshNamespaceAnchor(t, record.Anchor, record.AnchorMount)
		assertNamespaceClone(t, *record)
		replayed, err := catalog.AllocateRestore(context.Background(), request)
		if err != nil {
			t.Fatalf("restore replay across mount namespace restart: %v", err)
		}
		if !reflect.DeepEqual(replayed.Report, record.Report) || replayed.HostRoot != record.HostRoot {
			t.Fatalf("restore replay changed durable identity: %#v", replayed)
		}
		assertNamespaceRecordImmutable(t, store, record.Report.SelectionID, before)
	case "handoff_replay":
		request := handoffNamespaceRequest(filepath.Join(shared, "handoff"))
		record := namespaceRecordForHandoff(t, store, request.OperationID)
		before := immutableNamespaceRecord(*record)
		bindFreshNamespaceAnchor(t, record.Anchor, record.AnchorMount)
		assertNamespaceClone(t, *record)
		replayed, err := catalog.AllocateHandoff(context.Background(), request)
		if err != nil {
			t.Fatalf("handoff replay across mount namespace restart: %v", err)
		}
		if !reflect.DeepEqual(replayed.Report, record.Report) || replayed.HostRoot != record.HostRoot {
			t.Fatalf("handoff replay changed durable identity: %#v", replayed)
		}
		assertNamespaceRecordImmutable(t, store, record.Report.SelectionID, before)
	case "nested_root_rejected":
		record := namespaceRecordForTeam(t, store, readyNamespaceRequest(filepath.Join(shared, "ready")))
		bindFreshNamespaceAnchor(t, record.Anchor, record.AnchorMount)
		assertNamespaceClone(t, *record)
		bindSelf(t, record.HostRoot)
		assertNestedMount(t, record.Anchor, record.HostRoot)
		if _, err := catalog.Resolve(context.Background(), resolveForRecord(*record)); !errors.Is(err, ErrProjectChanged) {
			t.Fatalf("nested root bind was accepted: %v", err)
		}
	case "nested_git_rejected":
		record := namespaceRecordForTeam(t, store, readyNamespaceRequest(filepath.Join(shared, "ready")))
		bindFreshNamespaceAnchor(t, record.Anchor, record.AnchorMount)
		assertNamespaceClone(t, *record)
		bindSelf(t, filepath.Join(record.HostRoot, ".git"))
		assertNestedMount(t, record.HostRoot, filepath.Join(record.HostRoot, ".git"))
		if _, err := catalog.Resolve(context.Background(), resolveForRecord(*record)); !errors.Is(err, ErrProjectChanged) {
			t.Fatalf("nested Git bind was accepted: %v", err)
		}
	default:
		t.Fatalf("unsupported mount namespace phase %q", phase)
	}
}

func initializeWorkspaceNamespaceJourney(t *testing.T, shared string) {
	t.Helper()
	for _, name := range []string{"ready", "created", "restore", "handoff"} {
		anchor := filepath.Join(shared, name)
		if err := os.Mkdir(anchor, 0700); err != nil {
			t.Fatal(err)
		}
		bindSelf(t, anchor)
	}
	store := openWorkspaceNamespaceStore(t, shared)
	defer store.Close()

	if _, err := (Catalog{State: store}).EnsureDefault(context.Background(), readyNamespaceRequest(filepath.Join(shared, "ready"))); err != nil {
		t.Fatal(err)
	}

	interrupted := &struct{}{}
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_, _ = (Catalog{State: store, BeforeGit: func() { panic(interrupted) }}).EnsureDefault(
			context.Background(), createdNamespaceRequest(filepath.Join(shared, "created")),
		)
	}()
	if recovered != interrupted {
		t.Fatalf("created project journey did not stop at the durable pre-Git boundary: %#v", recovered)
	}
	created := namespaceRecordForTeam(t, store, createdNamespaceRequest(filepath.Join(shared, "created")))
	if created.Phase != "created" || created.RootInode == 0 || created.Report.RootAttestation == "" {
		t.Fatalf("interrupted created project = %#v", created)
	}

	if _, err := (Catalog{State: store}).AllocateRestore(context.Background(), restoreNamespaceRequest(filepath.Join(shared, "restore"))); err != nil {
		t.Fatal(err)
	}
	if _, err := (Catalog{State: store}).AllocateHandoff(context.Background(), handoffNamespaceRequest(filepath.Join(shared, "handoff"))); err != nil {
		t.Fatal(err)
	}
}

func openWorkspaceNamespaceStore(t *testing.T, shared string) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(shared, "runtime.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func bindSelf(t *testing.T, path string) {
	t.Helper()
	if err := unix.Mount(path, path, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		t.Fatalf("bind test fixture: %v", err)
	}
}

func bindFreshNamespaceAnchor(t *testing.T, anchor, storedMount string) {
	t.Helper()
	for attempt := 0; attempt < 8; attempt++ {
		bindSelf(t, anchor)
		file, current, err := openDirectoryNoFollow(anchor)
		if err != nil {
			t.Fatal(err)
		}
		file.Close()
		if current.Mount != storedMount {
			return
		}
	}
	t.Fatal("fresh namespace did not produce a distinct mount identity")
}

func assertNamespaceClone(t *testing.T, record state.LocalManagedProject) {
	t.Helper()
	anchor, anchorIdentity, err := openDirectoryNoFollow(record.Anchor)
	if err != nil {
		t.Fatal(err)
	}
	anchor.Close()
	root, rootIdentity, err := openDirectoryNoFollow(record.HostRoot)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	if anchorIdentity.Device != record.AnchorDevice || anchorIdentity.Inode != record.AnchorInode ||
		rootIdentity.Device != record.RootDevice || rootIdentity.Inode != record.RootInode ||
		anchorIdentity.Mount == record.AnchorMount || rootIdentity.Mount == record.RootMount ||
		!sameMount(anchorIdentity, rootIdentity) {
		t.Fatalf("test fixture did not isolate namespace-local mount identity")
	}
}

func assertNestedMount(t *testing.T, parentPath, childPath string) {
	t.Helper()
	parent, parentIdentity, err := openDirectoryNoFollow(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	parent.Close()
	child, childIdentity, err := openDirectoryNoFollow(childPath)
	if err != nil {
		t.Fatal(err)
	}
	child.Close()
	if parentIdentity.Device != childIdentity.Device || sameMount(parentIdentity, childIdentity) {
		t.Fatal("nested bind fixture did not preserve device while changing mount identity")
	}
}

type immutableNamespaceProject struct {
	SelectionID, ProjectID, WorkspaceEpoch, RootAttestation string
	AnchorDevice, AnchorInode, RootDevice, RootInode        uint64
	AnchorMount, RootMount                                  string
}

func immutableNamespaceRecord(record state.LocalManagedProject) immutableNamespaceProject {
	return immutableNamespaceProject{
		SelectionID: record.Report.SelectionID, ProjectID: record.Report.ProjectID,
		WorkspaceEpoch: record.Report.WorkspaceEpoch, RootAttestation: record.Report.RootAttestation,
		AnchorDevice: record.AnchorDevice, AnchorInode: record.AnchorInode, AnchorMount: record.AnchorMount,
		RootDevice: record.RootDevice, RootInode: record.RootInode, RootMount: record.RootMount,
	}
}

func assertNamespaceRecordImmutable(t *testing.T, store *state.Store, selectionID string, before immutableNamespaceProject) {
	t.Helper()
	after, err := store.ManagedProject(context.Background(), selectionID)
	if err != nil || after == nil {
		t.Fatalf("reopen durable project: %#v %v", after, err)
	}
	if got := immutableNamespaceRecord(*after); got != before {
		t.Fatalf("namespace replay rewrote attested provenance:\nbefore=%#v\nafter=%#v", before, got)
	}
}

func namespaceRecordForTeam(t *testing.T, store *state.Store, request DefaultProjectRequest) *state.LocalManagedProject {
	t.Helper()
	record, err := store.ManagedProjectForTeam(context.Background(), request.SandboxID, request.SandboxGeneration, request.TeamID)
	if err != nil || record == nil {
		t.Fatalf("load team project: %#v %v", record, err)
	}
	return record
}

func namespaceRecordForAllocation(t *testing.T, store *state.Store, operationKey string) *state.LocalManagedProject {
	t.Helper()
	projects, err := store.ManagedProjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for index := range projects {
		if projects[index].TeamID == operationKey {
			return &projects[index]
		}
	}
	t.Fatalf("allocation %s is missing", operationKey)
	return nil
}

func namespaceRecordForHandoff(t *testing.T, store *state.Store, operationID string) *state.LocalManagedProject {
	t.Helper()
	projects, err := store.ManagedProjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	allocationDigest := digestText("handoff:" + operationID)
	for index := range projects {
		if projects[index].Report.Designation == "continuity-handoff" && projects[index].AllocationDigest == allocationDigest {
			return &projects[index]
		}
	}
	t.Fatalf("handoff allocation %s is missing", operationID)
	return nil
}

func resolveForRecord(record state.LocalManagedProject) ResolveProjectRequest {
	return ResolveProjectRequest{
		SelectionID: record.Report.SelectionID, ProjectID: record.Report.ProjectID,
		WorkspaceEpoch: record.Report.WorkspaceEpoch, SandboxID: record.Report.SandboxID,
		SandboxGeneration:     record.Report.SandboxGeneration,
		ServiceRegistrationID: pointerValue(record.Report.ServiceRegistrationID), ConfigDigest: record.ConfigDigest,
	}
}

func readyNamespaceRequest(anchor string) DefaultProjectRequest {
	return namespaceDefaultRequest(anchor, "ready", "a")
}

func createdNamespaceRequest(anchor string) DefaultProjectRequest {
	return namespaceDefaultRequest(anchor, "created", "b")
}

func namespaceDefaultRequest(anchor, suffix, digest string) DefaultProjectRequest {
	return DefaultProjectRequest{
		Anchor: anchor, ServerID: "srv_namespace0001", TeamID: "team_namespace_" + suffix,
		MemberID: "tmem_namespace_" + suffix, SandboxID: "sbx_namespace_" + suffix,
		SandboxGeneration: 1, ServiceRegistrationID: "service_namespace_" + suffix,
		AllocationDigest: "sha256:" + strings.Repeat(digest, 64), ConfigDigest: "sha256:" + strings.Repeat(digest, 64),
	}
}

func restoreNamespaceRequest(anchor string) RestoreProjectRequest {
	return RestoreProjectRequest{
		OperationID: "op_namespace_restore", Anchor: anchor, ServerID: "srv_namespace0001",
		SandboxID: "sbx_namespace_restore", SandboxGeneration: 1,
	}
}

func handoffNamespaceRequest(anchor string) HandoffProjectRequest {
	return HandoffProjectRequest{
		OperationID: "op_namespace_handoff", Anchor: anchor, ServerID: "srv_namespace0001",
		SandboxID: "sbx_namespace_handoff", SandboxGeneration: 1,
		ServiceRegistrationID: "service_namespace_handoff", TeamID: "team_namespace_handoff",
		MemberID: "tmem_namespace_handoff",
	}
}
