package workspacecatalog

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/warpmetal/warpmetal-agent-runtime/internal/model"
	"github.com/warpmetal/warpmetal-agent-runtime/internal/state"
)

const maxCatalogEntries = 64

var (
	ErrUnsafeProjectRoot = errors.New("unsafe managed project root")
	ErrProjectChanged    = errors.New("managed project changed")
	// ErrManagedProjectRemountAttestation marks a managed-service apply whose
	// only mismatch with the local managed-project record and its manifest is
	// the root attestation produced by the documented workspace remount: the
	// exact same sandbox, selection, project, workspace epoch, container root,
	// service identity, config, allocation, paths and durable directory objects
	// carried by a new loop device after an authorized re-mount of the unchanged
	// workspace image. It is returned only for that bounded, retryable reason,
	// it never admits, executes or advances the managed service, and the backend
	// remains the sole ratifier of the re-attested root.
	ErrManagedProjectRemountAttestation = errors.New("managed project root attestation changed by a workspace remount")
	ErrCatalogLimit                     = errors.New("managed project catalog limit exceeded")
	// ErrManagedProjectImageIdentityRaced marks the narrow case where the
	// complete current authority a durable image identity bind had just
	// re-proven moved immediately around its write. The one-way bind is already
	// durable and is never refreshed or replaced afterwards; returning the race
	// aborts the pass so the affected managed service is never admitted from an
	// observation a later observation contradicted.
	ErrManagedProjectImageIdentityRaced = errors.New("managed project image identity observation raced the bind")
	// errLoopBackingUnavailable reports that the host cannot name the file a
	// device is loop-backed by: the device is not a loop device, the host has
	// no sysfs, or the platform has no loop devices at all.
	errLoopBackingUnavailable = errors.New("loop backing file unavailable")
	safeComponent             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	digestPattern             = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type Catalog struct {
	State *state.Store
	Now   func() time.Time
	// BeforeGit and Sync are narrow fault/race injection seams used by the
	// filesystem journey. Production leaves them nil.
	BeforeGit func()
	Sync      func(*os.File) error
	// ImageIdentity and LoopBacking are narrow observation seams used by the
	// filesystem journey to exercise the backing-image identity checks on a
	// host without loop devices. Production leaves them nil: the real durable
	// file identity and the real Linux sysfs backing file are used.
	ImageIdentity func(string) (state.ManagedProjectImageIdentity, error)
	LoopBacking   func(uint64) (string, error)
}

type DefaultProjectRequest struct {
	Anchor                string
	ServerID              string
	TeamID                string
	MemberID              string
	SandboxID             string
	SandboxGeneration     int64
	ServiceRegistrationID string
	AllocationDigest      string
	ConfigDigest          string
	// RebindSelectionID must name the existing allocation when a revoked
	// service/config tuple is explicitly rebound. Omission never adopts or
	// replaces existing storage.
	RebindSelectionID string
}

type ResolveProjectRequest struct {
	SelectionID           string
	ProjectID             string
	WorkspaceEpoch        string
	SandboxID             string
	SandboxGeneration     int64
	ServiceRegistrationID string
	ConfigDigest          string
}

type RestoreProjectRequest struct {
	OperationID       string
	Anchor            string
	ServerID          string
	SandboxID         string
	SandboxGeneration int64
}

type HandoffProjectRequest struct {
	OperationID           string
	Anchor                string
	ServerID              string
	TeamID                string
	MemberID              string
	SandboxID             string
	SandboxGeneration     int64
	ServiceRegistrationID string
}

type RefreshRequest struct {
	Anchor            string
	SandboxID         string
	SandboxGeneration int64
	Limit             int
}

type RegisteredProject struct {
	Report        model.ProjectCatalogReportV1
	HostRoot      string
	ContainerRoot string
	ScopeRevision int64
	RootDevice    uint64 // host-private materialization fence
	RootInode     uint64 // host-private materialization fence
	// SupersededRootAttestation is the root attestation the record carried
	// before the documented workspace remount was re-attested to the live
	// device. It is host-private and never part of a published report.
	SupersededRootAttestation string
}

type fileIdentity struct {
	Device uint64
	Inode  uint64
	Mount  string
}

func (c Catalog) Reports(ctx context.Context) ([]model.ProjectCatalogReportV1, error) {
	projects, err := c.State.ManagedProjects(ctx)
	if err != nil {
		return nil, err
	}
	reports := make([]model.ProjectCatalogReportV1, 0, len(projects))
	for _, project := range projects {
		// A persisted allocation intent without an attested root is host-private
		// until materialization completes; publishing it would hand the control
		// plane a root it cannot authenticate and reject the whole report.
		if project.Phase == "handoff_allocating" || project.Phase == "restore_allocating" {
			continue
		}
		reports = append(reports, project.Report)
	}
	return reports, nil
}

// ReobserveRemountedRoots reopens every ready team-project record that a
// managed service may select and, when and only when the live root identity
// differs from the recorded one solely by the loop device that carries the
// documented workspace remount of the same, unchanged workspace image,
// re-attests the record to the live device. Anchor and project root must still
// be the exact recorded directory objects (identical inodes) on one current
// device, the record must be a self-attesting team project, the live device
// must carry the same backing workspace image the record was attested against
// (both the persisted image identity, when the record has one, and the host's
// loop backing file, where the host can report it), and every other durable
// field must stay untouched; the recorded statx mount ids remain immutable
// creation provenance. The re-attested root attestation then travels through
// the ordinary workspace report for backend ratification. A record that does
// not qualify is left exactly as it is: the ordinary resolve keeps refusing it,
// and any real project, identity, config, allocation or backing-image change
// stays fatal.
//
// The same observation also binds, one-way and only while the identity is
// still exactly zero, the durable object identity of the workspace image that
// an unchanged, already re-attested root is mounted from. A record a pre-A5
// runtime wrote (or re-attested) carries no durable image identity, so the
// later A22R adoption predicate correctly refuses the backend-ratified service
// adoption and no ordinary path ever backfills the missing identity. Only a
// fresh re-proof of the complete current authority admits the bind; every
// other record stays exactly as it is. Records of the other lineages
// (continuation handoff or materialization) are deliberately not re-observed
// and keep their pre-existing fail-closed behaviour.
func (c Catalog) ReobserveRemountedRoots(ctx context.Context) error {
	projects, err := c.State.ManagedProjects(ctx)
	if err != nil {
		return err
	}
	for index := range projects {
		if err := c.reobserveRemountedRoot(ctx, &projects[index]); err != nil {
			return err
		}
	}
	return nil
}

func (c Catalog) reobserveRemountedRoot(ctx context.Context, record *state.LocalManagedProject) error {
	// Only managed-service project selections are re-observed: a ready team
	// project whose live root device moved. Every other lineage stays exactly
	// as the ordinary paths left it.
	//
	// Availability is deliberately not an ordering precondition: identity is
	// re-attested, the availability field itself is left untouched, and the
	// managed service stays blocked until a manifest carries the ratified
	// attestation.
	if record.Phase != "ready" || record.Report.Designation != "team_project" ||
		record.AnchorInode == 0 || record.RootInode == 0 ||
		attest(*record) != record.Report.RootAttestation {
		return nil
	}
	anchorIdentity, _, rootIdentity, err := observeRecordRoot(*record)
	if err != nil {
		return nil
	}
	switch {
	case remountDeviceChange(*record, anchorIdentity, rootIdentity):
		if !c.backingImageMatches(*record, anchorIdentity.Device) {
			return nil
		}
		record.SupersededRootAttestation = record.Report.RootAttestation
		record.AnchorDevice, record.RootDevice = anchorIdentity.Device, rootIdentity.Device
		record.Report.RootAttestation = attest(*record)
		return c.State.PutManagedProject(ctx, *record)
	case unmovedRootIdentity(*record, anchorIdentity, rootIdentity):
		return c.bindObservedRootImageIdentity(ctx, *record)
	}
	return nil
}

// observeRecordRoot reopens the record's exact anchor, shared projects
// directory and project root from paths alone, no-follow, and re-proves current
// mount containment. It is the traversal shared by the documented remount
// re-attestation and the durable image identity bind: each caller separately
// proves the durable object identity it needs from these observations.
func observeRecordRoot(record state.LocalManagedProject) (fileIdentity, fileIdentity, fileIdentity, error) {
	anchor, anchorIdentity, err := openDirectoryNoFollow(record.Anchor)
	if err != nil {
		return fileIdentity{}, fileIdentity{}, fileIdentity{}, err
	}
	defer anchor.Close()
	projects, err := openDirectoryAt(anchor, "projects")
	if err != nil {
		return fileIdentity{}, fileIdentity{}, fileIdentity{}, err
	}
	defer projects.Close()
	projectsIdentity, err := identityForFile(projects)
	if err != nil || !sameMount(anchorIdentity, projectsIdentity) {
		return fileIdentity{}, fileIdentity{}, fileIdentity{}, ErrProjectChanged
	}
	leaf := filepath.Base(record.HostRoot)
	if !safeComponent.MatchString(leaf) || filepath.Clean(record.HostRoot) != filepath.Join(filepath.Clean(record.Anchor), "projects", leaf) {
		return fileIdentity{}, fileIdentity{}, fileIdentity{}, ErrProjectChanged
	}
	rootFD, err := unix.Openat(int(projects.Fd()), leaf, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fileIdentity{}, fileIdentity{}, fileIdentity{}, err
	}
	root := os.NewFile(uintptr(rootFD), record.HostRoot)
	defer root.Close()
	rootIdentity, err := identityForFile(root)
	if err != nil || !sameMount(anchorIdentity, rootIdentity) {
		return fileIdentity{}, fileIdentity{}, fileIdentity{}, ErrProjectChanged
	}
	return anchorIdentity, projectsIdentity, rootIdentity, nil
}

// bindObservedRootImageIdentity performs the one-way, zero-only durable image
// identity bind the A25 owner decision authorizes. A pre-A5 ready, available,
// self-attesting team project whose live anchor and project root are still the
// exact recorded directory objects on the unchanged recorded device may record
// the durable object identity of the workspace image that device is
// loop-backed by - and nothing else. Every precondition is re-proven from the
// filesystem for this call alone:
//
//   - the record still carries its exactly zero durable identity, and the
//     complete current authority is observed twice immediately around the
//     write, so a path or object race between any two observations refuses the
//     bind;
//   - the recorded anchor, shared projects directory and project root open
//     no-follow, are the exact recorded inodes on the one recorded nonzero
//     device, and stay on one current mount;
//   - the record's own anchor derives the canonical per-sandbox workspace image
//     path (the documented <directory>/workspace mount of
//     <directory>/workspace.ext4); a legacy anchor without a derivable image
//     is refused, never guessed from a neighbouring file;
//   - the host can name the loop backing file of that exact current device and
//     it equals that exact derived path: an unavailable or mismatched backing
//     observation refuses the bind, and a path-only assertion is never
//     accepted;
//   - the image is freshly observed, no-follow, as a regular file with a fully
//     nonzero durable device/inode/size identity.
//
// The store write is the narrow compare-and-write of the exact re-proven
// record, so a record that moved under this observation is refused there too.
// Only the durable image identity and the ordinary write timestamp move.
func (c Catalog) bindObservedRootImageIdentity(ctx context.Context, record state.LocalManagedProject) error {
	if record.ImageIdentity != (state.ManagedProjectImageIdentity{}) || record.Report.Availability != "available" ||
		record.AnchorMount == "" || record.RootMount == "" {
		return nil
	}
	imagePath, derived := workspaceImagePath(record)
	if !derived {
		return nil
	}
	first, ok := c.observeUnmovedRootImage(record, imagePath)
	if !ok {
		return nil
	}
	second, ok := c.observeUnmovedRootImage(record, imagePath)
	if !ok || !first.sameAuthority(second) {
		return nil
	}
	bound := record
	bound.ImageIdentity = second.image
	if err := c.State.BindManagedProjectImageIdentity(ctx, bound); err != nil {
		return err
	}
	final, ok := c.observeUnmovedRootImage(record, imagePath)
	if !ok || !first.sameAuthority(final) {
		return ErrManagedProjectImageIdentityRaced
	}
	return nil
}

// observedRootImage is one complete observation of the authority an A25 image
// identity bind rests on.
type observedRootImage struct {
	anchor   fileIdentity
	projects fileIdentity
	root     fileIdentity
	backing  string
	image    state.ManagedProjectImageIdentity
}

// sameAuthority reports whether two observations name the exact same current
// authority. The image modification time is deliberately not compared: mounted
// filesystem writes legitimately move it while the durable object stays
// unchanged.
func (observation observedRootImage) sameAuthority(other observedRootImage) bool {
	return observation.anchor == other.anchor && observation.projects == other.projects &&
		observation.root == other.root && observation.backing == other.backing &&
		observation.image.SameDurableObject(other.image)
}

// observeUnmovedRootImage re-proves, from paths alone, the complete current
// authority the bind rests on: the exact recorded anchor, shared projects
// directory and project root objects on one current mount and the one recorded
// device, the host-reported loop backing of that device naming exactly the
// record's derived workspace image path, and that image freshly observed as a
// no-follow regular file with a fully nonzero durable identity. Any
// unavailable, mismatched or moved observation refuses the bind.
func (c Catalog) observeUnmovedRootImage(record state.LocalManagedProject, imagePath string) (observedRootImage, bool) {
	anchorIdentity, projectsIdentity, rootIdentity, err := observeRecordRoot(record)
	if err != nil || !unmovedRootIdentity(record, anchorIdentity, rootIdentity) {
		return observedRootImage{}, false
	}
	backing, err := c.observeLoopBacking(anchorIdentity.Device)
	if err != nil || backing != imagePath {
		return observedRootImage{}, false
	}
	image, err := c.observeImageIdentity(imagePath)
	if err != nil || image.Device == 0 || image.Inode == 0 || image.Size == 0 {
		return observedRootImage{}, false
	}
	return observedRootImage{
		anchor: anchorIdentity, projects: projectsIdentity, root: rootIdentity,
		backing: backing, image: image,
	}, true
}

// unmovedRootIdentity reports whether the live anchor and project root are the
// exact durable directory objects the record attests, with a nonzero recorded
// device that is the one current device of both objects: no remount, root or
// anchor movement. The recorded statx mount ids are deliberately neither
// compared nor rewritten - they are namespace-scoped creation provenance, and
// the current mount containment is proved live by the traversal - while the
// bind separately requires the record's recorded mount provenance to be
// present and keeps every byte of it exactly as recorded.
func unmovedRootIdentity(record state.LocalManagedProject, anchor, root fileIdentity) bool {
	return record.AnchorDevice != 0 && record.AnchorDevice == record.RootDevice &&
		anchor.Device == record.AnchorDevice && root.Device == record.AnchorDevice &&
		anchor.Inode == record.AnchorInode && root.Inode == record.RootInode
}

// remountDeviceChange reports whether the live anchor and project root are the
// exact durable directory objects the record attests (identical inodes) on
// exactly one current device and that device is not the recorded one. The
// recorded statx mount ids are deliberately neither compared nor rewritten:
// they are namespace-scoped creation provenance.
func remountDeviceChange(record state.LocalManagedProject, anchor, root fileIdentity) bool {
	return record.AnchorDevice != 0 && record.AnchorDevice == record.RootDevice &&
		anchor.Device == root.Device && anchor.Device != record.AnchorDevice &&
		anchor.Inode == record.AnchorInode && root.Inode == record.RootInode
}

// workspaceImagePath derives the per-sandbox workspace image file that carries
// a managed project's root from the record's own host-private anchor. The
// documented Workspaces.Ensure layout mounts <directory>/workspace.ext4 at
// <directory>/workspace, and the catalog anchor is that mountpoint; the project
// root lives at <anchor>/projects/<leaf>. An anchor outside that layout, or a
// relative one, has no derivable image and is treated as a legacy anchor.
func workspaceImagePath(record state.LocalManagedProject) (string, bool) {
	anchor := filepath.Clean(record.Anchor)
	if !filepath.IsAbs(anchor) || filepath.Base(anchor) != "workspace" {
		return "", false
	}
	return filepath.Join(filepath.Dir(anchor), "workspace.ext4"), true
}

// bindWorkspaceImageIdentity records the durable identity of the workspace
// image file at the record's derived image path. It is called only when the
// catalog creates a record: a record born with the identity requires it to
// still be observed exactly on re-observation, while a record whose anchor has
// no observable image (a legacy anchor, or a test anchor without an image
// file) keeps the zero identity and is treated exactly like a record that
// predates the field.
func (c Catalog) bindWorkspaceImageIdentity(record *state.LocalManagedProject) {
	path, derived := workspaceImagePath(*record)
	if !derived {
		return
	}
	identity, err := c.observeImageIdentity(path)
	if err != nil {
		return
	}
	record.ImageIdentity = identity
}

// backingImageMatches reports whether the live device carries exactly the
// backing workspace image object the record was attested against:
//   - mechanism (b): when the record persisted the image file's durable
//     identity, the live image at the record's derived host-private image path
//     must still be that exact file object (device, inode and size); the
//     image's modification time is deliberately not compared, because mounted
//     filesystem writes legitimately move it while the object stays unchanged;
//   - mechanism (a): when the host can report the loop backing file of the
//     live device (Linux sysfs), it must be exactly that same image path.
//
// Both must hold whenever they are available. A record that can prove neither
// is left untouched: the documented remount is never adopted on an unproven
// image, and the service keeps failing closed on the ordinary paths.
func (c Catalog) backingImageMatches(record state.LocalManagedProject, device uint64) bool {
	path, derived := workspaceImagePath(record)
	recorded := record.ImageIdentity != (state.ManagedProjectImageIdentity{})
	if recorded {
		if !derived {
			return false
		}
		live, err := c.observeImageIdentity(path)
		if err != nil || !live.SameDurableObject(record.ImageIdentity) {
			return false
		}
	}
	backing, err := c.observeLoopBacking(device)
	if err != nil {
		// The host cannot name the backing file of this device, so the
		// persisted image identity is the only available authority.
		return recorded
	}
	return derived && backing == path
}

func (c Catalog) observeImageIdentity(path string) (state.ManagedProjectImageIdentity, error) {
	if c.ImageIdentity != nil {
		return c.ImageIdentity(path)
	}
	return imageIdentity(path)
}

func (c Catalog) observeLoopBacking(device uint64) (string, error) {
	if c.LoopBacking != nil {
		return c.LoopBacking(device)
	}
	return hostLoopBackingFile(device)
}

func (c Catalog) EnsureDefault(ctx context.Context, request DefaultProjectRequest) (RegisteredProject, error) {
	if err := validateDefaultRequest(request); err != nil {
		return RegisteredProject{}, err
	}
	existing, err := c.State.ManagedProjectForTeam(ctx, request.SandboxID, request.SandboxGeneration, request.TeamID)
	if err != nil {
		return RegisteredProject{}, err
	}
	if existing != nil {
		if existing.AllocationDigest != request.AllocationDigest {
			return RegisteredProject{}, ErrProjectChanged
		}
		if pointerValue(existing.Report.ServiceRegistrationID) == request.ServiceRegistrationID && existing.ConfigDigest == request.ConfigDigest {
			if existing.Phase == "created" {
				return c.resumeCreated(ctx, existing)
			}
			return c.resolveRecord(existing)
		}
		if request.RebindSelectionID == "" || request.RebindSelectionID != existing.Report.SelectionID {
			return RegisteredProject{}, ErrProjectChanged
		}
		if _, err := c.resolveRecord(existing); err != nil {
			return RegisteredProject{}, err
		}
		existing.ConfigDigest = request.ConfigDigest
		existing.Report.ServiceRegistrationID = stringPointer(request.ServiceRegistrationID)
		existing.Report.LastObservedAt = c.now()
		existing.Report.RootAttestation = attest(*existing)
		// An explicit rebind re-attests the record for a non-remount reason, so
		// any superseded remount attestation is no longer this record's
		// pre-remount authority and must never be deferred against again.
		existing.SupersededRootAttestation = ""
		if err := c.State.PutManagedProject(ctx, *existing); err != nil {
			return RegisteredProject{}, err
		}
		return registered(*existing), nil
	}

	anchor, anchorIdentity, err := openDirectoryNoFollow(request.Anchor)
	if err != nil {
		return RegisteredProject{}, fmt.Errorf("%w: anchor: %v", ErrUnsafeProjectRoot, err)
	}
	defer anchor.Close()
	projects, err := ensureProjectsDirectory(anchor)
	if err != nil {
		return RegisteredProject{}, fmt.Errorf("%w: projects: %v", ErrUnsafeProjectRoot, err)
	}
	defer projects.Close()
	projectsIdentity, err := identityForFile(projects)
	if err != nil || !sameMount(anchorIdentity, projectsIdentity) {
		return RegisteredProject{}, ErrUnsafeProjectRoot
	}
	if err := c.ensureProjectsOwner(ctx, anchor, projects, anchorIdentity, request.Anchor); err != nil {
		return RegisteredProject{}, err
	}

	now := c.now()
	selectionID, err := opaqueID("selection")
	if err != nil {
		return RegisteredProject{}, err
	}
	projectID, err := opaqueID("project")
	if err != nil {
		return RegisteredProject{}, err
	}
	workspaceEpoch, err := opaqueID("epoch")
	if err != nil {
		return RegisteredProject{}, err
	}
	record := state.LocalManagedProject{
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: selectionID, ProjectID: projectID,
			WorkspaceEpoch: workspaceEpoch, SandboxID: request.SandboxID,
			SandboxGeneration: request.SandboxGeneration, ServiceRegistrationID: stringPointer(request.ServiceRegistrationID),
			Designation: "team_project", Label: request.TeamID, Availability: "unavailable",
			Reason: stringPointer("initializing"), LastObservedAt: now,
		},
		ServerID: request.ServerID, TeamID: request.TeamID, MemberID: request.MemberID,
		AllocationDigest: request.AllocationDigest, ConfigDigest: request.ConfigDigest, Anchor: filepath.Clean(request.Anchor),
		ScopeRevision: 1,
		HostRoot:      filepath.Join(filepath.Clean(request.Anchor), "projects", request.TeamID),
		ContainerRoot: "/home/agent/projects/" + request.TeamID, Phase: "allocated",
		AnchorDevice: anchorIdentity.Device, AnchorInode: anchorIdentity.Inode, AnchorMount: anchorIdentity.Mount,
	}
	c.bindWorkspaceImageIdentity(&record)
	if err := c.State.PutManagedProject(ctx, record); err != nil {
		return RegisteredProject{}, err
	}
	if err := unix.Mkdirat(int(projects.Fd()), request.TeamID, 0700); err != nil {
		return RegisteredProject{}, fmt.Errorf("%w: exclusive project creation: %v", ErrUnsafeProjectRoot, err)
	}
	rootFD, err := unix.Openat(int(projects.Fd()), request.TeamID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return RegisteredProject{}, fmt.Errorf("%w: open created root: %v", ErrUnsafeProjectRoot, err)
	}
	root := os.NewFile(uintptr(rootFD), record.HostRoot)
	defer root.Close()
	rootIdentity, err := identityForFile(root)
	if err != nil || !sameMount(anchorIdentity, rootIdentity) {
		return RegisteredProject{}, ErrUnsafeProjectRoot
	}
	record.RootDevice, record.RootInode, record.RootMount = rootIdentity.Device, rootIdentity.Inode, rootIdentity.Mount
	record.Phase = "created"
	record.Report.RootAttestation = attest(record)
	if err := c.State.PutManagedProject(ctx, record); err != nil {
		return RegisteredProject{}, err
	}
	if err := ensureEmpty(root); err != nil {
		return RegisteredProject{}, fmt.Errorf("%w: %v", ErrUnsafeProjectRoot, err)
	}
	if c.BeforeGit != nil {
		c.BeforeGit()
	}
	if err := initializeGit(ctx, root, now); err != nil {
		return RegisteredProject{}, err
	}
	if err := verifyRoot(record); err != nil {
		return RegisteredProject{}, err
	}
	if err := c.ownDefaultBootstrap(ctx, record); err != nil {
		return RegisteredProject{}, err
	}
	if err := c.syncGitTree(root); err != nil {
		return RegisteredProject{}, err
	}
	for _, directory := range []*os.File{root, projects, anchor} {
		if err := c.syncFile(directory); err != nil {
			return RegisteredProject{}, fmt.Errorf("sync managed project publication: %w", err)
		}
	}
	if err := verifyRoot(record); err != nil {
		return RegisteredProject{}, err
	}
	record.Phase = "ready"
	record.Report.Availability = "available"
	record.Report.Reason = nil
	record.Report.LastObservedAt = c.now()
	record.Report.RootAttestation = attest(record)
	if err := c.State.PutManagedProject(ctx, record); err != nil {
		return RegisteredProject{}, err
	}
	return registered(record), nil
}

// AllocateRestore exclusively creates and durably records a new empty project
// leaf. It never initializes Git, binds a service, or advertises the leaf as an
// available source; the restore controller publishes availability only after
// verified checkpoint materialization.
func (c Catalog) AllocateRestore(ctx context.Context, request RestoreProjectRequest) (RegisteredProject, error) {
	if !safeComponent.MatchString(request.OperationID) || request.Anchor == "" ||
		!safeComponent.MatchString(request.ServerID) || !safeComponent.MatchString(request.SandboxID) || request.SandboxGeneration < 1 {
		return RegisteredProject{}, ErrUnsafeProjectRoot
	}
	operationKey := "restore:" + request.OperationID
	projects, err := c.State.ManagedProjects(ctx)
	if err != nil {
		return RegisteredProject{}, err
	}
	for i := range projects {
		record := &projects[i]
		if record.TeamID != operationKey {
			continue
		}
		if record.ServerID != request.ServerID || record.Report.SandboxID != request.SandboxID ||
			record.Report.SandboxGeneration != request.SandboxGeneration || filepath.Clean(record.Anchor) != filepath.Clean(request.Anchor) ||
			record.Report.Designation != "continuity-materialization" || record.Report.ServiceRegistrationID != nil || record.ScopeRevision != 1 {
			return RegisteredProject{}, ErrProjectChanged
		}
		if record.RootInode == 0 {
			return c.finishRestoreAllocation(ctx, record)
		}
		if attest(*record) != record.Report.RootAttestation {
			return RegisteredProject{}, ErrProjectChanged
		}
		if err := verifyOwnedRoot(*record); err != nil {
			return RegisteredProject{}, err
		}
		return registered(*record), nil
	}
	if len(projects) >= maxCatalogEntries {
		return RegisteredProject{}, ErrCatalogLimit
	}
	record, err := c.BeginRestoreAllocation(ctx, request)
	if err != nil {
		return RegisteredProject{}, err
	}
	return c.finishRestoreAllocation(ctx, &record)
}

// BeginRestoreAllocation persists the durable pre-attestation intent for a
// restore materialization. AllocateRestore continues with the actual
// materialization; an interrupted allocation leaves exactly this host-private
// record for a later resume and must never be published in a report before it
// carries an attested root.
func (c Catalog) BeginRestoreAllocation(ctx context.Context, request RestoreProjectRequest) (state.LocalManagedProject, error) {
	if !safeComponent.MatchString(request.OperationID) || request.Anchor == "" ||
		!safeComponent.MatchString(request.ServerID) || !safeComponent.MatchString(request.SandboxID) || request.SandboxGeneration < 1 {
		return state.LocalManagedProject{}, ErrUnsafeProjectRoot
	}
	operationKey := "restore:" + request.OperationID
	anchor, anchorIdentity, err := openDirectoryNoFollow(request.Anchor)
	if err != nil {
		return state.LocalManagedProject{}, fmt.Errorf("%w: anchor: %v", ErrUnsafeProjectRoot, err)
	}
	defer anchor.Close()
	projectsDirectory, err := ensureProjectsDirectory(anchor)
	if err != nil {
		return state.LocalManagedProject{}, fmt.Errorf("%w: projects: %v", ErrUnsafeProjectRoot, err)
	}
	defer projectsDirectory.Close()
	projectsIdentity, err := identityForFile(projectsDirectory)
	if err != nil || !sameMount(anchorIdentity, projectsIdentity) {
		return state.LocalManagedProject{}, ErrUnsafeProjectRoot
	}
	if err := c.ensureProjectsOwner(ctx, anchor, projectsDirectory, anchorIdentity, request.Anchor); err != nil {
		return state.LocalManagedProject{}, err
	}
	selectionID, err := opaqueID("selection")
	if err != nil {
		return state.LocalManagedProject{}, err
	}
	projectID, err := opaqueID("project")
	if err != nil {
		return state.LocalManagedProject{}, err
	}
	epoch, err := opaqueID("epoch")
	if err != nil {
		return state.LocalManagedProject{}, err
	}
	leafID, err := opaqueID("restore")
	if err != nil {
		return state.LocalManagedProject{}, err
	}
	now := c.now()
	record := state.LocalManagedProject{
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: selectionID, ProjectID: projectID, WorkspaceEpoch: epoch,
			SandboxID: request.SandboxID, SandboxGeneration: request.SandboxGeneration,
			Designation: "continuity-materialization", Label: leafID, Availability: "unavailable",
			Reason: stringPointer("materialization_pending"), LastObservedAt: now,
		},
		ServerID: request.ServerID, TeamID: operationKey, AllocationDigest: digestText(operationKey),
		ConfigDigest: digestText("continuity-materialization:" + request.OperationID), ScopeRevision: 1,
		Anchor: filepath.Clean(request.Anchor), HostRoot: filepath.Join(filepath.Clean(request.Anchor), "projects", leafID),
		ContainerRoot: "/home/agent/projects/" + leafID, Phase: "restore_allocating",
		AnchorDevice: anchorIdentity.Device, AnchorInode: anchorIdentity.Inode, AnchorMount: anchorIdentity.Mount,
	}
	c.bindWorkspaceImageIdentity(&record)
	if err := c.State.PutManagedProject(ctx, record); err != nil {
		return state.LocalManagedProject{}, err
	}
	return record, nil
}

func (c Catalog) finishRestoreAllocation(ctx context.Context, record *state.LocalManagedProject) (RegisteredProject, error) {
	anchor, anchorIdentity, err := openDirectoryNoFollow(record.Anchor)
	if err != nil || !sameDurableObject(record.AnchorDevice, record.AnchorInode, anchorIdentity) {
		if anchor != nil {
			anchor.Close()
		}
		return RegisteredProject{}, ErrProjectChanged
	}
	defer anchor.Close()
	projects, err := ensureProjectsDirectory(anchor)
	if err != nil {
		return RegisteredProject{}, ErrUnsafeProjectRoot
	}
	defer projects.Close()
	projectsIdentity, err := identityForFile(projects)
	if err != nil || !sameMount(anchorIdentity, projectsIdentity) {
		return RegisteredProject{}, ErrUnsafeProjectRoot
	}
	if err := c.ensureProjectsOwner(ctx, anchor, projects, anchorIdentity, record.Anchor); err != nil {
		return RegisteredProject{}, err
	}
	leaf := filepath.Base(record.HostRoot)
	if filepath.Join(record.Anchor, "projects", leaf) != record.HostRoot || !safeComponent.MatchString(leaf) {
		return RegisteredProject{}, ErrProjectChanged
	}
	if err := unix.Mkdirat(int(projects.Fd()), leaf, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return RegisteredProject{}, fmt.Errorf("%w: exclusive restore creation: %v", ErrUnsafeProjectRoot, err)
	}
	rootFD, err := unix.Openat(int(projects.Fd()), leaf, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return RegisteredProject{}, ErrUnsafeProjectRoot
	}
	root := os.NewFile(uintptr(rootFD), record.HostRoot)
	defer root.Close()
	rootIdentity, err := identityForFile(root)
	if err != nil || !sameMount(anchorIdentity, rootIdentity) {
		return RegisteredProject{}, ErrUnsafeProjectRoot
	}
	if record.RootInode != 0 && !sameDurableObject(record.RootDevice, record.RootInode, rootIdentity) {
		return RegisteredProject{}, ErrProjectChanged
	}
	if record.RootInode == 0 {
		if err := ensureEmpty(root); err != nil {
			return RegisteredProject{}, ErrUnsafeProjectRoot
		}
		record.RootDevice, record.RootInode, record.RootMount = rootIdentity.Device, rootIdentity.Inode, rootIdentity.Mount
	}
	for _, directory := range []*os.File{root, projects, anchor} {
		if err := c.syncFile(directory); err != nil {
			return RegisteredProject{}, fmt.Errorf("sync restore allocation: %w", err)
		}
	}
	record.Phase = "restore_allocated"
	record.Report.RootAttestation = attest(*record)
	record.Report.LastObservedAt = c.now()
	if err := c.State.PutManagedProject(ctx, *record); err != nil {
		return RegisteredProject{}, err
	}
	return registered(*record), nil
}

func (c Catalog) CompleteRestore(ctx context.Context, operationID string) (RegisteredProject, error) {
	if !safeComponent.MatchString(operationID) {
		return RegisteredProject{}, ErrProjectChanged
	}
	operationKey := "restore:" + operationID
	projects, err := c.State.ManagedProjects(ctx)
	if err != nil {
		return RegisteredProject{}, err
	}
	for i := range projects {
		record := &projects[i]
		if record.TeamID != operationKey {
			continue
		}
		if record.Report.Designation != "continuity-materialization" || record.Report.ServiceRegistrationID != nil ||
			record.ScopeRevision != 1 || record.RootInode == 0 || attest(*record) != record.Report.RootAttestation {
			return RegisteredProject{}, ErrProjectChanged
		}
		if record.Phase == "ready" && record.Report.Availability == "available" {
			if err := verifyRoot(*record); err != nil {
				return RegisteredProject{}, err
			}
			if err := verifyPublishedOwner(*record); err != nil {
				return RegisteredProject{}, err
			}
			return registered(*record), nil
		}
		if record.Phase != "restore_allocated" || record.Report.Availability != "unavailable" {
			return RegisteredProject{}, ErrProjectChanged
		}
		if err := verifyRoot(*record); err != nil {
			return RegisteredProject{}, err
		}
		if err := verifyPublishedOwner(*record); err != nil {
			return RegisteredProject{}, err
		}
		record.Phase = "ready"
		record.Report.Availability = "available"
		record.Report.Reason = nil
		record.Report.LastObservedAt = c.now()
		record.Report.RootAttestation = attest(*record)
		if err := c.State.PutManagedProject(ctx, *record); err != nil {
			return RegisteredProject{}, err
		}
		return registered(*record), nil
	}
	return RegisteredProject{}, ErrProjectChanged
}

// AllocateHandoff creates one durable empty leaf for a separate continuation
// session. The operation ID, never an owner path, is the replay key.
func (c Catalog) AllocateHandoff(ctx context.Context, request HandoffProjectRequest) (RegisteredProject, error) {
	if !safeComponent.MatchString(request.OperationID) || request.Anchor == "" ||
		!safeComponent.MatchString(request.ServerID) || !safeComponent.MatchString(request.SandboxID) ||
		request.SandboxGeneration < 1 || !safeComponent.MatchString(request.ServiceRegistrationID) ||
		request.TeamID != "" && !safeComponent.MatchString(request.TeamID) ||
		request.MemberID != "" && !safeComponent.MatchString(request.MemberID) {
		return RegisteredProject{}, ErrUnsafeProjectRoot
	}
	operationKey := "handoff:" + request.OperationID
	allocationDigest := digestText(operationKey)
	projects, err := c.State.ManagedProjects(ctx)
	if err != nil {
		return RegisteredProject{}, err
	}
	for i := range projects {
		record := &projects[i]
		if record.Report.Designation != "continuity-handoff" || record.AllocationDigest != allocationDigest {
			continue
		}
		if record.ServerID != request.ServerID || record.Report.SandboxID != request.SandboxID ||
			record.Report.SandboxGeneration != request.SandboxGeneration || filepath.Clean(record.Anchor) != filepath.Clean(request.Anchor) ||
			record.Report.Designation != "continuity-handoff" || pointerValue(record.Report.ServiceRegistrationID) != request.ServiceRegistrationID ||
			record.ScopeRevision != 1 || record.MemberID != request.MemberID {
			return RegisteredProject{}, ErrProjectChanged
		}
		if record.RootInode == 0 {
			return c.finishHandoffAllocation(ctx, record)
		}
		if attest(*record) != record.Report.RootAttestation || verifyOwnedRoot(*record) != nil {
			return RegisteredProject{}, ErrProjectChanged
		}
		return registered(*record), nil
	}
	if len(projects) >= maxCatalogEntries {
		return RegisteredProject{}, ErrCatalogLimit
	}
	record, err := c.BeginHandoffAllocation(ctx, request)
	if err != nil {
		return RegisteredProject{}, err
	}
	return c.finishHandoffAllocation(ctx, &record)
}

// BeginHandoffAllocation persists the durable pre-attestation intent for a
// handoff target. AllocateHandoff continues with the actual materialization; an
// interrupted allocation leaves exactly this host-private record for a later
// resume and must never be published in a report before it carries an attested
// root.
func (c Catalog) BeginHandoffAllocation(ctx context.Context, request HandoffProjectRequest) (state.LocalManagedProject, error) {
	if !safeComponent.MatchString(request.OperationID) || request.Anchor == "" ||
		!safeComponent.MatchString(request.ServerID) || !safeComponent.MatchString(request.SandboxID) ||
		request.SandboxGeneration < 1 || !safeComponent.MatchString(request.ServiceRegistrationID) ||
		request.TeamID != "" && !safeComponent.MatchString(request.TeamID) ||
		request.MemberID != "" && !safeComponent.MatchString(request.MemberID) {
		return state.LocalManagedProject{}, ErrUnsafeProjectRoot
	}
	operationKey := "handoff:" + request.OperationID
	allocationDigest := digestText(operationKey)
	anchor, anchorIdentity, err := openDirectoryNoFollow(request.Anchor)
	if err != nil {
		return state.LocalManagedProject{}, fmt.Errorf("%w: anchor: %v", ErrUnsafeProjectRoot, err)
	}
	defer anchor.Close()
	projectsDirectory, err := ensureProjectsDirectory(anchor)
	if err != nil {
		return state.LocalManagedProject{}, ErrUnsafeProjectRoot
	}
	defer projectsDirectory.Close()
	projectsIdentity, err := identityForFile(projectsDirectory)
	if err != nil || !sameMount(anchorIdentity, projectsIdentity) {
		return state.LocalManagedProject{}, ErrUnsafeProjectRoot
	}
	if err := c.ensureProjectsOwner(ctx, anchor, projectsDirectory, anchorIdentity, request.Anchor); err != nil {
		return state.LocalManagedProject{}, err
	}
	selectionID, err := opaqueID("selection")
	if err != nil {
		return state.LocalManagedProject{}, err
	}
	projectID, err := opaqueID("project")
	if err != nil {
		return state.LocalManagedProject{}, err
	}
	epoch, err := opaqueID("epoch")
	if err != nil {
		return state.LocalManagedProject{}, err
	}
	leafID, err := opaqueID("handoff")
	if err != nil {
		return state.LocalManagedProject{}, err
	}
	now := c.now()
	record := state.LocalManagedProject{
		Report: model.ProjectCatalogReportV1{
			FormatVersion: 1, SelectionID: selectionID, ProjectID: projectID, WorkspaceEpoch: epoch,
			SandboxID: request.SandboxID, SandboxGeneration: request.SandboxGeneration,
			ServiceRegistrationID: stringPointer(request.ServiceRegistrationID), Designation: "continuity-handoff",
			Label: leafID, Availability: "unavailable", Reason: stringPointer("materialization_pending"), LastObservedAt: now,
		},
		ServerID: request.ServerID, TeamID: request.TeamID, MemberID: request.MemberID,
		AllocationDigest: allocationDigest, ConfigDigest: digestText("continuity-handoff:" + request.OperationID),
		ScopeRevision: 1, Anchor: filepath.Clean(request.Anchor),
		HostRoot:      filepath.Join(filepath.Clean(request.Anchor), "projects", leafID),
		ContainerRoot: "/home/agent/projects/" + leafID, Phase: "handoff_allocating",
		AnchorDevice: anchorIdentity.Device, AnchorInode: anchorIdentity.Inode, AnchorMount: anchorIdentity.Mount,
	}
	c.bindWorkspaceImageIdentity(&record)
	if err := c.State.PutManagedProject(ctx, record); err != nil {
		return state.LocalManagedProject{}, err
	}
	return record, nil
}

func (c Catalog) finishHandoffAllocation(ctx context.Context, record *state.LocalManagedProject) (RegisteredProject, error) {
	anchor, anchorIdentity, err := openDirectoryNoFollow(record.Anchor)
	if err != nil || !sameDurableObject(record.AnchorDevice, record.AnchorInode, anchorIdentity) {
		if anchor != nil {
			anchor.Close()
		}
		return RegisteredProject{}, ErrProjectChanged
	}
	defer anchor.Close()
	projects, err := ensureProjectsDirectory(anchor)
	if err != nil {
		return RegisteredProject{}, ErrUnsafeProjectRoot
	}
	defer projects.Close()
	projectsIdentity, err := identityForFile(projects)
	if err != nil || !sameMount(anchorIdentity, projectsIdentity) {
		return RegisteredProject{}, ErrUnsafeProjectRoot
	}
	if err := c.ensureProjectsOwner(ctx, anchor, projects, anchorIdentity, record.Anchor); err != nil {
		return RegisteredProject{}, err
	}
	leaf := filepath.Base(record.HostRoot)
	if filepath.Join(record.Anchor, "projects", leaf) != record.HostRoot || !safeComponent.MatchString(leaf) {
		return RegisteredProject{}, ErrProjectChanged
	}
	if err := unix.Mkdirat(int(projects.Fd()), leaf, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return RegisteredProject{}, fmt.Errorf("%w: exclusive handoff creation: %v", ErrUnsafeProjectRoot, err)
	}
	rootFD, err := unix.Openat(int(projects.Fd()), leaf, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return RegisteredProject{}, ErrUnsafeProjectRoot
	}
	root := os.NewFile(uintptr(rootFD), record.HostRoot)
	defer root.Close()
	rootIdentity, err := identityForFile(root)
	if err != nil || !sameMount(anchorIdentity, rootIdentity) {
		return RegisteredProject{}, ErrUnsafeProjectRoot
	}
	if record.RootInode != 0 && !sameDurableObject(record.RootDevice, record.RootInode, rootIdentity) {
		return RegisteredProject{}, ErrProjectChanged
	}
	if record.RootInode == 0 {
		if err := ensureEmpty(root); err != nil {
			return RegisteredProject{}, ErrUnsafeProjectRoot
		}
		record.RootDevice, record.RootInode, record.RootMount = rootIdentity.Device, rootIdentity.Inode, rootIdentity.Mount
	}
	for _, directory := range []*os.File{root, projects, anchor} {
		if err := c.syncFile(directory); err != nil {
			return RegisteredProject{}, fmt.Errorf("sync handoff allocation: %w", err)
		}
	}
	record.Phase = "handoff_allocated"
	record.Report.RootAttestation = attest(*record)
	record.Report.LastObservedAt = c.now()
	if err := c.State.PutManagedProject(ctx, *record); err != nil {
		return RegisteredProject{}, err
	}
	return registered(*record), nil
}

func (c Catalog) CompleteHandoff(ctx context.Context, operationID string) (RegisteredProject, error) {
	if !safeComponent.MatchString(operationID) {
		return RegisteredProject{}, ErrProjectChanged
	}
	operationKey := "handoff:" + operationID
	allocationDigest := digestText(operationKey)
	projects, err := c.State.ManagedProjects(ctx)
	if err != nil {
		return RegisteredProject{}, err
	}
	for i := range projects {
		record := &projects[i]
		if record.Report.Designation != "continuity-handoff" || record.AllocationDigest != allocationDigest {
			continue
		}
		if record.Report.Designation != "continuity-handoff" || record.Report.ServiceRegistrationID == nil ||
			record.ScopeRevision != 1 || record.RootInode == 0 || attest(*record) != record.Report.RootAttestation {
			return RegisteredProject{}, ErrProjectChanged
		}
		if record.Phase == "ready" && record.Report.Availability == "available" {
			if err := verifyOwnedRoot(*record); err != nil {
				return RegisteredProject{}, err
			}
			if err := verifyPublishedOwner(*record); err != nil {
				return RegisteredProject{}, err
			}
			return registered(*record), nil
		}
		if record.Phase != "handoff_allocated" || record.Report.Availability != "unavailable" || verifyOwnedRoot(*record) != nil {
			return RegisteredProject{}, ErrProjectChanged
		}
		if err := verifyPublishedOwner(*record); err != nil {
			return RegisteredProject{}, err
		}
		record.Phase = "ready"
		record.Report.Availability = "available"
		record.Report.Reason = nil
		record.Report.LastObservedAt = c.now()
		record.Report.RootAttestation = attest(*record)
		if err := c.State.PutManagedProject(ctx, *record); err != nil {
			return RegisteredProject{}, err
		}
		return registered(*record), nil
	}
	return RegisteredProject{}, ErrProjectChanged
}

func (c Catalog) resumeCreated(ctx context.Context, record *state.LocalManagedProject) (RegisteredProject, error) {
	root, _, err := openVerifiedRoot(*record)
	if err != nil {
		return RegisteredProject{}, err
	}
	defer root.Close()
	if err := ensureEmpty(root); err == nil {
		if c.BeforeGit != nil {
			c.BeforeGit()
		}
		if err := initializeGit(ctx, root, c.now()); err != nil {
			return RegisteredProject{}, err
		}
	}
	if err := verifyRoot(*record); err != nil {
		return RegisteredProject{}, err
	}
	if err := c.ownDefaultBootstrap(ctx, *record); err != nil {
		return RegisteredProject{}, err
	}
	if err := c.syncGitTree(root); err != nil {
		return RegisteredProject{}, err
	}
	if err := c.syncFile(root); err != nil {
		return RegisteredProject{}, fmt.Errorf("sync managed project publication: %w", err)
	}
	if err := c.syncParentDirectories(*record); err != nil {
		return RegisteredProject{}, err
	}
	if err := verifyRoot(*record); err != nil {
		return RegisteredProject{}, err
	}
	record.Phase = "ready"
	record.Report.Availability = "available"
	record.Report.Reason = nil
	record.Report.LastObservedAt = c.now()
	record.Report.RootAttestation = attest(*record)
	if err := c.State.PutManagedProject(ctx, *record); err != nil {
		return RegisteredProject{}, err
	}
	return registered(*record), nil
}

func (c Catalog) Resolve(ctx context.Context, request ResolveProjectRequest) (RegisteredProject, error) {
	record, err := c.State.ManagedProject(ctx, request.SelectionID)
	if err != nil {
		return RegisteredProject{}, err
	}
	if record == nil || record.Report.ProjectID != request.ProjectID || record.Report.WorkspaceEpoch != request.WorkspaceEpoch ||
		record.Report.SandboxID != request.SandboxID || record.Report.SandboxGeneration != request.SandboxGeneration ||
		pointerValue(record.Report.ServiceRegistrationID) != request.ServiceRegistrationID || record.ConfigDigest != request.ConfigDigest {
		return RegisteredProject{}, ErrProjectChanged
	}
	return c.resolveRecord(record)
}

func (c Catalog) resolveRecord(record *state.LocalManagedProject) (RegisteredProject, error) {
	if record.Phase != "ready" || record.Report.Availability != "available" || attest(*record) != record.Report.RootAttestation {
		return RegisteredProject{}, ErrProjectChanged
	}
	if record.Report.Designation == "team_project" && record.AllocationDigest != "" {
		if err := c.repairDefaultOwner(context.Background(), *record); err != nil {
			return RegisteredProject{}, err
		}
	}
	if err := verifyPublishedOwner(*record); err != nil {
		return RegisteredProject{}, err
	}
	if err := verifyRoot(*record); err != nil {
		return RegisteredProject{}, err
	}
	return registered(*record), nil
}

func (c Catalog) Refresh(ctx context.Context, request RefreshRequest) ([]model.ProjectCatalogReportV1, error) {
	if request.SandboxGeneration < 1 || !safeComponent.MatchString(request.SandboxID) || request.Limit < 1 || request.Limit > maxCatalogEntries {
		return nil, errors.New("invalid catalog refresh request")
	}
	anchor, anchorIdentity, err := openDirectoryNoFollow(request.Anchor)
	if err != nil {
		return nil, ErrUnsafeProjectRoot
	}
	defer anchor.Close()
	projectsFD, err := unix.Openat(int(anchor.Fd()), "projects", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafeProjectRoot
	}
	projects := os.NewFile(uintptr(projectsFD), filepath.Join(request.Anchor, "projects"))
	defer projects.Close()
	projectsIdentity, err := identityForFile(projects)
	if err != nil || !sameMount(anchorIdentity, projectsIdentity) {
		return nil, ErrUnsafeProjectRoot
	}
	entries, err := projects.ReadDir(request.Limit + 1)
	if err != nil {
		return nil, err
	}
	if len(entries) > request.Limit {
		return nil, ErrCatalogLimit
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	reports := make([]model.ProjectCatalogReportV1, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || !safeComponent.MatchString(name) {
			continue
		}
		report, record, err := c.observeCandidate(ctx, request, anchorIdentity, name)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
		if record != nil {
			if err := c.State.PutManagedProject(ctx, *record); err != nil {
				return nil, err
			}
		}
	}
	return reports, nil
}

func (c Catalog) observeCandidate(ctx context.Context, request RefreshRequest, anchorIdentity fileIdentity, name string) (model.ProjectCatalogReportV1, *state.LocalManagedProject, error) {
	hostRoot := filepath.Join(filepath.Clean(request.Anchor), "projects", name)
	record, _ := c.State.ManagedProjectForRoot(ctx, request.SandboxID, request.SandboxGeneration, hostRoot)
	isNew := record == nil
	if record == nil {
		selectionID, err := opaqueID("selection")
		if err != nil {
			return model.ProjectCatalogReportV1{}, nil, err
		}
		projectID, err := opaqueID("project")
		if err != nil {
			return model.ProjectCatalogReportV1{}, nil, err
		}
		epoch, err := opaqueID("epoch")
		if err != nil {
			return model.ProjectCatalogReportV1{}, nil, err
		}
		record = &state.LocalManagedProject{Report: model.ProjectCatalogReportV1{FormatVersion: 1, SelectionID: selectionID, ProjectID: projectID, WorkspaceEpoch: epoch, SandboxID: request.SandboxID, SandboxGeneration: request.SandboxGeneration, Designation: "team_project", Label: name}, Anchor: filepath.Clean(request.Anchor), HostRoot: hostRoot, ContainerRoot: "/home/agent/projects/" + name, Phase: "observed", AnchorDevice: anchorIdentity.Device, AnchorInode: anchorIdentity.Inode, AnchorMount: anchorIdentity.Mount}
		c.bindWorkspaceImageIdentity(record)
	}
	reason := "unsafe_root"
	availability := "unavailable"
	root, identity, err := openDirectoryNoFollow(hostRoot)
	if err == nil {
		defer root.Close()
		if isNew {
			record.RootDevice, record.RootInode, record.RootMount = identity.Device, identity.Inode, identity.Mount
		}
		identityMatches := isNew ||
			sameDurableObject(record.AnchorDevice, record.AnchorInode, anchorIdentity) &&
				sameDurableObject(record.RootDevice, record.RootInode, identity)
		if identityMatches && sameMount(anchorIdentity, identity) {
			switch classifyGit(ctx, root, identity) {
			case "available":
				availability, reason = "available", ""
			case "no_git":
				reason = "no_git"
			case "unborn":
				reason = "unborn"
			}
		}
	}
	record.Report.Availability = availability
	if reason == "" {
		record.Report.Reason = nil
	} else {
		record.Report.Reason = stringPointer(reason)
	}
	record.Report.LastObservedAt = c.now()
	record.Report.RootAttestation = attest(*record)
	return record.Report, record, nil
}

func verifyRoot(record state.LocalManagedProject) error {
	root, rootIdentity, err := openVerifiedRoot(record)
	if err != nil {
		return err
	}
	defer root.Close()
	if classifyGit(context.Background(), root, rootIdentity) != "available" {
		return ErrProjectChanged
	}
	return nil
}

func verifyOwnedRoot(record state.LocalManagedProject) error {
	root, _, err := openVerifiedRoot(record)
	if err != nil {
		return err
	}
	return root.Close()
}

func openVerifiedRoot(record state.LocalManagedProject) (*os.File, fileIdentity, error) {
	anchor, anchorIdentity, err := openDirectoryNoFollow(record.Anchor)
	if err != nil {
		return nil, fileIdentity{}, ErrProjectChanged
	}
	defer anchor.Close()
	projectsFD, err := unix.Openat(int(anchor.Fd()), "projects", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileIdentity{}, ErrProjectChanged
	}
	projects := os.NewFile(uintptr(projectsFD), "projects")
	defer projects.Close()
	projectsIdentity, err := identityForFile(projects)
	if err != nil || !sameMount(anchorIdentity, projectsIdentity) {
		return nil, fileIdentity{}, ErrProjectChanged
	}
	leaf := filepath.Base(record.HostRoot)
	if !safeComponent.MatchString(leaf) || filepath.Clean(record.HostRoot) != filepath.Join(filepath.Clean(record.Anchor), "projects", leaf) {
		return nil, fileIdentity{}, ErrProjectChanged
	}
	rootFD, err := unix.Openat(int(projects.Fd()), leaf, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileIdentity{}, ErrProjectChanged
	}
	root := os.NewFile(uintptr(rootFD), record.HostRoot)
	rootIdentity, err := identityForFile(root)
	if err != nil {
		root.Close()
		return nil, fileIdentity{}, ErrProjectChanged
	}
	if !sameDurableObject(record.AnchorDevice, record.AnchorInode, anchorIdentity) ||
		!sameDurableObject(record.RootDevice, record.RootInode, rootIdentity) || !sameMount(anchorIdentity, rootIdentity) {
		root.Close()
		return nil, fileIdentity{}, ErrProjectChanged
	}
	return root, rootIdentity, nil
}

func validateDefaultRequest(request DefaultProjectRequest) error {
	for _, value := range []string{request.ServerID, request.TeamID, request.MemberID, request.SandboxID, request.ServiceRegistrationID} {
		if !safeComponent.MatchString(value) {
			return errors.New("invalid default project identity")
		}
	}
	if request.SandboxGeneration < 1 || !digestPattern.MatchString(request.AllocationDigest) ||
		(request.ConfigDigest != "" && !digestPattern.MatchString(request.ConfigDigest)) || request.Anchor == "" || !filepath.IsAbs(request.Anchor) {
		return errors.New("invalid default project request")
	}
	return nil
}

func ensureProjectsDirectory(anchor *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(anchor.Fd()), "projects", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		if err := unix.Mkdirat(int(anchor.Fd()), "projects", 0700); err != nil {
			return nil, err
		}
		fd, err = unix.Openat(int(anchor.Fd()), "projects", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "projects"), nil
}

func openDirectoryNoFollow(path string) (*os.File, fileIdentity, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	identity, err := identityForFile(file)
	if err != nil {
		file.Close()
		return nil, fileIdentity{}, err
	}
	return file, identity, nil
}

func sameMount(left, right fileIdentity) bool {
	return left.Device == right.Device && left.Mount == right.Mount
}

// statx mount IDs are scoped to one mount namespace. Device and inode are the
// durable object authority; every traversal separately proves current mount
// containment with sameMount.
func sameDurableObject(device, inode uint64, current fileIdentity) bool {
	return current.Device == device && current.Inode == inode
}

func ensureEmpty(directory *os.File) error {
	names, err := directory.Readdirnames(1)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if len(names) != 0 {
		return errors.New("project root is not empty")
	}
	return nil
}

func initializeGit(_ context.Context, root *os.File, observed time.Time) error {
	if err := unix.Mkdirat(int(root.Fd()), ".git", 0700); err != nil {
		return fmt.Errorf("create Git metadata: %w", err)
	}
	git, err := openDirectoryAt(root, ".git")
	if err != nil {
		return err
	}
	defer git.Close()
	for _, name := range []string{"objects", "refs"} {
		if err := unix.Mkdirat(int(git.Fd()), name, 0700); err != nil {
			return err
		}
	}
	refs, err := openDirectoryAt(git, "refs")
	if err != nil {
		return err
	}
	defer refs.Close()
	for _, name := range []string{"heads", "tags"} {
		if err := unix.Mkdirat(int(refs.Fd()), name, 0700); err != nil {
			return err
		}
	}
	heads, err := openDirectoryAt(refs, "heads")
	if err != nil {
		return err
	}
	defer heads.Close()
	objects, err := openDirectoryAt(git, "objects")
	if err != nil {
		return err
	}
	defer objects.Close()
	treeID, err := writeGitObject(objects, "tree", nil)
	if err != nil {
		return err
	}
	when := observed.UTC().Unix()
	commitBody := fmt.Sprintf("tree %s\nauthor WarpMetal Runtime <runtime@localhost> %d +0000\ncommitter WarpMetal Runtime <runtime@localhost> %d +0000\n\nInitial project\n", treeID, when, when)
	commitID, err := writeGitObject(objects, "commit", []byte(commitBody))
	if err != nil {
		return err
	}
	config := []byte("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n")
	if err := writeFileAt(git, "config", config, 0600); err != nil {
		return err
	}
	if err := writeFileAt(git, "HEAD", []byte("ref: refs/heads/main\n"), 0600); err != nil {
		return err
	}
	if err := writeFileAt(heads, "main", []byte(commitID+"\n"), 0600); err != nil {
		return err
	}
	indexHeader := make([]byte, 12)
	copy(indexHeader, "DIRC")
	binary.BigEndian.PutUint32(indexHeader[4:8], 2)
	checksum := sha1.Sum(indexHeader)
	if err := writeFileAt(git, "index", append(indexHeader, checksum[:]...), 0600); err != nil {
		return err
	}
	return nil
}

func classifyGit(ctx context.Context, root *os.File, rootIdentity fileIdentity) string {
	if err := ctx.Err(); err != nil {
		return "unsafe_root"
	}
	gitFD, err := unix.Openat(int(root.Fd()), ".git", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return "no_git"
	}
	if err != nil {
		return "unsafe_root"
	}
	git := os.NewFile(uintptr(gitFD), ".git")
	defer git.Close()
	gitIdentity, err := identityForFile(git)
	if err != nil {
		return "unsafe_root"
	}
	if !sameMount(rootIdentity, gitIdentity) {
		return "unsafe_root"
	}
	for _, name := range []string{"HEAD", "config"} {
		file, err := openRegularAt(git, name, gitIdentity)
		if err != nil {
			return "unsafe_root"
		}
		file.Close()
	}
	index, err := openRegularAt(git, "index", gitIdentity)
	if errors.Is(err, unix.ENOENT) {
		return "unborn"
	}
	if err != nil {
		return "unsafe_root"
	}
	index.Close()
	head, err := openRegularAt(git, "HEAD", gitIdentity)
	if err != nil {
		return "unsafe_root"
	}
	headValue, err := readBounded(head, 256)
	head.Close()
	if err != nil || !strings.HasPrefix(headValue, "ref: refs/heads/") {
		return "unsafe_root"
	}
	branch := strings.TrimSpace(strings.TrimPrefix(headValue, "ref: refs/heads/"))
	if !safeComponent.MatchString(branch) {
		return "unsafe_root"
	}
	refs, err := openDirectoryAt(git, "refs")
	if err != nil {
		return "unsafe_root"
	}
	defer refs.Close()
	heads, err := openDirectoryAt(refs, "heads")
	if err != nil {
		return "unsafe_root"
	}
	defer heads.Close()
	ref, err := openRegularAt(heads, branch, gitIdentity)
	if errors.Is(err, unix.ENOENT) {
		return "unborn"
	}
	if err != nil {
		return "unsafe_root"
	}
	refValue, err := readBounded(ref, 128)
	ref.Close()
	objectID := strings.TrimSpace(refValue)
	if err != nil || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(objectID) {
		return "unsafe_root"
	}
	objectDirectory, err := openDirectoryAt(git, "objects")
	if err != nil {
		return "unsafe_root"
	}
	defer objectDirectory.Close()
	prefix, err := openDirectoryAt(objectDirectory, objectID[:2])
	if err != nil {
		return "unsafe_root"
	}
	defer prefix.Close()
	object, err := openRegularAt(prefix, objectID[2:], gitIdentity)
	if err != nil {
		return "unsafe_root"
	}
	object.Close()
	return "available"
}

func openDirectoryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func writeFileAt(parent *os.File, name string, contents []byte, mode uint32) error {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if _, err := file.Write(contents); err != nil {
		return err
	}
	return nil
}

func writeGitObject(objects *os.File, kind string, body []byte) (string, error) {
	raw := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(body))), body...)
	digest := sha1.Sum(raw)
	id := hex.EncodeToString(digest[:])
	if err := unix.Mkdirat(int(objects.Fd()), id[:2], 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return "", err
	}
	prefix, err := openDirectoryAt(objects, id[:2])
	if err != nil {
		return "", err
	}
	defer prefix.Close()
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write(raw); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	if err := writeFileAt(prefix, id[2:], compressed.Bytes(), 0444); err != nil && !errors.Is(err, unix.EEXIST) {
		return "", err
	}
	return id, nil
}

func readBounded(file *os.File, maximum int64) (string, error) {
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		return "", ErrUnsafeProjectRoot
	}
	return string(payload), nil
}

func openRegularAt(directory *os.File, name string, parentIdentity fileIdentity) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, ErrUnsafeProjectRoot
	}
	identity, err := identityForFile(file)
	if err != nil || !sameMount(parentIdentity, identity) {
		file.Close()
		return nil, ErrUnsafeProjectRoot
	}
	return file, nil
}

func (c Catalog) syncGitTree(root *os.File) error {
	git, err := openDirectoryAt(root, ".git")
	if err != nil {
		return err
	}
	defer git.Close()
	return c.syncDirectoryTree(git)
}

func (c Catalog) syncDirectoryTree(directory *os.File) error {
	identity, err := identityForFile(directory)
	if err != nil {
		return err
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrUnsafeProjectRoot
		}
		if entry.IsDir() {
			child, err := openDirectoryAt(directory, entry.Name())
			if err != nil {
				return err
			}
			err = c.syncDirectoryTree(child)
			child.Close()
			if err != nil {
				return err
			}
			continue
		}
		file, err := openRegularAt(directory, entry.Name(), identity)
		if err != nil {
			return err
		}
		err = c.syncFile(file)
		file.Close()
		if err != nil {
			return err
		}
	}
	return c.syncFile(directory)
}

func (c Catalog) syncFile(file *os.File) error {
	if c.Sync != nil {
		return c.Sync(file)
	}
	return file.Sync()
}

func (c Catalog) syncParentDirectories(record state.LocalManagedProject) error {
	anchor, anchorIdentity, err := openDirectoryNoFollow(record.Anchor)
	if err != nil {
		return ErrProjectChanged
	}
	defer anchor.Close()
	if !sameDurableObject(record.AnchorDevice, record.AnchorInode, anchorIdentity) {
		return ErrProjectChanged
	}
	projects, err := openDirectoryAt(anchor, "projects")
	if err != nil {
		return ErrProjectChanged
	}
	defer projects.Close()
	projectsIdentity, err := identityForFile(projects)
	if err != nil || !sameMount(anchorIdentity, projectsIdentity) {
		return ErrProjectChanged
	}
	if err := c.syncFile(projects); err != nil {
		return fmt.Errorf("sync projects directory: %w", err)
	}
	if err := c.syncFile(anchor); err != nil {
		return fmt.Errorf("sync workspace anchor: %w", err)
	}
	return nil
}

func attest(record state.LocalManagedProject) string {
	payload, _ := json.Marshal(struct {
		SelectionID, ProjectID, WorkspaceEpoch, SandboxID, ServiceRegistrationID, AllocationDigest, ConfigDigest string
		SandboxGeneration                                                                                        int64
		AnchorDevice, AnchorInode, RootDevice, RootInode                                                         uint64
		AnchorMount, RootMount                                                                                   string
		ScopeRevision                                                                                            int64
	}{record.Report.SelectionID, record.Report.ProjectID, record.Report.WorkspaceEpoch, record.Report.SandboxID, pointerValue(record.Report.ServiceRegistrationID), record.AllocationDigest, record.ConfigDigest, record.Report.SandboxGeneration, record.AnchorDevice, record.AnchorInode, record.RootDevice, record.RootInode, record.AnchorMount, record.RootMount, record.ScopeRevision})
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func opaqueID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(value[:]), nil
}
func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	copy := value
	return &copy
}
func pointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func registered(value state.LocalManagedProject) RegisteredProject {
	return RegisteredProject{
		Report: value.Report, HostRoot: value.HostRoot, ContainerRoot: value.ContainerRoot,
		ScopeRevision: value.ScopeRevision, RootDevice: value.RootDevice, RootInode: value.RootInode,
		SupersededRootAttestation: value.SupersededRootAttestation,
	}
}
func (c Catalog) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}
