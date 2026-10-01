# Managed Team workspace catalog contract

Status: S1.M.A implemented host-private catalog boundary, 2026-09-27. The
ordinary Runtime remains the only authority that maps an opaque workspace
selection to a host path.

## Setup materializer compatibility prerequisite

The backend's approved OpenCode profile currently sends this closed
`archive-binary` shape:

```json
{
  "kind": "archive-binary",
  "platform": "linux/amd64",
  "artifact": {
    "id": "opencode-cli-linux-x64",
    "source": "https://registry.npmjs.org/@opencode/cli-linux-x64/-/cli-linux-x64-2.0.14.tgz",
    "sha256": "sha256:a3824cc0d080fd69e95c47ae751a8ba49b668f6492fcfe377f5c941c337e53a9",
    "integrity": "sha512-YFGnck40hBmD8S785zHi1sCZMVodoyxy615SrEo+YXJj/i92I8ViETodsY6Yde0H0VJk/ZuLu8mrllOA4wbAlQ==",
    "format": "tar-gz",
    "sizeBytes": 88757774
  },
  "bin": {
    "name": "opencode",
    "member": "package/bin/opencode",
    "sha256": "sha256:78accad0f9fa61f681c4e0342ce4960ab784d27ddf34796ce12d156f9b5c3abb",
    "version": "2.0.14",
    "environment": {"OPENCODE_DISABLE_AUTOUPDATE": "1"}
  }
}
```

Runtime's current archive model omits `platform`, artifact `integrity`, and bin
`sha256`, `version`, and `environment`; it also rejects a safe nested member
path. S1.M.A adds those closed fields, preserves the older Ant archive shape,
validates the platform and safe relative member, and transports the exact
document to the existing fixed setup runner. It adds no command, hook, script,
post-install, or caller-selected executable.

Only a `ready` setup receipt matching sandbox generation, profile ID, integer
profile revision, and profile digest may be used by the later managed-service
producer. The semver-like Team member profile revision remains a separate
backend capability selector.

## Host-private project interface

The red tests freeze this narrow local interface:

```go
type DefaultProjectRequest struct {
    Anchor, ServerID, TeamID, MemberID, SandboxID string
    SandboxGeneration int64
    ServiceRegistrationID, AllocationDigest, ConfigDigest string
    RebindSelectionID string // required to rebind existing storage
}

type RefreshRequest struct {
    Anchor, SandboxID string
    SandboxGeneration int64
    Limit int
}

type ResolveProjectRequest struct {
    SelectionID, ProjectID, WorkspaceEpoch string
    SandboxID string
    SandboxGeneration int64
    ServiceRegistrationID, ConfigDigest string
}

type RegisteredProject struct {
    Report ProjectCatalogReportV1
    HostRoot, ContainerRoot string // host-private; never JSON/report fields
}

func (Catalog) EnsureDefault(context.Context, DefaultProjectRequest) (RegisteredProject, error)
func (Catalog) Refresh(context.Context, RefreshRequest) ([]ProjectCatalogReportV1, error)
func (Catalog) Resolve(context.Context, ResolveProjectRequest) (RegisteredProject, error)
```

The safe report shape is:

```json
{
  "formatVersion": 1,
  "selectionId": "selection_opaque",
  "projectId": "project_opaque",
  "workspaceEpoch": "epoch_opaque",
  "sandboxId": "sbx_opaque",
  "sandboxGeneration": 4,
  "serviceRegistrationId": "service_opaque",
  "designation": "team_project",
  "label": "bounded-display-label",
  "availability": "available",
  "reason": null,
  "rootAttestation": "sha256:opaque",
  "lastObservedAt": "2026-09-27T18:00:00Z"
}
```

`serviceRegistrationId` is null for a discovered candidate until an exact
managed-service registration binds it. Reports never contain an absolute or
relative path, container path, device, inode, Git directory, credential path,
or native ID. `selectionId`, `projectId`, and `workspaceEpoch` are generated
and persisted by Runtime. Backend manifests can select only a current reported
`selectionId` or explicitly request creation of the new-Team default; they
cannot submit a path.

## New-Team default project

For an explicit new-Team default request, Runtime treats the exact result of
`Workspaces.Ensure` as a trusted volume anchor, never as the project. It
validates the backend-issued opaque Team ID as a single safe component and
creates:

```text
/home/agent/projects/<opaqueTeam>
```

The corresponding host root is the same relative location beneath the trusted
mount. Runtime persists the allocation digest before filesystem
mutation, opens the anchor and `projects` directory by descriptor, and creates
the leaf with `mkdirat` and exclusive semantics. An existing leaf, symlinked
`projects` directory, non-directory component, different device/mount, or any
entry already present in the new leaf fails closed. Runtime never adopts or
initializes `/home/agent`, `.warpmetal`, an owner directory, or an existing
empty directory.

Only the directory created by that exact durable allocation may be initialized
as Git. Runtime keeps the no-follow root descriptor open and writes the closed
ordinary `.git` layout relative to that descriptor: an empty tree object, an
initial `main` commit, a loose ref, and a v2 empty index. It does not invoke Git
through a mutable pathname and does not run a network operation, template
hook, filter, credential helper, or user configuration. A path replacement
during initialization can only receive a failed post-write attestation; the
replacement is never written. A crash before the created inode is durably
recorded leaves an unowned orphan that Runtime never adopts. Later recovery
resumes only when the recorded anchor/root identities and initialization phase
still match.

## Existing project observation

Refresh is bounded to at most 64 direct children of `projects`; it never walks
the whole home or recursively searches. Dot entries and `.warpmetal` are not
project candidates. Each entry and its `.git`, `HEAD`, `config`, index, ref,
and referenced object are opened without following links and checked against
the current anchor device/mount. Existing catalog entries retain their original
mount provenance during refresh; a service restart never rewrites the stored
attestation merely because systemd created a fresh mount namespace. Reports
classify candidates without changing them:

| Condition | availability / reason |
|---|---|
| ordinary repository with HEAD and index | `available` / null |
| no `.git` | `unavailable` / `no_git` |
| repository without HEAD | `unavailable` / `unborn` |
| symlink, mount escape, linked worktree, special file, unsafe Git metadata | `unavailable` / `unsafe_root` |
| scan limit exceeded | `ErrCatalogLimit`; caller reports unavailable / `catalog_limit` |

Runtime never runs `git init` for an observed entry. An observed candidate gets
host-issued IDs only in the private catalog; selecting it later must match its
attestation and persisted device/inode tuple.

## TOCTOU, epoch, and config fences

The private SQLite record includes server/team/member/service references,
sandbox generation, config digest, anchor and root device/inode/mount identity,
container-relative root, Git metadata identity, allocation phase, IDs, and the
attestation digest. Path strings and inode facts stay local. Device and inode
are the durable filesystem-object authority. The recorded `statx` mount IDs are
immutable, attested creation provenance because Linux mount IDs are scoped to
one mount namespace and systemd creates a new namespace on service restart.

The allocation digest is a stable idempotency fence for the create-default
request. It remains separate from the managed service config digest because a
new default has no `selectionId` when allocation begins. Once the backend
rematerializes the execution tuple with that selection, an explicit rebind
records the config digest.

Every resolve reopens from the trusted anchor with descriptor-relative,
no-follow operations and recomputes the attestation. It requires the exact
durable anchor/root device and inode and separately requires anchor,
`projects`, root, `.git`, and the opened Git files to remain on one current
device/mount boundary. This permits a new systemd namespace, including a bind
of the exact host-controlled anchor object, while rejecting a nested root or
Git bind mount. Root replacement, rename, current mount escape, sandbox
generation mismatch, epoch mismatch, service mismatch, or config digest
mismatch returns `ErrProjectChanged` with no helper or Git action.
`workspaceEpoch` is stable for an exact root and changes only when storage/root
identity is explicitly replaced. Profile or instruction changes revoke the
old service/source binding but do not silently create a new project or epoch;
a later binding must revalidate the same selection.

An explicit rebind after service/config revocation must supply the exact prior
`selectionId`. Runtime revalidates the recorded root and preserves its
`selectionId`, `projectId`, and `workspaceEpoch`; omission or mismatch fails
closed and cannot allocate replacement storage.

Runtime fsyncs every Git file and directory plus the project, `projects`, and
anchor directories before changing the SQLite phase to `ready`. A sync error
leaves the record non-ready. A final descriptor-relative identity check runs
after those syncs and immediately before publication.

`rootAttestation` binds the safe identity/config tuple and filesystem identity
with SHA-256. It proves only what Runtime observed locally. It is not a native
project/location/session receipt, and S1.M.A does not invent those IDs. The
supervisor/native receipt and Team enrollment/worker lifecycle remain separate
S1.M packets coordinated with Sandbox and backend.


## Sandbox ownership boundary

Runtime derives the host owner from the verified workspace anchor. It preserves
strict project permissions and transfers newly created default Git content to
that owner before publishing availability. Restore and handoff pass the allocated
root device/inode to checkpoint materialization; only verified destination content
is transferred, with no source-workspace ownership changes.

Legacy inaccessible default projects are repaired only when the recorded identity,
attestation and exact pristine Runtime Git bootstrap match. Unknown worktree
content, owner, unsafe mode, symlink, hardlink or mount changes fail closed.
Root ownership transfers last, allowing a partial transfer to be reverified.
Checkpoint Git reads trust only the exact validated source root, suppress global
configuration, hooks and fsmonitor, and do not refresh the source index.

The packaged service uses UMask=0027: generated immutable Git objects may be
0440 rather than0444. Both exact generated modes are recognized and preserved;
project directories and private Git metadata retain0700/0600.
