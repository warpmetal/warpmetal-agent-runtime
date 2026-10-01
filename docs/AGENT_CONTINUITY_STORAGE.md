# Agent continuity storage

This package provides the host-side storage, manifest consumer, and lifecycle
primitives for an agent continuity checkpoint. Runtime reports explicit closed
continuity arrays and admits a source only after the managed-service producer
has validated its exact native session, project, instructions, profile, and
host-private workspace registration.

## Identity and safe boundary

Every operation is fenced by the exact V1 identity:

```json
{
  "workId": "work_opaque",
  "projectId": "project_opaque",
  "sandboxId": "sbx_opaque",
  "workspaceEpoch": "epoch_opaque",
  "sandboxGeneration": 4,
  "taskId": "task_opaque",
  "taskAttempt": 2,
  "expectedRevision": 9
}
```

`taskId` and `taskAttempt` are either both present or both JSON `null`. The null
pair is accepted only for an initial boundary whose registered workspace proves
that no execution has ever been admitted. A stopped workspace may also use the
null pair when it carries the same no-admission proof. Task and stopped-history
captures use the exact non-null task pair.

The sandbox boundary receipt is advisory evidence bound to Runtime authority.
Runtime accepts it only when its binding object exactly matches the host-private
workspace registration. An initial receipt has a null task pair and null
`lastAcceptedExecutionId`. A task receipt has a non-null task pair and null last
execution ID. A stopped-history receipt has a non-null task pair and a non-null
last accepted execution ID. Callers never supply a filesystem root or container
ID; the registry resolves those from the identity and binding.

Runtime also stores a host-local monotonic lifecycle revision with pause
ownership. This revision is deliberately not part of the wire identity. It
prevents an old capture from thawing a stopped and restarted container even
when its sandbox generation did not change.

## Capture, checkpoint, and materialize

Capture writes an immutable host-private object. It records HEAD/base, the raw
Git index digest and object, and a sorted path manifest. Each path can carry a
separate index version and worktree version, preserving staged plus unstaged
content, binary bytes, deletion, symlink target bytes, and executable mode.
Capture reads the index and object database without changing HEAD or the live
index.

The object limit is 256 MiB and 10,000 paths. SQLite additionally enforces a
1 GiB durable-capture budget across every Work in one sandbox. Retention is
also per sandbox: the default is 20 accepted checkpoints and 30 days across
all Work. Explicit pins, every current accepted pointer, and active capture,
materialize, continuation, restore, and handoff references survive retention
and consume the same box quota. If protected state fills a count or byte limit,
new publication or acceptance fails with checkpoint quota and leaves the prior
pointer readable.

The default excluded paths are `.git`, `.env`, `.env.*`, `.ssh`, `.aws`,
`.config/gcloud`, and `node_modules`. Untracked excluded paths are omitted. A
tracked or staged excluded path fails capture because preserving the raw index
while omitting its content would silently produce an incomplete checkpoint.
Capture also rejects escaping symlinks, hardlinks, devices, FIFOs, traversal,
linked Git worktrees, symlinked Git metadata, unmerged index entries, and other
unsupported Git layouts.

Files are opened beneath the registered root with `openat` and `O_NOFOLLOW`.
Symlinks are stored as link target bytes and are never dereferenced. Blobs,
manifest, staging directory, and publication parent are fsynced before an
atomic rename publishes the object.

Checkpoint verifies every object digest and the persisted immutable capture,
then atomically inserts the named checkpoint and moves the work pointer in one
SQLite transaction. An exact replay is idempotent. Verification or quota
failure leaves the previous pointer unchanged.

## Collection and crash recovery

The daemon runs a bounded checkpoint lifecycle pass before each control-plane
poll. SQLite first records an exact `planned` collection intent. After a grace
period it rechecks every pointer, pin, and in-flight authority root in the same
transaction that advances the intent to `deleting`. That durable fence blocks
late historical acceptance and new continuation, restore, handoff, or
materialize references.

Physical removal accepts only the capture/object ID and manifest digest from
the deleting intent. It opens the fixed private checkpoint directory with
descriptor-relative, no-follow operations, refuses symlinks, mount changes and
unknown entries, and fsyncs directory updates. It never traverses a registered
workspace, restored project, Git directory, native history, or owner path.
Known `.capture-*` and `.verify-*` staging directories are collected only after
the same grace period. Published-looking symlinks and unknown formats fail the
whole pass closed.

After physical removal, one SQLite transaction removes object metadata, writes
an immutable tombstone, and preserves operation and receipt history. A crash
after the deleting fence or after unlink resumes idempotently on reopen. A
historical replay returns unavailable and cannot recreate bytes or move an
accepted pointer backward. An interrupted pass may retain extra charged bytes;
it never manufactures capacity before deletion is verified.

Materialize accepts only a new registry-owned destination marked
`continuity-materialization`. The destination may be a pristine designated
base clone at the exact recorded commit. An arbitrary existing clean workspace
is not sufficient. Runtime refuses the source epoch, a dirty destination, a
different base, and unsupported Git metadata. It writes through descriptor
relative operations, replaces the index atomically, and re-reads every path
and the index to verify exact digests. An interrupted materialization is
outcome-unknown and is never replayed onto the same destination.

## Pause ownership and recovery

A running capture persists `pausing` before invoking Podman pause. It confirms
the paused state, persists operation-owned pause plus sandbox generation and
local lifecycle revision, and only then reads the filesystem. Capture has a
15-second deadline. Thaw uses a separate 15-second watchdog context so caller
cancellation cannot suppress it.

Runtime never thaws a pre-existing operator pause. It thaws only a pause whose
durable owner, sandbox generation, lifecycle revision, registry target, and
current Podman paused state all still match. An ambiguous pause response,
unknown state, changed target, restart race, or thaw failure remains
`recovery_required` and blocks lifecycle reconciliation.

On restart, a durably owned pause can be inspected and thawed before the
interrupted capture is marked failed. A stopped capture is marked interrupted
without being replayed. A verification-stage checkpoint re-verifies its
immutable capture and completes idempotently. A materialization in progress is
marked outcome-unknown and requires a new registered destination.

## Managed-service producer and mapped sessions

The ordinary Runtime constructor now wires the frozen V1 registration and
operation consumer, fixed boundary helper, SQLite registry, checkpoint object
store, recovery, and reports. It never creates source authority from a
manifest. The managed-service producer:

- creates host SQLite source/service registrations from actual managed-instance
  creation and validation, never from owner paths or agent-writable helper
  files;
- treats `Workspaces.Ensure` and the `/home/agent` bind as a trusted volume anchor
  only. The registered root must be the exact native project/location beneath
  that anchor, with containment, symlink, mount-escape, and managed credential
  directory checks. Runtime must never register `/home/agent` or `.warpmetal`;
- reports no-Git and unborn repositories as unsupported until explicitly
  supported, and never initialize Git in an existing workspace;
- authorizes `sessionMode:create_initial` only for the explicit first managed
  Team start. Restart, inspection, recovery, and bridge paths use
  `sessionMode:lookup_only`, and Runtime records the actual `ses_*` receipt;
- sources the integer profile revision from the applied setup operation and uses
  separate monotonic instruction/config revisions instead of parsing the Team
  profile version string;
- increments the local lifecycle revision on container stop, start, replace,
  and delete before refreshing a source; and
- advertises only a currently validated service tuple. A stale source disables
  new admission after 120 seconds.

Separate continuation sessions retain an additional immutable source mapping;
they never replace the managed service's primary source. Runtime allocates or
resolves only a catalog-owned target workspace, verifies the checkpoint files,
persists the exact mapping, and calls the packaged helper to publish the target
Work registration before starting its one targeted worker. Gateway access
requires the mapped source, project, Work binding, and current managed service,
profile, and instruction tuple. The primary session cannot substitute for a
mapped continuation session.
