# Managed Agent Team Runtime producer contract

Status: S1.M Runtime producer implemented and locally verified, 2026-09-27.
No managed service or continuity source is advertised until the full receipt
chain succeeds.

## Control-plane inputs and outputs

The ordinary manifest adds the canonical `managedWorkspaceRequests` and
`managedServices` arrays from `agent-managed-service-v1`. The ordinary report
adds `managedWorkspaceSelections` and managed `managedServices` reports.
Runtime validates exact server, desired/action revision, sandbox generation,
service generation, setup tuple, workspace selection/epoch/attestation,
instruction revision/digest, role, and config digest before any action.

A `create_default` workspace request carries its own `allocationDigest`. It is
processed through the S1.M.A catalog and reported before a service config can
select the new host-issued selection. The later stable service `configDigest`
excludes the owner operation, action, desired state, and desired revision, so
pause/resume does not replace native configuration or storage.

The safe workspace report remains:

```json
{
  "formatVersion": 1,
  "sandboxId": "sbx_opaque",
  "sandboxGeneration": 4,
  "workspaceEpoch": "epoch_opaque",
  "selectionId": "selection_opaque",
  "projectId": "project_opaque",
  "serviceRegistrationId": "service_opaque",
  "designation": "team_project",
  "label": "bounded label",
  "availability": "available",
  "reason": null,
  "rootAttestation": "sha256:opaque",
  "lastObservedAt": "2026-09-27T17:00:00Z"
}
```

No path, inode, mount, native workspace ID, token, or instruction text enters
that report.

## Node-authenticated fetches

The existing Runtime node credential owns two closed POST operations:

```text
/internal/runtime/agent-teams/managed-services/<serviceRegistrationId>/enrollment
/internal/runtime/agent-teams/managed-services/<serviceRegistrationId>/instructions
```

Both receive the exact common fetch tuple from the canonical fixture:
`formatVersion`, operation/action/desired revision, `configDigest`, service
registration/generation, sandbox/generation, and persisted `processInstance`.
The decoder is strict and bounded. Enrollment credentials are transient and
redacted. Instruction content must be non-empty UTF-8, at most 32,768 bytes,
must hash to the exact current digest, must carry the current positive
revision, and must not be expired. SQLite stores only its digest, revision and
expiry.

## Durable operation order

For an active service, Runtime performs this sequence:

1. Require the exact setup operation to be locally `ready` for the current
   sandbox generation, profile ID, integer profile revision and profile
   digest.
2. Resolve the host-private workspace selection again, including the current
   root attestation and config fence.
3. Persist the immutable service intent, service generation, runtime-owned
   process instance and port before any node fetch or sandbox action.
4. Fetch the current enrollment and instructions. Invoke the packaged
   supervisor `enroll` action with the bound Team/member/generation/process
   tuple. The sandbox exchange provides the current derived role and lease.
5. Persist `creationDispatched` before the one possible `start` with
   `sessionMode:create_initial`. Once set, every retry, restart, recovery,
   upgrade and rollback uses `lookup_only`, even if the current desired entry
   still says `create_initial`. Unknown or lost responses fail closed.
6. Invoke the existing packaged supervisor `start` with exact container
   `projectRoot` and the all-or-none `instructionText`, `instructionDigest`,
   and `instructionRevision` fields. A ready receipt must return the exact
   saved session, actual native project ID, native location digest, and
   `instructionApplied:true` with the current digest and revision.
7. Probe the packaged supervisor `status` action and require the same session,
   native project/location and current applied instruction proof.
8. Run the packaged Team worker `reconcile` and `status` boundary, then launch
   at most one bounded `execute` one-shot per member under the daemon lifecycle
   rather than the shorter manifest poll context. Regular reconciliation and
   node reporting continue while the one-shot runs. Daemon shutdown and an
   explicit pause/stop cancel it; policy acknowledgement waits for that
   cancellation. On restart, Runtime reconciles the worker's durable marker
   before launching one replacement one-shot. These are the existing
   broker/lease worker operations; Runtime does not create another queue,
   daemon, or native worker. An execute receipt is task admission/output state;
   it is never treated as proof that a worker task succeeded.
9. Recheck SQLite lifecycle/config/generation and the workspace root after all
   external responses. Only then publish the ready service report and create
   the host-private continuity source mapping.

The fixed container executor accepts closed action enums. Supervisor actions
run `/usr/local/bin/warpmetal-opencode-supervisor`; worker actions run
`/usr/bin/python3` with the image-owned
`/usr/local/libexec/warpmetal-agent-teams/warpmetal_team_worker.py`. Neither
seam accepts an executable, argv, shell, host path, or arbitrary action.

## Lifecycle and recovery

`paused` requires a current supervisor drain acknowledgement and retains the
native/config/storage tuple. `stopped` requires a stop acknowledgement.
Neither path clears an operation-owned continuity barrier or any independent
operator pause. `retired` retains service and source history, revokes admission
and publishes an unavailable source tombstone with safe reason
`service_retired`.

Profile, instruction, workspace, sandbox generation, expected service
generation, role, or config drift fences the prior source before admission.
An ambiguous result remains `recovery_required`; Runtime does not assume
ready, does not mint a native ID, and does not publish a source. Its outbound
state is the nonterminal `registering` report with stable progress digest and
without `lastError`, so replay cannot freeze a terminal backend receipt before
recovery. Restart reads the durable creation bit and reconciles the same
service with `lookup_only`.

## Validation boundary

The production tree includes the managed manifest/report model, strict node
client, durable SQLite service state, fixed supervisor/worker Podman methods,
Reconciler producer and ordinary daemon wiring. The local journey reopens the
SQLite database and constructs a new reconciler after an ambiguous initial
start, proves the retry is `lookup_only`, then reopens it again before
pause/stop/retire to prove independent capture barriers and source tombstones
survive daemon restart. Live Linux/Podman and deployed-candidate validation
remains deferred by direction.
