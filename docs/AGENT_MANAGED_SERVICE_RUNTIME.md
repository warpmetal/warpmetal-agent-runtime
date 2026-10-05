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
   `sessionMode:create_initial`. The fresh startup monitor intent below is
   resolved before that bit is persisted, so a policy hold cannot consume
   `create_initial` and force later `lookup_only` recovery. Once set, every
   retry, restart, recovery, upgrade and rollback uses `lookup_only`, even if
   the current desired entry still says `create_initial`. Unknown or lost
   responses fail closed.
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

## Fresh startup monitor intent

Monitoring is per sandbox. Before `creationDispatched` is persisted for an
actual spawn, Runtime performs one fresh, bounded read of the existing
authenticated `InsightPolicies` operation through the already-wired managed
control client. The read is a child of the reconcile context and never depends
on a cache refreshed by the post-ACK feedback phase, so a hold retries on the
next pass without a permanent loop.

- Any read failure holds admission and is never interpreted as disabled.
- A previously applied row is not authority: a service disabled earlier may
  have just been enabled.
- Only a successful empty response with no applied policy row proves a
  never-configured service and composes `monitorEnabled:false`.
- A known service (any applied row) with a missing or expired entry holds.
- A fresh disabled entry composes `monitorEnabled:false` without monitor
  identity; a fresh enabled entry composes `monitorEnabled:true`.
- If a `ContinuitySource` row exists, its sandbox/service generations, workspace
  epoch, running lifecycle and native session are validated strictly and reused
  exactly. When no source row exists yet (a new managed service on an already
  monitored sandbox), the monitor source ID is derived with the existing
  `managedSourceID(serviceRegistrationId)` and the workspace epoch from the
  already validated manifest/project. A policy source ref for that derived ID
  without a local source holds rather than inventing or replacing a session.
- Source-ref freshness is collection eligibility only. Stale or omitted refs do
  not block retained bootstrap; a ref matching the retained source is validated
  strictly against it.
- Native session authority is unchanged: `create_initial` remains the one
  possible start before `creationDispatched`, `lookup_only` afterwards.

## Shared launch composition

Ordinary managed start, safe-idle mismatch re-establishment and monitor restart
all build one typed launch request: sandbox/instance/profile/profile digest,
pinned version, port, project root, session mode, the all-or-none instruction
tuple, `runtimeContractVersion` when present, and the explicit monitor intent.
No path silently starts unmonitored while an enabled policy applies.

## Current writer proof and legacy receipts

The packaged supervisor start/status receipts add only these fields:
`monitorReadinessVersion`, `monitorEnabled`, `monitorSourceInstanceId`,
`monitorWorkspaceEpoch`, `monitorWriterReady`, `monitorJournalGeneration`.
Version 1 for a configured-enabled process requires the exact source/epoch and
current writer readiness before worker admission; `monitorJournalGeneration` is
recorded evidence, not an admission gate, and journal readability or
non-emptiness is never readiness. Configured-disabled requires no writer fields.

A receipt missing all of these fields is an explicitly legacy receipt: existing
supported behavior is preserved, but it cannot certify the new automatic
eligibility and Runtime records no qualification for it. Unknown versions fail
closed, and Runtime consumes the existing supervisor `error` field for the
mismatch signal below.

## Safe-idle mismatch and equal-policy verification

A current-capable supervisor start against a running process whose monitor tuple
differs from the request returns `status:"failed"` with error
`monitor_configuration_mismatch` instead of ready. Runtime then performs at most
one re-establishment through the shared composition for either monitor intent
(enabled or explicit disabled), only when the pinned retained source is at
`NoAdmittedExecution`. An active worker task is never restarted; the mismatch
holds at the safe-idle boundary and retries later.

An equal policy revision is not by itself a no-op. Runtime probes the current
process and returns only when the status receipt proves the current monitor
effect. That verification may complete while a worker task is active; only an
actual restart requires the safe-idle boundary.

## Compatibility and qualification limits

- Current-image qualification requires `monitorReadinessVersion:1` writer
  readiness. Legacy images keep legacy behavior but are not qualified for the
  new automatic eligibility.
- This contract adds no endpoint, policy ledger, second refresh loop, state
  schema change or Runtime `/proc` access; the supervisor owns current process
  identity and writer proof.
- No image allowlist, release pin, publication or deployment change is made
  here. Rollout order and installed-gate execution remain with the integration
  owner; the installed gate must use image bytes with the corrected Runtime
  export and the frozen tests.

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
survive daemon restart. The same journey also covers the retained startup
monitor contract: fresh enabled intent after a stale cache, stale/omitted
source refs, explicit disabled authority, new-service derivation without a
source row, expired hold, enabled and explicit-disabled mismatch
re-establishment with an active-task hold, and equal-policy verification while
active. Live Linux/Podman and deployed-candidate validation remains deferred by
direction.
