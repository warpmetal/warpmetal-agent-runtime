# WarpMetal Agent Runtime

`warpmetald` is the optional, outbound-only supervisor installed on a customer's
server by the official `warpmetal runtime install` command. It reconciles the
server-scoped manifest, runs fixed-image rootless Podman sandboxes, enforces
resource and ext4 workspace limits, expires temporary workspaces locally, and
renders the forced-command SSH access map.

This repository is the canonical public source for the supervisor, installer,
systemd units, and restricted SSH gateway. The WarpMetal control plane and
billing system are separate: this runtime manages only the sandboxes belonging
to the owner of one server.

## Security boundary

- The node token is root-only, stored outside every sandbox, and authorizes only
  manifest reads and runtime reports.
- Sandboxes are non-privileged, read-only-root containers without host sockets,
  host namespaces, published ports, capabilities, or host credentials.
- Host output rules tied to the dedicated runtime UID reject IPv4 and IPv6
  link-local metadata endpoints before any sandbox starts.
- Each public key is forced through the locked `warpmetal-sandbox` account and
  an opaque grant ID. The restricted shell cannot start a host shell.
- Stop, revocation, expiration, image replacement, and deletion cancel matching
  gateway sessions.
- Temporary expiry uses the local SQLite clock state and continues during a
  control-plane outage.
- Workspace images live outside the root-only supervisor state directory. The
  runtime user's subordinate UID/GID ranges and a dedicated, delegated Podman
  service keep container lifecycle operations rootless after reboot. Its Unix
  socket is mode `0600` inside a runtime-user-owned `0700` directory.
- The root supervisor performs ext4 mount operations through PID 1's host mount
  namespace so the separate rootless engine sees only the intended workspace
  mounts; the rest of the supervisor stays inside its hardened mount namespace.
- On amd64 hosts that actively enforce AppArmor's restricted-unprivileged-userns
  control, an explicit signed-installer option can load a narrowly attached
  policy for the exact root-owned `/usr/local/libexec/warpmetal-bwrap` helper in
  the signed sandbox image. Bubblewrap may construct its inner namespaces and
  mounts, but every descendant is forcibly stacked with a capability-denying
  profile. The Agent Box keeps every capability set, including the bounding
  set, empty. The policy does not attach to `/usr/bin/bwrap`, workspace
  binaries, or generic `unshare`, and it does not add a container capability.
  Codex and Claude Code use the same provider-neutral immutable helper; neither
  receives a broader host privilege.

## Automatic sandbox setup

Tool setup is a durable Runtime reconciliation workflow. Each immutable setup
operation follows `pending -> applying -> ready/failed/cancelled`, and those
states survive daemon restarts.

Runtime executes one setup operation per report cycle. Each has a 10-minute per-operation deadline.
The applied revision advances only when all setup operations are ready.
A failed, cancelled, or still-applying operation keeps the desired revision
unapplied and visible in Runtime reports.

Provisioning cloud-init is used only to bootstrap and then enroll Runtime.
Cloud-init does not install provider tools or an AI CLI as host root. Provider
artifacts are instead materialized by the fixed runner inside the target
sandbox as its unprivileged user, after that sandbox exists and is running.

The Runtime transports two closed generic materializers: exact offline npm
package sets with optional updater-disabled Node launchers, and exact `tar.gz`
archive binaries with one declared executable. This supports the unreleased
`claude-code` 2.1.277 and install-only `claude-managed-ant` 1.33.0 candidates
without adding Anthropic credentials or provider lifecycle policy to Runtime.
Installing `ant` does not connect or activate Claude Managed Agents; that later
capability requires protected per-work secrets and fenced execution leases.

The outer rootless Podman container is the Runtime boundary.
Sandbox processes run as UID/GID 1000 with a read-only root.
`/home/agent` is the persistent workspace.
No host container runtime socket is exposed.
Runtime materializes only explicit setup operations through the fixed sandbox
runner. It does not authenticate providers or inspect arbitrary user tools;
each user owns configuration, credentials, and later software maintenance.
User tools inherit the sandbox's existing capability,
seccomp, network, cgroup, and host-socket restrictions. Provider credentials
remain user-owned files or process environment inside the workspace and must
never be sent through desired state, registration, or runtime reports.

## Agent continuity storage

Runtime now has a host-side continuity storage and manifest consumer for
immutable Git workspace capture, atomic checkpoint acceptance, fresh-destination
materialization, operation-owned Podman pause, and fail-closed restart
recovery. Checkpoint objects and their SQLite identities remain host-private;
sandboxes cannot select roots, container IDs, or destinations. The ordinary
Runtime constructor consumes and reports the frozen continuity records. Its
managed-service producer now publishes a source only after the fixed supervisor
returns an exact current native session/project receipt and Runtime matches that
receipt to the host-private project catalog, service generation, profile, and
instructions.

See [`docs/AGENT_CONTINUITY_STORAGE.md`](docs/AGENT_CONTINUITY_STORAGE.md) for
the exact identity, safe-boundary, quota, filesystem, recovery, and integration
contracts.

## Standard SSH aliases use the forced gateway

A WarpMetal CLI-managed OpenSSH alias is only a client-side view of an existing,
pinned sandbox connection profile and its sandbox-specific private key. It does
not add another Runtime access path. The alias connects to the host's existing
SSH service as the locked `warpmetal-sandbox` account, where the public key is
already bound to one opaque grant ID and forced through
`warpmetal-sandbox-gateway`. Runtime does not start `sshd` in a sandbox, open a
new port, copy or expose the VPS owner key, or provide a host shell.

The two supported session forms retain the same grant and sandbox boundary:

```sh
ssh <alias>
ssh <alias> '<command>'
```

An empty SSH command requests the assigned sandbox's interactive shell. A
supplied command becomes `SSH_ORIGINAL_COMMAND` and is executed inside that same
sandbox; its exit status is returned to the SSH client. The client alias does
not set `RemoteCommand`, so it can support both forms. It uses strict pinned host
keys and clears forwarding. Host SSH policy and each forced authorized-key entry
also deny agent, TCP, stream-local, X11, tunnel, and user-rc forwarding. Adding
an alias does not relax those controls.

Access remains grant-scoped. Revoking a grant denies new connections and causes
the supervisor to terminate its tracked active sessions without deleting the
sandbox workspace. Each separately delegated sandbox should use its own key and
grant; neither is an owner-management credential.

After an OS reload or another authorized host-key rotation, never bypass a stale
pin or delete it to make SSH connect. First reinstall Runtime, wait for the
retained grant to become `applied`, and use the authenticated
`warpmetal sandbox access refresh --confirm REFRESH` flow to replace the
connection profile with control-plane-reported host keys. Then explicitly
refresh the managed alias with
`warpmetal sandbox access install-ssh --confirm REFRESH`. Alias refresh consumes
that already-refreshed profile; it does not observe or trust a host key from the
network. Do not use `StrictHostKeyChecking=no`, `accept-new`, or `ssh-keyscan` as
a recovery shortcut.

Build and test on Linux with Go 1.25 or newer:

```sh
go test ./...
go vet ./...
```

Host isolation tests additionally require a disposable systemd VM with cgroups
v2 and rootless Podman; they intentionally do not run against a developer's
workstation.

## Releases

Tagged releases provide static Linux binaries for `amd64` and `arm64`. Each
archive has a SHA-256 checksum and a detached Cosign signature. The signing
public key is committed as [`cosign.pub`](cosign.pub).

The tag workflow initially publishes those exact artifacts as a prerelease.
Promote an existing release only after its signed asset passes the provider
canary and rollback gates; never rebuild or replace an asset during promotion.
Backend activation must use the tested asset URL, checksum, signature, and
version.

The future release archive contains only:

- `install.sh`
- `warpmetald`
- `warpmetal-agentctl`
- `warpmetal-sandbox-gateway`
- `warpmetal-sandbox-shell`
- `warpmetal-podman-service`
- `warpmetal-podman.service`
- `warpmetald.service`
- `warpmetal-sandbox.conf`

The official CLI verifies the configured checksum and signature before it runs
the root installer. To verify a downloaded release manually:

```sh
sha256sum -c warpmetal-runtime-<version>-linux-<arch>.tar.gz.sha256
cosign verify-blob \
  --key cosign.pub \
  --signature warpmetal-runtime-<version>-linux-<arch>.tar.gz.sig \
  --insecure-ignore-tlog=true \
  warpmetal-runtime-<version>-linux-<arch>.tar.gz
```

The archive also carries the AppArmor profile, its transactional installer
library, the Linux metadata verifier, and
`nested-private-procfs-oracle.sh`. That host-policy oracle is credential-free
and verifies the fixed helper's ownership/mode and direct-host private-procfs
policy behavior. It does not model the additional kernel restriction imposed
by a rootless outer container and does not replace the required Ubuntu 24.04
packaged/live qualification.

For a newly started or generation-replaced running sandbox with an explicit
setup operation, the supervisor also executes a closed, credential-free
equivalent through the private Podman service before reporting that generation
as running. It uses only fixed Runtime
argv, UID/GID 1000, the immutable helper, nested namespaces, the already
PID-isolated outer procfs mounted read-only, a private `/dev` and `/tmp`, and a
temporary workspace probe. Inheriting procfs is Codex's documented
restrictive-container fallback when the kernel denies a second procfs mount.
The preflight also proves effective and bounding capabilities are empty and the image root
remains unwritable. Failure stops the container and records
`nested_sandbox_preflight_failed`; access grants and tool setup cannot advance
against that generation.

Each actual setup execution rechecks this boundary, including operations added
to an already-running sandbox and work resumed after a daemon restart. Failed
execution preflight produces a durable setup failure. Capacity-only sandboxes
do not require the nested helper. Ordinary SSH keeps the existing streaming and
cancellation contract: newer images use the fixed image-owned capability
launcher, while pinned older images retain their original shell behavior.

Only install a release through an authenticated WarpMetal runtime-install
session. The installer requires root because it creates the dedicated runtime
and SSH gateway accounts, installs host firewall rules, and enables the
supervisor service. Supported hosts are AlmaLinux 9, Debian 12, Rocky Linux 9,
and Ubuntu 24.04 with systemd and cgroups v2. The installer uses the host's
`apt` or `dnf` packages and explicitly selects the distribution `crun` package
for WarpMetal's private rootless Podman service. It never requests the distro
`runc` package, because that package conflicts with Docker CE's
`containerd.io` bundle on Debian-family hosts.

Before package mutation, the installer takes a root-only metadata snapshot of
recognized container-runtime processes and any running Docker container IDs,
init PIDs, and start timestamps. It does not collect container names, images,
environment variables, mounts, or logs. APT runs a simulated transaction and
then applies it with `--no-remove`; DNF runs an RPM transaction test without
`--allowerasing`. Both paths preserve the exact versions of installed known
Docker/containerd/Podman and package-manager components and verify that stack
after the package action. Package apply failures run the same package and
workload postconditions before returning. The workload snapshot is checked
again immediately before registration. Package-plan conflicts, uninspectable
Docker state, or workload drift fail closed with a stable `runtime_*` error
before the supervisor is registered.

On an upgrade, an already-active private WarpMetal Podman service is preserved
instead of restarted. This keeps persistent sandboxes and their delegated
cgroups running while the supervisor binaries are replaced. A fresh install,
or an inactive service, is still started before registration.

The installer accepts the closed option
`--nested-private-procfs preserve|enable|disable`; omission is `preserve`.
Preserve mode does not inspect, parse, load, unload, create, replace, or remove
the Runtime AppArmor policy. Explicit `enable` is currently supported only on
amd64 and installs the policy only when the host reports that AppArmor's
restricted-unprivileged-userns control is active. When that restriction is
definitively absent, enable is a no-op. Explicit `disable` removes Runtime's
policy and restores the exact file and loaded state captured before the first
enable.

On a restricted AppArmor host, enable/disable requires the host's existing
`apparmor_parser`. Runtime does not install an AppArmor package, write the
restricted-userns sysctl, reload or restart AppArmor, restart Podman, grant
host capabilities, mount a runtime socket, or relax container AppArmor/seccomp
globally. The signed candidate is parsed first, only
`/etc/apparmor.d/warpmetal-agent-runtime-bwrap` is atomically replaced, and only
that file is loaded. Root-only durable state under
`/var/lib/warpmetal-apparmor-policy-state`, outside Runtime's systemd-managed
`StateDirectory`, preserves the exact pre-enable file and kernel-loaded state.
A host with the legacy `/var/lib/warpmetal/apparmor-policy-state` layout is
adopted only when that state is the closed empty baseline and the installed
candidate is already active; an atomic marker records the adoption while the
legacy evidence is retained. A legacy nonempty backup or ambiguous state fails
closed because systemd may already have rewritten its saved ownership and the
original metadata cannot be reconstructed safely. A mutating operation is
committed only after Runtime registration and service restart succeed;
installer failure restores the snapshot, and a later explicit enable/disable
recovers an interrupted transaction before applying a new one. Conflicting
disk/kernel state and metadata, parse, load, architecture, or recovery failures
fail closed.

This is a host-scoped policy for the exact immutable helper path, not a
per-sandbox grant or an image-digest verifier. The control plane remains
responsible for selecting a trusted immutable image. Agent-enabled first boot
can opt in through the already verified signed Runtime bundle, so no later SSH
step is required. The daemon has no autonomous signed maintenance operation:
post-provision repair or policy-mode changes must re-run the authenticated
signed installer through the provider's normal reload/reprovision path. No
sandbox manifest or Runtime HTTP field is added.

Workspace mounts receive a private Podman SELinux label on enforcing hosts.
The ordinary installer does not install or replace a kernel. If a reboot is
already pending, it exits with status 75 and `runtime_reboot_required` before
updating package indexes or consuming the bootstrap token. Reboot only as a
separately authorized maintenance action, then retry the same verified
installer.

The ordinary installer also never runs `podman system reset`. A preview install
whose Podman state still points at the former user-manager run root exits with
`runtime_legacy_migration_required`; preserve that host and use a separately
reviewed migration procedure rather than deleting container metadata.

Signed v0.1.25 and v0.1.26 archives are immutable historical releases. Their
existing signed members remain unchanged; future bundles carry only the closed
setup and policy contract described here.

## Sandbox images and persistence

The base userspace image is maintained separately in
[`warpmetal/warpmetal-agent-sandbox`](https://github.com/warpmetal/warpmetal-agent-sandbox).
Production must use the complete registry digest emitted by that repository's
signed workflow, and the package must permit unauthenticated pulls from
customer servers. A new default digest applies only to newly created sandboxes;
existing sandboxes remain pinned to their creation image.

An existing sandbox changes images only when its authenticated manifest names
an explicit immutable per-sandbox digest and advances that sandbox's
generation. The runtime ensures the exact immutable target is locally available (pulling only when missing) before interruption, terminates active
gateway sessions, and replaces only the container root filesystem. The
external `/home/agent` workspace, sandbox identity, lifetime, and original
start time are preserved. Running sandboxes return to running and stopped
sandboxes remain stopped. The old container is retained under a deterministic
backup name until the replacement reaches its desired state, allowing a failed
or interrupted refresh to roll back or resume safely.

Runtime continues to open databases created by earlier releases. Retired
columns are treated as passive compatibility data: lifecycle reads and upserts
do not reconcile, rewrite, or report their contents. Likewise, unrecognized
fields in a legacy manifest do not prevent the remaining sandbox lifecycle
contract from being decoded and reconciled.

## Managed insights transport

Managed monitoring remains off until the authenticated node policy enables it.
The daemon accepts policies for at most 120 seconds and compares every sandbox,
service generation, workspace epoch, registered source, and native session with
its host-private registry before reading the packaged exporter. Enabling or
disabling the monitor environment restarts the existing managed process only
at its durable idle boundary, in `lookup_only` mode, with the pinned project,
profile, instruction, port, and native session unchanged.

The fixed exporter returns sanitized finding revisions rather than native event
bodies. Runtime persists each bounded batch in SQLite before sending it and
replays an uncertain request byte-for-byte after restart. The acknowledgement
transaction removes the outbox record and advances its journal/change cursor
together. Unchanged health polls are coalesced. Journal rotation first sends an
empty explicit gap and installs the new generation floor only after the server
acknowledges that batch.

Before a managed source becomes visible, Runtime also sends the exact
host-authoritative service, project, profile, instruction, and native tuple to
the fixed supervisor `register-source` command. A missing or changed receipt
keeps the source private. This source record does not create Work, a task, a
prompt, or a new native session.

Managed enrollment binds the sandbox generation. Its process instance and native service registration bind the independent service generation; refreshing a sandbox does not equate those counters. Recovery after any dispatched native creation remains lookup-only.

Managed managers use idle status and native registration for readiness. Only worker and reviewer services run broker task reconciliation and execution; manager leases are never granted task.claim by Runtime.

Lease renewal and fresh native checks refresh source health while retaining a semantically identical completed managed-service receipt for the same action. Backend observations do not rewrite that action’s desired session mode.

Idle worker completion updates only the execution flag when the exact observed source and lifecycle still match, preserving newer readiness observations and lifecycle fences.

### Managed review execution, findings and hold recovery

Automatic and manual manager reviews follow one durable lifecycle. Runtime first
persists a non-dispatched `start_ack_pending` intent and submits the exact
canonical `reviewing` report for that reservation, run, finding, source, target
and policy revision. Only after the backend acknowledges that exact identity does
Runtime persist possible dispatch (`execution_unknown` with `DispatchStarted`) and
invoke the helper. A refused or mismatched acknowledgement dispatches zero helper
calls; a lost acknowledgement retries the same idempotent report while the
original authority is valid. A run that never crossed possible dispatch settles
as failed with `trusted_zero_start` and zero usage once its authority is gone; a
possible or actual dispatch never claims trusted zero.

`Continue` and `Reconcile` observe the stored native session and typed completed
assistant for the same admitted run instead of replaying `start_review` or
creating a new session. `Reconcile`, including `request_evidence` results, is
GET-only; any permitted `Continue` second evidence prompt remains behind the
helper's fresh original-authority checks and the existing two-request budget.
Non-start recovery does not require a local finding row. Usage stays uncertain
and conservative until a truthful terminal receipt arrives, and terminal reports
are immutable and re-sent exactly.

A terminal receipt carries the actual outcome. `recommended` requires bounded
non-empty guidance, `no_action` carries null guidance, and `needs_owner` permits
null or bounded guidance; an invalid completed answer settles as `needs_owner`
with a null proposal under the existing closed error. Runtime passes through the
actual proposal summary, rationale, cited sequence bounds and manager session; it
never invents a recommendation, rationale or finding window, and raw guidance and
citations remain private.

Findings acknowledged by the backend while the manager is Off, or under an older
policy, are retained as observation evidence whose policy revision is provenance,
not execution permission. Automatic reviews still require the current recommend
policy with its allowed-rule, cooldown, episode and limit fences. A manual review
may instead consume the optional backend `findingEvidence` snapshot for a finding
whose local batch record no longer exists, validated against the manifest
id/revision/rule/native session and its bounded shape; retention or the snapshot
alone never authorizes a review without the fresh current policy, source, target
and capability fences.

Protective Pause and Resume hold operations recover by exact persisted operation
identity. Restart or lost-response recovery observes the same operation with
`reconcile_intervention_hold`, including after the 120-second effect lease
expires, and never replays an acquire or release. Acquisition and release unknown
phases are preserved across read failures; a fresh observation never authorizes a
new release or prompt, and a settled Resume keeps its local `released` phase with
a canonical `ready` report.

Protocol compatibility: the managed control protocol is planned to be required by
the backend at admission from Runtime 0.1.31 or newer. The paired backend compatibility gate must deliver only the legacy seven-field
manifest shape to nodes on the older strict 0.1.30 decoder; that gate is still
pending. A signed 0.1.31 candidate remains qualification-pending; this
section does not claim a released, deployed or live-verified state.
