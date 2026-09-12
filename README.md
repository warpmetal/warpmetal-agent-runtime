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

The outer rootless Podman container is the Runtime boundary.
Sandbox processes run as UID/GID 1000 with a read-only root.
`/home/agent` is the persistent workspace.
No host container runtime socket is exposed.
Runtime does not install, configure, authenticate, inspect, update, or remove
user tools; each user owns their installation, configuration, authentication,
updates, and removal. User tools inherit the sandbox's existing capability,
seccomp, network, cgroup, and host-socket restrictions. Provider credentials
remain user-owned files or process environment inside the workspace and must
never be sent through desired state, registration, or runtime reports.

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

The installer never changes host user-namespace policy, runs `podman system
reset`, or restarts a third-party container runtime. A preview install whose
Podman state still points at the former user-manager run root exits with
`runtime_legacy_migration_required`; preserve that host and use a separately
reviewed migration procedure rather than deleting container metadata.

Signed v0.1.25 and v0.1.26 archives are immutable historical releases. Their
existing signed members remain unchanged; the reduced bundle contract applies
only to future releases.

## Sandbox images and persistence

The base userspace image is maintained separately in
[`warpmetal/warpmetal-agent-sandbox`](https://github.com/warpmetal/warpmetal-agent-sandbox).
Production must use the complete registry digest emitted by that repository's
signed workflow, and the package must permit unauthenticated pulls from
customer servers. A new default digest applies only to newly created sandboxes;
existing sandboxes remain pinned to their creation image.

An existing sandbox changes images only when its authenticated manifest names
an explicit immutable per-sandbox digest and advances that sandbox's
generation. The runtime pulls the target before interruption, terminates active
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
