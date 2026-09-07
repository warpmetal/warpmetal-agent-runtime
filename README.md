# WarpMetal Agent Runtime

`warpmetald` is the optional, outbound-only supervisor installed on a customer's
server by the official `warpmetal runtime install` command. It reconciles the
server-scoped manifest, runs fixed-image rootless Podman sandboxes, enforces
resource and ext4 workspace limits, expires temporary workspaces locally, and
renders the forced-command SSH access map.

This repository is the canonical public source for the supervisor, installer,
systemd unit, and restricted SSH gateway. The WarpMetal control plane and
billing system are separate: this runtime manages only the sandboxes belonging
to the owner of one server.

Security boundaries:

- The node token is root-only, stored outside every sandbox, and authorizes only
  manifest reads and runtime reports.
- Sandboxes are non-privileged, read-only-root containers without host sockets,
  host namespaces, published ports, capabilities, or host credentials.
- Host output rules tied to the dedicated runtime UID reject IPv4 and IPv6
  link-local metadata endpoints before any sandbox starts.
- Each agent public key is forced through the locked `warpmetal-sandbox` account
  and an opaque grant ID. The restricted shell cannot start a host shell.
- Stop, revocation, expiration, and deletion cancel matching gateway sessions.
- Temporary expiry uses the local SQLite clock state and continues during a
  control-plane outage.
- Workspace images live outside the root-only supervisor state directory. The
  runtime user's subordinate UID/GID ranges and a dedicated, delegated Podman
  service keep container lifecycle operations rootless after reboot. Its Unix
  socket is mode `0600` inside a runtime-user-owned `0700` directory.
- The root supervisor performs ext4 mount operations through PID 1's host mount
  namespace so the separate rootless engine sees only the intended workspace
  mounts; the rest of the supervisor stays inside its hardened mount namespace.
- On amd64 hosts that actively enforce AppArmor's
  restricted-unprivileged-userns control, an explicit signed-installer option
  can load a narrowly attached policy for the exact root-owned Codex Bubblewrap
  helper in the signed coding image. The setup profile permits Bubblewrap to
  construct an inner user/PID namespace and new procfs, then stacks every child
  executable with a capability-denying profile. The capability is off by
  default, does not apply to `/usr/bin/bwrap`, workspace binaries, or generic
  `unshare`, and does not change sandbox container-create arguments.

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
Promote the existing release only after the signed asset passes the provider
canary and rollback gates; never rebuild or replace an asset during promotion.
Backend activation must use the tested asset URL, checksum, signature, and
version.

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

The archive also contains the amd64 coding-host AppArmor policy, its
transactional installer helper, and `nested-private-procfs-oracle.sh`. Runtime
continues to publish arm64 supervisor archives, but explicit capability enable
fails closed there because the current signed coding image and exact helper path
are amd64-only. The oracle is credential-free: inside the matching signed
sandbox image it verifies the helper ownership,
creates its own short-lived outer sentinel, mounts a new procfs in a new PID
namespace, checks that the inner process is PID 1, checks a descendant's
`/proc/self`, and confirms the outer sentinel is absent. It clears the inherited
environment before starting the inner process. Passing this userspace oracle is
not by itself a production promotion: the guarded provider canary must also
prove generic user namespaces remain restricted and all host workload
invariants remain unchanged.

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
`--allowerasing`. Both paths preserve the exact versions of an installed
known Docker/containerd/Podman and package-manager components and verify that
stack after the package action. Package apply failures run the same package and
workload postconditions before returning. The workload snapshot is checked
again immediately before registration. Package-plan conflicts, uninspectable
Docker state, or workload drift fail closed with a stable `runtime_*` error
before the supervisor is registered. Docker receives container-level checks;
other recognized engines receive process-level checks and require separate
certification before WarpMetal claims container-level coexistence.

On an upgrade, an already-active private WarpMetal Podman service is preserved
instead of restarted. This keeps persistent Agent Runtime sandboxes and their
delegated cgroups running while the supervisor binaries are replaced. A fresh
install, or an inactive service, is still started before registration.

Ordinary installs and upgrades use
`--nested-private-procfs preserve` by default. Preserve mode does not inspect,
parse, load, unload, create, replace, or remove the Runtime AppArmor policy.
Dedicated amd64 coding hosts may explicitly use
`--nested-private-procfs enable`; other architectures fail closed. Explicit
`--nested-private-procfs disable` unloads/removes the Runtime policy and restores
the exact file and loaded/unloaded state that preceded its first enable. These
are host-scoped operations, not per-user or per-sandbox grants: after enable,
every same-owner sandbox on that Runtime host containing the trusted exact
helper path can invoke it. The authenticated backend remains the trusted
immutable-image selection boundary; AppArmor pathname attachment does not
verify an image digest.

On an AppArmor-enabled host where
`kernel.apparmor_restrict_unprivileged_userns=1`, explicit enable requires the
host's existing `apparmor_parser`. Runtime does not install an AppArmor package,
change that sysctl, reload/restart the AppArmor service, or restart Podman. It
parses the signed candidate first, atomically replaces only
`/etc/apparmor.d/warpmetal-agent-runtime-bwrap`, and loads only that file. A
root-only durable baseline under `/var/lib/warpmetal/apparmor-policy-state`
retains the exact pre-enable file and loaded state until disable. Each mutating
operation first writes and syncs an atomic transaction snapshot there; ordinary
installer failure restores it through the EXIT trap, and the next explicit
enable/disable recovers a transaction left by interruption before applying a
new operation. A completed enable or disable is committed only after Runtime
registration and service restart succeed.

Disk/kernel mismatches and partial profile loads, including non-enforce modes,
fail closed. The signed Linux metadata helper copies through
`O_NOATIME|O_NOFOLLOW`, rejects nonregular or pre-existing targets, clears
inherited attributes, and reapplies ownership, every xattr, raw mode, and
nanosecond timestamps in a fail-closed order. It verifies source stability plus
exact content, UID/GID, raw mode, timestamps, and xattr identity on both backup
and restoration, including POSIX ACL and SELinux context xattrs. Copy or
comparison failure preserves durable recovery evidence. If parser reads advance
a restored file's atime, the installer reapplies the baseline timestamps before
its final non-atime-mutating comparison. Unsupported, conflicting, parse, load,
architecture, and recovery conditions use distinct safe `runtime_*` errors.
The capability remains unproven for a release until the Ubuntu 24.04 live
acceptance oracle passes.

Workspace mounts receive a private Podman SELinux label on enforcing hosts.
The ordinary installer does not install or replace a kernel. If a reboot is
already pending, it exits with status 75 and `runtime_reboot_required` before
updating package indexes or consuming the bootstrap token. Reboot only as a
separately authorized maintenance action, then retry the same verified
installer.

The ordinary installer also never runs `podman system reset`. A preview install
whose Podman state still points at the former user-manager run root exits with
`runtime_legacy_migration_required`; preserve that host and use a separately
reviewed migration procedure instead of deleting container metadata implicitly.

The fixed userspace image is maintained separately in
[`warpmetal/warpmetal-agent-sandbox`](https://github.com/warpmetal/warpmetal-agent-sandbox).
That repository publishes `ghcr.io/warpmetal/warpmetal-agent-sandbox` for
`linux/amd64` and `linux/arm64` with SBOM, provenance, and a keyless signature.
Production must use the complete registry digest emitted by that workflow, and
the package must permit unauthenticated pulls from customer servers. A new
default digest applies only to newly created sandboxes; existing sandboxes
remain pinned to their creation image.

An existing sandbox changes images only when its authenticated manifest names
an explicit immutable per-sandbox digest and advances that sandbox's
generation. The runtime pulls the target before interruption, terminates active
gateway sessions, and replaces only the container root filesystem. The external
`/home/agent` workspace, sandbox identity, lifetime, and original start time are
preserved. Running sandboxes return to running and stopped sandboxes remain
stopped. The old container is retained under a deterministic backup name until
the replacement reaches its desired state, allowing a failed or interrupted
refresh to roll back or resume safely. A refresh therefore causes a brief
connection interruption but is not a workspace migration or deletion.
