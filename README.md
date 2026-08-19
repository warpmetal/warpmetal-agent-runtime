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
`apt` or `dnf` packages and installs the distribution `runc` package. Workspace
mounts receive a private Podman SELinux label on enforcing hosts. On Ubuntu it
installs the supported generic kernel; if a reboot is pending, it exits with
status 75 and `runtime_reboot_required` before consuming the bootstrap token.
Reboot the server and retry the same verified installer.
Upgrading from the preview's former user-manager layout resets only the
dedicated Podman container/image metadata; desired sandboxes are recreated and
their separately mounted workspace data is preserved.

The fixed userspace image is maintained separately in
[`warpmetal/warpmetal-agent-sandbox`](https://github.com/warpmetal/warpmetal-agent-sandbox).
That repository publishes `ghcr.io/warpmetal/warpmetal-agent-sandbox` for
`linux/amd64` and `linux/arm64` with SBOM, provenance, and a keyless signature.
Production must use the complete registry digest emitted by that workflow, and
the package must permit unauthenticated pulls from customer servers. A new
default digest applies only to newly created sandboxes; existing sandboxes
remain pinned to their creation image.
