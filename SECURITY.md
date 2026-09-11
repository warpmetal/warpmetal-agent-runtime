# Security policy

Please do not disclose suspected vulnerabilities in a public issue.

Report them through this repository's private vulnerability reporting flow:

https://github.com/warpmetal/warpmetal-agent-runtime/security/advisories/new

Include the affected release, host operating system, expected impact, and a
minimal reproduction when possible. Do not include live credentials, private
keys, node tokens, provider tokens, or customer data.

Only the latest release receives security fixes during the V1 preview.

## Runtime boundary

The root supervisor never exposes the Podman API outside the host. Container
lifecycle operations are delegated to a service running as the locked
`warpmetal-runtime` account. Its Unix socket is reachable only by that account
and root, and the service receives only its own cgroup subtree. Sandbox access
uses forced SSH commands and never grants access to this socket.

The outer rootless Podman container is the Runtime boundary.
Sandbox processes run as UID/GID 1000 with a read-only root.
`/home/agent` is the persistent workspace.
No host container runtime socket is exposed.
Runtime does not install, configure, or authenticate user tools; each user owns
their installation, configuration, authentication, updates, and removal.

The container also drops capabilities, sets no-new-privileges, applies the
default seccomp policy, isolates networking, and enforces resource limits. User
tools and provider credentials remain subject to that boundary. A compromised
program can access the sandbox home, network, and user-owned credentials made
available to other processes in the same sandbox.

The node credential remains root-only and outside sandbox mounts. Desired state
contains lifecycle and capacity intent, not executable commands, package
sources, login input, or provider credentials. Runtime reports sandbox state,
generation, image identity, timestamps, errors, host keys, and grants; it does
not probe installed user software or return its output.

## Installer and upgrades

The signed host installer treats an existing container stack as protected
state. It selects `crun` for WarpMetal rather than requesting a conflicting
distro `runc`, refuses package removals and protected runtime changes, and
compares a minimal root-only liveness snapshot before registration and after
the guarded package action. It rechecks immediately before the registration
commit boundary and never reports workload drift after activation has begun.
It never reads container configuration or logs and never attempts to repair,
restart, or replace a third-party runtime. Docker receives container-level
checks; other recognized engines receive process-level checks. Legacy
WarpMetal Podman state that would require a reset is refused for separate
operator review.

The installer also treats existing persistent WarpMetal sandboxes as protected
upgrade state. It starts the private Podman service when needed but does not
restart an already-active service, avoiding a systemd cgroup teardown of live
sandboxes during a supervisor upgrade. It does not change host user-namespace
policy or install a host policy for software running inside a sandbox.

Signed v0.1.25 and v0.1.26 archives are immutable historical artifacts and are
not rebuilt or edited by future source changes. Operators should install only
the exact verified release selected by the authenticated control plane.

## Persistence and image replacement

Sandbox image refresh is a separate authenticated control-plane action. The
runtime accepts only an immutable registry digest paired with a sandbox
generation advance; changing the global default does not refresh existing
sandboxes. It pulls the target before stopping the old container and never
deletes or remounts the external workspace. A deterministic backup container is
kept until the target reaches the requested running or stopped state. Failure
restores the old container when possible, and an incomplete rollback is
reported as a distinct fail-closed condition for operator review.

Databases created by earlier releases may contain retired columns. Future
Runtime reads and writes only the active lifecycle schema and leaves those
columns untouched. This compatibility behavior avoids silently changing an
existing sandbox's image, workspace, generation, or historical data.

User-installed executables, configuration, and provider credentials belong
beneath `/home/agent` and remain the owner's responsibility.
They must not be copied into release bundles, desired state, host installer
arguments, or Runtime logs and reports.
