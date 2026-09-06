# Security policy

Please do not disclose suspected vulnerabilities in a public issue.

Report them through this repository's private vulnerability reporting flow:

https://github.com/warpmetal/warpmetal-agent-runtime/security/advisories/new

Include the affected release, host operating system, expected impact, and a
minimal reproduction when possible. Do not include live credentials, private
keys, node tokens, or customer data.

Only the latest release receives security fixes during the V1 preview.

The root supervisor never exposes the Podman API outside the host. Container
lifecycle operations are delegated to a service running as the locked
`warpmetal-runtime` account. Its Unix socket is reachable only by that account
and root, and the service receives only its own cgroup subtree. Sandbox access
continues to use forced SSH commands and never grants access to this socket.

The signed host installer treats an existing container stack as protected
state. It selects `crun` for WarpMetal rather than requesting a conflicting
distro `runc`, refuses package removals and protected runtime changes, and
compares a minimal root-only liveness snapshot before registration and after
the guarded package action. It rechecks immediately before the registration
commit boundary and never reports workload drift after activation has begun. It
never reads container configuration or logs and never attempts to repair,
restart, or replace a third-party runtime. Docker receives container-level
checks; other recognized engines receive process-level checks. Legacy
WarpMetal Podman state that would require a reset is refused for separate
operator review.

The installer also treats existing persistent WarpMetal sandboxes as protected
upgrade state. It starts the private Podman service when needed but does not
restart an already-active service, avoiding a systemd cgroup teardown of live
sandboxes during a supervisor upgrade.

Sandbox image refresh is a separate authenticated control-plane action. The
runtime accepts only an immutable registry digest paired with a sandbox
generation advance; changing the global default does not refresh existing
sandboxes. It pulls the target before stopping the old container and never
deletes or remounts the external workspace. A deterministic backup container is
kept until the target reaches the requested running or stopped state. Failure
restores the old container when possible, and an incomplete rollback is
reported as a distinct fail-closed condition for operator review.

CLI onboarding selection does not expand the supervisor command surface. The
runtime invokes only the fixed image-owned
`/usr/local/bin/warpmetal-agent-tool-report`, bounds and strictly validates its
JSON, and reports only allowlisted selected tool IDs. It never accepts an
executable, version command, package source, login input, or credential from
desired state. Invalid reporter output is replaced with generic per-tool
failures and cannot change an otherwise-running sandbox lifecycle state.
