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

Ubuntu's restricted-unprivileged-userns control is never disabled for Runtime.
When that AppArmor control is active, the signed installer requires the host's
existing parser and transactionally installs one Runtime-owned policy. The
policy attaches setup permission only to the immutable, root-owned Codex
Bubblewrap path in the signed sandbox image; it does not attach to the distro
Bubblewrap path or a workspace executable. Bubblewrap's target and all later
descendants are stacked with a profile that audits and denies capabilities, so
the setup permission cannot be reused by the model process or a nested helper.
The policy is based on AppArmor's upstream restricted-Bubblewrap setup/child
split: <https://gitlab.com/apparmor/apparmor/-/blob/8e431ebcd915216a03ebc8d01e72b1741bb2f855/profiles/apparmor/profiles/extras/bwrap-userns-restrict>.

Policy installation never changes a sysctl, installs/replaces AppArmor
packages, invokes the AppArmor service, or alters Podman container-create
arguments. Candidate syntax is checked before replacement; an existing policy
is checked and backed up first; only the exact Runtime file is loaded. Any later
installer failure restores the previous file and kernel policy, or unloads a
new first-install policy. A rollback failure is reported separately and must be
reviewed rather than worked around by relaxing host policy. Runtime snapshots
both policy names independently, rejects partial or disk/kernel-conflicting
states, unloads candidate definitions before restoration, and restores whether
the prior policy was loaded or unloaded in enforce mode. Backup and restore use
GNU `cp --preserve=all` and fail closed if ownership, mode, ACL, or extended
attribute preservation is unsupported. A signed static comparator verifies the
source and copy byte content, UID/GID, raw mode, nanosecond atime/mtime, and the
complete xattr map after backup, before restored-file publication, and after
publication. It therefore detects preservation warnings that GNU `cp` may not
return as failures. Because `apparmor_parser` reads a restored policy, Runtime
reapplies the backup's reference timestamps after loading it and performs its
final comparison with `O_NOATIME`; timestamp restoration failure is fail-closed.
Failed comparison/unload/removal recovery retains the root-only installer state
and backup for operator diagnosis.

Sandbox image refresh is a separate authenticated control-plane action. The
runtime accepts only an immutable registry digest paired with a sandbox
generation advance; changing the global default does not refresh existing
sandboxes. It pulls the target before stopping the old container and never
deletes or remounts the external workspace. A deterministic backup container is
kept until the target reaches the requested running or stopped state. Failure
restores the old container when possible, and an incomplete rollback is
reported as a distinct fail-closed condition for operator review.
