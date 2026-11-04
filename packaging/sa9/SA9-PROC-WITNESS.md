# SA9 childless-procfs witness — Podman `precreate` config hook

Status: **Runtime lifecycle/hook mechanism implemented and unit-proven.** The
live all-oracles-together run on the built Linux candidate remains `not_run`
(it requires the pinned Podman/crun host and the live sandbox).

## Why

A formatVersion 2 cell worker keeps its own PID namespace with its own procfs.
A fresh `mount("proc", ...)` inside the worker's nested bubblewrap jail is
refused by the kernel (`mount_too_revealing` / `mnt_already_visible`) because
the container's `/proc` carries inherited `MNT_LOCKED` submounts. The reviewed
resolution is to have the OCI runtime mount a fixed **childless** procfs witness
at container creation, **before** crun drops to UID 1000 with an empty
capability set, at a destination outside every worker bind source.

## Exact OCI mount

```json
{
  "destination": "/warpmetal-proc-witness",
  "type": "proc",
  "source": "proc",
  "options": ["rw", "nosuid", "nodev", "noexec", "relatime"]
}
```

Appended by the hook to the container OCI config only when the container carries
the allowlisted annotation
`io.warpmetal.cell.lifecycle=sa9-proc-witness-v1`.

## Mechanism

- A cell sandbox is created with the explicit `--hooks-dir` persistent flag and
  the exact allowlisted annotation (`internal/containers/podman.go`,
  `createArgumentsWithLifecycle`). Legacy Team/member sandboxes are
  byte-for-byte unchanged (no `--hooks-dir`, no `--annotation`).
- The LOCAL `podman create` is a fresh process per create, so it runs the
  `precreate` hook from that `--hooks-dir` and injects the witness mount into
  the container's OCI config at creation — this covers new cell containers
  created after installation.
- The delegated Podman SERVICE is also started with the same trusted flag
  `--hooks-dir /usr/libexec/warpmetal-agent-runtime/hooks` (in
  `packaging/systemd/warpmetal-podman-service`). The service re-runs `generateSpec`
  (and therefore the `precreate` hook) when it re-initializes a container on
  `restart` or `start`-after-`stop`, so the service process needs the hook
  directory too; a create-time `--hooks-dir` is not persisted across that
  remote-service re-init.
- **Upgrade adoption (important):** the running service reads `--hooks-dir` at
  its own startup. Writing the new wrapper/flag to disk does not change a live
  service. A service started before the SA9 hook was installed adopts the
  trusted directory only on its next start — a safe service restart (drain then
  restart, preserving the delegated cgroup's running containers). This is a
  one-time adoption step for the upgrade that introduces the hook; the live
  candidate run must prove the running service actually executes the hook.
- Podman loads the `precreate` hook from that directory and runs it only when
  the container's `--annotation io.warpmetal.cell.lifecycle=sa9-proc-witness-v1`
  matches the hook config `when.annotations` allowlist.
- The hook receives the proposed OCI config as JSON on stdin and writes the
  modified config on stdout. It appends exactly one witness mount, is
  idempotent, passes non-allowlisted containers through byte-exact, and exits
  non-zero (fail-closed) on malformed input.
- `Podman.verifyCellLifecycle` refuses a cell launch unless the hook storage is
  immutable/allowlisted and the pinned Podman (`>= 4.9.3`) and crun
  (`>= 1.14.1`) support `precreate` + `--hooks-dir`. There is no silent
  no-witness fallback.
- `Podman.ObserveCellWitness` is the **only** source of observed cell readiness:
  it verifies the running container's current mount namespace actually carries
  a childless procfs witness (never the desired cell flag, hook-file presence,
  or a create request), and the reconciler persists and reports it as
  `SandboxReport.CellReady`. A missing/replaced/childed witness fails closed
  (not ready), so the backend launch gate stays refused. This observation proves
  PREREQUISITE witness availability, NOT worker private-proc isolation (that is
  the live gate's oracle).

## Files and digests

| File | sha256 |
| --- | --- |
| `sa9-precreate-hook.py` | `e92fe25ca79d69378622f0b8e8d24bf24f80a557290c28c64edee0e86ef2cd6d` |
| `sa9-precreate-hook.json` | `cf6f8adaf30845281815260e28a38a7d075f19af83b5535a3e3c831a01670bf6` |

The hook config pins `hook.path` to
`/usr/libexec/warpmetal-agent-runtime/hooks/sa9-precreate-hook.py`.

## Install layout and permissions

```
/usr/libexec/warpmetal-agent-runtime/hooks/          root:root 0755 (not group/world writable)
/usr/libexec/warpmetal-agent-runtime/hooks/sa9-precreate-hook.py    root:root 0555
/usr/libexec/warpmetal-agent-runtime/hooks/sa9-precreate-hook.json  root:root 0444
```

The storage is root/control-owned and immutable; the rootless Podman runtime
user only reads it. It is a host path, never a container bind, so the
container/worker cannot write or read it. `verifyCellHookStorage` enforces the
non-writable/regular-file/allowlisted-config properties (and root ownership
when the runtime runs as root) before any cell launch.

The Runtime installer (`packaging/install/install.sh`) ships both hook files
from the signed release bundle with a complete-install preflight: it pins the
sha256 of each file (version-bound bytes, refused on mismatch), requires a
usable `/usr/bin/python3`, parses the hook, smoke-runs it to prove the witness
mount is emitted, and only then installs into the protected directory. The hook
directory is installed before the delegated Podman service starts.

Install (root, via the signed installer):

```sh
install -d -m 0755 /usr/libexec/warpmetal-agent-runtime/hooks
install -m 0555 sa9-precreate-hook.py /usr/libexec/warpmetal-agent-runtime/hooks/sa9-precreate-hook.py
install -m 0444 sa9-precreate-hook.json /usr/libexec/warpmetal-agent-runtime/hooks/sa9-precreate-hook.json
```

## Verification

- Go unit tests: `internal/containers/cell_witness_test.go` executes the real
  packaged hook and proves the exact mount, allowlist passthrough, idempotency,
  invalid-input rejection, legacy create-args byte-identity, cell gating,
  fail-closed capability negotiation, and hook-storage permissions.
- `not_run`: live all-oracles-together validation on the pinned Linux candidate.
