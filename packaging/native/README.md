# Native OpenCode package (WarpMetal atomic-input build)

This directory owns the reproducible public build of the WarpMetal-patched
OpenCode binary used by automatic steering. It is **not** an OpenCode release
and never uses upstream/npm identities.

- Upstream source: official OpenCode `08462140ec0de1e4b17d4a353d8d5827f53cf7b0`
  (tree `9572aed1d292ca13d50e917d794bb0656db51efc`), fetched by CI into an
  isolated `RUNNER_TEMP/upstream` checkout from
  `https://github.com/anomalyco/opencode.git`
- Toolchain: Bun `1.4.2`, frozen lockfile, `--ignore-scripts` install; the CLI
  build runs with `--skip-install` and the pinned Bun directory is prepended to
  `PATH` so generator/build children resolve the same Bun
- Custom version: `2.0.14-wm.1` (`OPENCODE_CHANNEL=latest`,
  `--target=opencode-linux-x64`)
- Archive: `package/bin/opencode` npm layout (the existing approved
  `archive-binary` profile decoder accepts this member) plus `package.json`,
  `LICENSE` and `warpmetal-native-manifest.json`
- Public release: tag `opencode-v2.0.14-wm.1` in this Runtime repository,
  independent from every existing `v*` Runtime release, never `--latest`, and
  never published to npm or any official upstream repository

## Files

- `upstream.lock.json` — closed lock. It is intentionally `incomplete` and its
  `patch.digest` is `null` until the root seal step. `build.sh` refuses every
  subcommand while the lock is incomplete or the digest does not match the
  patch bytes.
- `warpmetal-atomic-input-v1.patch` — **owned by the root seal step**, not by
  this tooling. Root writes the single canonical `git diff --binary` against
  the exact upstream revision, then sets `patch.status` to `complete` and
  `patch.digest` to `sha256:<64 hex>` of those exact bytes. The patch never
  embeds its own digest.
- `build.sh` — `verify` and `build` subcommands. The official source checkout is
  never modified: the script makes a local clone inside the disposable output
  directory, applies the patch there, creates an ephemeral local-only baseline
  commit with a fixed fixture identity/time (hooks disabled, gpgsign off, parent
  asserted equal to the official revision) so upstream `check:generated`
  generate-then-diff can pass against the intentional patched state, then runs
  the frozen install, generated-client and migration checks, optionally the
  affected test files (`--tests`: core prompt+runner via the normal
  `packages/core` test script, server guard fixture, schema event manifest),
  builds the exact target, stages the archive with deterministic metadata
  (`tar --sort=name --mtime=@0`, owner/group 0, `gzip -n`), writes checksums,
  emits the bare SLSA v0.2 provenance predicate (top-level
  builder/buildType/invocation/materials/metadata, with artifact and binary
  SHA256 in `invocation.parameters`; cosign 2.5.3 wraps it into the signed
  in-toto statement with the archive subject), and runs the smoke assertions
  (exact `--version`; with `--smoke`, `smoke.py` starts the server with an
  isolated home/XDG tree and verifies the real authenticated guard API).
  The ephemeral baseline commit is never pushed and is never presented as
  official upstream source; the manifest/provenance record both the official
  revision/tree and the local baseline commit.
- `smoke.py` — authenticated Linux x64 smoke helper. Uses a fresh fixture
  nonce, a mode-0600 curl config for Basic auth, a child environment
  constructed from scratch (no inherited provider credentials) and
  `OPENCODE_DISABLE_MODELS_FETCH=1`. Asserts anonymous guard access is 401 and
  the authorized guard GET matches the exact contract141 snapshot for a fresh
  inactive session. No credential is printed and the config is removed.
- `.github/workflows/native-build.yml` — every job fetches the exact upstream
  revision; PRs run lock closure, build, generation checks, affected tests and
  smoke; the exact custom tag publishes from main ancestry with the same route
  plus smoke, checksums, keyless cosign OIDC `sign-blob` bundle and
  `attest-blob` SLSA provenance, then `gh release create --verify-tag
  --latest=false`.

## Root seal and build sequence

```sh
# 1. Root writes the canonical patch and seals the lock.
sha256sum packaging/native/warpmetal-atomic-input-v1.patch
# set patch.status = "complete" and patch.digest = the exact sv hash

# 2. Local reproduction (isolated official checkout + disposable output).
sh -n packaging/native/build.sh
python3 -m py_compile packaging/native/smoke.py
git init /tmp/opencode-08462140 && git -C /tmp/opencode-08462140 remote add origin https://github.com/anomalyco/opencode.git
git -C /tmp/opencode-08462140 fetch --depth=1 origin 08462140ec0de1e4b17d4a353d8d5827f53cf7b0
git -C /tmp/opencode-08462140 checkout --detach FETCH_HEAD
packaging/native/build.sh verify \
  --lock packaging/native/upstream.lock.json \
  --source /tmp/opencode-08462140 \
  --patch packaging/native/warpmetal-atomic-input-v1.patch
packaging/native/build.sh build \
  --lock packaging/native/upstream.lock.json \
  --source /tmp/opencode-08462140 \
  --patch packaging/native/warpmetal-atomic-input-v1.patch \
  --out /tmp/native-package --bun /path/to/bun-1.4.2 --tests --smoke

# 3. Publish only through the tag workflow on main ancestry.
git tag opencode-v2.0.14-wm.1 <main-ancestor-commit>
git push origin opencode-v2.0.14-wm.1
```

The workflow asserts the exact tag, main ancestry, and custom identity before
building; it never touches `v*` Runtime releases, npm, or official upstream
repositories, and it requires no private credentials. The Runtime and sandbox
images stay separately signed and are not modified here.

## Fail-closed rules

- Missing/invalid `patch.digest`, `status != "complete"`, a digest mismatch, a
  dirty or mismatched official source checkout, a wrong Bun version, a
  generator diff, or a failed smoke assertion aborts the run.
- No placeholder, environment variable or source default may enable a build or
  a publication before the root seal.
- The archive never contains its own digest; checksums and the bare SLSA
  predicate are produced after the archive bytes are final, and the predicate
  contains no absolute private output path and no `reproducible: true`.
