#!/bin/sh
# WarpMetal native OpenCode packaging build (revision 146 corrections).
#
# Interface:
#   build.sh verify --lock <lock.json> --source <official-checkout> --patch <patch-file>
#   build.sh build  --lock <lock.json> --source <official-checkout> --patch <patch-file> \
#                   --out <disposable-dir> [--bun <bun-binary>] [--tests] [--smoke]
#
# --source must be an isolated checkout of the exact official upstream revision
# (CI fetches https://github.com/anomalyco/opencode.git at 08462140... into
# RUNNER_TEMP/upstream); it is never the Runtime repository checkout.
#
# The lock is fail-closed: until the root seal step fills the canonical patch
# digest and sets patch.status to "complete", every subcommand refuses. No
# placeholder can enable an artifact or a publication. The patch is written by
# the root seal owner, never by this tooling.
set -eu

TZ=UTC
export TZ

COMMAND=${1:-}
if [ -z "$COMMAND" ]; then
  echo "native-build: command required: verify|build" >&2
  exit 2
fi
case "$COMMAND" in
  verify|build) ;;
  -h|--help)
    sed -n '2,16p' "$0"
    exit 0
    ;;
  *)
    echo "native-build: unknown command: $COMMAND" >&2
    exit 2
    ;;
esac
shift

LOCK=
SOURCE=
PATCH=
OUT=
BUN=
SMOKE=0
RUN_TESTS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --lock) [ $# -ge 2 ] || { echo "native-build: --lock needs a value" >&2; exit 2; }; LOCK=$2; shift 2 ;;
    --source) [ $# -ge 2 ] || { echo "native-build: --source needs a value" >&2; exit 2; }; SOURCE=$2; shift 2 ;;
    --patch) [ $# -ge 2 ] || { echo "native-build: --patch needs a value" >&2; exit 2; }; PATCH=$2; shift 2 ;;
    --out) [ $# -ge 2 ] || { echo "native-build: --out needs a value" >&2; exit 2; }; OUT=$2; shift 2 ;;
    --bun) [ $# -ge 2 ] || { echo "native-build: --bun needs a value" >&2; exit 2; }; BUN=$2; shift 2 ;;
    --tests) RUN_TESTS=1; shift ;;
    --smoke) SMOKE=1; shift ;;
    *) echo "native-build: unknown argument: $1" >&2; exit 2 ;;
  esac
done

fail() {
  printf 'native-build: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command missing: $1"
}

canonical_dir() {
  ( cd "$1" 2>/dev/null && pwd -P ) || fail "path does not exist: $1"
}

SCRIPT_DIR=$(canonical_dir "$(dirname "$0")")

[ -n "$LOCK" ] || fail "--lock is required"
[ -n "$SOURCE" ] || fail "--source is required"
[ -n "$PATCH" ] || fail "--patch is required"
[ -f "$LOCK" ] || fail "lock file missing: $LOCK"
[ -d "$SOURCE" ] || fail "source checkout missing: $SOURCE"
[ -f "$PATCH" ] || fail "patch file missing: $PATCH"
need_cmd python3

SOURCE_ABS=$(canonical_dir "$SOURCE")
LOCK_ABS=$(canonical_dir "$(dirname "$LOCK")")/$(basename "$LOCK")
PATCH_ABS=$(canonical_dir "$(dirname "$PATCH")")/$(basename "$PATCH")

# Validate the closed lock shape and fail closed while the root seal is absent.
LOCK_VALUES=$(python3 - "$LOCK_ABS" "$PATCH_ABS" <<'PY'
import hashlib
import json
import re
import sys

lock_path, patch_path = sys.argv[1], sys.argv[2]
with open(lock_path, "rb") as handle:
    data = json.load(handle)
if data.get("formatVersion") != 1:
    sys.exit("lock formatVersion must be 1")
source = data["source"]
toolchain = data["toolchain"]
patch = data["patch"]
build = data["build"]
archive = data["archive"]
release = data["release"]
if not re.fullmatch(r"[0-9a-f]{40}", source["revision"]):
    sys.exit("lock source.revision must be a 40-hex commit")
if not re.fullmatch(r"[0-9a-f]{40}", source["tree"]):
    sys.exit("lock source.tree must be a 40-hex tree")
if toolchain.get("bun") != "1.4.2":
    sys.exit("lock toolchain.bun must be 1.4.2")
if toolchain.get("install") != "frozen-lockfile-ignore-scripts":
    sys.exit("lock toolchain.install must be frozen-lockfile-ignore-scripts")
if patch.get("file") != "warpmetal-atomic-input-v1.patch":
    sys.exit("lock patch.file must be warpmetal-atomic-input-v1.patch")
if patch.get("status") != "complete":
    sys.exit("patch_lock_incomplete: root must seal the canonical patch digest before build")
digest = patch.get("digest")
if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    sys.exit("patch_digest_missing_or_invalid")
try:
    with open(patch_path, "rb") as handle:
        actual = "sha256:" + hashlib.sha256(handle.read()).hexdigest()
except OSError as error:
    sys.exit("patch_file_unreadable: %s" % error)
if actual != digest:
    sys.exit("patch_digest_mismatch: root-sealed digest does not match the patch file")
if build.get("target") != "opencode-linux-x64":
    sys.exit("lock build.target must be opencode-linux-x64")
if build.get("version") != "2.0.14-wm.1":
    sys.exit("lock build.version must be 2.0.14-wm.1")
if build.get("channel") != "latest":
    sys.exit("lock build.channel must be latest")
if build.get("bunCompileRelease") != "bun-v1.4.2":
    sys.exit("lock build.bunCompileRelease must be bun-v1.4.2")
if archive.get("member") != "package/bin/opencode":
    sys.exit("lock archive.member must be package/bin/opencode")
if archive.get("name") != "opencode-cli-linux-x64-2.0.14-wm.1.tgz":
    sys.exit("lock archive.name must be opencode-cli-linux-x64-2.0.14-wm.1.tgz")
if release.get("tag") != "opencode-v2.0.14-wm.1":
    sys.exit("lock release.tag must be opencode-v2.0.14-wm.1")
if release.get("repository") != "warpmetal/warpmetal-agent-runtime":
    sys.exit("lock release.repository must be warpmetal/warpmetal-agent-runtime")
print("\t".join([
    source["revision"], source["tree"], digest, build["version"],
    build["target"], build["bunCompileRelease"], archive["name"], release["tag"],
]))
PY
) || fail "lock verification failed"

IFS="$(printf '\t')"
read -r REVISION TREE DIGEST VERSION TARGET BUN_RELEASE ARCHIVE TAG <<EOF
$LOCK_VALUES
EOF

# Official upstream closure: the source must be a git checkout of the exact
# revision/tree, clean, and the patch must apply before any build.
if [ -d "$SOURCE_ABS/.git" ]; then
  need_cmd git
  HEAD_REV=$(git -C "$SOURCE_ABS" rev-parse HEAD)
  HEAD_TREE=$(git -C "$SOURCE_ABS" rev-parse 'HEAD^{tree}')
  [ "$HEAD_REV" = "$REVISION" ] || fail "source_revision_mismatch: $HEAD_REV != $REVISION"
  [ "$HEAD_TREE" = "$TREE" ] || fail "source_tree_mismatch: $HEAD_TREE != $TREE"
  [ -z "$(git -C "$SOURCE_ABS" status --porcelain)" ] || fail "source_checkout_dirty: refuse to build from a modified checkout"
  git -C "$SOURCE_ABS" apply --binary --check "$PATCH_ABS" || fail "patch_does_not_apply_to_source"
else
  fail "source_checkout_not_git: exact revision/tree closure requires a git checkout"
fi

if [ "$COMMAND" = "verify" ]; then
  printf 'native-build: verify ok revision=%s tree=%s digest=%s\n' "$REVISION" "$TREE" "$DIGEST"
  exit 0
fi

# build
[ -n "$OUT" ] || fail "--out is required for build"
case "$OUT" in
  /|""|"$HOME") fail "out_directory_unsafe: $OUT" ;;
esac
OUT_ABS=$(canonical_dir "$(dirname "$OUT")")/$(basename "$OUT")
if [ -e "$OUT_ABS" ]; then
  [ -d "$OUT_ABS" ] || fail "out_directory_not_a_directory"
  [ -z "$(ls -A "$OUT_ABS" 2>/dev/null)" ] || fail "out_directory_not_empty: $OUT_ABS"
else
  mkdir -p "$OUT_ABS"
fi
[ "$OUT_ABS" != "$SOURCE_ABS" ] || fail "out_directory_is_source"
case "$SOURCE_ABS" in "$OUT_ABS"/*) fail "out_directory_contains_source" ;; esac
case "$OUT_ABS" in "$SOURCE_ABS"/*) fail "out_directory_inside_source" ;; esac

if [ -z "$BUN" ]; then
  BUN=$(command -v bun || true)
fi
[ -n "$BUN" ] && [ -x "$BUN" ] || fail "bun_binary_missing: pass --bun with the frozen Bun 1.4.2"
BUN_VERSION=$("$BUN" --version)
[ "$BUN_VERSION" = "1.4.2" ] || fail "bun_version_mismatch: got $BUN_VERSION want 1.4.2"
BUN_DIR=$(canonical_dir "$(dirname "$BUN")")
PATH="$BUN_DIR:$PATH"
export PATH

STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

SRC="$OUT_ABS/src"
ART="$OUT_ABS/artifacts"
STAGE="$OUT_ABS/stage"
mkdir -p "$SRC" "$ART" "$STAGE"

# Local clone from the exact official checkout: the source is never modified.
git clone --quiet --local --no-checkout "$SOURCE_ABS" "$SRC"
git -C "$SRC" checkout --quiet --detach "$REVISION"
git -C "$SRC" apply --binary "$PATCH_ABS" || fail "patch_apply_failed"

# Ephemeral LOCAL-ONLY baseline: upstream check:generated diffs against HEAD,
# so the patched tree needs a fixed-identity baseline commit before the
# generator checks can be meaningful. This commit is never pushed and is never
# presented as official upstream source; its parent is asserted to be the
# official revision and both are recorded in the manifest/provenance.
(
  cd "$SRC"
  git config --local user.name "WarpMetal native baseline"
  git config --local user.email "native-baseline@warpmetal.invalid"
  git config --local commit.gpgsign false
  git config --local core.hooksPath /dev/null
  git add -A
  GIT_AUTHOR_DATE="2000-01-01T00:00:00Z" GIT_COMMITTER_DATE="2000-01-01T00:00:00Z" \
    git commit --quiet --no-verify -m "ephemeral WarpMetal atomic-input baseline (local only)"
)
BASELINE_COMMIT=$(git -C "$SRC" rev-parse HEAD)
[ "$(git -C "$SRC" rev-parse 'HEAD^')" = "$REVISION" ] || fail "baseline_parent_mismatch"

(
  cd "$SRC"
  "$BUN" install --frozen-lockfile --ignore-scripts
  ( cd packages/client && "$BUN" run check:generated )
  ( cd packages/core && "$BUN" script/migration.ts --check )
)

if [ "$RUN_TESTS" = "1" ]; then
  ( cd "$SRC/packages/core" && "$BUN" run test test/session-prompt.test.ts test/session-runner.test.ts )
  ( cd "$SRC/packages/server" && "$BUN" test --only-failures test/session-guard.test.ts )
  ( cd "$SRC/packages/schema" && "$BUN" test --only-failures test/event-manifest.test.ts )
fi

(
  cd "$SRC"
  mkdir -p "$OUT_ABS/home"
  HOME="$OUT_ABS/home" \
  OPENCODE_CHANNEL=latest \
  OPENCODE_VERSION="$VERSION" \
  BUN_COMPILE_RELEASE="$BUN_RELEASE" \
    "$BUN" ./packages/cli/script/build.ts --target="$TARGET" --skip-install
)

DIST_BIN="$SRC/packages/cli/dist/cli-linux-x64/bin/opencode"
DIST_PKG="$SRC/packages/cli/dist/cli-linux-x64/package.json"
[ -f "$DIST_BIN" ] || fail "build_output_missing: $DIST_BIN"
[ -f "$DIST_PKG" ] || fail "build_package_json_missing: $DIST_PKG"

PKG_ROOT="$STAGE/package"
mkdir -p "$PKG_ROOT/bin"
cp "$DIST_BIN" "$PKG_ROOT/bin/opencode"
chmod 0755 "$PKG_ROOT/bin/opencode"
cp "$DIST_PKG" "$PKG_ROOT/package.json"
cp "$SRC/LICENSE" "$PKG_ROOT/LICENSE"

python3 - "$OUT_ABS/warpmetal-native-manifest.json" "$VERSION" "$REVISION" "$TREE" "$DIGEST" "$TARGET" "$ARCHIVE" "$TAG" "$BASELINE_COMMIT" <<'PY'
import json
import sys

path, version, revision, tree, digest, target, archive, tag, baseline = sys.argv[1:10]
manifest = {
    "formatVersion": 1,
    "artifact": archive,
    "version": version,
    "sourceRevision": revision,
    "sourceTree": tree,
    "patchDigest": digest,
    "target": target,
    "releaseTag": tag,
    "baselineCommit": baseline,
    "baselineCommitOfficial": False,
    "builder": "packaging/native/build.sh",
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
cp "$OUT_ABS/warpmetal-native-manifest.json" "$PKG_ROOT/warpmetal-native-manifest.json"

# Deterministic npm-layout archive: package/bin/opencode + package.json +
# LICENSE + manifest. gzip -n keeps the gzip header free of timestamps/names.
TARBALL="$ART/$ARCHIVE"
( cd "$STAGE" && tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - package ) | gzip -n -9 > "$TARBALL"
[ -s "$TARBALL" ] || fail "archive_empty"
( cd "$ART" && sha256sum "$ARCHIVE" > "$ARCHIVE.sha256" )
BINARY_SHA=$(sha256sum "$PKG_ROOT/bin/opencode" | awk '{print $1}')
printf 'sha256:%s\n' "$BINARY_SHA" > "$ART/opencode.binary.sha256"

# Smoke: exact version always; authenticated real HTTP guard assertion with --smoke.
SMOKE_BIN="$PKG_ROOT/bin/opencode"
SMOKE_VERSION=$("$SMOKE_BIN" --version)
[ "$SMOKE_VERSION" = "opencode v$VERSION" ] || fail "smoke_version_mismatch: got $SMOKE_VERSION want opencode v$VERSION"
if [ "$SMOKE" = "1" ]; then
  [ -f "$SCRIPT_DIR/smoke.py" ] || fail "smoke_helper_missing: packaging/native/smoke.py"
  python3 "$SCRIPT_DIR/smoke.py" \
    --binary "$SMOKE_BIN" \
    --workdir "$OUT_ABS/smoke" \
    --version "$VERSION" \
    --guard-version "warpmetal.atomic-input.v1"
fi

# Bare SLSA v0.2 predicate for cosign 2.5.3 attest-blob --type slsaprovenance:
# cosign parses this file as a ProvenancePredicate and wraps it into the signed
# in-toto Statement with the archive subject itself. All digests are computed
# only after the final bytes exist; the predicate never contains its own digest
# or an absolute private output path.
BUILDER_SHA=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || true)
LOCK_SHA=$(sha256sum "$LOCK_ABS" | awk '{print $1}')
ARCHIVE_SHA=$(sha256sum "$TARBALL" | awk '{print $1}')
FINISHED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 - "$ART/warpmetal-native-provenance.json" \
  "$ARCHIVE" "$ARCHIVE_SHA" "$BINARY_SHA" "$VERSION" "$REVISION" "$TREE" "$DIGEST" "$TARGET" "$BUN_VERSION" "$LOCK_SHA" \
  "$STARTED_AT" "$FINISHED_AT" "$BUILDER_SHA" <<'PY'
import json
import sys

(
    path, archive, archive_sha, binary_sha, version, revision, tree, digest, target,
    bun_version, lock_sha, started_at, finished_at, builder_sha,
) = sys.argv[1:15]
import os

repo = os.environ.get("GITHUB_REPOSITORY", "")
run_id = os.environ.get("GITHUB_RUN_ID", "")
run_uri = os.environ.get("GITHUB_RUN_URI", "")
server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
ci = bool(run_id and repo)
if ci:
    builder_id = f"{server}/{repo}/actions/runs/{run_id}"
    build_type = f"{server}/{repo}/blob/{builder_sha}/packaging/native/build.sh" if builder_sha else f"{server}/{repo}"
    config_uri = f"git+{server}/{repo}@{builder_sha}" if builder_sha else f"git+{server}/{repo}"
    environment = {"githubRunId": run_id, "githubRunUri": run_uri or f"{server}/{repo}/actions/runs/{run_id}"}
else:
    builder_id = f"warpmetal:packaging/native/build.sh@{builder_sha or 'local'}"
    build_type = "warpmetal:packaging/native/build.sh"
    config_uri = f"git+https://github.com/warpmetal/warpmetal-agent-runtime@{builder_sha}" if builder_sha else "warpmetal:packaging/native/build.sh"
    environment = {}
invocation = {
    "configSource": {"uri": config_uri, "entryPoint": "packaging/native/build.sh"},
    "parameters": {
        "version": version,
        "target": target,
        "sourceRevision": revision,
        "sourceTree": tree,
        "patchDigest": digest,
        "bun": bun_version,
        "lockSha256": lock_sha,
        "artifactSha256": "sha256:" + archive_sha,
        "binarySha256": "sha256:" + binary_sha,
    },
    "environment": environment,
}
materials = [
    {"uri": "git+https://github.com/anomalyco/opencode", "digest": {"sha1": revision}},
    {"uri": "warpmetal-atomic-input-v1.patch", "digest": {"sha256": digest.split(":", 1)[1]}},
]
if builder_sha:
    materials.append({"uri": "git+https://github.com/warpmetal/warpmetal-agent-runtime", "digest": {"sha1": builder_sha}})
predicate = {
    "builder": {"id": builder_id},
    "buildType": build_type,
    "invocation": invocation,
    "materials": materials,
    "metadata": {
        "buildInvocationId": run_id or "local",
        "buildStartedOn": started_at,
        "buildFinishedOn": finished_at,
        "completeness": {"parameters": True, "environment": ci, "materials": True},
        "reproducible": False,
    },
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(predicate, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY

printf 'native-build: build ok %s\n' "$TARBALL"
printf 'native-build: checksums %s.sha256 %s\n' "$TARBALL" "$ART/opencode.binary.sha256"
printf 'native-build: archive sha256 %s\n' "$ARCHIVE_SHA"
printf 'native-build: binary sha256 %s\n' "$BINARY_SHA"
