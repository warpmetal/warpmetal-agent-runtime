#!/bin/sh
set -eu

# This probe is intentionally credential-free. It exercises only the immutable
# Codex Bubblewrap helper and a short-lived process that it creates itself.
bwrap_path=/opt/warpmetal-agent-tools/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex-resources/bwrap

[ -f "$bwrap_path" ] && [ ! -L "$bwrap_path" ] || {
  echo runtime_nested_procfs_helper_missing >&2
  exit 1
}

helper_identity=$(stat -c '%u:%g:%a' "$bwrap_path" 2>/dev/null || true)
[ "$helper_identity" = 0:0:555 ] || {
  echo runtime_nested_procfs_helper_untrusted >&2
  exit 1
}

sleep 2147483647 &
outer_pid=$!
cleanup() {
  kill "$outer_pid" 2>/dev/null || true
  wait "$outer_pid" 2>/dev/null || true
}
trap cleanup 0 1 2 15

assert_outer_sentinel_live() {
  if ! kill -0 "$outer_pid" 2>/dev/null; then
    echo runtime_nested_procfs_sentinel_exited >&2
    exit 1
  fi
}

assert_outer_sentinel_live

"$bwrap_path" \
  --die-with-parent \
  --new-session \
  --unshare-user \
  --unshare-pid \
  --unshare-ipc \
  --unshare-uts \
  --as-pid-1 \
  --ro-bind / / \
  --proc /proc \
  --dev /dev \
  --clearenv \
  --setenv HOME /tmp \
  --setenv PATH /usr/bin:/bin \
  -- /usr/bin/node -e '
    const fs = require("node:fs");
    const cp = require("node:child_process");
    const outerPid = process.argv[1];
    if (process.pid !== 1 || fs.readlinkSync("/proc/self") !== "1") process.exit(11);
    try {
      fs.statSync(`/proc/${outerPid}`);
      process.exit(12);
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== "ESRCH") process.exit(15);
    }
    const child = cp.spawnSync("/usr/bin/node", ["-e", `
      const fs = require("node:fs");
      if (fs.readlinkSync("/proc/self") !== String(process.pid)) process.exit(13);
    `], {stdio: "inherit"});
    if (child.status !== 0) process.exit(child.status || 14);
  ' "$outer_pid"

assert_outer_sentinel_live
echo runtime_nested_private_procfs_verified
