#!/bin/sh
set -eu

profile=packaging/apparmor/warpmetal-agent-runtime-bwrap
oracle=packaging/apparmor/nested-private-procfs-oracle.sh
helper=/opt/warpmetal-agent-tools/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex-resources/bwrap

reject_match() {
  if grep "$@"; then
    echo unexpected_profile_or_oracle_match >&2
    exit 1
  fi
}

grep -Fqx "profile warpmetal-agent-runtime-bwrap $helper flags=(attach_disconnected,mediate_deleted) {" "$profile"
grep -Fqx 'profile warpmetal-agent-runtime-unpriv-bwrap flags=(attach_disconnected,mediate_deleted) {' "$profile"
test "$(grep -Fxc '  allow capability,' "$profile")" -eq 1
test "$(grep -Fxc '  audit deny capability,' "$profile")" -eq 1
grep -Fqx '  allow pix /** -> &warpmetal-agent-runtime-bwrap//&warpmetal-agent-runtime-unpriv-bwrap,' "$profile"
grep -Fqx '  allow pix /** -> &warpmetal-agent-runtime-unpriv-bwrap,' "$profile"
grep -Fqx '  allow userns,' "$profile"
grep -Fqx '  allow mount,' "$profile"
grep -Fqx '  allow pivot_root,' "$profile"
reject_match -Fq '/usr/bin/bwrap' "$profile"
reject_match -Fq 'include if exists <local/' "$profile"
reject_match -Eq 'flags=.*unconfined|change_profile|^[[:space:]]*hat[[:space:]]' "$profile"

grep -Fqx "bwrap_path=$helper" "$oracle"
grep -Fq -- '--unshare-pid' "$oracle"
grep -Fq -- '--as-pid-1' "$oracle"
grep -Fq -- '--proc /proc' "$oracle"
grep -Fq -- '--clearenv' "$oracle"
grep -Fq 'fs.readlinkSync("/proc/self")' "$oracle"
reject_match -Fq 'fs.existsSync(`/proc/${outerPid}`)' "$oracle"
grep -Fq 'fs.statSync(`/proc/${outerPid}`)' "$oracle"
grep -Fq 'error.code !== "ENOENT" && error.code !== "ESRCH"' "$oracle"
reject_match -Eq 'OPENAI|GITHUB|TOKEN|SECRET|PRIVATE_KEY|printenv|/proc/[0-9]+/environ' "$oracle"

reject_match -Fq 'sleep 30' "$oracle"
reject_match -Fq 'while :; do' "$oracle"
grep -Fqx 'sleep 2147483647 &' "$oracle"
test "$(grep -Fxc 'assert_outer_sentinel_live' "$oracle")" -eq 2
first_liveness_line=$(grep -n '^assert_outer_sentinel_live$' "$oracle" | sed -n '1s/:.*//p')
bwrap_line=$(grep -n '^"$bwrap_path" \\' "$oracle" | sed -n '1s/:.*//p')
second_liveness_line=$(grep -n '^assert_outer_sentinel_live$' "$oracle" | sed -n '2s/:.*//p')
test "$first_liveness_line" -lt "$bwrap_line"
test "$bwrap_line" -lt "$second_liveness_line"

# Exercise the directly backgrounded sentinel lifecycle and prove wait reaps it.
sleep 2147483647 &
sentinel_test_pid=$!
if ! kill -0 "$sentinel_test_pid" 2>/dev/null; then
  echo sentinel_fixture_exited_early >&2
  exit 1
fi
kill "$sentinel_test_pid"
wait "$sentinel_test_pid" 2>/dev/null || true
if kill -0 "$sentinel_test_pid" 2>/dev/null; then
  echo sentinel_fixture_survived_cleanup >&2
  exit 1
fi

if command -v apparmor_parser >/dev/null 2>&1; then
  apparmor_parser -Q "$profile"
fi
