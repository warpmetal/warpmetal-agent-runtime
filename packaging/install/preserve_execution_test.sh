#!/bin/sh
set -eu

installer=${1:-/source/packaging/install/install.sh}

[ "$(id -u)" -eq 0 ] || {
  echo preserve_execution_test_requires_root >&2
  exit 1
}
[ -f /sys/fs/cgroup/cgroup.controllers ] || {
  echo preserve_execution_test_requires_cgroups_v2 >&2
  exit 1
}
command -v flock >/dev/null 2>&1 || {
  echo preserve_execution_test_requires_flock >&2
  exit 1
}

mkdir -p /run/systemd/system /run/lock
bundle=/tmp/warpmetal-runtime-preserve-test
mkdir -p "$bundle"
lock=/run/lock/warpmetal-runtime-install.lock
ready=/tmp/warpmetal-preserve-lock-ready

cleanup() {
  if [ -n "${lock_holder_pid:-}" ]; then
    kill "$lock_holder_pid" 2>/dev/null || true
    wait "$lock_holder_pid" 2>/dev/null || true
  fi
  rm -f -- "$ready"
  rm -rf -- "$bundle"
}
trap cleanup 0 1 2 15

flock "$lock" sh -c 'touch "$1"; sleep 30' sh "$ready" &
lock_holder_pid=$!
attempt=0
while [ ! -f "$ready" ] && [ "$attempt" -lt 50 ]; do
  attempt=$((attempt + 1))
  sleep 0.1
done
[ -f "$ready" ] || {
  echo preserve_execution_test_lock_failed >&2
  exit 1
}

installer_status=0
installer_output=$(
  sh "$installer" \
    --api https://example.invalid \
    --server srv_preserve123 \
    --bundle "$bundle" 2>&1
) || installer_status=$?

[ "$installer_status" -eq 1 ] || {
  echo "unexpected_preserve_installer_status $installer_status" >&2
  exit 1
}
[ "$installer_output" = runtime_install_in_progress ] || {
  printf 'unexpected_preserve_installer_output %s\n' "$installer_output" >&2
  exit 1
}

for state_directory in /run/warpmetal-install.*; do
  [ ! -e "$state_directory" ] || {
    echo preserve_installer_left_temporary_state >&2
    exit 1
  }
done

echo runtime_preserve_execution_verified
