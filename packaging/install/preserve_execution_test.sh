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
  for process_id in ${test_processes:-}; do
    kill "$process_id" 2>/dev/null || true
    wait "$process_id" 2>/dev/null || true
  done
  rm -f -- "$ready"
  rm -rf -- "$bundle"
  rm -rf -- /tmp/warpmetal-preserve-processes /tmp/warpmetal-preserve-state \
    /tmp/warpmetal-preserve-bin /tmp/warpmetal-preserve-guard.sh
  rmdir /sys/fs/cgroup/system.slice/warpmetal-podman.service/manager 2>/dev/null || true
  rmdir /sys/fs/cgroup/system.slice/warpmetal-podman.service 2>/dev/null || true
  rmdir /sys/fs/cgroup/system.slice/warpmetald.service 2>/dev/null || true
  rmdir /sys/fs/cgroup/system.slice/warpmetal-unrelated.service 2>/dev/null || true
  rmdir /sys/fs/cgroup/system.slice 2>/dev/null || true
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

# Exercise the production process guard against real Linux /proc and cgroup
# identities. Runtime's private remote Podman client and conmon --exec monitor
# are command-scoped helpers; their exit must not be mistaken for a persistent
# workload restart. The Podman service, a container's long-lived conmon and an
# unrelated monitor remain protected identities.
mkdir -p /tmp/warpmetal-preserve-processes /tmp/warpmetal-preserve-state \
  /tmp/warpmetal-preserve-bin
mkdir -p /sys/fs/cgroup/system.slice/warpmetal-podman.service/manager \
  /sys/fs/cgroup/system.slice/warpmetald.service \
  /sys/fs/cgroup/system.slice/warpmetal-unrelated.service

awk '
  /^process_start_ticks\(\)/ { copy = 1 }
  /^apt_protected_packages=/ { copy = 0 }
  copy { print }
' "$installer" > /tmp/warpmetal-preserve-guard.sh

start_test_process() {
  process_name=$1
  process_cgroup=$2
  shift 2
  process_binary=/tmp/warpmetal-preserve-processes/$process_name
  if [ ! -x "$process_binary" ]; then
    cp /bin/bash "$process_binary"
    chmod 0755 "$process_binary"
  fi
  "$process_binary" -c \
    'trap "exit 0" TERM INT; while :; do read -r -t 1 _ || :; done' \
    "$process_name" "$@" &
  started_process=$!
  test_processes="${test_processes:-} $started_process"
  printf '%s\n' "$started_process" > "$process_cgroup/cgroup.procs"
  process_attempt=0
  while [ "$process_attempt" -lt 50 ]; do
    [ -r "/proc/$started_process/comm" ] && \
      [ "$(cat "/proc/$started_process/comm")" = "$process_name" ] && return 0
    process_attempt=$((process_attempt + 1))
    sleep 0.02
  done
  echo preserve_process_fixture_failed >&2
  return 1
}

stop_test_process() {
  kill "$1"
  wait "$1" 2>/dev/null || true
}

start_test_process podman \
  /sys/fs/cgroup/system.slice/warpmetal-podman.service/manager \
  system service --time 0
podman_service_pid=$started_process
start_test_process warpmetald \
  /sys/fs/cgroup/system.slice/warpmetald.service
warpmetald_pid=$started_process
start_test_process podman \
  /sys/fs/cgroup/system.slice/warpmetald.service \
  --remote --url unix:///run/warpmetal-podman/podman.sock exec fixture true
transient_podman_pid=$started_process
start_test_process conmon \
  /sys/fs/cgroup/system.slice/warpmetal-podman.service/manager \
  --container fixture
persistent_conmon_pid=$started_process
start_test_process sandbox-init \
  /sys/fs/cgroup/system.slice/warpmetal-podman.service/manager \
  --container fixture
container_init_pid=$started_process
start_test_process conmon \
  /sys/fs/cgroup/system.slice/warpmetal-podman.service/manager \
  --container fixture --exec
transient_conmon_pid=$started_process
start_test_process conmon \
  /sys/fs/cgroup/system.slice/warpmetal-unrelated.service \
  --container unrelated
unrelated_conmon_pid=$started_process

cat > /tmp/warpmetal-preserve-bin/systemctl <<'EOF'
#!/bin/sh
case "$*" in
  *ActiveState*warpmetal-podman.service*) printf '%s\n' active ;;
  *ActiveState*warpmetald.service*) printf '%s\n' active ;;
  *MainPID*warpmetal-podman.service*) printf '%s\n' "$WARPMETAL_TEST_PODMAN_PID" ;;
  *MainPID*warpmetald.service*) printf '%s\n' "$WARPMETAL_TEST_RUNTIME_PID" ;;
  *) exit 1 ;;
esac
EOF
chmod 0755 /tmp/warpmetal-preserve-bin/systemctl
cat > /tmp/warpmetal-preserve-bin/runuser <<'EOF'
#!/bin/sh
[ "$1" = -u ] && [ "$2" = warpmetal-runtime ] && [ "$3" = -- ] || exit 2
shift 3
exec "$@"
EOF
chmod 0755 /tmp/warpmetal-preserve-bin/runuser
cat > /tmp/warpmetal-preserve-bin/podman <<'EOF'
#!/bin/sh
case " $* " in
  *' ps '*) printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
  *' inspect '*)
    printf '%s|%s|%s|%s|%s\n' \
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
      "$WARPMETAL_TEST_CONTAINER_INIT_PID" \
      "$WARPMETAL_TEST_CONTAINER_CONMON_PID" \
      '2026-09-28T00:40:09Z' true
    ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 /tmp/warpmetal-preserve-bin/podman
export WARPMETAL_TEST_PODMAN_PID=$podman_service_pid
export WARPMETAL_TEST_RUNTIME_PID=$warpmetald_pid
export WARPMETAL_TEST_CONTAINER_INIT_PID=$container_init_pid
export WARPMETAL_TEST_CONTAINER_CONMON_PID=$persistent_conmon_pid
PATH=/tmp/warpmetal-preserve-bin:$PATH
export PATH

fail_install() {
  echo "$1" >&2
  exit "${2:-1}"
}
# shellcheck source=/dev/null
. /tmp/warpmetal-preserve-guard.sh
install_state_dir=/tmp/warpmetal-preserve-state
snapshot_host_workloads
stop_test_process "$transient_podman_pid"
stop_test_process "$transient_conmon_pid"
transient_status=0
(assert_host_workloads_unchanged) >/tmp/warpmetal-preserve-transient.out 2>&1 || \
  transient_status=$?

# The private engine's real container init identity remains protected even
# when its command name is application-defined rather than engine-defined.
snapshot_host_workloads
stop_test_process "$container_init_pid"
container_init_status=0
(assert_host_workloads_unchanged) >/tmp/warpmetal-preserve-init.out 2>&1 || \
  container_init_status=$?
start_test_process sandbox-init \
  /sys/fs/cgroup/system.slice/warpmetal-podman.service/manager \
  --container fixture
container_init_pid=$started_process
export WARPMETAL_TEST_CONTAINER_INIT_PID=$container_init_pid

# A long-lived container monitor remains a protected workload identity.
snapshot_host_workloads
stop_test_process "$persistent_conmon_pid"
persistent_conmon_status=0
(assert_host_workloads_unchanged) >/tmp/warpmetal-preserve-conmon.out 2>&1 || \
  persistent_conmon_status=$?

# An unrelated monitor is never classified as a Runtime helper.
start_test_process conmon \
  /sys/fs/cgroup/system.slice/warpmetal-podman.service/manager \
  --container fixture
persistent_conmon_pid=$started_process
export WARPMETAL_TEST_CONTAINER_CONMON_PID=$persistent_conmon_pid
snapshot_host_workloads
stop_test_process "$unrelated_conmon_pid"
unrelated_conmon_status=0
(assert_host_workloads_unchanged) >/tmp/warpmetal-preserve-unrelated.out 2>&1 || \
  unrelated_conmon_status=$?

# The persistent private Podman engine service identity is also protected.
start_test_process conmon \
  /sys/fs/cgroup/system.slice/warpmetal-unrelated.service \
  --container unrelated
unrelated_conmon_pid=$started_process
snapshot_host_workloads
stop_test_process "$podman_service_pid"
podman_service_status=0
(assert_host_workloads_unchanged) >/tmp/warpmetal-preserve-service.out 2>&1 || \
  podman_service_status=$?

printf 'preservation_status transient=%s persistent_conmon=%s unrelated_conmon=%s podman_service=%s\n' \
  "$transient_status" "$persistent_conmon_status" "$unrelated_conmon_status" \
  "$podman_service_status"
printf 'preservation_private_container_init_status=%s\n' "$container_init_status"
[ "$transient_status" -eq 0 ] || {
  echo transient_runtime_helpers_reported_workload_drift >&2
  exit 1
}
[ "$persistent_conmon_status" -ne 0 ] || {
  echo persistent_conmon_drift_was_not_detected >&2
  exit 1
}
[ "$container_init_status" -ne 0 ] || {
  echo private_container_init_drift_was_not_detected >&2
  exit 1
}
[ "$unrelated_conmon_status" -ne 0 ] || {
  echo unrelated_conmon_drift_was_not_detected >&2
  exit 1
}
[ "$podman_service_status" -ne 0 ] || {
  echo podman_service_drift_was_not_detected >&2
  exit 1
}

echo runtime_preserve_execution_verified
