#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

fail_install() {
  echo "$1" >&2
  exit "${2:-1}"
}

# Preserve mode never sources or invokes the optional AppArmor policy helper.
warpmetal_apparmor_policy_initialized=0

is_warpmetal_podman_service_process() {
  process_id=$1
  [ -n "$warpmetal_podman_pid" ] || return 1
  [ "$process_id" = "$warpmetal_podman_pid" ] && return 0
  [ -r "/proc/$process_id/cgroup" ] || return 1
  grep -Eq '^0::/system[.]slice/warpmetal-podman[.]service(/|$)' \
    "/proc/$process_id/cgroup"
}

snapshot_host_workloads() {
  process_snapshot_unsorted="$install_state_dir/processes.unsorted"
  process_snapshot="$install_state_dir/processes.before"
  : > "$process_snapshot_unsorted"
  docker_process_present=0
  warpmetal_podman_pid=$(
    systemctl show --property MainPID --value warpmetal-podman.service 2>/dev/null || true
  )
  case "$warpmetal_podman_pid" in
    ''|0|*[!0-9]*) warpmetal_podman_pid= ;;
  esac
  for process_dir in /proc/[0-9]*; do
    [ -r "$process_dir/comm" ] && [ -r "$process_dir/stat" ] || continue
    process_id=${process_dir#/proc/}
    IFS= read -r process_name < "$process_dir/comm" || continue
    case "$process_name" in
      dockerd)
        docker_process_present=1
        ;;
      containerd|containerd-shim*|conmon|crio|kubelet|lxc-start|lxd|incusd)
        ;;
      podman)
        # Restarting WarpMetal's own API service is an allowed installer action.
        # Podman may fork a child inside the same service cgroup. Exempt only
        # those Podman processes; sandbox processes remain protected through
        # their separately inventoried conmon processes.
        is_warpmetal_podman_service_process "$process_id" && continue
        ;;
      *)
        continue
        ;;
    esac
    process_start=$(awk '{print $22}' "$process_dir/stat" 2>/dev/null) || continue
    [ -n "$process_start" ] || continue
    printf '%s %s %s\n' "$process_id" "$process_start" "$process_name" >> "$process_snapshot_unsorted"
  done
  sort -n "$process_snapshot_unsorted" > "$process_snapshot"

  docker_inventory_enabled=0
  docker_cli=$(command -v docker 2>/dev/null || true)
  docker_socket=/var/run/docker.sock
  if [ "$docker_process_present" -eq 1 ] || [ -S "$docker_socket" ]; then
    [ -n "$docker_cli" ] || fail_install runtime_workload_state_unverifiable
    if ! DOCKER_HOST="unix://$docker_socket" "$docker_cli" info >/dev/null 2>&1; then
      fail_install runtime_workload_state_unverifiable
    fi
    docker_inventory_enabled=1
  elif [ -n "$docker_cli" ] && \
       DOCKER_HOST="unix://$docker_socket" "$docker_cli" info >/dev/null 2>&1; then
    docker_inventory_enabled=1
  fi

  : > "$install_state_dir/docker.ids"
  : > "$install_state_dir/docker.before"
  if [ "$docker_inventory_enabled" -eq 1 ]; then
    if ! docker_ids=$(DOCKER_HOST="unix://$docker_socket" "$docker_cli" ps --quiet --no-trunc); then
      fail_install runtime_workload_state_unverifiable
    fi
    if [ -n "$docker_ids" ]; then
      printf '%s\n' "$docker_ids" > "$install_state_dir/docker.ids"
      if grep -Ev '^[a-f0-9]{64}$' "$install_state_dir/docker.ids" >/dev/null; then
        fail_install runtime_workload_state_unverifiable
      fi
      # Docker IDs contain only lowercase hexadecimal characters, validated above.
      # One inspect call keeps the snapshot fast without collecting application data.
      if ! DOCKER_HOST="unix://$docker_socket" xargs -n 128 \
        "$docker_cli" inspect \
        --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.State.Running}}' \
        < "$install_state_dir/docker.ids" > "$install_state_dir/docker.unsorted"; then
        fail_install runtime_workload_state_unverifiable
      fi
      sort "$install_state_dir/docker.unsorted" > "$install_state_dir/docker.before"
    fi
  fi
}

assert_host_workloads_unchanged() {
  while read -r process_id process_start process_name; do
    [ -n "$process_id" ] || continue
    [ -r "/proc/$process_id/comm" ] && [ -r "/proc/$process_id/stat" ] || \
      fail_install runtime_workload_drift_detected
    IFS= read -r current_name < "/proc/$process_id/comm" || \
      fail_install runtime_workload_drift_detected
    current_start=$(awk '{print $22}' "/proc/$process_id/stat" 2>/dev/null) || \
      fail_install runtime_workload_drift_detected
    [ "$current_name" = "$process_name" ] && [ "$current_start" = "$process_start" ] || \
      fail_install runtime_workload_drift_detected
  done < "$install_state_dir/processes.before"

  if [ "$docker_inventory_enabled" -eq 1 ]; then
    if ! DOCKER_HOST="unix://$docker_socket" "$docker_cli" info >/dev/null 2>&1; then
      fail_install runtime_workload_drift_detected
    fi
    : > "$install_state_dir/docker.after"
    if [ -s "$install_state_dir/docker.ids" ]; then
      if ! DOCKER_HOST="unix://$docker_socket" xargs -n 128 \
        "$docker_cli" inspect \
        --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.State.Running}}' \
        < "$install_state_dir/docker.ids" > "$install_state_dir/docker.unsorted"; then
        fail_install runtime_workload_drift_detected
      fi
      sort "$install_state_dir/docker.unsorted" > "$install_state_dir/docker.after"
    fi
    cmp -s "$install_state_dir/docker.before" "$install_state_dir/docker.after" || \
      fail_install runtime_workload_drift_detected
  fi
}

apt_protected_packages='apt apt-utils dpkg docker-ce docker-ce-cli docker-ce-rootless-extras containerd.io docker-buildx-plugin docker-compose-plugin docker.io docker-compose docker-compose-v2 containerd runc podman crun conmon buildah netavark aardvark-dns containernetworking-plugins cri-o cri-tools kubelet moby-engine moby-cli moby-buildx moby-compose moby-containerd moby-runc lxc lxc-utils lxd lxd-client incus fuse-overlayfs slirp4netns iptables nftables'
rpm_protected_packages='dnf dnf5 rpm rpm-libs libdnf libdnf5 docker-ce docker-ce-cli containerd.io containerd docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras moby-engine moby-cli moby-buildx moby-compose moby-containerd moby-runc docker podman crun runc conmon buildah netavark aardvark-dns containernetworking-plugins cri-o cri-tools kubelet lxc lxc-libs lxcfs lxd incus fuse-overlayfs slirp4netns iptables iptables-nft iptables-libs nftables'

snapshot_apt_protected_packages() {
  : > "$install_state_dir/protected.before"
  for package in $apt_protected_packages; do
    package_status=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)
    [ "$package_status" = 'install ok installed' ] || continue
    package_version=$(dpkg-query -W -f='${Version}' "$package")
    printf '%s\t%s\n' "$package" "$package_version" >> "$install_state_dir/protected.before"
  done
  sort -o "$install_state_dir/protected.before" "$install_state_dir/protected.before"
}

verify_apt_protected_packages() {
  tab=$(printf '\t')
  while IFS="$tab" read -r package expected_version; do
    [ -n "$package" ] || continue
    package_status=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)
    [ "$package_status" = 'install ok installed' ] || \
      fail_install runtime_package_postcondition_failed
    package_version=$(dpkg-query -W -f='${Version}' "$package")
    [ "$package_version" = "$expected_version" ] || \
      fail_install runtime_package_postcondition_failed
  done < "$install_state_dir/protected.before"
}

install_apt_packages() {
  snapshot_apt_protected_packages
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=l
  if ! apt-get update -qq > "$install_state_dir/package-index.log" 2>&1; then
    fail_install runtime_package_index_failed
  fi

  apt_packages='podman crun uidmap fuse-overlayfs slirp4netns e2fsprogs iptables util-linux'
  set --
  for package in $apt_packages; do
    set -- "$@" "$package"
  done
  tab=$(printf '\t')
  while IFS="$tab" read -r package package_version; do
    [ -n "$package" ] || continue
    set -- "$@" "$package"
  done < "$install_state_dir/protected.before"

  if ! apt-get --simulate --no-remove --no-upgrade --no-install-recommends \
    install "$@" > "$install_state_dir/package.plan" 2>&1; then
    fail_install runtime_package_plan_unsafe
  fi
  if grep -Eq '^(Remv|Purg) ' "$install_state_dir/package.plan"; then
    fail_install runtime_package_plan_unsafe
  fi
  while IFS="$tab" read -r package package_version; do
    [ -n "$package" ] || continue
    if grep -Eq "^Inst ${package}(:[^ ]+)? \[" "$install_state_dir/package.plan"; then
      fail_install runtime_package_plan_unsafe
    fi
  done < "$install_state_dir/protected.before"

  package_apply_status=0
  apt-get install -y --no-remove --no-upgrade --no-install-recommends \
    "$@" > "$install_state_dir/package.apply" 2>&1 || package_apply_status=$?
  verify_apt_protected_packages
  if [ "$package_apply_status" -ne 0 ]; then
    assert_host_workloads_unchanged
    fail_install runtime_package_apply_failed
  fi
}

snapshot_rpm_protected_packages() {
  : > "$install_state_dir/protected.before"
  for package in $rpm_protected_packages; do
    rpm -q "$package" >/dev/null 2>&1 || continue
    rpm -q --qf '%{NAME}.%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
      "$package" >> "$install_state_dir/protected.before"
  done
  sort -o "$install_state_dir/protected.before" "$install_state_dir/protected.before"
}

verify_rpm_protected_packages() {
  tab=$(printf '\t')
  while IFS="$tab" read -r package_arch expected_version; do
    [ -n "$package_arch" ] || continue
    package_version=$(rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' \
      "$package_arch" 2>/dev/null || true)
    [ "$package_version" = "$expected_version" ] || \
      fail_install runtime_package_postcondition_failed
  done < "$install_state_dir/protected.before"
}

install_dnf_packages() {
  snapshot_rpm_protected_packages
  dnf_packages='podman crun shadow-utils fuse-overlayfs slirp4netns e2fsprogs iptables util-linux'
  set -- install
  missing_package_count=0
  for package in $dnf_packages; do
    if [ "$package" = iptables ] && \
       [ -x /usr/sbin/iptables ] && [ -x /usr/sbin/ip6tables ]; then
      continue
    fi
    if ! rpm -q "$package" >/dev/null 2>&1; then
      set -- "$@" "$package"
      missing_package_count=$((missing_package_count + 1))
    fi
  done

  if [ "$missing_package_count" -gt 0 ]; then
    protected_exclude=$(cut -f1 "$install_state_dir/protected.before" | paste -sd, -)
    if [ -n "$protected_exclude" ]; then
      set -- "--exclude=$protected_exclude" "$@"
    fi
    if ! dnf -y --setopt=install_weak_deps=False --setopt=obsoletes=False \
      --setopt=tsflags=test "$@" \
      > "$install_state_dir/package.plan" 2>&1; then
      fail_install runtime_package_plan_unsafe
    fi
    if grep -Eq '^(Removing|Downgrading|Replacing)( [^:]*)?:$|^[[:space:]]*(Remove|Downgrade)[[:space:]]+[0-9]+ Package' \
      "$install_state_dir/package.plan"; then
      fail_install runtime_package_plan_unsafe
    fi
    package_apply_status=0
    dnf -y -q --setopt=install_weak_deps=False --setopt=obsoletes=False \
      "$@" \
      > "$install_state_dir/package.apply" 2>&1 || package_apply_status=$?
    verify_rpm_protected_packages
    if [ "$package_apply_status" -ne 0 ]; then
      assert_host_workloads_unchanged
      fail_install runtime_package_apply_failed
    fi
  fi
  verify_rpm_protected_packages
}

if [ "$(id -u)" -ne 0 ]; then
  echo "installer_requires_root" >&2
  exit 1
fi

api_origin=""
server_id=""
bundle_dir=""
nested_private_procfs_mode=preserve
while [ "$#" -gt 0 ]; do
  case "$1" in
    --api) [ "$#" -ge 2 ] || { echo "invalid_installer_argument" >&2; exit 2; }; api_origin=$2; shift 2 ;;
    --server) [ "$#" -ge 2 ] || { echo "invalid_installer_argument" >&2; exit 2; }; server_id=$2; shift 2 ;;
    --bundle) [ "$#" -ge 2 ] || { echo "invalid_installer_argument" >&2; exit 2; }; bundle_dir=$2; shift 2 ;;
    --nested-private-procfs)
      [ "$#" -ge 2 ] || { echo "invalid_installer_argument" >&2; exit 2; }
      nested_private_procfs_mode=$2
      shift 2
      ;;
    *) echo "invalid_installer_argument" >&2; exit 2 ;;
  esac
done

case "$nested_private_procfs_mode" in
  preserve|enable|disable) ;;
  *) echo "runtime_nested_private_procfs_mode_invalid" >&2; exit 2 ;;
esac
if [ "$nested_private_procfs_mode" = enable ]; then
  case "$(uname -m)" in
    x86_64) ;;
    *) fail_install runtime_nested_private_procfs_architecture_unsupported ;;
  esac
fi

case "$api_origin" in https://*) ;; *) echo "invalid_api_origin" >&2; exit 2 ;; esac
case "$server_id" in srv_*) ;; *) echo "invalid_server_id" >&2; exit 2 ;; esac
case "$server_id" in *[!A-Za-z0-9_-]*) echo "invalid_server_id" >&2; exit 2 ;; esac
[ "${#server_id}" -ge 12 ] && [ "${#server_id}" -le 64 ] || {
  echo "invalid_server_id" >&2
  exit 2
}
case "$bundle_dir" in /tmp/warpmetal-runtime-*) ;; *) echo "invalid_bundle_path" >&2; exit 2 ;; esac
bundle_name=${bundle_dir#/tmp/warpmetal-runtime-}
case "$bundle_name" in ''|*[!A-Za-z0-9_-]*) echo "invalid_bundle_path" >&2; exit 2 ;; esac

# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04|debian:12) package_manager=apt ;;
  almalinux:9|almalinux:9.*|rocky:9|rocky:9.*) package_manager=dnf ;;
  *) echo "unsupported_runtime_os" >&2; exit 1 ;;
esac

test -d /run/systemd/system || { echo "systemd_required" >&2; exit 1; }
test -f /sys/fs/cgroup/cgroup.controllers || { echo "cgroups_v2_required" >&2; exit 1; }

if [ -f /var/run/reboot-required ]; then
  fail_install runtime_reboot_required 75
fi

command -v flock >/dev/null 2>&1 || fail_install runtime_install_lock_unavailable
test -d /run/lock || fail_install runtime_install_lock_unavailable
umask 077
install_state_dir=$(mktemp -d /run/warpmetal-install.XXXXXX) || \
  fail_install runtime_install_state_unavailable
cleanup_install_state() {
  apparmor_rollback_status=0
  if [ "$warpmetal_apparmor_policy_initialized" -eq 1 ]; then
    if ! warpmetal_rollback_apparmor_policy; then
      apparmor_rollback_status=1
      echo runtime_apparmor_policy_rollback_failed >&2
    fi
  fi
  # Assigned by the signed helper sourced below.
  # shellcheck disable=SC2154
  if [ "${warpmetal_apparmor_policy_recovery_required:-0}" -eq 1 ]; then
    apparmor_rollback_status=1
  fi
  if [ "$apparmor_rollback_status" -eq 0 ]; then
    case "$install_state_dir" in
      /run/warpmetal-install.*) rm -rf -- "$install_state_dir" ;;
    esac
  else
    printf 'runtime_apparmor_policy_recovery_state_preserved %s\n' \
      "${warpmetal_apparmor_policy_durable_state:-$install_state_dir}" >&2
  fi
}
trap cleanup_install_state 0
trap 'exit 130' 1 2 15
exec 9>/run/lock/warpmetal-runtime-install.lock
flock -n 9 || fail_install runtime_install_in_progress

snapshot_host_workloads
if [ "$package_manager" = apt ]; then
  install_apt_packages
else
  install_dnf_packages
fi
assert_host_workloads_unchanged
command -v podman >/dev/null 2>&1 || fail_install runtime_podman_unavailable
command -v crun >/dev/null 2>&1 || fail_install runtime_oci_runtime_unavailable

if [ "$nested_private_procfs_mode" != preserve ]; then
  apparmor_policy_source=$bundle_dir/warpmetal-agent-runtime-bwrap
  apparmor_policy_library=$bundle_dir/warpmetal-apparmor-policy.sh
  [ -f "$apparmor_policy_library" ] && [ ! -L "$apparmor_policy_library" ] || \
    fail_install runtime_apparmor_policy_bundle_invalid
  # shellcheck source=/dev/null
  . "$apparmor_policy_library"
  warpmetal_apparmor_policy_initialized=1
  apparmor_requirement_status=0
  warpmetal_detect_apparmor_policy_requirement \
    /sys/module/apparmor/parameters/enabled \
    /proc/sys/kernel/apparmor_restrict_unprivileged_userns || \
    apparmor_requirement_status=$?
  case "$apparmor_requirement_status:$nested_private_procfs_mode" in
    0:enable|0:disable|1:disable)
    apparmor_parser_path=$(command -v apparmor_parser 2>/dev/null || true)
    [ -n "$apparmor_parser_path" ] || fail_install runtime_apparmor_policy_unsupported
    apparmor_policy_destination=/etc/apparmor.d/warpmetal-agent-runtime-bwrap
    apparmor_policy_durable_state=/var/lib/warpmetal/apparmor-policy-state
    apparmor_metadata_helper=$bundle_dir/warpmetal-policy-metadata
    [ -f "$apparmor_metadata_helper" ] && [ ! -L "$apparmor_metadata_helper" ] && \
      [ -x "$apparmor_metadata_helper" ] || \
      fail_install runtime_apparmor_policy_bundle_invalid
    if ! warpmetal_configure_apparmor_policy \
      "$nested_private_procfs_mode" \
      "$(uname -m)" \
      "$apparmor_policy_source" \
      "$apparmor_policy_destination" \
      "$apparmor_policy_durable_state" \
      "$apparmor_parser_path" \
      /sys/kernel/security/apparmor/profiles \
      "$apparmor_metadata_helper"; then
      # Assigned by the signed helper sourced above.
      # shellcheck disable=SC2154
      fail_install "$warpmetal_apparmor_policy_error"
    fi
      ;;
    1:enable) ;;
    *)
      # Assigned by the signed helper sourced above.
      # shellcheck disable=SC2154
      fail_install "$warpmetal_apparmor_policy_error"
      ;;
  esac
fi

getent passwd warpmetal-runtime >/dev/null 2>&1 || \
  useradd --system --create-home --home-dir /var/lib/warpmetal-runtime --shell /usr/sbin/nologin warpmetal-runtime
gateway_home=/var/empty/warpmetal-sandbox
install -d -o root -g root -m 0755 "$gateway_home"
getent passwd warpmetal-sandbox >/dev/null 2>&1 || \
  useradd --system --no-create-home --home-dir "$gateway_home" --shell /usr/libexec/warpmetal-sandbox-shell warpmetal-sandbox
usermod --lock warpmetal-sandbox
usermod --home "$gateway_home" warpmetal-sandbox
usermod --shell /usr/libexec/warpmetal-sandbox-shell warpmetal-sandbox

install -d -m 0700 /var/lib/warpmetal
install -d -o root -g warpmetal-runtime -m 0710 /var/lib/warpmetal-workspaces

ensure_subid_range() {
  subid_file=$1
  usermod_option=$2
  grep '^warpmetal-runtime:' "$subid_file" >/dev/null 2>&1 && return 0
  range_start=100000
  while [ "$range_start" -le 2000000000 ]; do
    range_end=$((range_start + 65535))
    if ! awk -F: -v start="$range_start" -v end="$range_end" '
      $2 <= end && ($2 + $3 - 1) >= start { overlap = 1 }
      END { exit overlap ? 0 : 1 }
    ' "$subid_file"; then
      usermod "$usermod_option" "$range_start-$range_end" warpmetal-runtime
      return 0
    fi
    range_start=$((range_end + 1))
  done
  echo "runtime_subid_range_unavailable" >&2
  exit 1
}

ensure_subid_range /etc/subuid --add-subuids
ensure_subid_range /etc/subgid --add-subgids

install -d -o warpmetal-runtime -g warpmetal-runtime -m 0700 /run/warpmetal-podman
if [ -f /var/lib/warpmetal-runtime/.local/share/containers/storage/libpod/bolt_state.db ] || \
   [ -f /var/lib/warpmetal-runtime/.local/share/containers/storage/db.sql ]; then
  current_runroot=$(
    cd /var/lib/warpmetal-runtime
    runuser -u warpmetal-runtime -- env \
      HOME=/var/lib/warpmetal-runtime \
      XDG_RUNTIME_DIR=/run/warpmetal-podman \
      podman --runroot /run/warpmetal-podman/containers \
        --runtime crun \
        --cgroup-manager cgroupfs \
        info --format '{{.Store.RunRoot}}' 2>/dev/null || true
  )
  if [ "$current_runroot" != /run/warpmetal-podman/containers ]; then
    fail_install runtime_legacy_migration_required
  fi
fi

install -d -m 0755 /usr/libexec
install -m 0755 "$bundle_dir/warpmetald" /usr/local/sbin/warpmetald
install -m 0755 "$bundle_dir/warpmetal-agentctl" /usr/local/sbin/warpmetal-agentctl
install -m 0755 "$bundle_dir/warpmetal-sandbox-gateway" /usr/libexec/warpmetal-sandbox-gateway
install -m 0755 "$bundle_dir/warpmetal-sandbox-shell" /usr/libexec/warpmetal-sandbox-shell
install -m 0755 "$bundle_dir/warpmetal-podman-service" /usr/libexec/warpmetal-podman-service
install -m 0644 "$bundle_dir/warpmetal-podman.service" /etc/systemd/system/warpmetal-podman.service
install -m 0644 "$bundle_dir/warpmetald.service" /etc/systemd/system/warpmetald.service
install -m 0644 "$bundle_dir/warpmetal-sandbox.conf" /etc/ssh/sshd_config.d/90-warpmetal-sandbox.conf
install -d -o root -g warpmetal-sandbox -m 0750 /etc/ssh/warpmetal-runtime
install -o root -g warpmetal-sandbox -m 0640 /dev/null /etc/ssh/warpmetal-runtime/authorized_keys

install -d -m 0755 /etc/systemd/system/warpmetald.service.d
runtime_cgroup=/sys/fs/cgroup/system.slice/warpmetal-podman.service
printf '[Service]\nBindPaths=%s\nReadWritePaths=/run/warpmetal-podman %s\n' \
  "$runtime_cgroup" "$runtime_cgroup" > \
  /etc/systemd/system/warpmetald.service.d/10-runtime-user.conf

/usr/sbin/sshd -t
systemctl daemon-reload
systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service
systemctl enable warpmetal-podman.service
# Starting an already-active service is intentionally a no-op. Runtime
# upgrades must not stop its delegated cgroup because systemd would also stop
# the persistent sandbox processes that live below it. Fresh installs and
# failed/inactive services are still started here.
systemctl start warpmetal-podman.service

attempt=0
while [ ! -S /run/warpmetal-podman/podman.sock ] && [ "$attempt" -lt 50 ]; do
  attempt=$((attempt + 1))
  sleep 0.1
done
test -S /run/warpmetal-podman/podman.sock || { echo "runtime_podman_unavailable" >&2; exit 1; }

assert_host_workloads_unchanged
/usr/local/sbin/warpmetald register --api "$api_origin" --server "$server_id"
systemctl enable warpmetald.service
systemctl restart warpmetald.service
if [ "$nested_private_procfs_mode" != preserve ]; then
  if ! warpmetal_commit_apparmor_policy_operation; then
    fail_install runtime_apparmor_policy_recovery_failed
  fi
fi
# Read by the helper-backed EXIT trap.
# shellcheck disable=SC2034
warpmetal_apparmor_policy_committed=1
