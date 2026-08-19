#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "installer_requires_root" >&2
  exit 1
fi

api_origin=""
server_id=""
bundle_dir=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --api) api_origin=$2; shift 2 ;;
    --server) server_id=$2; shift 2 ;;
    --bundle) bundle_dir=$2; shift 2 ;;
    *) echo "invalid_installer_argument" >&2; exit 2 ;;
  esac
done

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

. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04|debian:12) ;;
  *) echo "unsupported_runtime_os" >&2; exit 1 ;;
esac

test -d /run/systemd/system || { echo "systemd_required" >&2; exit 1; }
test -f /sys/fs/cgroup/cgroup.controllers || { echo "cgroups_v2_required" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq podman uidmap fuse-overlayfs slirp4netns e2fsprogs iptables

getent passwd warpmetal-runtime >/dev/null 2>&1 || \
  useradd --system --create-home --home-dir /var/lib/warpmetal-runtime --shell /usr/sbin/nologin warpmetal-runtime
getent passwd warpmetal-sandbox >/dev/null 2>&1 || \
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/libexec/warpmetal-sandbox-shell warpmetal-sandbox
usermod --lock warpmetal-sandbox
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
loginctl enable-linger warpmetal-runtime
runtime_uid=$(id -u warpmetal-runtime)
systemctl start "user@${runtime_uid}.service"
install -d -m 0755 /etc/systemd/system/warpmetald.service.d
printf '[Service]\nBindPaths=/run/user/%s\n' "$runtime_uid" > \
  /etc/systemd/system/warpmetald.service.d/10-runtime-user.conf

install -d -m 0755 /usr/libexec
install -m 0755 "$bundle_dir/warpmetald" /usr/local/sbin/warpmetald
install -m 0755 "$bundle_dir/warpmetal-agentctl" /usr/local/sbin/warpmetal-agentctl
install -m 0755 "$bundle_dir/warpmetal-sandbox-gateway" /usr/libexec/warpmetal-sandbox-gateway
install -m 0755 "$bundle_dir/warpmetal-sandbox-shell" /usr/libexec/warpmetal-sandbox-shell
install -m 0644 "$bundle_dir/warpmetald.service" /etc/systemd/system/warpmetald.service
install -m 0644 "$bundle_dir/warpmetal-sandbox.conf" /etc/ssh/sshd_config.d/90-warpmetal-sandbox.conf
install -o root -g warpmetal-sandbox -m 0640 /dev/null /etc/ssh/warpmetal_sandbox_authorized_keys

/usr/sbin/sshd -t
systemctl daemon-reload
systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service

/usr/local/sbin/warpmetald register --api "$api_origin" --server "$server_id"
systemctl enable --now warpmetald.service
