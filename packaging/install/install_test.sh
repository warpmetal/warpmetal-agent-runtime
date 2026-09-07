#!/bin/sh
set -eu

script=packaging/install/install.sh
service=packaging/systemd/warpmetald.service
podman_service=packaging/systemd/warpmetal-podman.service
podman_launcher=packaging/systemd/warpmetal-podman-service
release_workflow=.github/workflows/release.yml
apparmor_library=packaging/install/warpmetal-apparmor-policy.sh
apparmor_profile=packaging/apparmor/warpmetal-agent-runtime-bwrap
apparmor_oracle=packaging/apparmor/nested-private-procfs-oracle.sh

reject_match() {
  if grep "$@"; then
    echo unexpected_installer_match >&2
    exit 1
  fi
}
register_line=$(grep -n '^/usr/local/sbin/warpmetald register ' "$script" | cut -d: -f1)
podman_start_line=$(grep -n '^systemctl start warpmetal-podman.service$' "$script" | cut -d: -f1)
enable_line=$(grep -n '^systemctl enable warpmetald.service$' "$script" | cut -d: -f1)
restart_line=$(grep -n '^systemctl restart warpmetald.service$' "$script" | cut -d: -f1)
snapshot_line=$(grep -n '^snapshot_host_workloads$' "$script" | cut -d: -f1)
package_line=$(grep -n '^  install_apt_packages$' "$script" | cut -d: -f1)
runtime_user_line=$(grep -n '^getent passwd warpmetal-runtime ' "$script" | cut -d: -f1)
apparmor_load_line=$(grep -n '^[[:space:]]*if ! warpmetal_install_apparmor_policy ' "$script" | cut -d: -f1)
last_workload_assert_line=$(grep -n '^[[:space:]]*assert_host_workloads_unchanged$' "$script" | tail -n 1 | cut -d: -f1)

test -n "$register_line"
test -n "$podman_start_line"
test -n "$enable_line"
test -n "$restart_line"
test -n "$snapshot_line"
test -n "$package_line"
test -n "$runtime_user_line"
test -n "$apparmor_load_line"
test -n "$last_workload_assert_line"
test "$podman_start_line" -lt "$register_line"
test "$register_line" -lt "$enable_line"
test "$enable_line" -lt "$restart_line"
test "$snapshot_line" -lt "$package_line"
test "$package_line" -lt "$runtime_user_line"
test "$package_line" -lt "$apparmor_load_line"
test "$apparmor_load_line" -lt "$runtime_user_line"
test "$last_workload_assert_line" -lt "$register_line"
reject_match -F 'systemctl enable --now warpmetald.service' "$script"
reject_match -Fq 'systemctl restart warpmetal-podman.service' "$script"
grep -Fq 'systemctl start warpmetal-podman.service' "$script"
grep -Fq "apt_packages='podman crun uidmap" "$script"
grep -Fq "dnf_packages='podman crun shadow-utils" "$script"
grep -Fq 'iptables util-linux' "$script"
reject_match -Eq 'apt_packages=.*runc|dnf_packages=.*runc' "$script"
reject_match -Fq 'linux-generic' "$script"
grep -Fq 'almalinux:9|almalinux:9.*|rocky:9|rocky:9.*' "$script"
grep -Fq 'apt-get --simulate --no-remove --no-upgrade --no-install-recommends' "$script"
grep -Fq 'apt-get install -y --no-remove --no-upgrade --no-install-recommends' "$script"
grep -Fq 'export NEEDRESTART_MODE=l' "$script"
grep -Fq -- '--setopt=tsflags=test' "$script"
grep -Fq -- '--setopt=obsoletes=False' "$script"
grep -Fq 'set -- "--exclude=$protected_exclude" "$@"' "$script"
reject_match -Fq -- '--allowerasing' "$script"
grep -Fq 'fail_install runtime_reboot_required 75' "$script"
grep -Fq 'fail_install runtime_package_plan_unsafe' "$script"
grep -Fq 'fail_install runtime_package_postcondition_failed' "$script"
grep -Fq 'fail_install runtime_workload_state_unverifiable' "$script"
grep -Fq 'fail_install runtime_workload_drift_detected' "$script"
grep -Fq 'flock -n 9 || fail_install runtime_install_in_progress' "$script"
grep -Fq -- "--format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.State.Running}}'" "$script"
reject_match -Eq '\{\{\.(Name|Config|Image|Mounts)' "$script"
test "$(grep -Ec '^[[:space:]]*assert_host_workloads_unchanged$' "$script")" -eq 4
grep -Fq 'systemctl show --property MainPID --value warpmetal-podman.service' "$script"
grep -Fq 'is_warpmetal_podman_service_process "$process_id" && continue' "$script"
grep -Fq "grep -Eq '^0::/system[.]slice/warpmetal-podman[.]service(/|$)'" "$script"
grep -Fq '"/proc/$process_id/cgroup"' "$script"
grep -Fq 'xargs -n 128' "$script"
grep -Fq 'package_apply_status=$?' "$script"
test "$(grep -Fc 'package_apply_status=$?' "$script")" -eq 2
grep -Fq 'apt apt-utils dpkg docker-ce' "$script"
grep -Fq 'dnf dnf5 rpm rpm-libs libdnf libdnf5 docker-ce' "$script"
grep -Fq 'containerd.io containerd' "$script"
grep -Fq '[ -x /usr/sbin/iptables ] && [ -x /usr/sbin/ip6tables ]' "$script"
grep -Fq "'%{NAME}.%{ARCH}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n'" "$script"
grep -Fq '"$package_arch" 2>/dev/null || true' "$script"
grep -Fq 'gateway_home=/var/empty/warpmetal-sandbox' "$script"
grep -Fq 'install -d -o root -g root -m 0755 "$gateway_home"' "$script"
grep -Fq 'usermod --home "$gateway_home" warpmetal-sandbox' "$script"
reject_match -Fq '/nonexistent' "$script"
grep -Fq 'runtime_cgroup=/sys/fs/cgroup/system.slice/warpmetal-podman.service' "$script"
grep -Fq "info --format '{{.Store.RunRoot}}'" "$script"
grep -Fq 'fail_install runtime_legacy_migration_required' "$script"
test "$(grep -Fc -- '--runtime crun' "$script")" -eq 1
test "$(grep -Fc -- '--runtime runc' "$script")" -eq 0
test "$(grep -Fc -- '--cgroup-manager cgroupfs' "$script")" -eq 1
test "$(grep -Fc 'cd /var/lib/warpmetal-runtime' "$script")" -eq 1
reject_match -Fq 'system reset --force' "$script"
reject_match -Eq 'systemctl (stop|restart) (docker|containerd)' "$script"
reject_match -Eq 'systemctl (start|stop|restart|reload) apparmor' "$script" "$apparmor_library"
reject_match -Eq 'sysctl[[:space:]]+-w|/proc/sys/.+>|/sys/module/apparmor/.+>' "$script" "$apparmor_library"
reject_match -Eq '(apt-get|dnf).*(apparmor|apparmor-utils)' "$script" "$apparmor_library"
test "$(grep -Fc 'install -d -o warpmetal-runtime -g warpmetal-runtime -m 0700 /run/warpmetal-podman' "$script")" -eq 1
grep -Fq "printf '[Service]\\nBindPaths=%s" "$script"
grep -Fq 'ReadWritePaths=/run/warpmetal-podman %s' "$script"
grep -Fq 'test -S /run/warpmetal-podman/podman.sock' "$script"
grep -Fq 'install -d -o root -g warpmetal-sandbox -m 0750 /etc/ssh/warpmetal-runtime' "$script"
grep -Fq 'install -o root -g warpmetal-sandbox -m 0640 /dev/null /etc/ssh/warpmetal-runtime/authorized_keys' "$script"
grep -Fqx 'ProtectHome=no' "$service"
grep -Fqx 'InaccessiblePaths=/home /root' "$service"
grep -Fqx 'ProtectControlGroups=yes' "$service"
grep -Fq '/etc/ssh/warpmetal-runtime' "$service"
grep -Fq 'CapabilityBoundingSet=' "$service"
grep -Fq 'CAP_SYS_ADMIN' "$service"
grep -Fq 'CAP_SYS_CHROOT' "$service"
grep -Fq 'CAP_SYS_PTRACE' "$service"
reject_match -Fqx 'ProtectHome=yes' "$service"
grep -Fqx 'User=warpmetal-runtime' "$podman_service"
grep -Fqx 'RuntimeDirectory=warpmetal-podman' "$podman_service"
grep -Fqx 'Delegate=yes' "$podman_service"
grep -Fqx 'ProtectControlGroups=no' "$podman_service"
grep -Fqx 'PrivateTmp=no' "$podman_service"
grep -Fqx 'UMask=0077' "$podman_service"
grep -Fqx 'ExecStart=/usr/libexec/warpmetal-podman-service' "$podman_service"
grep -Fqx 'cgroup_path=/sys/fs/cgroup/system.slice/warpmetal-podman.service' "$podman_launcher"
grep -Fqx '/usr/bin/mkdir "$cgroup_path/manager"' "$podman_launcher"
grep -Fqx "printf '%s\\n' \"\$\$\" > \"\$cgroup_path/manager/cgroup.procs\"" "$podman_launcher"
grep -Fq -- '--runtime crun' "$podman_launcher"
reject_match -Fq -- '--runtime runc' "$podman_launcher"
grep -Fq -- '--cgroup-manager cgroupfs' "$podman_launcher"
grep -Fq -- '--prerelease' "$release_workflow"
grep -Fq 'warpmetal_detect_apparmor_policy_requirement' "$script"
grep -Fq '/sys/module/apparmor/parameters/enabled' "$script"
grep -Fq '/proc/sys/kernel/apparmor_restrict_unprivileged_userns' "$script"
grep -Fq '/sys/kernel/security/apparmor/profiles' "$script"
grep -Fq 'fail_install runtime_apparmor_policy_unsupported' "$script"
grep -Fq 'fail_install "$warpmetal_apparmor_policy_error"' "$script"
grep -Fq 'warpmetal_apparmor_policy_committed=1' "$script"
grep -Fq 'warpmetal_rollback_apparmor_policy' "$script"
grep -Fq 'runtime_apparmor_policy_rollback_failed' "$script"
grep -Fq '"$policy_parser" -Q -K "$policy_source"' "$apparmor_library"
grep -Fq '"$policy_parser" -r -K "$policy_destination"' "$apparmor_library"
grep -Fq '"$warpmetal_apparmor_policy_parser" -R -K "$warpmetal_apparmor_policy_source"' "$apparmor_library"
grep -Fq 'cp --preserve=all -- "$policy_destination" "$policy_backup"' "$apparmor_library"
grep -Fq 'cp --preserve=all -- "$warpmetal_apparmor_policy_backup" "$rollback_staged"' "$apparmor_library"
grep -Fq '"$policy_metadata_helper" compare "$policy_destination" "$policy_backup"' "$apparmor_library"
grep -Fq '"$warpmetal_apparmor_policy_metadata_helper" compare' "$apparmor_library"
grep -Fq 'mv -f -- "$policy_staged" "$policy_destination"' "$apparmor_library"
grep -Fq 'warpmetal_read_apparmor_loaded_state' "$apparmor_library"
grep -Fq 'runtime_apparmor_state_unverifiable' "$apparmor_library"
grep -Fq 'runtime_apparmor_policy_recovery_state_preserved' "$script"
grep -Fq 'warpmetal-agent-runtime-bwrap "$stage/warpmetal-agent-runtime-bwrap"' "$release_workflow"
grep -Fq 'warpmetal-apparmor-policy.sh "$stage/warpmetal-apparmor-policy.sh"' "$release_workflow"
grep -Fq 'nested-private-procfs-oracle.sh "$stage/nested-private-procfs-oracle.sh"' "$release_workflow"
grep -Fq 'warpmetal-policy-metadata" ./cmd/warpmetal-policy-metadata' "$release_workflow"
test -s "$apparmor_profile"
test -s "$apparmor_oracle"

sh packaging/apparmor/profile_test.sh
sh packaging/install/apparmor_policy_test.sh
