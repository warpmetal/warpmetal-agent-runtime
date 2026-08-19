#!/bin/sh
set -eu

script=packaging/install/install.sh
service=packaging/systemd/warpmetald.service
podman_service=packaging/systemd/warpmetal-podman.service
podman_launcher=packaging/systemd/warpmetal-podman-service
register_line=$(grep -n '^/usr/local/sbin/warpmetald register ' "$script" | cut -d: -f1)
podman_restart_line=$(grep -n '^systemctl restart warpmetal-podman.service$' "$script" | cut -d: -f1)
enable_line=$(grep -n '^systemctl enable warpmetald.service$' "$script" | cut -d: -f1)
restart_line=$(grep -n '^systemctl restart warpmetald.service$' "$script" | cut -d: -f1)

test -n "$register_line"
test -n "$podman_restart_line"
test -n "$enable_line"
test -n "$restart_line"
test "$podman_restart_line" -lt "$register_line"
test "$register_line" -lt "$enable_line"
test "$enable_line" -lt "$restart_line"
! grep -F 'systemctl enable --now warpmetald.service' "$script"
grep -Fq 'podman runc uidmap' "$script"
grep -Fq 'podman runc shadow-utils' "$script"
grep -Fq 'iptables util-linux' "$script"
grep -Fq 'apt-get install -y -qq linux-generic' "$script"
grep -Fq 'almalinux:9|almalinux:9.*|rocky:9|rocky:9.*' "$script"
grep -Fq 'dnf install -y -q' "$script"
grep -Fq 'echo "runtime_reboot_required"' "$script"
grep -Fq 'exit 75' "$script"
grep -Fq 'gateway_home=/var/empty/warpmetal-sandbox' "$script"
grep -Fq 'install -d -o root -g root -m 0755 "$gateway_home"' "$script"
grep -Fq 'usermod --home "$gateway_home" warpmetal-sandbox' "$script"
! grep -Fq '/nonexistent' "$script"
grep -Fq 'runtime_cgroup=/sys/fs/cgroup/system.slice/warpmetal-podman.service' "$script"
grep -Fq "info --format '{{.Store.RunRoot}}'" "$script"
grep -Fq 'legacy_runroot="/run/user/${runtime_uid}/containers"' "$script"
grep -Fq 'podman --runroot "$legacy_runroot"' "$script"
grep -Fq 'if [ "$legacy_current_runroot" = "$legacy_runroot" ]; then' "$script"
grep -Fq 'reset_runroot=$legacy_runroot' "$script"
grep -Fq 'podman --runroot "$reset_runroot"' "$script"
test "$(grep -Fc -- '--runtime runc' "$script")" -eq 3
test "$(grep -Fc -- '--cgroup-manager cgroupfs' "$script")" -eq 3
test "$(grep -Fc 'cd /var/lib/warpmetal-runtime' "$script")" -eq 3
grep -Fq 'system reset --force' "$script"
test "$(grep -Fc 'install -d -o warpmetal-runtime -g warpmetal-runtime -m 0700 /run/warpmetal-podman' "$script")" -eq 2
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
! grep -Fqx 'ProtectHome=yes' "$service"
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
grep -Fq -- '--cgroup-manager cgroupfs' "$podman_launcher"
