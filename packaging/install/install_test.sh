#!/bin/sh
set -eu

script=packaging/install/install.sh
service=packaging/systemd/warpmetald.service
register_line=$(grep -n '^/usr/local/sbin/warpmetald register ' "$script" | cut -d: -f1)
enable_line=$(grep -n '^systemctl enable warpmetald.service$' "$script" | cut -d: -f1)
restart_line=$(grep -n '^systemctl restart warpmetald.service$' "$script" | cut -d: -f1)

test -n "$register_line"
test -n "$enable_line"
test -n "$restart_line"
test "$register_line" -lt "$enable_line"
test "$enable_line" -lt "$restart_line"
! grep -F 'systemctl enable --now warpmetald.service' "$script"
grep -Fq 'runtime_cgroup=/sys/fs/cgroup/user.slice/user-${runtime_uid}.slice/user@${runtime_uid}.service' "$script"
grep -Fq 'BindPaths=/run/user/%s %s' "$script"
grep -Fq 'ReadWritePaths=/run/user/%s %s' "$script"
grep -Fqx 'ProtectHome=no' "$service"
grep -Fqx 'InaccessiblePaths=/home /root' "$service"
grep -Fqx 'ProtectControlGroups=yes' "$service"
! grep -Fqx 'ProtectHome=yes' "$service"
