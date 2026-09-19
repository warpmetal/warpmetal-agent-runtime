#!/bin/sh
set -eu

installer=packaging/install/install.sh
release_workflow=.github/workflows/release.yml
runtime_readme=README.md
security_policy=SECURITY.md

fail() {
  echo "$1" >&2
  exit 1
}

require_document_fact() {
  document=$1
  pattern=$2
  fact=$3
  grep -Eiq "$pattern" "$document" || \
    fail "missing Runtime documentation fact in $document: $fact"
}

for document in "$runtime_readme" "$security_policy"
do
  [ -s "$document" ] || fail "missing future Runtime documentation: $document"
  require_document_fact \
    "$document" \
    'rootless Podman.*(container|sandbox).*(boundary|isolation)|outer.*rootless Podman.*boundary' \
    'the rootless Podman container is the outer Runtime boundary'
  require_document_fact \
    "$document" \
    'UID(/GID)?[[:space:]]+1000|UID[[:space:]]+and[[:space:]]+GID[[:space:]]+1000|1000:1000' \
    'sandbox processes run as UID/GID 1000'
  require_document_fact \
    "$document" \
    'read-only[- ]root|read-only[[:space:]]+root' \
    'the sandbox root filesystem is read-only'
  require_document_fact \
    "$document" \
    'persistent[^.\n]*/home/agent|/home/agent[^.\n]*persistent' \
    '/home/agent is the persistent workspace'
  require_document_fact \
    "$document" \
    'no host (container-engine|container runtime|runtime) socket|without host (runtime )?sockets' \
    'no host container-runtime socket is exposed'
  require_document_fact \
    "$document" \
    'owner[^.\n]*responsib|user[^.\n]*responsib|user owns|user-owned' \
    'users own software configuration and credentials'
  require_document_fact "$document" 'setup operation|setup materializer' \
    'setup is a closed, explicit operation'
  require_document_fact "$document" '/usr/local/libexec/warpmetal-bwrap' \
    'nested policy attaches only to the exact immutable helper'
done

if grep -Eiq \
  'allToolsInstalled|toolManifest|tool readiness' \
  "$runtime_readme" "$security_policy"; then
  fail 'Runtime documentation retains retired tool-report readiness promises'
fi

for base_source in \
  cmd/warpmetald/main.go \
  cmd/warpmetal-agentctl/main.go \
  cmd/warpmetal-sandbox-gateway/main.go \
  cmd/warpmetal-sandbox-shell/main.go \
  packaging/install/install.sh \
  packaging/systemd/warpmetal-podman-service \
  packaging/systemd/warpmetal-podman.service \
  packaging/systemd/warpmetald.service \
  packaging/sshd/warpmetal-sandbox.conf
do
  [ -s "$base_source" ] || fail "missing future Runtime base source: $base_source"
done

[ ! -e internal/toolreport ] || fail 'retired image tool-report executor remains'

if grep -Eiq 'tool[_-]report|apparmor=unconfined|seccomp=unconfined|CAP_SYS_ADMIN|sysctl[[:space:]]+-w' \
  "$installer" "$release_workflow"; then
  fail 'installer or release workflow weakens isolation or executes retired tool reports'
fi

# The signed bundle supplies the only policy and metadata helper; no manifest,
# workspace, environment override, or mutable download can select another path.
grep -Fqx 'nested_private_procfs=preserve' "$installer" || fail 'policy default is not preserve'
grep -Fqx '      apparmor_policy_destination=/etc/apparmor.d/warpmetal-agent-runtime-bwrap' "$installer" || fail 'policy destination is not closed'
grep -Fqx '      apparmor_metadata_helper=$bundle_dir/warpmetal-policy-metadata' "$installer" || fail 'metadata helper is not bundle-owned'
sh packaging/apparmor/profile_test.sh

if find cmd internal -type f -name '*.go' ! -name '*_test.go' \
  -exec grep -HnE 'ToolReport|toolreport|warpmetal-agent-tool-report' {} +; then
  fail 'future Runtime production Go source retains image tool-report execution'
fi

actual_members=$(
  sed -n 's/.*"\$stage\/\([^"]*\)".*/\1/p' "$release_workflow" | LC_ALL=C sort
)
expected_members=$(cat <<'EOF'
install.sh
nested-private-procfs-oracle.sh
warpmetal-agent-runtime-bwrap
warpmetal-agentctl
warpmetal-apparmor-policy.sh
warpmetal-podman-service
warpmetal-podman.service
warpmetal-policy-metadata
warpmetal-sandbox-gateway
warpmetal-sandbox-shell
warpmetal-sandbox.conf
warpmetald
warpmetald.service
EOF
)
if [ "$actual_members" != "$expected_members" ]; then
  printf 'future Runtime archive members differ\nactual:\n%s\nexpected:\n%s\n' \
    "$actual_members" "$expected_members" >&2
  exit 1
fi

grep -Fq 'tar -C dist -czf "dist/${archive}" "$(basename "$stage")"' "$release_workflow" || \
  fail 'release workflow no longer archives the exact staged Runtime directory'
