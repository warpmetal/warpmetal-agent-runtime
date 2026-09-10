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
    'Runtime does not install|owner[^.\n]*responsib|user[^.\n]*responsib' \
    'users own software installation and Runtime does not install tools'
done

if grep -Eiq \
  'nested-private-procfs|apparmor|cliTools|tool[- ]selection|tool readiness|allToolsInstalled|toolManifest|preinstall(ed|ation)' \
  "$runtime_readme" "$security_policy"; then
  fail 'Runtime documentation retains a nested-policy or tool-selection/readiness promise'
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

for removed_source in \
  cmd/warpmetal-policy-metadata \
  internal/toolreport \
  packaging/apparmor \
  packaging/install/warpmetal-apparmor-policy.sh
do
  [ ! -e "$removed_source" ] || fail "obsolete future Runtime source remains: $removed_source"
done

if grep -Eiq 'nested-private-procfs|apparmor|warpmetal-policy-metadata|tool[_-]report' \
  "$installer" "$release_workflow"; then
  fail 'future installer or release workflow retains nested-policy/tool-report behavior'
fi

if find cmd internal -type f -name '*.go' ! -name '*_test.go' \
  -exec grep -HnE 'ToolReport|toolreport|warpmetal-agent-tool-report' {} +; then
  fail 'future Runtime production Go source retains image tool-report execution'
fi

actual_members=$(
  sed -n 's/.*"\$stage\/\([^"]*\)".*/\1/p' "$release_workflow" | LC_ALL=C sort
)
expected_members=$(cat <<'EOF'
install.sh
warpmetal-agentctl
warpmetal-podman-service
warpmetal-podman.service
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
