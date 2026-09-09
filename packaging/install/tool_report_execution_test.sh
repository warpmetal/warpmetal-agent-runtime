#!/bin/sh
set -eu

image='ghcr.io/warpmetal/warpmetal-agent-sandbox@sha256:c3fefa156c491c31db48c3799e21a15438f2c5c452555e49b7c37815b5aee5ba'
container="warpmetal-tool-report-test-$$"
test_root=$(mktemp -d)
workspace="$test_root/home"
report="$test_root/report.json"

cleanup() {
  docker rm --force "$container" >/dev/null 2>&1 || true
  rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

docker image inspect "$image" >/dev/null
mkdir -p "$workspace/hostile-bin"

for command in warpmetal-agent-tool-report codex claude agent; do
  printf '%s\n' '#!/bin/sh' 'touch /tmp/hostile-path-executed' \
    'printf '\''forged-output\\n'\''' > "$workspace/hostile-bin/$command"
  chmod 0755 "$workspace/hostile-bin/$command"
done

printf '%s\n' \
  'touch /tmp/hostile-profile-executed' \
  'printf '\''forged-profile-output\\n'\''' \
  'exit 97' > "$workspace/.profile"
chmod 0666 "$workspace/.profile"

docker run --detach --rm \
  --name "$container" \
  --platform linux/amd64 \
  --pull never \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 1000:1000 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --mount "type=bind,src=$workspace,dst=/home/agent" \
  "$image" \
  /usr/bin/sleep infinity >/dev/null

docker exec "$container" /usr/bin/test -w /home/agent/.profile

desired_payload='touch /tmp/desired-state-payload-executed; printf forged-desired-output'
docker exec \
  --env 'ENV=/home/agent/.profile' \
  --env 'BASH_ENV=/home/agent/.profile' \
  --env 'PATH=/home/agent/hostile-bin' \
  --env "WARPMETAL_DESIRED_STATE_PAYLOAD=$desired_payload" \
  "$container" \
  /usr/local/bin/warpmetal-agent-tool-report > "$report"

test "$(wc -c < "$report" | tr -d ' ')" -le 16384
test "$(wc -l < "$report" | tr -d ' ')" -eq 1
expected='[{"id":"codex","status":"available","version":"0.153.4"},{"id":"claude","status":"available","version":"2.1.263"},{"id":"cursor","status":"available","version":"2026.09.02-c22c1a3"}]'
test "$(sed -n '1p' "$report")" = "$expected"

docker exec "$container" /usr/bin/test ! -e /tmp/hostile-profile-executed
docker exec "$container" /usr/bin/test ! -e /tmp/hostile-path-executed
docker exec "$container" /usr/bin/test ! -e /tmp/desired-state-payload-executed
