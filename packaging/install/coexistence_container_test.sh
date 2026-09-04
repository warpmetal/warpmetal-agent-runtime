#!/bin/sh
set -eu

test -f /.dockerenv || {
  echo "coexistence_test_requires_disposable_container" >&2
  exit 1
}
test "$(id -u)" -eq 0 || {
  echo "coexistence_test_requires_root" >&2
  exit 1
}

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04|debian:12)
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=l
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends ca-certificates curl
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/$ID/gpg" \
      -o /etc/apt/keyrings/docker.asc
    chmod 0644 /etc/apt/keyrings/docker.asc
    architecture=$(dpkg --print-architecture)
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
      "$architecture" "$ID" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      docker-ce docker-ce-cli containerd.io
    ;;
  almalinux:9|almalinux:9.*|rocky:9|rocky:9.*)
    dnf install -y -q dnf-plugins-core
    dnf config-manager --add-repo \
      https://download.docker.com/linux/centos/docker-ce.repo >/dev/null
    dnf install -y -q docker-ce docker-ce-cli containerd.io
    ;;
  *)
    echo "unsupported_coexistence_test_os" >&2
    exit 1
    ;;
esac

dockerd --host=unix:///var/run/docker.sock --storage-driver=vfs \
  > /tmp/warpmetal-dockerd-test.log 2>&1 &
dockerd_pid=$!
cleanup() {
  kill "$dockerd_pid" 2>/dev/null || true
  wait "$dockerd_pid" 2>/dev/null || true
}
trap cleanup 0 1 2 15

attempt=0
while ! docker info >/dev/null 2>&1 && [ "$attempt" -lt 100 ]; do
  attempt=$((attempt + 1))
  sleep 0.1
done
docker info >/dev/null 2>&1 || {
  echo "coexistence_test_docker_unavailable" >&2
  exit 1
}

docker pull -q busybox:1.36 >/dev/null
docker network create warpmetal-coexistence >/dev/null
docker run -d \
  --network warpmetal-coexistence \
  --network-alias sentinel-server \
  -p 127.0.0.1:18080:8080 \
  --restart unless-stopped \
  busybox:1.36 \
  sh -c 'mkdir -p /www && printf ok > /www/index.html && exec httpd -f -p 8080 -h /www' \
  >/dev/null
client_container=$(docker run -d \
  --network warpmetal-coexistence \
  --restart unless-stopped \
  busybox:1.36 sleep 600)
sentinel=3
while [ "$sentinel" -le 9 ]; do
  docker run -d --network none --restart unless-stopped \
    busybox:1.36 sleep 600 >/dev/null
  sentinel=$((sentinel + 1))
done

test "$(curl -fsS http://127.0.0.1:18080)" = ok
test "$(docker exec "$client_container" wget -qO- http://sentinel-server:8080)" = ok

docker ps --quiet --no-trunc > /tmp/warpmetal-docker-ids.before
test "$(wc -l < /tmp/warpmetal-docker-ids.before)" -eq 9
set --
while IFS= read -r docker_id; do
  set -- "$@" "$docker_id"
done < /tmp/warpmetal-docker-ids.before
docker inspect \
  --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.State.Running}}' \
  "$@" | sort > /tmp/warpmetal-docker-state.before

# The production installer has no test-only branch. This disposable harness
# executes its exact package/workload gate and stops at the first configuration
# statement, before users, services, SSH, registration, or supervisor state.
sed -n '1,/^command -v crun/p' /source/packaging/install/install.sh \
  > /tmp/warpmetal-package-gate.sh
chmod 0755 /tmp/warpmetal-package-gate.sh
mkdir -p /run/systemd/system /tmp/warpmetal-runtime-coexistence

if [ "${WARPMETAL_COEXISTENCE_EXPECT_DRIFT:-0}" = 1 ]; then
  [ "$ID" = ubuntu ] || {
    echo "coexistence_drift_fixture_requires_ubuntu" >&2
    exit 1
  }
  # The single-quoted lines are the literal body of the disposable wrapper.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/bin/sh' \
    '/usr/bin/apt-get "$@"' \
    'status=$?' \
    '[ "$status" -eq 0 ] || exit "$status"' \
    'if [ "$1" = install ] && [ ! -f /tmp/warpmetal-drift-injected ]; then' \
    '  /usr/bin/docker restart -t 0 "$(sed -n "1p" /tmp/warpmetal-docker-ids.before)" >/dev/null' \
    '  touch /tmp/warpmetal-drift-injected' \
    'fi' \
    'exit 0' \
    > /usr/local/bin/apt-get
  chmod 0755 /usr/local/bin/apt-get
  if /tmp/warpmetal-package-gate.sh \
    --api https://api.warpmetal.example \
    --server srv_coexistence123 \
    --bundle /tmp/warpmetal-runtime-coexistence \
    > /tmp/warpmetal-drift-result 2>&1; then
    echo "coexistence_drift_was_not_detected" >&2
    exit 1
  fi
  grep -Fx runtime_workload_drift_detected /tmp/warpmetal-drift-result >/dev/null
  printf 'coexistence_drift_gate_passed %s %s\n' "$ID" "$VERSION_ID"
  exit 0
fi

/tmp/warpmetal-package-gate.sh \
  --api https://api.warpmetal.example \
  --server srv_coexistence123 \
  --bundle /tmp/warpmetal-runtime-coexistence

set --
while IFS= read -r docker_id; do
  set -- "$@" "$docker_id"
done < /tmp/warpmetal-docker-ids.before
docker inspect \
  --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.State.Running}}' \
  "$@" | sort > /tmp/warpmetal-docker-state.after
cmp /tmp/warpmetal-docker-state.before /tmp/warpmetal-docker-state.after
test "$(curl -fsS http://127.0.0.1:18080)" = ok
test "$(docker exec "$client_container" wget -qO- http://sentinel-server:8080)" = ok
podman --runtime crun version >/dev/null
sandbox_image=${WARPMETAL_SANDBOX_TEST_IMAGE:-ghcr.io/warpmetal/warpmetal-agent-sandbox@sha256:68976f7693dd5d28ba71e20c090425d26d87b38543e83c9ff04373ee2081b026}
mkdir -p /tmp/warpmetal-podman-root /tmp/warpmetal-podman-run
podman \
  --root /tmp/warpmetal-podman-root \
  --runroot /tmp/warpmetal-podman-run \
  --storage-driver vfs \
  --runtime crun \
  --cgroup-manager cgroupfs \
  --events-backend file \
  run --rm --pull=missing \
  --cgroups disabled \
  --read-only \
  --user 1000:1000 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --network none \
  --entrypoint /bin/sh \
  "$sandbox_image" \
  -c 'test "$(id -u)" -eq 1000 && test "$(id -g)" -eq 1000'
printf 'coexistence_gate_passed %s %s\n' "$ID" "$VERSION_ID"
