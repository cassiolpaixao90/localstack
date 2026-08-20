#!/usr/bin/env bash
# CDK Docker lifecycle gate: runs the real pinned CDK CLI deploy/update/no-op/destroy
# lifecycle against a throwaway LocalStack Docker container, including a container
# restart phase and zero-residue assertions.
#
# Required: docker, the repo .venv, Node on PATH, npm ci in tests/aws/cli.
# Optional env:
#   CDK_DOCKER_GATE_IMAGE    image to test (default: localstack/localstack:current)
#   CDK_DOCKER_GATE_BUILD=1  build the image via bin/docker-helper.sh when missing
#   CDK_DOCKER_GATE_OVERLAY=1  bind-mount this checkout's localstack-core over the
#                              image's source (fast iteration without image rebuild)
#   CDK_EXPECTED_NODE_VERSION  relax the Node pin outside required CI lanes
#   CDK_DOCKER_GATE_KEEP=1   keep container and state for debugging
set -euo pipefail

cd "$(dirname "$0")/.."

image="${CDK_DOCKER_GATE_IMAGE:-localstack/localstack:current}"
if ! docker image inspect "$image" >/dev/null 2>&1; then
  if [[ "${CDK_DOCKER_GATE_BUILD:-0}" == "1" ]]; then
    IMAGE_NAME="$image" ./bin/docker-helper.sh build
  else
    echo "image $image not found; set CDK_DOCKER_GATE_BUILD=1 to build it" >&2
    exit 2
  fi
fi

suffix="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
container="ls-cdk-docker-gate-${suffix}"
state_dir="$(mktemp -d "${TMPDIR:-/tmp}/ls-cdk-docker-gate.XXXXXX")"
mkdir -p target
log_file="target/cdk-docker-gate-${suffix}.log"

port="$("${PYTHON:-.venv/bin/python}" -c "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()")"
endpoint="http://127.0.0.1:${port}"

cleanup() {
  status=$?
  docker logs "$container" >"$log_file" 2>&1 || true
  if [[ "${CDK_DOCKER_GATE_KEEP:-0}" != "1" ]]; then
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf "$state_dir"
  fi
  echo "container log: $log_file" >&2
  exit $status
}
trap cleanup EXIT

overlay_args=()
if [[ "${CDK_DOCKER_GATE_OVERLAY:-0}" == "1" ]]; then
  overlay_args=(-v "$PWD/localstack-core:/opt/code/localstack/localstack-core:ro")
fi

echo "starting $container from $image on $endpoint" >&2
docker run -d --name "$container" \
  -p "127.0.0.1:${port}:4566" \
  -v "$state_dir:/var/lib/localstack" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ${overlay_args[@]+"${overlay_args[@]}"} \
  -e PERSISTENCE=1 \
  -e DEBUG="${DEBUG:-0}" \
  "$image" >/dev/null

deadline=$((SECONDS + 120))
until curl -sf "$endpoint/_localstack/health" >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "container did not become healthy within 120s" >&2
    exit 1
  fi
  sleep 1
done

CDK_DOCKER_GATE_ENDPOINT="$endpoint" \
CDK_DOCKER_GATE_CONTAINER="$container" \
TEST_TARGET=LOCALSTACK \
"${PYTHON:-.venv/bin/python}" -m pytest -q \
  --junitxml="target/pytest-junit-cdk-docker-gate-${suffix}.xml" \
  tests/aws/cli/test_cdk_cli_docker_lifecycle.py
