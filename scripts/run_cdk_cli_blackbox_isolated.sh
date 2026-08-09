#!/usr/bin/env bash

set -euo pipefail

mode="${1:-}"
shift || true

case "$mode" in
  enter)
    if [[ "$#" -ne 8 ]]; then
      echo "usage: $0 enter UID GID GATE_ROOT NODE_DIR WORKSPACE ARCH MACHINE_ARCH NODE_ARCH" >&2
      exit 2
    fi
    if [[ "$EUID" -ne 0 ]]; then
      echo "the network namespace entrypoint must run as root" >&2
      exit 1
    fi

    readonly sandbox_uid="$1"
    readonly sandbox_gid="$2"
    readonly gate_root="$3"
    readonly node_dir="$4"
    readonly workspace="$5"
    readonly result_arch="$6"
    readonly machine_arch="$7"
    readonly node_arch="$8"

    chown -R "$sandbox_uid:$sandbox_gid" "$gate_root"
    chmod 0755 "$gate_root" "$gate_root/home" "$gate_root/tmp"
    mount --make-rprivate /
    mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
    mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp
    ip link set lo up
    exec setpriv \
      --reuid="$sandbox_uid" \
      --regid="$sandbox_gid" \
      --clear-groups \
      --no-new-privs \
      --inh-caps=-all \
      --ambient-caps=-all \
      --bounding-set=-all \
      env -i \
        HOME="$gate_root/home" \
        TMPDIR="$gate_root/tmp" \
        PATH="$node_dir:/usr/sbin:/usr/bin:/sbin:/bin" \
        GATE_ROOT="$gate_root" \
        WORKSPACE="$workspace" \
        RESULT_ARCH="$result_arch" \
        CDK_EXPECTED_MACHINE_ARCH="$machine_arch" \
        CDK_EXPECTED_NODE_ARCH="$node_arch" \
        PYTHONDONTWRITEBYTECODE=1 \
        PYTHONNOUSERSITE=1 \
        TEST_TARGET=LOCALSTACK \
        CDK_REAL_CLI_REQUIRED=1 \
        AWS_ACCESS_KEY_ID=test \
        AWS_SECRET_ACCESS_KEY=test \
        AWS_EC2_METADATA_DISABLED=true \
        AWS_CONFIG_FILE=/dev/null \
        AWS_SHARED_CREDENTIALS_FILE=/dev/null \
        DISABLE_EVENTS=1 \
        DNS_PORT=4513 \
        "$workspace/scripts/run_cdk_cli_blackbox_isolated.sh" run
    ;;
  run)
    if [[ "$#" -ne 0 ]]; then
      echo "usage: $0 run" >&2
      exit 2
    fi
    if [[ "$(id -u)" -eq 0 ]]; then
      echo "the CDK gate must not run as root" >&2
      exit 1
    fi
    if [[ -w "$WORKSPACE" ]]; then
      echo "the CDK gate can write to the checked-out workspace" >&2
      exit 1
    fi
    if [[ -w /home/runner/work/_temp/_runner_file_commands ]]; then
      echo "the CDK gate can write GitHub Actions file commands" >&2
      exit 1
    fi
    if find /run /tmp -type s -print -quit | grep -q .; then
      echo "the CDK gate inherited a host Unix socket" >&2
      exit 1
    fi

    readonly interfaces="$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n')"
    if [[ "$interfaces" != "lo" ]]; then
      echo "unexpected network interfaces: $interfaces" >&2
      exit 1
    fi
    if [[ -n "$(ip -4 route show default)" || -n "$(ip -6 route show default)" ]]; then
      echo "the CDK gate network namespace has a default route" >&2
      exit 1
    fi
    if [[ -S /var/run/docker.sock && -w /var/run/docker.sock ]]; then
      echo "Docker socket remains writable inside the CDK gate" >&2
      exit 1
    fi

    cd "$WORKSPACE"
    exec .venv/bin/python -m pytest -q \
      --junitxml="$GATE_ROOT/pytest-junit-cdk-cli-$RESULT_ARCH.xml" \
      tests/aws/cli/test_cdk_cli_blackbox.py
    ;;
  *)
    echo "usage: $0 {enter|run}" >&2
    exit 2
    ;;
esac
