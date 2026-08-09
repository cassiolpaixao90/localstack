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
    readonly sandbox_workspace="/mnt/localstack-cdk-workspace"
    readonly sandbox_gate_root="/mnt/localstack-cdk-gate"

    chmod -R o+rX,o-w "$workspace"
    mkdir -p "$gate_root/filesystem/usr/lib/localstack"
    chown -R "$sandbox_uid:$sandbox_gid" "$gate_root"
    chmod 0755 "$gate_root" "$gate_root/home" "$gate_root/tmp"
    mount --make-rprivate /
    mkdir -p "$sandbox_workspace" "$sandbox_gate_root"
    mount --bind "$workspace" "$sandbox_workspace"
    mount -o remount,bind,ro,nosuid,nodev "$sandbox_workspace"
    mount --bind "$gate_root" "$sandbox_gate_root"
    mount -o remount,bind,rw,nosuid,nodev "$sandbox_gate_root"
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
        HOME="$sandbox_gate_root/home" \
        TMPDIR="$sandbox_gate_root/tmp" \
        PATH="$node_dir:/usr/sbin:/usr/bin:/sbin:/bin" \
        GATE_ROOT="$sandbox_gate_root" \
        WORKSPACE="$sandbox_workspace" \
        RESULT_ARCH="$result_arch" \
        CDK_EXECUTION_RECEIPT="$sandbox_gate_root/cdk-execution-receipt-$result_arch.json" \
        CDK_EXPECTED_MACHINE_ARCH="$machine_arch" \
        CDK_EXPECTED_NODE_ARCH="$node_arch" \
        FILESYSTEM_ROOT="$sandbox_gate_root/filesystem" \
        PYTHONDONTWRITEBYTECODE=1 \
        PYTHONNOUSERSITE=1 \
        PYTHONPATH="$sandbox_workspace/localstack-core" \
        TEST_TARGET=LOCALSTACK \
        CDK_REAL_CLI_REQUIRED=1 \
        AWS_ACCESS_KEY_ID=test \
        AWS_SECRET_ACCESS_KEY=test \
        AWS_EC2_METADATA_DISABLED=true \
        AWS_CONFIG_FILE=/dev/null \
        AWS_SHARED_CREDENTIALS_FILE=/dev/null \
        DISABLE_EVENTS=1 \
        DNS_PORT=4513 \
        /bin/bash "$sandbox_workspace/scripts/run_cdk_cli_blackbox_isolated.sh" run
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

    if ! interfaces="$(ip -o link show | awk -F': ' '{print $2}')"; then
      echo "failed to enumerate network interfaces" >&2
      exit 1
    fi
    readonly interfaces
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
