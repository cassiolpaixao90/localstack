import json
from pathlib import Path

import pytest
from tests.aws.cli.test_cdk_cli_blackbox import (
    MAX_YAML_ALIASES,
    MAX_YAML_DEPTH,
    MAX_YAML_NODES,
    _load_bounded_yaml,
    _validate_required_network_isolation,
    _validate_required_target,
)
from tests.aws.cli.validate_junit import MAX_JUNIT_BYTES, validate_junit

PROJECT_ROOT = Path(__file__).parents[3]
TOOLCHAIN_ROOT = PROJECT_ROOT / "tests/aws/cli"
WORKFLOW_PATH = PROJECT_ROOT / ".github/workflows/cdk-cli-blackbox.yml"
ISOLATED_RUNNER_PATH = PROJECT_ROOT / "scripts/run_cdk_cli_blackbox_isolated.sh"


def test_cdk_cli_blackbox_toolchain_is_exactly_pinned():
    package = json.loads((TOOLCHAIN_ROOT / "package.json").read_text())
    lock = json.loads((TOOLCHAIN_ROOT / "package-lock.json").read_text())

    assert package == {
        "name": "localstack-cdk-cli-blackbox",
        "private": True,
        "version": "0.0.0",
        "engines": {"node": "22.23.2"},
        "devDependencies": {"aws-cdk": "2.1135.1"},
    }
    assert lock["lockfileVersion"] == 3
    assert lock["packages"][""] == {
        key: value for key, value in package.items() if key != "private"
    }
    locked = lock["packages"]["node_modules/aws-cdk"]
    assert locked["version"] == "2.1135.1"
    assert locked["resolved"] == "https://registry.npmjs.org/aws-cdk/-/aws-cdk-2.1135.1.tgz"
    assert locked["integrity"] == (
        "sha512-g1jcMfWlyYtGamFJ/kPBOCuchl3NfwTF2UwOLTIDN0nJbGm84EAO+c8DlYnaemM8"
        "UmKFkdoq4BGdmiNL5nHWwA=="
    )


def test_cdk_cli_blackbox_ci_matrix_is_pinned_and_network_isolated():
    workflow = _load_bounded_yaml(WORKFLOW_PATH.read_text())
    job = workflow["jobs"]["cdk-cli-blackbox"]

    assert workflow[True] == {"push": {"branches": ["main"]}}
    assert workflow["permissions"] == {"contents": "read"}
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["matrix"]["include"] == [
        {
            "runner": "ubuntu-24.04",
            "arch": "amd64",
            "machine_arch": "x86_64",
            "node_arch": "x64",
        },
        {
            "runner": "ubuntu-24.04-arm",
            "arch": "arm64",
            "machine_arch": "aarch64",
            "node_arch": "arm64",
        },
    ]
    assert job["runs-on"] == "${{ matrix.runner }}"

    steps = {step["name"]: step for step in job["steps"]}
    checkout = steps["Checkout"]
    assert checkout["uses"] == "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
    assert checkout["with"]["persist-credentials"] is False
    node_setup = steps["Set up pinned Node"]
    assert node_setup["uses"] == "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38"
    assert node_setup["with"] == {
        "node-version": "22.23.2",
        "package-manager-cache": "false",
    }
    isolated_run = steps["Run CDK gate without external egress"]["run"]
    assert "sudo timeout" in isolated_run
    assert "unshare --net --pid --fork --kill-child=KILL --mount-proc" in isolated_run
    assert "scripts/run_cdk_cli_blackbox_isolated.sh" in isolated_run
    assert 'sudo chown -R "$host_uid:$host_gid" "$gate_root"' in isolated_run

    isolated_runner = ISOLATED_RUNNER_PATH.read_text()
    assert 'chmod -R o+rX,o-w "$workspace"' in isolated_runner
    assert 'mkdir -p "$gate_root/filesystem/usr/lib/localstack"' in isolated_runner
    assert 'mount --bind "$workspace" "$sandbox_workspace"' in isolated_runner
    assert 'mount -o remount,bind,ro,nosuid,nodev "$sandbox_workspace"' in isolated_runner
    assert 'mount --bind "$gate_root" "$sandbox_gate_root"' in isolated_runner
    assert '/bin/bash "$sandbox_workspace/scripts/run_cdk_cli_blackbox_isolated.sh" run' in (
        isolated_runner
    )
    assert "ip link set lo up" in isolated_runner
    assert "mount --make-rprivate /" in isolated_runner
    assert "mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run" in isolated_runner
    assert "mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp" in isolated_runner
    assert "setpriv" in isolated_runner
    assert "--clear-groups" in isolated_runner
    assert "--no-new-privs" in isolated_runner
    assert "--inh-caps=-all" in isolated_runner
    assert "--ambient-caps=-all" in isolated_runner
    assert "--bounding-set=-all" in isolated_runner
    assert "env -i" in isolated_runner
    assert 'PATH="$node_dir:/usr/sbin:/usr/bin:/sbin:/bin"' in isolated_runner
    assert 'PYTHONPATH="$sandbox_workspace/localstack-core"' in isolated_runner
    assert 'FILESYSTEM_ROOT="$sandbox_gate_root/filesystem"' in isolated_runner
    assert 'CDK_EXECUTION_RECEIPT="$sandbox_gate_root/cdk-execution-receipt-$result_arch.json"' in (
        isolated_runner
    )
    assert "TEST_TARGET=LOCALSTACK" in isolated_runner
    assert "CDK_REAL_CLI_REQUIRED=1" in isolated_runner
    assert 'if [[ -w "$WORKSPACE" ]]' in isolated_runner
    assert "/home/runner/work/_temp/_runner_file_commands" in isolated_runner
    assert "find /run /tmp -type s" in isolated_runner
    assert "ip -o link show" in isolated_runner
    assert "/sys/class/net" not in isolated_runner
    assert "sub(/@.*/" not in isolated_runner
    assert 'readonly interfaces="$' not in isolated_runner
    assert "readonly interfaces" in isolated_runner
    assert steps["Archive lane result"]["uses"] == (
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    )
    assert steps["Reject workflow reruns"]["run"] == 'test "${{ github.run_attempt }}" = 1'

    aggregator = workflow["jobs"]["cdk-cli-blackbox-complete"]
    assert aggregator["needs"] == "cdk-cli-blackbox"
    aggregate_steps = {step["name"]: step for step in aggregator["steps"]}
    assert aggregate_steps["Download architecture results"]["uses"] == (
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
    )
    assert aggregate_steps["Download architecture results"]["with"]["merge-multiple"] is False
    aggregate_run = aggregate_steps["Require the complete passing matrix"]["run"]
    assert 'test "${#downloaded[@]}" -eq 4' in aggregate_run
    assert 'test "${#reports[@]}" -eq 2' in aggregate_run
    assert "pytest-junit-cdk-cli-amd64.xml" in aggregate_run
    assert "pytest-junit-cdk-cli-arm64.xml" in aggregate_run
    assert 'test "${{ github.run_attempt }}" = 1' in aggregate_run
    assert aggregate_steps["Attest candidate evidence"]["uses"] == (
        "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26"
    )
    assert aggregator["permissions"] == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
        "artifact-metadata": "write",
    }
    assert aggregate_steps["Archive candidate evidence"]["with"]["retention-days"] == 90


def test_required_cdk_cli_gate_rejects_external_network_interfaces():
    _validate_required_network_isolation(False, "darwin", {"lo0", "en0"})
    _validate_required_network_isolation(True, "linux", {"lo"})

    with pytest.raises(pytest.UsageError, match="only the loopback interface"):
        _validate_required_network_isolation(True, "linux", {"eth0", "lo"})
    with pytest.raises(pytest.UsageError, match="only the loopback interface"):
        _validate_required_network_isolation(True, "darwin", {"lo0"})


@pytest.mark.parametrize("test_target", [None, "AWS_CLOUD"])
def test_required_cdk_cli_gate_requires_an_explicit_localstack_target(test_target):
    with pytest.raises(pytest.UsageError, match="TEST_TARGET=LOCALSTACK"):
        _validate_required_target(True, test_target)


def test_cdk_cli_yaml_loader_rejects_duplicate_keys():
    with pytest.raises(ValueError, match="duplicate mapping key"):
        _load_bounded_yaml("Description: malicious\nDescription: expected\n")


def test_cdk_cli_yaml_loader_rejects_excessive_aliases():
    aliases = "\n".join(f"alias{index}: *value" for index in range(MAX_YAML_ALIASES + 1))

    with pytest.raises(ValueError, match="alias limit"):
        _load_bounded_yaml(f"value: &value safe\n{aliases}\n")


def test_cdk_cli_yaml_loader_rejects_excessive_depth():
    nested = "[" * (MAX_YAML_DEPTH + 1) + "safe" + "]" * (MAX_YAML_DEPTH + 1)

    with pytest.raises(ValueError, match="nesting limit"):
        _load_bounded_yaml(f"value: {nested}\n")


def test_cdk_cli_yaml_loader_rejects_excessive_nodes():
    wide_sequence = ",".join("safe" for _ in range(MAX_YAML_NODES))

    with pytest.raises(ValueError, match="node limit"):
        _load_bounded_yaml(f"value: [{wide_sequence}]\n")


def test_cdk_cli_junit_validator_accepts_exact_pass(tmp_path):
    report = tmp_path / "report.xml"
    report.write_text(
        '<testsuites tests="1" failures="0" errors="0" skipped="0">'
        '<testsuite name="cdk-cli" tests="1" failures="0" errors="0" skipped="0">'
        '<testcase classname="tests.aws.cli.test_cdk_cli_blackbox" '
        'name="test_cdk_cli_bootstrap_show_template_matches_pinned_v32" />'
        "</testsuite></testsuites>"
    )

    validate_junit(report)


def test_cdk_cli_junit_validator_rejects_oversize_and_fifo_without_blocking(tmp_path):
    oversized = tmp_path / "oversized.xml"
    oversized.write_bytes(b" " * (MAX_JUNIT_BYTES + 1))
    fifo = tmp_path / "report.fifo"
    import os

    os.mkfifo(fifo)

    with pytest.raises(ValueError, match="size"):
        validate_junit(oversized)
    with pytest.raises(ValueError, match="regular file"):
        validate_junit(fifo)


@pytest.mark.parametrize(
    "testcase",
    [
        '<testcase classname="tests.aws.cli.test_cdk_cli_blackbox" '
        'name="test_cdk_cli_bootstrap_show_template_matches_pinned_v32"><skipped /></testcase>',
        '<testcase classname="tests.aws.cli.test_cdk_cli_blackbox" '
        'name="test_cdk_cli_bootstrap_show_template_matches_pinned_v32"><failure /></testcase>',
        '<testcase classname="tests.aws.cli.test_cdk_cli_blackbox" name="unexpected" />',
    ],
)
def test_cdk_cli_junit_validator_rejects_non_promotable_results(tmp_path, testcase):
    report = tmp_path / "report.xml"
    report.write_text(f"<testsuites><testsuite>{testcase}</testsuite></testsuites>")

    with pytest.raises(ValueError):
        validate_junit(report)
