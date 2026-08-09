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
from tests.aws.cli.test_cdk_cli_bootstrap_upgrade import (
    _attach_external_policy,
    _load_template_body,
    _validate_role_names,
    _validated_role_identities,
)
from tests.aws.cli.test_cdk_cli_bootstrap_upgrade import (
    _require as _require_bootstrap_upgrade,
)
from tests.aws.cli.test_cdk_cli_bootstrap_upgrade import (
    _validate_required_target as _validate_bootstrap_upgrade_target,
)
from tests.aws.cli.test_cdk_cli_python_synth import _python_interpreter_path
from tests.aws.cli.validate_junit import EXPECTED_TESTS, MAX_JUNIT_BYTES, validate_junit

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
    assert job["timeout-minutes"] == 15
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
    step_names = [step["name"] for step in job["steps"]]
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
    assert "sudo timeout --signal=TERM --kill-after=10s 420s" in isolated_run
    assert "unshare --net --pid --fork --kill-child=KILL --mount-proc" in isolated_run
    assert "scripts/run_cdk_cli_blackbox_isolated.sh" in isolated_run
    for github_value in (
        "github.repository",
        "github.sha",
        "github.ref",
        "github.event_name",
        "github.run_id",
        "github.run_attempt",
    ):
        assert github_value in isolated_run
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
    assert (
        "tests/aws/cli/test_cdk_cli_blackbox.py::"
        "test_cdk_cli_bootstrap_show_template_matches_pinned_v32" in isolated_runner
    )
    assert (
        "tests/aws/cli/test_cdk_cli_bootstrap_upgrade.py::"
        "test_cdk_cli_upgrades_api_v28_to_builtin_v32" in isolated_runner
    )
    assert "pytest-junit-cdk-bootstrap-upgrade-$RESULT_ARCH.xml" in isolated_runner
    assert "--scenario bootstrap-upgrade-v28-v32" in isolated_runner
    assert "CDK_BOOTSTRAP_UPGRADE_OBSERVATION=" in isolated_runner
    for variable in (
        "CDK_EVIDENCE_REPOSITORY",
        "CDK_EVIDENCE_COMMIT_SHA",
        "CDK_EVIDENCE_REF",
        "CDK_EVIDENCE_EVENT",
        "CDK_EVIDENCE_WORKFLOW_PATH",
        "CDK_EVIDENCE_RUN_ID",
        "CDK_EVIDENCE_RUN_ATTEMPT",
    ):
        assert variable in isolated_runner
    lane_builder = steps["Build bootstrap upgrade lane receipt"]["run"]
    assert "bootstrap_upgrade_execution_evidence.py lane" in lane_builder
    assert "cdk-bootstrap-upgrade-execution-receipt-${{ matrix.arch }}.json" in lane_builder
    assert step_names.index("Run CDK gate without external egress") < step_names.index(
        "Build bootstrap upgrade lane receipt"
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
    upgrade_lane = steps["Archive bootstrap upgrade lane result"]
    assert upgrade_lane["uses"] == (
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    )
    assert upgrade_lane["with"]["name"] == "test-results-cdk-bootstrap-upgrade-${{ matrix.arch }}"
    assert "test-results-cdk-cli-" not in upgrade_lane["with"]["name"]
    assert upgrade_lane["with"]["if-no-files-found"] == "error"
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
    assert "Download bootstrap upgrade results" in aggregate_steps
    assert "Require the passing bootstrap upgrade matrix" in aggregate_steps
    upgrade_build = aggregate_steps["Build bootstrap upgrade candidate evidence"]["run"]
    assert "bootstrap_upgrade_execution_evidence.py aggregate" in upgrade_build
    assert (
        "--scenario bootstrap-upgrade-v28-v32"
        in aggregate_steps["Require the passing bootstrap upgrade matrix"]["run"]
    )
    assert (
        aggregate_steps["Attest bootstrap upgrade candidate evidence"]["with"]["subject-path"]
        == "target/cdk-bootstrap-upgrade-execution-evidence.json"
    )
    assert (
        aggregate_steps["Archive bootstrap upgrade candidate evidence"]["with"]["name"]
        == "cdk-bootstrap-upgrade-execution-evidence"
    )


def test_cdk_python_synth_diagnostic_is_separate_and_closed():
    workflow = _load_bounded_yaml(WORKFLOW_PATH.read_text())
    job = workflow["jobs"]["cdk-cli-blackbox"]
    steps = {step["name"]: step for step in job["steps"]}
    aggregate_steps = {
        step["name"]: step for step in workflow["jobs"]["cdk-cli-blackbox-complete"]["steps"]
    }
    isolated_runner = ISOLATED_RUNNER_PATH.read_text()

    assert EXPECTED_TESTS["synth-python-minimal-sqs-v1"] == (
        "tests.aws.cli.test_cdk_cli_python_synth",
        "test_cdk_cli_synthesizes_minimal_python_sqs_app",
    )
    assert (
        "tests/aws/cli/test_cdk_cli_python_synth.py::"
        "test_cdk_cli_synthesizes_minimal_python_sqs_app" in isolated_runner
    )
    assert "pytest-junit-cdk-python-synth-$RESULT_ARCH.xml" in isolated_runner
    assert "--scenario synth-python-minimal-sqs-v1" in isolated_runner
    assert "CDK_PYTHON_SYNTH_OBSERVATION=" in isolated_runner
    assert "CDK_PYTHON_SYNTH_OUTPUT=" in isolated_runner

    lane = steps["Build Python synth lane receipt"]["run"]
    assert "python_synth_execution_evidence.py lane" in lane
    assert "--assembly-output" in lane
    assert "cdk-python-synth-observation-${{ matrix.arch }}.json" in lane
    assert "cdk-python-synth-execution-receipt-${{ matrix.arch }}.json" in lane

    artifact = steps["Archive Python synth lane result"]
    assert artifact["uses"] == ("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a")
    assert artifact["with"]["name"] == "test-results-cdk-python-synth-${{ matrix.arch }}"
    assert "test-results-cdk-cli-" not in artifact["with"]["name"]
    assert "test-results-cdk-bootstrap-upgrade-" not in artifact["with"]["name"]
    assert artifact["with"]["if-no-files-found"] == "error"
    assert "pytest-junit-cdk-python-synth-${{ matrix.arch }}.xml" in artifact["with"]["path"]
    assert "cdk-python-synth-execution-receipt-${{ matrix.arch }}.json" in artifact["with"]["path"]

    download = aggregate_steps["Download Python synth results"]
    assert download["with"] == {
        "pattern": "test-results-cdk-python-synth-*",
        "path": "target/cdk-python-synth-results",
        "merge-multiple": False,
    }
    required = aggregate_steps["Require the passing Python synth matrix"]["run"]
    assert 'test "${#downloaded[@]}" -eq 4' in required
    assert "--scenario synth-python-minimal-sqs-v1" in required
    aggregate = aggregate_steps["Build Python synth candidate evidence"]["run"]
    assert "python_synth_execution_evidence.py aggregate" in aggregate
    assert "--receipt-amd64" in aggregate and "--receipt-arm64" in aggregate
    assert (
        aggregate_steps["Attest Python synth candidate evidence"]["with"]["subject-path"]
        == "target/cdk-python-synth-execution-evidence.json"
    )
    assert (
        aggregate_steps["Archive Python synth candidate evidence"]["with"]["name"]
        == "cdk-python-synth-execution-evidence"
    )


def test_cdk_python_synth_preserves_the_virtualenv_interpreter_path(tmp_path):
    interpreter = tmp_path / "python-base"
    interpreter.write_bytes(b"")
    virtualenv_interpreter = tmp_path / "venv" / "bin" / "python"
    virtualenv_interpreter.parent.mkdir(parents=True)
    virtualenv_interpreter.symlink_to(interpreter)

    assert _python_interpreter_path(str(virtualenv_interpreter)) == virtualenv_interpreter


def test_required_cdk_cli_gate_rejects_external_network_interfaces():
    _validate_required_network_isolation(False, "darwin", {"lo0", "en0"})
    _validate_required_network_isolation(True, "linux", {"lo"})

    with pytest.raises(pytest.UsageError, match="only the loopback interface"):
        _validate_required_network_isolation(True, "linux", {"eth0", "lo"})
    with pytest.raises(pytest.UsageError, match="only the loopback interface"):
        _validate_required_network_isolation(True, "darwin", {"lo0"})


def test_optional_bootstrap_upgrade_skips_missing_prerequisites():
    with pytest.raises(pytest.skip.Exception, match="missing toolchain"):
        _require_bootstrap_upgrade(False, "missing toolchain", required=False)
    with pytest.raises(pytest.fail.Exception, match="missing toolchain"):
        _require_bootstrap_upgrade(False, "missing toolchain", required=True)


@pytest.mark.parametrize("test_target", [None, "AWS_CLOUD"])
def test_required_bootstrap_upgrade_cannot_be_skipped_by_target_marker(test_target):
    with pytest.raises(pytest.UsageError, match="TEST_TARGET=LOCALSTACK"):
        _validate_bootstrap_upgrade_target(True, test_target)


def test_bootstrap_upgrade_journals_external_policy_before_write():
    journal = []

    class Iam:
        @staticmethod
        def attach_role_policy(**kwargs):
            raise RuntimeError(f"response lost after applying {kwargs['PolicyArn']}")

    with pytest.raises(RuntimeError, match="response lost"):
        _attach_external_policy(Iam(), journal, "role", "arn:policy")

    assert journal == [("role", "arn:policy")]


def test_bootstrap_upgrade_rejects_ambiguous_template_and_malformed_role_identity():
    with pytest.raises(ValueError, match="duplicate mapping key"):
        _load_template_body("Resources: {Expected: first}\nResources: {Expected: second}\n")

    role_names = {
        "CloudFormationExecutionRole": "shared",
        "DeploymentActionRole": "shared",
        "FilePublishingRole": "file",
        "ImagePublishingRole": "image",
        "LookupRole": "lookup",
    }
    with pytest.raises(ValueError, match="non-empty and unique"):
        _validate_role_names(role_names)

    malformed_roles = {
        logical_id: {"Arn": f"arn:aws:iam::000000000000:role/{logical_id}"}
        for logical_id in role_names
    }
    with pytest.raises(ValueError, match="identity is malformed"):
        _validated_role_identities(malformed_roles)


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


def test_cdk_cli_junit_validator_accepts_exact_bootstrap_upgrade_pass(tmp_path):
    report = tmp_path / "report.xml"
    report.write_text(
        '<testsuites tests="1" failures="0" errors="0" skipped="0">'
        '<testsuite name="cdk-bootstrap-upgrade" tests="1" failures="0" errors="0" skipped="0">'
        '<testcase classname="tests.aws.cli.test_cdk_cli_bootstrap_upgrade" '
        'name="test_cdk_cli_upgrades_api_v28_to_builtin_v32" />'
        "</testsuite></testsuites>"
    )

    validate_junit(report, scenario="bootstrap-upgrade-v28-v32")


def test_cdk_cli_junit_validator_accepts_exact_python_synth_pass(tmp_path):
    report = tmp_path / "report.xml"
    report.write_text(
        '<testsuites tests="1" failures="0" errors="0" skipped="0">'
        '<testsuite name="cdk-python-synth" tests="1" failures="0" errors="0" skipped="0">'
        '<testcase classname="tests.aws.cli.test_cdk_cli_python_synth" '
        'name="test_cdk_cli_synthesizes_minimal_python_sqs_app" />'
        "</testsuite></testsuites>"
    )

    validate_junit(report, scenario="synth-python-minimal-sqs-v1")


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
