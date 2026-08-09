import json
import platform
from pathlib import Path

import pytest
from tests.aws.cli.bootstrap_upgrade_execution_evidence import (
    MAX_EVIDENCE_BYTES,
    PINNED_INPUTS,
    PINNED_TOOLCHAIN,
    build_aggregate_evidence,
    create_lane_receipt,
    create_observation,
    main,
    validate_aggregate_evidence,
    write_canonical_json,
)
from tests.aws.cli.test_cdk_cli_blackbox import _load_bounded_yaml, _semantic_sha256

PROJECT_ROOT = Path(__file__).parents[3]


def _write_junit(path: Path) -> None:
    path.write_text(
        '<testsuites tests="1" failures="0" errors="0" skipped="0">'
        '<testsuite name="cdk-bootstrap-upgrade" tests="1" failures="0" errors="0" '
        'skipped="0"><testcase '
        'classname="tests.aws.cli.test_cdk_cli_bootstrap_upgrade" '
        'name="test_cdk_cli_upgrades_api_v28_to_builtin_v32" />'
        "</testsuite></testsuites>"
    )


def _observation(
    tmp_path: Path,
    *,
    platform_id: str = "linux-amd64",
    run_id: int = 123456,
    commit_sha: str = "a" * 40,
    python_version: str = "3.13.7",
    kernel_release: str = "6.8.0-1021-azure",
    argv_override: list[str] | None = None,
) -> Path:
    architectures = {
        "linux-amd64": ("x86_64", "x64"),
        "linux-arm64": ("aarch64", "arm64"),
    }
    machine_arch, node_arch = architectures[platform_id]
    stack_name = "CDKToolkit-a1b2c3d4"
    qualifier = "a1b2c3d4"
    argv = [
        "bootstrap",
        "aws://000000000000/us-east-1",
        "--toolkit-stack-name",
        stack_name,
        "--qualifier",
        qualifier,
        "--bootstrap-kms-key-id",
        "AWS_MANAGED_KEY",
        "--yes",
        "--ci",
        "--no-color",
        "--no-notices",
        "--execute",
    ]
    observation = create_observation(
        platform_id=platform_id,
        machine_arch=machine_arch,
        node_arch=node_arch,
        python_version=python_version,
        kernel_release=kernel_release,
        repository="cassiolpaixao90/localstack",
        commit_sha=commit_sha,
        ref="refs/heads/main",
        event="push",
        workflow_path=".github/workflows/cdk-cli-blackbox.yml",
        run_id=run_id,
        run_attempt=1,
        account_id="000000000000",
        region="us-east-1",
        stack_name=stack_name,
        qualifier=qualifier,
        argv=argv if argv_override is None else argv_override,
        stack_id="arn:aws:cloudformation:us-east-1:000000000000:stack/example/id",
        role_identities={
            f"Role{index}": {
                "Arn": f"arn:aws:iam::000000000000:role/role-{index}",
                "RoleId": f"AROA{index:016d}",
            }
            for index in range(5)
        },
        returncode=0,
        timed_out=False,
        duration_ms=6200,
        stdout=b"upgrade complete\n",
        stderr=b"",
        stdout_bytes=17,
        stderr_bytes=0,
        stdout_truncated=False,
        stderr_truncated=False,
        observed_at="2026-08-09T02:25:30Z",
    )
    path = tmp_path / "observation.json"
    write_canonical_json(path, observation, MAX_EVIDENCE_BYTES)
    return path


def _receipt(tmp_path: Path, platform_id: str) -> tuple[Path, Path]:
    architectures = {
        "linux-amd64": ("x86_64", "x64"),
        "linux-arm64": ("aarch64", "arm64"),
    }
    machine_arch, node_arch = architectures[platform_id]
    junit = tmp_path / f"junit-{platform_id}.xml"
    _write_junit(junit)
    receipt = create_lane_receipt(
        observation_path=_observation(tmp_path / platform_id, platform_id=platform_id),
        junit_path=junit,
        platform_id=platform_id,
        machine_arch=machine_arch,
        node_arch=node_arch,
        python_version="3.13.7",
        kernel_release="6.8.0-1021-azure",
        interface_names=["lo"],
        isolation_profile_id="linux-net-pid-mount-nobody-v1",
        completed_at="2026-08-09T02:25:32Z",
        repository="cassiolpaixao90/localstack",
        commit_sha="a" * 40,
        ref="refs/heads/main",
        event="push",
        workflow_path=".github/workflows/cdk-cli-blackbox.yml",
        run_id=123456,
        run_attempt=1,
    )
    receipt_path = tmp_path / f"receipt-{platform_id}.json"
    write_canonical_json(receipt_path, receipt, MAX_EVIDENCE_BYTES)
    return receipt_path, junit


def _aggregate(tmp_path: Path, *, run_attempt: int = 1) -> dict:
    receipt_paths = {}
    junit_paths = {}
    for platform_id in ("linux-amd64", "linux-arm64"):
        receipt, junit = _receipt(tmp_path, platform_id)
        receipt_paths[platform_id] = receipt
        junit_paths[platform_id] = junit
    return build_aggregate_evidence(
        receipt_paths=receipt_paths,
        junit_paths=junit_paths,
        project_root=PROJECT_ROOT,
        repository="cassiolpaixao90/localstack",
        commit_sha="a" * 40,
        ref="refs/heads/main",
        event="push",
        workflow_path=".github/workflows/cdk-cli-blackbox.yml",
        run_id=123456,
        run_attempt=run_attempt,
    )


def test_bootstrap_upgrade_evidence_is_closed_content_addressed_and_not_promotional(tmp_path):
    evidence = _aggregate(tmp_path)

    validate_aggregate_evidence(evidence)
    schema = json.loads(
        (
            PROJECT_ROOT / "capabilities/cdk/bootstrap-upgrade-execution-evidence.schema.json"
        ).read_text()
    )
    import jsonschema

    jsonschema.validators.validator_for(schema).check_schema(schema)
    jsonschema.validate(evidence, schema)
    assert evidence["scenario"] == {
        "id": "bootstrap-upgrade-v28-v32",
        "result": "cli-pass",
        "construct_language": None,
        "cloud_assembly_produced": False,
        "resource_deployment_performed": True,
        "aws_differential": False,
        "seed_mechanism": "cloudformation-api-change-set",
        "target_template_source": "cdk-cli-built-in",
        "cleanup_required": True,
    }
    assert [lane["platform"]["id"] for lane in evidence["lanes"]] == [
        "linux-amd64",
        "linux-arm64",
    ]
    assert all(lane["cleanup"]["completed"] is True for lane in evidence["lanes"])
    assert tuple(evidence["harness"]["input_sha256"]) == PINNED_INPUTS
    assert "tests/aws/cli/execution_evidence.py" in PINNED_INPUTS
    assert evidence["promotion"]["eligible"] is False
    assert "no-bootstrap-deploy" not in evidence["promotion"]["blockers"]


def test_bootstrap_upgrade_template_pins_match_both_repository_fixtures():
    for version, prefix in ((28, "source"), (32, "target")):
        path = PROJECT_ROOT / f"tests/aws/templates/cdk_bootstrap_v{version}.yaml"
        assert (
            f"sha256:{_semantic_sha256(_load_bounded_yaml(path.read_text()))}"
            == PINNED_TOOLCHAIN[f"{prefix}_template_semantic_sha256"]
        )


def test_bootstrap_upgrade_receipt_rejects_the_show_template_junit(tmp_path):
    junit = tmp_path / "show-template.xml"
    junit.write_text(
        '<testsuites tests="1" failures="0" errors="0" skipped="0">'
        '<testsuite name="cdk-cli" tests="1" failures="0" errors="0" skipped="0">'
        '<testcase classname="tests.aws.cli.test_cdk_cli_blackbox" '
        'name="test_cdk_cli_bootstrap_show_template_matches_pinned_v32" />'
        "</testsuite></testsuites>"
    )

    with pytest.raises(ValueError, match="unexpected test"):
        create_lane_receipt(
            observation_path=_observation(tmp_path),
            junit_path=junit,
            platform_id="linux-amd64",
            machine_arch="x86_64",
            node_arch="x64",
            python_version="3.13.7",
            kernel_release="6.8.0-1021-azure",
            interface_names=["lo"],
            isolation_profile_id="linux-net-pid-mount-nobody-v1",
            completed_at="2026-08-09T02:25:32Z",
            repository="cassiolpaixao90/localstack",
            commit_sha="a" * 40,
            ref="refs/heads/main",
            event="push",
            workflow_path=".github/workflows/cdk-cli-blackbox.yml",
            run_id=123456,
            run_attempt=1,
        )


def test_bootstrap_upgrade_receipt_rejects_replayed_run_and_cross_lane_observation(tmp_path):
    junit = tmp_path / "upgrade.xml"
    _write_junit(junit)
    common = {
        "junit_path": junit,
        "platform_id": "linux-amd64",
        "machine_arch": "x86_64",
        "node_arch": "x64",
        "python_version": "3.13.7",
        "kernel_release": "6.8.0-1021-azure",
        "interface_names": ["lo"],
        "isolation_profile_id": "linux-net-pid-mount-nobody-v1",
        "completed_at": "2026-08-09T02:25:32Z",
        "repository": "cassiolpaixao90/localstack",
        "commit_sha": "a" * 40,
        "ref": "refs/heads/main",
        "event": "push",
        "workflow_path": ".github/workflows/cdk-cli-blackbox.yml",
        "run_id": 123456,
        "run_attempt": 1,
    }

    with pytest.raises(ValueError, match="different workflow run"):
        create_lane_receipt(
            observation_path=_observation(tmp_path / "old", run_id=123455),
            **common,
        )

    with pytest.raises(ValueError, match="different platform"):
        create_lane_receipt(
            observation_path=_observation(tmp_path / "arm64", platform_id="linux-arm64"),
            **common,
        )


def test_bootstrap_upgrade_lane_builder_does_not_write_before_a_passing_junit(tmp_path):
    junit = tmp_path / "failed.xml"
    junit.write_text(
        '<testsuites tests="1" failures="1" errors="0" skipped="0">'
        '<testsuite name="cdk-bootstrap-upgrade" tests="1" failures="1" errors="0" '
        'skipped="0"><testcase '
        'classname="tests.aws.cli.test_cdk_cli_bootstrap_upgrade" '
        'name="test_cdk_cli_upgrades_api_v28_to_builtin_v32"><failure /></testcase>'
        "</testsuite></testsuites>"
    )
    output = tmp_path / "receipt.json"

    with pytest.raises(ValueError, match="expected failures=0"):
        main(
            [
                "lane",
                "--observation",
                str(
                    _observation(
                        tmp_path,
                        python_version=platform.python_version(),
                        kernel_release=platform.release(),
                    )
                ),
                "--junit",
                str(junit),
                "--platform-id",
                "linux-amd64",
                "--machine-arch",
                "x86_64",
                "--node-arch",
                "x64",
                "--repository",
                "cassiolpaixao90/localstack",
                "--commit-sha",
                "a" * 40,
                "--ref",
                "refs/heads/main",
                "--event",
                "push",
                "--workflow-path",
                ".github/workflows/cdk-cli-blackbox.yml",
                "--run-id",
                "123456",
                "--run-attempt",
                "1",
                "--output",
                str(output),
            ]
        )

    assert not output.exists()


def test_bootstrap_upgrade_evidence_rejects_rerun_and_missing_lane(tmp_path):
    with pytest.raises(ValueError, match="workflow run attempt"):
        _aggregate(tmp_path, run_attempt=2)

    receipt, junit = _receipt(tmp_path, "linux-amd64")
    with pytest.raises(ValueError, match="exactly linux-amd64 and linux-arm64"):
        build_aggregate_evidence(
            receipt_paths={"linux-amd64": receipt},
            junit_paths={"linux-amd64": junit},
            project_root=PROJECT_ROOT,
            repository="cassiolpaixao90/localstack",
            commit_sha="a" * 40,
            ref="refs/heads/main",
            event="push",
            workflow_path=".github/workflows/cdk-cli-blackbox.yml",
            run_id=123456,
            run_attempt=1,
        )


def test_bootstrap_upgrade_evidence_rejects_false_cleanup_and_toolchain_tampering(tmp_path):
    evidence = _aggregate(tmp_path)
    evidence["lanes"][0]["cleanup"]["completed"] = False
    with pytest.raises(ValueError, match="cleanup"):
        validate_aggregate_evidence(evidence)

    evidence = _aggregate(tmp_path)
    evidence["toolchain"]["cdk_cli_version"] = "999.0.0"
    with pytest.raises(ValueError, match="pinned CDK toolchain"):
        validate_aggregate_evidence(evidence)


def test_bootstrap_upgrade_schema_and_runtime_reject_invalid_command_contract(tmp_path):
    import jsonschema

    schema = json.loads(
        (
            PROJECT_ROOT / "capabilities/cdk/bootstrap-upgrade-execution-evidence.schema.json"
        ).read_text()
    )

    with pytest.raises(ValueError, match="argv does not match"):
        _observation(tmp_path / "invalid-argv", argv_override=["x"] * 13)

    evidence = _aggregate(tmp_path)
    evidence["lanes"][0]["command"]["argv_contract"] = "unsupported"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(evidence, schema)
    with pytest.raises(ValueError):
        validate_aggregate_evidence(evidence)

    evidence = _aggregate(tmp_path)
    evidence["lanes"][0]["command"]["qualifier"] = "hnb659fds"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(evidence, schema)
    with pytest.raises(ValueError):
        validate_aggregate_evidence(evidence)
