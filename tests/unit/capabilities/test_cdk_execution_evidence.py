import json
from pathlib import Path

import pytest
from tests.aws.cli.execution_evidence import (
    MAX_EVIDENCE_BYTES,
    build_aggregate_evidence,
    create_lane_receipt,
    load_bounded_json,
    validate_aggregate_evidence,
    write_canonical_json,
)

PROJECT_ROOT = Path(__file__).parents[3]


def _write_junit(path: Path) -> None:
    path.write_text(
        '<testsuites tests="1" failures="0" errors="0" skipped="0">'
        '<testsuite name="cdk-cli" tests="1" failures="0" errors="0" skipped="0">'
        '<testcase classname="tests.aws.cli.test_cdk_cli_blackbox" '
        'name="test_cdk_cli_bootstrap_show_template_matches_pinned_v32" />'
        "</testsuite></testsuites>"
    )


def _receipt(platform_id: str) -> dict:
    architectures = {
        "linux-amd64": ("x86_64", "x64"),
        "linux-arm64": ("aarch64", "arm64"),
    }
    machine_arch, node_arch = architectures[platform_id]
    return create_lane_receipt(
        platform_id=platform_id,
        machine_arch=machine_arch,
        node_arch=node_arch,
        python_version="3.13.7",
        kernel_release="6.8.0-1021-azure",
        node_version="22.23.2",
        cdk_cli_version="2.1135.1",
        bootstrap_version=32,
        reference_template_byte_sha256=(
            "sha256:a484ad768d3446874161044d986bec096e201a54037c8ce93ed5a0d215e1dd25"
        ),
        template_semantic_sha256=(
            "sha256:9e04a3226e702258e2ba13063dc6ecbc6fba7880d9fa27298445499db453013a"
        ),
        returncode=0,
        timed_out=False,
        duration_ms=1200,
        stdout=b"template",
        stderr=b"",
        stdout_bytes=8,
        stderr_bytes=0,
        stdout_truncated=False,
        stderr_truncated=False,
        interface_names=["lo"],
        isolation_profile_id="linux-net-pid-mount-nobody-v1",
        observed_at="2026-08-09T01:24:09Z",
    )


def _aggregate(tmp_path: Path, *, run_attempt: int = 1) -> dict:
    receipt_paths = {}
    junit_paths = {}
    for platform_id in ("linux-amd64", "linux-arm64"):
        receipt_path = tmp_path / f"receipt-{platform_id}.json"
        junit_path = tmp_path / f"pytest-junit-cdk-cli-{platform_id.removeprefix('linux-')}.xml"
        write_canonical_json(receipt_path, _receipt(platform_id), MAX_EVIDENCE_BYTES)
        _write_junit(junit_path)
        receipt_paths[platform_id] = receipt_path
        junit_paths[platform_id] = junit_path

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


def test_cdk_execution_evidence_is_closed_content_addressed_and_language_neutral(tmp_path):
    evidence = _aggregate(tmp_path)

    validate_aggregate_evidence(evidence)
    schema = json.loads(
        (PROJECT_ROOT / "capabilities/cdk/execution-evidence.schema.json").read_text()
    )
    import jsonschema

    jsonschema.validators.validator_for(schema).check_schema(schema)
    jsonschema.validate(evidence, schema)
    assert evidence["record_type"] == "aggregate"
    assert evidence["mode"] == "candidate"
    assert evidence["scenario"] == {
        "id": "bootstrap-show-template-v32",
        "result": "cli-pass",
        "construct_language": None,
        "cloud_assembly_produced": False,
        "resource_deployment_performed": False,
        "aws_differential": False,
    }
    assert [lane["platform_id"] for lane in evidence["lanes"]] == [
        "linux-amd64",
        "linux-arm64",
    ]
    assert evidence["promotion"]["eligible"] is False
    assert evidence["evidence_id"].startswith("sha256:")
    assert evidence["claim_id"].startswith("sha256:")


def test_cdk_execution_evidence_rejects_reruns(tmp_path):
    with pytest.raises(ValueError, match="first workflow attempt"):
        _aggregate(tmp_path, run_attempt=2)


def test_cdk_execution_evidence_rejects_duplicate_or_missing_platforms(tmp_path):
    receipt = tmp_path / "receipt.json"
    junit = tmp_path / "junit.xml"
    write_canonical_json(receipt, _receipt("linux-amd64"), MAX_EVIDENCE_BYTES)
    _write_junit(junit)

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


def test_cdk_execution_evidence_rejects_tampering(tmp_path):
    evidence = _aggregate(tmp_path)
    evidence["toolchain"]["cdk_cli_version"] = "999.0.0"

    with pytest.raises(ValueError, match="pinned CDK toolchain"):
        validate_aggregate_evidence(evidence)


def test_cdk_execution_evidence_rejects_an_unpinned_toolchain():
    arguments = _receipt("linux-amd64")
    arguments["toolchain"]["node_version"] = "999.0.0"
    arguments["receipt_id"] = "sha256:" + "0" * 64

    with pytest.raises(ValueError, match="pinned CDK toolchain"):
        from tests.aws.cli.execution_evidence import _validate_lane_receipt

        _validate_lane_receipt(arguments)


def test_cdk_execution_evidence_runtime_limits_match_the_closed_schema():
    arguments = _receipt("linux-amd64")
    arguments["platform"]["python_version"] = "x" * 33
    arguments["receipt_id"] = "sha256:" + "0" * 64

    with pytest.raises(ValueError, match="bounded non-empty string"):
        from tests.aws.cli.execution_evidence import _validate_lane_receipt

        _validate_lane_receipt(arguments)


def test_cdk_execution_evidence_reader_rejects_oversize_and_non_regular_files(tmp_path):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_EVIDENCE_BYTES + 1))
    fifo = tmp_path / "record.fifo"
    fifo.unlink(missing_ok=True)
    import os

    os.mkfifo(fifo)

    with pytest.raises(ValueError, match="size"):
        load_bounded_json(oversized)
    with pytest.raises(ValueError, match="regular file"):
        load_bounded_json(fifo)
