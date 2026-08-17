import copy
import importlib.metadata
import json
import tarfile
from pathlib import Path

import jsonschema
import pytest
from tests.aws.cli import python_synth_execution_evidence_v2 as evidence_v2
from tests.aws.cli import python_synth_toolchain
from tests.aws.cli.python_synth_execution_evidence_v2 import (
    ASSEMBLY_FILES,
    MAX_EVIDENCE_BYTES,
    PINNED_INPUTS,
    PROMOTION_BLOCKERS,
    SUPPLY_CHAIN_CONTRACT,
    build_aggregate_evidence,
    create_lane_receipt,
    create_observation,
    validate_aggregate_evidence,
    write_canonical_json,
)

PROJECT_ROOT = Path(__file__).parents[3]
APP_PATH = PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/minimal_sqs.py"
SCHEMA_PATH = PROJECT_ROOT / "capabilities/cdk/python-synth-execution-evidence-v2.schema.json"
COMMIT_SHA = "a" * 40
RUN_ID = 123456


def _schema_payload() -> bytes:
    version = "52.2.0"
    distribution = importlib.metadata.distribution("aws-cdk-cloud-assembly-schema")
    archive_path = Path(
        distribution.locate_file(
            Path("aws_cdk/cloud_assembly_schema/_jsii")
            / f"cloud-assembly-schema@{version}.jsii.tgz"
        )
    )
    with tarfile.open(archive_path, "r:gz") as archive:
        stream = archive.extractfile("package/schema/cloud-assembly.schema.json")
        assert stream is not None
        return stream.read()


def _toolchain_manifest(path: Path) -> Path:
    contract = python_synth_toolchain.load_contract()
    keys = (
        "role",
        "project",
        "version",
        "filename",
        "bytes",
        "sha256",
        "metadata_sha256",
        "tags",
    )
    wheels = [{key: item[key] for key in keys} for item in contract["applications"]]
    installer = {key: contract["installer"][key] for key in keys}
    installed = [
        {
            "project": item["project"],
            "version": item["version"],
            "metadata_sha256": item["metadata_sha256"],
        }
        for item in contract["applications"]
    ]
    manifest = {
        "schema_version": 2,
        "contract": python_synth_toolchain.TOOLCHAIN_CONTRACT,
        "origins_sha256": contract["origins_sha256"],
        "lock_sha256": contract["lock_sha256"],
        "roots": list(python_synth_toolchain.ROOTS),
        "installer": installer,
        "wheels": wheels,
        "resolved": installed,
        "installed": installed,
        "installed_metadata_sha256": python_synth_toolchain._sha256(
            python_synth_toolchain._canonical_bytes(installed)
        ),
        "installed_tree_sha256": "0" * 64,
        "resolve_argv_contract": list(python_synth_toolchain.RESOLVE_ARGV_CONTRACT),
        "install_argv_contract": list(python_synth_toolchain.INSTALL_ARGV_CONTRACT),
    }
    path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    return path


def _assembly_files() -> dict[str, bytes]:
    return {name: b'{"fixture":true,"name":"' + name.encode() + b'"}' for name in ASSEMBLY_FILES}


def _argv(python: Path, output: Path) -> list[str]:
    import shlex

    return [
        "synth",
        "SynthStack",
        "--app",
        shlex.join((str(python), "-I", "-B", str(APP_PATH))),
        "--output",
        str(output),
        "--no-lookups",
        "--strict",
        "--no-version-reporting",
        "--no-path-metadata",
        "--no-asset-metadata",
        "--no-notices",
        "--no-color",
        "--ci",
        "--quiet",
    ]


def _write_junit(path: Path) -> None:
    path.write_text(
        '<testsuites tests="1" failures="0" errors="0" skipped="0">'
        '<testsuite name="cdk-python-synth" tests="1" failures="0" errors="0" skipped="0">'
        '<testcase classname="tests.aws.cli.test_cdk_cli_python_synth" '
        'name="test_cdk_cli_synthesizes_minimal_python_sqs_app" />'
        "</testsuite></testsuites>"
    )


def _receipt(tmp_path: Path, platform_id: str) -> tuple[Path, Path]:
    architectures = {
        "linux-amd64": ("x86_64", "x64"),
        "linux-arm64": ("aarch64", "arm64"),
    }
    machine_arch, node_arch = architectures[platform_id]
    python = Path("/usr/bin/python3")
    output = Path("/tmp/cdk-python-synth-output")
    manifest = _toolchain_manifest(tmp_path / f"manifest-{platform_id}.json")
    observation = create_observation(
        platform_id=platform_id,
        machine_arch=machine_arch,
        node_arch=node_arch,
        python_version="3.13.14",
        kernel_release="6.8.0-1021-azure",
        repository="cassiolpaixao90/localstack",
        commit_sha=COMMIT_SHA,
        ref="refs/heads/main",
        event="push",
        workflow_path=".github/workflows/cdk-cli-blackbox.yml",
        run_id=RUN_ID,
        run_attempt=1,
        python_executable=python,
        app_path=APP_PATH,
        output_path=output,
        argv=_argv(python, output),
        assembly_files=_assembly_files(),
        schema_payload=_schema_payload(),
        toolchain_manifest_path=manifest,
        returncode=0,
        timed_out=False,
        duration_ms=4200,
        stdout=b"Successfully synthesized\n",
        stderr=b"",
        stdout_bytes=25,
        stderr_bytes=0,
        stdout_truncated=False,
        stderr_truncated=False,
        observed_at="2026-08-09T02:25:30Z",
    )
    observation_path = tmp_path / f"observation-{platform_id}.json"
    write_canonical_json(observation_path, observation, MAX_EVIDENCE_BYTES)
    junit = tmp_path / f"junit-{platform_id}.xml"
    _write_junit(junit)
    receipt = create_lane_receipt(
        observation_path=observation_path,
        junit_path=junit,
        assembly_output_path=tmp_path / f"removed-{platform_id}",
        platform_id=platform_id,
        machine_arch=machine_arch,
        node_arch=node_arch,
        python_version="3.13.14",
        kernel_release="6.8.0-1021-azure",
        interface_names=["lo"],
        isolation_profile_id="linux-net-pid-mount-nobody-v1",
        completed_at="2026-08-09T02:25:32Z",
        repository="cassiolpaixao90/localstack",
        commit_sha=COMMIT_SHA,
        ref="refs/heads/main",
        event="push",
        workflow_path=".github/workflows/cdk-cli-blackbox.yml",
        run_id=RUN_ID,
        run_attempt=1,
    )
    receipt_path = tmp_path / f"receipt-{platform_id}.json"
    write_canonical_json(receipt_path, receipt, MAX_EVIDENCE_BYTES)
    return receipt_path, junit


def _aggregate(tmp_path: Path) -> dict:
    receipts = {}
    junits = {}
    for platform_id in ("linux-amd64", "linux-arm64"):
        receipts[platform_id], junits[platform_id] = _receipt(tmp_path, platform_id)
    return build_aggregate_evidence(
        receipt_paths=receipts,
        junit_paths=junits,
        project_root=PROJECT_ROOT,
        repository="cassiolpaixao90/localstack",
        commit_sha=COMMIT_SHA,
        ref="refs/heads/main",
        event="push",
        workflow_path=".github/workflows/cdk-cli-blackbox.yml",
        run_id=RUN_ID,
        run_attempt=1,
    )


def test_v2_python_synth_evidence_binds_offline_hash_locked_supply_chain(tmp_path):
    evidence = _aggregate(tmp_path)
    schema = json.loads(SCHEMA_PATH.read_bytes())

    jsonschema.validators.validator_for(schema).check_schema(schema)
    jsonschema.validate(evidence, schema)
    validate_aggregate_evidence(evidence)

    assert evidence["schema_version"] == 2
    assert evidence["verification_contract"]["supply_chain"] == SUPPLY_CHAIN_CONTRACT
    assert (
        evidence["verification_contract"]["supply_chain"]["installation"]["source_date_epoch"] == 0
    )
    assert all(
        lane["supply_chain"]["contract"] == SUPPLY_CHAIN_CONTRACT for lane in evidence["lanes"]
    )
    assert "python-distribution-origin-not-attested" not in evidence["promotion"]["blockers"]
    assert evidence["promotion"] == {
        "eligible": False,
        "blockers": list(PROMOTION_BLOCKERS),
    }
    assert set(evidence["harness"]["input_sha256"]) == set(PINNED_INPUTS)


def test_v2_python_synth_evidence_rejects_supply_chain_tampering(tmp_path):
    evidence = _aggregate(tmp_path)
    invalid = copy.deepcopy(evidence)
    invalid["lanes"][0]["supply_chain"]["contract"]["runtime_wheel_count"] = 4
    with pytest.raises(ValueError, match="supply chain"):
        validate_aggregate_evidence(invalid)

    invalid = copy.deepcopy(evidence)
    invalid["promotion"]["blockers"].append("python-distribution-origin-not-attested")
    with pytest.raises((ValueError, jsonschema.ValidationError)):
        validate_aggregate_evidence(invalid)

    invalid = copy.deepcopy(evidence)
    invalid["lanes"][1]["supply_chain"]["installed_tree_sha256"] = "sha256:" + "1" * 64
    invalid["lanes"][1]["receipt_id"] = evidence_v2._record_digest(
        invalid["lanes"][1], "receipt_id"
    )
    with pytest.raises(ValueError, match="installed environment"):
        validate_aggregate_evidence(invalid)
