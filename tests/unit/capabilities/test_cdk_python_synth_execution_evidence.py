import base64
import copy
import hashlib
import importlib.metadata
import json
import tarfile
from pathlib import Path

import jsonschema
import pytest
from tests.aws.cli.python_synth_execution_evidence import (
    ASSEMBLY_FILES,
    MAX_EVIDENCE_BYTES,
    PINNED_INPUTS,
    PINNED_PYTHON_PACKAGES,
    PINNED_TOOLCHAIN,
    PROMOTION_BLOCKERS,
    build_aggregate_evidence,
    create_lane_receipt,
    create_observation,
    main,
    validate_aggregate_evidence,
    write_canonical_json,
)

PROJECT_ROOT = Path(__file__).parents[3]
APP_PATH = PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/minimal_sqs.py"
SCHEMA_PATH = PROJECT_ROOT / "capabilities/cdk/python-synth-execution-evidence.schema.json"
COMMIT_SHA = "a" * 40
RUN_ID = 123456
RETAINED_RUN_ID = 31307734639
RETAINED_EVIDENCE_DIR = PROJECT_ROOT / "capabilities/cdk/evidence/runs" / str(RETAINED_RUN_ID)


def _schema_payload() -> bytes:
    version = PINNED_PYTHON_PACKAGES["aws-cdk-cloud-assembly-schema"]
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


def _assembly_files(*, suffix: bytes = b"") -> dict[str, bytes]:
    return {
        name: b'{"fixture":true,"name":"' + name.encode() + b'"}' + suffix
        for name in ASSEMBLY_FILES
    }


def _argv(python: Path, app: Path, output: Path) -> list[str]:
    import shlex

    return [
        "synth",
        "SynthStack",
        "--app",
        shlex.join((str(python), "-I", "-B", str(app))),
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


def _observation(
    tmp_path: Path,
    *,
    platform_id: str = "linux-amd64",
    run_id: int = RUN_ID,
    run_attempt: int = 1,
    python_version: str = "3.13.7",
    kernel_release: str = "6.8.0-1021-azure",
    assembly_files: dict[str, bytes] | None = None,
    argv: list[str] | None = None,
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    architectures = {
        "linux-amd64": ("x86_64", "x64"),
        "linux-arm64": ("aarch64", "arm64"),
    }
    machine_arch, node_arch = architectures[platform_id]
    python = Path("/usr/bin/python3")
    output = Path("/tmp/cdk-python-synth-output")
    observation = create_observation(
        platform_id=platform_id,
        machine_arch=machine_arch,
        node_arch=node_arch,
        python_version=python_version,
        kernel_release=kernel_release,
        repository="cassiolpaixao90/localstack",
        commit_sha=COMMIT_SHA,
        ref="refs/heads/main",
        event="push",
        workflow_path=".github/workflows/cdk-cli-blackbox.yml",
        run_id=run_id,
        run_attempt=run_attempt,
        python_executable=python,
        app_path=APP_PATH,
        output_path=output,
        argv=_argv(python, APP_PATH, output) if argv is None else argv,
        assembly_files=_assembly_files() if assembly_files is None else assembly_files,
        schema_payload=_schema_payload(),
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
    path = tmp_path / "observation.json"
    write_canonical_json(path, observation, MAX_EVIDENCE_BYTES)
    return path


def _write_junit(path: Path, *, failures: int = 0) -> None:
    outcome = "<failure />" if failures else ""
    path.write_text(
        f'<testsuites tests="1" failures="{failures}" errors="0" skipped="0">'
        f'<testsuite name="cdk-python-synth" tests="1" failures="{failures}" '
        'errors="0" skipped="0"><testcase '
        'classname="tests.aws.cli.test_cdk_cli_python_synth" '
        'name="test_cdk_cli_synthesizes_minimal_python_sqs_app">'
        f"{outcome}</testcase></testsuite></testsuites>"
    )


def _receipt(
    tmp_path: Path,
    platform_id: str,
    *,
    run_id: int = RUN_ID,
    assembly_files: dict[str, bytes] | None = None,
    python_version: str = "3.13.7",
) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    architectures = {
        "linux-amd64": ("x86_64", "x64"),
        "linux-arm64": ("aarch64", "arm64"),
    }
    machine_arch, node_arch = architectures[platform_id]
    junit = tmp_path / f"junit-{platform_id}.xml"
    _write_junit(junit)
    receipt = create_lane_receipt(
        observation_path=_observation(
            tmp_path / platform_id,
            platform_id=platform_id,
            run_id=run_id,
            python_version=python_version,
            assembly_files=assembly_files,
        ),
        junit_path=junit,
        assembly_output_path=tmp_path / f"removed-{platform_id}",
        platform_id=platform_id,
        machine_arch=machine_arch,
        node_arch=node_arch,
        python_version=python_version,
        kernel_release="6.8.0-1021-azure",
        interface_names=["lo"],
        isolation_profile_id="linux-net-pid-mount-nobody-v1",
        completed_at="2026-08-09T02:25:32Z",
        repository="cassiolpaixao90/localstack",
        commit_sha=COMMIT_SHA,
        ref="refs/heads/main",
        event="push",
        workflow_path=".github/workflows/cdk-cli-blackbox.yml",
        run_id=run_id,
        run_attempt=1,
    )
    receipt_path = tmp_path / f"receipt-{platform_id}.json"
    write_canonical_json(receipt_path, receipt, MAX_EVIDENCE_BYTES)
    return receipt_path, junit


def _aggregate(
    tmp_path: Path,
    *,
    arm_files: dict[str, bytes] | None = None,
    arm_python_version: str = "3.13.7",
) -> dict:
    receipt_paths = {}
    junit_paths = {}
    for platform_id in ("linux-amd64", "linux-arm64"):
        receipt, junit = _receipt(
            tmp_path,
            platform_id,
            assembly_files=arm_files if platform_id == "linux-arm64" else None,
            python_version=(arm_python_version if platform_id == "linux-arm64" else "3.13.7"),
        )
        receipt_paths[platform_id] = receipt
        junit_paths[platform_id] = junit
    return build_aggregate_evidence(
        receipt_paths=receipt_paths,
        junit_paths=junit_paths,
        project_root=PROJECT_ROOT,
        repository="cassiolpaixao90/localstack",
        commit_sha=COMMIT_SHA,
        ref="refs/heads/main",
        event="push",
        workflow_path=".github/workflows/cdk-cli-blackbox.yml",
        run_id=RUN_ID,
        run_attempt=1,
    )


def test_python_synth_evidence_is_closed_content_addressed_and_not_promotional(tmp_path):
    evidence = _aggregate(tmp_path)
    schema = json.loads(SCHEMA_PATH.read_bytes())

    jsonschema.validators.validator_for(schema).check_schema(schema)
    jsonschema.validate(evidence, schema)
    validate_aggregate_evidence(evidence)
    serialized = tmp_path / "aggregate.json"
    write_canonical_json(serialized, evidence, MAX_EVIDENCE_BYTES)
    validate_aggregate_evidence(json.loads(serialized.read_bytes()))

    assert [lane["platform"]["id"] for lane in evidence["lanes"]] == [
        "linux-amd64",
        "linux-arm64",
    ]
    assert all(lane["cleanup"]["assembly_output_absent"] for lane in evidence["lanes"])
    assert tuple(evidence["harness"]["input_sha256"]) == PINNED_INPUTS
    assert evidence["promotion"] == {
        "eligible": False,
        "blockers": list(PROMOTION_BLOCKERS),
    }
    assert "python-distribution-origin-not-attested" in evidence["promotion"]["blockers"]


def test_retained_python_synth_candidate_is_content_addressed_and_attested():
    from jsonschema.validators import validator_for
    from tests.aws.cli.execution_evidence import read_regular_bounded

    evidence_path = RETAINED_EVIDENCE_DIR / "cdk-python-synth-execution-evidence.json"
    attestation_path = RETAINED_EVIDENCE_DIR / "cdk-python-synth-execution-evidence.sigstore.json"
    assert set(RETAINED_EVIDENCE_DIR.iterdir()) == {evidence_path, attestation_path}

    evidence_bytes = read_regular_bounded(evidence_path, MAX_EVIDENCE_BYTES)
    attestation_bytes = read_regular_bounded(attestation_path, MAX_EVIDENCE_BYTES)
    assert hashlib.sha256(evidence_bytes).hexdigest() == (
        "cb13ec230cccba5fbacd2586d34f030bd36ab5631e717d9f12c011632ee279ba"
    )
    assert hashlib.sha256(attestation_bytes).hexdigest() == (
        "6f3d8b0ab1891014a8ee9e699b37d4c639f4c30201298c7303cf3f1059339b58"
    )

    evidence = json.loads(evidence_bytes)
    attestation = json.loads(attestation_bytes)
    schema = json.loads(SCHEMA_PATH.read_bytes())
    validator = validator_for(schema)
    validator.check_schema(schema)
    validator(schema, format_checker=validator.FORMAT_CHECKER).validate(evidence)
    validate_aggregate_evidence(evidence)

    assert evidence["evidence_id"] == (
        "sha256:30f760d363a2697e76e0f2e3bdee01f2a7eedcef8d9f656f1c715ca5e3ba8987"
    )
    assert evidence["claim_id"] == (
        "sha256:cc491228ec1e8fa152edc8cbdfd8b28dd15f10b6d4a4804ce93c3de05eb57099"
    )
    assert evidence["subject"] == {
        "repository": "cassiolpaixao90/localstack",
        "commit_sha": "7d2ce5f636f87785262185bce42aa497d88ee50b",
        "ref": "refs/heads/main",
    }
    assert evidence["run"] == {
        "provider": "github-actions",
        "workflow_path": ".github/workflows/cdk-cli-blackbox.yml",
        "run_id": RETAINED_RUN_ID,
        "run_attempt": 1,
        "event": "push",
    }
    assert [lane["platform"]["id"] for lane in evidence["lanes"]] == [
        "linux-amd64",
        "linux-arm64",
    ]
    assert {lane["platform"]["python_version"] for lane in evidence["lanes"]} == {"3.13.14"}
    assert evidence["promotion"] == {
        "eligible": False,
        "blockers": list(PROMOTION_BLOCKERS),
    }

    envelope = attestation["dsseEnvelope"]
    assert len(envelope["signatures"]) == 1
    assert len(attestation["verificationMaterial"]["tlogEntries"]) == 1
    payload = base64.b64decode(envelope["payload"], validate=True)
    assert len(payload) <= 16 * 1024
    statement = json.loads(payload)
    assert statement["subject"] == [
        {
            "name": evidence_path.name,
            "digest": {"sha256": hashlib.sha256(evidence_bytes).hexdigest()},
        }
    ]
    assert statement["predicateType"] == "https://slsa.dev/provenance/v1"
    predicate = statement["predicate"]
    definition = predicate["buildDefinition"]
    assert definition["externalParameters"]["workflow"] == {
        "ref": "refs/heads/main",
        "repository": "https://github.com/cassiolpaixao90/localstack",
        "path": ".github/workflows/cdk-cli-blackbox.yml",
    }
    assert definition["resolvedDependencies"] == [
        {
            "uri": "git+https://github.com/cassiolpaixao90/localstack@refs/heads/main",
            "digest": {"gitCommit": evidence["subject"]["commit_sha"]},
        }
    ]
    assert definition["internalParameters"]["github"]["event_name"] == "push"
    assert definition["internalParameters"]["github"]["runner_environment"] == ("github-hosted")
    assert predicate["runDetails"]["metadata"]["invocationId"] == (
        f"https://github.com/cassiolpaixao90/localstack/actions/runs/{RETAINED_RUN_ID}/attempts/1"
    )


def test_observation_rejects_argv_or_schema_not_used_by_the_real_validator(tmp_path):
    with pytest.raises(ValueError, match="argv"):
        _observation(tmp_path / "argv", argv=["synth", "SynthStack"])

    schema_payload = bytearray(_schema_payload())
    schema_payload[-1] ^= 1
    python = Path("/usr/bin/python3")
    output = Path("/tmp/cdk-python-synth-output")
    with pytest.raises(ValueError, match="schema"):
        create_observation(
            platform_id="linux-amd64",
            machine_arch="x86_64",
            node_arch="x64",
            python_version="3.13.7",
            kernel_release="6.8.0",
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
            argv=_argv(python, APP_PATH, output),
            assembly_files=_assembly_files(),
            schema_payload=bytes(schema_payload),
            returncode=0,
            timed_out=False,
            duration_ms=1,
            stdout=b"",
            stderr=b"",
            stdout_bytes=0,
            stderr_bytes=0,
            stdout_truncated=False,
            stderr_truncated=False,
            observed_at="2026-08-09T02:25:30Z",
        )


def test_lane_receipt_rejects_replay_failed_junit_and_incomplete_cleanup(tmp_path):
    observation = _observation(tmp_path / "observation")
    junit = tmp_path / "junit.xml"
    _write_junit(junit)
    common = {
        "observation_path": observation,
        "junit_path": junit,
        "assembly_output_path": tmp_path / "removed",
        "platform_id": "linux-amd64",
        "machine_arch": "x86_64",
        "node_arch": "x64",
        "python_version": "3.13.7",
        "kernel_release": "6.8.0-1021-azure",
        "interface_names": ["lo"],
        "isolation_profile_id": "linux-net-pid-mount-nobody-v1",
        "completed_at": "2026-08-09T02:25:32Z",
        "repository": "cassiolpaixao90/localstack",
        "commit_sha": COMMIT_SHA,
        "ref": "refs/heads/main",
        "event": "push",
        "workflow_path": ".github/workflows/cdk-cli-blackbox.yml",
        "run_id": RUN_ID,
        "run_attempt": 1,
    }
    with pytest.raises(ValueError, match="different workflow run"):
        create_lane_receipt(**{**common, "run_id": RUN_ID + 1})

    _write_junit(junit, failures=1)
    with pytest.raises(ValueError, match="failures"):
        create_lane_receipt(**common)

    _write_junit(junit)
    common["assembly_output_path"].mkdir()
    with pytest.raises(ValueError, match="cleanup"):
        create_lane_receipt(**common)


def test_lane_receipt_rejects_broken_symlink_as_remaining_output(tmp_path):
    output = tmp_path / "broken-output"
    try:
        output.symlink_to(tmp_path / "missing-target")
    except OSError:
        pytest.skip("symlinks are unavailable")
    junit = tmp_path / "junit.xml"
    _write_junit(junit)
    with pytest.raises(ValueError, match="cleanup"):
        create_lane_receipt(
            observation_path=_observation(tmp_path / "observation"),
            junit_path=junit,
            assembly_output_path=output,
            platform_id="linux-amd64",
            machine_arch="x86_64",
            node_arch="x64",
            python_version="3.13.7",
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


def test_aggregate_rejects_missing_lane_cross_lane_assembly_and_rerun(tmp_path):
    amd_receipt, amd_junit = _receipt(tmp_path / "missing", "linux-amd64")
    with pytest.raises(ValueError, match="exactly"):
        build_aggregate_evidence(
            receipt_paths={"linux-amd64": amd_receipt},
            junit_paths={"linux-amd64": amd_junit},
            project_root=PROJECT_ROOT,
            repository="cassiolpaixao90/localstack",
            commit_sha=COMMIT_SHA,
            ref="refs/heads/main",
            event="push",
            workflow_path=".github/workflows/cdk-cli-blackbox.yml",
            run_id=RUN_ID,
            run_attempt=1,
        )
    with pytest.raises(ValueError, match="assembly"):
        _aggregate(tmp_path / "mixed", arm_files=_assembly_files(suffix=b"changed"))
    with pytest.raises(ValueError, match="Python patch version"):
        _aggregate(tmp_path / "mixed-python", arm_python_version="3.13.8")
    with pytest.raises(ValueError, match="first workflow attempt"):
        build_aggregate_evidence(
            receipt_paths={"linux-amd64": amd_receipt, "linux-arm64": amd_receipt},
            junit_paths={"linux-amd64": amd_junit, "linux-arm64": amd_junit},
            project_root=PROJECT_ROOT,
            repository="cassiolpaixao90/localstack",
            commit_sha=COMMIT_SHA,
            ref="refs/heads/main",
            event="push",
            workflow_path=".github/workflows/cdk-cli-blackbox.yml",
            run_id=RUN_ID,
            run_attempt=2,
        )


def test_schema_and_runtime_reject_promotion_or_extra_fields(tmp_path):
    evidence = _aggregate(tmp_path)
    schema = json.loads(SCHEMA_PATH.read_bytes())
    promoted = copy.deepcopy(evidence)
    promoted["promotion"] = {"eligible": True, "blockers": []}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(promoted, schema)
    with pytest.raises(ValueError, match="cannot authorize promotion"):
        validate_aggregate_evidence(promoted)

    extra = copy.deepcopy(evidence)
    extra["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(extra, schema)
    with pytest.raises(ValueError, match="closed evidence contract"):
        validate_aggregate_evidence(extra)


def test_cli_lane_fails_before_writing_when_cleanup_is_incomplete(tmp_path):
    import platform

    junit = tmp_path / "junit.xml"
    _write_junit(junit)
    assembly = tmp_path / "assembly"
    assembly.mkdir()
    output = tmp_path / "receipt.json"
    with pytest.raises(ValueError, match="cleanup"):
        main(
            [
                "lane",
                "--observation",
                str(
                    _observation(
                        tmp_path / "observation",
                        python_version=platform.python_version(),
                        kernel_release=platform.release(),
                    )
                ),
                "--junit",
                str(junit),
                "--assembly-output",
                str(assembly),
                "--platform-id",
                "linux-amd64",
                "--machine-arch",
                "x86_64",
                "--node-arch",
                "x64",
                "--output",
                str(output),
                "--repository",
                "cassiolpaixao90/localstack",
                "--commit-sha",
                COMMIT_SHA,
                "--ref",
                "refs/heads/main",
                "--event",
                "push",
                "--workflow-path",
                ".github/workflows/cdk-cli-blackbox.yml",
                "--run-id",
                str(RUN_ID),
                "--run-attempt",
                "1",
            ]
        )
    assert not output.exists()


def test_schema_digest_constant_matches_the_payload_used_by_the_validator():
    import hashlib

    assert (
        "sha256:" + hashlib.sha256(_schema_payload()).hexdigest()
        == PINNED_TOOLCHAIN["cloud_assembly_schema_sha256"]
    )
