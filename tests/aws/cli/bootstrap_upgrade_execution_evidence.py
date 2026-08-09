import argparse
import copy
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

if __package__:
    from .execution_evidence import (
        MAX_EVIDENCE_BYTES,
        NPM_INTEGRITY,
        _canonical_bytes,
        _expect_int,
        _expect_keys,
        _expect_sha256,
        _expect_string,
        _record_digest,
        _sha256_bytes,
        load_bounded_json,
        write_canonical_json,
    )
    from .validate_junit import load_junit, validate_junit_payload
else:
    from execution_evidence import (
        MAX_EVIDENCE_BYTES,
        NPM_INTEGRITY,
        _canonical_bytes,
        _expect_int,
        _expect_keys,
        _expect_sha256,
        _expect_string,
        _record_digest,
        _sha256_bytes,
        load_bounded_json,
        write_canonical_json,
    )
    from validate_junit import load_junit, validate_junit_payload

MAX_OBSERVATION_BYTES = 8 * 1024
SCHEMA_VERSION = 1
SCENARIO = {
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
PINNED_TOOLCHAIN = {
    "node_version": "22.23.2",
    "cdk_cli_version": "2.1135.1",
    "source_bootstrap_version": 28,
    "target_bootstrap_version": 32,
    "source_template_byte_sha256": (
        "sha256:d84e26fcd602ef1b58a60a71e7f47a4cc9a6fa3f62e7c88182905cfb080fab4e"
    ),
    "source_template_semantic_sha256": (
        "sha256:7a86502e6cdd86402f3ce159f12d89e7ed0cc0d37bf399202f6ee98bb41b5169"
    ),
    "target_template_byte_sha256": (
        "sha256:a484ad768d3446874161044d986bec096e201a54037c8ce93ed5a0d215e1dd25"
    ),
    "target_template_semantic_sha256": (
        "sha256:9e04a3226e702258e2ba13063dc6ecbc6fba7880d9fa27298445499db453013a"
    ),
}
VERIFICATION_CONTRACT = {
    "seed_stack_status": "CREATE_COMPLETE",
    "seed_output_and_ssm_version": 28,
    "seed_template_matches_fixture": True,
    "same_stack_id": True,
    "preserved_role_identity_count": 5,
    "external_policy_preserved_count": 5,
    "target_stack_status": "UPDATE_COMPLETE",
    "target_output_and_ssm_version": 32,
    "target_template_matches_fixture": True,
    "managed_policy_delta_verified": True,
    "trust_policy_delta_count": 4,
    "inline_policy_delta_verified": True,
    "default_stack_absent": True,
    "default_qualifier_absent": True,
}
CLEANUP_CONTRACT = {
    "completed": True,
    "stack_absent": True,
    "bucket_absent": True,
    "absent_role_count": 5,
    "ssm_parameter_absent": True,
}
EXPECTED_PLATFORMS = ("linux-amd64", "linux-arm64")
EXPECTED_ARCHITECTURES = {
    "linux-amd64": ("x86_64", "x64"),
    "linux-arm64": ("aarch64", "arm64"),
}
PROMOTION_BLOCKERS = (
    "not-reviewed-for-promotion",
    "no-clean-bootstrap-create",
    "no-cloud-assembly",
    "no-language-binding",
    "no-aws-differential",
)
PINNED_INPUTS = (
    ".github/workflows/cdk-cli-blackbox.yml",
    ".python-version",
    "Makefile",
    "capabilities/cdk/bootstrap-upgrade-execution-evidence.schema.json",
    "capabilities/cdk/compatibility.json",
    "localstack-core/localstack/cli/_cdk_health_probe.py",
    "localstack-core/localstack/cli/cdk.py",
    "localstack-core/localstack/services/iam/iam_patches.py",
    "localstack-core/localstack/services/moto.py",
    "localstack-core/localstack/services/iam/resource_providers/aws_iam_role.py",
    "localstack-core/localstack/services/iam/resource_providers/aws_iam_role.schema.json",
    "pyproject.toml",
    "requirements-test.txt",
    "scripts/run_cdk_cli_blackbox_isolated.sh",
    "tests/aws/cli/bootstrap_upgrade_execution_evidence.py",
    "tests/aws/cli/execution_evidence.py",
    "tests/aws/cli/package-lock.json",
    "tests/aws/cli/package.json",
    "tests/aws/cli/test_cdk_cli_blackbox.py",
    "tests/aws/cli/test_cdk_cli_bootstrap_upgrade.py",
    "tests/aws/cli/validate_junit.py",
    "tests/aws/templates/cdk_bootstrap_v28.yaml",
    "tests/aws/templates/cdk_bootstrap_v32.yaml",
)
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")
_ACCOUNT_RE = re.compile(r"[0-9]{12}\Z")
_REGION_RE = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_STACK_RE = re.compile(r"CDKToolkit-[a-z0-9]{8,32}\Z")
_QUALIFIER_RE = re.compile(r"[a-z0-9]{1,10}\Z")
_ARGV_CONTRACT = "bootstrap-upgrade-v28-to-built-in-v32-v1"


def _value_digest(value: object) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _validate_result(value: object) -> dict:
    result = _expect_keys(
        value,
        {
            "status",
            "returncode",
            "timed_out",
            "duration_ms",
            "stdout_bytes",
            "stderr_bytes",
            "stdout_sha256",
            "stderr_sha256",
            "stdout_truncated",
            "stderr_truncated",
        },
        "bootstrap upgrade result",
    )
    if (
        result["status"] != "pass"
        or result["returncode"] != 0
        or result["timed_out"] is not False
        or result["stdout_truncated"] is not False
        or result["stderr_truncated"] is not False
    ):
        raise ValueError("bootstrap upgrade result is not an exact pass")
    _expect_int(result["duration_ms"], "CLI duration", maximum=90_000)
    _expect_int(result["stdout_bytes"], "stdout bytes", maximum=256 * 1024)
    _expect_int(result["stderr_bytes"], "stderr bytes", maximum=256 * 1024)
    _expect_sha256(result["stdout_sha256"], "stdout digest")
    _expect_sha256(result["stderr_sha256"], "stderr digest")
    return result


def _validate_command(value: object) -> dict:
    command = _expect_keys(
        value,
        {"account_id", "region", "stack_name", "qualifier", "argv_contract"},
        "bootstrap upgrade command",
    )
    for field in ("account_id", "region", "stack_name", "qualifier"):
        _expect_string(command[field], f"bootstrap upgrade {field}")
    if not _ACCOUNT_RE.fullmatch(command["account_id"]):
        raise ValueError("bootstrap upgrade account ID is invalid")
    if not _REGION_RE.fullmatch(command["region"]):
        raise ValueError("bootstrap upgrade region is invalid")
    if not _STACK_RE.fullmatch(command["stack_name"]) or command["stack_name"] == "CDKToolkit":
        raise ValueError("bootstrap upgrade stack name is not unique")
    if not _QUALIFIER_RE.fullmatch(command["qualifier"]) or command["qualifier"] == "hnb659fds":
        raise ValueError("bootstrap upgrade qualifier is not unique")
    if command["argv_contract"] != _ARGV_CONTRACT:
        raise ValueError("bootstrap upgrade argv contract is unsupported")
    return command


def _expected_argv(command: Mapping[str, str]) -> list[str]:
    return [
        "bootstrap",
        f"aws://{command['account_id']}/{command['region']}",
        "--toolkit-stack-name",
        command["stack_name"],
        "--qualifier",
        command["qualifier"],
        "--bootstrap-kms-key-id",
        "AWS_MANAGED_KEY",
        "--yes",
        "--ci",
        "--no-color",
        "--no-notices",
        "--execute",
    ]


def _validate_run(value: object) -> dict:
    run = _expect_keys(
        value,
        {"repository", "commit_sha", "ref", "event", "workflow_path", "run_id", "run_attempt"},
        "bootstrap upgrade run",
    )
    _expect_string(run["repository"], "repository")
    if not isinstance(run["commit_sha"], str) or not _COMMIT_RE.fullmatch(run["commit_sha"]):
        raise ValueError("bootstrap upgrade source commit is invalid")
    _expect_int(run["run_attempt"], "workflow run attempt", minimum=1, maximum=1)
    if (
        run["ref"] != "refs/heads/main"
        or run["event"] != "push"
        or run["workflow_path"] != ".github/workflows/cdk-cli-blackbox.yml"
        or run["run_attempt"] != 1
    ):
        raise ValueError("bootstrap upgrade evidence is not a first workflow attempt on main")
    _expect_int(run["run_id"], "workflow run ID", minimum=1, maximum=2**63 - 1)
    return run


def _validate_platform(value: object) -> dict:
    platform = _expect_keys(
        value,
        {"id", "machine_arch", "node_arch", "python_version", "kernel_release"},
        "bootstrap upgrade platform",
    )
    if platform["id"] not in EXPECTED_PLATFORMS:
        raise ValueError("bootstrap upgrade platform is unsupported")
    for field in ("machine_arch", "node_arch", "python_version"):
        _expect_string(platform[field], f"bootstrap upgrade {field}", maximum=32)
    _expect_string(platform["kernel_release"], "bootstrap upgrade kernel release")
    if (platform["machine_arch"], platform["node_arch"]) != EXPECTED_ARCHITECTURES[platform["id"]]:
        raise ValueError("bootstrap upgrade platform is not native")
    return platform


def _validate_observation(value: object) -> dict:
    observation = _expect_keys(
        value,
        {
            "schema_version",
            "record_type",
            "observation_id",
            "scenario",
            "toolchain",
            "run",
            "platform",
            "command",
            "verification",
            "result",
            "observed_at",
        },
        "bootstrap upgrade observation",
    )
    if (
        observation["schema_version"] != SCHEMA_VERSION
        or observation["record_type"] != "observation"
    ):
        raise ValueError("unsupported bootstrap upgrade observation")
    if observation["scenario"] != SCENARIO or observation["toolchain"] != PINNED_TOOLCHAIN:
        raise ValueError("observation does not describe the pinned bootstrap upgrade")
    _validate_run(observation["run"])
    _validate_platform(observation["platform"])
    _validate_command(observation["command"])
    verification = _expect_keys(
        observation["verification"],
        {"contract", "stack_id_sha256", "role_identities_sha256"},
        "bootstrap upgrade verification",
    )
    if verification["contract"] != VERIFICATION_CONTRACT:
        raise ValueError("bootstrap upgrade verification contract is incomplete")
    _expect_sha256(verification["stack_id_sha256"], "stack identity digest")
    _expect_sha256(verification["role_identities_sha256"], "role identity digest")
    _validate_result(observation["result"])
    if not isinstance(observation["observed_at"], str) or not _UTC_RE.fullmatch(
        observation["observed_at"]
    ):
        raise ValueError("bootstrap upgrade observation time is invalid")
    _expect_sha256(observation["observation_id"], "observation digest")
    if observation["observation_id"] != _record_digest(observation, "observation_id"):
        raise ValueError("bootstrap upgrade observation digest is stale")
    return observation


def create_observation(
    *,
    platform_id: str,
    machine_arch: str,
    node_arch: str,
    python_version: str,
    kernel_release: str,
    repository: str,
    commit_sha: str,
    ref: str,
    event: str,
    workflow_path: str,
    run_id: int,
    run_attempt: int,
    account_id: str,
    region: str,
    stack_name: str,
    qualifier: str,
    argv: Sequence[str],
    stack_id: str,
    role_identities: Mapping[str, Mapping[str, str]],
    returncode: int,
    timed_out: bool,
    duration_ms: int,
    stdout: bytes,
    stderr: bytes,
    stdout_bytes: int,
    stderr_bytes: int,
    stdout_truncated: bool,
    stderr_truncated: bool,
    observed_at: str,
) -> dict:
    if stdout_bytes != len(stdout) or stderr_bytes != len(stderr):
        raise ValueError("untruncated bootstrap output totals must match captured output")
    if not isinstance(stack_id, str) or not stack_id:
        raise ValueError("bootstrap stack identity is missing")
    if len(role_identities) != 5:
        raise ValueError("bootstrap observation requires exactly five role identities")
    for identity in role_identities.values():
        if set(identity) != {"Arn", "RoleId"} or any(
            not isinstance(value, str) or not value for value in identity.values()
        ):
            raise ValueError("bootstrap observation contains a malformed role identity")
    command = _validate_command(
        {
            "account_id": account_id,
            "region": region,
            "stack_name": stack_name,
            "qualifier": qualifier,
            "argv_contract": _ARGV_CONTRACT,
        }
    )
    if list(argv) != _expected_argv(command):
        raise ValueError("bootstrap upgrade argv does not match the closed contract")
    observation = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "observation",
        "observation_id": "sha256:" + "0" * 64,
        "scenario": copy.deepcopy(SCENARIO),
        "toolchain": copy.deepcopy(PINNED_TOOLCHAIN),
        "run": {
            "repository": repository,
            "commit_sha": commit_sha,
            "ref": ref,
            "event": event,
            "workflow_path": workflow_path,
            "run_id": run_id,
            "run_attempt": run_attempt,
        },
        "platform": {
            "id": platform_id,
            "machine_arch": machine_arch,
            "node_arch": node_arch,
            "python_version": python_version,
            "kernel_release": kernel_release,
        },
        "command": command,
        "verification": {
            "contract": copy.deepcopy(VERIFICATION_CONTRACT),
            "stack_id_sha256": _sha256_bytes(stack_id.encode()),
            "role_identities_sha256": _value_digest(role_identities),
        },
        "result": {
            "status": "pass",
            "returncode": returncode,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
            "stdout_bytes": stdout_bytes,
            "stderr_bytes": stderr_bytes,
            "stdout_sha256": _sha256_bytes(stdout),
            "stderr_sha256": _sha256_bytes(stderr),
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        },
        "observed_at": observed_at,
    }
    observation["observation_id"] = _record_digest(observation, "observation_id")
    return _validate_observation(observation)


def _validate_lane_receipt(value: object) -> dict:
    receipt = _expect_keys(
        value,
        {
            "schema_version",
            "record_type",
            "receipt_id",
            "scenario",
            "toolchain",
            "run",
            "platform",
            "command",
            "verification",
            "result",
            "junit",
            "cleanup",
            "observed_at",
            "completed_at",
        },
        "bootstrap upgrade lane receipt",
    )
    if receipt["schema_version"] != SCHEMA_VERSION or receipt["record_type"] != "lane-receipt":
        raise ValueError("unsupported bootstrap upgrade lane receipt")
    if receipt["scenario"] != SCENARIO or receipt["toolchain"] != PINNED_TOOLCHAIN:
        raise ValueError("lane receipt does not match the pinned CDK toolchain")
    _validate_run(receipt["run"])
    _validate_platform(receipt["platform"])
    _validate_command(receipt["command"])
    verification = _expect_keys(
        receipt["verification"],
        {"contract", "stack_id_sha256", "role_identities_sha256"},
        "bootstrap upgrade verification",
    )
    if verification["contract"] != VERIFICATION_CONTRACT:
        raise ValueError("bootstrap upgrade verification contract is incomplete")
    _expect_sha256(verification["stack_id_sha256"], "stack identity digest")
    _expect_sha256(verification["role_identities_sha256"], "role identity digest")
    _validate_result(receipt["result"])
    junit = _expect_keys(receipt["junit"], {"sha256", "bytes"}, "bootstrap upgrade JUnit")
    _expect_sha256(junit["sha256"], "JUnit digest")
    _expect_int(junit["bytes"], "JUnit bytes", minimum=1, maximum=1024 * 1024)
    if receipt["cleanup"] != CLEANUP_CONTRACT:
        raise ValueError("bootstrap upgrade cleanup is not complete")
    for field in ("observed_at", "completed_at"):
        if not isinstance(receipt[field], str) or not _UTC_RE.fullmatch(receipt[field]):
            raise ValueError(f"bootstrap upgrade {field} is invalid")
    if receipt["completed_at"] < receipt["observed_at"]:
        raise ValueError("bootstrap upgrade receipt completed before its observation")
    _expect_sha256(receipt["receipt_id"], "lane receipt digest")
    if receipt["receipt_id"] != _record_digest(receipt, "receipt_id"):
        raise ValueError("bootstrap upgrade lane receipt digest is stale")
    return receipt


def create_lane_receipt(
    *,
    observation_path: Path,
    junit_path: Path,
    platform_id: str,
    machine_arch: str,
    node_arch: str,
    python_version: str,
    kernel_release: str,
    interface_names: Sequence[str],
    isolation_profile_id: str,
    completed_at: str,
    repository: str,
    commit_sha: str,
    ref: str,
    event: str,
    workflow_path: str,
    run_id: int,
    run_attempt: int,
) -> dict:
    observation = _validate_observation(load_bounded_json(observation_path, MAX_OBSERVATION_BYTES))
    expected_run = _validate_run(
        {
            "repository": repository,
            "commit_sha": commit_sha,
            "ref": ref,
            "event": event,
            "workflow_path": workflow_path,
            "run_id": run_id,
            "run_attempt": run_attempt,
        }
    )
    expected_platform = _validate_platform(
        {
            "id": platform_id,
            "machine_arch": machine_arch,
            "node_arch": node_arch,
            "python_version": python_version,
            "kernel_release": kernel_release,
        }
    )
    if observation["run"] != expected_run:
        raise ValueError("bootstrap upgrade observation belongs to a different workflow run")
    if observation["platform"] != expected_platform:
        raise ValueError("bootstrap upgrade observation belongs to a different platform")
    junit_payload = load_junit(junit_path)
    validate_junit_payload(junit_payload, scenario="bootstrap-upgrade-v28-v32")
    if list(interface_names) != ["lo"] or isolation_profile_id != "linux-net-pid-mount-nobody-v1":
        raise ValueError("bootstrap upgrade isolation does not match the pinned profile")
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "lane-receipt",
        "receipt_id": "sha256:" + "0" * 64,
        "scenario": copy.deepcopy(observation["scenario"]),
        "toolchain": copy.deepcopy(observation["toolchain"]),
        "run": copy.deepcopy(observation["run"]),
        "platform": copy.deepcopy(observation["platform"]),
        "command": copy.deepcopy(observation["command"]),
        "verification": copy.deepcopy(observation["verification"]),
        "result": copy.deepcopy(observation["result"]),
        "junit": {"sha256": _sha256_bytes(junit_payload), "bytes": len(junit_payload)},
        "cleanup": copy.deepcopy(CLEANUP_CONTRACT),
        "observed_at": observation["observed_at"],
        "completed_at": completed_at,
    }
    receipt["receipt_id"] = _record_digest(receipt, "receipt_id")
    return _validate_lane_receipt(receipt)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _pinned_input_digests(project_root: Path) -> dict[str, str]:
    result = {}
    for relative in PINNED_INPUTS:
        path = project_root / relative
        if not path.is_file():
            raise ValueError(f"pinned bootstrap upgrade input is missing: {relative}")
        result[relative] = _file_sha256(path)
    return result


def _claim_id(evidence: Mapping[str, object]) -> str:
    return _sha256_bytes(
        _canonical_bytes(
            {
                "scenario": evidence["scenario"],
                "toolchain": evidence["toolchain"],
                "verification_contract": evidence["verification_contract"],
                "harness": evidence["harness"],
                "platforms": [
                    {
                        "id": lane["platform"]["id"],
                        "machine_arch": lane["platform"]["machine_arch"],
                        "node_arch": lane["platform"]["node_arch"],
                    }
                    for lane in evidence["lanes"]
                ],
            }
        )
    )


def build_aggregate_evidence(
    *,
    receipt_paths: Mapping[str, Path],
    junit_paths: Mapping[str, Path],
    project_root: Path,
    repository: str,
    commit_sha: str,
    ref: str,
    event: str,
    workflow_path: str,
    run_id: int,
    run_attempt: int,
) -> dict:
    if set(receipt_paths) != set(EXPECTED_PLATFORMS) or set(junit_paths) != set(EXPECTED_PLATFORMS):
        raise ValueError("evidence requires exactly linux-amd64 and linux-arm64")
    expected_run = {
        "repository": repository,
        "commit_sha": commit_sha,
        "ref": ref,
        "event": event,
        "workflow_path": workflow_path,
        "run_id": run_id,
        "run_attempt": run_attempt,
    }
    _validate_run(expected_run)
    lanes = []
    for platform_id in EXPECTED_PLATFORMS:
        receipt = _validate_lane_receipt(load_bounded_json(receipt_paths[platform_id]))
        if receipt["run"] != expected_run or receipt["platform"]["id"] != platform_id:
            raise ValueError("bootstrap upgrade lane does not match its workflow matrix")
        junit_payload = load_junit(junit_paths[platform_id])
        validate_junit_payload(junit_payload, scenario="bootstrap-upgrade-v28-v32")
        if receipt["junit"] != {
            "sha256": _sha256_bytes(junit_payload),
            "bytes": len(junit_payload),
        }:
            raise ValueError("bootstrap upgrade receipt does not match its JUnit")
        lanes.append(receipt)

    input_digests = _pinned_input_digests(project_root)
    if (
        input_digests["tests/aws/templates/cdk_bootstrap_v28.yaml"]
        != PINNED_TOOLCHAIN["source_template_byte_sha256"]
    ):
        raise ValueError("source bootstrap fixture does not match the evidence contract")
    if (
        input_digests["tests/aws/templates/cdk_bootstrap_v32.yaml"]
        != PINNED_TOOLCHAIN["target_template_byte_sha256"]
    ):
        raise ValueError("target bootstrap fixture does not match the evidence contract")
    package_lock = json.loads((project_root / "tests/aws/cli/package-lock.json").read_bytes())
    if package_lock["packages"]["node_modules/aws-cdk"].get("integrity") != NPM_INTEGRITY:
        raise ValueError("CDK package integrity does not match the evidence contract")
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "aggregate",
        "mode": "diagnostic-candidate",
        "evidence_id": "sha256:" + "0" * 64,
        "claim_id": "sha256:" + "0" * 64,
        "subject": {"repository": repository, "commit_sha": commit_sha, "ref": ref},
        "run": {
            "provider": "github-actions",
            "workflow_path": workflow_path,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "event": event,
        },
        "scenario": copy.deepcopy(SCENARIO),
        "toolchain": {**copy.deepcopy(PINNED_TOOLCHAIN), "npm_integrity": NPM_INTEGRITY},
        "verification_contract": {
            "functional": copy.deepcopy(VERIFICATION_CONTRACT),
            "cleanup": copy.deepcopy(CLEANUP_CONTRACT),
        },
        "harness": {"input_sha256": input_digests},
        "lanes": lanes,
        "promotion": {"eligible": False, "blockers": list(PROMOTION_BLOCKERS)},
    }
    evidence["claim_id"] = _claim_id(evidence)
    evidence["evidence_id"] = _record_digest(evidence, "evidence_id")
    return validate_aggregate_evidence(evidence)


def validate_aggregate_evidence(value: object) -> dict:
    evidence = _expect_keys(
        value,
        {
            "schema_version",
            "record_type",
            "mode",
            "evidence_id",
            "claim_id",
            "subject",
            "run",
            "scenario",
            "toolchain",
            "verification_contract",
            "harness",
            "lanes",
            "promotion",
        },
        "bootstrap upgrade aggregate evidence",
    )
    if (
        evidence["schema_version"] != SCHEMA_VERSION
        or evidence["record_type"] != "aggregate"
        or evidence["mode"] != "diagnostic-candidate"
    ):
        raise ValueError("unsupported bootstrap upgrade aggregate evidence")
    if evidence["scenario"] != SCENARIO:
        raise ValueError("aggregate does not describe the pinned bootstrap upgrade")
    expected_toolchain = {**PINNED_TOOLCHAIN, "npm_integrity": NPM_INTEGRITY}
    if evidence["toolchain"] != expected_toolchain:
        raise ValueError("aggregate does not match the pinned CDK toolchain")
    if evidence["verification_contract"] != {
        "functional": VERIFICATION_CONTRACT,
        "cleanup": CLEANUP_CONTRACT,
    }:
        raise ValueError("aggregate bootstrap verification contract is incomplete")
    subject = _expect_keys(evidence["subject"], {"repository", "commit_sha", "ref"}, "subject")
    run = _expect_keys(
        evidence["run"],
        {"provider", "workflow_path", "run_id", "run_attempt", "event"},
        "aggregate run",
    )
    expected_run = {
        "repository": subject["repository"],
        "commit_sha": subject["commit_sha"],
        "ref": subject["ref"],
        "event": run["event"],
        "workflow_path": run["workflow_path"],
        "run_id": run["run_id"],
        "run_attempt": run["run_attempt"],
    }
    if run["provider"] != "github-actions":
        raise ValueError("bootstrap upgrade evidence provider is invalid")
    _validate_run(expected_run)
    harness = _expect_keys(evidence["harness"], {"input_sha256"}, "bootstrap upgrade harness")
    digests = harness["input_sha256"]
    if not isinstance(digests, dict) or set(digests) != set(PINNED_INPUTS):
        raise ValueError("bootstrap upgrade harness input set is not exact")
    for path, digest in digests.items():
        if Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("bootstrap upgrade harness path is unsafe")
        _expect_sha256(digest, "bootstrap upgrade harness digest")
    if (
        digests["tests/aws/templates/cdk_bootstrap_v28.yaml"]
        != PINNED_TOOLCHAIN["source_template_byte_sha256"]
        or digests["tests/aws/templates/cdk_bootstrap_v32.yaml"]
        != PINNED_TOOLCHAIN["target_template_byte_sha256"]
    ):
        raise ValueError("bootstrap upgrade fixture digest is stale")
    lanes = evidence["lanes"]
    if not isinstance(lanes, list) or [
        lane.get("platform", {}).get("id") for lane in lanes
    ] != list(EXPECTED_PLATFORMS):
        raise ValueError("aggregate evidence does not contain the exact platform matrix")
    for lane in lanes:
        _validate_lane_receipt(lane)
        if lane["run"] != expected_run:
            raise ValueError("bootstrap upgrade lane comes from another run")
    targets = {(lane["command"]["account_id"], lane["command"]["region"]) for lane in lanes}
    if len(targets) != 1:
        raise ValueError("bootstrap upgrade lanes do not use the same local target")
    if evidence["promotion"] != {
        "eligible": False,
        "blockers": list(PROMOTION_BLOCKERS),
    }:
        raise ValueError("bootstrap upgrade evidence cannot authorize promotion")
    _expect_sha256(evidence["claim_id"], "claim digest")
    _expect_sha256(evidence["evidence_id"], "evidence digest")
    if evidence["claim_id"] != _claim_id(evidence):
        raise ValueError("bootstrap upgrade claim digest is stale")
    if evidence["evidence_id"] != _record_digest(evidence, "evidence_id"):
        raise ValueError("bootstrap upgrade evidence digest is stale")
    return evidence


def _lane_command(args: argparse.Namespace) -> None:
    import platform
    from datetime import UTC, datetime

    receipt = create_lane_receipt(
        observation_path=args.observation,
        junit_path=args.junit,
        platform_id=args.platform_id,
        machine_arch=args.machine_arch,
        node_arch=args.node_arch,
        python_version=platform.python_version(),
        kernel_release=platform.release(),
        interface_names=["lo"],
        isolation_profile_id="linux-net-pid-mount-nobody-v1",
        completed_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        repository=args.repository,
        commit_sha=args.commit_sha,
        ref=args.ref,
        event=args.event,
        workflow_path=args.workflow_path,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
    )
    write_canonical_json(args.output, receipt, MAX_EVIDENCE_BYTES)


def _aggregate_command(args: argparse.Namespace) -> None:
    evidence = build_aggregate_evidence(
        receipt_paths={"linux-amd64": args.receipt_amd64, "linux-arm64": args.receipt_arm64},
        junit_paths={"linux-amd64": args.junit_amd64, "linux-arm64": args.junit_arm64},
        project_root=args.project_root,
        repository=args.repository,
        commit_sha=args.commit_sha,
        ref=args.ref,
        event=args.event,
        workflow_path=args.workflow_path,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
    )
    write_canonical_json(args.output, evidence, MAX_EVIDENCE_BYTES)


def _add_run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    lane = subparsers.add_parser("lane")
    lane.add_argument("--observation", type=Path, required=True)
    lane.add_argument("--junit", type=Path, required=True)
    lane.add_argument("--platform-id", required=True)
    lane.add_argument("--machine-arch", required=True)
    lane.add_argument("--node-arch", required=True)
    lane.add_argument("--output", type=Path, required=True)
    _add_run_arguments(lane)
    lane.set_defaults(handler=_lane_command)
    aggregate = subparsers.add_parser("aggregate")
    aggregate.add_argument("--receipt-amd64", type=Path, required=True)
    aggregate.add_argument("--receipt-arm64", type=Path, required=True)
    aggregate.add_argument("--junit-amd64", type=Path, required=True)
    aggregate.add_argument("--junit-arm64", type=Path, required=True)
    aggregate.add_argument("--project-root", type=Path, required=True)
    aggregate.add_argument("--output", type=Path, required=True)
    _add_run_arguments(aggregate)
    aggregate.set_defaults(handler=_aggregate_command)
    args = parser.parse_args(argv)
    args.handler(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
