import argparse
import copy
import json
import os
import re
import shlex
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
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
        read_regular_bounded,
        write_canonical_json,
    )
    from .python_synth_toolchain import (
        INSTALL_ARGV_CONTRACT,
        RESOLVE_ARGV_CONTRACT,
        ROOTS,
        load_toolchain_manifest,
    )
    from .validate_junit import load_junit, validate_junit_payload
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
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
        read_regular_bounded,
        write_canonical_json,
    )
    from python_synth_toolchain import (
        INSTALL_ARGV_CONTRACT,
        RESOLVE_ARGV_CONTRACT,
        ROOTS,
        load_toolchain_manifest,
    )
    from validate_junit import load_junit, validate_junit_payload

MAX_OBSERVATION_BYTES = 8 * 1024
MAX_ASSEMBLY_FILE_BYTES = 1024 * 1024
MAX_ASSEMBLY_TOTAL_BYTES = 2 * 1024 * 1024
SCHEMA_VERSION = 2
SCENARIO = {
    "id": "synth-python-minimal-sqs-v1",
    "result": "cli-pass",
    "construct_language": "python",
    "cloud_assembly_produced": True,
    "resource_deployment_performed": False,
    "aws_differential": False,
    "user_authored_assets": False,
    "cleanup_required": True,
}
PINNED_PYTHON_PACKAGES = {
    "aws-cdk-lib": "2.241.0",
    "aws-cdk-cloud-assembly-schema": "52.2.0",
    "constructs": "10.5.1",
    "jsii": "1.127.0",
}
PINNED_TOOLCHAIN = {
    "node_version": "22.23.2",
    "cdk_cli_version": "2.1135.1",
    "python_packages": PINNED_PYTHON_PACKAGES,
    "cloud_assembly_schema_sha256": (
        "sha256:ba8defba06c63d1a9ae2c7218c0d089372547629205b5fcb862ddd911efef3f8"
    ),
    "emitted_assembly_version": "52.0.0",
}
ASSEMBLY_CONTRACT = {
    "stack_name": "SynthStack",
    "resource_type": "AWS::SQS::Queue",
    "default_stack_synthesizer": True,
    "top_level_references_closed": True,
    "template_asset_hash": "039a840a9267a7acf895d29d5f2bd4894a720070cff12e3f10dd9852b76f4e1c",
}
ASSEMBLY_FILES = (
    "SynthStack.assets.json",
    "SynthStack.template.json",
    "cdk.out",
    "manifest.json",
    "tree.json",
)
CLEANUP_CONTRACT = {"completed": True, "assembly_output_absent": True}
EXPECTED_PLATFORMS = ("linux-amd64", "linux-arm64")
EXPECTED_ARCHITECTURES = {
    "linux-amd64": ("x86_64", "x64"),
    "linux-arm64": ("aarch64", "arm64"),
}
PROMOTION_BLOCKERS = (
    "not-reviewed-for-promotion",
    "no-deploy",
    "no-aws-differential",
    "only-python",
)
SUPPLY_CHAIN_CONTRACT = {
    "profile": "official-wheel-origins-resolved-hash-locked-offline-venv-v2",
    "origins_sha256": "sha256:8b6b4587079238976f90063c1a56730c1f3341c2ac5836908d4504db80b1efb1",
    "lock_sha256": "sha256:b59bb9d70da365d145fc5b8ac01839da9de6853eb304b3c013aa6ab8c6803399",
    "runtime_wheel_inventory_sha256": (
        "sha256:fd0a1699615525422b92d8676036b5e376d1def1dd72373666e939df8f050668"
    ),
    "runtime_wheel_count": 14,
    "runtime_wheel_total_bytes": 71824153,
    "installed_metadata_sha256": (
        "sha256:82850eb3ba098852ccaf0a4ed2e323b3453d91c0f7a2f60811168b10cc8048fb"
    ),
    "installer": {
        "project": "pip",
        "version": "26.0.1",
        "filename": "pip-26.0.1-py3-none-any.whl",
        "bytes": 1787723,
        "sha256": "sha256:bdb1b08f4274833d62c1aa29e20907365a2ceb950410df15fc9521bad440122b",
    },
    "installation": {
        "network_isolated": True,
        "non_root": True,
        "venv_without_pip": True,
        "venv_read_only_at_runtime": True,
        "runtime_environment_reverified": True,
        "dependencies_resolved": True,
        "resolver_roots": list(ROOTS),
        "source_date_epoch": 0,
        "resolve_argv_contract": list(RESOLVE_ARGV_CONTRACT),
        "argv_contract": list(INSTALL_ARGV_CONTRACT),
    },
}
PINNED_INPUTS = (
    ".github/workflows/cdk-cli-blackbox.yml",
    ".python-version",
    "Makefile",
    "capabilities/cdk/compatibility.json",
    "capabilities/cdk/python-synth-execution-evidence-v2.schema.json",
    "localstack-core/localstack/cli/_cdk_health_probe.py",
    "localstack-core/localstack/cli/cdk.py",
    "pyproject.toml",
    "requirements-test.txt",
    "scripts/run_cdk_cli_blackbox_isolated.sh",
    "tests/aws/cli/execution_evidence.py",
    "tests/aws/cli/fixtures/cdk_apps/python/minimal_sqs.py",
    "tests/aws/cli/package-lock.json",
    "tests/aws/cli/package.json",
    "tests/aws/cli/python-synth-requirements.lock",
    "tests/aws/cli/python-synth-wheel-origins.json",
    "tests/aws/cli/python_synth_execution_evidence_v2.py",
    "tests/aws/cli/python_synth_toolchain.py",
    "tests/aws/cli/test_cdk_cli_blackbox.py",
    "tests/aws/cli/test_cdk_cli_bootstrap_upgrade.py",
    "tests/aws/cli/test_cdk_cli_python_synth.py",
    "tests/aws/cli/validate_junit.py",
)
WORKFLOW_PATH = ".github/workflows/cdk-cli-blackbox.yml"
ARGV_CONTRACT = "synth-python-minimal-sqs-v1"
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")


def _value_digest(value: object) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _validate_utc(value: object, label: str) -> str:
    if not isinstance(value, str) or not _UTC_RE.fullmatch(value):
        raise ValueError(f"{label} is not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(f"{label} is not a valid UTC timestamp") from error
    if parsed.tzinfo != UTC:
        raise ValueError(f"{label} is not UTC")
    return value


def _validate_run(value: object) -> dict:
    run = _expect_keys(
        value,
        {"repository", "commit_sha", "ref", "event", "workflow_path", "run_id", "run_attempt"},
        "Python synth run",
    )
    _expect_string(run["repository"], "repository")
    if not isinstance(run["commit_sha"], str) or not _COMMIT_RE.fullmatch(run["commit_sha"]):
        raise ValueError("Python synth source commit is invalid")
    if (
        run["ref"] != "refs/heads/main"
        or run["event"] != "push"
        or run["workflow_path"] != WORKFLOW_PATH
        or run["run_attempt"] != 1
    ):
        raise ValueError("Python synth evidence is not a first workflow attempt on main")
    _expect_int(run["run_id"], "workflow run ID", minimum=1, maximum=2**63 - 1)
    _expect_int(run["run_attempt"], "workflow run attempt", minimum=1, maximum=1)
    return run


def _validate_platform(value: object) -> dict:
    platform = _expect_keys(
        value,
        {"id", "machine_arch", "node_arch", "python_version", "kernel_release"},
        "Python synth platform",
    )
    if platform["id"] not in EXPECTED_PLATFORMS:
        raise ValueError("Python synth platform is unsupported")
    for field in ("machine_arch", "node_arch", "python_version"):
        _expect_string(platform[field], f"Python synth {field}", maximum=32)
    _expect_string(platform["kernel_release"], "Python synth kernel release")
    if (platform["machine_arch"], platform["node_arch"]) != EXPECTED_ARCHITECTURES[platform["id"]]:
        raise ValueError("Python synth platform is not native")
    return platform


def _validate_toolchain(value: object, *, aggregate: bool = False) -> dict:
    expected = copy.deepcopy(PINNED_TOOLCHAIN)
    if aggregate:
        expected["npm_integrity"] = NPM_INTEGRITY
    toolchain = _expect_keys(value, set(expected), "Python synth toolchain")
    if toolchain != expected:
        raise ValueError("Python synth toolchain does not match the pinned contract")
    return toolchain


def _supply_chain_from_manifest(manifest: Mapping[str, object]) -> dict:
    wheels = manifest["wheels"]
    runtime_inventory = [
        {
            key: wheel[key]
            for key in (
                "role",
                "project",
                "version",
                "filename",
                "bytes",
                "sha256",
                "metadata_sha256",
                "tags",
            )
        }
        for wheel in wheels
    ]
    runtime_digest = _sha256_bytes(_canonical_bytes(runtime_inventory))
    contract = copy.deepcopy(SUPPLY_CHAIN_CONTRACT)
    if (
        "sha256:" + manifest["origins_sha256"] != contract["origins_sha256"]
        or "sha256:" + manifest["lock_sha256"] != contract["lock_sha256"]
        or runtime_digest != contract["runtime_wheel_inventory_sha256"]
        or len(runtime_inventory) != contract["runtime_wheel_count"]
        or sum(wheel["bytes"] for wheel in runtime_inventory)
        != contract["runtime_wheel_total_bytes"]
        or "sha256:" + manifest["installed_metadata_sha256"]
        != contract["installed_metadata_sha256"]
    ):
        raise ValueError("Python synth supply chain manifest does not match the pinned contract")
    return {
        "contract": contract,
        "installed_tree_sha256": "sha256:" + manifest["installed_tree_sha256"],
        "toolchain_manifest_sha256": "sha256:" + manifest["manifest_sha256"],
    }


def _validate_supply_chain(value: object) -> dict:
    supply_chain = _expect_keys(
        value,
        {"contract", "installed_tree_sha256", "toolchain_manifest_sha256"},
        "Python synth supply chain",
    )
    if supply_chain["contract"] != SUPPLY_CHAIN_CONTRACT:
        raise ValueError("Python synth supply chain contract is stale")
    _expect_sha256(supply_chain["installed_tree_sha256"], "installed tree digest")
    _expect_sha256(supply_chain["toolchain_manifest_sha256"], "toolchain manifest digest")
    return supply_chain


def _validate_command(value: object) -> dict:
    command = _expect_keys(value, {"stack_name", "argv_contract", "app_sha256"}, "synth command")
    if command["stack_name"] != "SynthStack" or command["argv_contract"] != ARGV_CONTRACT:
        raise ValueError("Python synth command does not match the closed contract")
    _expect_sha256(command["app_sha256"], "Python synth app digest")
    return command


def _expected_argv(
    *, python_executable: str, app_path: str, assembly_output_path: str
) -> list[str]:
    app_command = shlex.join((python_executable, "-I", "-B", app_path))
    return [
        "synth",
        "SynthStack",
        "--app",
        app_command,
        "--output",
        assembly_output_path,
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


def _validate_assembly(value: object) -> dict:
    assembly = _expect_keys(value, {"contract", "files", "total_bytes"}, "Cloud Assembly")
    if assembly["contract"] != ASSEMBLY_CONTRACT:
        raise ValueError("Cloud Assembly verification contract is incomplete")
    files = assembly["files"]
    if not isinstance(files, list) or len(files) != len(ASSEMBLY_FILES):
        raise ValueError("Cloud Assembly evidence requires the exact file inventory")
    sizes = []
    for expected_name, entry in zip(ASSEMBLY_FILES, files, strict=True):
        entry = _expect_keys(entry, {"name", "bytes", "sha256"}, "Cloud Assembly file")
        if entry["name"] != expected_name:
            raise ValueError("Cloud Assembly evidence file order or name is invalid")
        sizes.append(
            _expect_int(
                entry["bytes"],
                "Cloud Assembly file size",
                minimum=1,
                maximum=MAX_ASSEMBLY_FILE_BYTES,
            )
        )
        _expect_sha256(entry["sha256"], "Cloud Assembly file digest")
    total = _expect_int(
        assembly["total_bytes"],
        "Cloud Assembly total size",
        minimum=len(ASSEMBLY_FILES),
        maximum=MAX_ASSEMBLY_TOTAL_BYTES,
    )
    if total != sum(sizes):
        raise ValueError("Cloud Assembly total size does not match its inventory")
    return assembly


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
        "Python synth result",
    )
    if (
        result["status"] != "pass"
        or result["returncode"] != 0
        or result["timed_out"] is not False
        or result["stdout_truncated"] is not False
        or result["stderr_truncated"] is not False
    ):
        raise ValueError("Python synth result is not an exact pass")
    _expect_int(result["duration_ms"], "synth duration", maximum=60_000)
    _expect_int(result["stdout_bytes"], "stdout bytes", maximum=256 * 1024)
    _expect_int(result["stderr_bytes"], "stderr bytes", maximum=256 * 1024)
    _expect_sha256(result["stdout_sha256"], "stdout digest")
    _expect_sha256(result["stderr_sha256"], "stderr digest")
    return result


def _validate_observation(value: object) -> dict:
    observation = _expect_keys(
        value,
        {
            "schema_version",
            "record_type",
            "observation_id",
            "scenario",
            "toolchain",
            "supply_chain",
            "run",
            "platform",
            "command",
            "assembly",
            "result",
            "observed_at",
        },
        "Python synth observation",
    )
    if (
        observation["schema_version"] != SCHEMA_VERSION
        or observation["record_type"] != "observation"
    ):
        raise ValueError("unsupported Python synth observation")
    if observation["scenario"] != SCENARIO:
        raise ValueError("observation does not describe the pinned Python synth scenario")
    _validate_toolchain(observation["toolchain"])
    _validate_supply_chain(observation["supply_chain"])
    _validate_run(observation["run"])
    _validate_platform(observation["platform"])
    _validate_command(observation["command"])
    _validate_assembly(observation["assembly"])
    _validate_result(observation["result"])
    _validate_utc(observation["observed_at"], "Python synth observation time")
    _expect_sha256(observation["observation_id"], "observation digest")
    if observation["observation_id"] != _record_digest(observation, "observation_id"):
        raise ValueError("Python synth observation digest is stale")
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
    python_executable: Path,
    app_path: Path,
    output_path: Path,
    argv: Sequence[str],
    assembly_files: Mapping[str, bytes],
    schema_payload: bytes,
    toolchain_manifest_path: Path,
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
    for label, value in (
        ("Python executable", os.fspath(python_executable)),
        ("CDK app path", os.fspath(app_path)),
        ("Cloud Assembly output path", os.fspath(output_path)),
    ):
        _expect_string(value, label, maximum=4096)
        if not Path(value).is_absolute():
            raise ValueError(f"{label} must be absolute")
    if list(argv) != _expected_argv(
        python_executable=os.fspath(python_executable),
        app_path=os.fspath(app_path),
        assembly_output_path=os.fspath(output_path),
    ):
        raise ValueError("Python synth argv does not match the closed contract")
    app_bytes = read_regular_bounded(app_path, MAX_ASSEMBLY_FILE_BYTES)
    if not app_bytes:
        raise ValueError("Python synth app is empty")
    if (
        not isinstance(schema_payload, bytes)
        or _sha256_bytes(schema_payload) != PINNED_TOOLCHAIN["cloud_assembly_schema_sha256"]
    ):
        raise ValueError("Cloud Assembly schema does not match the pinned contract")
    if set(assembly_files) != set(ASSEMBLY_FILES):
        raise ValueError("Cloud Assembly evidence requires the exact file inventory")
    entries = []
    for name in ASSEMBLY_FILES:
        payload = assembly_files[name]
        if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_ASSEMBLY_FILE_BYTES:
            raise ValueError("Cloud Assembly file bytes are outside the accepted bounds")
        entries.append({"name": name, "bytes": len(payload), "sha256": _sha256_bytes(payload)})
    if sum(entry["bytes"] for entry in entries) > MAX_ASSEMBLY_TOTAL_BYTES:
        raise ValueError("Cloud Assembly total size is outside the accepted bounds")
    if stdout_bytes != len(stdout) or stderr_bytes != len(stderr):
        raise ValueError("untruncated Python synth output totals must match captured output")
    toolchain = copy.deepcopy(PINNED_TOOLCHAIN)
    _validate_toolchain(toolchain)
    supply_chain = _supply_chain_from_manifest(load_toolchain_manifest(toolchain_manifest_path))
    observation = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "observation",
        "observation_id": "sha256:" + "0" * 64,
        "scenario": copy.deepcopy(SCENARIO),
        "toolchain": toolchain,
        "supply_chain": supply_chain,
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
        "command": {
            "stack_name": "SynthStack",
            "argv_contract": ARGV_CONTRACT,
            "app_sha256": _sha256_bytes(app_bytes),
        },
        "assembly": {
            "contract": copy.deepcopy(ASSEMBLY_CONTRACT),
            "files": entries,
            "total_bytes": sum(entry["bytes"] for entry in entries),
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
            "supply_chain",
            "run",
            "platform",
            "command",
            "assembly",
            "result",
            "junit",
            "isolation",
            "cleanup",
            "observed_at",
            "completed_at",
        },
        "Python synth lane receipt",
    )
    if receipt["schema_version"] != SCHEMA_VERSION or receipt["record_type"] != "lane-receipt":
        raise ValueError("unsupported Python synth lane receipt")
    if receipt["scenario"] != SCENARIO:
        raise ValueError("lane receipt does not describe the pinned Python synth scenario")
    _validate_toolchain(receipt["toolchain"])
    _validate_supply_chain(receipt["supply_chain"])
    _validate_run(receipt["run"])
    _validate_platform(receipt["platform"])
    _validate_command(receipt["command"])
    _validate_assembly(receipt["assembly"])
    _validate_result(receipt["result"])
    junit = _expect_keys(receipt["junit"], {"sha256", "bytes"}, "Python synth JUnit")
    _expect_sha256(junit["sha256"], "JUnit digest")
    _expect_int(junit["bytes"], "JUnit bytes", minimum=1, maximum=1024 * 1024)
    if receipt["isolation"] != {
        "profile_id": "linux-net-pid-mount-nobody-v1",
        "interface_names": ["lo"],
    }:
        raise ValueError("Python synth isolation does not match the pinned profile")
    if receipt["cleanup"] != CLEANUP_CONTRACT:
        raise ValueError("Python synth cleanup is not complete")
    observed = _validate_utc(receipt["observed_at"], "Python synth observation time")
    completed = _validate_utc(receipt["completed_at"], "Python synth completion time")
    if datetime.fromisoformat(completed[:-1] + "+00:00") < datetime.fromisoformat(
        observed[:-1] + "+00:00"
    ):
        raise ValueError("Python synth receipt completed before its observation")
    _expect_sha256(receipt["receipt_id"], "lane receipt digest")
    if receipt["receipt_id"] != _record_digest(receipt, "receipt_id"):
        raise ValueError("Python synth lane receipt digest is stale")
    return receipt


def create_lane_receipt(
    *,
    observation_path: Path,
    junit_path: Path,
    assembly_output_path: Path,
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
        raise ValueError("Python synth observation belongs to a different workflow run")
    if observation["platform"] != expected_platform:
        raise ValueError("Python synth observation belongs to a different platform")
    if os.path.lexists(assembly_output_path):
        raise ValueError("Cloud Assembly output still exists; cleanup is incomplete")
    junit_payload = load_junit(junit_path)
    validate_junit_payload(junit_payload, scenario=SCENARIO["id"])
    if list(interface_names) != ["lo"] or isolation_profile_id != "linux-net-pid-mount-nobody-v1":
        raise ValueError("Python synth isolation does not match the pinned profile")
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "lane-receipt",
        "receipt_id": "sha256:" + "0" * 64,
        "scenario": copy.deepcopy(observation["scenario"]),
        "toolchain": copy.deepcopy(observation["toolchain"]),
        "supply_chain": copy.deepcopy(observation["supply_chain"]),
        "run": copy.deepcopy(observation["run"]),
        "platform": copy.deepcopy(observation["platform"]),
        "command": copy.deepcopy(observation["command"]),
        "assembly": copy.deepcopy(observation["assembly"]),
        "result": copy.deepcopy(observation["result"]),
        "junit": {"sha256": _sha256_bytes(junit_payload), "bytes": len(junit_payload)},
        "isolation": {
            "profile_id": isolation_profile_id,
            "interface_names": list(interface_names),
        },
        "cleanup": copy.deepcopy(CLEANUP_CONTRACT),
        "observed_at": observation["observed_at"],
        "completed_at": completed_at,
    }
    receipt["receipt_id"] = _record_digest(receipt, "receipt_id")
    return _validate_lane_receipt(receipt)


def _pinned_input_digests(project_root: Path) -> dict[str, str]:
    result = {}
    for relative in PINNED_INPUTS:
        payload = read_regular_bounded(project_root / relative, 4 * 1024 * 1024)
        result[relative] = _sha256_bytes(payload)
    return result


def _claim_id(evidence: Mapping[str, object]) -> str:
    return _sha256_bytes(
        _canonical_bytes(
            {
                "scenario": evidence["scenario"],
                "toolchain": evidence["toolchain"],
                "verification_contract": evidence["verification_contract"],
                "harness": evidence["harness"],
                "command": evidence["lanes"][0]["command"],
                "assembly": evidence["lanes"][0]["assembly"],
                "supply_chain": [lane["supply_chain"] for lane in evidence["lanes"]],
                "platforms": [
                    {
                        "id": lane["platform"]["id"],
                        "machine_arch": lane["platform"]["machine_arch"],
                        "node_arch": lane["platform"]["node_arch"],
                        "python_version": lane["platform"]["python_version"],
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
        raise ValueError("Python synth evidence requires exactly linux-amd64 and linux-arm64")
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
    lanes = []
    for platform_id in EXPECTED_PLATFORMS:
        receipt = _validate_lane_receipt(load_bounded_json(receipt_paths[platform_id]))
        if receipt["run"] != expected_run or receipt["platform"]["id"] != platform_id:
            raise ValueError("Python synth lane does not match its workflow matrix")
        junit_payload = load_junit(junit_paths[platform_id])
        validate_junit_payload(junit_payload, scenario=SCENARIO["id"])
        if receipt["junit"] != {
            "sha256": _sha256_bytes(junit_payload),
            "bytes": len(junit_payload),
        }:
            raise ValueError("Python synth receipt does not match its JUnit")
        lanes.append(receipt)
    for field in ("toolchain", "command", "assembly"):
        if lanes[0][field] != lanes[1][field]:
            raise ValueError(f"Python synth lanes disagree on {field}")
    if lanes[0]["supply_chain"]["contract"] != lanes[1]["supply_chain"]["contract"]:
        raise ValueError("Python synth lanes disagree on the supply chain contract")
    if (
        lanes[0]["supply_chain"]["installed_tree_sha256"]
        != lanes[1]["supply_chain"]["installed_tree_sha256"]
    ):
        raise ValueError("Python synth lanes disagree on the installed environment")
    if lanes[0]["platform"]["python_version"] != lanes[1]["platform"]["python_version"]:
        raise ValueError("Python synth lanes disagree on the Python patch version")
    input_digests = _pinned_input_digests(project_root)
    package_lock = json.loads(
        read_regular_bounded(project_root / "tests/aws/cli/package-lock.json", 4 * 1024 * 1024)
    )
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
            "assembly": copy.deepcopy(ASSEMBLY_CONTRACT),
            "cleanup": copy.deepcopy(CLEANUP_CONTRACT),
            "supply_chain": copy.deepcopy(SUPPLY_CHAIN_CONTRACT),
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
        "Python synth aggregate evidence",
    )
    if (
        evidence["schema_version"] != SCHEMA_VERSION
        or evidence["record_type"] != "aggregate"
        or evidence["mode"] != "diagnostic-candidate"
    ):
        raise ValueError("unsupported Python synth aggregate evidence")
    if evidence["scenario"] != SCENARIO:
        raise ValueError("aggregate does not describe the pinned Python synth scenario")
    _validate_toolchain(evidence["toolchain"], aggregate=True)
    if evidence["verification_contract"] != {
        "assembly": ASSEMBLY_CONTRACT,
        "cleanup": CLEANUP_CONTRACT,
        "supply_chain": SUPPLY_CHAIN_CONTRACT,
    }:
        raise ValueError("aggregate Python synth verification contract is incomplete")
    subject = _expect_keys(evidence["subject"], {"repository", "commit_sha", "ref"}, "subject")
    run = _expect_keys(
        evidence["run"],
        {"provider", "workflow_path", "run_id", "run_attempt", "event"},
        "aggregate run",
    )
    if run["provider"] != "github-actions":
        raise ValueError("Python synth evidence provider is invalid")
    expected_run = _validate_run(
        {
            "repository": subject["repository"],
            "commit_sha": subject["commit_sha"],
            "ref": subject["ref"],
            "event": run["event"],
            "workflow_path": run["workflow_path"],
            "run_id": run["run_id"],
            "run_attempt": run["run_attempt"],
        }
    )
    harness = _expect_keys(evidence["harness"], {"input_sha256"}, "Python synth harness")
    digests = harness["input_sha256"]
    if not isinstance(digests, dict) or set(digests) != set(PINNED_INPUTS):
        raise ValueError("Python synth harness input set is not exact")
    for path, digest in digests.items():
        if Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("Python synth harness path is unsafe")
        _expect_sha256(digest, "Python synth harness digest")
    lanes = evidence["lanes"]
    if not isinstance(lanes, list) or [
        lane.get("platform", {}).get("id") for lane in lanes if isinstance(lane, dict)
    ] != list(EXPECTED_PLATFORMS):
        raise ValueError("aggregate evidence does not contain the exact platform matrix")
    for lane in lanes:
        _validate_lane_receipt(lane)
        if lane["run"] != expected_run:
            raise ValueError("Python synth lane comes from another run")
    for field in ("toolchain", "command", "assembly"):
        if lanes[0][field] != lanes[1][field]:
            raise ValueError(f"Python synth lanes disagree on {field}")
    if lanes[0]["supply_chain"]["contract"] != lanes[1]["supply_chain"]["contract"]:
        raise ValueError("Python synth lanes disagree on the supply chain contract")
    if (
        lanes[0]["supply_chain"]["installed_tree_sha256"]
        != lanes[1]["supply_chain"]["installed_tree_sha256"]
    ):
        raise ValueError("Python synth lanes disagree on the installed environment")
    if lanes[0]["platform"]["python_version"] != lanes[1]["platform"]["python_version"]:
        raise ValueError("Python synth lanes disagree on the Python patch version")
    if evidence["promotion"] != {"eligible": False, "blockers": list(PROMOTION_BLOCKERS)}:
        raise ValueError("Python synth diagnostic evidence cannot authorize promotion")
    _expect_sha256(evidence["claim_id"], "claim digest")
    _expect_sha256(evidence["evidence_id"], "evidence digest")
    if evidence["claim_id"] != _claim_id(evidence):
        raise ValueError("Python synth claim digest is stale")
    if evidence["evidence_id"] != _record_digest(evidence, "evidence_id"):
        raise ValueError("Python synth evidence digest is stale")
    return evidence


def _lane_command(args: argparse.Namespace) -> None:
    import platform

    receipt = create_lane_receipt(
        observation_path=args.observation,
        junit_path=args.junit,
        assembly_output_path=args.assembly_output,
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
    lane.add_argument("--assembly-output", type=Path, required=True)
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
