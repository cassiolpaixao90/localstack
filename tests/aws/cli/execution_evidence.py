import argparse
import copy
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path

if __package__:
    from .validate_junit import load_junit, validate_junit_payload
else:
    from validate_junit import load_junit, validate_junit_payload

MAX_EVIDENCE_BYTES = 64 * 1024
SCHEMA_VERSION = 1
SCENARIO = {
    "id": "bootstrap-show-template-v32",
    "result": "cli-pass",
    "construct_language": None,
    "cloud_assembly_produced": False,
    "resource_deployment_performed": False,
    "aws_differential": False,
}
EXPECTED_PLATFORMS = ("linux-amd64", "linux-arm64")
EXPECTED_ARCHITECTURES = {
    "linux-amd64": ("x86_64", "x64"),
    "linux-arm64": ("aarch64", "arm64"),
}
PROMOTION_BLOCKERS = (
    "no-bootstrap-deploy",
    "no-cloud-assembly",
    "no-language-binding",
    "no-aws-differential",
)
NPM_INTEGRITY = (
    "sha512-g1jcMfWlyYtGamFJ/kPBOCuchl3NfwTF2UwOLTIDN0nJbGm84EAO+c8DlYnaemM8"
    "UmKFkdoq4BGdmiNL5nHWwA=="
)
PINNED_TOOLCHAIN = {
    "node_version": "22.23.2",
    "cdk_cli_version": "2.1135.1",
    "bootstrap_version": 32,
    "reference_template_byte_sha256": (
        "sha256:a484ad768d3446874161044d986bec096e201a54037c8ce93ed5a0d215e1dd25"
    ),
    "template_semantic_sha256": (
        "sha256:9e04a3226e702258e2ba13063dc6ecbc6fba7880d9fa27298445499db453013a"
    ),
}
PINNED_INPUTS = (
    ".github/workflows/cdk-cli-blackbox.yml",
    ".python-version",
    "Makefile",
    "capabilities/cdk/compatibility.json",
    "capabilities/cdk/execution-evidence.schema.json",
    "localstack-core/localstack/cli/_cdk_health_probe.py",
    "localstack-core/localstack/cli/cdk.py",
    "pyproject.toml",
    "requirements-test.txt",
    "scripts/run_cdk_cli_blackbox_isolated.sh",
    "tests/aws/cli/execution_evidence.py",
    "tests/aws/cli/package-lock.json",
    "tests/aws/cli/package.json",
    "tests/aws/cli/test_cdk_cli_blackbox.py",
    "tests/aws/cli/validate_junit.py",
    "tests/aws/templates/cdk_bootstrap_v32.yaml",
)
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _record_digest(record: Mapping[str, object], field: str) -> str:
    payload = {key: value for key, value in record.items() if key != field}
    return _sha256_bytes(_canonical_bytes(payload))


def _expect_keys(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} does not match the closed evidence contract")
    return value


def _expect_string(value: object, label: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{label} must be a bounded non-empty string")
    return value


def _expect_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return value


def _expect_int(value: object, label: str, *, minimum: int = 0, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside the accepted bounds")
    return value


def _validate_lane_receipt(receipt: object) -> dict:
    receipt = _expect_keys(
        receipt,
        {
            "schema_version",
            "record_type",
            "receipt_id",
            "scenario",
            "platform",
            "toolchain",
            "result",
            "isolation",
            "observed_at",
        },
        "lane receipt",
    )
    if receipt["schema_version"] != SCHEMA_VERSION or receipt["record_type"] != "lane-receipt":
        raise ValueError("unsupported CDK lane receipt version")
    if receipt["scenario"] != SCENARIO:
        raise ValueError("lane receipt scenario is not the pinned CDK scenario")

    platform = _expect_keys(
        receipt["platform"],
        {"id", "machine_arch", "node_arch", "python_version", "kernel_release"},
        "lane platform",
    )
    if platform["id"] not in EXPECTED_PLATFORMS:
        raise ValueError("lane receipt has an unsupported platform")
    for field in ("machine_arch", "node_arch", "python_version"):
        _expect_string(platform[field], f"lane platform {field}", maximum=32)
    _expect_string(platform["kernel_release"], "lane platform kernel_release")
    if (platform["machine_arch"], platform["node_arch"]) != EXPECTED_ARCHITECTURES[platform["id"]]:
        raise ValueError("lane receipt does not describe the native platform architecture")

    toolchain = _expect_keys(
        receipt["toolchain"],
        {
            "node_version",
            "cdk_cli_version",
            "bootstrap_version",
            "reference_template_byte_sha256",
            "template_semantic_sha256",
        },
        "lane toolchain",
    )
    _expect_string(toolchain["node_version"], "Node version")
    _expect_string(toolchain["cdk_cli_version"], "CDK CLI version")
    if toolchain["bootstrap_version"] != 32:
        raise ValueError("lane receipt bootstrap version is not 32")
    _expect_sha256(toolchain["reference_template_byte_sha256"], "reference template byte digest")
    _expect_sha256(toolchain["template_semantic_sha256"], "template semantic digest")
    if toolchain != PINNED_TOOLCHAIN:
        raise ValueError("lane receipt does not match the pinned CDK toolchain")

    result = _expect_keys(
        receipt["result"],
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
        "lane result",
    )
    if (
        result["status"] != "pass"
        or result["returncode"] != 0
        or result["timed_out"] is not False
        or result["stdout_truncated"] is not False
        or result["stderr_truncated"] is not False
    ):
        raise ValueError("lane receipt does not describe an exact passing result")
    _expect_int(result["duration_ms"], "duration", maximum=300_000)
    _expect_int(result["stdout_bytes"], "stdout bytes", maximum=16 * 1024 * 1024)
    _expect_int(result["stderr_bytes"], "stderr bytes", maximum=16 * 1024 * 1024)
    _expect_sha256(result["stdout_sha256"], "stdout digest")
    _expect_sha256(result["stderr_sha256"], "stderr digest")

    isolation = _expect_keys(
        receipt["isolation"], {"profile_id", "interface_names"}, "lane isolation"
    )
    if isolation != {
        "profile_id": "linux-net-pid-mount-nobody-v1",
        "interface_names": ["lo"],
    }:
        raise ValueError("lane receipt does not use the pinned isolation profile")
    observed_at = _expect_string(receipt["observed_at"], "observation time")
    if not _UTC_RE.fullmatch(observed_at):
        raise ValueError("lane receipt observation time is not UTC")
    _expect_sha256(receipt["receipt_id"], "lane receipt digest")
    if receipt["receipt_id"] != _record_digest(receipt, "receipt_id"):
        raise ValueError("lane receipt digest does not match its content")
    return receipt


def create_lane_receipt(
    *,
    platform_id: str,
    machine_arch: str,
    node_arch: str,
    python_version: str,
    kernel_release: str,
    node_version: str,
    cdk_cli_version: str,
    bootstrap_version: int,
    reference_template_byte_sha256: str,
    template_semantic_sha256: str,
    returncode: int,
    timed_out: bool,
    duration_ms: int,
    stdout: bytes,
    stderr: bytes,
    stdout_bytes: int,
    stderr_bytes: int,
    stdout_truncated: bool,
    stderr_truncated: bool,
    interface_names: Sequence[str],
    isolation_profile_id: str,
    observed_at: str,
) -> dict:
    if stdout_bytes != len(stdout) or stderr_bytes != len(stderr):
        raise ValueError("untruncated lane output byte totals must match captured output")
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "lane-receipt",
        "receipt_id": "sha256:" + "0" * 64,
        "scenario": copy.deepcopy(SCENARIO),
        "platform": {
            "id": platform_id,
            "machine_arch": machine_arch,
            "node_arch": node_arch,
            "python_version": python_version,
            "kernel_release": kernel_release,
        },
        "toolchain": {
            "node_version": node_version,
            "cdk_cli_version": cdk_cli_version,
            "bootstrap_version": bootstrap_version,
            "reference_template_byte_sha256": reference_template_byte_sha256,
            "template_semantic_sha256": template_semantic_sha256,
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
        "isolation": {
            "profile_id": isolation_profile_id,
            "interface_names": list(interface_names),
        },
        "observed_at": observed_at,
    }
    receipt["receipt_id"] = _record_digest(receipt, "receipt_id")
    return _validate_lane_receipt(receipt)


def _read_regular_bounded(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY
    for name in ("O_BINARY", "O_CLOEXEC", "O_NONBLOCK", "O_NOFOLLOW"):
        flags |= getattr(os, name, 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("evidence input must be a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            payload = stream.read(maximum + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not payload or len(payload) > maximum:
        raise ValueError("evidence input size is outside the accepted bounds")
    return payload


def load_bounded_json(path: Path, maximum: int = MAX_EVIDENCE_BYTES) -> dict:
    payload = _read_regular_bounded(path, maximum)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ValueError("evidence input is not bounded valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("evidence input must be a JSON object")
    return value


def write_canonical_json(path: Path, value: Mapping[str, object], maximum: int) -> None:
    payload = _canonical_bytes(value) + b"\n"
    if len(payload) > maximum:
        raise ValueError("evidence output exceeds the accepted size")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


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
            raise ValueError(f"pinned evidence input is missing: {relative}")
        result[relative] = _file_sha256(path)
    return result


def _claim_id(evidence: Mapping[str, object]) -> str:
    claim = {
        "scenario": evidence["scenario"],
        "toolchain": evidence["toolchain"],
        "harness": evidence["harness"],
        "platforms": [
            {
                "platform_id": lane["platform_id"],
                "machine_arch": lane["machine_arch"],
                "node_arch": lane["node_arch"],
            }
            for lane in evidence["lanes"]
        ],
    }
    return _sha256_bytes(_canonical_bytes(claim))


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
    if run_attempt != 1:
        raise ValueError("promotion evidence requires the first workflow attempt")
    if not _COMMIT_RE.fullmatch(commit_sha):
        raise ValueError("source commit must be a full lowercase Git SHA")
    if ref != "refs/heads/main" or event != "push":
        raise ValueError("candidate evidence must come from a push to main")
    _expect_string(repository, "repository")
    _expect_string(workflow_path, "workflow path")
    _expect_int(run_id, "workflow run ID", minimum=1, maximum=2**63 - 1)

    receipts = {}
    lanes = []
    for platform_id in EXPECTED_PLATFORMS:
        receipt = _validate_lane_receipt(load_bounded_json(receipt_paths[platform_id]))
        if receipt["platform"]["id"] != platform_id:
            raise ValueError("lane receipt platform does not match its matrix lane")
        junit_payload = load_junit(junit_paths[platform_id])
        validate_junit_payload(junit_payload)
        receipts[platform_id] = receipt
        lanes.append(
            {
                "platform_id": platform_id,
                "machine_arch": receipt["platform"]["machine_arch"],
                "node_arch": receipt["platform"]["node_arch"],
                "python_version": receipt["platform"]["python_version"],
                "kernel_release": receipt["platform"]["kernel_release"],
                "receipt_id": receipt["receipt_id"],
                "observed_at": receipt["observed_at"],
                "junit_sha256": _sha256_bytes(junit_payload),
                "junit_bytes": len(junit_payload),
                "result": copy.deepcopy(receipt["result"]),
                "isolation": copy.deepcopy(receipt["isolation"]),
            }
        )

    first = receipts[EXPECTED_PLATFORMS[0]]
    for receipt in receipts.values():
        if receipt["scenario"] != first["scenario"] or receipt["toolchain"] != first["toolchain"]:
            raise ValueError("matrix lanes do not describe the same scenario and toolchain")

    package_lock = json.loads((project_root / "tests/aws/cli/package-lock.json").read_bytes())
    if package_lock["packages"]["node_modules/aws-cdk"].get("integrity") != NPM_INTEGRITY:
        raise ValueError("CDK package integrity does not match the evidence contract")
    input_digests = _pinned_input_digests(project_root)
    if (
        input_digests["tests/aws/templates/cdk_bootstrap_v32.yaml"]
        != first["toolchain"]["reference_template_byte_sha256"]
    ):
        raise ValueError("reference bootstrap template digest does not match the pinned fixture")
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "aggregate",
        "mode": "candidate",
        "evidence_id": "sha256:" + "0" * 64,
        "claim_id": "sha256:" + "0" * 64,
        "subject": {
            "repository": repository,
            "commit_sha": commit_sha,
            "ref": ref,
        },
        "run": {
            "provider": "github-actions",
            "workflow_path": workflow_path,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "event": event,
        },
        "scenario": copy.deepcopy(first["scenario"]),
        "toolchain": {
            **copy.deepcopy(first["toolchain"]),
            "npm_integrity": NPM_INTEGRITY,
        },
        "harness": {"input_sha256": input_digests},
        "lanes": lanes,
        "promotion": {
            "eligible": False,
            "blockers": list(PROMOTION_BLOCKERS),
        },
    }
    evidence["claim_id"] = _claim_id(evidence)
    evidence["evidence_id"] = _record_digest(evidence, "evidence_id")
    validate_aggregate_evidence(evidence)
    return evidence


def validate_aggregate_evidence(evidence: object) -> dict:
    evidence = _expect_keys(
        evidence,
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
            "harness",
            "lanes",
            "promotion",
        },
        "aggregate evidence",
    )
    if (
        evidence["schema_version"] != SCHEMA_VERSION
        or evidence["record_type"] != "aggregate"
        or evidence["mode"] != "candidate"
    ):
        raise ValueError("unsupported aggregate evidence record")
    if evidence["scenario"] != SCENARIO:
        raise ValueError("aggregate evidence scenario is not language-neutral show-template")
    subject = _expect_keys(evidence["subject"], {"repository", "commit_sha", "ref"}, "subject")
    _expect_string(subject["repository"], "repository")
    if not isinstance(subject["commit_sha"], str) or not _COMMIT_RE.fullmatch(
        subject["commit_sha"]
    ):
        raise ValueError("aggregate subject commit is invalid")
    if subject["ref"] != "refs/heads/main":
        raise ValueError("aggregate subject is not main")
    run = _expect_keys(
        evidence["run"],
        {"provider", "workflow_path", "run_id", "run_attempt", "event"},
        "run",
    )
    if run["provider"] != "github-actions" or run["event"] != "push" or run["run_attempt"] != 1:
        raise ValueError("aggregate run is not a first-attempt GitHub push")
    if run["workflow_path"] != ".github/workflows/cdk-cli-blackbox.yml":
        raise ValueError("aggregate run uses an unexpected workflow")
    _expect_int(run["run_id"], "workflow run ID", minimum=1, maximum=2**63 - 1)
    toolchain = _expect_keys(
        evidence["toolchain"],
        {
            "node_version",
            "cdk_cli_version",
            "bootstrap_version",
            "reference_template_byte_sha256",
            "template_semantic_sha256",
            "npm_integrity",
        },
        "aggregate toolchain",
    )
    if toolchain["npm_integrity"] != NPM_INTEGRITY:
        raise ValueError("aggregate CDK package integrity is invalid")
    _expect_sha256(toolchain["reference_template_byte_sha256"], "reference template byte digest")
    _expect_sha256(toolchain["template_semantic_sha256"], "template semantic digest")
    harness = _expect_keys(evidence["harness"], {"input_sha256"}, "harness")
    digests = harness["input_sha256"]
    if not isinstance(digests, dict) or tuple(digests) != PINNED_INPUTS:
        raise ValueError("aggregate harness input set is not exact and ordered")
    for path, digest in digests.items():
        if Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("aggregate harness path is unsafe")
        _expect_sha256(digest, "harness input digest")
    if (
        digests["tests/aws/templates/cdk_bootstrap_v32.yaml"]
        != toolchain["reference_template_byte_sha256"]
    ):
        raise ValueError("aggregate reference template digest does not match its harness input")
    lanes = evidence["lanes"]
    if not isinstance(lanes, list) or [lane.get("platform_id") for lane in lanes] != list(
        EXPECTED_PLATFORMS
    ):
        raise ValueError("aggregate evidence does not contain the exact platform matrix")
    for lane in lanes:
        lane = _expect_keys(
            lane,
            {
                "platform_id",
                "machine_arch",
                "node_arch",
                "python_version",
                "kernel_release",
                "receipt_id",
                "observed_at",
                "junit_sha256",
                "junit_bytes",
                "result",
                "isolation",
            },
            "aggregate lane",
        )
        _expect_sha256(lane["receipt_id"], "lane receipt digest")
        _expect_sha256(lane["junit_sha256"], "lane JUnit digest")
        _expect_int(lane["junit_bytes"], "lane JUnit bytes", minimum=1, maximum=1024 * 1024)
        _validate_lane_receipt(
            {
                "schema_version": SCHEMA_VERSION,
                "record_type": "lane-receipt",
                "receipt_id": lane["receipt_id"],
                "scenario": copy.deepcopy(evidence["scenario"]),
                "platform": {
                    "id": lane["platform_id"],
                    "machine_arch": lane["machine_arch"],
                    "node_arch": lane["node_arch"],
                    "python_version": lane["python_version"],
                    "kernel_release": lane["kernel_release"],
                },
                "toolchain": {
                    key: value
                    for key, value in evidence["toolchain"].items()
                    if key != "npm_integrity"
                },
                "result": copy.deepcopy(lane["result"]),
                "isolation": copy.deepcopy(lane["isolation"]),
                "observed_at": lane["observed_at"],
            }
        )
    if evidence["promotion"] != {
        "eligible": False,
        "blockers": list(PROMOTION_BLOCKERS),
    }:
        raise ValueError("candidate evidence cannot authorize broad promotion")
    _expect_sha256(evidence["claim_id"], "claim digest")
    _expect_sha256(evidence["evidence_id"], "evidence digest")
    if evidence["claim_id"] != _claim_id(evidence):
        raise ValueError("claim digest does not match aggregate content")
    if evidence["evidence_id"] != _record_digest(evidence, "evidence_id"):
        raise ValueError("evidence digest does not match aggregate content")
    return evidence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt-amd64", type=Path, required=True)
    parser.add_argument("--receipt-arm64", type=Path, required=True)
    parser.add_argument("--junit-amd64", type=Path, required=True)
    parser.add_argument("--junit-arm64", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    evidence = build_aggregate_evidence(
        receipt_paths={
            "linux-amd64": args.receipt_amd64,
            "linux-arm64": args.receipt_arm64,
        },
        junit_paths={
            "linux-amd64": args.junit_amd64,
            "linux-arm64": args.junit_arm64,
        },
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
