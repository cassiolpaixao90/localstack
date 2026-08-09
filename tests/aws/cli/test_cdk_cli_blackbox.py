import hashlib
import json
import os
import platform
import shutil
import socket
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from yaml.events import AliasEvent

from localstack import config
from localstack.cli.cdk import (
    build_cdk_environment,
    launch_cdk,
    probe_cdk_cli_version,
    probe_localstack_health,
)
from localstack.testing.pytest import markers
from tests.aws.cli.execution_evidence import (
    MAX_EVIDENCE_BYTES,
    create_lane_receipt,
    write_canonical_json,
)

PROJECT_ROOT = Path(__file__).parents[3]
TOOLCHAIN_ROOT = Path(__file__).parent
PINNED_NODE_VERSION = "22.23.2"
PINNED_CDK_VERSION = "2.1135.1"
PINNED_BOOTSTRAP_VERSION = "32"
PINNED_BOOTSTRAP_BYTE_SHA256 = (
    "sha256:a484ad768d3446874161044d986bec096e201a54037c8ce93ed5a0d215e1dd25"
)
PINNED_BOOTSTRAP_SEMANTIC_SHA256 = (
    "9e04a3226e702258e2ba13063dc6ecbc6fba7880d9fa27298445499db453013a"
)
MAX_YAML_ALIASES = 32
MAX_YAML_DEPTH = 64
MAX_YAML_NODES = 10_000
_REQUIRED = os.environ.get("CDK_REAL_CLI_REQUIRED") == "1"


def _validate_required_target(required: bool, test_target: str | None) -> None:
    if required and test_target != "LOCALSTACK":
        raise pytest.UsageError(
            "CDK_REAL_CLI_REQUIRED requires TEST_TARGET=LOCALSTACK; skips cannot promote"
        )


def _validate_required_network_isolation(
    required: bool, system: str, interface_names: set[str]
) -> None:
    if not required:
        return
    if system != "linux" or interface_names != {"lo"}:
        raise pytest.UsageError(
            "the required CDK gate must run on Linux with only the loopback interface"
        )


_validate_required_target(_REQUIRED, os.environ.get("TEST_TARGET"))


class _BoundedUniqueKeyLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self.alias_count = 0
        self.node_depth = 0
        self.node_count = 0

    def compose_node(self, parent, index):
        self.node_count += 1
        if self.node_count > MAX_YAML_NODES:
            raise ValueError("CDK template exceeds the YAML node limit")
        if self.check_event(AliasEvent):
            self.alias_count += 1
            if self.alias_count > MAX_YAML_ALIASES:
                raise ValueError("CDK template exceeds the YAML alias limit")
        self.node_depth += 1
        if self.node_depth > MAX_YAML_DEPTH:
            raise ValueError("CDK template exceeds the YAML nesting limit")
        try:
            return super().compose_node(parent, index)
        finally:
            self.node_depth -= 1

    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise ValueError("CDK template contains an invalid mapping key") from error
            if duplicate:
                raise ValueError(f"CDK template contains a duplicate mapping key: {key}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _load_bounded_yaml(value: str):
    return yaml.load(value, Loader=_BoundedUniqueKeyLoader)


def _semantic_sha256(value) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _require(condition: bool, message: str) -> None:
    if condition:
        return
    if _REQUIRED:
        pytest.fail(message)
    pytest.skip(message)


@markers.aws.only_localstack
def test_cdk_cli_bootstrap_show_template_matches_pinned_v32(
    tmp_path,
    account_id,
    region_name,
):
    _require(os.name == "posix", "the safe CDK supervisor requires POSIX")
    interface_names = {name for _, name in socket.if_nameindex()}
    _validate_required_network_isolation(
        _REQUIRED,
        sys.platform,
        interface_names,
    )
    expected_machine_arch = os.environ.get("CDK_EXPECTED_MACHINE_ARCH")
    expected_node_arch = os.environ.get("CDK_EXPECTED_NODE_ARCH")
    _require(
        not _REQUIRED or expected_machine_arch is not None,
        "the required CDK gate needs an expected machine architecture",
    )
    _require(
        not _REQUIRED or expected_node_arch is not None,
        "the required CDK gate needs an expected Node architecture",
    )
    if expected_machine_arch:
        _require(
            platform.machine() == expected_machine_arch,
            f"native machine architecture {expected_machine_arch} is required",
        )
    node = shutil.which("node")
    _require(node is not None, "the pinned Node executable is not installed")
    node = str(Path(node).resolve())

    expected_node_version = PINNED_NODE_VERSION
    if not _REQUIRED:
        expected_node_version = os.environ.get("CDK_EXPECTED_NODE_VERSION", PINNED_NODE_VERSION)
    node_result = launch_cdk(
        ["--version"],
        executable=node,
        environment={"PATH": str(Path(node).parent)},
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    _require(node_result.returncode == 0, "the Node version probe failed")
    _require(not node_result.stdout_truncated, "the Node version output was truncated")
    _require(not node_result.stderr_truncated, "the Node version error output was truncated")
    _require(
        node_result.stdout.decode().strip() == f"v{expected_node_version}",
        f"Node {expected_node_version} is required",
    )
    node_arch_result = launch_cdk(
        ["--print", "process.arch"],
        executable=node,
        environment={"PATH": str(Path(node).parent)},
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    _require(node_arch_result.returncode == 0, "the Node architecture probe failed")
    _require(not node_arch_result.stdout_truncated, "the Node architecture output was truncated")
    _require(not node_arch_result.stderr_truncated, "the Node architecture error was truncated")
    if expected_node_arch:
        _require(
            node_arch_result.stdout.decode().strip() == expected_node_arch,
            f"native Node architecture {expected_node_arch} is required",
        )

    cdk_executable = (TOOLCHAIN_ROOT / "node_modules/aws-cdk/bin/cdk").resolve()
    _require(cdk_executable.is_file(), "run npm ci in tests/aws/cli before this gate")
    package = json.loads((TOOLCHAIN_ROOT / "node_modules/aws-cdk/package.json").read_text())
    _require(package.get("version") == PINNED_CDK_VERSION, "the CDK package pin is stale")

    home = tmp_path / "home"
    temporary = tmp_path / "tmp"
    workspace = tmp_path / "workspace"
    for directory in (home, temporary, workspace):
        directory.mkdir()
    endpoint_url = config.internal_service_url()
    environment = build_cdk_environment(
        {
            "HOME": str(home),
            "PATH": str(Path(node).parent),
            "TMPDIR": str(temporary),
        },
        endpoint_url=endpoint_url,
        region=region_name,
        account_id=account_id,
    )

    probe_localstack_health(endpoint_url, timeout_seconds=2)
    assert (
        probe_cdk_cli_version(str(cdk_executable), environment=environment, cwd=workspace)
        == PINNED_CDK_VERSION
    )
    started = time.monotonic_ns()
    result = launch_cdk(
        ["bootstrap", "--show-template", "--no-notices"],
        executable=str(cdk_executable),
        environment=environment,
        cwd=workspace,
        timeout_seconds=30,
        max_output_bytes=1024 * 1024,
    )
    duration_ms = (time.monotonic_ns() - started) // 1_000_000

    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.timed_out is False
    assert result.stdout_truncated is False
    assert result.stderr_truncated is False
    actual = _load_bounded_yaml(result.stdout.decode("utf-8"))
    expected = _load_bounded_yaml(
        (PROJECT_ROOT / "tests/aws/templates/cdk_bootstrap_v32.yaml").read_text()
    )
    assert actual == expected
    assert _semantic_sha256(actual) == PINNED_BOOTSTRAP_SEMANTIC_SHA256
    assert (
        actual["Resources"]["CdkBootstrapVersion"]["Properties"]["Value"]
        == PINNED_BOOTSTRAP_VERSION
    )
    assert actual["Outputs"]["BootstrapVersion"]["Value"] == PINNED_BOOTSTRAP_VERSION

    receipt_path = os.environ.get("CDK_EXECUTION_RECEIPT")
    _require(
        not _REQUIRED or receipt_path is not None,
        "the required CDK gate needs an execution receipt path",
    )
    if receipt_path:
        platform_id = f"linux-{os.environ['RESULT_ARCH']}"
        receipt = create_lane_receipt(
            platform_id=platform_id,
            machine_arch=platform.machine(),
            node_arch=node_arch_result.stdout.decode().strip(),
            python_version=platform.python_version(),
            kernel_release=platform.release(),
            node_version=expected_node_version,
            cdk_cli_version=PINNED_CDK_VERSION,
            bootstrap_version=int(PINNED_BOOTSTRAP_VERSION),
            reference_template_byte_sha256=PINNED_BOOTSTRAP_BYTE_SHA256,
            template_semantic_sha256=f"sha256:{PINNED_BOOTSTRAP_SEMANTIC_SHA256}",
            returncode=result.returncode,
            timed_out=result.timed_out,
            duration_ms=duration_ms,
            stdout=result.stdout,
            stderr=result.stderr,
            stdout_bytes=result.stdout_bytes,
            stderr_bytes=result.stderr_bytes,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
            interface_names=sorted(interface_names),
            isolation_profile_id="linux-net-pid-mount-nobody-v1",
            observed_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
        write_canonical_json(Path(receipt_path), receipt, MAX_EVIDENCE_BYTES)
