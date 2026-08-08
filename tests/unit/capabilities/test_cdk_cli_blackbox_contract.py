import json
from pathlib import Path

import pytest
from tests.aws.cli.test_cdk_cli_blackbox import (
    MAX_YAML_ALIASES,
    MAX_YAML_DEPTH,
    MAX_YAML_NODES,
    _load_bounded_yaml,
    _validate_required_target,
)

PROJECT_ROOT = Path(__file__).parents[3]
TOOLCHAIN_ROOT = PROJECT_ROOT / "tests/aws/cli"


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
