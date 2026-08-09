import importlib.metadata
import json
import os
import shlex
import shutil
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath

import pytest
from jsonschema import Draft7Validator

from localstack.cli.cdk import launch_cdk
from localstack.testing.pytest import markers
from tests.aws.cli.execution_evidence import read_regular_bounded
from tests.aws.cli.test_cdk_cli_bootstrap_upgrade import CdkRuntime

pytest_plugins = ("tests.aws.cli.test_cdk_cli_bootstrap_upgrade",)

PROJECT_ROOT = Path(__file__).parents[3]
APP_PATH = PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/minimal_sqs.py"
STACK_NAME = "SynthStack"
PINNED_PYTHON_PACKAGES = {
    "aws-cdk-lib": "2.241.0",
    "aws-cdk-cloud-assembly-schema": "52.2.0",
    "constructs": "10.5.1",
    "jsii": "1.127.0",
}
EMITTED_ASSEMBLY_VERSION = "52.0.0"
TEMPLATE_ASSET_HASH = "039a840a9267a7acf895d29d5f2bd4894a720070cff12e3f10dd9852b76f4e1c"
EXPECTED_ASSEMBLY_FILES = {
    "SynthStack.assets.json",
    "SynthStack.template.json",
    "cdk.out",
    "manifest.json",
    "tree.json",
}
MAX_ASSEMBLY_FILES = 32
MAX_ASSEMBLY_FILE_BYTES = 1024 * 1024
MAX_ASSEMBLY_TOTAL_BYTES = 2 * 1024 * 1024
ASSEMBLY_SCHEMA_MEMBER = "package/schema/cloud-assembly.schema.json"
_REQUIRED = os.environ.get("CDK_REAL_CLI_REQUIRED") == "1"


def _require(condition: bool, message: str) -> None:
    if condition:
        return
    if _REQUIRED:
        pytest.fail(message)
    pytest.skip(message)


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Cloud Assembly JSON contains a duplicate key: {key}")
        value[key] = item
    return value


def _load_assembly_json(path: Path, maximum: int = MAX_ASSEMBLY_FILE_BYTES) -> dict:
    payload = read_regular_bounded(path, maximum)
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ValueError("Cloud Assembly file is not bounded valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("Cloud Assembly JSON root must be an object")
    return value


def _load_pinned_assembly_schema() -> dict:
    archive_name = (
        f"cloud-assembly-schema@{PINNED_PYTHON_PACKAGES['aws-cdk-cloud-assembly-schema']}.jsii.tgz"
    )
    distribution = importlib.metadata.distribution("aws-cdk-cloud-assembly-schema")
    archive_path = Path(
        distribution.locate_file(Path("aws_cdk/cloud_assembly_schema/_jsii") / archive_name)
    )
    with (
        archive_path.open("rb") as archive_stream,
        tarfile.open(fileobj=archive_stream, mode="r:gz") as archive,
    ):
        member = archive.getmember(ASSEMBLY_SCHEMA_MEMBER)
        if not member.isfile() or member.size <= 0 or member.size > MAX_ASSEMBLY_FILE_BYTES:
            raise ValueError("the pinned Cloud Assembly schema is outside the accepted bounds")
        schema_stream = archive.extractfile(member)
        if schema_stream is None:
            raise ValueError("the pinned Cloud Assembly schema is unavailable")
        with schema_stream:
            payload = schema_stream.read(MAX_ASSEMBLY_FILE_BYTES + 1)
    try:
        schema = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ValueError("the pinned Cloud Assembly schema is not bounded valid JSON") from error
    if not isinstance(schema, dict):
        raise ValueError("the pinned Cloud Assembly schema root must be an object")
    return schema


def _assembly_inventory(root: Path) -> dict[str, int]:
    root_stat = root.lstat()
    if not stat.S_ISDIR(root_stat.st_mode) or root.is_symlink():
        raise ValueError("Cloud Assembly root must be a regular directory")
    inventory = {}
    for path in root.iterdir():
        path_stat = path.lstat()
        if not stat.S_ISREG(path_stat.st_mode):
            raise ValueError("Cloud Assembly must contain only regular top-level files")
        inventory[path.name] = path_stat.st_size
        if len(inventory) > MAX_ASSEMBLY_FILES:
            raise ValueError("Cloud Assembly contains too many files")
    if any(size <= 0 or size > MAX_ASSEMBLY_FILE_BYTES for size in inventory.values()):
        raise ValueError("Cloud Assembly file size is outside the accepted bounds")
    if sum(inventory.values()) > MAX_ASSEMBLY_TOTAL_BYTES:
        raise ValueError("Cloud Assembly total size is outside the accepted bounds")
    return inventory


def _validate_assembly_reference(root: Path, inventory: dict[str, int], reference: str) -> None:
    if not isinstance(reference, str):
        raise ValueError("Cloud Assembly file reference must be a string")
    relative = PurePosixPath(reference)
    if relative.is_absolute() or len(relative.parts) != 1 or relative.name != reference:
        raise ValueError("Cloud Assembly file reference must be a top-level basename")
    if reference not in inventory:
        raise ValueError("Cloud Assembly file reference is not present in the inventory")
    resolved = (root / reference).resolve(strict=True)
    if resolved.parent != root.resolve(strict=True):
        raise ValueError("Cloud Assembly file reference escapes its root")


def _expected_tree() -> dict:
    library_version = PINNED_PYTHON_PACKAGES["aws-cdk-lib"]
    return {
        "version": "tree-0.1",
        "tree": {
            "id": "App",
            "path": "",
            "constructInfo": {"fqn": "aws-cdk-lib.App", "version": library_version},
            "children": {
                STACK_NAME: {
                    "id": STACK_NAME,
                    "path": STACK_NAME,
                    "constructInfo": {
                        "fqn": "aws-cdk-lib.Stack",
                        "version": library_version,
                    },
                    "children": {
                        "BootstrapVersion": {
                            "id": "BootstrapVersion",
                            "path": f"{STACK_NAME}/BootstrapVersion",
                            "constructInfo": {
                                "fqn": "aws-cdk-lib.CfnParameter",
                                "version": library_version,
                            },
                        },
                        "CheckBootstrapVersion": {
                            "id": "CheckBootstrapVersion",
                            "path": f"{STACK_NAME}/CheckBootstrapVersion",
                            "constructInfo": {
                                "fqn": "aws-cdk-lib.CfnRule",
                                "version": library_version,
                            },
                        },
                        "Queue": {
                            "id": "Queue",
                            "path": f"{STACK_NAME}/Queue",
                            "constructInfo": {
                                "fqn": "aws-cdk-lib.aws_sqs.CfnQueue",
                                "version": library_version,
                            },
                            "attributes": {
                                "aws:cdk:cloudformation:props": {},
                                "aws:cdk:cloudformation:type": "AWS::SQS::Queue",
                            },
                        },
                    },
                },
                "Tree": {
                    "id": "Tree",
                    "path": "Tree",
                    "constructInfo": {
                        "fqn": "constructs.Construct",
                        "version": PINNED_PYTHON_PACKAGES["constructs"],
                    },
                },
            },
        },
    }


def _python_app_command(python: Path, app: Path) -> str:
    if not python.is_absolute() or not python.is_file():
        raise ValueError("the Python interpreter must be an absolute regular file")
    if not app.is_absolute() or not app.is_file():
        raise ValueError("the CDK app must be an absolute regular file")
    return shlex.join((str(python), "-I", "-B", str(app)))


def _python_interpreter_path(executable: str) -> Path:
    python = Path(executable)
    if not python.is_absolute() or not python.is_file():
        raise ValueError("the current Python interpreter must be an absolute regular file")
    return python


@pytest.fixture
def python_synth_output(tmp_path):
    output = tmp_path / "assembly"
    try:
        yield output
    finally:
        if output.exists():
            shutil.rmtree(output, ignore_errors=False)
        assert not output.exists()


@markers.aws.only_localstack
def test_cdk_cli_synthesizes_minimal_python_sqs_app(
    pinned_cdk_cli_runtime: CdkRuntime,
    python_synth_output: Path,
):
    for distribution, expected in PINNED_PYTHON_PACKAGES.items():
        try:
            actual = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            _require(False, f"the pinned Python package is not installed: {distribution}")
        else:
            _require(actual == expected, f"{distribution} {expected} is required")

    python = _python_interpreter_path(sys.executable)
    app = APP_PATH.resolve()
    app_command = _python_app_command(python, app)
    environment = dict(pinned_cdk_cli_runtime.environment)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    argv = [
        "synth",
        STACK_NAME,
        "--app",
        app_command,
        "--output",
        str(python_synth_output),
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
    result = launch_cdk(
        argv,
        executable=pinned_cdk_cli_runtime.executable,
        environment=environment,
        cwd=pinned_cdk_cli_runtime.workspace,
        timeout_seconds=60,
        max_output_bytes=256 * 1024,
    )

    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.timed_out is False
    assert result.stdout_truncated is False
    assert result.stderr_truncated is False
    inventory = _assembly_inventory(python_synth_output)
    assert set(inventory) == EXPECTED_ASSEMBLY_FILES

    manifest_path = python_synth_output / "manifest.json"
    manifest = _load_assembly_json(manifest_path)
    assembly_schema = _load_pinned_assembly_schema()
    Draft7Validator.check_schema(assembly_schema)
    assembly_validator = Draft7Validator(assembly_schema)
    assembly_validator.validate(manifest)
    assert set(manifest) == {"artifacts", "minimumCliVersion", "version"}
    assert manifest["version"] == EMITTED_ASSEMBLY_VERSION
    assert manifest["minimumCliVersion"] == "2.1107.0"
    artifacts = manifest["artifacts"]
    assert {artifact_id: artifact["type"] for artifact_id, artifact in artifacts.items()} == {
        STACK_NAME: "aws:cloudformation:stack",
        f"{STACK_NAME}.assets": "cdk:asset-manifest",
        "Tree": "cdk:tree",
        "aws-cdk-lib/feature-flag-report": "cdk:feature-flag-report",
    }
    stack_artifact = artifacts[STACK_NAME]
    assert set(stack_artifact) == {
        "dependencies",
        "displayName",
        "environment",
        "metadata",
        "properties",
        "type",
    }
    assert stack_artifact["dependencies"] == [f"{STACK_NAME}.assets"]
    assert stack_artifact["displayName"] == STACK_NAME
    assert stack_artifact["environment"] == "aws://unknown-account/unknown-region"
    assert stack_artifact["metadata"] == {
        f"/{STACK_NAME}/BootstrapVersion": [
            {"data": "BootstrapVersion", "type": "aws:cdk:logicalId"}
        ],
        f"/{STACK_NAME}/CheckBootstrapVersion": [
            {"data": "CheckBootstrapVersion", "type": "aws:cdk:logicalId"}
        ],
        f"/{STACK_NAME}/Queue": [{"data": "Queue", "type": "aws:cdk:logicalId"}],
    }
    stack_properties = stack_artifact["properties"]
    assert stack_properties == {
        "additionalDependencies": [f"{STACK_NAME}.assets"],
        "assumeRoleArn": (
            "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/"
            "cdk-hnb659fds-deploy-role-${AWS::AccountId}-${AWS::Region}"
        ),
        "bootstrapStackVersionSsmParameter": "/cdk-bootstrap/hnb659fds/version",
        "cloudFormationExecutionRoleArn": (
            "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/"
            "cdk-hnb659fds-cfn-exec-role-${AWS::AccountId}-${AWS::Region}"
        ),
        "lookupRole": {
            "arn": (
                "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/"
                "cdk-hnb659fds-lookup-role-${AWS::AccountId}-${AWS::Region}"
            ),
            "bootstrapStackVersionSsmParameter": "/cdk-bootstrap/hnb659fds/version",
            "requiresBootstrapStackVersion": 8,
        },
        "requiresBootstrapStackVersion": 6,
        "stackTemplateAssetObjectUrl": (
            "s3://cdk-hnb659fds-assets-${AWS::AccountId}-${AWS::Region}/"
            f"{TEMPLATE_ASSET_HASH}.json"
        ),
        "templateFile": f"{STACK_NAME}.template.json",
        "terminationProtection": False,
        "validateOnSynth": False,
    }

    asset_artifact = artifacts[f"{STACK_NAME}.assets"]
    assert asset_artifact == {
        "type": "cdk:asset-manifest",
        "properties": {
            "bootstrapStackVersionSsmParameter": "/cdk-bootstrap/hnb659fds/version",
            "file": f"{STACK_NAME}.assets.json",
            "requiresBootstrapStackVersion": 6,
        },
    }
    assert artifacts["Tree"] == {
        "type": "cdk:tree",
        "properties": {"file": "tree.json"},
    }
    feature_report = artifacts["aws-cdk-lib/feature-flag-report"]
    assert set(feature_report) == {"properties", "type"}
    assert set(feature_report["properties"]) == {"flags", "module"}
    assert feature_report["properties"]["module"] == "aws-cdk-lib"
    assert isinstance(feature_report["properties"]["flags"], dict)
    assert feature_report["properties"]["flags"]

    for reference in (
        stack_properties["templateFile"],
        asset_artifact["properties"]["file"],
        artifacts["Tree"]["properties"]["file"],
    ):
        _validate_assembly_reference(python_synth_output, inventory, reference)

    template = _load_assembly_json(python_synth_output / "SynthStack.template.json")
    assert template == {
        "Parameters": {
            "BootstrapVersion": {
                "Default": "/cdk-bootstrap/hnb659fds/version",
                "Description": (
                    "Version of the CDK Bootstrap resources in this environment, "
                    "automatically retrieved from SSM Parameter Store. [cdk:skip]"
                ),
                "Type": "AWS::SSM::Parameter::Value<String>",
            }
        },
        "Resources": {"Queue": {"Type": "AWS::SQS::Queue"}},
        "Rules": {
            "CheckBootstrapVersion": {
                "Assertions": [
                    {
                        "Assert": {
                            "Fn::Not": [
                                {
                                    "Fn::Contains": [
                                        ["1", "2", "3", "4", "5"],
                                        {"Ref": "BootstrapVersion"},
                                    ]
                                }
                            ]
                        },
                        "AssertDescription": (
                            "CDK bootstrap stack version 6 required. Please run "
                            "'cdk bootstrap' with a recent version of the CDK CLI."
                        ),
                    }
                ]
            }
        },
    }
    asset_manifest = _load_assembly_json(python_synth_output / "SynthStack.assets.json")
    assert asset_manifest == {
        "version": EMITTED_ASSEMBLY_VERSION,
        "files": {
            TEMPLATE_ASSET_HASH: {
                "displayName": f"{STACK_NAME} Template",
                "source": {
                    "path": f"{STACK_NAME}.template.json",
                    "packaging": "file",
                },
                "destinations": {
                    "current_account-current_region-44d81174": {
                        "bucketName": ("cdk-hnb659fds-assets-${AWS::AccountId}-${AWS::Region}"),
                        "objectKey": f"{TEMPLATE_ASSET_HASH}.json",
                        "assumeRoleArn": (
                            "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/"
                            "cdk-hnb659fds-file-publishing-role-"
                            "${AWS::AccountId}-${AWS::Region}"
                        ),
                    }
                },
            }
        },
        "dockerImages": {},
    }
    _validate_assembly_reference(
        python_synth_output,
        inventory,
        asset_manifest["files"][TEMPLATE_ASSET_HASH]["source"]["path"],
    )
    assert _load_assembly_json(python_synth_output / "cdk.out", 1024) == {
        "version": EMITTED_ASSEMBLY_VERSION
    }
    tree = _load_assembly_json(python_synth_output / "tree.json")
    assert tree == _expected_tree()
