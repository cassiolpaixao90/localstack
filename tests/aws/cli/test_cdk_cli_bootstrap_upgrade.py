import os
import platform
import shutil
import socket
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from math import ceil
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from localstack import config
from localstack.cli.cdk import (
    build_cdk_environment,
    launch_cdk,
    probe_cdk_cli_version,
    probe_localstack_health,
)
from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.cli.bootstrap_upgrade_execution_evidence import (
    MAX_OBSERVATION_BYTES,
    create_observation,
)
from tests.aws.cli.execution_evidence import write_canonical_json
from tests.aws.cli.test_cdk_cli_blackbox import _load_bounded_yaml

PROJECT_ROOT = Path(__file__).parents[3]
TOOLCHAIN_ROOT = Path(__file__).parent
PINNED_NODE_VERSION = "22.23.2"
PINNED_CDK_VERSION = "2.1135.1"
MAX_TEMPLATE_BYTES = 1024 * 1024
EXPECTED_ROLE_LOGICAL_IDS = {
    "CloudFormationExecutionRole",
    "DeploymentActionRole",
    "FilePublishingRole",
    "ImagePublishingRole",
    "LookupRole",
}
_REQUIRED = os.environ.get("CDK_REAL_CLI_REQUIRED") == "1"


def _validate_required_target(required: bool, test_target: str | None) -> None:
    if required and test_target != "LOCALSTACK":
        raise pytest.UsageError(
            "CDK_REAL_CLI_REQUIRED requires TEST_TARGET=LOCALSTACK; skips cannot promote"
        )


_validate_required_target(_REQUIRED, os.environ.get("TEST_TARGET"))


@dataclass(frozen=True)
class BootstrapStack:
    stack_id: str
    stack_name: str
    qualifier: str
    bucket_name: str
    repository_name: str
    role_names: dict[str, str]
    role_identities: dict[str, dict[str, str]]
    external_policy_arn: str


@dataclass(frozen=True)
class CdkRuntime:
    executable: str
    environment: dict[str, str]
    workspace: Path


def _delete_versioned_bucket(aws_client, bucket_name: str) -> None:
    for page in aws_client.s3.get_paginator("list_object_versions").paginate(Bucket=bucket_name):
        objects = [
            {"Key": item["Key"], "VersionId": item["VersionId"]}
            for collection in ("Versions", "DeleteMarkers")
            for item in page.get(collection, [])
        ]
        for offset in range(0, len(objects), 1000):
            aws_client.s3.delete_objects(
                Bucket=bucket_name,
                Delete={"Objects": objects[offset : offset + 1000], "Quiet": True},
            )

    for page in aws_client.s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket_name):
        for upload in page.get("Uploads", []):
            aws_client.s3.abort_multipart_upload(
                Bucket=bucket_name,
                Key=upload["Key"],
                UploadId=upload["UploadId"],
            )

    aws_client.s3.delete_bucket(Bucket=bucket_name)


def _resource_is_missing(call, *, expected_codes: set[str], **kwargs) -> bool:
    try:
        call(**kwargs)
    except ClientError as error:
        return error.response.get("Error", {}).get("Code") in expected_codes
    return False


def _load_template_body(value):
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        raise ValueError("CDK bootstrap template is outside the accepted bounds")
    return _load_bounded_yaml(value)


def _validate_role_names(role_names: dict[str, str]) -> None:
    if set(role_names) != EXPECTED_ROLE_LOGICAL_IDS:
        raise ValueError("CDK bootstrap role set is incomplete")
    names = tuple(role_names.values())
    if any(not isinstance(name, str) or not name for name in names) or len(set(names)) != len(
        names
    ):
        raise ValueError("CDK bootstrap physical role names must be non-empty and unique")


def _validated_role_identities(roles: dict[str, dict]) -> dict[str, dict[str, str]]:
    identities = {}
    for logical_id in EXPECTED_ROLE_LOGICAL_IDS:
        role = roles.get(logical_id)
        if not isinstance(role, dict):
            raise ValueError(f"CDK bootstrap role is malformed: {logical_id}")
        identity = {key: role.get(key) for key in ("Arn", "RoleId")}
        if any(not isinstance(value, str) or not value for value in identity.values()):
            raise ValueError(f"CDK bootstrap role identity is malformed: {logical_id}")
        identities[logical_id] = identity
    return identities


def _stack_is_deleted(aws_client, stack_id: str) -> bool:
    try:
        response = aws_client.cloudformation.describe_stacks(StackName=stack_id)
    except ClientError as error:
        return error.response.get("Error", {}).get("Code") == "ValidationError"
    return response["Stacks"][0]["StackStatus"] == "DELETE_COMPLETE"


def _wait_with_deadline(waiter, deadline: float, **kwargs) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("CloudFormation phase exceeded its deadline")
    waiter.wait(
        **kwargs,
        WaiterConfig={"Delay": 1, "MaxAttempts": max(1, ceil(remaining))},
    )


def _require(condition: bool, message: str, *, required: bool) -> None:
    if condition:
        return
    if required:
        pytest.fail(message)
    pytest.skip(message)


def _attach_external_policy(iam, journal, role_name: str, policy_arn: str) -> None:
    journal.append((role_name, policy_arn))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)


@pytest.fixture
def pinned_cdk_cli_runtime(tmp_path, account_id, region_name):
    required = _REQUIRED
    if required:
        assert os.environ.get("TEST_TARGET") == "LOCALSTACK"
        assert sys.platform == "linux"
        assert {name for _, name in socket.if_nameindex()} == {"lo"}
    elif os.name != "posix":
        pytest.skip("the CDK process-group supervisor requires POSIX")
    _require(
        is_v2_engine(), "the CDK bootstrap upgrade requires CloudFormation v2", required=required
    )

    node = shutil.which("node")
    _require(node is not None, "the pinned Node executable is not installed", required=required)
    assert node is not None
    node = str(Path(node).resolve())
    node_version = launch_cdk(
        ["--version"],
        executable=node,
        environment={"PATH": str(Path(node).parent)},
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    _require(node_version.returncode == 0, "the Node version probe failed", required=required)
    _require(not node_version.timed_out, "the Node version probe timed out", required=required)
    _require(
        not node_version.stdout_truncated,
        "the Node version output was truncated",
        required=required,
    )
    _require(
        not node_version.stderr_truncated,
        "the Node version error output was truncated",
        required=required,
    )
    expected_node_version = (
        PINNED_NODE_VERSION
        if required
        else os.environ.get("CDK_EXPECTED_NODE_VERSION", PINNED_NODE_VERSION)
    )
    _require(
        node_version.stdout.decode().strip() == f"v{expected_node_version}",
        f"Node {expected_node_version} is required",
        required=required,
    )
    expected_machine_arch = os.environ.get("CDK_EXPECTED_MACHINE_ARCH")
    if expected_machine_arch:
        assert platform.machine() == expected_machine_arch
    node_arch = launch_cdk(
        ["--print", "process.arch"],
        executable=node,
        environment={"PATH": str(Path(node).parent)},
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    _require(node_arch.returncode == 0, "the Node architecture probe failed", required=required)
    _require(not node_arch.timed_out, "the Node architecture probe timed out", required=required)
    _require(
        not node_arch.stdout_truncated,
        "the Node architecture output was truncated",
        required=required,
    )
    _require(
        not node_arch.stderr_truncated,
        "the Node architecture error was truncated",
        required=required,
    )
    expected_node_arch = os.environ.get("CDK_EXPECTED_NODE_ARCH")
    if required:
        assert expected_machine_arch is not None
        assert expected_node_arch is not None
    if expected_node_arch:
        assert node_arch.stdout.decode().strip() == expected_node_arch

    cdk_executable = (TOOLCHAIN_ROOT / "node_modules/aws-cdk/bin/cdk").resolve()
    _require(
        cdk_executable.is_file(),
        "run npm ci in tests/aws/cli before this gate",
        required=required,
    )
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
    _require(
        probe_cdk_cli_version(str(cdk_executable), environment=environment, cwd=workspace)
        == PINNED_CDK_VERSION,
        f"CDK CLI {PINNED_CDK_VERSION} is required",
        required=required,
    )
    return CdkRuntime(
        executable=str(cdk_executable),
        environment=environment,
        workspace=workspace,
    )


@pytest.fixture
def cdk_v28_stack(
    pinned_cdk_cli_runtime,
    aws_client,
    account_id,
    region_name,
):
    qualifier = short_uid()[:10]
    stack_name = f"CDKToolkit-{short_uid()}"
    bucket_name = f"cdk-{qualifier}-assets-{account_id}-{region_name}"
    repository_name = f"cdk-{qualifier}-container-assets-{account_id}-{region_name}"
    parameters = {
        "CloudFormationExecutionPolicies": "",
        "FileAssetsBucketKmsKeyId": "AWS_MANAGED_KEY",
        "PublicAccessBlockConfiguration": "true",
        "Qualifier": qualifier,
        "TrustedAccounts": "",
        "TrustedAccountsForLookup": "",
    }
    stack_id = None
    create_attempted = False
    attachments: list[tuple[str, str]] = []
    role_names: dict[str, str] = {}
    cleanup_errors: list[Exception] = []

    try:
        seed_deadline = time.monotonic() + 45
        change_set_name = f"cdk-bootstrap-seed-{short_uid()}"
        create_attempted = True
        create_change_set = aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            ChangeSetType="CREATE",
            TemplateBody=(PROJECT_ROOT / "tests/aws/templates/cdk_bootstrap_v28.yaml").read_text(),
            Parameters=[
                {"ParameterKey": key, "ParameterValue": value} for key, value in parameters.items()
            ],
            Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        )
        stack_id = create_change_set["StackId"]
        change_set_id = create_change_set["Id"]
        _wait_with_deadline(
            aws_client.cloudformation.get_waiter("change_set_create_complete"),
            seed_deadline,
            ChangeSetName=change_set_id,
        )
        aws_client.cloudformation.execute_change_set(ChangeSetName=change_set_id)
        _wait_with_deadline(
            aws_client.cloudformation.get_waiter("stack_create_complete"),
            seed_deadline,
            StackName=stack_id,
        )
        created_stack = aws_client.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][0]
        assert created_stack["StackStatus"] == "CREATE_COMPLETE"
        created_outputs = {
            output["OutputKey"]: output["OutputValue"]
            for output in created_stack.get("Outputs", [])
        }
        assert created_outputs["BootstrapVersion"] == "28"
        assert created_outputs["BucketName"] == bucket_name
        assert (
            aws_client.ssm.get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")["Parameter"][
                "Value"
            ]
            == "28"
        )

        original = _load_template_body(
            aws_client.cloudformation.get_template(
                StackName=stack_id,
                TemplateStage="Original",
            )["TemplateBody"]
        )
        expected_v28 = _load_template_body(
            (PROJECT_ROOT / "tests/aws/templates/cdk_bootstrap_v28.yaml").read_text()
        )
        assert original == expected_v28

        stack_resources = aws_client.cloudformation.describe_stack_resources(StackName=stack_id)[
            "StackResources"
        ]
        role_names = {
            resource["LogicalResourceId"]: resource["PhysicalResourceId"]
            for resource in stack_resources
            if resource["ResourceType"] == "AWS::IAM::Role"
        }
        _validate_role_names(role_names)
        roles_before = {
            logical_id: aws_client.iam.get_role(RoleName=role_name)["Role"]
            for logical_id, role_name in role_names.items()
        }
        role_identities = _validated_role_identities(roles_before)
        partition = role_identities["DeploymentActionRole"]["Arn"].split(":", 2)[1]
        external_policy_arn = f"arn:{partition}:iam::aws:policy/SecurityAudit"
        for role_name in role_names.values():
            baseline = aws_client.iam.list_attached_role_policies(RoleName=role_name)[
                "AttachedPolicies"
            ]
            assert external_policy_arn not in {policy["PolicyArn"] for policy in baseline}
            _attach_external_policy(
                aws_client.iam,
                attachments,
                role_name,
                external_policy_arn,
            )

        yield BootstrapStack(
            stack_id=stack_id,
            stack_name=stack_name,
            qualifier=qualifier,
            bucket_name=bucket_name,
            repository_name=repository_name,
            role_names=role_names,
            role_identities=role_identities,
            external_policy_arn=external_policy_arn,
        )
    finally:
        for role_name, policy_arn in reversed(attachments):
            try:
                aws_client.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    cleanup_errors.append(error)
            except Exception as error:
                cleanup_errors.append(error)

        stack_target = stack_id or stack_name
        if create_attempted:
            try:
                aws_client.cloudformation.delete_stack(StackName=stack_target)
                _wait_with_deadline(
                    aws_client.cloudformation.get_waiter("stack_delete_complete"),
                    time.monotonic() + 45,
                    StackName=stack_target,
                )
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") != "ValidationError":
                    cleanup_errors.append(error)
            except Exception as error:
                cleanup_errors.append(error)

        try:
            aws_client.s3.head_bucket(Bucket=bucket_name)
        except ClientError as error:
            if error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 404:
                cleanup_errors.append(error)
        except Exception as error:
            cleanup_errors.append(error)
        else:
            try:
                _delete_versioned_bucket(aws_client, bucket_name)
            except Exception as error:
                cleanup_errors.append(error)

        try:
            aws_client.s3.head_bucket(Bucket=bucket_name)
        except ClientError as error:
            if error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 404:
                cleanup_errors.append(error)
        except Exception as error:
            cleanup_errors.append(error)
        else:
            cleanup_errors.append(AssertionError("bootstrap bucket still exists after cleanup"))

        if create_attempted:
            try:
                stack_deleted = _stack_is_deleted(aws_client, stack_target)
            except Exception as error:
                cleanup_errors.append(error)
            else:
                if not stack_deleted:
                    cleanup_errors.append(
                        AssertionError("bootstrap stack still exists after cleanup")
                    )
        for role_name in role_names.values():
            try:
                role_missing = _resource_is_missing(
                    aws_client.iam.get_role,
                    RoleName=role_name,
                    expected_codes={"NoSuchEntity"},
                )
            except Exception as error:
                cleanup_errors.append(error)
            else:
                if not role_missing:
                    cleanup_errors.append(
                        AssertionError(f"bootstrap role still exists: {role_name}")
                    )
        try:
            parameter_missing = _resource_is_missing(
                aws_client.ssm.get_parameter,
                Name=f"/cdk-bootstrap/{qualifier}/version",
                expected_codes={"ParameterNotFound"},
            )
        except Exception as error:
            cleanup_errors.append(error)
        else:
            if not parameter_missing:
                cleanup_errors.append(
                    AssertionError("bootstrap version parameter still exists after cleanup")
                )
        if cleanup_errors:
            raise ExceptionGroup("CDK bootstrap cleanup failed", cleanup_errors)


@markers.aws.only_localstack
def test_cdk_cli_upgrades_api_v28_to_builtin_v32(
    pinned_cdk_cli_runtime,
    cdk_v28_stack,
    aws_client,
    account_id,
    region_name,
):
    observation_path = os.environ.get("CDK_BOOTSTRAP_UPGRADE_OBSERVATION")
    if observation_path and not _REQUIRED:
        pytest.fail("bootstrap upgrade observations are restricted to the required CI lane")
    _require(
        not _REQUIRED or observation_path is not None,
        "the required bootstrap upgrade gate needs an observation path",
        required=_REQUIRED,
    )
    evidence_environment = {
        name: os.environ.get(name)
        for name in (
            "RESULT_ARCH",
            "CDK_EXPECTED_MACHINE_ARCH",
            "CDK_EXPECTED_NODE_ARCH",
            "CDK_EVIDENCE_REPOSITORY",
            "CDK_EVIDENCE_COMMIT_SHA",
            "CDK_EVIDENCE_REF",
            "CDK_EVIDENCE_EVENT",
            "CDK_EVIDENCE_WORKFLOW_PATH",
            "CDK_EVIDENCE_RUN_ID",
            "CDK_EVIDENCE_RUN_ATTEMPT",
        )
    }
    _require(
        not _REQUIRED or all(evidence_environment.values()),
        "the required bootstrap upgrade gate needs complete evidence metadata",
        required=_REQUIRED,
    )
    argv = [
        "bootstrap",
        f"aws://{account_id}/{region_name}",
        "--toolkit-stack-name",
        cdk_v28_stack.stack_name,
        "--qualifier",
        cdk_v28_stack.qualifier,
        "--bootstrap-kms-key-id",
        "AWS_MANAGED_KEY",
        "--yes",
        "--ci",
        "--no-color",
        "--no-notices",
        "--execute",
    ]
    started = time.monotonic_ns()
    result = launch_cdk(
        argv,
        executable=pinned_cdk_cli_runtime.executable,
        environment=pinned_cdk_cli_runtime.environment,
        cwd=pinned_cdk_cli_runtime.workspace,
        timeout_seconds=90,
        max_output_bytes=256 * 1024,
    )
    duration_ms = (time.monotonic_ns() - started) // 1_000_000
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.timed_out is False
    assert result.stdout_truncated is False
    assert result.stderr_truncated is False

    stack = aws_client.cloudformation.describe_stacks(StackName=cdk_v28_stack.stack_id)["Stacks"][0]
    assert stack["StackId"] == cdk_v28_stack.stack_id
    assert stack["StackStatus"] == "UPDATE_COMPLETE"
    assert _resource_is_missing(
        aws_client.cloudformation.describe_stacks,
        StackName="CDKToolkit",
        expected_codes={"ValidationError"},
    )
    assert _resource_is_missing(
        aws_client.ssm.get_parameter,
        Name="/cdk-bootstrap/hnb659fds/version",
        expected_codes={"ParameterNotFound"},
    )
    outputs = {output["OutputKey"]: output["OutputValue"] for output in stack["Outputs"]}
    assert outputs["BootstrapVersion"] == "32"
    assert outputs["BucketName"] == cdk_v28_stack.bucket_name
    assert outputs["ImageRepositoryName"] == cdk_v28_stack.repository_name
    assert (
        aws_client.ssm.get_parameter(Name=f"/cdk-bootstrap/{cdk_v28_stack.qualifier}/version")[
            "Parameter"
        ]["Value"]
        == "32"
    )

    template = _load_template_body(
        aws_client.cloudformation.get_template(
            StackName=cdk_v28_stack.stack_id,
            TemplateStage="Original",
        )["TemplateBody"]
    )
    expected_v32 = _load_template_body(
        (PROJECT_ROOT / "tests/aws/templates/cdk_bootstrap_v32.yaml").read_text()
    )
    assert template == expected_v32

    roles_after = {
        logical_id: aws_client.iam.get_role(RoleName=role_name)["Role"]
        for logical_id, role_name in cdk_v28_stack.role_names.items()
    }
    role_identities_after = _validated_role_identities(roles_after)
    assert role_identities_after == cdk_v28_stack.role_identities

    attached_policies = {
        logical_id: {
            policy["PolicyArn"]
            for policy in aws_client.iam.list_attached_role_policies(RoleName=role_name)[
                "AttachedPolicies"
            ]
        }
        for logical_id, role_name in cdk_v28_stack.role_names.items()
    }
    assert all(
        cdk_v28_stack.external_policy_arn in policies for policies in attached_policies.values()
    )
    partition = cdk_v28_stack.role_identities["DeploymentActionRole"]["Arn"].split(":", 2)[1]
    assert (
        f"arn:{partition}:iam::aws:policy/AWSCloudFormationReadOnlyAccess"
        in attached_policies["DeploymentActionRole"]
    )
    for logical_id in (
        "DeploymentActionRole",
        "FilePublishingRole",
        "ImagePublishingRole",
        "LookupRole",
    ):
        statements = roles_after[logical_id]["AssumeRolePolicyDocument"]["Statement"]
        assert any(
            statement.get("Condition", {}).get("Null", {}).get("sts:ExternalId") == "true"
            for statement in statements
        )

    deployment_policy = aws_client.iam.get_role_policy(
        RoleName=cdk_v28_stack.role_names["DeploymentActionRole"],
        PolicyName="default",
    )["PolicyDocument"]
    statement_ids = {statement.get("Sid") for statement in deployment_policy["Statement"]}
    assert "DeployPermissions" in statement_ids
    assert "CloudFormationPermissions" not in statement_ids

    if observation_path:
        observation = create_observation(
            platform_id=f"linux-{evidence_environment['RESULT_ARCH']}",
            machine_arch=evidence_environment["CDK_EXPECTED_MACHINE_ARCH"],
            node_arch=evidence_environment["CDK_EXPECTED_NODE_ARCH"],
            python_version=platform.python_version(),
            kernel_release=platform.release(),
            repository=evidence_environment["CDK_EVIDENCE_REPOSITORY"],
            commit_sha=evidence_environment["CDK_EVIDENCE_COMMIT_SHA"],
            ref=evidence_environment["CDK_EVIDENCE_REF"],
            event=evidence_environment["CDK_EVIDENCE_EVENT"],
            workflow_path=evidence_environment["CDK_EVIDENCE_WORKFLOW_PATH"],
            run_id=int(evidence_environment["CDK_EVIDENCE_RUN_ID"]),
            run_attempt=int(evidence_environment["CDK_EVIDENCE_RUN_ATTEMPT"]),
            account_id=account_id,
            region=region_name,
            stack_name=cdk_v28_stack.stack_name,
            qualifier=cdk_v28_stack.qualifier,
            argv=argv,
            stack_id=cdk_v28_stack.stack_id,
            role_identities=cdk_v28_stack.role_identities,
            returncode=result.returncode,
            timed_out=result.timed_out,
            duration_ms=duration_ms,
            stdout=result.stdout,
            stderr=result.stderr,
            stdout_bytes=result.stdout_bytes,
            stderr_bytes=result.stderr_bytes,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
            observed_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
        write_canonical_json(Path(observation_path), observation, MAX_OBSERVATION_BYTES)
