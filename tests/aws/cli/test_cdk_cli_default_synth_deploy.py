import json
import logging
import os
import re
import secrets
import shlex
import sys
import time
from pathlib import Path

from botocore.exceptions import ClientError

from localstack.cli.cdk import launch_cdk
from localstack.testing.pytest import markers
from tests.aws.cli.execution_evidence import read_regular_bounded
from tests.aws.cli.test_cdk_cli_bootstrap_upgrade import (
    CdkRuntime,
    _delete_versioned_bucket,
    _resource_is_missing,
)

pytest_plugins = ("tests.aws.cli.test_cdk_cli_bootstrap_upgrade",)

LOG = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).parents[3]
APP_PATH = PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/default_synth_app.py"
OWNER_TAG_KEY = "localstack:diagnostic-owner"
OWNER_PATTERN = re.compile(r"^[a-f0-9]{24}$")
EXPECTED_OUTPUT_KEYS = {
    "DeploymentAccount",
    "DeploymentRegion",
    "FunctionName",
    "QueueName",
}
BOOTSTRAP_ROLE_LOGICAL_IDS = {
    "CloudFormationExecutionRole",
    "DeploymentActionRole",
    "FilePublishingRole",
    "ImagePublishingRole",
    "LookupRole",
}


def _python_app_command() -> str:
    configured = os.environ.get("CDK_PYTHON_SYNTH_PYTHON")
    python = Path(configured) if configured else Path(sys.executable)
    if not python.is_absolute() or not python.is_file() or not APP_PATH.is_file():
        raise ValueError("the pinned Python interpreter and default-synth fixture must exist")
    return shlex.join((str(python), "-I", "-B", str(APP_PATH)))


def _run_cdk(runtime: CdkRuntime, arguments: list[str], timeout_seconds: float = 600):
    result = launch_cdk(
        arguments,
        executable=runtime.executable,
        environment=runtime.environment,
        cwd=runtime.workspace,
        timeout_seconds=timeout_seconds,
        max_output_bytes=256 * 1024,
    )
    assert not result.timed_out
    assert not result.stdout_truncated
    assert not result.stderr_truncated
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result


def _stack_absent(cloudformation, stack_name: str) -> bool:
    try:
        cloudformation.describe_stacks(StackName=stack_name)
    except ClientError as error:
        return error.response.get("Error", {}).get("Code") == "ValidationError"
    return False


def _delete_stack_and_wait(cloudformation, stack_name: str) -> None:
    cloudformation.delete_stack(StackName=stack_name, DeletionMode="FORCE_DELETE_STACK")
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if _stack_absent(cloudformation, stack_name):
            return
        time.sleep(1)
    raise TimeoutError(f"stack {stack_name} was not deleted within the deadline")


def _bootstrap_role_names(cloudformation, toolkit_stack: str) -> list[str]:
    resources = cloudformation.describe_stack_resources(StackName=toolkit_stack)["StackResources"]
    names = []
    for item in resources:
        if item.get("ResourceType") == "AWS::IAM::Role":
            if item.get("LogicalResourceId") not in BOOTSTRAP_ROLE_LOGICAL_IDS:
                raise RuntimeError("bootstrap stack contains an unexpected IAM role")
            names.append(item["PhysicalResourceId"])
    if len(names) != len(BOOTSTRAP_ROLE_LOGICAL_IDS):
        raise RuntimeError("bootstrap stack role set is incomplete")
    return names


def _delete_bootstrap_roles(iam, role_names: list[str]) -> None:
    for role_name in role_names:
        # The toolkit stack deletion normally removes the roles already
        if _resource_is_missing(iam.get_role, expected_codes={"NoSuchEntity"}, RoleName=role_name):
            continue
        for policy in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy)
        for policy in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])
        iam.delete_role(RoleName=role_name)


def _loopback_ip_runtime(runtime: CdkRuntime) -> CdkRuntime:
    # The JS SDK inside the CDK CLI ignores AWS_S3_FORCE_PATH_STYLE and uses
    # virtual-hosted S3 addressing unless the endpoint host is an IP literal.
    # The gateway only honors virtual-host addressing on *.localhost.localstack.cloud,
    # so point the CLI at 127.0.0.1 to force path-style asset publishing.
    environment = dict(runtime.environment)
    for name in ("AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3"):
        value = environment.get(name, "")
        environment[name] = value.replace("://localhost:", "://127.0.0.1:").replace(
            "://localhost.localstack.cloud:", "://127.0.0.1:"
        )
    return CdkRuntime(
        executable=runtime.executable,
        environment=environment,
        workspace=runtime.workspace,
    )


@markers.aws.only_localstack
def test_cdk_cli_bootstrap_and_default_synth_deploy(
    pinned_cdk_cli_runtime: CdkRuntime,
    aws_client_factory,
    account_id,
    region_name,
    tmp_path,
):
    runtime = _loopback_ip_runtime(pinned_cdk_cli_runtime)
    clients = aws_client_factory()
    cloudformation = clients.cloudformation
    owner_nonce = secrets.token_hex(12)
    assert OWNER_PATTERN.fullmatch(owner_nonce)
    deployment = f"d{owner_nonce[:23]}"
    stack_name = f"localstack-defsynth-{deployment}"
    qualifier = f"q{owner_nonce[:9]}"
    toolkit_stack = f"CDKToolkit-{owner_nonce[:12]}"
    bucket_name = f"cdk-{qualifier}-assets-{account_id}-{region_name}"
    ssm_parameter = f"/cdk-bootstrap/{qualifier}/version"
    output_path = tmp_path / "default-synth-outputs.json"
    role_names: list[str] = []
    bootstrapped = False
    deployed = False
    cleanup_errors = []

    try:
        _run_cdk(
            runtime,
            [
                "bootstrap",
                f"aws://{account_id}/{region_name}",
                "--qualifier",
                qualifier,
                "--toolkit-stack-name",
                toolkit_stack,
                "--no-color",
                "--no-notices",
                "--ci",
            ],
        )
        bootstrapped = True
        stack = cloudformation.describe_stacks(StackName=toolkit_stack)["Stacks"][0]
        assert stack["StackStatus"] in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
        version = clients.ssm.get_parameter(Name=ssm_parameter)["Parameter"]["Value"]
        assert version.isdigit() and int(version) >= 32
        clients.s3.head_bucket(Bucket=bucket_name)
        role_names = _bootstrap_role_names(cloudformation, toolkit_stack)

        _run_cdk(
            runtime,
            [
                "deploy",
                "DefaultSynthApp",
                "--app",
                _python_app_command(),
                "--context",
                f"deployment={deployment}",
                "--context",
                f"owner={owner_nonce}",
                "--context",
                f"qualifier={qualifier}",
                "--outputs-file",
                str(output_path),
                "--require-approval",
                "never",
                "--no-lookups",
                "--strict",
                "--no-version-reporting",
                "--no-notices",
                "--no-color",
                "--ci",
            ],
        )
        deployed = True
        value = json.loads(read_regular_bounded(output_path, 64 * 1024))
        assert set(value) == {stack_name}
        outputs = value[stack_name]
        assert set(outputs) == EXPECTED_OUTPUT_KEYS
        assert outputs["DeploymentAccount"] == account_id
        assert outputs["DeploymentRegion"] == region_name

        # The DefaultStackSynthesizer must have published the Lambda file asset to S3
        objects = clients.s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        asset_keys = [item["Key"] for item in objects if item["Key"].endswith(".zip")]
        assert asset_keys, "no file asset was published to the bootstrap bucket"

        app_stack = cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]
        assert app_stack["StackStatus"] == "CREATE_COMPLETE"
        result = clients.lambda_.invoke(FunctionName=outputs["FunctionName"])
        assert result["StatusCode"] == 200
        assert json.loads(result["Payload"].read())["body"] == "default-synth-asset-ok"

        _run_cdk(
            runtime,
            [
                "destroy",
                "DefaultSynthApp",
                "--app",
                _python_app_command(),
                "--context",
                f"deployment={deployment}",
                "--context",
                f"owner={owner_nonce}",
                "--context",
                f"qualifier={qualifier}",
                "--force",
                "--no-version-reporting",
                "--no-notices",
                "--no-color",
                "--ci",
            ],
        )
        deployed = False
        assert _stack_absent(cloudformation, stack_name)
    finally:
        try:
            if deployed and not _stack_absent(cloudformation, stack_name):
                _delete_stack_and_wait(cloudformation, stack_name)
        except Exception as error:
            cleanup_errors.append(error)
        if bootstrapped:
            try:
                if not role_names:
                    role_names = _bootstrap_role_names(cloudformation, toolkit_stack)
            except Exception as error:
                LOG.debug("failed to enumerate bootstrap roles: %s", error)
            try:
                if not _stack_absent(cloudformation, toolkit_stack):
                    _delete_stack_and_wait(cloudformation, toolkit_stack)
            except Exception as error:
                cleanup_errors.append(error)
            try:
                if not _resource_is_missing(
                    clients.s3.head_bucket,
                    expected_codes={"404", "NoSuchBucket"},
                    Bucket=bucket_name,
                ):
                    _delete_versioned_bucket(clients, bucket_name)
            except Exception as error:
                cleanup_errors.append(error)
            try:
                if not _resource_is_missing(
                    clients.ssm.get_parameter,
                    expected_codes={"ParameterNotFound"},
                    Name=ssm_parameter,
                ):
                    clients.ssm.delete_parameter(Name=ssm_parameter)
            except Exception as error:
                cleanup_errors.append(error)
            try:
                if role_names:
                    _delete_bootstrap_roles(clients.iam, role_names)
            except Exception as error:
                cleanup_errors.append(error)
        try:
            if not _stack_absent(cloudformation, stack_name):
                cleanup_errors.append(RuntimeError("default-synth stack remains"))
            if not _stack_absent(cloudformation, toolkit_stack):
                cleanup_errors.append(RuntimeError("bootstrap stack remains"))
        except Exception as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            summary = "; ".join(f"{type(error).__name__}: {error}" for error in cleanup_errors)
            raise RuntimeError(f"default-synth gate cleanup failed: {summary}") from cleanup_errors[
                0
            ]
