import json
import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
import requests
from botocore.exceptions import ClientError

from localstack.cli.cdk import launch_cdk
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.cli.execution_evidence import read_regular_bounded
from tests.aws.cli.test_cdk_cli_bootstrap_upgrade import CdkRuntime
from tests.aws.services.apigateway.apigateway_fixtures import UrlType, api_invoke_url

pytest_plugins = ("tests.aws.cli.test_cdk_cli_bootstrap_upgrade",)

PROJECT_ROOT = Path(__file__).parents[3]
APP_PATH = PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/enterprise_api.py"
MAX_OUTPUT_BYTES = 64 * 1024
EXPECTED_OUTPUT_KEYS = {
    "ApiId",
    "ApiRootResourceId",
    "ApiStageName",
    "DeploymentAccount",
    "DeploymentRegion",
}
MAX_OUTPUT_VALUE_BYTES = 256


@dataclass(frozen=True)
class ApiGatewayDeployment:
    stack_name: str
    api_name: str
    api_id: str
    root_resource_id: str
    stage_name: str


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"CDK output JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _load_outputs(path: Path, *, stack_name: str, account_id: str, region_name: str) -> dict:
    payload = read_regular_bounded(path, MAX_OUTPUT_BYTES)
    value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict) or set(value) != {stack_name}:
        raise ValueError("CDK output must contain exactly the deployed stack")
    stack_outputs = value[stack_name]
    if not isinstance(stack_outputs, dict) or set(stack_outputs) != EXPECTED_OUTPUT_KEYS:
        raise ValueError("CDK stack output does not match the closed API contract")
    if any(
        not isinstance(item, str) or not item or len(item.encode("utf-8")) > MAX_OUTPUT_VALUE_BYTES
        for item in stack_outputs.values()
    ):
        raise ValueError("CDK stack output values must be bounded non-empty strings")
    if stack_outputs["DeploymentAccount"] != account_id:
        raise ValueError("CDK output account does not match the requested account")
    if stack_outputs["DeploymentRegion"] != region_name:
        raise ValueError("CDK output region does not match the requested region")
    return stack_outputs


def _python_app_command() -> str:
    configured = os.environ.get("CDK_PYTHON_SYNTH_PYTHON")
    python = Path(configured) if configured else Path(sys.executable)
    if not python.is_absolute() or not python.is_file():
        raise ValueError("the CDK Python interpreter must be an absolute file-backed path")
    if not APP_PATH.is_absolute() or not APP_PATH.is_file():
        raise ValueError("the enterprise API CDK fixture is unavailable")
    return shlex.join((str(python), "-I", "-B", str(APP_PATH)))


def _stack_is_absent(cloudformation, stack_name: str) -> bool:
    try:
        cloudformation.describe_stacks(StackName=stack_name)
    except ClientError as error:
        return error.response.get("Error", {}).get("Code") == "ValidationError"
    return False


def _apis_named(apigateway, api_name: str) -> list[dict]:
    return [
        api
        for page in apigateway.get_paginator("get_rest_apis").paginate()
        for api in page.get("items", [])
        if api.get("name") == api_name
    ]


@pytest.fixture
def deployed_enterprise_api(
    pinned_cdk_cli_runtime: CdkRuntime,
    aws_client,
    account_id,
    region_name,
    tmp_path,
):
    deployment = short_uid()[:8]
    stack_name = f"localstack-enterprise-dev-{deployment}-api"
    api_name = stack_name
    output_path = tmp_path / "apigateway-outputs.json"
    environment = dict(pinned_cdk_cli_runtime.environment)
    environment.update(
        {
            "CDK_DEFAULT_ACCOUNT": account_id,
            "CDK_DEFAULT_REGION": region_name,
        }
    )
    result = None
    outputs = None
    cleanup_errors: list[Exception] = []
    try:
        result = launch_cdk(
            [
                "deploy",
                "EnterpriseApi",
                "--app",
                _python_app_command(),
                "--context",
                "project=localstack-enterprise",
                "--context",
                "stage=dev",
                "--context",
                f"deployment={deployment}",
                "--context",
                "owner=platform",
                "--outputs-file",
                str(output_path),
                "--require-approval",
                "never",
                "--no-lookups",
                "--strict",
                "--no-version-reporting",
                "--no-path-metadata",
                "--no-asset-metadata",
                "--no-notices",
                "--no-color",
                "--ci",
                "--execute",
            ],
            executable=pinned_cdk_cli_runtime.executable,
            environment=environment,
            cwd=pinned_cdk_cli_runtime.workspace,
            timeout_seconds=90,
            max_output_bytes=256 * 1024,
        )
        assert not result.timed_out
        assert not result.stdout_truncated
        assert not result.stderr_truncated
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        outputs = _load_outputs(
            output_path,
            stack_name=stack_name,
            account_id=account_id,
            region_name=region_name,
        )
        deployment_state = ApiGatewayDeployment(
            stack_name=stack_name,
            api_name=api_name,
            api_id=outputs["ApiId"],
            root_resource_id=outputs["ApiRootResourceId"],
            stage_name=outputs["ApiStageName"],
        )
        yield deployment_state
    finally:
        try:
            if not _stack_is_absent(aws_client.cloudformation, stack_name):
                aws_client.cloudformation.delete_stack(StackName=stack_name)
                aws_client.cloudformation.get_waiter("stack_delete_complete").wait(
                    StackName=stack_name,
                    WaiterConfig={"Delay": 1, "MaxAttempts": 60},
                )
        except Exception as error:
            cleanup_errors.append(error)
        try:
            for api in _apis_named(aws_client.apigateway, api_name):
                aws_client.apigateway.delete_rest_api(restApiId=api["id"])
        except Exception as error:
            cleanup_errors.append(error)
        try:
            if not _stack_is_absent(aws_client.cloudformation, stack_name):
                raise RuntimeError(f"CloudFormation stack {stack_name} remains after cleanup")
        except Exception as error:
            cleanup_errors.append(error)
        try:
            residual_apis = _apis_named(aws_client.apigateway, api_name)
            if residual_apis:
                raise RuntimeError(f"API Gateway REST APIs remain after cleanup: {residual_apis!r}")
        except Exception as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            summary = "; ".join(f"{type(error).__name__}: {error}" for error in cleanup_errors)
            raise RuntimeError(f"enterprise API cleanup failed: {summary}") from cleanup_errors[0]


@markers.aws.only_localstack
def test_cdk_cli_deploys_invokes_and_cleans_up_enterprise_apigateway(
    deployed_enterprise_api: ApiGatewayDeployment,
    aws_client,
):
    deployment = deployed_enterprise_api
    rest_api = aws_client.apigateway.get_rest_api(restApiId=deployment.api_id)
    assert rest_api["id"] == deployment.api_id
    assert rest_api["name"] == deployment.api_name
    assert rest_api["endpointConfiguration"]["types"] == ["REGIONAL"]

    method = aws_client.apigateway.get_method(
        restApiId=deployment.api_id,
        resourceId=deployment.root_resource_id,
        httpMethod="GET",
    )
    assert method["authorizationType"] == "NONE"
    assert method["methodIntegration"]["type"] == "MOCK"
    assert method["methodResponses"] == {"200": {"statusCode": "200"}}

    stages = aws_client.apigateway.get_stages(restApiId=deployment.api_id)["item"]
    assert len(stages) == 1
    assert stages[0]["stageName"] == deployment.stage_name == "local"

    response = requests.get(
        api_invoke_url(
            deployment.api_id,
            stage=deployment.stage_name,
            path="/",
            url_type=UrlType.LS_PATH_BASED,
        ),
        timeout=10,
    )
    assert response.status_code == 200
    assert response.json() == {"service": "localstack", "status": "ok"}
