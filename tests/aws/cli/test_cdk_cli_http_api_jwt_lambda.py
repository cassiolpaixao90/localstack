import json
import logging
import os
import re
import secrets
import shlex
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
import requests
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack.cli.cdk import launch_cdk
from localstack.testing.pytest import markers
from localstack.utils.aws.arns import get_partition
from localstack.utils.strings import short_uid
from tests.aws.cli.execution_evidence import read_regular_bounded
from tests.aws.cli.test_cdk_cli_bootstrap_upgrade import CdkRuntime
from tests.aws.services.apigateway.apigateway_fixtures import UrlType, api_invoke_url

pytest_plugins = (
    "tests.aws.cli.test_cdk_cli_bootstrap_upgrade",
    "tests.aws.services.cognito_idp.conftest",
)

LOG = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).parents[3]
APP_PATH = PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/enterprise_http_api_jwt.py"
ORIGIN = "https://app.example.test"
OWNER_TAG_KEY = "localstack:diagnostic-owner"
OWNER_PATTERN = re.compile(r"^[a-f0-9]{24}$")
ID_PATTERN = re.compile(r"^[A-Za-z0-9_$-]{1,256}$")
LIST_DEADLINE_SECONDS = 10
RPC_TIMEOUT_SECONDS = 2
EXPECTED_OUTPUT_KEYS = {
    "ApiEndpoint",
    "ApiId",
    "AuthorizerId",
    "DeploymentAccount",
    "DeploymentId",
    "DeploymentRegion",
    "FunctionName",
    "StageName",
    "UserPoolClientId",
    "UserPoolId",
}
EXPECTED_STACK_RESOURCES = {
    "Deployment": "AWS::ApiGatewayV2::Deployment",
    "Handler886CB40B": "AWS::Lambda::Function",
    "HandlerServiceRoleFCDC14AE": "AWS::IAM::Role",
    "HttpApiF5A9A8A7": "AWS::ApiGatewayV2::Api",
    "HttpApiGETprivateid6E716BA9": "AWS::ApiGatewayV2::Route",
    "HttpApiGETprivateidLambdaIntegration4DD64095": "AWS::ApiGatewayV2::Integration",
    "HttpApiGETprivateidLambdaIntegrationPermission285C863E": "AWS::Lambda::Permission",
    "JwtAuthorizer": "AWS::ApiGatewayV2::Authorizer",
    "Stage": "AWS::ApiGatewayV2::Stage",
    "UserPool6BA7E5F2": "AWS::Cognito::UserPool",
    "UserPoolUserPoolClient40176907": "AWS::Cognito::UserPoolClient",
}


@dataclass(frozen=True)
class HttpApiJwtDeployment:
    api_id: str
    authorizer_id: str
    client_id: str
    deployment_id: str
    function_name: str
    integration_id: str
    owner_nonce: str
    permission_id: str
    pool_id: str
    route_id: str
    stack_id: str
    stack_name: str
    stage_name: str


def _rpc_config() -> Config:
    return Config(
        connect_timeout=RPC_TIMEOUT_SECONDS,
        read_timeout=RPC_TIMEOUT_SECONDS,
        retries={"mode": "standard", "total_max_attempts": 1},
    )


def _deadline() -> float:
    return time.monotonic() + LIST_DEADLINE_SECONDS


def _ensure_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError("bounded resource inventory exceeded its deadline")


def _python_app_command() -> str:
    configured = os.environ.get("CDK_PYTHON_SYNTH_PYTHON")
    python = Path(configured) if configured else Path(sys.executable)
    if not python.is_absolute() or not python.is_file() or not APP_PATH.is_file():
        raise ValueError("the pinned Python interpreter and HTTP API fixture must be file-backed")
    return shlex.join((str(python), "-I", "-B", str(APP_PATH)))


def _load_outputs(path: Path, stack_name: str, account_id: str, region_name: str) -> dict:
    value = json.loads(read_regular_bounded(path, 64 * 1024))
    if not isinstance(value, dict) or set(value) != {stack_name}:
        raise ValueError("CDK output must contain exactly the owned stack")
    outputs = value[stack_name]
    if not isinstance(outputs, dict) or set(outputs) != EXPECTED_OUTPUT_KEYS:
        raise ValueError("CDK HTTP API output contract is not closed")
    if outputs["DeploymentAccount"] != account_id or outputs["DeploymentRegion"] != region_name:
        raise ValueError("CDK output scope does not match the deployment")
    if any(not isinstance(item, str) or not item or len(item) > 2048 for item in outputs.values()):
        raise ValueError("CDK output contains an invalid value")
    return outputs


def _stack_absent(cloudformation, stack_name: str) -> bool:
    try:
        cloudformation.describe_stacks(StackName=stack_name)
    except ClientError as error:
        return error.response.get("Error", {}).get("Code") == "ValidationError"
    return False


def _validated_stack(
    cloudformation,
    stack_name: str,
    owner_nonce: str,
    account_id: str,
    region_name: str,
    *,
    require_complete: bool,
) -> dict:
    stack = cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]
    stack_id = stack.get("StackId")
    expected_prefix = (
        f"arn:{get_partition(region_name)}:cloudformation:{region_name}:{account_id}:"
        f"stack/{stack_name}/"
    )
    owner_values = [
        item.get("Value") for item in stack.get("Tags", []) if item.get("Key") == OWNER_TAG_KEY
    ]
    if (
        stack.get("StackName") != stack_name
        or not isinstance(stack_id, str)
        or not stack_id.startswith(expected_prefix)
        or owner_values != [owner_nonce]
        or (require_complete and stack.get("StackStatus") != "CREATE_COMPLETE")
    ):
        raise RuntimeError("CloudFormation stack ownership or status validation failed")
    return stack


def _validated_resource_ids(cloudformation, stack_id: str) -> dict[str, str]:
    resources = cloudformation.describe_stack_resources(StackName=stack_id)["StackResources"]
    if len(resources) != len(EXPECTED_STACK_RESOURCES):
        raise RuntimeError("CloudFormation stack resource set is incomplete")
    result = {}
    for item in resources:
        logical_id = item.get("LogicalResourceId")
        physical_id = item.get("PhysicalResourceId")
        if (
            logical_id not in EXPECTED_STACK_RESOURCES
            or item.get("ResourceType") != EXPECTED_STACK_RESOURCES[logical_id]
            or item.get("ResourceStatus") != "CREATE_COMPLETE"
            or not isinstance(physical_id, str)
            or not ID_PATTERN.fullmatch(physical_id)
            or logical_id in result
        ):
            raise RuntimeError("CloudFormation resource identity contract is invalid")
        result[logical_id] = physical_id
    if set(result) != set(EXPECTED_STACK_RESOURCES):
        raise RuntimeError("CloudFormation stack resource set is not exact")
    return result


def _known_physical_ids(cloudformation, stack_id: str) -> tuple[dict[str, str], list[str]]:
    result = {}
    retain = []
    for item in cloudformation.describe_stack_resources(StackName=stack_id)["StackResources"]:
        logical_id = item.get("LogicalResourceId")
        if (
            logical_id not in EXPECTED_STACK_RESOURCES
            or item.get("ResourceType") != EXPECTED_STACK_RESOURCES[logical_id]
        ):
            raise RuntimeError("fallback encountered a foreign stack resource")
        physical_id = item.get("PhysicalResourceId")
        if isinstance(physical_id, str) and physical_id:
            result[logical_id] = physical_id
        else:
            retain.append(logical_id)
    return result, sorted(retain)


def _owned_fallback_cleanup(
    clients,
    stack_id: str,
    stack_name: str,
    owner_nonce: str,
    physical_ids: dict[str, str],
    retain: list[str],
) -> None:
    api_id = physical_ids.get("HttpApiF5A9A8A7")
    if api_id:
        try:
            api = clients.apigatewayv2.get_api(ApiId=api_id)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
        else:
            if api.get("Tags", {}).get(OWNER_TAG_KEY) != owner_nonce:
                raise RuntimeError("refusing to delete an HTTP API without the owner tag")
            clients.apigatewayv2.delete_api(ApiId=api_id)
    pool_id = physical_ids.get("UserPool6BA7E5F2")
    if pool_id:
        try:
            pool = clients.cognito_idp.describe_user_pool(UserPoolId=pool_id)["UserPool"]
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        else:
            if pool.get("UserPoolTags", {}).get(OWNER_TAG_KEY) != owner_nonce:
                raise RuntimeError("refusing to delete a user pool without the owner tag")
            clients.cognito_idp.delete_user_pool(UserPoolId=pool_id)
    function_name = physical_ids.get("Handler886CB40B")
    if function_name:
        try:
            function = clients.lambda_.get_function(FunctionName=function_name)["Configuration"]
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        else:
            tags = clients.lambda_.list_tags(Resource=function["FunctionArn"])["Tags"]
            if tags.get(OWNER_TAG_KEY) != owner_nonce:
                raise RuntimeError("refusing to delete a Lambda without the owner tag")
            clients.lambda_.delete_function(FunctionName=function_name)
    role_name = physical_ids.get("HandlerServiceRoleFCDC14AE")
    if role_name:
        try:
            role = clients.iam.get_role(RoleName=role_name)["Role"]
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
        else:
            tags = {item["Key"]: item["Value"] for item in role.get("Tags", [])}
            if tags.get(OWNER_TAG_KEY) != owner_nonce:
                raise RuntimeError("refusing to delete an IAM role without the owner tag")
            for policy in clients.iam.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            ):
                clients.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])
            clients.iam.delete_role(RoleName=role_name)
    if not _stack_absent(clients.cloudformation, stack_name):
        parameters = {"StackName": stack_id, "DeletionMode": "FORCE_DELETE_STACK"}
        if retain:
            parameters["RetainResources"] = retain
        clients.cloudformation.delete_stack(**parameters)
        clients.cloudformation.get_waiter("stack_delete_complete").wait(
            StackName=stack_id, WaiterConfig={"Delay": 1, "MaxAttempts": 30}
        )


def _api_inventory(client, *, deadline: float) -> dict[str, str]:
    result = {}
    token = None
    seen = set()
    for _ in range(16):
        _ensure_deadline(deadline)
        parameters = {"MaxResults": "500"}
        if token:
            parameters["NextToken"] = token
        response = client.get_apis(**parameters)
        for item in response.get("Items", []):
            result[item["ApiId"]] = item["Name"]
        token = response.get("NextToken")
        if token is None:
            return result
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError("invalid API Gateway v2 continuation token")
        seen.add(token)
    raise RuntimeError("API Gateway v2 inventory exceeded the page bound")


def _pool_inventory(client, *, deadline: float) -> dict[str, str]:
    result = {}
    token = None
    seen = set()
    for _ in range(16):
        _ensure_deadline(deadline)
        parameters = {"MaxResults": 60}
        if token:
            parameters["NextToken"] = token
        response = client.list_user_pools(**parameters)
        for item in response.get("UserPools", []):
            result[item["Id"]] = item["Name"]
        token = response.get("NextToken")
        if token is None:
            return result
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError("invalid Cognito continuation token")
        seen.add(token)
    raise RuntimeError("Cognito inventory exceeded the page bound")


def _function_inventory(client, *, deadline: float) -> dict[str, str]:
    result = {}
    marker = None
    seen = set()
    for _ in range(16):
        _ensure_deadline(deadline)
        parameters = {"MaxItems": 50}
        if marker:
            parameters["Marker"] = marker
        response = client.list_functions(**parameters)
        for item in response.get("Functions", []):
            result[item["FunctionName"]] = item["FunctionArn"]
        marker = response.get("NextMarker")
        if marker is None:
            return result
        if not isinstance(marker, str) or not marker or marker in seen:
            raise RuntimeError("invalid Lambda continuation marker")
        seen.add(marker)
    raise RuntimeError("Lambda inventory exceeded the page bound")


@pytest.fixture
def deployed_http_api_jwt_lambda(
    pinned_cdk_cli_runtime: CdkRuntime,
    aws_client_factory,
    account_id,
    region_name,
    tmp_path,
):
    owner_nonce = secrets.token_hex(12)
    assert OWNER_PATTERN.fullmatch(owner_nonce)
    deployment = f"d{owner_nonce[:23]}"
    stack_name = f"localstack-http-jwt-{deployment}"
    api_name = f"{stack_name}-api"
    pool_name = f"{stack_name}-pool"
    function_name = f"{stack_name}-handler"
    output_path = tmp_path / "http-api-jwt-outputs.json"
    environment = dict(pinned_cdk_cli_runtime.environment)
    environment.update({"CDK_DEFAULT_ACCOUNT": account_id, "CDK_DEFAULT_REGION": region_name})
    clients = aws_client_factory(config=_rpc_config())
    cloudformation = clients.cloudformation
    apigatewayv2 = clients.apigatewayv2
    cognito_idp = clients.cognito_idp
    lambda_client = clients.lambda_
    baseline_deadline = _deadline()
    if not _stack_absent(cloudformation, stack_name):
        raise RuntimeError("owned stack name collided before deployment")
    baseline_apis = _api_inventory(apigatewayv2, deadline=baseline_deadline)
    baseline_pools = _pool_inventory(cognito_idp, deadline=baseline_deadline)
    baseline_functions = _function_inventory(lambda_client, deadline=baseline_deadline)
    if api_name in baseline_apis.values() or pool_name in baseline_pools.values():
        raise RuntimeError("owned API or pool name collided before deployment")
    if function_name in baseline_functions:
        raise RuntimeError("owned Lambda name collided before deployment")
    stack_id = None
    resource_ids = None
    cleanup_errors = []
    try:
        result = launch_cdk(
            [
                "deploy",
                "EnterpriseHttpApiJwt",
                "--app",
                _python_app_command(),
                "--context",
                f"deployment={deployment}",
                "--context",
                f"owner={owner_nonce}",
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
            timeout_seconds=150,
            max_output_bytes=256 * 1024,
        )
        assert not result.timed_out
        assert not result.stdout_truncated
        assert not result.stderr_truncated
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        outputs = _load_outputs(output_path, stack_name, account_id, region_name)
        stack = _validated_stack(
            cloudformation,
            stack_name,
            owner_nonce,
            account_id,
            region_name,
            require_complete=True,
        )
        stack_id = stack["StackId"]
        resource_ids = _validated_resource_ids(cloudformation, stack_id)
        assert resource_ids["HttpApiF5A9A8A7"] == outputs["ApiId"]
        assert resource_ids["JwtAuthorizer"] == outputs["AuthorizerId"]
        assert resource_ids["Deployment"] == outputs["DeploymentId"]
        assert resource_ids["Stage"] == outputs["StageName"]
        assert resource_ids["Handler886CB40B"] == outputs["FunctionName"]
        assert resource_ids["UserPool6BA7E5F2"] == outputs["UserPoolId"]
        assert resource_ids["UserPoolUserPoolClient40176907"] == outputs["UserPoolClientId"]
        yield HttpApiJwtDeployment(
            api_id=outputs["ApiId"],
            authorizer_id=outputs["AuthorizerId"],
            client_id=outputs["UserPoolClientId"],
            deployment_id=outputs["DeploymentId"],
            function_name=outputs["FunctionName"],
            integration_id=resource_ids["HttpApiGETprivateidLambdaIntegration4DD64095"],
            owner_nonce=owner_nonce,
            permission_id=resource_ids["HttpApiGETprivateidLambdaIntegrationPermission285C863E"],
            pool_id=outputs["UserPoolId"],
            route_id=resource_ids["HttpApiGETprivateid6E716BA9"],
            stack_id=stack_id,
            stack_name=stack_name,
            stage_name=outputs["StageName"],
        )
    finally:
        fallback_ids = {}
        retain = []
        try:
            if not _stack_absent(cloudformation, stack_name):
                if stack_id is None:
                    stack = _validated_stack(
                        cloudformation,
                        stack_name,
                        owner_nonce,
                        account_id,
                        region_name,
                        require_complete=False,
                    )
                    stack_id = stack["StackId"]
                fallback_ids, retain = _known_physical_ids(cloudformation, stack_id)
                cloudformation.delete_stack(StackName=stack_id)
                cloudformation.get_waiter("stack_delete_complete").wait(
                    StackName=stack_id, WaiterConfig={"Delay": 1, "MaxAttempts": 90}
                )
        except Exception as error:
            cleanup_errors.append(error)
        check_deadline = _deadline()
        try:
            current_apis = _api_inventory(apigatewayv2, deadline=check_deadline)
            current_pools = _pool_inventory(cognito_idp, deadline=check_deadline)
            current_functions = _function_inventory(lambda_client, deadline=check_deadline)
            if current_apis != baseline_apis:
                cleanup_errors.append(RuntimeError("HTTP API inventory leaked or changed"))
            if current_pools != baseline_pools:
                cleanup_errors.append(RuntimeError("Cognito pool inventory leaked or changed"))
            if current_functions != baseline_functions:
                cleanup_errors.append(RuntimeError("Lambda inventory leaked or changed"))
            if not _stack_absent(cloudformation, stack_name):
                cleanup_errors.append(RuntimeError("owned CloudFormation stack remains"))
        except Exception as error:
            cleanup_errors.append(error)
        if cleanup_errors and stack_id is not None:
            try:
                _owned_fallback_cleanup(
                    clients, stack_id, stack_name, owner_nonce, fallback_ids, retain
                )
                fallback_deadline = _deadline()
                if _api_inventory(apigatewayv2, deadline=fallback_deadline) != baseline_apis:
                    raise RuntimeError("HTTP API inventory remains after owned fallback")
                if _pool_inventory(cognito_idp, deadline=fallback_deadline) != baseline_pools:
                    raise RuntimeError("Cognito inventory remains after owned fallback")
                if (
                    _function_inventory(lambda_client, deadline=fallback_deadline)
                    != baseline_functions
                ):
                    raise RuntimeError("Lambda inventory remains after owned fallback")
                if not _stack_absent(cloudformation, stack_name):
                    raise RuntimeError("stack remains after owned fallback")
            except Exception as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            summary = "; ".join(f"{type(error).__name__}: {error}" for error in cleanup_errors)
            raise RuntimeError(f"HTTP API JWT cleanup failed: {summary}") from cleanup_errors[0]


@pytest.fixture
def authenticated_http_user(cognito_idp_resources):
    cleanups = []

    def factory(pool_id: str):
        username = f"web-{short_uid()}@example.test"
        password = "EnterprisePass9!"
        response = cognito_idp_resources.client.admin_create_user(
            UserPoolId=pool_id,
            Username=username,
            TemporaryPassword=password,
            UserAttributes=[
                {"Name": "email", "Value": username},
                {"Name": "email_verified", "Value": "true"},
            ],
        )
        cognito_idp_resources.client.admin_set_user_password(
            UserPoolId=pool_id,
            Username=username,
            Password=password,
            Permanent=True,
        )
        cognito_idp_resources.client.create_group(UserPoolId=pool_id, GroupName="trainer")
        cognito_idp_resources.client.admin_add_user_to_group(
            UserPoolId=pool_id, Username=username, GroupName="trainer"
        )
        cleanups.append((pool_id, username))
        return response, username, password

    yield factory
    for pool_id, username in reversed(cleanups):
        try:
            cognito_idp_resources.client.admin_delete_user(UserPoolId=pool_id, Username=username)
            cognito_idp_resources.client.delete_group(UserPoolId=pool_id, GroupName="trainer")
        except Exception as error:
            LOG.debug("failed to clean HTTP API Cognito user fixture: %s", error)


@markers.aws.only_localstack
def test_cdk_http_api_cognito_jwt_invokes_real_lambda_and_enforces_permission(
    deployed_http_api_jwt_lambda: HttpApiJwtDeployment,
    authenticated_http_user,
    aws_client_factory,
    account_id,
    region_name,
):
    deployment = deployed_http_api_jwt_lambda
    clients = aws_client_factory(config=_rpc_config())
    cognito_idp = clients.cognito_idp
    lambda_client = clients.lambda_
    assert deployment.stage_name == "$default"
    assert ID_PATTERN.fullmatch(deployment.integration_id)
    assert ID_PATTERN.fullmatch(deployment.route_id)
    assert ID_PATTERN.fullmatch(deployment.permission_id)
    url = api_invoke_url(
        deployment.api_id,
        path="private/exercise-1",
        url_type=UrlType.LS_PATH_BASED,
    )
    preflight = requests.options(
        url,
        headers={
            "Access-Control-Request-Headers": "authorization",
            "Access-Control-Request-Method": "GET",
            "Origin": ORIGIN,
        },
        timeout=10,
    )
    assert preflight.status_code == 204
    assert preflight.headers["Access-Control-Allow-Origin"] == ORIGIN
    unauthorized = requests.get(url, headers={"Origin": ORIGIN}, timeout=10)
    assert unauthorized.status_code == 401
    assert unauthorized.headers["Access-Control-Allow-Origin"] == ORIGIN

    _, username, password = authenticated_http_user(deployment.pool_id)
    token = cognito_idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=deployment.client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["IdToken"]
    headers = {"Authorization": f"Bearer {token}", "Origin": ORIGIN}
    authorized = requests.get(url, headers=headers, timeout=30)
    assert authorized.status_code == 200
    assert authorized.headers["Access-Control-Allow-Origin"] == ORIGIN
    assert authorized.headers["x-authenticated"] == "true"
    assert "localstack-session=authenticated" in authorized.headers["set-cookie"]
    assert authorized.json()["groups"] == "[trainer]"
    assert authorized.json()["pathId"] == "exercise-1"
    assert authorized.json()["version"] == "2.0"

    policy = json.loads(lambda_client.get_policy(FunctionName=deployment.function_name)["Policy"])
    permission = next(
        statement
        for statement in policy["Statement"]
        if statement.get("Principal", {}).get("Service") == "apigateway.amazonaws.com"
    )
    lambda_client.remove_permission(
        FunctionName=deployment.function_name, StatementId=permission["Sid"]
    )
    missing = requests.get(url, headers=headers, timeout=10)
    assert missing.status_code == 500
    assert missing.headers["Access-Control-Allow-Origin"] == ORIGIN

    partition = get_partition(region_name)
    wrong_sid = f"wrong-{short_uid()}"
    lambda_client.add_permission(
        Action="lambda:InvokeFunction",
        FunctionName=deployment.function_name,
        Principal="apigateway.amazonaws.com",
        SourceArn=(
            f"arn:{partition}:execute-api:{region_name}:{account_id}:wrong-api/*/GET/private/*"
        ),
        StatementId=wrong_sid,
    )
    wrong = requests.get(url, headers=headers, timeout=10)
    assert wrong.status_code == 500
    lambda_client.remove_permission(FunctionName=deployment.function_name, StatementId=wrong_sid)

    lambda_client.add_permission(
        Action="lambda:InvokeFunction",
        FunctionName=deployment.function_name,
        Principal="apigateway.amazonaws.com",
        SourceArn=(
            f"arn:{partition}:execute-api:{region_name}:{account_id}:"
            f"{deployment.api_id}/$default/GET/private/{{id}}"
        ),
        StatementId=f"exact-{short_uid()}",
    )
    exact = requests.get(url, headers=headers, timeout=30)
    assert exact.status_code == 200
    assert exact.json()["pathId"] == "exercise-1"
