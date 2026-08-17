"""Amplify v6 protocol gate, not UI or native-device runtime qualification.

This executes Billgym's installed Amplify Auth/API packages. It does not execute
the Amplify Authenticator visual component, an Expo browser, iOS, or Android.
Those surfaces require separate browser/simulator/device evidence.
"""

import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api.lambda_ import Runtime
from localstack.cli.cdk import launch_cdk
from localstack.testing.pytest import markers
from localstack.utils.aws.arns import get_partition
from localstack.utils.strings import short_uid

THIS_FOLDER = Path(__file__).parent
HARNESS = THIS_FOLDER / "amplify_v6_harness.mjs"
LAMBDA_HANDLER = THIS_FOLDER / "functions" / "amplify_gate.py"
EXPECTED_NODE_VERSION = "v22.23.2"
PINNED_NODE_IMAGE = "node@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a"
PINNED_NODE_IMAGE_ID = "sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a"
MAX_HARNESS_OUTPUT_BYTES = 128 * 1024
LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class AmplifyV6Stack:
    api_endpoint: str
    new_password: str
    temporary_password: str
    tenant_id: str
    user_pool_client_id: str
    user_pool_id: str
    username: str


def _docker_environment() -> dict[str, str]:
    return {
        key: os.environ[key]
        for key in ("DOCKER_CONTEXT", "DOCKER_HOST", "HOME", "PATH")
        if key in os.environ
    }


def _pinned_node_runner() -> str:
    docker = shutil.which("docker")
    if not docker or not os.path.isabs(docker):
        raise RuntimeError("the Amplify protocol gate requires an absolute Docker executable")
    inspected = launch_cdk(
        ["image", "inspect", "--format", "{{.Id}}", PINNED_NODE_IMAGE],
        executable=docker,
        environment=_docker_environment(),
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    if inspected.returncode or inspected.stdout.decode().strip() != PINNED_NODE_IMAGE_ID:
        raise RuntimeError("the content-addressed Node 22.23.2 runner is unavailable")
    return docker


def _run_amplify_harness(stack: AmplifyV6Stack, region_name: str) -> dict:
    checkout = Path(
        os.environ.get("BILLGYM_CHECKOUT", "/Users/cassiopaixao/GolandProjects/billgym")
    ).resolve()
    if not (checkout / "apps" / "mobile" / "package.json").is_file():
        pytest.skip("Billgym mobile checkout with installed Amplify v6 is unavailable")
    endpoint = os.environ.get("AWS_ENDPOINT_URL", "http://localhost.localstack.cloud:4566")
    request = {
        "apiEndpoint": stack.api_endpoint,
        "billgymCheckout": str(checkout),
        "localstackEndpoint": endpoint,
        "newPassword": stack.new_password,
        "region": region_name,
        "temporaryPassword": stack.temporary_password,
        "tenantId": stack.tenant_id,
        "userPoolClientId": stack.user_pool_client_id,
        "userPoolId": stack.user_pool_id,
        "username": stack.username,
    }
    with tempfile.TemporaryFile() as stdin:
        stdin.write(json.dumps(request).encode())
        stdin.seek(0)
        project_root = THIS_FOLDER.parents[3].resolve()
        result = launch_cdk(
            [
                "run",
                "--rm",
                "--pull=never",
                "--network=host",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=64",
                "--memory=512m",
                "--tmpfs=/tmp:rw,noexec,nosuid,size=16m",
                f"--mount=type=bind,src={project_root},dst={project_root},readonly",
                f"--mount=type=bind,src={checkout},dst={checkout},readonly",
                f"--workdir={project_root}",
                "-i",
                PINNED_NODE_IMAGE,
                "node",
                str(HARNESS),
            ],
            executable=_pinned_node_runner(),
            environment=_docker_environment(),
            cwd=project_root,
            timeout_seconds=60,
            max_output_bytes=MAX_HARNESS_OUTPUT_BYTES,
            stdin=stdin,
        )
    if result.returncode:
        message = result.stderr.decode(errors="replace").strip()
        raise AssertionError(f"Amplify v6 harness failed with exit {result.returncode}: {message}")
    if result.stdout_truncated or result.stderr_truncated:
        raise AssertionError("Amplify v6 harness exceeded its output bound")
    try:
        output = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError("Amplify v6 harness returned invalid JSON") from error
    if not isinstance(output, dict):
        raise AssertionError("Amplify v6 harness returned an invalid result shape")
    return output


def _http_api_exists(client, api_id: str) -> bool:
    token = None
    seen = set()
    for _ in range(20):
        request = {"MaxResults": "100"}
        if token is not None:
            request["NextToken"] = token
        response = client.get_apis(**request)
        if any(item.get("ApiId") == api_id for item in response["Items"]):
            return True
        token = response.get("NextToken")
        if token is None:
            return False
        if token in seen:
            raise AssertionError("HTTP API inventory returned a repeated pagination token")
        seen.add(token)
    raise AssertionError("HTTP API inventory exceeded the bounded pagination contract")


def _local_api_endpoint(api_endpoint: str) -> str:
    edge = urlsplit(os.environ.get("AWS_ENDPOINT_URL", "http://127.0.0.1:4566"))
    api = urlsplit(api_endpoint)
    if edge.hostname not in {"127.0.0.1", "localhost"} or edge.port is None:
        raise AssertionError("Amplify gate requires a loopback LocalStack endpoint with a port")
    host = api.hostname
    if host is None:
        raise AssertionError("HTTP API returned an invalid endpoint")
    return urlunsplit((edge.scheme, f"{host}:{edge.port}", api.path, "", ""))


@pytest.fixture
def amplify_v6_stack(
    aws_client,
    account_id,
    region_name,
    cognito_idp_resources,
    create_lambda_function,
):
    suffix = short_uid()
    username = f"amplify-{suffix}@example.test"
    temporary_password = f"Tmp-{suffix}-A9!"
    new_password = f"Final-{suffix}-B8!"
    tenant_id = f"tenant-{suffix}"
    api_id = None

    pool = cognito_idp_resources.create_user_pool(
        PoolName=f"billgym-amplify-{suffix}",
        UsernameAttributes=["email"],
        AutoVerifiedAttributes=["email"],
        AdminCreateUserConfig={"AllowAdminCreateUserOnly": True},
        MfaConfiguration="OPTIONAL",
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "RequireUppercase": True,
                "TemporaryPasswordValidityDays": 7,
            }
        },
        Schema=[
            {
                "AttributeDataType": "String",
                "Mutable": False,
                "Name": "email",
                "Required": True,
            },
            {
                "AttributeDataType": "String",
                "Mutable": True,
                "Name": "tenantId",
                "Required": False,
                "StringAttributeConstraints": {"MinLength": "1", "MaxLength": "128"},
            },
        ],
    )["UserPool"]
    pool_id = pool["Id"]
    client = cognito_idp_resources.create_user_pool_client(
        pool_id,
        ClientName=f"billgym-mobile-{suffix}",
        AccessTokenValidity=1,
        IdTokenValidity=1,
        RefreshTokenValidity=30,
        TokenValidityUnits={
            "AccessToken": "hours",
            "IdToken": "hours",
            "RefreshToken": "days",
        },
        EnableTokenRevocation=True,
        ExplicitAuthFlows=["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
        PreventUserExistenceErrors="ENABLED",
        ReadAttributes=["custom:tenantId", "email", "email_verified", "name"],
        WriteAttributes=["email", "name", "preferred_username"],
    )["UserPoolClient"]
    client_id = client["ClientId"]
    aws_client.cognito_idp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )
    for group in ("admin", "trainer", "member"):
        aws_client.cognito_idp.create_group(UserPoolId=pool_id, GroupName=group)
    aws_client.cognito_idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=temporary_password,
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "email", "Value": username},
            {"Name": "email_verified", "Value": "true"},
            {"Name": "custom:tenantId", "Value": tenant_id},
        ],
    )
    aws_client.cognito_idp.admin_add_user_to_group(
        UserPoolId=pool_id, Username=username, GroupName="trainer"
    )

    function_name = f"billgym-amplify-gate-{suffix}"
    function = create_lambda_function(
        func_name=function_name,
        handler_file=str(LAMBDA_HANDLER),
        runtime=Runtime.python3_13,
    )
    function_arn = function["CreateFunctionResponse"]["FunctionArn"]

    try:
        api = aws_client.apigatewayv2.create_api(
            Name=f"billgym-amplify-{suffix}",
            ProtocolType="HTTP",
            CorsConfiguration={
                "AllowHeaders": ["authorization", "content-type"],
                "AllowMethods": ["GET", "OPTIONS"],
                "AllowOrigins": ["*"],
            },
        )
        api_id = api["ApiId"]
        integration = aws_client.apigatewayv2.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=function_arn,
            PayloadFormatVersion="2.0",
            TimeoutInMillis=5000,
        )
        authorizer = aws_client.apigatewayv2.create_authorizer(
            ApiId=api_id,
            AuthorizerType="JWT",
            IdentitySource=["$request.header.Authorization"],
            JwtConfiguration={
                "Audience": [client_id],
                "Issuer": f"https://cognito-idp.{region_name}.amazonaws.com/{pool_id}",
            },
            Name=f"billgym-cognito-{suffix}",
        )
        for path in ("/v1/profile", "/v1/workout-plans", "/v1/workout-sessions"):
            aws_client.apigatewayv2.create_route(
                ApiId=api_id,
                RouteKey=f"GET {path}",
                Target=f"integrations/{integration['IntegrationId']}",
                AuthorizationType="JWT",
                AuthorizerId=authorizer["AuthorizerId"],
            )
        deployment = aws_client.apigatewayv2.create_deployment(ApiId=api_id)
        aws_client.apigatewayv2.create_stage(
            ApiId=api_id,
            StageName="prod",
            AutoDeploy=False,
            DeploymentId=deployment["DeploymentId"],
        )
        partition = get_partition(region_name)
        aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId=f"apigw-{suffix}",
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=(
                f"arn:{partition}:execute-api:{region_name}:{account_id}:{api_id}/prod/GET/v1/*"
            ),
        )
        yield AmplifyV6Stack(
            api_endpoint=f"{_local_api_endpoint(api['ApiEndpoint'])}/prod",
            new_password=new_password,
            temporary_password=temporary_password,
            tenant_id=tenant_id,
            user_pool_client_id=client_id,
            user_pool_id=pool_id,
            username=username,
        )
    finally:
        if api_id is not None:
            try:
                aws_client.apigatewayv2.delete_api(ApiId=api_id)
            except ClientError as error:
                LOG.warning("Amplify gate API cleanup failed for %s: %s", api_id, error)
            if _http_api_exists(aws_client.apigatewayv2, api_id):
                pytest.fail(f"Amplify gate leaked HTTP API {api_id}")


@markers.aws.only_localstack
def test_amplify_v6_direct_runtime(amplify_v6_stack, region_name):
    result = _run_amplify_harness(amplify_v6_stack, region_name)

    assert result["nodeVersion"] == EXPECTED_NODE_VERSION
    assert result["amplifyVersion"] == "6.20.0"
    assert result["claims"] == {
        "groups": ["trainer"],
        "tenantId": amplify_v6_stack.tenant_id,
        "tokenUse": "id",
    }
    assert result["api"] == {
        "group": "trainer",
        "path": "/v1/profile",
        "tenantId": amplify_v6_stack.tenant_id,
    }
    cognito = [entry for entry in result["trace"] if entry["kind"] == "cognito"]
    assert cognito
    assert all(entry["rewritten"] is True for entry in cognito)
    assert all(
        entry["originalOrigin"] == f"https://cognito-idp.{region_name}.amazonaws.com"
        for entry in cognito
    )
    assert all(200 <= entry["status"] < 300 for entry in result["trace"])
    targets = {entry["target"] for entry in cognito}
    assert {
        "AWSCognitoIdentityProviderService.AssociateSoftwareToken",
        "AWSCognitoIdentityProviderService.GetTokensFromRefreshToken",
        "AWSCognitoIdentityProviderService.GlobalSignOut",
        "AWSCognitoIdentityProviderService.InitiateAuth",
        "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
        "AWSCognitoIdentityProviderService.RevokeToken",
        "AWSCognitoIdentityProviderService.SetUserMFAPreference",
        "AWSCognitoIdentityProviderService.VerifySoftwareToken",
    } <= targets
    flows = {entry.get("authFlow") for entry in cognito}
    challenges = {entry.get("challengeName") for entry in cognito}
    assert "USER_SRP_AUTH" in flows
    assert {"PASSWORD_VERIFIER", "NEW_PASSWORD_REQUIRED", "SOFTWARE_TOKEN_MFA"} <= challenges
