import base64
import hashlib
import json
import os
import re
import secrets
import shlex
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack import config
from localstack.cli.cdk import launch_cdk
from localstack.testing.pytest import markers
from localstack.utils.aws.arns import get_partition
from tests.aws.cli.execution_evidence import read_regular_bounded
from tests.aws.cli.test_cdk_cli_bootstrap_upgrade import CdkRuntime

pytest_plugins = ("tests.aws.cli.test_cdk_cli_bootstrap_upgrade",)

PROJECT_ROOT = Path(__file__).parents[3]
APP_PATH = PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/enterprise_cognito.py"
MAX_OUTPUT_BYTES = 64 * 1024
MAX_OUTPUT_VALUE_BYTES = 256
EXPECTED_OUTPUT_KEYS = {
    "AuthenticatedRoleArn",
    "DeploymentAccount",
    "DeploymentRegion",
    "IdentityPoolId",
    "IdentityPoolPrincipalTagId",
    "IdentityProviderName",
    "UserPoolArn",
    "UserPoolClientId",
    "UserPoolId",
}
EXPECTED_AUTH_FLOWS = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
]
EXPECTED_OAUTH_SCOPES = [
    "profile",
    "phone",
    "email",
    "openid",
    "aws.cognito.signin.user.admin",
]
POOL_ID_PATTERN = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]_[A-Za-z0-9]{1,64}$")
CLIENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_+]{1,128}$")
MAX_LIST_PAGES = 128
LIST_DEADLINE_SECONDS = 10.0
RPC_TIMEOUT_SECONDS = 2
CLEANUP_DEADLINE_SECONDS = 75.0
OWNER_TAG_KEY = "localstack:diagnostic-owner"
OWNER_NONCE_PATTERN = re.compile(r"^[a-f0-9]{24}$")
EXPECTED_STACK_RESOURCES = {
    "AdminGroup": "AWS::Cognito::UserPoolGroup",
    "AdminMembership": "AWS::Cognito::UserPoolUserToGroupAttachment",
    "AdminUser": "AWS::Cognito::UserPoolUser",
    "MemberGroup": "AWS::Cognito::UserPoolGroup",
    "MemberMembership": "AWS::Cognito::UserPoolUserToGroupAttachment",
    "MemberUser": "AWS::Cognito::UserPoolUser",
    "TrainerMembership": "AWS::Cognito::UserPoolUserToGroupAttachment",
    "TrainerGroup": "AWS::Cognito::UserPoolGroup",
    "TrainerUser": "AWS::Cognito::UserPoolUser",
    "UserPool": "AWS::Cognito::UserPool",
    "UserPoolClient": "AWS::Cognito::UserPoolClient",
    "UserPoolDomain": "AWS::Cognito::UserPoolDomain",
    "UserPoolResourceServer": "AWS::Cognito::UserPoolResourceServer",
    "AuthenticatedRole": "AWS::IAM::Role",
    "IdentityPool": "AWS::Cognito::IdentityPool",
    "IdentityPoolPrincipalTag": "AWS::Cognito::IdentityPoolPrincipalTag",
    "IdentityPoolRoleAttachment": "AWS::Cognito::IdentityPoolRoleAttachment",
}
EXPECTED_GROUP_PHYSICAL_IDS = {
    "AdminGroup": "admin",
    "MemberGroup": "member",
    "TrainerGroup": "trainer",
}
EXPECTED_USER_PHYSICAL_IDS = {
    "AdminUser": "admin@example.test",
    "MemberUser": "member@example.test",
    "TrainerUser": "trainer@example.test",
}
ATTACHMENT_ID_PATTERN = re.compile(r"^UserToGroupAttachment-[0-9a-f]{16}$")
DOMAIN_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
RESOURCE_SERVER_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:/-]{1,256}$")
IDENTITY_POOL_ID_PATTERN = re.compile(
    r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
ROLE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_+=,.@-]{1,64}$")
IDENTITY_PROVIDER_PATTERN = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
CALLBACK_URL = "https://app.example.test/auth/callback"
ADMIN_USERNAME = "admin@example.test"
HOSTED_UI_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class CognitoDeployment:
    authenticated_role_arn: str
    identity_pool_id: str
    identity_provider_name: str
    principal_tag_id: str
    stack_id: str
    stack_name: str
    owner_nonce: str
    pool_name: str
    pool_id: str
    pool_arn: str
    client_name: str
    client_id: str
    admin_password: str


def _rpc_client_config() -> Config:
    return Config(
        connect_timeout=RPC_TIMEOUT_SECONDS,
        read_timeout=RPC_TIMEOUT_SECONDS,
        retries={"mode": "standard", "total_max_attempts": 1},
    )


def _new_owner_nonce() -> str:
    return secrets.token_hex(12)


def _deployment_from_owner_nonce(owner_nonce: str) -> str:
    if not OWNER_NONCE_PATTERN.fullmatch(owner_nonce):
        raise ValueError("owner nonce must be a 96-bit lowercase hexadecimal value")
    return f"d{owner_nonce[:23]}"


def _record_stack_id(current_stack_id: str | None, candidate_stack_id: str) -> str:
    if current_stack_id is not None and current_stack_id != candidate_stack_id:
        raise RuntimeError("owned CloudFormation StackId changed during the deployment lifecycle")
    return candidate_stack_id


def _validate_owned_stack(
    stack: dict,
    *,
    stack_name: str,
    owner_nonce: str,
    account_id: str,
    region_name: str,
    require_create_complete: bool,
) -> str:
    if not OWNER_NONCE_PATTERN.fullmatch(owner_nonce):
        raise RuntimeError("diagnostic Cognito owner nonce is not a 96-bit identity")
    stack_id = stack.get("StackId")
    if not isinstance(stack_id, str) or len(stack_id) > 2048:
        raise RuntimeError("CloudFormation returned an invalid StackId")
    arn_parts = stack_id.split(":", 5)
    if (
        len(arn_parts) != 6
        or arn_parts[0] != "arn"
        or arn_parts[1] != get_partition(region_name)
        or arn_parts[2] != "cloudformation"
        or arn_parts[3] != region_name
        or arn_parts[4] != account_id
        or not arn_parts[5].startswith(f"stack/{stack_name}/")
        or len(arn_parts[5]) <= len(f"stack/{stack_name}/")
    ):
        raise RuntimeError("CloudFormation StackId does not match the requested identity")
    if stack.get("StackName") != stack_name:
        raise RuntimeError("CloudFormation stack name does not match the requested identity")
    tags = stack.get("Tags", [])
    owner_tags = [
        tag.get("Value")
        for tag in tags
        if isinstance(tag, dict) and tag.get("Key") == OWNER_TAG_KEY
    ]
    if owner_tags != [owner_nonce]:
        raise RuntimeError("CloudFormation owner tag does not match the deployment nonce")
    if require_create_complete and stack.get("StackStatus") != "CREATE_COMPLETE":
        raise RuntimeError("CloudFormation stack did not reach CREATE_COMPLETE")
    return stack_id


def _validated_stack_resource_ids(
    resources: list[dict],
    *,
    stack_id: str,
    expected_pool_id: str | None = None,
    expected_client_id: str | None = None,
    expected_identity_pool_id: str | None = None,
    expected_principal_tag_id: str | None = None,
    expected_role_arn: str | None = None,
    expected_resource_server_id: str | None = None,
    require_complete: bool = True,
) -> dict[str, str]:
    physical_ids: dict[str, str] = {}
    for resource in resources:
        logical_id = resource.get("LogicalResourceId")
        resource_type = resource.get("ResourceType")
        physical_id = resource.get("PhysicalResourceId")
        if (
            resource.get("StackId") != stack_id
            or logical_id not in EXPECTED_STACK_RESOURCES
            or resource_type != EXPECTED_STACK_RESOURCES.get(logical_id)
            or logical_id in physical_ids
        ):
            raise RuntimeError("CloudFormation stack resource contract is invalid")
        if not isinstance(physical_id, str):
            if not require_complete and physical_id is None:
                continue
            raise RuntimeError("CloudFormation stack resource contract is invalid")
        if logical_id == "UserPool":
            valid_physical_id = POOL_ID_PATTERN.fullmatch(physical_id) is not None
        elif logical_id == "UserPoolClient":
            valid_physical_id = CLIENT_ID_PATTERN.fullmatch(physical_id) is not None
        elif logical_id == "UserPoolDomain":
            valid_physical_id = DOMAIN_ID_PATTERN.fullmatch(physical_id) is not None
        elif logical_id == "UserPoolResourceServer":
            valid_physical_id = RESOURCE_SERVER_ID_PATTERN.fullmatch(physical_id) is not None
        elif logical_id == "IdentityPool":
            valid_physical_id = IDENTITY_POOL_ID_PATTERN.fullmatch(physical_id) is not None
        elif logical_id == "AuthenticatedRole":
            valid_physical_id = ROLE_NAME_PATTERN.fullmatch(physical_id) is not None
        elif logical_id == "IdentityPoolRoleAttachment":
            valid_physical_id = IDENTITY_POOL_ID_PATTERN.fullmatch(physical_id) is not None
            if expected_identity_pool_id is not None:
                valid_physical_id = valid_physical_id and physical_id == expected_identity_pool_id
        elif logical_id == "IdentityPoolPrincipalTag":
            tag_pool_id, separator, provider_name = physical_id.partition("|")
            valid_physical_id = (
                separator == "|"
                and IDENTITY_POOL_ID_PATTERN.fullmatch(tag_pool_id) is not None
                and IDENTITY_PROVIDER_PATTERN.fullmatch(provider_name) is not None
            )
            if expected_principal_tag_id is not None:
                valid_physical_id = valid_physical_id and physical_id == expected_principal_tag_id
        elif logical_id.endswith("Membership"):
            valid_physical_id = ATTACHMENT_ID_PATTERN.fullmatch(physical_id) is not None
        elif logical_id.endswith("User"):
            valid_physical_id = physical_id == EXPECTED_USER_PHYSICAL_IDS.get(logical_id)
        else:
            valid_physical_id = physical_id == EXPECTED_GROUP_PHYSICAL_IDS.get(logical_id)
        if not valid_physical_id:
            raise RuntimeError("CloudFormation stack resource physical ID is invalid")
        physical_ids[logical_id] = physical_id
    expected_logical_ids = set(EXPECTED_STACK_RESOURCES)
    if require_complete and set(physical_ids) != expected_logical_ids:
        raise RuntimeError("CloudFormation stack resource contract is incomplete")
    if expected_pool_id is not None and physical_ids.get("UserPool") != expected_pool_id:
        raise RuntimeError("CloudFormation UserPool physical ID does not match the CDK output")
    if expected_client_id is not None and physical_ids.get("UserPoolClient") != expected_client_id:
        raise RuntimeError(
            "CloudFormation UserPoolClient physical ID does not match the CDK output"
        )
    if (
        expected_identity_pool_id is not None
        and physical_ids.get("IdentityPool") != expected_identity_pool_id
    ):
        raise RuntimeError("CloudFormation IdentityPool physical ID does not match the CDK output")
    if (
        expected_principal_tag_id is not None
        and physical_ids.get("IdentityPoolPrincipalTag") != expected_principal_tag_id
    ):
        raise RuntimeError(
            "CloudFormation IdentityPoolPrincipalTag physical ID does not match the CDK output"
        )
    if expected_role_arn is not None:
        role_name = expected_role_arn.rsplit("/", 1)[-1]
        if physical_ids.get("AuthenticatedRole") != role_name:
            raise RuntimeError(
                "CloudFormation authenticated-role physical ID does not match the CDK output"
            )
    if (
        expected_resource_server_id is not None
        and physical_ids.get("UserPoolResourceServer") != expected_resource_server_id
    ):
        raise RuntimeError(
            "CloudFormation UserPoolResourceServer physical ID does not match the deployment"
        )
    return physical_ids


def _record_post_stack_delete_leaks(
    cleanup_errors: list[Exception],
    *,
    owned_pool_ids: set[str],
    current_pools: dict[str, str],
    stack_delete_completed: bool,
) -> set[str]:
    leaks = owned_pool_ids & set(current_pools)
    if stack_delete_completed and leaks:
        cleanup_errors.append(
            RuntimeError(
                f"CloudFormation delete completed but left owned Cognito pools: {sorted(leaks)!r}"
            )
        )
    return leaks


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
        raise ValueError("CDK stack output does not match the closed Cognito contract")
    if any(
        not isinstance(item, str) or not item or len(item.encode("utf-8")) > MAX_OUTPUT_VALUE_BYTES
        for item in stack_outputs.values()
    ):
        raise ValueError("CDK stack output values must be bounded non-empty strings")
    if stack_outputs["DeploymentAccount"] != account_id:
        raise ValueError("CDK output account does not match the requested account")
    if stack_outputs["DeploymentRegion"] != region_name:
        raise ValueError("CDK output region does not match the requested region")
    if not POOL_ID_PATTERN.fullmatch(stack_outputs["UserPoolId"]):
        raise ValueError("CDK UserPoolId does not match the bounded Cognito identifier contract")
    if not CLIENT_ID_PATTERN.fullmatch(stack_outputs["UserPoolClientId"]):
        raise ValueError(
            "CDK UserPoolClientId does not match the bounded Cognito identifier contract"
        )
    identity_pool_id = stack_outputs["IdentityPoolId"]
    if not IDENTITY_POOL_ID_PATTERN.fullmatch(identity_pool_id) or not identity_pool_id.startswith(
        f"{region_name}:"
    ):
        raise ValueError("CDK IdentityPoolId does not match the bounded regional contract")
    partition = get_partition(region_name)
    dns_suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
    expected_provider = f"cognito-idp.{region_name}.{dns_suffix}/{stack_outputs['UserPoolId']}"
    if stack_outputs["IdentityProviderName"] != expected_provider:
        raise ValueError("CDK identity provider does not match the deployed user pool")
    if stack_outputs["IdentityPoolPrincipalTagId"] != (f"{identity_pool_id}|{expected_provider}"):
        raise ValueError("CDK principal-tag Ref does not match its composite identity")
    role_parts = stack_outputs["AuthenticatedRoleArn"].split(":", 5)
    if (
        len(role_parts) != 6
        or role_parts[:3] != ["arn", partition, "iam"]
        or role_parts[3] != ""
        or role_parts[4] != account_id
        or not role_parts[5].startswith("role/")
        or ROLE_NAME_PATTERN.fullmatch(role_parts[5][len("role/") :]) is None
    ):
        raise ValueError("CDK authenticated-role ARN does not match the deployment identity")
    arn_parts = stack_outputs["UserPoolArn"].split(":", 5)
    if (
        len(arn_parts) != 6
        or arn_parts[0] != "arn"
        or arn_parts[1] != get_partition(region_name)
        or arn_parts[2] != "cognito-idp"
        or arn_parts[3] != region_name
        or arn_parts[4] != account_id
        or arn_parts[5] != f"userpool/{stack_outputs['UserPoolId']}"
    ):
        raise ValueError("CDK user-pool ARN does not match the deployed identity")
    return stack_outputs


def _python_app_command() -> str:
    configured = os.environ.get("CDK_PYTHON_SYNTH_PYTHON")
    python = Path(configured) if configured else Path(sys.executable)
    if not python.is_absolute() or not python.is_file():
        raise ValueError("the CDK Python interpreter must be an absolute file-backed path")
    if not APP_PATH.is_absolute() or not APP_PATH.is_file():
        raise ValueError("the diagnostic Cognito CDK fixture is unavailable")
    return shlex.join((str(python), "-I", "-B", str(APP_PATH)))


def _deploy_arguments(
    *,
    deployment: str,
    owner_nonce: str,
    output_path: Path,
    extra_context: dict[str, str] | None = None,
) -> list[str]:
    arguments = [
        "deploy",
        "EnterpriseCognito",
        "--app",
        _python_app_command(),
        "--context",
        "project=localstack-enterprise",
        "--context",
        "stage=dev",
        "--context",
        f"deployment={deployment}",
    ]
    for name, value in (extra_context or {}).items():
        arguments.extend(("--context", f"{name}={value}"))
    arguments.extend(
        [
            "--tags",
            f"{OWNER_TAG_KEY}={owner_nonce}",
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
        ]
    )
    return arguments


def _launch_deploy(
    pinned_cdk_cli_runtime: CdkRuntime,
    environment: dict[str, str],
    arguments: list[str],
):
    result = launch_cdk(
        arguments,
        executable=pinned_cdk_cli_runtime.executable,
        environment=environment,
        cwd=pinned_cdk_cli_runtime.workspace,
        timeout_seconds=90,
        max_output_bytes=256 * 1024,
    )
    assert not result.timed_out
    assert not result.stdout_truncated
    assert not result.stderr_truncated
    return result


def _describe_stack(cloudformation, stack_name_or_id: str) -> dict | None:
    try:
        response = cloudformation.describe_stacks(StackName=stack_name_or_id)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ValidationError":
            return None
        raise
    stacks = response.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise RuntimeError("CloudFormation returned an invalid stack description")
    return stacks[0]


def _stack_is_absent(cloudformation, stack_name_or_id: str) -> bool:
    stack = _describe_stack(cloudformation, stack_name_or_id)
    return stack is None or stack.get("StackStatus") == "DELETE_COMPLETE"


def _ensure_deadline(deadline: float, *, clock=time.monotonic) -> None:
    if clock() >= deadline:
        raise RuntimeError("diagnostic Cognito AWS RPC deadline exceeded")


def _pool_inventory(
    cognito_idp,
    *,
    max_pages: int = MAX_LIST_PAGES,
    deadline_seconds: float = LIST_DEADLINE_SECONDS,
    deadline: float | None = None,
    clock=time.monotonic,
) -> dict[str, str]:
    if max_pages < 1 or deadline_seconds < 0:
        raise ValueError("pagination bounds must be non-negative")
    pools: dict[str, str] = {}
    next_token = None
    seen_tokens = set()
    deadline = deadline if deadline is not None else clock() + deadline_seconds
    for _ in range(max_pages):
        try:
            _ensure_deadline(deadline, clock=clock)
        except RuntimeError as error:
            raise RuntimeError("Cognito user-pool listing exceeded its deadline") from error
        params = {"MaxResults": 60}
        if next_token is not None:
            params["NextToken"] = next_token
        response = cognito_idp.list_user_pools(**params)
        for pool in response.get("UserPools", []):
            pool_id = pool.get("Id")
            pool_name = pool.get("Name")
            if not isinstance(pool_id, str) or not isinstance(pool_name, str):
                raise RuntimeError("Cognito returned an invalid user-pool inventory item")
            if pool_id in pools:
                raise RuntimeError("Cognito returned a duplicate user-pool identifier")
            pools[pool_id] = pool_name
        next_token = response.get("NextToken")
        if next_token is None:
            return pools
        if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
            raise RuntimeError("Cognito returned an invalid user-pool continuation token")
        seen_tokens.add(next_token)
    raise RuntimeError("Cognito user-pool listing exceeded its maximum page count")


def _assert_no_baseline_collision(
    *, stack_absent: bool, baseline_pools: dict[str, str], pool_name: str
) -> None:
    if not stack_absent:
        raise RuntimeError("diagnostic Cognito stack name collision")
    if any(name == pool_name for name in baseline_pools.values()):
        raise RuntimeError("diagnostic Cognito pool name collision")


def _new_named_pool_ids(
    *, baseline_pools: dict[str, str], current_pools: dict[str, str], pool_name: str
) -> set[str]:
    """Return collision evidence only; these IDs are never treated as owned."""

    baseline_ids = set(baseline_pools)
    return {
        pool_id
        for pool_id, current_name in current_pools.items()
        if pool_id not in baseline_ids and current_name == pool_name
    }


def _delete_pool_clients(
    cognito_idp,
    pool_id: str,
    *,
    max_pages: int = MAX_LIST_PAGES,
    deadline_seconds: float = LIST_DEADLINE_SECONDS,
    deadline: float | None = None,
    clock=time.monotonic,
) -> None:
    if max_pages < 1 or deadline_seconds < 0:
        raise ValueError("pagination bounds must be non-negative")
    client_ids = []
    next_token = None
    seen_tokens = set()
    deadline = deadline if deadline is not None else clock() + deadline_seconds
    for _ in range(max_pages):
        try:
            _ensure_deadline(deadline, clock=clock)
        except RuntimeError as error:
            raise RuntimeError("Cognito client listing exceeded its deadline") from error
        params = {"MaxResults": 60, "UserPoolId": pool_id}
        if next_token is not None:
            params["NextToken"] = next_token
        response = cognito_idp.list_user_pool_clients(**params)
        for client in response.get("UserPoolClients", []):
            client_id = client.get("ClientId")
            if not isinstance(client_id, str) or not CLIENT_ID_PATTERN.fullmatch(client_id):
                raise RuntimeError("Cognito returned an invalid client inventory item")
            client_ids.append(client_id)
        next_token = response.get("NextToken")
        if next_token is None:
            break
        if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
            raise RuntimeError("Cognito returned an invalid client continuation token")
        seen_tokens.add(next_token)
    else:
        raise RuntimeError("Cognito client listing exceeded its maximum page count")
    if len(client_ids) != len(set(client_ids)):
        raise RuntimeError("Cognito returned a duplicate client identifier")
    for client_id in client_ids:
        try:
            _ensure_deadline(deadline, clock=clock)
        except RuntimeError as error:
            raise RuntimeError("Cognito client cleanup exceeded its deadline") from error
        cognito_idp.delete_user_pool_client(ClientId=client_id, UserPoolId=pool_id)


def _wait_for_stack_delete(cloudformation, stack_id: str, *, deadline: float) -> None:
    _ensure_deadline(deadline)
    remaining_seconds = max(1, int(deadline - time.monotonic()))
    worst_case_attempt_seconds = (RPC_TIMEOUT_SECONDS * 2) + 1
    max_attempts = max(1, remaining_seconds // worst_case_attempt_seconds)
    cloudformation.get_waiter("stack_delete_complete").wait(
        StackName=stack_id,
        WaiterConfig={"Delay": 1, "MaxAttempts": min(60, max_attempts)},
    )
    _ensure_deadline(deadline)


def _hosted_ui_url(domain: str) -> str:
    endpoint = urlsplit(config.internal_service_url())
    if endpoint.scheme not in {"http", "https"} or endpoint.port is None:
        raise RuntimeError("LocalStack internal service URL cannot host the Cognito UI")
    return f"{endpoint.scheme}://{domain}.localhost.localstack.cloud:{endpoint.port}"


def _hosted_ui_id_token(*, domain: str, client_id: str, username: str, password: str) -> str:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    state = secrets.token_urlsafe(24)
    base_url = _hosted_ui_url(domain)
    with requests.Session() as session:
        authorize = session.get(
            f"{base_url}/oauth2/authorize",
            params={
                "client_id": client_id,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "redirect_uri": CALLBACK_URL,
                "response_type": "code",
                "scope": "openid",
                "state": state,
            },
            allow_redirects=False,
            timeout=HOSTED_UI_TIMEOUT_SECONDS,
        )
        assert authorize.status_code == 302
        assert urlsplit(authorize.headers["Location"]).path == "/login"
        assert session.cookies.get("cognito_oauth_transaction")
        login_form = session.get(
            f"{base_url}/login",
            allow_redirects=False,
            timeout=HOSTED_UI_TIMEOUT_SECONDS,
        )
        assert login_form.status_code == 200
        csrf = re.search(rb'name="csrf_token" value="([A-Za-z0-9_-]+)"', login_form.content)
        assert csrf is not None
        authenticated = session.post(
            f"{base_url}/login",
            data={
                "csrf_token": csrf.group(1).decode(),
                "password": password,
                "username": username,
            },
            allow_redirects=False,
            timeout=HOSTED_UI_TIMEOUT_SECONDS,
        )
        assert authenticated.status_code == 302
        assert session.cookies.get("cognito_oauth_session")
        callback = authenticated.headers["Location"]
        callback_parts = urlsplit(callback)
        callback_parameters = parse_qs(callback_parts.query)
        assert (
            f"{callback_parts.scheme}://{callback_parts.netloc}{callback_parts.path}"
            == CALLBACK_URL
        )
        assert callback_parameters.get("state") == [state]
        assert set(callback_parameters) == {"code", "state"}
        code = callback_parameters["code"]
        assert len(code) == 1 and code[0]
        token_response = session.post(
            f"{base_url}/oauth2/token",
            data={
                "client_id": client_id,
                "code": code[0],
                "code_verifier": verifier,
                "grant_type": "authorization_code",
                "redirect_uri": CALLBACK_URL,
            },
            allow_redirects=False,
            timeout=HOSTED_UI_TIMEOUT_SECONDS,
        )
        assert token_response.status_code == 200
        token_payload = token_response.json()
        assert isinstance(token_payload, dict)
        id_token = token_payload.get("id_token")
        assert isinstance(id_token, str) and id_token.count(".") == 2
        return id_token


def _identity_pool_is_absent(cognito_identity, identity_pool_id: str) -> bool:
    try:
        cognito_identity.describe_identity_pool(IdentityPoolId=identity_pool_id)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise
    return False


def _role_is_absent(iam, role_name: str) -> bool:
    try:
        iam.get_role(RoleName=role_name)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return True
        raise
    return False


@pytest.fixture
def deployed_enterprise_cognito(
    pinned_cdk_cli_runtime: CdkRuntime,
    aws_client_factory,
    account_id,
    region_name,
    tmp_path,
):
    owner_nonce = _new_owner_nonce()
    deployment = _deployment_from_owner_nonce(owner_nonce)
    prefix = f"localstack-enterprise-dev-{deployment}"
    stack_name = f"{prefix}-auth"
    pool_name = stack_name
    client_name = f"{prefix}-web"
    output_path = tmp_path / "cognito-outputs.json"
    environment = dict(pinned_cdk_cli_runtime.environment)
    environment.update(
        {
            "CDK_DEFAULT_ACCOUNT": account_id,
            "CDK_DEFAULT_REGION": region_name,
        }
    )
    bounded_clients = aws_client_factory(config=_rpc_client_config())
    cloudformation = bounded_clients.cloudformation
    cognito_identity = bounded_clients.cognito_identity
    cognito_idp = bounded_clients.cognito_idp
    iam = bounded_clients.iam
    setup_deadline = time.monotonic() + LIST_DEADLINE_SECONDS
    _ensure_deadline(setup_deadline)
    stack_was_absent = _stack_is_absent(cloudformation, stack_name)
    baseline_pools = _pool_inventory(cognito_idp, deadline=setup_deadline)
    _assert_no_baseline_collision(
        stack_absent=stack_was_absent,
        baseline_pools=baseline_pools,
        pool_name=pool_name,
    )
    cleanup_errors: list[Exception] = []
    deploy_attempted = False
    stack_id: str | None = None
    validated_output_pool_id: str | None = None
    owned_pool_ids: set[str] = set()
    owned_identity_pool_ids: set[str] = set()
    owned_role_names: set[str] = set()
    try:
        deploy_attempted = True
        result = _launch_deploy(
            pinned_cdk_cli_runtime,
            environment,
            _deploy_arguments(
                deployment=deployment,
                owner_nonce=owner_nonce,
                output_path=output_path,
            ),
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        outputs = _load_outputs(
            output_path,
            stack_name=stack_name,
            account_id=account_id,
            region_name=region_name,
        )
        validated_output_pool_id = outputs["UserPoolId"]
        if validated_output_pool_id in baseline_pools:
            raise RuntimeError("deployed Cognito pool ID existed in the baseline")
        owned_pool_ids.add(validated_output_pool_id)
        owned_identity_pool_ids.add(outputs["IdentityPoolId"])
        owned_role_names.add(outputs["AuthenticatedRoleArn"].rsplit("/", 1)[-1])
        validation_deadline = time.monotonic() + LIST_DEADLINE_SECONDS
        _ensure_deadline(validation_deadline)
        stack = _describe_stack(cloudformation, stack_name)
        if stack is None:
            raise RuntimeError("deployed CloudFormation stack is missing")
        stack_id = _record_stack_id(
            stack_id,
            _validate_owned_stack(
                stack,
                stack_name=stack_name,
                owner_nonce=owner_nonce,
                account_id=account_id,
                region_name=region_name,
                require_create_complete=True,
            ),
        )
        _ensure_deadline(validation_deadline)
        resources = cloudformation.describe_stack_resources(StackName=stack_id).get(
            "StackResources", []
        )
        resource_ids = _validated_stack_resource_ids(
            resources,
            stack_id=stack_id,
            expected_pool_id=outputs["UserPoolId"],
            expected_client_id=outputs["UserPoolClientId"],
            expected_identity_pool_id=outputs["IdentityPoolId"],
            expected_principal_tag_id=outputs["IdentityPoolPrincipalTagId"],
            expected_role_arn=outputs["AuthenticatedRoleArn"],
            expected_resource_server_id=f"{prefix}-api",
        )
        owned_pool_ids.add(resource_ids["UserPool"])
        owned_identity_pool_ids.add(resource_ids["IdentityPool"])
        owned_role_names.add(resource_ids["AuthenticatedRole"])
        current_pools = _pool_inventory(cognito_idp, deadline=validation_deadline)
        if current_pools.get(outputs["UserPoolId"]) != pool_name:
            raise RuntimeError("deployed Cognito pool is not owned by this fixture")
        _ensure_deadline(validation_deadline)
        admin_password = f"Aa1!{secrets.token_urlsafe(24)}"
        cognito_idp.admin_set_user_password(
            UserPoolId=outputs["UserPoolId"],
            Username=ADMIN_USERNAME,
            Password=admin_password,
            Permanent=True,
        )
        yield CognitoDeployment(
            authenticated_role_arn=outputs["AuthenticatedRoleArn"],
            identity_pool_id=outputs["IdentityPoolId"],
            identity_provider_name=outputs["IdentityProviderName"],
            principal_tag_id=outputs["IdentityPoolPrincipalTagId"],
            stack_id=stack_id,
            stack_name=stack_name,
            owner_nonce=owner_nonce,
            pool_name=pool_name,
            pool_id=outputs["UserPoolId"],
            pool_arn=outputs["UserPoolArn"],
            client_name=client_name,
            client_id=outputs["UserPoolClientId"],
            admin_password=admin_password,
        )
    finally:
        cleanup_deadline = time.monotonic() + CLEANUP_DEADLINE_SECONDS
        stack_delete_completed = False
        if deploy_attempted and validated_output_pool_id is None and output_path.exists():
            try:
                cleanup_outputs = _load_outputs(
                    output_path,
                    stack_name=stack_name,
                    account_id=account_id,
                    region_name=region_name,
                )
                validated_output_pool_id = cleanup_outputs["UserPoolId"]
                if validated_output_pool_id in baseline_pools:
                    raise RuntimeError("cleanup output pool ID existed in the baseline")
                owned_pool_ids.add(validated_output_pool_id)
                owned_identity_pool_ids.add(cleanup_outputs["IdentityPoolId"])
                owned_role_names.add(cleanup_outputs["AuthenticatedRoleArn"].rsplit("/", 1)[-1])
            except Exception as error:
                cleanup_errors.append(error)
        try:
            _ensure_deadline(cleanup_deadline)
            lookup_identity = stack_id or stack_name
            current_stack = (
                _describe_stack(cloudformation, lookup_identity) if deploy_attempted else None
            )
            if current_stack is not None:
                stack_id = _record_stack_id(
                    stack_id,
                    _validate_owned_stack(
                        current_stack,
                        stack_name=stack_name,
                        owner_nonce=owner_nonce,
                        account_id=account_id,
                        region_name=region_name,
                        require_create_complete=False,
                    ),
                )
                _ensure_deadline(cleanup_deadline)
                resources = cloudformation.describe_stack_resources(StackName=stack_id).get(
                    "StackResources", []
                )
                resource_ids = _validated_stack_resource_ids(
                    resources,
                    stack_id=stack_id,
                    require_complete=False,
                )
                if pool_id := resource_ids.get("UserPool"):
                    owned_pool_ids.add(pool_id)
                if identity_pool_id := resource_ids.get("IdentityPool"):
                    owned_identity_pool_ids.add(identity_pool_id)
                if role_name := resource_ids.get("AuthenticatedRole"):
                    owned_role_names.add(role_name)
                cloudformation.delete_stack(StackName=stack_id)
                _wait_for_stack_delete(
                    cloudformation,
                    stack_id,
                    deadline=cleanup_deadline,
                )
                stack_delete_completed = True
            elif stack_id is not None:
                stack_delete_completed = True
        except Exception as error:
            cleanup_errors.append(error)

        current_pools: dict[str, str] = {}
        try:
            current_pools = _pool_inventory(cognito_idp, deadline=cleanup_deadline)
            _record_post_stack_delete_leaks(
                cleanup_errors,
                owned_pool_ids=owned_pool_ids,
                current_pools=current_pools,
                stack_delete_completed=stack_delete_completed,
            )
        except Exception as error:
            cleanup_errors.append(error)

        try:
            for pool_id in sorted(owned_pool_ids & set(current_pools)):
                _delete_pool_clients(cognito_idp, pool_id, deadline=cleanup_deadline)
                _ensure_deadline(cleanup_deadline)
                cognito_idp.delete_user_pool(UserPoolId=pool_id)
        except Exception as error:
            cleanup_errors.append(error)
        try:
            for identity_pool_id in sorted(owned_identity_pool_ids):
                _ensure_deadline(cleanup_deadline)
                if not _identity_pool_is_absent(cognito_identity, identity_pool_id):
                    if stack_delete_completed:
                        cleanup_errors.append(
                            RuntimeError(
                                "CloudFormation delete completed but left owned Cognito "
                                f"identity pool: {identity_pool_id}"
                            )
                        )
                    cognito_identity.delete_identity_pool(IdentityPoolId=identity_pool_id)
        except Exception as error:
            cleanup_errors.append(error)
        try:
            for role_name in sorted(owned_role_names):
                _ensure_deadline(cleanup_deadline)
                if not _role_is_absent(iam, role_name):
                    if stack_delete_completed:
                        cleanup_errors.append(
                            RuntimeError(
                                "CloudFormation delete completed but left owned IAM role: "
                                f"{role_name}"
                            )
                        )
                    iam.delete_role(RoleName=role_name)
        except Exception as error:
            cleanup_errors.append(error)
        try:
            _ensure_deadline(cleanup_deadline)
            stack_target = stack_id or stack_name
            if deploy_attempted and not _stack_is_absent(cloudformation, stack_target):
                raise RuntimeError(f"CloudFormation stack {stack_target} remains after cleanup")
        except Exception as error:
            cleanup_errors.append(error)
        try:
            final_pools = _pool_inventory(cognito_idp, deadline=cleanup_deadline)
            residual_owned_ids = owned_pool_ids & set(final_pools)
            unexpected_new_ids = (
                _new_named_pool_ids(
                    baseline_pools=baseline_pools,
                    current_pools=final_pools,
                    pool_name=pool_name,
                )
                - owned_pool_ids
            )
            if residual_owned_ids or unexpected_new_ids:
                raise RuntimeError(
                    "Cognito ownership cleanup is incomplete: "
                    f"owned={sorted(residual_owned_ids)!r}, "
                    f"unexpected={sorted(unexpected_new_ids)!r}"
                )
        except Exception as error:
            cleanup_errors.append(error)
        try:
            for identity_pool_id in sorted(owned_identity_pool_ids):
                _ensure_deadline(cleanup_deadline)
                if not _identity_pool_is_absent(cognito_identity, identity_pool_id):
                    raise RuntimeError(
                        f"owned Cognito identity pool remains after cleanup: {identity_pool_id}"
                    )
            for role_name in sorted(owned_role_names):
                _ensure_deadline(cleanup_deadline)
                if not _role_is_absent(iam, role_name):
                    raise RuntimeError(f"owned IAM role remains after cleanup: {role_name}")
        except Exception as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            summary = "; ".join(f"{type(error).__name__}: {error}" for error in cleanup_errors)
            raise RuntimeError(f"diagnostic Cognito cleanup failed: {summary}") from cleanup_errors[
                0
            ]


@markers.aws.only_localstack
def test_cdk_cli_deploys_and_cleans_up_diagnostic_cognito(
    deployed_enterprise_cognito: CognitoDeployment,
    aws_client_factory,
    account_id,
    region_name,
):
    deployment = deployed_enterprise_cognito
    bounded_clients = aws_client_factory(config=_rpc_client_config())
    deadline = time.monotonic() + LIST_DEADLINE_SECONDS
    _ensure_deadline(deadline)
    pool = bounded_clients.cognito_idp.describe_user_pool(UserPoolId=deployment.pool_id)["UserPool"]
    assert pool["Id"] == deployment.pool_id
    assert pool["Name"] == deployment.pool_name
    assert pool["Arn"] == deployment.pool_arn
    assert pool["AdminCreateUserConfig"] == {"AllowAdminCreateUserOnly": True}
    assert pool["MfaConfiguration"] == "OPTIONAL"
    assert pool["UserPoolTags"] == {
        OWNER_TAG_KEY: deployment.owner_nonce,
        "component": "auth",
        "managed-by": "cdk",
        "project": "localstack-enterprise",
        "stage": "dev",
    }
    expected_password_policy = {
        "MinimumLength": 8,
        "RequireLowercase": True,
        "RequireNumbers": True,
        "RequireSymbols": True,
        "RequireUppercase": True,
    }
    password_policy = pool["Policies"]["PasswordPolicy"]
    assert all(password_policy.get(key) == value for key, value in expected_password_policy.items())
    schema = {attribute["Name"]: attribute for attribute in pool["SchemaAttributes"]}
    assert schema["email"]["Mutable"] is False
    assert schema["email"]["Required"] is True
    assert schema["custom:tenantId"]["AttributeDataType"] == "String"
    assert schema["custom:tenantId"]["Mutable"] is True
    arn_parts = deployment.pool_arn.split(":", 5)
    assert arn_parts[3] == region_name
    assert arn_parts[4] == account_id

    _ensure_deadline(deadline)
    client = bounded_clients.cognito_idp.describe_user_pool_client(
        ClientId=deployment.client_id,
        UserPoolId=deployment.pool_id,
    )["UserPoolClient"]
    assert client["ClientId"] == deployment.client_id
    assert client["ClientName"] == deployment.client_name
    assert client["UserPoolId"] == deployment.pool_id
    assert client["ExplicitAuthFlows"] == EXPECTED_AUTH_FLOWS
    assert client["AccessTokenValidity"] == 60
    assert client["AllowedOAuthFlows"] == ["implicit", "code"]
    assert client["AllowedOAuthFlowsUserPoolClient"] is True
    resource_server_id = (
        f"localstack-enterprise-dev-{_deployment_from_owner_nonce(deployment.owner_nonce)}-api"
    )
    assert client["AllowedOAuthScopes"] == [*EXPECTED_OAUTH_SCOPES, f"{resource_server_id}/read"]
    assert client["CallbackURLs"] == ["https://app.example.test/auth/callback"]
    assert client["IdTokenValidity"] == 60
    assert client["PreventUserExistenceErrors"] == "ENABLED"
    assert client["ReadAttributes"] == [
        "custom:tenantId",
        "email",
        "email_verified",
        "name",
    ]
    assert client["RefreshTokenValidity"] == 43200
    assert client["TokenValidityUnits"] == {
        "AccessToken": "minutes",
        "IdToken": "minutes",
        "RefreshToken": "minutes",
    }
    assert client["WriteAttributes"] == ["email", "name", "preferred_username"]
    assert "ClientSecret" not in client

    _ensure_deadline(deadline)
    resource_server = bounded_clients.cognito_idp.describe_resource_server(
        Identifier=resource_server_id,
        UserPoolId=deployment.pool_id,
    )["ResourceServer"]
    assert resource_server == {
        "Identifier": resource_server_id,
        "Name": "Billgym API",
        "Scopes": [
            {"ScopeDescription": "Read Billgym data", "ScopeName": "read"},
            {"ScopeDescription": "Write Billgym data", "ScopeName": "write"},
        ],
        "UserPoolId": deployment.pool_id,
    }

    _ensure_deadline(deadline)
    domain_name = f"ls-{_deployment_from_owner_nonce(deployment.owner_nonce)}"
    domain = bounded_clients.cognito_idp.describe_user_pool_domain(Domain=domain_name)[
        "DomainDescription"
    ]
    assert domain["Domain"] == domain_name
    assert domain["ManagedLoginVersion"] == 2
    assert domain["Status"] == "ACTIVE"
    assert domain["UserPoolId"] == deployment.pool_id

    _ensure_deadline(deadline)
    identity_pool = bounded_clients.cognito_identity.describe_identity_pool(
        IdentityPoolId=deployment.identity_pool_id
    )
    assert identity_pool["IdentityPoolId"] == deployment.identity_pool_id
    assert identity_pool["IdentityPoolName"] == (
        f"localstack-enterprise-dev-{_deployment_from_owner_nonce(deployment.owner_nonce)}-identity"
    )
    assert identity_pool["AllowUnauthenticatedIdentities"] is False
    assert identity_pool["CognitoIdentityProviders"] == [
        {
            "ClientId": deployment.client_id,
            "ProviderName": deployment.identity_provider_name,
            "ServerSideTokenCheck": True,
        }
    ]

    _ensure_deadline(deadline)
    identity_roles = bounded_clients.cognito_identity.get_identity_pool_roles(
        IdentityPoolId=deployment.identity_pool_id
    )
    assert identity_roles == {
        "IdentityPoolId": deployment.identity_pool_id,
        "RoleMappings": {},
        "Roles": {"authenticated": deployment.authenticated_role_arn},
        "ResponseMetadata": identity_roles["ResponseMetadata"],
    }

    _ensure_deadline(deadline)
    principal_tags = bounded_clients.cognito_identity.get_principal_tag_attribute_map(
        IdentityPoolId=deployment.identity_pool_id,
        IdentityProviderName=deployment.identity_provider_name,
    )
    assert principal_tags["IdentityPoolId"] == deployment.identity_pool_id
    assert principal_tags["IdentityProviderName"] == deployment.identity_provider_name
    assert principal_tags["PrincipalTags"] == {"tenant": "custom:tenantId"}
    assert principal_tags["UseDefaults"] is False
    assert deployment.principal_tag_id == (
        f"{deployment.identity_pool_id}|{deployment.identity_provider_name}"
    )

    role_name = deployment.authenticated_role_arn.rsplit("/", 1)[-1]
    _ensure_deadline(deadline)
    role = bounded_clients.iam.get_role(RoleName=role_name)["Role"]
    assert role["Arn"] == deployment.authenticated_role_arn
    assert role["AssumeRolePolicyDocument"] == {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "ForAnyValue:StringEquals": {
                        "cognito-identity.amazonaws.com:amr": "authenticated"
                    },
                    "StringEquals": {
                        "cognito-identity.amazonaws.com:aud": deployment.identity_pool_id
                    },
                },
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            }
        ],
    }

    for group_name, precedence in (("admin", 0), ("trainer", 1), ("member", 10)):
        _ensure_deadline(deadline)
        group = bounded_clients.cognito_idp.get_group(
            GroupName=group_name, UserPoolId=deployment.pool_id
        )["Group"]
        assert group["GroupName"] == group_name
        assert group["Precedence"] == precedence

        username = f"{group_name}@example.test"
        _ensure_deadline(deadline)
        user = bounded_clients.cognito_idp.admin_get_user(
            UserPoolId=deployment.pool_id,
            Username=username,
        )
        assert user["Username"] == username
        user_attributes = {
            attribute["Name"]: attribute["Value"] for attribute in user["UserAttributes"]
        }
        assert (
            user_attributes.items()
            >= {
                "email": username,
                "custom:tenantId": "diagnostic",
            }.items()
        )

        _ensure_deadline(deadline)
        memberships = bounded_clients.cognito_idp.admin_list_groups_for_user(
            UserPoolId=deployment.pool_id,
            Username=username,
        )
        assert [membership["GroupName"] for membership in memberships["Groups"]] == [group_name]

    identity_deadline = time.monotonic() + LIST_DEADLINE_SECONDS
    id_token = _hosted_ui_id_token(
        domain=domain_name,
        client_id=deployment.client_id,
        username=ADMIN_USERNAME,
        password=deployment.admin_password,
    )
    _ensure_deadline(identity_deadline)
    login = {deployment.identity_provider_name: id_token}
    identity_id = bounded_clients.cognito_identity.get_id(
        AccountId=account_id,
        IdentityPoolId=deployment.identity_pool_id,
        Logins=login,
    )["IdentityId"]
    assert IDENTITY_POOL_ID_PATTERN.fullmatch(identity_id)
    assert identity_id.startswith(f"{region_name}:")
    _ensure_deadline(identity_deadline)
    credential_response = bounded_clients.cognito_identity.get_credentials_for_identity(
        IdentityId=identity_id,
        Logins=login,
    )
    assert credential_response["IdentityId"] == identity_id
    credentials = credential_response["Credentials"]
    assert credentials["AccessKeyId"]
    assert credentials["SecretKey"]
    assert credentials["SessionToken"]
    assert credentials["Expiration"].timestamp() > time.time()
    _ensure_deadline(identity_deadline)
    assumed_role_clients = aws_client_factory(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretKey"],
        aws_session_token=credentials["SessionToken"],
        config=_rpc_client_config(),
    )
    caller = assumed_role_clients.sts.get_caller_identity()
    session_name = identity_id.replace(":", "-")
    assert caller["Account"] == account_id
    assert caller["Arn"] == (
        f"arn:{get_partition(region_name)}:sts::{account_id}:"
        f"assumed-role/{role_name}/{session_name}"
    )
    assert caller["UserId"].endswith(f":{session_name}")


@markers.aws.only_localstack
def test_cdk_cli_cognito_update_noop_rollback_lifecycle(
    deployed_enterprise_cognito: CognitoDeployment,
    pinned_cdk_cli_runtime: CdkRuntime,
    aws_client_factory,
    account_id,
    region_name,
    tmp_path,
):
    """Drive update, no-op, rollback, and recovery through the real CDK CLI.

    The fixture covers deploy and the destroy leg: its teardown deletes the
    stack and fails on any residual owned pool, identity pool, or IAM role.

    Rollback note: the v2 CloudFormation engine fails closed on a rejected
    update and parks the stack in UPDATE_ROLLBACK_FAILED instead of AWS's
    UPDATE_ROLLBACK_COMPLETE (cross-resource compensation is not implemented
    in the engine yet); the Cognito UserPool resource provider restores the
    last-good pool configuration itself. This test pins the fail-closed
    status, verifies the previous working state at the resource level, and
    then proves the stack recovers with a follow-up good update.
    """
    deployment = deployed_enterprise_cognito
    environment = dict(pinned_cdk_cli_runtime.environment)
    environment.update(
        {
            "CDK_DEFAULT_ACCOUNT": account_id,
            "CDK_DEFAULT_REGION": region_name,
        }
    )
    bounded_clients = aws_client_factory(config=_rpc_client_config())
    cloudformation = bounded_clients.cloudformation
    cognito_idp = bounded_clients.cognito_idp
    owner_deployment = _deployment_from_owner_nonce(deployment.owner_nonce)
    resource_server_id = f"localstack-enterprise-dev-{owner_deployment}-api"
    deadline = time.monotonic() + LIST_DEADLINE_SECONDS

    def _deploy(extra_context: dict[str, str], output_path: Path):
        return _launch_deploy(
            pinned_cdk_cli_runtime,
            environment,
            _deploy_arguments(
                deployment=owner_deployment,
                owner_nonce=deployment.owner_nonce,
                output_path=output_path,
                extra_context=extra_context,
            ),
        )

    def _owned_stack() -> dict:
        _ensure_deadline(deadline)
        stack = _describe_stack(cloudformation, deployment.stack_name)
        if stack is None:
            raise RuntimeError("deployed CloudFormation stack is missing")
        _record_stack_id(
            deployment.stack_id,
            _validate_owned_stack(
                stack,
                stack_name=deployment.stack_name,
                owner_nonce=deployment.owner_nonce,
                account_id=account_id,
                region_name=region_name,
                require_create_complete=False,
            ),
        )
        return stack

    def _physical_ids() -> dict[str, str]:
        _ensure_deadline(deadline)
        resources = cloudformation.describe_stack_resources(StackName=deployment.stack_id).get(
            "StackResources", []
        )
        return _validated_stack_resource_ids(
            resources,
            stack_id=deployment.stack_id,
            expected_pool_id=deployment.pool_id,
            expected_client_id=deployment.client_id,
            expected_identity_pool_id=deployment.identity_pool_id,
            expected_principal_tag_id=deployment.principal_tag_id,
            expected_role_arn=deployment.authenticated_role_arn,
            expected_resource_server_id=resource_server_id,
        )

    def _password_minimum_length() -> int:
        _ensure_deadline(deadline)
        pool = cognito_idp.describe_user_pool(UserPoolId=deployment.pool_id)["UserPool"]
        return pool["Policies"]["PasswordPolicy"]["MinimumLength"]

    baseline_ids = _physical_ids()
    assert _owned_stack()["StackStatus"] == "CREATE_COMPLETE"
    assert _password_minimum_length() == 8

    update_output_path = tmp_path / "cognito-outputs-update.json"
    update = _deploy({"passwordMinimumLength": "10"}, update_output_path)
    assert update.returncode == 0, update.stderr.decode(errors="replace")
    deadline = time.monotonic() + LIST_DEADLINE_SECONDS
    update_outputs = _load_outputs(
        update_output_path,
        stack_name=deployment.stack_name,
        account_id=account_id,
        region_name=region_name,
    )
    assert update_outputs["UserPoolId"] == deployment.pool_id
    assert update_outputs["UserPoolClientId"] == deployment.client_id
    assert update_outputs["IdentityPoolId"] == deployment.identity_pool_id
    assert update_outputs["IdentityPoolPrincipalTagId"] == deployment.principal_tag_id
    assert update_outputs["AuthenticatedRoleArn"] == deployment.authenticated_role_arn
    updated_stack = _owned_stack()
    assert updated_stack["StackStatus"] == "UPDATE_COMPLETE"
    assert _physical_ids() == baseline_ids
    assert _password_minimum_length() == 10

    noop_output_path = tmp_path / "cognito-outputs-noop.json"
    noop = _deploy({"passwordMinimumLength": "10"}, noop_output_path)
    assert noop.returncode == 0, noop.stderr.decode(errors="replace")
    deadline = time.monotonic() + LIST_DEADLINE_SECONDS
    noop_stack = _owned_stack()
    assert noop_stack["StackStatus"] == "UPDATE_COMPLETE"
    assert noop_stack.get("LastUpdatedTime") == updated_stack.get("LastUpdatedTime")
    assert _physical_ids() == baseline_ids
    assert _password_minimum_length() == 10

    rollback_output_path = tmp_path / "cognito-outputs-rollback.json"
    rollback = _deploy({"passwordMinimumLength": "4"}, rollback_output_path)
    assert rollback.returncode != 0
    deadline = time.monotonic() + LIST_DEADLINE_SECONDS
    assert _owned_stack()["StackStatus"] == "UPDATE_ROLLBACK_FAILED"
    assert _physical_ids() == baseline_ids
    assert _password_minimum_length() == 10
    assert not rollback_output_path.exists()
    _ensure_deadline(deadline)
    admin_user = cognito_idp.admin_get_user(
        UserPoolId=deployment.pool_id,
        Username=ADMIN_USERNAME,
    )
    assert admin_user["Username"] == ADMIN_USERNAME

    recovery_output_path = tmp_path / "cognito-outputs-recovery.json"
    recovery = _deploy({"passwordMinimumLength": "12"}, recovery_output_path)
    assert recovery.returncode == 0, recovery.stderr.decode(errors="replace")
    deadline = time.monotonic() + LIST_DEADLINE_SECONDS
    recovery_outputs = _load_outputs(
        recovery_output_path,
        stack_name=deployment.stack_name,
        account_id=account_id,
        region_name=region_name,
    )
    assert recovery_outputs["UserPoolId"] == deployment.pool_id
    assert _owned_stack()["StackStatus"] == "UPDATE_COMPLETE"
    assert _physical_ids() == baseline_ids
    assert _password_minimum_length() == 12
