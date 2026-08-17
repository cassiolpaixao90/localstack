import json
import os
import re
import secrets
import subprocess
import time
from dataclasses import dataclass

import boto3
import pytest
import requests
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers

OWNER_TAG_KEY = "localstack:diagnostic-owner"
OWNER_PATTERN = re.compile(r"^[a-f0-9]{24}$")
CONTAINER_PATTERN = re.compile(r"^ls-persistence-gate-[a-z0-9-]{1,80}$")
ENDPOINT_PATTERN = re.compile(r"^http://(?:localhost|127\.0\.0\.1):\d{2,5}$")
RPC_CONFIG = Config(connect_timeout=2, read_timeout=2, retries={"total_max_attempts": 1})


def _gate_configuration() -> tuple[str, str]:
    endpoint = os.environ.get("PERSISTENCE_GATE_ENDPOINT", "")
    container = os.environ.get("PERSISTENCE_GATE_CONTAINER", "")
    if not ENDPOINT_PATTERN.fullmatch(endpoint) or not CONTAINER_PATTERN.fullmatch(container):
        pytest.skip("explicit persistence gate endpoint and owned container are required")
    return endpoint, container


def _clients(endpoint: str, region_name: str):
    session = boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name=region_name,
    )
    return {
        name: session.client(name, endpoint_url=endpoint, config=RPC_CONFIG)
        for name in (
            "apigatewayv2",
            "cognito-idp",
            "cognito-identity",
            "cognito-sync",
            "iam",
        )
    }


def _docker(*arguments: str) -> str:
    result = subprocess.run(
        ["docker", *arguments],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0 or len(result.stdout) > 64 * 1024 or len(result.stderr) > 64 * 1024:
        raise RuntimeError(result.stderr.decode(errors="replace")[:4096])
    return result.stdout.decode().strip()


def _wait_healthy(endpoint: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            response = requests.get(f"{endpoint}/_localstack/health", timeout=2)
            if response.status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(0.2)
    raise TimeoutError("persistent LocalStack container did not become healthy")


def _list_all(client, operation: str, result_key: str, token_key: str, **parameters) -> list:
    deadline = time.monotonic() + 10
    token = None
    seen = set()
    result = []
    for _ in range(32):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{operation} exceeded its deadline")
        request = dict(parameters)
        if token:
            request[token_key] = token
        response = getattr(client, operation)(**request)
        result.extend(response.get(result_key, []))
        token = response.get(token_key)
        if token is None:
            return result
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError(f"{operation} returned an invalid continuation token")
        seen.add(token)
    raise RuntimeError(f"{operation} exceeded its page bound")


def _inventories(clients) -> dict[str, set[str]]:
    return {
        "apis": {
            item["ApiId"]
            for item in _list_all(
                clients["apigatewayv2"], "get_apis", "Items", "NextToken", MaxResults="500"
            )
        },
        "identity_pools": {
            item["IdentityPoolId"]
            for item in _list_all(
                clients["cognito-identity"],
                "list_identity_pools",
                "IdentityPools",
                "NextToken",
                MaxResults=60,
            )
        },
        "user_pools": {
            item["Id"]
            for item in _list_all(
                clients["cognito-idp"],
                "list_user_pools",
                "UserPools",
                "NextToken",
                MaxResults=60,
            )
        },
    }


@dataclass
class PersistentTopology:
    account_id: str
    endpoint: str
    container: str
    owner: str
    api_id: str
    authorizer_id: str
    client_id: str
    dataset_name: str
    domain: str
    identity_id: str
    identity_pool_id: str
    identity_provider_name: str
    idp_name: str
    password: str
    pool_id: str
    refresh_token: str
    resource_server_id: str
    region_name: str
    role_arn: str
    role_name: str
    stage_name: str
    sync_next_token: str
    sync_session_token: str
    username: str

    def restart(self) -> None:
        before = _docker("inspect", "--format", "{{.Id}}", self.container)
        _docker("stop", "--time", "15", self.container)
        _docker("start", self.container)
        _wait_healthy(self.endpoint)
        after = _docker("inspect", "--format", "{{.Id}}", self.container)
        assert after == before

    def ensure_role(self, iam) -> None:
        try:
            role = iam.get_role(RoleName=self.role_name)["Role"]
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
            iam.create_role(
                RoleName=self.role_name,
                AssumeRolePolicyDocument=json.dumps(_trust_policy(self.identity_pool_id)),
                Tags=[{"Key": OWNER_TAG_KEY, "Value": self.owner}],
            )
        else:
            tags = {item["Key"]: item["Value"] for item in role.get("Tags", [])}
            if tags.get(OWNER_TAG_KEY) != self.owner:
                raise RuntimeError("refusing to reuse an IAM role without the owner tag")


def _trust_policy(identity_pool_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": identity_pool_id},
                    "ForAnyValue:StringEquals": {
                        "cognito-identity.amazonaws.com:amr": "authenticated"
                    },
                },
            }
        ],
    }


@pytest.fixture
def persistent_topology(account_id, region_name):
    endpoint, container = _gate_configuration()
    owner = secrets.token_hex(12)
    assert OWNER_PATTERN.fullmatch(owner)
    clients = _clients(endpoint, region_name)
    baseline = _inventories(clients)
    if any(baseline.values()):
        raise RuntimeError("persistence gate requires an isolated empty service volume")
    prefix = f"persist-{owner[:20]}"
    username = f"{prefix}@example.test"
    password = "EnterprisePass9!"
    pool = clients["cognito-idp"].create_user_pool(
        PoolName=f"{prefix}-pool",
        UsernameAttributes=["email"],
        UserPoolTags={OWNER_TAG_KEY: owner},
    )["UserPool"]
    pool_id = pool["Id"]
    client = clients["cognito-idp"].create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=f"{prefix}-client",
        ExplicitAuthFlows=["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]
    client_id = client["ClientId"]
    clients["cognito-idp"].admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        UserAttributes=[
            {"Name": "email", "Value": username},
            {"Name": "email_verified", "Value": "true"},
        ],
    )
    clients["cognito-idp"].admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    clients["cognito-idp"].create_group(UserPoolId=pool_id, GroupName="persistent-users")
    clients["cognito-idp"].admin_add_user_to_group(
        UserPoolId=pool_id, Username=username, GroupName="persistent-users"
    )
    domain = prefix
    clients["cognito-idp"].create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    resource_server_id = f"urn:localstack:{owner}"
    clients["cognito-idp"].create_resource_server(
        UserPoolId=pool_id,
        Identifier=resource_server_id,
        Name="Persistence API",
        Scopes=[{"ScopeName": "read", "ScopeDescription": "Read persisted data"}],
    )
    idp_name = "PersistentOIDC"
    clients["cognito-idp"].create_identity_provider(
        UserPoolId=pool_id,
        ProviderName=idp_name,
        ProviderType="OIDC",
        ProviderDetails={
            "attributes_request_method": "GET",
            "authorize_scopes": "openid email",
            "client_id": f"{prefix}-oidc-client",
            "client_secret": f"{prefix}-oidc-secret",
            "oidc_issuer": "https://idp.example.test",
        },
        AttributeMapping={"email": "email"},
        IdpIdentifiers=[prefix],
    )
    auth = clients["cognito-idp"].initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]
    identity_provider_name = f"cognito-idp.{region_name}.amazonaws.com/{pool_id}"
    identity_pool = clients["cognito-identity"].create_identity_pool(
        IdentityPoolName=f"{prefix}-identities",
        AllowUnauthenticatedIdentities=False,
        AllowClassicFlow=True,
        CognitoIdentityProviders=[
            {
                "ProviderName": identity_provider_name,
                "ClientId": client_id,
                "ServerSideTokenCheck": True,
            }
        ],
        IdentityPoolTags={OWNER_TAG_KEY: owner},
    )
    identity_pool_id = identity_pool["IdentityPoolId"]
    login = {identity_provider_name: auth["IdToken"]}
    identity_id = clients["cognito-identity"].get_id(
        AccountId=account_id, IdentityPoolId=identity_pool_id, Logins=login
    )["IdentityId"]
    role_name = f"{prefix}-role"
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    topology = PersistentTopology(
        account_id=account_id,
        endpoint=endpoint,
        container=container,
        owner=owner,
        api_id="",
        authorizer_id="",
        client_id=client_id,
        dataset_name="profile",
        domain=domain,
        identity_id=identity_id,
        identity_pool_id=identity_pool_id,
        identity_provider_name=identity_provider_name,
        idp_name=idp_name,
        password=password,
        pool_id=pool_id,
        refresh_token=auth["RefreshToken"],
        resource_server_id=resource_server_id,
        region_name=region_name,
        role_arn=role_arn,
        role_name=role_name,
        stage_name="persist",
        sync_next_token="",
        sync_session_token="",
        username=username,
    )
    topology.ensure_role(clients["iam"])
    clients["cognito-identity"].set_identity_pool_roles(
        IdentityPoolId=identity_pool_id, Roles={"authenticated": role_arn}
    )
    credentials = clients["cognito-identity"].get_credentials_for_identity(
        IdentityId=identity_id, Logins=login
    )["Credentials"]
    assert credentials["AccessKeyId"]
    initial_sync = clients["cognito-sync"].list_records(
        IdentityPoolId=identity_pool_id, IdentityId=identity_id, DatasetName=topology.dataset_name
    )
    clients["cognito-sync"].update_records(
        IdentityPoolId=identity_pool_id,
        IdentityId=identity_id,
        DatasetName=topology.dataset_name,
        SyncSessionToken=initial_sync["SyncSessionToken"],
        RecordPatches=[
            {"Key": "a", "Op": "replace", "SyncCount": 0, "Value": "one"},
            {"Key": "b", "Op": "replace", "SyncCount": 0, "Value": "two"},
        ],
    )
    sync_page = clients["cognito-sync"].list_records(
        IdentityPoolId=identity_pool_id,
        IdentityId=identity_id,
        DatasetName=topology.dataset_name,
        MaxResults=1,
    )
    topology.sync_next_token = sync_page["NextToken"]
    topology.sync_session_token = sync_page["SyncSessionToken"]
    api = clients["apigatewayv2"].create_api(
        Name=f"{prefix}-api",
        ProtocolType="HTTP",
        Tags={OWNER_TAG_KEY: owner},
    )
    topology.api_id = api["ApiId"]
    authorizer = clients["apigatewayv2"].create_authorizer(
        ApiId=topology.api_id,
        AuthorizerType="JWT",
        IdentitySource=["$request.header.Authorization"],
        JwtConfiguration={
            "Audience": [client_id],
            "Issuer": f"https://cognito-idp.{region_name}.amazonaws.com/{pool_id}",
        },
        Name=f"{prefix}-jwt",
    )
    topology.authorizer_id = authorizer["AuthorizerId"]
    integration = clients["apigatewayv2"].create_integration(
        ApiId=topology.api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationMethod="GET",
        IntegrationUri="http://localhost:4566/_localstack/health",
        PayloadFormatVersion="1.0",
    )
    route = clients["apigatewayv2"].create_route(
        ApiId=topology.api_id,
        RouteKey="GET /persist",
        Target=f"integrations/{integration['IntegrationId']}",
        AuthorizationType="JWT",
        AuthorizerId=topology.authorizer_id,
    )
    deployment = clients["apigatewayv2"].create_deployment(
        ApiId=topology.api_id, Description="persistence restart gate"
    )
    clients["apigatewayv2"].create_stage(
        ApiId=topology.api_id,
        StageName=topology.stage_name,
        DeploymentId=deployment["DeploymentId"],
        AutoDeploy=False,
        Tags={OWNER_TAG_KEY: owner},
    )
    assert route["RouteId"]
    try:
        yield topology
    finally:
        clients = _clients(endpoint, region_name)
        cleanup_errors = []
        for cleanup in (
            lambda: clients["apigatewayv2"].delete_api(ApiId=topology.api_id),
            lambda: clients["cognito-sync"].delete_dataset(
                IdentityPoolId=identity_pool_id,
                IdentityId=identity_id,
                DatasetName=topology.dataset_name,
            ),
            lambda: clients["cognito-identity"].delete_identity_pool(
                IdentityPoolId=identity_pool_id
            ),
            lambda: clients["cognito-idp"].delete_user_pool(UserPoolId=pool_id),
        ):
            try:
                cleanup()
            except Exception as error:
                cleanup_errors.append(error)
        try:
            role = clients["iam"].get_role(RoleName=role_name)["Role"]
            tags = {item["Key"]: item["Value"] for item in role.get("Tags", [])}
            if tags.get(OWNER_TAG_KEY) != owner:
                raise RuntimeError("refusing to delete an IAM role without the owner tag")
            clients["iam"].delete_role(RoleName=role_name)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "NoSuchEntity":
                cleanup_errors.append(error)
        try:
            topology.restart()
            if _inventories(_clients(endpoint, region_name)) != baseline:
                cleanup_errors.append(
                    RuntimeError("persistent service inventory leaked after cleanup")
                )
        except Exception as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            summary = "; ".join(f"{type(error).__name__}: {error}" for error in cleanup_errors)
            raise RuntimeError(f"persistence gate cleanup failed: {summary}") from cleanup_errors[0]


@markers.aws.only_localstack
def test_native_cognito_and_http_api_state_survives_same_container_restart(
    persistent_topology: PersistentTopology,
):
    topology = persistent_topology
    topology.restart()
    clients = _clients(topology.endpoint, topology.region_name)
    pool = clients["cognito-idp"].describe_user_pool(UserPoolId=topology.pool_id)["UserPool"]
    assert pool["UserPoolTags"][OWNER_TAG_KEY] == topology.owner
    client = clients["cognito-idp"].describe_user_pool_client(
        UserPoolId=topology.pool_id, ClientId=topology.client_id
    )["UserPoolClient"]
    assert client["ClientId"] == topology.client_id
    user = clients["cognito-idp"].admin_get_user(
        UserPoolId=topology.pool_id, Username=topology.username
    )
    assert user["UserStatus"] == "CONFIRMED"
    memberships = clients["cognito-idp"].admin_list_groups_for_user(
        UserPoolId=topology.pool_id, Username=topology.username
    )["Groups"]
    assert [item["GroupName"] for item in memberships] == ["persistent-users"]
    assert (
        clients["cognito-idp"].describe_user_pool_domain(Domain=topology.domain)[
            "DomainDescription"
        ]["UserPoolId"]
        == topology.pool_id
    )
    assert (
        clients["cognito-idp"].describe_resource_server(
            UserPoolId=topology.pool_id, Identifier=topology.resource_server_id
        )["ResourceServer"]["Identifier"]
        == topology.resource_server_id
    )
    idp = clients["cognito-idp"].describe_identity_provider(
        UserPoolId=topology.pool_id, ProviderName=topology.idp_name
    )["IdentityProvider"]
    assert idp["ProviderDetails"]["client_secret"].endswith("-oidc-secret")
    refreshed = clients["cognito-idp"].initiate_auth(
        AuthFlow="REFRESH_TOKEN_AUTH",
        ClientId=topology.client_id,
        AuthParameters={"REFRESH_TOKEN": topology.refresh_token},
    )["AuthenticationResult"]
    id_token = refreshed["IdToken"]
    jwks = requests.get(
        f"{topology.endpoint}/{topology.pool_id}/.well-known/jwks.json", timeout=5
    ).json()
    assert len(jwks["keys"]) == 2
    login = {topology.identity_provider_name: id_token}
    identity_id = clients["cognito-identity"].get_id(
        AccountId=topology.account_id,
        IdentityPoolId=topology.identity_pool_id,
        Logins=login,
    )["IdentityId"]
    assert identity_id == topology.identity_id
    roles = clients["cognito-identity"].get_identity_pool_roles(
        IdentityPoolId=topology.identity_pool_id
    )["Roles"]
    assert roles == {"authenticated": topology.role_arn}
    topology.ensure_role(clients["iam"])
    credentials = clients["cognito-identity"].get_credentials_for_identity(
        IdentityId=identity_id, Logins=login
    )["Credentials"]
    assert credentials["AccessKeyId"]
    second_sync_page = clients["cognito-sync"].list_records(
        IdentityPoolId=topology.identity_pool_id,
        IdentityId=identity_id,
        DatasetName=topology.dataset_name,
        MaxResults=1,
        NextToken=topology.sync_next_token,
        SyncSessionToken=topology.sync_session_token,
    )
    assert [item["Key"] for item in second_sync_page["Records"]] == ["b"]
    api = clients["apigatewayv2"].get_api(ApiId=topology.api_id)
    assert api["Tags"][OWNER_TAG_KEY] == topology.owner
    authorizer = clients["apigatewayv2"].get_authorizer(
        ApiId=topology.api_id, AuthorizerId=topology.authorizer_id
    )
    assert authorizer["JwtConfiguration"]["Audience"] == [topology.client_id]
    response = requests.get(
        f"{topology.endpoint}/_aws/execute-api/{topology.api_id}/{topology.stage_name}/persist",
        headers={"Authorization": f"Bearer {id_token}"},
        timeout=10,
    )
    assert response.status_code == 200
    assert response.json()["services"]["cognito-idp"] in {"available", "running"}
