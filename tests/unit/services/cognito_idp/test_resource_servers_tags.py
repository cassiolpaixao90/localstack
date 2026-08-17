import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.tokens import decode_jwt_segment


@pytest.fixture
def context():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    yield context
    with cognito_idp_stores.lock:
        cognito_idp_stores.pop(context.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def test_resource_server_crud_pagination_and_custom_scope_client(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "resource-server-users"})["UserPool"]
    for identifier in ("api-a", "api-b"):
        created = provider.create_resource_server(
            context,
            {
                "Identifier": identifier,
                "Name": f"{identifier} server",
                "Scopes": [
                    {"ScopeDescription": "Read records", "ScopeName": "read"},
                    {"ScopeDescription": "Write records", "ScopeName": "write"},
                ],
                "UserPoolId": pool["Id"],
            },
        )["ResourceServer"]
        assert created["Identifier"] == identifier
        assert created["UserPoolId"] == pool["Id"]

    first = provider.list_resource_servers(context, {"MaxResults": 1, "UserPoolId": pool["Id"]})
    assert [server["Identifier"] for server in first["ResourceServers"]] == ["api-a"]
    second = provider.list_resource_servers(
        context,
        {
            "MaxResults": 1,
            "NextToken": first["NextToken"],
            "UserPoolId": pool["Id"],
        },
    )
    assert [server["Identifier"] for server in second["ResourceServers"]] == ["api-b"]

    updated = provider.update_resource_server(
        context,
        {
            "Identifier": "api-a",
            "Name": "Primary API",
            "Scopes": [{"ScopeDescription": "Read only", "ScopeName": "read"}],
            "UserPoolId": pool["Id"],
        },
    )["ResourceServer"]
    assert updated["Name"] == "Primary API"
    assert updated["Scopes"] == [{"ScopeDescription": "Read only", "ScopeName": "read"}]
    assert (
        provider.describe_resource_server(
            context, {"Identifier": "api-a", "UserPoolId": pool["Id"]}
        )["ResourceServer"]
        == updated
    )

    client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "api-a/read"],
            "CallbackURLs": ["https://app.example.test/callback"],
            "ClientName": "custom-scope-client",
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    assert client["AllowedOAuthScopes"] == ["openid", "api-a/read"]
    provider.admin_create_user(
        context,
        {
            "TemporaryPassword": "TemporaryPass9!",
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": "PermanentPass9!",
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    issued = provider.issue_oauth_tokens(
        context, pool["Id"], client["ClientId"], "alice", ["openid", "api-a/read"], None
    )
    assert decode_jwt_segment(issued["AccessToken"].split(".")[1])["scope"] == ("openid api-a/read")
    provider.delete_resource_server(context, {"Identifier": "api-a", "UserPoolId": pool["Id"]})
    with pytest.raises(CommonServiceException) as missing:
        provider.describe_resource_server(
            context, {"Identifier": "api-a", "UserPoolId": pool["Id"]}
        )
    assert missing.value.code == "ResourceNotFoundException"
    inactive = provider.issue_oauth_tokens(
        context,
        pool["Id"],
        client["ClientId"],
        "alice",
        ["openid", "api-a/read"],
        None,
    )
    assert decode_jwt_segment(inactive["AccessToken"].split(".")[1])["scope"] == "openid"
    refreshed = provider.refresh_oauth_tokens(
        context, pool["Id"], client["ClientId"], issued["RefreshToken"], None
    )
    assert decode_jwt_segment(refreshed["AccessToken"].split(".")[1])["scope"] == "openid"

    provider.create_resource_server(
        context,
        {
            "Identifier": "api-a",
            "Name": "Recreated API",
            "Scopes": [{"ScopeDescription": "Read", "ScopeName": "read"}],
            "UserPoolId": pool["Id"],
        },
    )
    reactivated = provider.refresh_oauth_tokens(
        context, pool["Id"], client["ClientId"], issued["RefreshToken"], None
    )
    assert decode_jwt_segment(reactivated["AccessToken"].split(".")[1])["scope"] == (
        "openid api-a/read"
    )


def test_resource_server_validation_quota_and_scope_references_are_atomic(
    provider, context, monkeypatch
):
    pool = provider.create_user_pool(context, {"PoolName": "resource-validation"})["UserPool"]
    with pytest.raises(CommonServiceException) as unknown_scope:
        provider.create_user_pool_client(
            context,
            {
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthFlowsUserPoolClient": True,
                "AllowedOAuthScopes": ["unknown/read"],
                "CallbackURLs": ["https://app.example.test/callback"],
                "ClientName": "unknown-scope",
                "UserPoolId": pool["Id"],
            },
        )
    assert unknown_scope.value.code == "InvalidParameterException"

    provider.create_resource_server(
        context,
        {
            "Identifier": "api",
            "Name": "API",
            "Scopes": [{"ScopeDescription": "Read", "ScopeName": "read"}],
            "UserPoolId": pool["Id"],
        },
    )
    with pytest.raises(CommonServiceException) as duplicate:
        provider.create_resource_server(
            context,
            {"Identifier": "api", "Name": "duplicate", "UserPoolId": pool["Id"]},
        )
    assert duplicate.value.code == "InvalidParameterException"

    monkeypatch.setattr(provider_module, "_MAX_RESOURCE_SERVERS_PER_POOL", 1)
    with pytest.raises(CommonServiceException) as quota:
        provider.create_resource_server(
            context,
            {"Identifier": "other", "Name": "Other", "UserPoolId": pool["Id"]},
        )
    assert quota.value.code == "LimitExceededException"
    assert provider.describe_resource_server(
        context, {"Identifier": "api", "UserPoolId": pool["Id"]}
    )["ResourceServer"]["Scopes"] == [{"ScopeDescription": "Read", "ScopeName": "read"}]


def test_user_pool_tags_create_mutate_validate_and_isolate(provider, context, monkeypatch):
    pool = provider.create_user_pool(
        context,
        {"PoolName": "tagged-users", "UserPoolTags": {"component": "auth", "env": "test"}},
    )["UserPool"]
    assert pool["UserPoolTags"] == {"component": "auth", "env": "test"}
    assert provider.list_tags_for_resource(context, {"ResourceArn": pool["Arn"]}) == {
        "Tags": {"component": "auth", "env": "test"}
    }
    provider.tag_resource(
        context, {"ResourceArn": pool["Arn"], "Tags": {"env": "prod", "owner": "platform"}}
    )
    assert provider.list_tags_for_resource(context, {"ResourceArn": pool["Arn"]})["Tags"] == {
        "component": "auth",
        "env": "prod",
        "owner": "platform",
    }
    provider.untag_resource(
        context, {"ResourceArn": pool["Arn"], "TagKeys": ["component", "missing"]}
    )
    assert provider.list_tags_for_resource(context, {"ResourceArn": pool["Arn"]})["Tags"] == {
        "env": "prod",
        "owner": "platform",
    }

    other_region = RequestContext(None)
    other_region.account_id = context.account_id
    other_region.region = "eu-west-1"
    with pytest.raises(CommonServiceException) as isolated:
        provider.list_tags_for_resource(other_region, {"ResourceArn": pool["Arn"]})
    assert isolated.value.code == "ResourceNotFoundException"

    monkeypatch.setattr(provider_module, "_MAX_TAGS_PER_POOL", 2)
    with pytest.raises(CommonServiceException) as quota:
        provider.tag_resource(context, {"ResourceArn": pool["Arn"], "Tags": {"extra": "x"}})
    assert quota.value.code == "LimitExceededException"
    assert provider.list_tags_for_resource(context, {"ResourceArn": pool["Arn"]})["Tags"] == {
        "env": "prod",
        "owner": "platform",
    }

    for tags in ({"aws:reserved": "x"}, {"": "x"}, {"x": "y" * 257}):
        with pytest.raises(CommonServiceException) as invalid:
            provider.tag_resource(context, {"ResourceArn": pool["Arn"], "Tags": tags})
        assert invalid.value.code == "InvalidParameterException"
