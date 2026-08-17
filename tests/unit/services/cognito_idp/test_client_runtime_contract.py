import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider


@pytest.fixture
def context():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    yield context
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(context.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(context.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def _stack(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "client-contract-users"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "AccessTokenValidity": 10,
            "ClientName": "amplify-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            "TokenValidityUnits": {
                "AccessToken": "minutes",
                "IdToken": "hours",
                "RefreshToken": "days",
            },
            "UserPoolId": pool["Id"],
            "WriteAttributes": ["email"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "TemporaryPassword": "TemporaryPass9!",
            "UserAttributes": [
                {"Name": "custom:tenantId", "Value": "tenant-1"},
                {"Name": "email", "Value": "original@example.com"},
                {"Name": "name", "Value": "Alice"},
            ],
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
    tokens = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]
    return pool, client, tokens


def test_write_attributes_round_trip_and_enforce_originating_client(provider, context):
    pool, client, tokens = _stack(provider, context)
    assert client["WriteAttributes"] == ["email"]
    provider.update_user_attributes(
        context,
        {
            "AccessToken": tokens["AccessToken"],
            "UserAttributes": [{"Name": "email", "Value": "alice@example.com"}],
        },
    )
    with pytest.raises(CommonServiceException) as denied:
        provider.update_user_attributes(
            context,
            {
                "AccessToken": tokens["AccessToken"],
                "UserAttributes": [{"Name": "name", "Value": "Alice"}],
            },
        )
    assert denied.value.code == "NotAuthorizedException"

    updated = provider.update_user_pool_client(
        context,
        {
            "ClientId": client["ClientId"],
            "UserPoolId": pool["Id"],
            "WriteAttributes": ["name"],
        },
    )["UserPoolClient"]
    assert updated["WriteAttributes"] == ["name"]
    with pytest.raises(CommonServiceException) as formerly_allowed:
        provider.update_user_attributes(
            context,
            {
                "AccessToken": tokens["AccessToken"],
                "UserAttributes": [{"Name": "email", "Value": "blocked@example.com"}],
            },
        )
    assert formerly_allowed.value.code == "NotAuthorizedException"
    with cognito_idp_stores.lock:
        assert (
            provider.get_store(context).user_pools[pool["Id"]].users["alice"].attributes["email"]
            == "alice@example.com"
        )


def test_update_client_resets_omitted_fields_and_validity_is_atomic(provider, context):
    pool, client, _ = _stack(provider, context)
    updated = provider.update_user_pool_client(
        context,
        {
            "AccessTokenValidity": 2,
            "ClientId": client["ClientId"],
            "RefreshTokenValidity": 12,
            "TokenValidityUnits": {"AccessToken": "hours"},
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    assert updated["AccessTokenValidity"] == 2
    assert updated["IdTokenValidity"] == 1
    assert updated["RefreshTokenValidity"] == 12
    assert updated["TokenValidityUnits"] == {
        "AccessToken": "hours",
        "IdToken": "hours",
        "RefreshToken": "days",
    }
    assert updated["ExplicitAuthFlows"] == [
        "ALLOW_CUSTOM_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
        "ALLOW_USER_SRP_AUTH",
    ]
    assert "WriteAttributes" not in updated
    assert (
        provider.describe_user_pool_client(
            context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
        )["UserPoolClient"]
        == updated
    )

    with pytest.raises(CommonServiceException) as invalid:
        provider.update_user_pool_client(
            context,
            {
                "AccessTokenValidity": 1,
                "ClientId": client["ClientId"],
                "TokenValidityUnits": {"AccessToken": "seconds"},
                "UserPoolId": pool["Id"],
                "WriteAttributes": ["preferred_username"],
            },
        )
    assert invalid.value.code == "InvalidParameterException"
    described = provider.describe_user_pool_client(
        context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
    )["UserPoolClient"]
    assert described["AccessTokenValidity"] == 2
    assert "WriteAttributes" not in described


def test_refresh_token_validity_zero_uses_the_aws_default(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "zero-refresh-users"})["UserPool"]

    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "zero-refresh-client",
            "RefreshTokenValidity": 0,
            "TokenValidityUnits": {"RefreshToken": "minutes"},
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]

    assert client["RefreshTokenValidity"] == 30
    assert client["TokenValidityUnits"]["RefreshToken"] == "days"


def test_get_user_read_permissions_and_default_custom_attribute_deny(provider, context):
    pool, client, tokens = _stack(provider, context)
    default_user = provider.get_user(context, {"AccessToken": tokens["AccessToken"]})
    default_names = {attribute["Name"] for attribute in default_user["UserAttributes"]}
    assert {"sub", "email", "name"} <= default_names
    assert "custom:tenantId" not in default_names

    provider.update_user_pool_client(
        context,
        {
            "ClientId": client["ClientId"],
            "ReadAttributes": ["email"],
            "UserPoolId": pool["Id"],
        },
    )
    restricted = provider.get_user(context, {"AccessToken": tokens["AccessToken"]})
    assert {attribute["Name"] for attribute in restricted["UserAttributes"]} == {
        "sub",
        "email",
    }


def test_write_permissions_apply_atomically_to_delete_and_default_custom_deny(provider, context):
    pool, client, tokens = _stack(provider, context)
    with pytest.raises(CommonServiceException) as mixed_delete:
        provider.delete_user_attributes(
            context,
            {
                "AccessToken": tokens["AccessToken"],
                "UserAttributeNames": ["email", "name"],
            },
        )
    assert mixed_delete.value.code == "NotAuthorizedException"
    with cognito_idp_stores.lock:
        attributes = provider.get_store(context).user_pools[pool["Id"]].users["alice"].attributes
        assert attributes["email"] == "original@example.com"
        assert attributes["name"] == "Alice"

    provider.update_user_pool_client(
        context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
    )
    with pytest.raises(CommonServiceException) as custom_write:
        provider.update_user_attributes(
            context,
            {
                "AccessToken": tokens["AccessToken"],
                "UserAttributes": [{"Name": "custom:tenantId", "Value": "tenant-2"}],
            },
        )
    assert custom_write.value.code == "NotAuthorizedException"
    with pytest.raises(CommonServiceException) as custom_delete:
        provider.delete_user_attributes(
            context,
            {
                "AccessToken": tokens["AccessToken"],
                "UserAttributeNames": ["custom:tenantId"],
            },
        )
    assert custom_delete.value.code == "NotAuthorizedException"

    provider.update_user_pool_client(
        context,
        {
            "ClientId": client["ClientId"],
            "UserPoolId": pool["Id"],
            "WriteAttributes": ["custom:tenantId"],
        },
    )
    provider.update_user_attributes(
        context,
        {
            "AccessToken": tokens["AccessToken"],
            "UserAttributes": [{"Name": "custom:tenantId", "Value": "tenant-2"}],
        },
    )
    provider.delete_user_attributes(
        context,
        {
            "AccessToken": tokens["AccessToken"],
            "UserAttributeNames": ["custom:tenantId"],
        },
    )


@pytest.mark.parametrize("write_attributes", [[], ["email", "email"], ["\x00"]])
def test_write_attributes_reject_invalid_configuration(provider, context, write_attributes):
    pool = provider.create_user_pool(context, {"PoolName": "invalid-write-attrs"})["UserPool"]
    with pytest.raises(CommonServiceException) as invalid:
        provider.create_user_pool_client(
            context,
            {
                "ClientName": "invalid-client",
                "UserPoolId": pool["Id"],
                "WriteAttributes": write_attributes,
            },
        )
    assert invalid.value.code == "InvalidParameterException"
