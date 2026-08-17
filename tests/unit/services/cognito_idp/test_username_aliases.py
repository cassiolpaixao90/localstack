import json
import uuid
from types import SimpleNamespace

import dill
import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider


@pytest.fixture
def context(region_name):
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = region_name
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


def _client(provider, context, pool_id):
    return provider.create_user_pool_client(
        context,
        {
            "ClientName": "amplify-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
            "UserPoolId": pool_id,
        },
    )["UserPoolClient"]


def _password_auth(provider, context, client_id, username):
    return provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": username},
            "ClientId": client_id,
        },
    )


def test_case_insensitive_username_is_unique_and_resolves_for_admin_and_auth(provider, context):
    pool = provider.create_user_pool(
        context,
        {
            "PoolName": "case-insensitive-users",
            "UsernameConfiguration": {"CaseSensitive": False},
        },
    )["UserPool"]
    client = _client(provider, context, pool["Id"])

    created = provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "PermanentPass9!",
            "UserPoolId": pool["Id"],
            "Username": "Alice",
        },
    )["User"]
    provider.admin_set_user_password(
        context,
        {
            "Password": "PermanentPass9!",
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": "aLiCe",
        },
    )

    assert created["Username"] == "alice"
    assert (
        provider.admin_get_user(context, {"UserPoolId": pool["Id"], "Username": "ALICE"})[
            "Username"
        ]
        == "alice"
    )
    assert "AuthenticationResult" in _password_auth(provider, context, client["ClientId"], "alice")
    with pytest.raises(CommonServiceException) as duplicate:
        provider.admin_create_user(
            context,
            {
                "MessageAction": "SUPPRESS",
                "TemporaryPassword": "PermanentPass9!",
                "UserPoolId": pool["Id"],
                "Username": "ALIce",
            },
        )
    assert duplicate.value.code == "UsernameExistsException"

    described = provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"]
    assert described["UsernameConfiguration"] == {"CaseSensitive": False}


def test_email_username_mode_derives_attribute_and_resolves_case_insensitively(
    provider, context, monkeypatch
):
    pool = provider.create_user_pool(
        context,
        {
            "AutoVerifiedAttributes": ["email"],
            "PoolName": "email-users",
            "UsernameAttributes": ["email"],
            "UsernameConfiguration": {"CaseSensitive": False},
        },
    )["UserPool"]
    client = _client(provider, context, pool["Id"])
    monkeypatch.setattr(provider_module, "_new_numeric_code", lambda: "123456")

    provider.sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "Password": "PermanentPass9!",
            "Username": "Alice@Example.test",
        },
    )
    provider.confirm_sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "ConfirmationCode": "123456",
            "Username": "alice@example.TEST",
        },
    )

    user = provider.admin_get_user(
        context, {"UserPoolId": pool["Id"], "Username": "ALICE@example.test"}
    )
    attributes = {item["Name"]: item["Value"] for item in user["UserAttributes"]}
    assert attributes["email"] == "alice@example.test"
    assert attributes["email_verified"] == "true"
    assert "AuthenticationResult" in _password_auth(
        provider, context, client["ClientId"], "alice@example.test"
    )


def test_alias_confirmation_is_atomic_and_force_alias_transfers_ownership(
    provider, context, monkeypatch
):
    pool = provider.create_user_pool(
        context,
        {
            "AliasAttributes": ["email", "preferred_username"],
            "AutoVerifiedAttributes": ["email"],
            "PoolName": "alias-users",
            "UsernameConfiguration": {"CaseSensitive": False},
        },
    )["UserPool"]
    client = _client(provider, context, pool["Id"])
    codes = iter(("111111", "222222"))
    monkeypatch.setattr(provider_module, "_new_numeric_code", lambda: next(codes))

    for username, code in (("first", "111111"), ("second", "222222")):
        provider.sign_up(
            context,
            {
                "ClientId": client["ClientId"],
                "Password": "PermanentPass9!",
                "UserAttributes": [
                    {"Name": "email", "Value": "Shared@Example.test"},
                ],
                "Username": username,
            },
        )
        if username == "first":
            provider.confirm_sign_up(
                context,
                {
                    "ClientId": client["ClientId"],
                    "ConfirmationCode": code,
                    "Username": username,
                },
            )

    with pytest.raises(CommonServiceException) as conflict:
        provider.confirm_sign_up(
            context,
            {
                "ClientId": client["ClientId"],
                "ConfirmationCode": "222222",
                "Username": "second",
            },
        )
    assert conflict.value.code == "AliasExistsException"
    assert (
        provider.admin_get_user(context, {"UserPoolId": pool["Id"], "Username": "second"})[
            "UserStatus"
        ]
        == "UNCONFIRMED"
    )

    provider.confirm_sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "ConfirmationCode": "222222",
            "ForceAliasCreation": True,
            "Username": "second",
        },
    )
    provider.admin_update_user_attributes(
        context,
        {
            "UserAttributes": [{"Name": "preferred_username", "Value": "second-alias"}],
            "UserPoolId": pool["Id"],
            "Username": "second",
        },
    )
    owner = provider.admin_get_user(
        context, {"UserPoolId": pool["Id"], "Username": "shared@example.TEST"}
    )
    assert owner["Username"] == "second"
    first = provider.admin_get_user(context, {"UserPoolId": pool["Id"], "Username": "first"})
    first_attributes = {item["Name"]: item["Value"] for item in first["UserAttributes"]}
    assert first_attributes["email_verified"] == "false"
    assert "AuthenticationResult" in _password_auth(
        provider, context, client["ClientId"], "SECOND-ALIAS"
    )


def test_username_and_alias_modes_are_mutually_exclusive_without_partial_pool(provider, context):
    with pytest.raises(CommonServiceException) as error:
        provider.create_user_pool(
            context,
            {
                "AliasAttributes": ["email"],
                "PoolName": "invalid-pool",
                "UsernameAttributes": ["email"],
            },
        )
    assert error.value.code == "InvalidParameterException"
    assert provider.list_user_pools(context, {"MaxResults": 60})["UserPools"] == []


def test_alias_mode_rejects_username_shaped_like_alias_and_preferred_alias_at_signup(
    provider, context
):
    pool = provider.create_user_pool(
        context,
        {
            "AliasAttributes": ["email", "phone_number", "preferred_username"],
            "PoolName": "reserved-alias-shapes",
        },
    )["UserPool"]
    client = _client(provider, context, pool["Id"])

    for username in ("alice@example.test", "+12065550100"):
        with pytest.raises(CommonServiceException) as invalid_username:
            provider.sign_up(
                context,
                {
                    "ClientId": client["ClientId"],
                    "Password": "PermanentPass9!",
                    "UserAttributes": [{"Name": "email", "Value": "alice@example.test"}],
                    "Username": username,
                },
            )
        assert invalid_username.value.code == "InvalidParameterException"

    with pytest.raises(CommonServiceException) as preferred_during_signup:
        provider.sign_up(
            context,
            {
                "ClientId": client["ClientId"],
                "Password": "PermanentPass9!",
                "UserAttributes": [
                    {"Name": "email", "Value": "alice@example.test"},
                    {"Name": "preferred_username", "Value": "alice-alias"},
                ],
                "Username": "alice",
            },
        )
    assert preferred_during_signup.value.code == "InvalidParameterException"


def test_confirmation_client_metadata_reaches_post_confirmation_trigger(
    provider, context, monkeypatch
):
    calls = []

    class LambdaClient:
        def invoke(self, **kwargs):
            calls.append(json.loads(kwargs["Payload"]))
            return {"Payload": b'{"response":{}}', "StatusCode": 200}

    monkeypatch.setattr(
        provider_module,
        "connect_to",
        lambda **_: SimpleNamespace(
            lambda_=SimpleNamespace(request_metadata=lambda **__: LambdaClient())
        ),
    )
    monkeypatch.setattr(provider_module, "_new_numeric_code", lambda: "654321")
    pool = provider.create_user_pool(
        context,
        {
            "LambdaConfig": {
                "PostConfirmation": (
                    f"arn:{context.partition}:lambda:{context.region}:{context.account_id}:"
                    "function:post-confirm"
                )
            },
            "PoolName": "metadata-users",
        },
    )["UserPool"]
    client = _client(provider, context, pool["Id"])
    provider.sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "Password": "PermanentPass9!",
            "UserAttributes": [{"Name": "email", "Value": "metadata@example.test"}],
            "Username": "metadata-user",
        },
    )
    provider.confirm_sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "ClientMetadata": {"tenant": "enterprise", "surface": "amplify-web"},
            "ConfirmationCode": "654321",
            "Username": "metadata-user",
        },
    )

    assert calls[0]["request"]["clientMetadata"] == {
        "surface": "amplify-web",
        "tenant": "enterprise",
    }


def test_auth_metadata_is_validated_and_retained_in_risk_event(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "risk-metadata"})["UserPool"]
    client = _client(provider, context, pool["Id"])
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "PermanentPass9!",
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

    provider.initiate_auth(
        context,
        {
            "AnalyticsMetadata": {"AnalyticsEndpointId": "mobile-install-123"},
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
            "UserContextData": {
                "EncodedData": "signed-risk-context",
                "IpAddress": "192.0.2.10",
            },
        },
    )
    events = provider.admin_list_user_auth_events(
        context, {"UserPoolId": pool["Id"], "Username": "alice"}
    )["AuthEvents"]
    assert events[0]["EventContextData"] == {
        "AnalyticsEndpointId": "mobile-install-123",
        "IpAddress": "192.0.2.10",
    }


def test_alias_indexes_survive_pickle_and_cleanup_releases_alias(provider, context):
    pool = provider.create_user_pool(
        context,
        {
            "AliasAttributes": ["email"],
            "PoolName": "persistent-aliases",
            "UsernameConfiguration": {"CaseSensitive": False},
        },
    )["UserPool"]
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "PermanentPass9!",
            "UserAttributes": [
                {"Name": "email", "Value": "Owner@Example.test"},
                {"Name": "email_verified", "Value": "true"},
            ],
            "UserPoolId": pool["Id"],
            "Username": "owner",
        },
    )
    with cognito_idp_stores.lock:
        store = provider.get_store(context)
        store.user_pools[pool["Id"]] = dill.loads(dill.dumps(store.user_pools[pool["Id"]]))

    assert (
        provider.admin_get_user(
            context, {"UserPoolId": pool["Id"], "Username": "OWNER@example.TEST"}
        )["Username"]
        == "owner"
    )
    provider.admin_delete_user(
        context, {"UserPoolId": pool["Id"], "Username": "owner@example.test"}
    )
    recreated = provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "PermanentPass9!",
            "UserAttributes": [
                {"Name": "email", "Value": "owner@example.test"},
                {"Name": "email_verified", "Value": "true"},
            ],
            "UserPoolId": pool["Id"],
            "Username": "replacement",
        },
    )["User"]
    assert recreated["Username"] == "replacement"


def test_admin_force_alias_creation_transfers_verified_alias(provider, context):
    pool = provider.create_user_pool(
        context, {"AliasAttributes": ["email"], "PoolName": "admin-alias-transfer"}
    )["UserPool"]
    base = {
        "MessageAction": "SUPPRESS",
        "TemporaryPassword": "PermanentPass9!",
        "UserAttributes": [
            {"Name": "email", "Value": "shared@example.test"},
            {"Name": "email_verified", "Value": "true"},
        ],
        "UserPoolId": pool["Id"],
    }
    provider.admin_create_user(context, {**base, "Username": "first"})
    with pytest.raises(CommonServiceException) as conflict:
        provider.admin_create_user(context, {**base, "Username": "second"})
    assert conflict.value.code == "AliasExistsException"

    provider.admin_create_user(context, {**base, "ForceAliasCreation": True, "Username": "second"})
    assert (
        provider.admin_get_user(
            context, {"UserPoolId": pool["Id"], "Username": "shared@example.test"}
        )["Username"]
        == "second"
    )
    first = provider.admin_get_user(context, {"UserPoolId": pool["Id"], "Username": "first"})
    attributes = {item["Name"]: item["Value"] for item in first["UserAttributes"]}
    assert attributes["email_verified"] == "false"
