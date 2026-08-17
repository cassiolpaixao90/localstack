import base64
import hashlib
import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import notification_delivery
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import PasswordHash, cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    yield value
    with cognito_idp_stores.lock:
        cognito_idp_stores.pop(value.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def _stack(provider, context, *, auto_verified=False):
    request = {"PoolName": "migration-query-users"}
    if auto_verified:
        request["AutoVerifiedAttributes"] = ["email"]
    pool = provider.create_user_pool(context, request)["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "migration-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    return pool, client


def _confirmed_user(provider, context, pool, username="alice", attributes=None):
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "TemporaryPass9!",
            "UserAttributes": attributes or [],
            "UserPoolId": pool["Id"],
            "Username": username,
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": "PermanentPass9!",
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": username,
        },
    )


def _imported_pbkdf2(password):
    salt = b"provider-import-salt"
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 10_000, dklen=32)
    return (
        "$pbkdf2-sha256$10000$"
        f"{base64.b64encode(salt).decode().rstrip('=')}$"
        f"{base64.b64encode(digest).decode().rstrip('=')}"
    )


def test_first_password_login_migrates_imported_hash_to_native_pbkdf2_and_srp(provider, context):
    pool, client = _stack(provider, context)
    _confirmed_user(provider, context, pool)
    with cognito_idp_stores.lock:
        user = provider.get_store(context).user_pools[pool["Id"]].users["alice"]
        user.password = PasswordHash(
            algorithm="imported:PBKDF2_SHA256",
            iterations=0,
            salt="",
            digest=_imported_pbkdf2("ImportedPass9!"),
        )
        user.srp_salt = user.srp_verifier = ""

    with pytest.raises(CommonServiceException):
        provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {"PASSWORD": "wrong", "USERNAME": "alice"},
                "ClientId": client["ClientId"],
            },
        )
    assert user.password.is_imported

    result = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "ImportedPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )

    assert result["AuthenticationResult"]["RefreshToken"]
    assert user.password.algorithm == "pbkdf2-sha256"
    assert user.password.verify("ImportedPass9!")
    assert user.srp_salt and user.srp_verifier


def test_list_users_filter_sort_and_token_are_provider_visible(provider, context):
    pool, _ = _stack(provider, context)
    for username, email in (
        ("zulu", "zulu@example.test"),
        ("alpha", "Alpha@example.test"),
        ("beta", "alpine@example.test"),
    ):
        _confirmed_user(
            provider,
            context,
            pool,
            username,
            [{"Name": "email", "Value": email}],
        )

    first = provider.list_users(
        context,
        {"Filter": 'email ^= "AL"', "Limit": 1, "UserPoolId": pool["Id"]},
    )
    second = provider.list_users(
        context,
        {
            "Filter": 'email ^= "AL"',
            "Limit": 1,
            "PaginationToken": first["PaginationToken"],
            "UserPoolId": pool["Id"],
        },
    )

    assert [first["Users"][0]["Username"], second["Users"][0]["Username"]] == [
        "alpha",
        "beta",
    ]
    assert "PaginationToken" not in second


def test_get_tokens_refresh_propagates_large_client_metadata_and_refresh_source(
    provider, context, monkeypatch
):
    pool, client = _stack(provider, context)
    _confirmed_user(provider, context, pool)
    authenticated = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]
    stored_pool = provider.get_store(context).user_pools[pool["Id"]]
    stored_pool.lambda_config = {
        "PreTokenGeneration": "arn:aws:lambda:us-east-1:123456789012:function:pre-token"
    }
    events = []

    def invoke(_context, _pool, _arn, event):
        events.append(event)
        event["response"] = {"claimsOverrideDetails": {}}
        return event

    monkeypatch.setattr(provider_module, "_invoke_lambda_trigger", invoke)
    metadata = {f"key-{index}": f"value-{index}" for index in range(64)}

    refreshed = provider.get_tokens_from_refresh_token(
        context,
        {
            "ClientId": client["ClientId"],
            "ClientMetadata": metadata,
            "RefreshToken": authenticated["RefreshToken"],
        },
    )

    assert refreshed["AuthenticationResult"]["AccessToken"]
    assert events[-1]["triggerSource"] == "TokenGeneration_RefreshTokens"
    assert events[-1]["request"]["clientMetadata"] == metadata


def test_custom_message_receives_metadata_for_signup_and_resend(provider, context, monkeypatch):
    pool, client = _stack(provider, context, auto_verified=True)
    stored_pool = provider.get_store(context).user_pools[pool["Id"]]
    stored_pool.lambda_config = {
        "CustomMessage": (
            f"arn:{context.partition}:lambda:{context.region}:"
            f"{context.account_id}:function:custom-message"
        )
    }
    events = []
    deliveries = []

    def invoke(_context, _pool, _arn, event, *, allow_none=False):
        events.append(event)
        return event

    monkeypatch.setattr(provider_module, "_invoke_lambda_trigger", invoke)
    monkeypatch.setattr(
        notification_delivery,
        "_save_cognito_default_email",
        lambda *_args: deliveries.append(_args) or {"MessageId": str(len(deliveries))},
    )
    provider.sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "ClientMetadata": {"request": "signup"},
            "Password": "PermanentPass9!",
            "UserAttributes": [{"Name": "email", "Value": "alice@example.test"}],
            "Username": "alice",
        },
    )
    provider.resend_confirmation_code(
        context,
        {
            "ClientId": client["ClientId"],
            "ClientMetadata": {"request": "resend"},
            "Username": "alice",
        },
    )

    assert [event["triggerSource"] for event in events] == [
        "CustomMessage_SignUp",
        "CustomMessage_ResendCode",
    ]
    assert [event["request"]["clientMetadata"] for event in events] == [
        {"request": "signup"},
        {"request": "resend"},
    ]
    assert len(deliveries) == 2


def test_list_user_pools_includes_lambda_config_and_replica_regions(provider, context):
    pool, _ = _stack(provider, context)
    stored_pool = provider.get_store(context).user_pools[pool["Id"]]
    stored_pool.lambda_config = {
        "PreSignUp": "arn:aws:lambda:us-east-1:123456789012:function:pre-signup"
    }
    provider.create_user_pool_replica(
        context,
        {"RegionName": "eu-west-1", "UserPoolId": pool["Id"]},
    )

    summary = provider.list_user_pools(context, {"MaxResults": 60})["UserPools"][0]

    assert summary["LambdaConfig"] == stored_pool.lambda_config
    assert summary["ReplicaRegions"] == ["eu-west-1"]
