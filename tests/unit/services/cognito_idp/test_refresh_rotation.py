import pickle
import re
import threading
import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
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


def _client_and_user(provider, context, *, rotation=None, generate_secret=False):
    pool = provider.create_user_pool(context, {"PoolName": "rotation-users"})["UserPool"]
    request = {
        "ClientName": "mobile",
        "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        "GenerateSecret": generate_secret,
        "UserPoolId": pool["Id"],
    }
    if rotation is not None:
        request["RefreshTokenRotation"] = rotation
    client = provider.create_user_pool_client(context, request)["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "TempPass9!",
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
    auth = {"USERNAME": "alice", "PASSWORD": "PermanentPass9!"}
    if generate_secret:
        import base64
        import hashlib
        import hmac

        auth["SECRET_HASH"] = base64.b64encode(
            hmac.new(
                client["ClientSecret"].encode(),
                f"alice{client['ClientId']}".encode(),
                hashlib.sha256,
            ).digest()
        ).decode()
    tokens = provider.initiate_auth(
        context,
        {"AuthFlow": "USER_PASSWORD_AUTH", "AuthParameters": auth, "ClientId": client["ClientId"]},
    )["AuthenticationResult"]
    return pool, client, tokens


def test_get_tokens_preserves_legacy_refresh_compatibility(provider, context):
    _, client, tokens = _client_and_user(provider, context)

    refreshed = provider.get_tokens_from_refresh_token(
        context, {"ClientId": client["ClientId"], "RefreshToken": tokens["RefreshToken"]}
    )["AuthenticationResult"]

    assert "RefreshToken" not in refreshed
    assert (
        decode_jwt_segment(refreshed["AccessToken"].split(".")[1])["origin_jti"]
        == decode_jwt_segment(tokens["AccessToken"].split(".")[1])["origin_jti"]
    )

    other_region = RequestContext(None)
    other_region.account_id = context.account_id
    other_region.region = "us-west-2"
    with pytest.raises(CommonServiceException) as isolated:
        provider.get_tokens_from_refresh_token(
            other_region,
            {"ClientId": client["ClientId"], "RefreshToken": tokens["RefreshToken"]},
        )
    assert isolated.value.code == "ResourceNotFoundException"


def test_refresh_rotation_is_atomic_and_reuse_revokes_family(provider, context):
    _, client, tokens = _client_and_user(
        provider,
        context,
        rotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": 0},
    )
    request = {"ClientId": client["ClientId"], "RefreshToken": tokens["RefreshToken"]}
    outcomes = []

    def rotate():
        try:
            outcomes.append(provider.get_tokens_from_refresh_token(context, request))
        except CommonServiceException as error:
            outcomes.append(error.code)

    threads = [threading.Thread(target=rotate) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(isinstance(item, dict) for item in outcomes) == 1
    assert "RefreshTokenReuseException" in outcomes
    replacement = next(item for item in outcomes if isinstance(item, dict))["AuthenticationResult"]
    assert replacement["RefreshToken"] != tokens["RefreshToken"]
    persisted = pickle.dumps(provider.get_store(context).refresh_sessions)
    assert tokens["RefreshToken"].encode() not in persisted
    assert replacement["RefreshToken"].encode() not in persisted
    assert pickle.loads(persisted).keys() == provider.get_store(context).refresh_sessions.keys()
    with pytest.raises(CommonServiceException) as revoked:
        provider.get_tokens_from_refresh_token(
            context,
            {"ClientId": client["ClientId"], "RefreshToken": replacement["RefreshToken"]},
        )
    assert revoked.value.code == "RefreshTokenReuseException"


def test_refresh_rotation_grace_returns_one_replacement(provider, context):
    _, client, tokens = _client_and_user(
        provider,
        context,
        rotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": 60},
    )
    request = {"ClientId": client["ClientId"], "RefreshToken": tokens["RefreshToken"]}

    first = provider.get_tokens_from_refresh_token(context, request)["AuthenticationResult"]
    retry = provider.get_tokens_from_refresh_token(context, request)["AuthenticationResult"]

    assert retry["RefreshToken"] == first["RefreshToken"]


def test_confidential_client_secret_lifecycle_and_auth(provider, context):
    pool, client, tokens = _client_and_user(provider, context, generate_secret=True)
    initial_secret = client["ClientSecret"]
    assert re.fullmatch(r"[\w+]{40}", initial_secret)
    assert initial_secret not in repr(provider.get_store(context).user_pools)
    assert initial_secret.encode() not in pickle.dumps(provider.get_store(context).user_pools)

    described = provider.describe_user_pool_client(
        context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
    )["UserPoolClient"]
    assert "ClientSecret" not in described

    added = provider.add_user_pool_client_secret(
        context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
    )["ClientSecretDescriptor"]
    assert added["ClientSecretValue"] not in repr(provider.get_store(context).user_pools)
    assert added["ClientSecretValue"].encode() not in pickle.dumps(
        provider.get_store(context).user_pools
    )

    listed = provider.list_user_pool_client_secrets(
        context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
    )["ClientSecrets"]
    assert len(listed) == 2
    assert all("ClientSecretValue" not in item for item in listed)

    assert (
        "AccessToken"
        in provider.get_tokens_from_refresh_token(
            context,
            {
                "ClientId": client["ClientId"],
                "ClientSecret": added["ClientSecretValue"],
                "RefreshToken": tokens["RefreshToken"],
            },
        )["AuthenticationResult"]
    )

    with pytest.raises(CommonServiceException) as invalid_page:
        provider.list_user_pool_client_secrets(
            context,
            {
                "ClientId": client["ClientId"],
                "NextToken": "not-a-bound-token",
                "UserPoolId": pool["Id"],
            },
        )
    assert invalid_page.value.code == "InvalidParameterException"

    with pytest.raises(CommonServiceException) as quota:
        provider.add_user_pool_client_secret(
            context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
        )
    assert quota.value.code == "LimitExceededException"

    assert (
        "AccessToken"
        in provider.get_tokens_from_refresh_token(
            context,
            {
                "ClientId": client["ClientId"],
                "ClientSecret": initial_secret,
                "RefreshToken": tokens["RefreshToken"],
            },
        )["AuthenticationResult"]
    )
    provider.delete_user_pool_client_secret(
        context,
        {
            "ClientId": client["ClientId"],
            "ClientSecretId": listed[0]["ClientSecretId"],
            "UserPoolId": pool["Id"],
        },
    )
    with pytest.raises(CommonServiceException) as last:
        provider.delete_user_pool_client_secret(
            context,
            {
                "ClientId": client["ClientId"],
                "ClientSecretId": listed[1]["ClientSecretId"],
                "UserPoolId": pool["Id"],
            },
        )
    assert last.value.code == "LimitExceededException"


def test_custom_secret_is_write_only_and_rotation_disables_legacy_auth(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "custom-secret-users"})["UserPool"]
    custom_secret = "A" * 24
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "custom-secret-client",
            "ClientSecret": custom_secret,
            "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_PASSWORD_AUTH"],
            "RefreshTokenRotation": {"Feature": "ENABLED"},
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]

    assert client["ClientSecret"] == custom_secret
    assert custom_secret not in repr(provider.get_store(context).user_pools)
    assert custom_secret.encode() not in pickle.dumps(provider.get_store(context).user_pools)
    assert (
        "ClientSecret"
        not in provider.describe_user_pool_client(
            context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
        )["UserPoolClient"]
    )

    with pytest.raises(CommonServiceException) as unsupported_legacy:
        provider.initiate_auth(
            context,
            {
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "AuthParameters": {"REFRESH_TOKEN": "invalid"},
                "ClientId": client["ClientId"],
            },
        )
    assert unsupported_legacy.value.code == "InvalidParameterException"


def test_revoke_token_revokes_the_rotated_family(provider, context):
    _, client, tokens = _client_and_user(
        provider,
        context,
        rotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": 30},
    )
    replacement = provider.get_tokens_from_refresh_token(
        context,
        {"ClientId": client["ClientId"], "RefreshToken": tokens["RefreshToken"]},
    )["AuthenticationResult"]["RefreshToken"]

    provider.revoke_token(context, {"ClientId": client["ClientId"], "Token": replacement})

    with pytest.raises(CommonServiceException) as revoked:
        provider.get_tokens_from_refresh_token(
            context, {"ClientId": client["ClientId"], "RefreshToken": replacement}
        )
    assert revoked.value.code == "NotAuthorizedException"


def test_rotation_configuration_validation_and_update_reset(provider, context):
    pool, client, _ = _client_and_user(
        provider,
        context,
        rotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": 5},
    )
    assert client["RefreshTokenRotation"] == {
        "Feature": "ENABLED",
        "RetryGracePeriodSeconds": 5,
    }

    updated = provider.update_user_pool_client(
        context,
        {"ClientId": client["ClientId"], "ClientName": "mobile", "UserPoolId": pool["Id"]},
    )["UserPoolClient"]
    assert updated["RefreshTokenRotation"] == {
        "Feature": "DISABLED",
        "RetryGracePeriodSeconds": 0,
    }
    assert updated["EnableTokenRevocation"] is True
