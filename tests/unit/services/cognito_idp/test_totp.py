import base64
import hashlib
import hmac
import struct
import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
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
    pool = provider.create_user_pool(context, {"PoolName": "mfa-users"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "mfa-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
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
    return pool, client


def _password_auth(provider, context, client):
    return provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )


def _totp(secret, now):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", int(now) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def test_mfa_setup_then_software_token_challenge(provider, context, monkeypatch):
    now = 1_800_000_000
    monkeypatch.setattr(provider_module.time, "time", lambda: now)
    pool, client = _stack(provider, context)
    provider.set_user_pool_mfa_config(
        context,
        {
            "MfaConfiguration": "ON",
            "SoftwareTokenMfaConfiguration": {"Enabled": True},
            "UserPoolId": pool["Id"],
        },
    )

    setup = _password_auth(provider, context, client)
    assert setup["ChallengeName"] == "MFA_SETUP"
    associated = provider.associate_software_token(context, {"Session": setup["Session"]})
    assert associated["SecretCode"]
    verified = provider.verify_software_token(
        context,
        {
            "Session": associated["Session"],
            "UserCode": _totp(associated["SecretCode"], now),
        },
    )
    assert verified["Status"] == "SUCCESS"
    completed = provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "MFA_SETUP",
            "ChallengeResponses": {"USERNAME": "alice"},
            "ClientId": client["ClientId"],
            "Session": verified["Session"],
        },
    )
    assert completed["AuthenticationResult"]["AccessToken"]

    now += 30
    challenge = _password_auth(provider, context, client)
    assert challenge["ChallengeName"] == "SOFTWARE_TOKEN_MFA"
    authenticated = provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "ChallengeResponses": {
                "SOFTWARE_TOKEN_MFA_CODE": _totp(associated["SecretCode"], now),
                "USERNAME": "alice",
            },
            "ClientId": client["ClientId"],
            "Session": challenge["Session"],
        },
    )
    assert authenticated["AuthenticationResult"]["IdToken"]

    replay = _password_auth(provider, context, client)
    with pytest.raises(CommonServiceException) as reused_step:
        provider.respond_to_auth_challenge(
            context,
            {
                "ChallengeName": "SOFTWARE_TOKEN_MFA",
                "ChallengeResponses": {
                    "SOFTWARE_TOKEN_MFA_CODE": _totp(associated["SecretCode"], now),
                    "USERNAME": "alice",
                },
                "ClientId": client["ClientId"],
                "Session": replay["Session"],
            },
        )
    assert reused_step.value.code == "CodeMismatchException"

    with cognito_idp_stores.lock:
        user = provider.get_store(context).user_pools[pool["Id"]].users["alice"]
        assert associated["SecretCode"] not in repr(user)
        assert not provider.get_store(context).mfa_sessions


def test_pool_config_preferences_and_admin_respond_shape(provider, context, monkeypatch):
    now = 1_800_000_000
    monkeypatch.setattr(provider_module.time, "time", lambda: now)
    pool, client = _stack(provider, context)
    configured = provider.set_user_pool_mfa_config(
        context,
        {
            "MfaConfiguration": "OPTIONAL",
            "SoftwareTokenMfaConfiguration": {"Enabled": True},
            "UserPoolId": pool["Id"],
        },
    )
    assert configured["MfaConfiguration"] == "OPTIONAL"
    assert provider.get_user_pool_mfa_config(context, {"UserPoolId": pool["Id"]}) == configured

    tokens = _password_auth(provider, context, client)["AuthenticationResult"]
    associated = provider.associate_software_token(context, {"AccessToken": tokens["AccessToken"]})
    provider.verify_software_token(
        context,
        {
            "AccessToken": tokens["AccessToken"],
            "UserCode": _totp(associated["SecretCode"], now),
        },
    )
    provider.set_user_mfa_preference(
        context,
        {
            "AccessToken": tokens["AccessToken"],
            "SoftwareTokenMfaSettings": {"Enabled": True, "PreferredMfa": True},
        },
    )
    provider.admin_set_user_mfa_preference(
        context,
        {
            "SoftwareTokenMfaSettings": {"Enabled": True, "PreferredMfa": True},
            "Username": "alice",
            "UserPoolId": pool["Id"],
        },
    )

    now += 30
    challenge = _password_auth(provider, context, client)
    result = provider.admin_respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "ChallengeResponses": {
                "SOFTWARE_TOKEN_MFA_CODE": _totp(associated["SecretCode"], now),
                "USERNAME": "alice",
            },
            "ClientId": client["ClientId"],
            "Session": challenge["Session"],
            "UserPoolId": pool["Id"],
        },
    )
    assert result["AuthenticationResult"]["AccessToken"]


def test_friendly_device_name_is_persisted_and_cleaned_with_user(provider, context, monkeypatch):
    now = 1_800_000_000
    monkeypatch.setattr(provider_module.time, "time", lambda: now)
    pool, client = _stack(provider, context)
    provider.set_user_pool_mfa_config(
        context,
        {
            "MfaConfiguration": "OPTIONAL",
            "SoftwareTokenMfaConfiguration": {"Enabled": True},
            "UserPoolId": pool["Id"],
        },
    )
    tokens = _password_auth(provider, context, client)["AuthenticationResult"]
    associated = provider.associate_software_token(context, {"AccessToken": tokens["AccessToken"]})
    provider.verify_software_token(
        context,
        {
            "AccessToken": tokens["AccessToken"],
            "FriendlyDeviceName": "Cassio authenticator",
            "UserCode": _totp(associated["SecretCode"], now),
        },
    )

    store = provider.get_store(context)
    assert store.friendly_device_names[(pool["Id"], "alice")] == "Cassio authenticator"
    provider.admin_delete_user(context, {"UserPoolId": pool["Id"], "Username": "alice"})
    assert store.friendly_device_names == {}


def test_totp_sessions_are_hash_only_bounded_consumed_and_sms_fails_closed(
    provider, context, monkeypatch
):
    now = 1_800_000_000
    monkeypatch.setattr(provider_module.time, "time", lambda: now)
    pool, client = _stack(provider, context)
    with pytest.raises(CommonServiceException) as sms:
        provider.set_user_pool_mfa_config(
            context,
            {
                "MfaConfiguration": "ON",
                "SmsMfaConfiguration": {"SmsAuthenticationMessage": "code"},
                "SoftwareTokenMfaConfiguration": {"Enabled": True},
                "UserPoolId": pool["Id"],
            },
        )
    assert sms.value.code == "InvalidParameterException"
    provider.set_user_pool_mfa_config(
        context,
        {
            "MfaConfiguration": "ON",
            "SoftwareTokenMfaConfiguration": {"Enabled": True},
            "UserPoolId": pool["Id"],
        },
    )
    setup = _password_auth(provider, context, client)
    with cognito_idp_stores.lock:
        store = provider.get_store(context)
        assert setup["Session"] not in store.mfa_sessions
    associated = provider.associate_software_token(context, {"Session": setup["Session"]})
    with cognito_idp_stores.lock:
        assert associated["Session"] not in store.mfa_sessions
        assert associated["SecretCode"] not in repr(store.mfa_sessions)

    invalid_request = {"Session": associated["Session"], "UserCode": "000000"}
    if invalid_request["UserCode"] == _totp(associated["SecretCode"], now):
        invalid_request["UserCode"] = "000001"
    with pytest.raises(CommonServiceException) as invalid:
        provider.verify_software_token(context, invalid_request)
    assert invalid.value.code == "CodeMismatchException"
    with pytest.raises(CommonServiceException) as consumed:
        provider.verify_software_token(context, invalid_request)
    assert consumed.value.code == "NotAuthorizedException"


def test_access_token_is_verified_before_mfa_preference_mutation(provider, context):
    pool, client = _stack(provider, context)
    provider.set_user_pool_mfa_config(
        context,
        {
            "MfaConfiguration": "OPTIONAL",
            "SoftwareTokenMfaConfiguration": {"Enabled": True},
            "UserPoolId": pool["Id"],
        },
    )
    token = _password_auth(provider, context, client)["AuthenticationResult"]["AccessToken"]
    header, claims, signature = token.split(".")
    signature = f"{'A' if signature[0] != 'A' else 'B'}{signature[1:]}"
    tampered = f"{header}.{claims}.{signature}"
    with pytest.raises(CommonServiceException) as rejected:
        provider.set_user_mfa_preference(
            context,
            {
                "AccessToken": tampered,
                "SoftwareTokenMfaSettings": {"Enabled": False, "PreferredMfa": False},
            },
        )
    assert rejected.value.code == "NotAuthorizedException"
