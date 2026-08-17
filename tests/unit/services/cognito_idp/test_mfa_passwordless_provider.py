import re
import uuid
from types import SimpleNamespace

import pytest

from localstack.aws.api import RequestContext
from localstack.services.cognito_idp import notification_delivery
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
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


def _passwordless_stack(provider, context):
    pool = provider.create_user_pool(
        context,
        {
            "AutoVerifiedAttributes": ["email"],
            "EmailConfiguration": {"EmailSendingAccount": "COGNITO_DEFAULT"},
            "Policies": {
                "SignInPolicy": {
                    "AllowedFirstAuthFactors": ["PASSWORD", "EMAIL_OTP"]
                }
            },
            "PoolName": "choice-auth",
        },
    )["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "AuthSessionValidity": 3,
            "ClientName": "choice-client",
            "ExplicitAuthFlows": ["ALLOW_USER_AUTH"],
            "PreventUserExistenceErrors": "ENABLED",
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    return pool, client


def _code(message):
    match = re.search(r"[0-9]{6}", message)
    assert match is not None
    return match.group()


def test_user_auth_email_otp_confirms_and_verifies_signup_user(
    provider, context, monkeypatch
):
    pool, client = _passwordless_stack(provider, context)
    delivered = []

    def save(_context, destination, _source, _subject, message):
        assert pool["Id"] not in provider_module._POOL_LOCKS
        delivered.append((destination, message))
        return {"MessageId": f"message-{len(delivered)}"}

    monkeypatch.setattr(notification_delivery, "_save_cognito_default_email", save)
    provider.sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "Password": "PermanentPass9!",
            "UserAttributes": [{"Name": "email", "Value": "alice@example.test"}],
            "Username": "alice",
        },
    )
    challenge = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_AUTH",
            "AuthParameters": {
                "PREFERRED_CHALLENGE": "EMAIL_OTP",
                "USERNAME": "alice",
            },
            "ClientId": client["ClientId"],
            "ClientMetadata": {"source": "amplify"},
        },
    )
    assert challenge["ChallengeName"] == "EMAIL_OTP"
    authenticated = provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "EMAIL_OTP",
            "ChallengeResponses": {
                "EMAIL_OTP_CODE": _code(delivered[-1][1]),
                "USERNAME": "alice",
            },
            "ClientId": client["ClientId"],
            "Session": challenge["Session"],
        },
    )
    assert authenticated["AuthenticationResult"]["AccessToken"]
    user = provider.admin_get_user(
        context, {"UserPoolId": pool["Id"], "Username": "alice"}
    )
    assert user["UserStatus"] == "CONFIRMED"
    assert {item["Name"]: item["Value"] for item in user["UserAttributes"]}[
        "email_verified"
    ] == "true"
    assert _code(delivered[-1][1]) not in repr(provider.get_store(context).mfa_passwordless)


def test_user_auth_select_password_completes_inline(provider, context):
    pool, client = _passwordless_stack(provider, context)
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
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
    selected = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_AUTH",
            "AuthParameters": {"USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )
    assert selected["ChallengeName"] == "SELECT_CHALLENGE"
    assert {"PASSWORD", "PASSWORD_SRP"} <= set(selected["AvailableChallenges"])
    authenticated = provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "SELECT_CHALLENGE",
            "ChallengeResponses": {
                "ANSWER": "PASSWORD",
                "PASSWORD": "PermanentPass9!",
                "USERNAME": "alice",
            },
            "ClientId": client["ClientId"],
            "Session": selected["Session"],
        },
    )
    assert authenticated["AuthenticationResult"]["IdToken"]


def test_user_auth_sms_otp_uses_sms_response_field(provider, context, monkeypatch):
    sent = []
    sns = SimpleNamespace(
        publish=lambda **request: sent.append(request) or {"MessageId": "sms-otp-id"}
    )
    monkeypatch.setattr(
        notification_delivery,
        "_client_factory",
        lambda *_args: SimpleNamespace(sns=sns),
    )
    monkeypatch.setattr(provider_module, "validate_local_resources", lambda *_args: "stable")
    pool = provider.create_user_pool(
        context,
        {
            "AutoVerifiedAttributes": ["phone_number"],
            "Policies": {
                "SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "SMS_OTP"]}
            },
            "PoolName": "sms-choice",
            "SmsConfiguration": {
                "SnsCallerArn": f"arn:aws:iam::{context.account_id}:role/cognito-sms"
            },
        },
    )["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "sms-client",
            "ExplicitAuthFlows": ["ALLOW_USER_AUTH"],
            "PreventUserExistenceErrors": "ENABLED",
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "Password": "PermanentPass9!",
            "UserAttributes": [{"Name": "phone_number", "Value": "+12065550123"}],
            "Username": "alice",
        },
    )
    challenge = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_AUTH",
            "AuthParameters": {
                "PREFERRED_CHALLENGE": "SMS_OTP",
                "USERNAME": "alice",
            },
            "ClientId": client["ClientId"],
        },
    )
    assert challenge["ChallengeName"] == "SMS_OTP"
    assert provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "SMS_OTP",
            "ChallengeResponses": {
                "SMS_OTP_CODE": _code(sent[-1]["Message"]),
                "USERNAME": "alice",
            },
            "ClientId": client["ClientId"],
            "Session": challenge["Session"],
        },
    )["AuthenticationResult"]["AccessToken"]


def test_email_mfa_after_password_uses_distinct_template_and_marks_verified(
    provider, context, monkeypatch
):
    sent = []
    ses = SimpleNamespace(
        send_email=lambda **request: sent.append(request) or {"MessageId": "email-mfa-id"}
    )
    monkeypatch.setattr(notification_delivery, "_client_factory", lambda *_args: SimpleNamespace(ses=ses))
    monkeypatch.setattr(provider_module, "validate_local_resources", lambda *_args: "stable")
    pool = provider.create_user_pool(
        context,
        {
            "EmailConfiguration": {
                "EmailSendingAccount": "DEVELOPER",
                "SourceArn": f"arn:aws:ses:us-east-1:{context.account_id}:identity/example.test",
            },
            "PoolName": "email-mfa",
        },
    )["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "password-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "TemporaryPass9!",
            "UserAttributes": [{"Name": "email", "Value": "alice@example.test"}],
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
    configured = provider.set_user_pool_mfa_config(
        context,
        {
            "EmailMfaConfiguration": {
                "Message": "MFA code {####}",
                "Subject": "MFA subject",
            },
            "MfaConfiguration": "OPTIONAL",
            "UserPoolId": pool["Id"],
        },
    )
    assert configured["EmailMfaConfiguration"]["Subject"] == "MFA subject"
    provider.admin_set_user_mfa_preference(
        context,
        {
            "EmailMfaSettings": {"Enabled": True, "PreferredMfa": True},
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    challenge = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )
    assert challenge["ChallengeName"] == "EMAIL_OTP"
    message = sent[-1]["Message"]["Body"]["Text"]["Data"]
    assert message.startswith("MFA code ")
    authenticated = provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "EMAIL_OTP",
            "ChallengeResponses": {
                "EMAIL_OTP_CODE": _code(message),
                "USERNAME": "alice",
            },
            "ClientId": client["ClientId"],
            "Session": challenge["Session"],
        },
    )
    assert authenticated["AuthenticationResult"]["RefreshToken"]
    user = provider.admin_get_user(
        context, {"UserPoolId": pool["Id"], "Username": "alice"}
    )
    assert {item["Name"]: item["Value"] for item in user["UserAttributes"]}[
        "email_verified"
    ] == "true"
