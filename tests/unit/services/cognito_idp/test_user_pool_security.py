import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

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


def _security_configuration(context):
    return {
        "AccountRecoverySetting": {
            "RecoveryMechanisms": [{"Name": "verified_email", "Priority": 1}]
        },
        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
        "AutoVerifiedAttributes": ["email"],
        "EmailVerificationMessage": "The verification code is {####}",
        "EmailVerificationSubject": "Verify your account",
        "LambdaConfig": {
            "PostConfirmation": (
                f"arn:aws:lambda:us-east-1:{context.account_id}:function:post-confirm"
            ),
            "PreTokenGeneration": (
                f"arn:aws:lambda:us-east-1:{context.account_id}:function:pre-token"
            ),
        },
        "MfaConfiguration": "OPTIONAL",
        "Policies": {
            "PasswordPolicy": {
                "MinimumLength": 10,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "RequireUppercase": True,
                "TemporaryPasswordValidityDays": 7,
            }
        },
        "Schema": [
            {"AttributeDataType": "String", "Mutable": False, "Name": "email", "Required": True},
            {"AttributeDataType": "String", "Mutable": True, "Name": "tenantId"},
        ],
        "SmsVerificationMessage": "The verification code is {####}",
        "UsernameAttributes": ["email"],
        "UserPoolTags": {"component": "auth"},
        "VerificationMessageTemplate": {
            "DefaultEmailOption": "CONFIRM_WITH_CODE",
            "EmailMessage": "The verification code is {####}",
            "EmailSubject": "Verify your account",
            "SmsMessage": "The verification code is {####}",
        },
    }


def test_temporary_password_validity_is_persisted_and_enforced(provider, context, monkeypatch):
    clock = [datetime(2026, 1, 1, tzinfo=UTC)]
    monkeypatch.setattr(provider_module, "_now", lambda: clock[0])
    pool = provider.create_user_pool(
        context,
        {
            "PoolName": "temporary-password-expiry",
            "Policies": {"PasswordPolicy": {"TemporaryPasswordValidityDays": 1}},
        },
    )["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "admin-auth",
            "ExplicitAuthFlows": ["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "TemporaryPass9!",
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    described = provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"]
    assert described["Policies"]["PasswordPolicy"]["TemporaryPasswordValidityDays"] == 1

    clock[0] += timedelta(days=1, seconds=1)
    with pytest.raises(CommonServiceException) as expired:
        provider.admin_initiate_auth(
            context,
            {
                "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "PASSWORD": "TemporaryPass9!",
                    "USERNAME": "alice",
                },
                "ClientId": client["ClientId"],
                "UserPoolId": pool["Id"],
            },
        )
    assert expired.value.code == "NotAuthorizedException"

    provider.admin_set_user_password(
        context,
        {
            "Password": "ReplacementPass9!",
            "Permanent": False,
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    challenge = provider.admin_initiate_auth(
        context,
        {
            "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "ReplacementPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
            "UserPoolId": pool["Id"],
        },
    )
    assert challenge["ChallengeName"] == "NEW_PASSWORD_REQUIRED"


def test_native_user_pool_security_configuration_round_trips_and_update_resets(provider, context):
    configuration = _security_configuration(context)
    created = provider.create_user_pool(context, {"PoolName": "billgym-security", **configuration})[
        "UserPool"
    ]

    described = provider.describe_user_pool(context, {"UserPoolId": created["Id"]})["UserPool"]
    for key, value in configuration.items():
        if key == "Schema":
            assert described["SchemaAttributes"] == [
                value[0],
                {**value[1], "Name": "custom:tenantId"},
            ]
        else:
            assert described[key] == value

    before = dict(described)
    with pytest.raises(CommonServiceException) as invalid:
        provider.update_user_pool(
            context,
            {
                "AccountRecoverySetting": {
                    "RecoveryMechanisms": [
                        {"Name": "verified_email", "Priority": 1},
                        {"Name": "verified_phone_number", "Priority": 1},
                    ]
                },
                "PoolName": "must-not-apply",
                "UserPoolId": created["Id"],
            },
        )
    assert invalid.value.code == "InvalidParameterException"
    assert provider.describe_user_pool(context, {"UserPoolId": created["Id"]})["UserPool"] == before

    provider.update_user_pool(context, {"PoolName": "reset-security", "UserPoolId": created["Id"]})
    reset = provider.describe_user_pool(context, {"UserPoolId": created["Id"]})["UserPool"]
    assert reset["Name"] == "reset-security"
    assert reset["AdminCreateUserConfig"] == {"AllowAdminCreateUserOnly": False}
    assert reset["MfaConfiguration"] == "OFF"
    for key in (
        "AccountRecoverySetting",
        "AutoVerifiedAttributes",
        "EmailVerificationMessage",
        "EmailVerificationSubject",
        "LambdaConfig",
        "Policies",
        "SmsVerificationMessage",
        "VerificationMessageTemplate",
    ):
        assert key not in reset or (key == "LambdaConfig" and reset[key] == {})
    assert reset["SchemaAttributes"] == [
        configuration["Schema"][0],
        {**configuration["Schema"][1], "Name": "custom:tenantId"},
    ]
    assert reset["UsernameAttributes"] == ["email"]


def test_password_policy_and_schema_are_enforced_atomically(provider, context):
    pool = provider.create_user_pool(
        context, {"PoolName": "schema-users", **_security_configuration(context)}
    )["UserPool"]

    with pytest.raises(CommonServiceException) as weak:
        provider.admin_create_user(
            context,
            {
                "TemporaryPassword": "weakpass",
                "UserAttributes": [{"Name": "email", "Value": "alice@example.test"}],
                "Username": "alice@example.test",
                "UserPoolId": pool["Id"],
            },
        )
    assert weak.value.code == "InvalidPasswordException"

    with pytest.raises(CommonServiceException) as unknown:
        provider.admin_create_user(
            context,
            {
                "TemporaryPassword": "Temporary9!",
                "UserAttributes": [
                    {"Name": "email", "Value": "alice@example.test"},
                    {"Name": "custom:undeclared", "Value": "x"},
                ],
                "Username": "alice@example.test",
                "UserPoolId": pool["Id"],
            },
        )
    assert unknown.value.code == "InvalidParameterException"

    provider.admin_create_user(
        context,
        {
            "TemporaryPassword": "Temporary9!",
            "UserAttributes": [
                {"Name": "email", "Value": "alice@example.test"},
                {"Name": "custom:tenantId", "Value": "tenant-a"},
            ],
            "Username": "alice@example.test",
            "UserPoolId": pool["Id"],
        },
    )
    with pytest.raises(CommonServiceException) as immutable:
        provider.admin_update_user_attributes(
            context,
            {
                "UserAttributes": [{"Name": "email", "Value": "other@example.test"}],
                "Username": "alice@example.test",
                "UserPoolId": pool["Id"],
            },
        )
    assert immutable.value.code == "InvalidParameterException"
    user = provider.admin_get_user(
        context, {"Username": "alice@example.test", "UserPoolId": pool["Id"]}
    )
    assert {item["Name"]: item["Value"] for item in user["UserAttributes"]}["email"] == (
        "alice@example.test"
    )


class _LambdaClient:
    def __init__(self, calls):
        self.calls = calls

    def invoke(self, **request):
        event = json.loads(request["Payload"])
        self.calls.append((request["FunctionName"], event))
        if request["FunctionName"].endswith(":pre-sign-up"):
            event["response"] = {
                "autoConfirmUser": True,
                "autoVerifyEmail": True,
                "autoVerifyPhone": False,
            }
        if request["FunctionName"].endswith(":pre-token"):
            event["response"] = {
                "claimsOverrideDetails": {
                    "claimsToAddOrOverride": {"custom:tenantId": "tenant-from-trigger"}
                }
            }
        return {"Payload": json.dumps(event).encode(), "StatusCode": 200}


def test_post_confirmation_and_pre_token_generation_invoke_local_lambda_fail_closed(
    provider, context, monkeypatch
):
    calls = []
    lambda_client = _LambdaClient(calls)
    monkeypatch.setattr(
        provider_module,
        "connect_to",
        lambda **_: SimpleNamespace(
            lambda_=SimpleNamespace(request_metadata=lambda **__: lambda_client)
        ),
    )
    monkeypatch.setattr(provider_module, "_verify_user_code", lambda *args, **kwargs: None)
    configuration = _security_configuration(context)
    configuration["AdminCreateUserConfig"] = {"AllowAdminCreateUserOnly": False}
    pool = provider.create_user_pool(context, {"PoolName": "trigger-users", **configuration})[
        "UserPool"
    ]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "trigger-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "Password": "Permanent9!",
            "UserAttributes": [
                {"Name": "email", "Value": "alice@example.test"},
                {"Name": "custom:tenantId", "Value": "tenant-a"},
            ],
            "Username": "alice@example.test",
        },
    )
    provider.confirm_sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "ConfirmationCode": "123456",
            "Username": "alice@example.test",
        },
    )
    authentication = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {
                "PASSWORD": "Permanent9!",
                "USERNAME": "alice@example.test",
            },
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]

    post_event = calls[0][1]
    assert post_event["triggerSource"] == "PostConfirmation_ConfirmSignUp"
    assert post_event["request"]["userAttributes"]["email_verified"] == "true"
    assert calls[1][1]["triggerSource"] == "TokenGeneration_Authentication"
    id_claims = decode_jwt_segment(authentication["IdToken"].split(".")[1])
    assert id_claims["custom:tenantId"] == "tenant-from-trigger"

    lambda_client.invoke = lambda **_: (_ for _ in ()).throw(RuntimeError("lambda down"))
    with pytest.raises(CommonServiceException) as failed:
        provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "PASSWORD": "Permanent9!",
                    "USERNAME": "alice@example.test",
                },
                "ClientId": client["ClientId"],
            },
        )
    assert failed.value.code == "UnexpectedLambdaException"


def test_pool_lifecycle_fields_round_trip_reset_and_delete_protection(provider, context):
    configuration = {
        "DeletionProtection": "ACTIVE",
        "IssuerConfiguration": {"Type": "ORIGINAL"},
        "KeyConfiguration": {"KeyType": "AWS_OWNED_KEY"},
        "Policies": {
            "PasswordPolicy": {
                "PasswordHistorySize": 3,
                "TemporaryPasswordValidityDays": 0,
            }
        },
        "SmsAuthenticationMessage": "Your authentication code is {####}",
        "UserAttributeUpdateSettings": {
            "AttributesRequireVerificationBeforeUpdate": ["email", "phone_number"]
        },
        "UserPoolAddOns": {"AdvancedSecurityMode": "OFF"},
    }
    pool = provider.create_user_pool(
        context, {"PoolName": "lifecycle-security", **configuration}
    )["UserPool"]

    described = provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"]
    for field in (
        "DeletionProtection",
        "IssuerConfiguration",
        "KeyConfiguration",
        "SmsAuthenticationMessage",
        "UserAttributeUpdateSettings",
        "UserPoolAddOns",
    ):
        assert described[field] == configuration[field]
    assert described["Policies"]["PasswordPolicy"] == {
        "PasswordHistorySize": 3,
        "TemporaryPasswordValidityDays": 7,
    }

    with pytest.raises(CommonServiceException) as protected:
        provider.delete_user_pool(context, {"UserPoolId": pool["Id"]})
    assert protected.value.code == "InvalidParameterException"
    assert provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"][
        "Id"
    ] == pool["Id"]

    provider.update_user_pool(
        context,
        {
            "DeletionProtection": "INACTIVE",
            "PoolName": "lifecycle-security",
            "UserPoolId": pool["Id"],
        },
    )
    reset = provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"]
    assert reset["DeletionProtection"] == "INACTIVE"
    for field in (
        "IssuerConfiguration",
        "KeyConfiguration",
        "SmsAuthenticationMessage",
        "UserAttributeUpdateSettings",
        "UserPoolAddOns",
    ):
        assert field not in reset
    provider.delete_user_pool(context, {"UserPoolId": pool["Id"]})


def test_pool_advanced_security_and_updated_issuer_fail_closed_without_mutation(
    provider, context
):
    before = provider.create_user_pool(context, {"PoolName": "fail-closed-security"})[
        "UserPool"
    ]
    for update in (
        {"UserPoolAddOns": {"AdvancedSecurityMode": "AUDIT"}},
        {"IssuerConfiguration": {"Type": "UPDATED"}},
    ):
        with pytest.raises(CommonServiceException) as unavailable:
            provider.update_user_pool(
                context,
                {**update, "UserPoolId": before["Id"]},
            )
        assert unavailable.value.code == "InvalidParameterException"
        assert "not implemented" in unavailable.value.message or "engine" in unavailable.value.message
    after = provider.describe_user_pool(context, {"UserPoolId": before["Id"]})["UserPool"]
    assert after == before


def test_pre_sign_up_receives_validation_metadata_and_applies_auto_confirm_atomically(
    provider, context, monkeypatch
):
    calls = []
    lambda_client = _LambdaClient(calls)
    monkeypatch.setattr(
        provider_module,
        "connect_to",
        lambda **_: SimpleNamespace(
            lambda_=SimpleNamespace(request_metadata=lambda **__: lambda_client)
        ),
    )
    pool = provider.create_user_pool(
        context,
        {
            "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": False},
            "LambdaConfig": {
                "PreSignUp": (
                    f"arn:aws:lambda:{context.region}:{context.account_id}:function:pre-sign-up"
                )
            },
            "PoolName": "pre-sign-up",
        },
    )["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {"ClientName": "web", "UserPoolId": pool["Id"]},
    )["UserPoolClient"]

    response = provider.sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "ClientMetadata": {"surface": "amplify-web"},
            "Password": "PermanentPass9!",
            "UserAttributes": [{"Name": "email", "Value": "alice@example.test"}],
            "Username": "alice",
            "ValidationData": [{"Name": "tenant", "Value": "enterprise"}],
        },
    )

    assert response["UserConfirmed"] is True
    assert "CodeDeliveryDetails" not in response
    event = calls[0][1]
    assert event["triggerSource"] == "PreSignUp_SignUp"
    assert event["request"] == {
        "clientMetadata": {"surface": "amplify-web"},
        "userAttributes": {"email": "alice@example.test"},
        "validationData": {"tenant": "enterprise"},
    }
    user = provider.admin_get_user(
        context, {"UserPoolId": pool["Id"], "Username": "alice"}
    )
    attributes = {item["Name"]: item["Value"] for item in user["UserAttributes"]}
    assert user["UserStatus"] == "CONFIRMED"
    assert attributes["email_verified"] == "true"

    provider.admin_create_user(
        context,
        {
            "ClientMetadata": {"surface": "admin-api"},
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "TemporaryPass9!",
            "UserAttributes": [{"Name": "email", "Value": "bob@example.test"}],
            "UserPoolId": pool["Id"],
            "Username": "bob",
            "ValidationData": [{"Name": "tenant", "Value": "operations"}],
        },
    )
    admin_event = calls[1][1]
    assert admin_event["triggerSource"] == "PreSignUp_AdminCreateUser"
    assert admin_event["request"]["clientMetadata"] == {"surface": "admin-api"}
    assert admin_event["request"]["validationData"] == {"tenant": "operations"}
    assert provider.admin_get_user(
        context, {"UserPoolId": pool["Id"], "Username": "bob"}
    )["UserStatus"] == "FORCE_CHANGE_PASSWORD"


def test_customer_managed_pool_key_is_validated_twice_and_aba_fails_before_create(
    provider, context, monkeypatch
):
    arn = (
        f"arn:aws:kms:{context.region}:{context.account_id}:"
        "key/11111111-2222-3333-4444-555555555555"
    )
    states = iter(("Enabled", "PendingDeletion"))

    class Kms:
        def describe_key(self, **request):
            state = next(states)
            return {
                "KeyMetadata": {
                    "Arn": request["KeyId"],
                    "Enabled": state == "Enabled",
                    "KeyId": "11111111-2222-3333-4444-555555555555",
                    "KeyState": state,
                    "KeyUsage": "ENCRYPT_DECRYPT",
                    "Origin": "AWS_KMS",
                }
            }

    monkeypatch.setattr(provider_module, "connect_to", lambda **_: SimpleNamespace(kms=Kms()))
    with pytest.raises(CommonServiceException) as changed:
        provider.create_user_pool(
            context,
            {
                "KeyConfiguration": {
                    "KeyType": "CUSTOMER_MANAGED_KEY",
                    "KmsKeyArn": arn,
                },
                "PoolName": "kms-aba",
            },
        )
    assert changed.value.code == "InvalidParameterException"
    assert provider.list_user_pools(context, {"MaxResults": 60})["UserPools"] == []


def test_pre_sign_up_configuration_race_fails_without_creating_user(provider, context, monkeypatch):
    pool = provider.create_user_pool(
        context,
        {
            "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": False},
            "LambdaConfig": {
                "PreSignUp": (
                    f"arn:aws:lambda:{context.region}:{context.account_id}:function:pre-sign-up"
                )
            },
            "PoolName": "pre-sign-up-race",
        },
    )["UserPool"]
    client = provider.create_user_pool_client(
        context, {"ClientName": "web", "UserPoolId": pool["Id"]}
    )["UserPoolClient"]

    class RaceLambda:
        def invoke(self, **request):
            provider.update_user_pool(
                context,
                {"PoolName": "changed", "UserPoolId": pool["Id"]},
            )
            return {"Payload": request["Payload"], "StatusCode": 200}

    monkeypatch.setattr(
        provider_module,
        "connect_to",
        lambda **_: SimpleNamespace(
            lambda_=SimpleNamespace(request_metadata=lambda **__: RaceLambda())
        ),
    )

    with pytest.raises(CommonServiceException) as raced:
        provider.sign_up(
            context,
            {
                "ClientId": client["ClientId"],
                "Password": "PermanentPass9!",
                "UserAttributes": [{"Name": "email", "Value": "race@example.test"}],
                "Username": "race",
            },
        )
    assert raced.value.code == "ResourceConflictException"
    assert provider.list_users(context, {"UserPoolId": pool["Id"]})["Users"] == []


def test_password_history_is_enforced_for_admin_and_self_service(provider, context):
    pool = provider.create_user_pool(
        context,
        {
            "Policies": {"PasswordPolicy": {"PasswordHistorySize": 2}},
            "PoolName": "password-history",
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
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": "FirstPermanent9!",
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    with pytest.raises(CommonServiceException) as temporary_reuse:
        provider.admin_set_user_password(
            context,
            {
                "Password": "TemporaryPass9!",
                "Permanent": True,
                "UserPoolId": pool["Id"],
                "Username": "alice",
            },
        )
    assert temporary_reuse.value.code == "PasswordHistoryPolicyViolationException"

    auth = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "FirstPermanent9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]
    provider.change_password(
        context,
        {
            "AccessToken": auth["AccessToken"],
            "PreviousPassword": "FirstPermanent9!",
            "ProposedPassword": "SecondPermanent9!",
        },
    )
    with pytest.raises(CommonServiceException) as self_reuse:
        provider.change_password(
            context,
            {
                "AccessToken": auth["AccessToken"],
                "PreviousPassword": "SecondPermanent9!",
                "ProposedPassword": "FirstPermanent9!",
            },
        )
    assert self_reuse.value.code == "PasswordHistoryPolicyViolationException"
    with cognito_idp_stores.lock:
        user = provider.get_store(context).user_pools[pool["Id"]].users["alice"]
        assert len(user.password_history) == 2
        assert "TemporaryPass9!" not in json.dumps(
            [password.to_dict() for password in user.password_history]
        )
