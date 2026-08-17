import copy
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
)
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpool import (
    CognitoUserPoolProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpool_plugin import (
    CognitoUserPoolProviderPlugin,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolclient import (
    CognitoUserPoolClientProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolclient_plugin import (
    CognitoUserPoolClientProviderPlugin,
)


def _request(*, client, desired_state, previous_state=None):
    return SimpleNamespace(
        account_id=f"{uuid.uuid4().int % 10**12:012d}",
        aws_client_factory=SimpleNamespace(cognito_idp=client),
        custom_context={},
        desired_state=desired_state,
        previous_state=previous_state,
        logical_resource_id="Auth",
        stack_name="enterprise",
        region_name="us-east-1",
    )


def _not_found(operation: str) -> ClientError:
    return ClientError(
        {
            "Error": {
                "Code": "ResourceNotFoundException",
                "Message": "resource does not exist",
            }
        },
        operation,
    )


class _NativeCognitoClient:
    def __init__(self, provider: CognitoIdpProvider, context: RequestContext):
        self.provider = provider
        self.context = context

    def __getattr__(self, name: str):
        handler = getattr(self.provider, name)

        def invoke(**request):
            try:
                return handler(self.context, request)
            except CommonServiceException as error:
                raise ClientError(
                    {"Error": {"Code": error.code, "Message": error.message}},
                    name,
                ) from error

        return invoke


def test_user_pool_schema_is_closed_and_exposes_ref_and_supported_getatts():
    schema = CognitoUserPoolProvider.SCHEMA

    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {
        "AccountRecoverySetting",
        "AdminCreateUserConfig",
        "AliasAttributes",
        "Arn",
        "AutoVerifiedAttributes",
        "DeletionProtection",
        "DeviceConfiguration",
        "EmailAuthenticationMessage",
        "EmailAuthenticationSubject",
        "EmailConfiguration",
        "EmailVerificationMessage",
        "EmailVerificationSubject",
        "EnabledMfas",
        "IssuerConfiguration",
        "KeyConfiguration",
        "LambdaConfig",
        "MfaConfiguration",
        "Policies",
        "ProviderName",
        "ProviderURL",
        "Schema",
        "SmsAuthenticationMessage",
        "SmsConfiguration",
        "SmsVerificationMessage",
        "UserAttributeUpdateSettings",
        "UserPoolAddOns",
        "UserPoolId",
        "UserPoolName",
        "UserPoolTags",
        "UserPoolTier",
        "UsernameAttributes",
        "UsernameConfiguration",
        "VerificationMessageTemplate",
        "WebAuthnFactorConfiguration",
        "WebAuthnRelyingPartyID",
        "WebAuthnUserVerification",
    }
    assert schema["primaryIdentifier"] == ["/properties/UserPoolId"]
    assert set(schema["readOnlyProperties"]) == {
        "/properties/Arn",
        "/properties/ProviderName",
        "/properties/ProviderURL",
        "/properties/UserPoolId",
    }
    assert schema.get("createOnlyProperties", []) == []
    assert schema["tagging"] == {
        "cloudFormationSystemTags": True,
        "tagOnCreate": True,
        "tagProperty": "/properties/UserPoolTags",
        "tagUpdatable": True,
        "taggable": True,
    }
    assert schema["handlers"] == {
        "create": {
            "permissions": [
                "cognito-idp:CreateUserPool",
                "cognito-idp:DeleteUserPool",
                "cognito-idp:SetUserPoolMfaConfig",
            ]
        },
        "read": {
            "permissions": [
                "cognito-idp:DescribeUserPool",
                "cognito-idp:GetUserPoolMfaConfig",
            ]
        },
        "update": {
            "permissions": [
                "cognito-idp:DescribeUserPool",
                "cognito-idp:GetUserPoolMfaConfig",
                "cognito-idp:SetUserPoolMfaConfig",
                "cognito-idp:TagResource",
                "cognito-idp:UntagResource",
                "cognito-idp:AddCustomAttributes",
                "cognito-idp:UpdateUserPool",
            ]
        },
        "delete": {"permissions": ["cognito-idp:DeleteUserPool"]},
        "list": {"permissions": ["cognito-idp:ListUserPools"]},
    }
    properties = schema["properties"]
    recovery = properties["AccountRecoverySetting"]["properties"]["RecoveryMechanisms"]
    assert recovery["maxItems"] == 1
    assert recovery["items"]["properties"]["Name"]["enum"] == ["verified_email"]
    assert recovery["items"]["properties"]["Priority"]["enum"] == [1]
    assert properties["AutoVerifiedAttributes"]["items"]["enum"] == ["email"]
    assert properties["EnabledMfas"]["items"]["enum"] == ["SOFTWARE_TOKEN_MFA"]
    assert set(properties["Policies"]["properties"]["PasswordPolicy"]["properties"]) == {
        "MinimumLength",
        "PasswordHistorySize",
        "RequireLowercase",
        "RequireNumbers",
        "RequireSymbols",
        "RequireUppercase",
        "TemporaryPasswordValidityDays",
    }
    schema_attribute = properties["Schema"]["items"]["properties"]
    assert schema_attribute["AttributeDataType"]["enum"] == [
        "String",
        "Number",
        "DateTime",
        "Boolean",
    ]
    assert set(schema_attribute) == {
        "AttributeDataType",
        "DeveloperOnlyAttribute",
        "Mutable",
        "Name",
        "NumberAttributeConstraints",
        "Required",
        "StringAttributeConstraints",
    }
    assert properties["UsernameAttributes"]["items"]["enum"] == ["email"]
    assert properties["VerificationMessageTemplate"]["properties"]["DefaultEmailOption"][
        "enum"
    ] == ["CONFIRM_WITH_CODE"]


def test_resource_provider_plugins_load_the_expected_factories():
    pool_plugin = CognitoUserPoolProviderPlugin()
    client_plugin = CognitoUserPoolClientProviderPlugin()

    pool_plugin.load()
    client_plugin.load()

    assert pool_plugin.factory is CognitoUserPoolProvider
    assert client_plugin.factory is CognitoUserPoolClientProvider


def test_user_pool_create_generates_name_and_does_not_mutate_desired_state(monkeypatch):
    client = MagicMock()
    client.create_user_pool.return_value = {
        "UserPool": {
            "Arn": "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool",
            "Id": "us-east-1_pool",
            "Name": "enterprise-Auth-generated",
        }
    }
    desired = {}
    original = copy.deepcopy(desired)
    monkeypatch.setattr(
        "localstack.services.cognito_idp.resource_providers.aws_cognito_userpool.util.generate_default_name",
        lambda stack_name, logical_resource_id: "enterprise-Auth-generated",
    )

    result = CognitoUserPoolProvider().create(_request(client=client, desired_state=desired))

    assert result.status == OperationStatus.SUCCESS
    assert desired == original
    assert result.resource_model == {
        "Arn": "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool",
        "ProviderName": "cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
        "ProviderURL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
        "UserPoolId": "us-east-1_pool",
        "UserPoolName": "enterprise-Auth-generated",
    }
    client.create_user_pool.assert_called_once_with(PoolName="enterprise-Auth-generated")


def test_user_pool_maps_billgym_security_contract_without_mutation():
    client = MagicMock()
    desired = {
        "AccountRecoverySetting": {
            "RecoveryMechanisms": [{"Name": "verified_email", "Priority": 1}]
        },
        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
        "AutoVerifiedAttributes": ["email"],
        "EmailVerificationMessage": "The verification code is {####}",
        "EmailVerificationSubject": "Verify your account",
        "EnabledMfas": ["SOFTWARE_TOKEN_MFA"],
        "LambdaConfig": {
            "PostConfirmation": "arn:aws:lambda:us-east-1:000000000000:function:post",
            "PreTokenGeneration": "arn:aws:lambda:us-east-1:000000000000:function:pre",
        },
        "MfaConfiguration": "OPTIONAL",
        "Policies": {
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "RequireUppercase": True,
            }
        },
        "Schema": [
            {"Mutable": False, "Name": "email", "Required": True},
            {
                "AttributeDataType": "String",
                "Mutable": True,
                "Name": "tenantId",
            },
        ],
        "SmsVerificationMessage": "The verification code is {####}",
        "UserPoolName": "billgym-prod-userpool",
        "UserPoolTags": {"component": "auth", "project": "billgym"},
        "UsernameAttributes": ["email"],
        "VerificationMessageTemplate": {
            "DefaultEmailOption": "CONFIRM_WITH_CODE",
            "EmailMessage": "The verification code is {####}",
            "EmailSubject": "Verify your account",
            "SmsMessage": "The verification code is {####}",
        },
    }
    original = copy.deepcopy(desired)
    client.create_user_pool.return_value = {
        "UserPool": {
            "Arn": "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool",
            "Id": "us-east-1_pool",
            "Name": desired["UserPoolName"],
            **{
                ("SchemaAttributes" if key == "Schema" else key): value
                for key, value in desired.items()
                if key != "UserPoolName"
            },
        }
    }

    result = CognitoUserPoolProvider().create(_request(client=client, desired_state=desired))

    assert result.status == OperationStatus.SUCCESS
    assert desired == original
    client.create_user_pool.assert_called_once_with(
        PoolName="billgym-prod-userpool",
        **{
            key: value
            for key, value in desired.items()
            if key not in {"EnabledMfas", "MfaConfiguration", "UserPoolName"}
        },
    )
    client.set_user_pool_mfa_config.assert_called_once_with(
        MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
        UserPoolId="us-east-1_pool",
    )
    assert result.resource_model == {
        **desired,
        "Arn": "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool",
        "ProviderName": "cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
        "ProviderURL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
        "UserPoolId": "us-east-1_pool",
    }


def test_user_pool_create_preserves_primary_and_failed_cleanup_errors():
    client = MagicMock()
    client.create_user_pool.return_value = {
        "UserPool": {
            "Arn": "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_orphan",
            "Id": "us-east-1_orphan",
            "Name": "orphan",
        }
    }
    primary = RuntimeError("set MFA failed")
    client.set_user_pool_mfa_config.side_effect = primary
    client.delete_user_pool.side_effect = RuntimeError("cleanup failed")

    with pytest.raises(RuntimeError, match="set MFA failed") as raised:
        CognitoUserPoolProvider().create(
            _request(
                client=client,
                desired_state={
                    "EnabledMfas": ["SOFTWARE_TOKEN_MFA"],
                    "MfaConfiguration": "OPTIONAL",
                    "UserPoolName": "orphan",
                },
            )
        )

    assert raised.value is primary
    assert raised.value.__notes__ == [
        "CreateUserPool rollback failed for us-east-1_orphan: RuntimeError: cleanup failed"
    ]
    client.delete_user_pool.assert_called_once_with(UserPoolId="us-east-1_orphan")


def test_user_pool_cfn_security_contract_round_trips_against_native_provider():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    native_provider = CognitoIdpProvider()
    native_client = _NativeCognitoClient(native_provider, context)
    desired = {
        "AccountRecoverySetting": {
            "RecoveryMechanisms": [{"Name": "verified_email", "Priority": 1}]
        },
        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
        "AutoVerifiedAttributes": ["email"],
        "EmailVerificationMessage": "The verification code is {####}",
        "EmailVerificationSubject": "Verify your account",
        "EnabledMfas": ["SOFTWARE_TOKEN_MFA"],
        "MfaConfiguration": "OPTIONAL",
        "Policies": {
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "RequireUppercase": True,
            }
        },
        "Schema": [
            {"Mutable": False, "Name": "email", "Required": True},
            {"AttributeDataType": "String", "Mutable": True, "Name": "tenantId"},
        ],
        "SmsVerificationMessage": "The verification code is {####}",
        "UserPoolName": "billgym-prod-userpool",
        "UserPoolTags": {"component": "auth", "project": "billgym"},
        "UsernameAttributes": ["email"],
        "VerificationMessageTemplate": {
            "DefaultEmailOption": "CONFIRM_WITH_CODE",
            "EmailMessage": "The verification code is {####}",
            "EmailSubject": "Verify your account",
            "SmsMessage": "The verification code is {####}",
        },
    }
    resource_provider = CognitoUserPoolProvider()
    pool_id = None

    try:
        created = resource_provider.create(_request(client=native_client, desired_state=desired))
        assert created.status == OperationStatus.SUCCESS
        pool_id = created.resource_model["UserPoolId"]
        assert created.resource_model == {
            **desired,
            "Arn": created.resource_model["Arn"],
            "ProviderName": created.resource_model["ProviderName"],
            "ProviderURL": created.resource_model["ProviderURL"],
            "UserPoolId": pool_id,
            "UsernameConfiguration": {"CaseSensitive": True},
        }

        read = resource_provider.read(
            _request(client=native_client, desired_state={"UserPoolId": pool_id})
        )
        assert read.status == OperationStatus.SUCCESS
        assert read.resource_model == created.resource_model
    finally:
        if pool_id is not None:
            native_provider.delete_user_pool(context, {"UserPoolId": pool_id})
        with cognito_idp_stores.lock:
            cognito_idp_stores.pop(context.account_id, None)


def test_user_pool_cfn_schema_addition_preserves_pool_and_existing_users():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    native_provider = CognitoIdpProvider()
    native_client = _NativeCognitoClient(native_provider, context)
    resource_provider = CognitoUserPoolProvider()
    pool_id = None

    try:
        created = resource_provider.create(
            _request(
                client=native_client,
                desired_state={"UserPoolName": "schema-update-users"},
            )
        )
        pool_id = created.resource_model["UserPoolId"]
        native_provider.admin_create_user(
            context,
            {
                "MessageAction": "SUPPRESS",
                "TemporaryPassword": "Temporary9!",
                "UserPoolId": pool_id,
                "Username": "existing",
            },
        )
        addition = {
            "AttributeDataType": "String",
            "Mutable": True,
            "Name": "tenantId",
            "StringAttributeConstraints": {"MaxLength": "64", "MinLength": "1"},
        }
        desired = {**created.resource_model, "Schema": [addition]}

        updated = resource_provider.update(
            _request(
                client=native_client,
                desired_state=desired,
                previous_state=created.resource_model,
            )
        )

        assert updated.status == OperationStatus.SUCCESS
        assert updated.resource_model["UserPoolId"] == pool_id
        assert updated.resource_model["Schema"] == [addition]
        assert (
            native_provider.admin_get_user(
                context, {"UserPoolId": pool_id, "Username": "existing"}
            )["Username"]
            == "existing"
        )
    finally:
        if pool_id is not None:
            native_provider.delete_user_pool(context, {"UserPoolId": pool_id})
        with cognito_idp_stores.lock:
            cognito_idp_stores.pop(context.account_id, None)


def test_user_pool_read_maps_supported_state_and_not_found_is_explicit():
    client = MagicMock()
    client.describe_user_pool.return_value = {
        "UserPool": {
            "Arn": "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool",
            "Id": "us-east-1_pool",
            "Name": "auth-pool",
        }
    }
    provider = CognitoUserPoolProvider()

    result = provider.read(_request(client=client, desired_state={"UserPoolId": "us-east-1_pool"}))

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model["UserPoolName"] == "auth-pool"
    client.describe_user_pool.side_effect = _not_found("DescribeUserPool")

    missing = provider.read(
        _request(client=client, desired_state={"UserPoolId": "us-east-1_missing"})
    )

    assert missing.status == OperationStatus.FAILED
    assert missing.error_code == "NotFound"


def test_user_pool_getatts_use_the_partition_dns_suffix():
    client = MagicMock()
    client.describe_user_pool.return_value = {
        "UserPool": {
            "Arn": "arn:aws-cn:cognito-idp:cn-north-1:000000000000:userpool/cn-north-1_pool",
            "Id": "cn-north-1_pool",
            "Name": "auth-pool",
        }
    }

    result = CognitoUserPoolProvider().read(
        _request(client=client, desired_state={"UserPoolId": "cn-north-1_pool"})
    )

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model["ProviderName"] == (
        "cognito-idp.cn-north-1.amazonaws.com.cn/cn-north-1_pool"
    )
    assert result.resource_model["ProviderURL"] == (
        "https://cognito-idp.cn-north-1.amazonaws.com.cn/cn-north-1_pool"
    )


def test_user_pool_update_renames_without_replacement():
    client = MagicMock()
    client.describe_user_pool.return_value = {
        "UserPool": {
            "Arn": "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool",
            "Id": "us-east-1_pool",
            "Name": "auth-pool",
        }
    }
    previous = {"UserPoolId": "us-east-1_pool", "UserPoolName": "auth-pool"}
    provider = CognitoUserPoolProvider()

    unchanged = provider.update(_request(client=client, desired_state={}, previous_state=previous))

    assert unchanged.status == OperationStatus.SUCCESS
    client.describe_user_pool.assert_called_once_with(UserPoolId="us-east-1_pool")

    client.reset_mock()
    client.update_user_pool.return_value = {}
    client.describe_user_pool.return_value["UserPool"]["Name"] = "renamed"
    rename_request = _request(
        client=client,
        desired_state={"UserPoolName": "renamed"},
        previous_state=previous,
    )
    rename_request.custom_context = {"marker": "preserved"}
    renamed = provider.update(rename_request)

    assert renamed.status == OperationStatus.SUCCESS
    assert renamed.custom_context == {"marker": "preserved"}
    assert renamed.resource_model["UserPoolId"] == "us-east-1_pool"
    assert renamed.resource_model["UserPoolName"] == "renamed"
    client.update_user_pool.assert_called_once_with(PoolName="renamed", UserPoolId="us-east-1_pool")


def test_user_pool_update_rejects_unsupported_username_attribute_change_without_mutation():
    client = MagicMock()
    previous = {
        "UserPoolId": "us-east-1_pool",
        "UserPoolName": "auth-pool",
        "UsernameAttributes": ["email"],
    }
    request = _request(
        client=client,
        desired_state={"UserPoolName": "auth-pool"},
        previous_state=previous,
    )
    request.custom_context = {"marker": "preserved"}

    result = CognitoUserPoolProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert "UsernameAttributes" in result.message
    client.update_user_pool.assert_not_called()


def test_user_pool_update_reports_primary_and_incomplete_rollback_errors():
    client = MagicMock()
    primary = RuntimeError("tag failed")
    client.update_user_pool.side_effect = [None, RuntimeError("restore update failed")]
    client.tag_resource.side_effect = primary
    previous = {
        "Arn": "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool",
        "UserPoolId": "us-east-1_pool",
        "UserPoolName": "auth-pool",
        "UserPoolTags": {},
    }

    with pytest.raises(RuntimeError, match="tag failed") as raised:
        CognitoUserPoolProvider().update(
            _request(
                client=client,
                desired_state={
                    "Arn": previous["Arn"],
                    "UserPoolId": previous["UserPoolId"],
                    "UserPoolName": previous["UserPoolName"],
                    "UserPoolTags": {"env": "prod"},
                },
                previous_state=previous,
            )
        )

    assert raised.value is primary
    assert raised.value.__notes__ == [
        "UpdateUserPool rollback failed for us-east-1_pool: RuntimeError: restore update failed"
    ]


def test_user_pool_update_adds_schema_without_replacing_pool_and_normalizes_api_prefixes():
    client = MagicMock()
    arn = "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool"
    previous = {
        "Arn": arn,
        "Schema": [
            {"AttributeDataType": "String", "Mutable": False, "Name": "email", "Required": True},
            {"AttributeDataType": "String", "Mutable": True, "Name": "tenantId"},
        ],
        "UserPoolId": "us-east-1_pool",
        "UserPoolName": "auth-pool",
    }
    addition = {
        "AttributeDataType": "Number",
        "Mutable": True,
        "Name": "score",
        "NumberAttributeConstraints": {"MaxValue": "10", "MinValue": "0"},
    }
    desired = {**previous, "Schema": [*previous["Schema"], addition]}
    client.describe_user_pool.return_value = {
        "UserPool": {
            "Arn": arn,
            "Id": "us-east-1_pool",
            "Name": "auth-pool",
            "SchemaAttributes": [
                previous["Schema"][0],
                {**previous["Schema"][1], "Name": "custom:tenantId"},
            ],
        }
    }
    client.get_user_pool_mfa_config.return_value = {
        "MfaConfiguration": "OFF",
        "SoftwareTokenMfaConfiguration": {"Enabled": False},
    }

    result = CognitoUserPoolProvider().update(
        _request(client=client, desired_state=desired, previous_state=previous)
    )

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model["Schema"] == desired["Schema"]
    client.add_custom_attributes.assert_called_once_with(
        CustomAttributes=[addition], UserPoolId="us-east-1_pool"
    )
    client.delete_user_pool.assert_not_called()


def test_user_pool_schema_add_response_lost_reconciles_applied_state_to_success():
    client = MagicMock()
    arn = "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool"
    previous = {
        "Arn": arn,
        "Schema": [{"AttributeDataType": "String", "Name": "existing"}],
        "UserPoolId": "us-east-1_pool",
        "UserPoolName": "auth-pool",
    }
    addition = {"AttributeDataType": "Boolean", "Mutable": True, "Name": "enabled"}
    desired = {**previous, "Schema": [*previous["Schema"], addition]}
    before = {
        "Arn": arn,
        "Id": "us-east-1_pool",
        "Name": "auth-pool",
        "SchemaAttributes": [{"AttributeDataType": "String", "Name": "custom:existing"}],
    }
    after = {
        **before,
        "SchemaAttributes": [
            *before["SchemaAttributes"],
            {**addition, "Name": "custom:enabled"},
        ],
    }
    client.describe_user_pool.side_effect = [{"UserPool": before}, {"UserPool": after}]
    client.get_user_pool_mfa_config.return_value = {
        "MfaConfiguration": "OFF",
        "SoftwareTokenMfaConfiguration": {"Enabled": False},
    }
    client.add_custom_attributes.side_effect = TimeoutError("response lost")

    result = CognitoUserPoolProvider().update(
        _request(client=client, desired_state=desired, previous_state=previous)
    )

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model["Schema"] == desired["Schema"]
    assert client.update_user_pool.call_count == 1


def test_user_pool_schema_add_partial_observation_fails_without_unsafe_rollback():
    client = MagicMock()
    arn = "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool"
    previous = {
        "Arn": arn,
        "UserPoolId": "us-east-1_pool",
        "UserPoolName": "auth-pool",
    }
    additions = [
        {"AttributeDataType": "String", "Name": "first"},
        {"AttributeDataType": "String", "Name": "second"},
    ]
    desired = {**previous, "Schema": additions}
    before = {"Arn": arn, "Id": "us-east-1_pool", "Name": "auth-pool"}
    partial = {
        **before,
        "SchemaAttributes": [
            {**additions[0], "Name": "custom:first"},
        ],
    }
    client.describe_user_pool.side_effect = [{"UserPool": before}, {"UserPool": partial}]
    client.get_user_pool_mfa_config.return_value = {
        "MfaConfiguration": "OFF",
        "SoftwareTokenMfaConfiguration": {"Enabled": False},
    }
    client.add_custom_attributes.side_effect = TimeoutError("response lost")

    with pytest.raises(RuntimeError, match="indeterminate schema update"):
        CognitoUserPoolProvider().update(
            _request(client=client, desired_state=desired, previous_state=previous)
        )

    assert client.update_user_pool.call_count == 1
    assert client.set_user_pool_mfa_config.call_count == 1


def test_user_pool_schema_add_observed_absent_rolls_back_reversible_updates():
    client = MagicMock()
    arn = "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool"
    previous = {
        "Arn": arn,
        "UserPoolId": "us-east-1_pool",
        "UserPoolName": "auth-pool",
    }
    desired = {
        **previous,
        "Schema": [{"AttributeDataType": "String", "Name": "absent"}],
    }
    unchanged = {"Arn": arn, "Id": "us-east-1_pool", "Name": "auth-pool"}
    client.describe_user_pool.side_effect = [
        {"UserPool": unchanged},
        {"UserPool": unchanged},
    ]
    client.get_user_pool_mfa_config.return_value = {
        "MfaConfiguration": "OFF",
        "SoftwareTokenMfaConfiguration": {"Enabled": False},
    }
    client.add_custom_attributes.side_effect = TimeoutError("not applied")

    with pytest.raises(TimeoutError, match="not applied"):
        CognitoUserPoolProvider().update(
            _request(client=client, desired_state=desired, previous_state=previous)
        )

    assert client.update_user_pool.call_count == 2
    assert client.set_user_pool_mfa_config.call_count == 2


@pytest.mark.parametrize(
    "desired_schema",
    [
        [{"AttributeDataType": "String", "Mutable": True, "Name": "email"}],
        [],
    ],
)
def test_user_pool_update_rejects_schema_mutation_or_removal_before_api_calls(desired_schema):
    client = MagicMock()
    previous = {
        "Schema": [
            {"AttributeDataType": "String", "Mutable": False, "Name": "email"},
        ],
        "UserPoolId": "us-east-1_pool",
        "UserPoolName": "auth-pool",
    }

    result = CognitoUserPoolProvider().update(
        _request(
            client=client,
            desired_state={**previous, "Schema": desired_schema},
            previous_state=previous,
        )
    )

    assert result.status == OperationStatus.FAILED
    assert "Schema" in result.message
    client.update_user_pool.assert_not_called()
    client.add_custom_attributes.assert_not_called()


def test_user_pool_delete_is_idempotent_and_list_returns_identifiers():
    client = MagicMock()
    provider = CognitoUserPoolProvider()
    request = _request(client=client, desired_state={"UserPoolId": "us-east-1_pool"})

    deleted = provider.delete(request)

    assert deleted.status == OperationStatus.SUCCESS
    client.delete_user_pool.assert_called_once_with(UserPoolId="us-east-1_pool")

    client.delete_user_pool.side_effect = _not_found("DeleteUserPool")
    repeated = provider.delete(request)

    assert repeated.status == OperationStatus.SUCCESS

    client.list_user_pools.return_value = {
        "UserPools": [
            {"Id": "us-east-1_b", "Name": "b"},
            {"Id": "us-east-1_a", "Name": "a"},
        ]
    }
    listed = provider.list(_request(client=client, desired_state={}))

    assert listed.status == OperationStatus.SUCCESS
    assert listed.resource_models == [
        {"UserPoolId": "us-east-1_a", "UserPoolName": "a"},
        {"UserPoolId": "us-east-1_b", "UserPoolName": "b"},
    ]
    client.list_user_pools.assert_called_once_with(MaxResults=60)


def test_user_pool_list_accepts_an_exact_full_final_page():
    client = MagicMock()
    client.list_user_pools.return_value = {
        "UserPools": [
            {"Id": f"us-east-1_{index:02d}", "Name": f"pool-{index:02d}"} for index in range(60)
        ]
    }

    result = CognitoUserPoolProvider().list(_request(client=client, desired_state={}))

    assert result.status == OperationStatus.SUCCESS
    assert len(result.resource_models) == 60


def test_user_pool_client_schema_is_closed_and_marks_unupdatable_fields_create_only():
    schema = CognitoUserPoolClientProvider.SCHEMA

    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {
        "AccessTokenValidity",
        "AllowedOAuthFlows",
        "AllowedOAuthFlowsUserPoolClient",
        "AllowedOAuthScopes",
        "AnalyticsConfiguration",
        "AuthSessionValidity",
        "CallbackURLs",
        "ClientId",
        "ClientName",
        "ClientSecret",
        "DefaultRedirectURI",
        "EnableTokenRevocation",
        "EnablePropagateAdditionalUserContextData",
        "ExplicitAuthFlows",
        "GenerateSecret",
        "IdTokenValidity",
        "LogoutURLs",
        "Name",
        "PreventUserExistenceErrors",
        "ReadAttributes",
        "RefreshTokenValidity",
        "RefreshTokenRotation",
        "SupportedIdentityProviders",
        "TokenValidityUnits",
        "UserPoolId",
        "WriteAttributes",
    }
    assert schema["primaryIdentifier"] == [
        "/properties/UserPoolId",
        "/properties/ClientId",
    ]
    assert set(schema["createOnlyProperties"]) == {
        "/properties/GenerateSecret",
        "/properties/UserPoolId",
    }
    assert set(schema["readOnlyProperties"]) == {
        "/properties/ClientId",
        "/properties/ClientSecret",
        "/properties/Name",
    }


def test_user_pool_client_maps_billgym_amplify_contract_without_mutation():
    client = MagicMock()
    desired = {
        "AccessTokenValidity": 60,
        "AllowedOAuthFlows": ["implicit", "code"],
        "AllowedOAuthFlowsUserPoolClient": True,
        "AllowedOAuthScopes": [
            "profile",
            "phone",
            "email",
            "openid",
            "aws.cognito.signin.user.admin",
        ],
        "CallbackURLs": ["https://app.example.test/auth/callback"],
        "ClientName": "billgym-web",
        "EnableTokenRevocation": True,
        "ExplicitAuthFlows": ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        "GenerateSecret": False,
        "IdTokenValidity": 60,
        "PreventUserExistenceErrors": "ENABLED",
        "ReadAttributes": [
            "custom:tenantId",
            "email",
            "email_verified",
            "name",
        ],
        "RefreshTokenValidity": 43200,
        "SupportedIdentityProviders": ["COGNITO"],
        "TokenValidityUnits": {
            "AccessToken": "minutes",
            "IdToken": "minutes",
            "RefreshToken": "minutes",
        },
        "UserPoolId": "us-east-1_pool",
        "WriteAttributes": ["email", "name", "preferred_username"],
    }
    original = copy.deepcopy(desired)
    client.create_user_pool_client.return_value = {
        "UserPoolClient": {
            **desired,
            "ClientId": "client-id",
        }
    }

    result = CognitoUserPoolClientProvider().create(_request(client=client, desired_state=desired))

    assert result.status == OperationStatus.SUCCESS
    assert desired == original
    client.create_user_pool_client.assert_called_once_with(
        **{key: value for key, value in desired.items() if key != "GenerateSecret"},
        GenerateSecret=False,
    )
    assert result.resource_model == {
        **desired,
        "ClientId": "client-id",
        "Name": "billgym-web",
    }


def test_user_pool_client_cfn_contract_round_trips_against_native_provider():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    native_provider = CognitoIdpProvider()
    native_client = _NativeCognitoClient(native_provider, context)
    pool = native_provider.create_user_pool(context, {"PoolName": "cfn-native-users"})["UserPool"]
    desired = {
        "AccessTokenValidity": 60,
        "AllowedOAuthFlows": ["implicit", "code"],
        "AllowedOAuthFlowsUserPoolClient": True,
        "AllowedOAuthScopes": ["openid", "email", "profile"],
        "CallbackURLs": ["https://app.example.test/auth/callback"],
        "ClientName": "billgym-web",
        "ExplicitAuthFlows": ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        "GenerateSecret": False,
        "IdTokenValidity": 60,
        "PreventUserExistenceErrors": "ENABLED",
        "ReadAttributes": ["custom:tenantId", "email", "email_verified", "name"],
        "RefreshTokenValidity": 43200,
        "SupportedIdentityProviders": ["COGNITO"],
        "TokenValidityUnits": {
            "AccessToken": "minutes",
            "IdToken": "minutes",
            "RefreshToken": "minutes",
        },
        "UserPoolId": pool["Id"],
        "WriteAttributes": ["email", "name", "preferred_username"],
    }
    resource_provider = CognitoUserPoolClientProvider()

    try:
        created = resource_provider.create(_request(client=native_client, desired_state=desired))
        assert created.status == OperationStatus.SUCCESS
        assert created.resource_model["WriteAttributes"] == desired["WriteAttributes"]
        assert created.resource_model["TokenValidityUnits"] == desired["TokenValidityUnits"]

        updated = resource_provider.update(
            _request(
                client=native_client,
                desired_state={"ClientName": "billgym-mobile", "UserPoolId": pool["Id"]},
                previous_state=created.resource_model,
            )
        )
        assert updated.status == OperationStatus.SUCCESS
        assert updated.resource_model["ExplicitAuthFlows"] == [
            "ALLOW_CUSTOM_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_SRP_AUTH",
        ]
        assert "ReadAttributes" not in updated.resource_model
        assert "WriteAttributes" not in updated.resource_model

        read = resource_provider.read(
            _request(
                client=native_client,
                desired_state={
                    "ClientId": updated.resource_model["ClientId"],
                    "UserPoolId": pool["Id"],
                },
            )
        )
        assert read.status == OperationStatus.SUCCESS
        assert read.resource_model == updated.resource_model

        deleted = resource_provider.delete(
            _request(client=native_client, desired_state=read.resource_model)
        )
        assert deleted.status == OperationStatus.SUCCESS
        repeated = resource_provider.delete(
            _request(client=native_client, desired_state=read.resource_model)
        )
        assert repeated.status == OperationStatus.SUCCESS
    finally:
        try:
            native_provider.delete_user_pool(context, {"UserPoolId": pool["Id"]})
        finally:
            with cognito_idp_stores.lock:
                cognito_idp_stores.pop(context.account_id, None)


def test_user_pool_client_physical_id_and_ref_remain_the_client_id():
    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")

    physical_id = executor.extract_physical_resource_id_from_model_with_schema(
        {"ClientId": "client-id", "UserPoolId": "pool-id"},
        CognitoUserPoolClientProvider.TYPE,
        CognitoUserPoolClientProvider.SCHEMA,
    )

    assert physical_id == "client-id"


def test_user_pool_client_create_maps_only_supported_fields_without_mutation(monkeypatch):
    client = MagicMock()
    client.create_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientId": "client-id",
            "ClientName": "enterprise-Client-generated",
            "ClientSecret": "client-secret",
            "ExplicitAuthFlows": [
                "ALLOW_REFRESH_TOKEN_AUTH",
                "ALLOW_USER_PASSWORD_AUTH",
            ],
            "UserPoolId": "us-east-1_pool",
        }
    }
    desired = {
        "ExplicitAuthFlows": [
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
        ],
        "GenerateSecret": True,
        "UserPoolId": "us-east-1_pool",
    }
    original = copy.deepcopy(desired)
    monkeypatch.setattr(
        "localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolclient.util.generate_default_name",
        lambda stack_name, logical_resource_id: "enterprise-Client-generated",
    )

    result = CognitoUserPoolClientProvider().create(_request(client=client, desired_state=desired))

    assert result.status == OperationStatus.SUCCESS
    assert desired == original
    assert result.resource_model == {
        **desired,
        "ClientId": "client-id",
        "ClientName": "enterprise-Client-generated",
        "ClientSecret": "client-secret",
        "Name": "enterprise-Client-generated",
    }
    client.create_user_pool_client.assert_called_once_with(
        ClientName="enterprise-Client-generated",
        ExplicitAuthFlows=[
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
        ],
        GenerateSecret=True,
        UserPoolId="us-east-1_pool",
    )


def test_user_pool_client_read_maps_supported_state_and_not_found_is_explicit():
    client = MagicMock()
    client.describe_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientId": "client-id",
            "ClientName": "web",
            "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
            "UserPoolId": "us-east-1_pool",
        }
    }
    provider = CognitoUserPoolClientProvider()

    result = provider.read(
        _request(
            client=client,
            desired_state={"ClientId": "client-id", "UserPoolId": "us-east-1_pool"},
        )
    )

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model["GenerateSecret"] is False
    client.describe_user_pool_client.side_effect = _not_found("DescribeUserPoolClient")

    missing = provider.read(
        _request(
            client=client,
            desired_state={"ClientId": "missing", "UserPoolId": "us-east-1_pool"},
        )
    )

    assert missing.status == OperationStatus.FAILED
    assert missing.error_code == "NotFound"


def test_user_pool_client_update_reconciles_supported_mutable_fields_without_mutation():
    client = MagicMock()
    client.update_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientId": "client-id",
            "ClientName": "mobile",
            "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
            "UserPoolId": "us-east-1_pool",
        }
    }
    previous = {
        "ClientId": "client-id",
        "ClientName": "web",
        "ExplicitAuthFlows": [
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
        ],
        "GenerateSecret": False,
        "UserPoolId": "us-east-1_pool",
    }
    desired = {"ClientName": "mobile", "UserPoolId": "us-east-1_pool"}
    original = copy.deepcopy(desired)

    result = CognitoUserPoolClientProvider().update(
        _request(client=client, desired_state=desired, previous_state=previous)
    )

    assert result.status == OperationStatus.SUCCESS
    assert desired == original
    client.update_user_pool_client.assert_called_once_with(
        ClientId="client-id",
        ClientName="mobile",
        ExplicitAuthFlows=[
            "ALLOW_CUSTOM_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_SRP_AUTH",
        ],
        UserPoolId="us-east-1_pool",
    )


def test_user_pool_client_rotation_round_trips_and_resets_on_omit_without_mutation():
    client = MagicMock()
    client.update_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientId": "client-id",
            "ClientName": "mobile",
            "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_SRP_AUTH"],
            "RefreshTokenRotation": {
                "Feature": "DISABLED",
                "RetryGracePeriodSeconds": 0,
            },
            "UserPoolId": "us-east-1_pool",
        }
    }
    previous = {
        "ClientId": "client-id",
        "ClientName": "mobile",
        "RefreshTokenRotation": {
            "Feature": "ENABLED",
            "RetryGracePeriodSeconds": 15,
        },
        "UserPoolId": "us-east-1_pool",
    }
    desired = {"ClientName": "mobile", "UserPoolId": "us-east-1_pool"}
    original = copy.deepcopy(desired)

    result = CognitoUserPoolClientProvider().update(
        _request(client=client, desired_state=desired, previous_state=previous)
    )

    assert result.status == OperationStatus.SUCCESS
    assert desired == original
    client.update_user_pool_client.assert_called_once_with(
        ClientId="client-id",
        ClientName="mobile",
        RefreshTokenRotation={"Feature": "DISABLED", "RetryGracePeriodSeconds": 0},
        UserPoolId="us-east-1_pool",
    )


def test_user_pool_client_update_rejects_create_only_change_before_api_call():
    client = MagicMock()
    previous = {
        "ClientId": "client-id",
        "ClientName": "web",
        "GenerateSecret": False,
        "UserPoolId": "us-east-1_pool",
    }

    result = CognitoUserPoolClientProvider().update(
        _request(
            client=client,
            desired_state={
                "ClientName": "web",
                "GenerateSecret": True,
                "UserPoolId": "us-east-1_pool",
            },
            previous_state=previous,
        )
    )

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "InvalidRequest"
    client.assert_not_called()

    removed = CognitoUserPoolClientProvider().update(
        _request(
            client=client,
            desired_state={
                "ClientName": "web",
                "UserPoolId": "us-east-1_pool",
            },
            previous_state=previous | {"GenerateSecret": True},
        )
    )
    assert removed.status == OperationStatus.FAILED
    assert "GenerateSecret" in removed.message
    client.assert_not_called()


def test_user_pool_client_unchanged_update_reads_current_state_without_writing():
    client = MagicMock()
    client.describe_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientId": "client-id",
            "ClientName": "web",
            "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
            "UserPoolId": "us-east-1_pool",
        }
    }
    previous = {
        "ClientId": "client-id",
        "ClientName": "web",
        "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
        "GenerateSecret": False,
        "UserPoolId": "us-east-1_pool",
    }

    result = CognitoUserPoolClientProvider().update(
        _request(
            client=client,
            desired_state={
                "ClientName": "web",
                "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
                "UserPoolId": "us-east-1_pool",
            },
            previous_state=previous,
        )
    )

    assert result.status == OperationStatus.SUCCESS
    client.describe_user_pool_client.assert_called_once_with(
        ClientId="client-id", UserPoolId="us-east-1_pool"
    )
    client.update_user_pool_client.assert_not_called()


def test_resource_providers_fail_closed_on_unsupported_properties():
    client = MagicMock()

    pool_result = CognitoUserPoolProvider().create(
        _request(
            client=client,
            desired_state={"WebAuthnFactorConfiguration": {"RelyingPartyId": "unsupported"}},
        )
    )
    client_result = CognitoUserPoolClientProvider().create(
        _request(
            client=client,
            desired_state={
                "UnsupportedProperty": "not-implemented",
                "UserPoolId": "us-east-1_pool",
            },
        )
    )

    assert pool_result.status == OperationStatus.FAILED
    assert pool_result.error_code == "InvalidRequest"
    assert client_result.status == OperationStatus.FAILED
    assert client_result.error_code == "InvalidRequest"
    client.assert_not_called()


def test_user_pool_client_delete_is_idempotent_and_list_returns_composite_state():
    client = MagicMock()
    provider = CognitoUserPoolClientProvider()
    request = _request(
        client=client,
        desired_state={"ClientId": "client-id", "UserPoolId": "us-east-1_pool"},
    )

    deleted = provider.delete(request)

    assert deleted.status == OperationStatus.SUCCESS
    client.delete_user_pool_client.assert_called_once_with(
        ClientId="client-id", UserPoolId="us-east-1_pool"
    )

    client.delete_user_pool_client.side_effect = _not_found("DeleteUserPoolClient")
    repeated = provider.delete(request)

    assert repeated.status == OperationStatus.SUCCESS

    client.list_user_pool_clients.return_value = {
        "UserPoolClients": [
            {"ClientId": "b", "ClientName": "b", "UserPoolId": "us-east-1_pool"},
            {"ClientId": "a", "ClientName": "a", "UserPoolId": "us-east-1_pool"},
        ]
    }
    listed = provider.list(_request(client=client, desired_state={"UserPoolId": "us-east-1_pool"}))

    assert listed.status == OperationStatus.SUCCESS
    assert listed.resource_models == [
        {"ClientId": "a", "ClientName": "a", "UserPoolId": "us-east-1_pool"},
        {"ClientId": "b", "ClientName": "b", "UserPoolId": "us-east-1_pool"},
    ]
    client.list_user_pool_clients.assert_called_once_with(
        MaxResults=60, UserPoolId="us-east-1_pool"
    )


def test_user_pool_client_list_consumes_continuation_tokens():
    client = MagicMock()
    client.list_user_pool_clients.side_effect = [
        {
            "NextToken": "page-2",
            "UserPoolClients": [
                {"ClientId": "b", "ClientName": "b", "UserPoolId": "us-east-1_pool"}
            ],
        },
        {"UserPoolClients": [{"ClientId": "a", "ClientName": "a", "UserPoolId": "us-east-1_pool"}]},
    ]

    result = CognitoUserPoolClientProvider().list(
        _request(client=client, desired_state={"UserPoolId": "us-east-1_pool"})
    )

    assert result.status == OperationStatus.SUCCESS
    assert [model["ClientId"] for model in result.resource_models] == ["a", "b"]
    assert client.list_user_pool_clients.call_args_list[1].kwargs == {
        "MaxResults": 60,
        "NextToken": "page-2",
        "UserPoolId": "us-east-1_pool",
    }
