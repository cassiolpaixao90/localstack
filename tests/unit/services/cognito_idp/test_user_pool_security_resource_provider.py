import copy
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpool import (
    CognitoUserPoolProvider,
)


def _request(*, client, desired_state, previous_state=None):
    return SimpleNamespace(
        aws_client_factory=SimpleNamespace(cognito_idp=client),
        custom_context={},
        desired_state=desired_state,
        previous_state=previous_state,
        logical_resource_id="Auth",
        stack_name="enterprise",
        region_name="us-east-1",
    )


class _NativeCognitoClient:
    def __init__(self, provider: CognitoIdpProvider, context: RequestContext):
        self.provider = provider
        self.context = context

    def __getattr__(self, name: str):
        handler = getattr(self.provider, name)

        def invoke(**request):
            return handler(self.context, request)

        return invoke


def _security_properties():
    return {
        "DeletionProtection": "INACTIVE",
        "IssuerConfiguration": {"Type": "ORIGINAL"},
        "KeyConfiguration": {"KeyType": "AWS_OWNED_KEY"},
        "LambdaConfig": {"PreSignUp": "arn:aws:lambda:us-east-1:000000000000:function:pre-sign-up"},
        "Policies": {
            "PasswordPolicy": {
                "MinimumLength": 9,
                "PasswordHistorySize": 2,
                "TemporaryPasswordValidityDays": 0,
            }
        },
        "SmsAuthenticationMessage": "Your authentication code is {####}",
        "UserAttributeUpdateSettings": {
            "AttributesRequireVerificationBeforeUpdate": ["email", "phone_number"]
        },
        "UserPoolAddOns": {"AdvancedSecurityMode": "OFF"},
    }


def test_user_pool_security_schema_is_closed_and_accepts_reset_values():
    properties = CognitoUserPoolProvider.SCHEMA["properties"]

    assert properties["IssuerConfiguration"] == {
        "type": "object",
        "additionalProperties": False,
        "required": ["Type"],
        "properties": {"Type": {"type": "string", "enum": ["ORIGINAL", "UPDATED"]}},
    }
    assert properties["KeyConfiguration"]["additionalProperties"] is False
    assert set(properties["KeyConfiguration"]["properties"]) == {"KeyType", "KmsKeyArn"}
    assert "PreSignUp" in properties["LambdaConfig"]["properties"]
    password = properties["Policies"]["properties"]["PasswordPolicy"]["properties"]
    assert password["PasswordHistorySize"] == {"type": "integer", "minimum": 0, "maximum": 24}
    assert password["TemporaryPasswordValidityDays"]["minimum"] == 0
    attribute_update = properties["UserAttributeUpdateSettings"]
    assert attribute_update["additionalProperties"] is False
    assert attribute_update["required"] == ["AttributesRequireVerificationBeforeUpdate"]
    assert attribute_update["properties"]["AttributesRequireVerificationBeforeUpdate"]["items"][
        "enum"
    ] == ["email", "phone_number"]
    add_ons = properties["UserPoolAddOns"]
    assert add_ons["additionalProperties"] is False
    assert add_ons["required"] == ["AdvancedSecurityMode"]


def test_user_pool_security_create_forwards_fields_without_mutating_desired():
    client = MagicMock()
    desired = {"UserPoolName": "secure-pool", **_security_properties()}
    original = copy.deepcopy(desired)
    client.create_user_pool.return_value = {
        "UserPool": {
            "Arn": "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool",
            "Id": "us-east-1_pool",
            "Name": "secure-pool",
            **_security_properties(),
        }
    }

    result = CognitoUserPoolProvider().create(_request(client=client, desired_state=desired))

    assert result.status == OperationStatus.SUCCESS
    assert desired == original
    client.create_user_pool.assert_called_once_with(
        PoolName="secure-pool", **_security_properties()
    )
    assert result.resource_model == {
        "Arn": "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool",
        "ProviderName": "cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
        "ProviderURL": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
        "UserPoolId": "us-east-1_pool",
        "UserPoolName": "secure-pool",
        **_security_properties(),
    }


def test_user_pool_security_update_resets_omitted_fields_and_rolls_back_on_read_failure():
    client = MagicMock()
    previous = {
        "Arn": "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool",
        "UserPoolId": "us-east-1_pool",
        "UserPoolName": "secure-pool",
        **_security_properties(),
    }
    desired = {
        "Arn": previous["Arn"],
        "UserPoolId": previous["UserPoolId"],
        "UserPoolName": previous["UserPoolName"],
    }
    original = copy.deepcopy(desired)
    primary = RuntimeError("read after update failed")
    client.describe_user_pool.side_effect = primary

    with pytest.raises(RuntimeError, match="read after update failed") as raised:
        CognitoUserPoolProvider().update(
            _request(client=client, desired_state=desired, previous_state=previous)
        )

    assert raised.value is primary
    assert desired == original
    assert client.update_user_pool.call_args_list[0].kwargs == {
        "PoolName": "secure-pool",
        "UserPoolId": "us-east-1_pool",
    }
    assert client.update_user_pool.call_args_list[1].kwargs == {
        "PoolName": "secure-pool",
        "UserPoolId": "us-east-1_pool",
        **_security_properties(),
    }


def test_user_pool_security_round_trips_and_resets_against_native_provider():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    native_provider = CognitoIdpProvider()
    native_client = _NativeCognitoClient(native_provider, context)
    resource_provider = CognitoUserPoolProvider()
    pool_id = None

    try:
        desired = {"UserPoolName": "secure-pool", **_security_properties()}
        desired["LambdaConfig"]["PreSignUp"] = (
            f"arn:aws:lambda:{context.region}:{context.account_id}:function:pre-sign-up"
        )
        original = copy.deepcopy(desired)
        created = resource_provider.create(_request(client=native_client, desired_state=desired))
        assert created.status == OperationStatus.SUCCESS
        assert desired == original
        pool_id = created.resource_model["UserPoolId"]
        assert (
            created.resource_model["Policies"]["PasswordPolicy"]["TemporaryPasswordValidityDays"]
            == 7
        )

        reset = {
            "Arn": created.resource_model["Arn"],
            "UserPoolId": pool_id,
            "UserPoolName": "secure-pool",
        }
        updated = resource_provider.update(
            _request(
                client=native_client,
                desired_state=reset,
                previous_state=created.resource_model,
            )
        )
        assert updated.status == OperationStatus.SUCCESS
        for field in _security_properties():
            assert field not in updated.resource_model
    finally:
        if pool_id is not None:
            native_provider.delete_user_pool(context, {"UserPoolId": pool_id})
        with cognito_idp_stores.lock:
            cognito_idp_stores.pop(context.account_id, None)


def test_user_pool_add_ons_audit_fails_closed_without_leaking_pool():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    native_provider = CognitoIdpProvider()
    native_client = _NativeCognitoClient(native_provider, context)

    try:
        with pytest.raises(CommonServiceException) as raised:
            CognitoUserPoolProvider().create(
                _request(
                    client=native_client,
                    desired_state={
                        "UserPoolAddOns": {"AdvancedSecurityMode": "AUDIT"},
                        "UserPoolName": "unsupported-security",
                    },
                )
            )
        assert raised.value.code == "InvalidParameterException"
        assert native_provider.list_user_pools(context, {"MaxResults": 60})["UserPools"] == []
    finally:
        with cognito_idp_stores.lock:
            cognito_idp_stores.pop(context.account_id, None)
