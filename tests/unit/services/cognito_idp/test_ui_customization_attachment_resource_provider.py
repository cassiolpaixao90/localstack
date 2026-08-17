import copy
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ParamValidationError, ReadTimeoutError

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
)
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpooluicustomizationattachment import (
    CognitoUserPoolUICustomizationAttachmentProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpooluicustomizationattachment_plugin import (
    CognitoUserPoolUICustomizationAttachmentProviderPlugin,
)


def _request(*, client, desired_state, previous_state=None):
    return SimpleNamespace(
        aws_client_factory=SimpleNamespace(cognito_idp=client),
        custom_context={},
        desired_state=desired_state,
        previous_state=previous_state,
        logical_resource_id="ClassicUI",
        stack_name="enterprise",
        region_name="us-east-1",
    )


class _NativeClient:
    def __init__(self, provider, context):
        self.provider = provider
        self.context = context

    def __getattr__(self, name):
        handler = getattr(self.provider, name)

        def invoke(**request):
            try:
                return handler(self.context, request)
            except CommonServiceException as error:
                from botocore.exceptions import ClientError

                raise ClientError(
                    {"Error": {"Code": error.code, "Message": error.message}}, name
                ) from error

        return invoke


def test_schema_plugin_and_exact_ref_contract():
    provider = CognitoUserPoolUICustomizationAttachmentProvider()
    schema = provider.SCHEMA
    plugin = CognitoUserPoolUICustomizationAttachmentProviderPlugin()
    plugin.load()

    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"CSS", "ClientId", "UserPoolId"}
    assert schema["required"] == ["ClientId", "UserPoolId"]
    assert schema["primaryIdentifier"] == [
        "/properties/UserPoolId",
        "/properties/ClientId",
    ]
    assert set(schema["createOnlyProperties"]) == {
        "/properties/ClientId",
        "/properties/UserPoolId",
    }
    assert schema["properties"]["CSS"]["maxLength"] == 131_072
    assert schema["properties"]["ClientId"] == {
        "type": "string",
        "minLength": 1,
        "maxLength": 128,
        "pattern": "^[\\w+]+$",
    }
    assert plugin.factory is CognitoUserPoolUICustomizationAttachmentProvider
    assert PHYSICAL_RESOURCE_ID_SPECIAL_CASES[provider.TYPE] == (
        "UserPoolUICustomizationAttachment-</properties/UserPoolId>-</properties/ClientId>"
    )
    model = {"ClientId": "client123", "UserPoolId": "us-east-1_pool"}
    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")
    assert (
        executor.extract_physical_resource_id_from_model_with_schema(model, provider.TYPE, schema)
        == "UserPoolUICustomizationAttachment-us-east-1_pool-client123"
    )


def test_lifecycle_uses_set_get_and_resets_css_without_mutating_desired():
    client = MagicMock()
    client.set_ui_customization.side_effect = [
        {
            "UICustomization": {
                "CSS": ".label-customizable{color:red}",
                "ClientId": "client123",
                "UserPoolId": "us-east-1_pool",
            }
        },
        {
            "UICustomization": {
                "CSS": ".label-customizable{color:blue}",
                "ClientId": "client123",
                "UserPoolId": "us-east-1_pool",
            }
        },
        {
            "UICustomization": {
                "CSS": "",
                "ClientId": "client123",
                "UserPoolId": "us-east-1_pool",
            }
        },
    ]
    client.get_ui_customization.return_value = {
        "UICustomization": {
            "CSS": ".label-customizable{color:red}",
            "ClientId": "client123",
            "UserPoolId": "us-east-1_pool",
        }
    }
    provider = CognitoUserPoolUICustomizationAttachmentProvider()
    desired = {
        "CSS": ".label-customizable{color:red}",
        "ClientId": "client123",
        "UserPoolId": "us-east-1_pool",
    }
    original = copy.deepcopy(desired)

    created = provider.create(_request(client=client, desired_state=desired))
    read = provider.read(_request(client=client, desired_state=created.resource_model))
    updated = provider.update(
        _request(
            client=client,
            desired_state={**desired, "CSS": ".label-customizable{color:blue}"},
            previous_state=created.resource_model,
        )
    )
    deleted = provider.delete(_request(client=client, desired_state=updated.resource_model))

    assert desired == original
    assert created.status == read.status == updated.status == deleted.status
    assert created.resource_model == read.resource_model == desired
    assert updated.resource_model["CSS"].endswith("blue}")
    assert deleted.status == OperationStatus.SUCCESS
    assert client.set_ui_customization.call_args_list == [
        ((), {"CSS": desired["CSS"], "ClientId": "client123", "UserPoolId": "us-east-1_pool"}),
        (
            (),
            {
                "CSS": ".label-customizable{color:blue}",
                "ClientId": "client123",
                "UserPoolId": "us-east-1_pool",
            },
        ),
        ((), {"CSS": "", "ClientId": "client123", "UserPoolId": "us-east-1_pool"}),
    ]


def test_update_omitted_css_resets_and_identifiers_are_create_only():
    client = MagicMock()
    client.set_ui_customization.return_value = {
        "UICustomization": {
            "CSS": "",
            "ClientId": "client123",
            "UserPoolId": "us-east-1_pool",
        }
    }
    provider = CognitoUserPoolUICustomizationAttachmentProvider()
    previous = {
        "CSS": ".label-customizable{color:red}",
        "ClientId": "client123",
        "UserPoolId": "us-east-1_pool",
    }

    reset = provider.update(
        _request(
            client=client,
            desired_state={"ClientId": "client123", "UserPoolId": "us-east-1_pool"},
            previous_state=previous,
        )
    )
    replaced = provider.update(
        _request(
            client=client,
            desired_state={"ClientId": "other", "UserPoolId": "us-east-1_pool"},
            previous_state=previous,
        )
    )

    assert reset.status == OperationStatus.SUCCESS
    assert reset.resource_model["CSS"] == ""
    assert replaced.status == OperationStatus.FAILED
    assert "create-only" in replaced.message


def test_read_does_not_adopt_inherited_default_and_create_reconciles_only_ambiguous_write():
    model = {
        "CSS": ".label-customizable{color:red}",
        "ClientId": "client123",
        "UserPoolId": "us-east-1_pool",
    }
    inherited = {
        "UICustomization": {
            "CSS": model["CSS"],
            "ClientId": "ALL",
            "UserPoolId": model["UserPoolId"],
        }
    }
    client = MagicMock()
    client.get_ui_customization.return_value = inherited
    provider = CognitoUserPoolUICustomizationAttachmentProvider()

    missing = provider.read(_request(client=client, desired_state=model))
    assert missing.status == OperationStatus.FAILED
    assert missing.error_code == "NotFound"

    exact = {"UICustomization": dict(model)}
    client.set_ui_customization.side_effect = ReadTimeoutError(
        endpoint_url="https://cognito-idp.example"
    )
    client.get_ui_customization.return_value = exact
    recovered = provider.create(_request(client=client, desired_state=model))
    assert recovered.status == OperationStatus.SUCCESS
    assert recovered.resource_model == model

    client.set_ui_customization.side_effect = ParamValidationError(report="invalid")
    with pytest.raises(ParamValidationError):
        provider.create(_request(client=client, desired_state=model))


def test_invalid_models_fail_before_service_io():
    client = MagicMock()
    provider = CognitoUserPoolUICustomizationAttachmentProvider()
    invalid = [
        {"ClientId": "bad-client", "UserPoolId": "us-east-1_pool"},
        {"ClientId": "client123", "UserPoolId": "not-a-pool"},
        {
            "CSS": "x" * 131_073,
            "ClientId": "client123",
            "UserPoolId": "us-east-1_pool",
        },
        {
            "ClientId": "client123",
            "Unknown": True,
            "UserPoolId": "us-east-1_pool",
        },
    ]

    for model in invalid:
        assert (
            provider.create(_request(client=client, desired_state=model)).status
            == OperationStatus.FAILED
        )
    client.set_ui_customization.assert_not_called()


def test_cloudformation_roundtrip_against_native_provider():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    native = CognitoIdpProvider()
    client = _NativeClient(native, context)
    pool = native.create_user_pool(context, {"PoolName": "cfn-classic-ui"})["UserPool"]
    app_client = native.create_user_pool_client(
        context, {"ClientName": "classic", "UserPoolId": pool["Id"]}
    )["UserPoolClient"]
    native.create_user_pool_domain(
        context,
        {"Domain": f"classic-{uuid.uuid4().hex[:12]}", "UserPoolId": pool["Id"]},
    )
    desired = {
        "CSS": ".label-customizable { color: red; }",
        "ClientId": app_client["ClientId"],
        "UserPoolId": pool["Id"],
    }
    provider = CognitoUserPoolUICustomizationAttachmentProvider()

    try:
        created = provider.create(_request(client=client, desired_state=desired))
        assert created.status == OperationStatus.SUCCESS
        assert (
            provider.read(
                _request(client=client, desired_state=created.resource_model)
            ).resource_model
            == created.resource_model
        )
        updated = provider.update(
            _request(
                client=client,
                desired_state={**desired, "CSS": ".label-customizable { color: blue; }"},
                previous_state=created.resource_model,
            )
        )
        assert updated.status == OperationStatus.SUCCESS
        assert "blue" in updated.resource_model["CSS"]
        assert (
            provider.delete(_request(client=client, desired_state=updated.resource_model)).status
            == OperationStatus.SUCCESS
        )
        assert (
            native.get_ui_customization(
                context,
                {"ClientId": app_client["ClientId"], "UserPoolId": pool["Id"]},
            )["UICustomization"]["CSS"]
            == ""
        )
    finally:
        with cognito_idp_stores.lock:
            cognito_idp_stores.pop(context.account_id, None)
