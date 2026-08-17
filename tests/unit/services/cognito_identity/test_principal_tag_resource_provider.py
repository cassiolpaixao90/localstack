import configparser
import copy
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
)
from localstack.services.cognito_identity.models import cognito_identity_stores
from localstack.services.cognito_identity.provider import CognitoIdentityProvider
from localstack.services.cognito_identity.resource_providers.aws_cognito_identitypoolprincipaltag import (
    CognitoIdentityPoolPrincipalTagProvider,
)
from localstack.services.cognito_identity.resource_providers.aws_cognito_identitypoolprincipaltag_plugin import (
    CognitoIdentityPoolPrincipalTagProviderPlugin,
)

PROJECT_ROOT = Path(__file__).resolve().parents[4]
PROVIDER_NAME = "cognito-idp.us-east-1.amazonaws.com/us-east-1_native"


def _request(*, client, desired_state, previous_state=None):
    return SimpleNamespace(
        aws_client_factory=SimpleNamespace(cognito_identity=client),
        custom_context={"attempt": 1},
        desired_state=desired_state,
        previous_state=previous_state,
        logical_resource_id="PrincipalTags",
        stack_name="enterprise",
        region_name="us-east-1",
    )


class _NativeCognitoIdentityClient:
    def __init__(self, provider: CognitoIdentityProvider, context: RequestContext):
        self.provider = provider
        self.context = context

    def __getattr__(self, name: str):
        handler = getattr(self.provider, name)

        def invoke(**request):
            try:
                return handler(self.context, request)
            except CommonServiceException as error:
                raise ClientError(
                    {"Error": {"Code": error.code, "Message": error.message}}, name
                ) from error

        return invoke


@pytest.fixture
def native_identity():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    context.partition = "aws"
    native_provider = CognitoIdentityProvider()
    client = _NativeCognitoIdentityClient(native_provider, context)
    pool = native_provider.create_identity_pool(
        context,
        {
            "AllowUnauthenticatedIdentities": True,
            "CognitoIdentityProviders": [
                {"ClientId": "nativeclient", "ProviderName": PROVIDER_NAME}
            ],
            "IdentityPoolName": "principal-tags",
        },
    )
    yield native_provider, client, context, pool
    try:
        native_provider.delete_identity_pool(context, {"IdentityPoolId": pool["IdentityPoolId"]})
    finally:
        with cognito_identity_stores.lock:
            cognito_identity_stores.pop(context.account_id, None)


def test_schema_plugin_manifest_and_ref_contract_are_official():
    schema = CognitoIdentityPoolPrincipalTagProvider.SCHEMA
    plugin = CognitoIdentityPoolPrincipalTagProviderPlugin()
    plugin.load()

    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {
        "IdentityPoolId",
        "IdentityProviderName",
        "PrincipalTags",
        "UseDefaults",
    }
    assert schema["required"] == ["IdentityPoolId", "IdentityProviderName"]
    assert schema["primaryIdentifier"] == [
        "/properties/IdentityPoolId",
        "/properties/IdentityProviderName",
    ]
    assert set(schema["createOnlyProperties"]) == {
        "/properties/IdentityPoolId",
        "/properties/IdentityProviderName",
    }
    assert "readOnlyProperties" not in schema
    assert schema["handlers"]["list"] == {
        "handlerSchema": {
            "properties": {
                "IdentityPoolId": {"$ref": "resource-schema.json#/properties/IdentityPoolId"},
                "IdentityProviderName": {
                    "$ref": "resource-schema.json#/properties/IdentityProviderName"
                },
            },
            "required": ["IdentityPoolId", "IdentityProviderName"],
        },
        "permissions": ["cognito-identity:GetPrincipalTagAttributeMap"],
    }
    assert plugin.factory is CognitoIdentityPoolPrincipalTagProvider

    quirk = PHYSICAL_RESOURCE_ID_SPECIAL_CASES["AWS::Cognito::IdentityPoolPrincipalTag"]
    assert quirk == "</properties/IdentityPoolId>|</properties/IdentityProviderName>"
    pool_id = "us-east-1:00000000-0000-4000-8000-000000000001"
    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")
    assert (
        executor.extract_physical_resource_id_from_model_with_schema(
            {"IdentityPoolId": pool_id, "IdentityProviderName": PROVIDER_NAME},
            CognitoIdentityPoolPrincipalTagProvider.TYPE,
            schema,
        )
        == f"{pool_id}|{PROVIDER_NAME}"
    )

    manifest = configparser.ConfigParser(delimiters=("=",), interpolation=None)
    manifest.read(PROJECT_ROOT / "plux.ini")
    assert manifest["localstack.cloudformation.resource_providers"][
        "aws::cognito::identitypoolprincipaltag"
    ].endswith(":CognitoIdentityPoolPrincipalTagProviderPlugin")


def test_native_roundtrip_update_reset_list_and_idempotent_cleanup(native_identity):
    _, client, _, pool = native_identity
    provider = CognitoIdentityPoolPrincipalTagProvider()
    identity = {
        "IdentityPoolId": pool["IdentityPoolId"],
        "IdentityProviderName": PROVIDER_NAME,
    }
    desired = {
        **identity,
        "PrincipalTags": {"department": "custom:department", "tenant": "custom:tenant"},
        "UseDefaults": False,
    }
    original = copy.deepcopy(desired)

    created = provider.create(_request(client=client, desired_state=desired))
    assert created.status == OperationStatus.SUCCESS
    assert created.resource_model == desired
    assert desired == original

    retried = provider.create(_request(client=client, desired_state=desired))
    assert retried.status == OperationStatus.SUCCESS
    assert retried.resource_model == desired

    read = provider.read(_request(client=client, desired_state=identity))
    assert read.status == OperationStatus.SUCCESS
    assert read.resource_model == desired

    listed = provider.list(_request(client=client, desired_state=identity))
    assert listed.status == OperationStatus.SUCCESS
    assert listed.resource_models == [desired]

    reset = provider.update(_request(client=client, desired_state=identity, previous_state=desired))
    assert reset.status == OperationStatus.SUCCESS
    assert reset.resource_model == {
        **identity,
        "PrincipalTags": {},
        "UseDefaults": True,
    }

    restored = provider.update(
        _request(
            client=client,
            desired_state=desired,
            previous_state=reset.resource_model,
        )
    )
    assert restored.status == OperationStatus.SUCCESS
    assert restored.resource_model == desired

    deleted = provider.delete(_request(client=client, desired_state={}, previous_state=desired))
    repeated = provider.delete(_request(client=client, desired_state={}, previous_state=desired))
    assert deleted.status == OperationStatus.SUCCESS
    assert repeated.status == OperationStatus.SUCCESS
    assert client.get_principal_tag_attribute_map(**identity) == {
        **identity,
        "PrincipalTags": {},
        "UseDefaults": True,
    }


def test_update_and_delete_do_not_clobber_external_drift(native_identity):
    _, client, _, pool = native_identity
    provider = CognitoIdentityPoolPrincipalTagProvider()
    identity = {
        "IdentityPoolId": pool["IdentityPoolId"],
        "IdentityProviderName": PROVIDER_NAME,
    }
    owned = {
        **identity,
        "PrincipalTags": {"tenant": "custom:tenant"},
        "UseDefaults": False,
    }
    external = {
        **identity,
        "PrincipalTags": {"external": "custom:external"},
        "UseDefaults": False,
    }
    provider.create(_request(client=client, desired_state=owned))
    client.set_principal_tag_attribute_map(**external)

    update = provider.update(
        _request(
            client=client,
            desired_state=owned | {"PrincipalTags": {"new": "custom:new"}},
            previous_state=owned,
        )
    )
    deleted = provider.delete(_request(client=client, desired_state={}, previous_state=owned))

    assert update.status == OperationStatus.FAILED
    assert update.error_code == "ResourceConflict"
    assert deleted.status == OperationStatus.SUCCESS
    assert client.get_principal_tag_attribute_map(**identity) == external


def test_read_is_account_and_region_isolated(native_identity):
    _, _, context, pool = native_identity
    provider = CognitoIdentityPoolPrincipalTagProvider()
    identity = {
        "IdentityPoolId": pool["IdentityPoolId"],
        "IdentityProviderName": PROVIDER_NAME,
    }
    foreign_account = RequestContext(None)
    foreign_account.account_id = f"{(int(context.account_id) + 1) % 10**12:012d}"
    foreign_account.region = context.region
    foreign_account.partition = "aws"
    foreign_region = RequestContext(None)
    foreign_region.account_id = context.account_id
    foreign_region.region = "us-west-2"
    foreign_region.partition = "aws"

    for foreign in (foreign_account, foreign_region):
        result = provider.read(
            _request(
                client=_NativeCognitoIdentityClient(CognitoIdentityProvider(), foreign),
                desired_state=identity,
            )
        )
        assert result.status == OperationStatus.FAILED
        assert result.error_code == "NotFound"

    with cognito_identity_stores.lock:
        cognito_identity_stores.pop(foreign_account.account_id, None)


def test_create_replacement_bounds_and_list_filters_fail_closed():
    client = MagicMock()
    pool_id = "us-east-1:00000000-0000-4000-8000-000000000001"
    identity = {"IdentityPoolId": pool_id, "IdentityProviderName": PROVIDER_NAME}
    client.get_principal_tag_attribute_map.return_value = {
        **identity,
        "PrincipalTags": {},
        "UseDefaults": True,
    }
    provider = CognitoIdentityPoolPrincipalTagProvider()

    invalid_models = (
        {**identity, "PrincipalTags": {}, "UseDefaults": False},
        {**identity, "PrincipalTags": {"tag": "claim"}, "UseDefaults": True},
        {
            **identity,
            "PrincipalTags": {f"tag-{index}": "claim" for index in range(51)},
            "UseDefaults": False,
        },
    )
    for model in invalid_models:
        result = provider.create(_request(client=client, desired_state=model))
        assert result.status == OperationStatus.FAILED
    client.set_principal_tag_attribute_map.assert_not_called()

    client.get_principal_tag_attribute_map.return_value = {
        **identity,
        "PrincipalTags": {"external": "claim"},
        "UseDefaults": False,
    }
    conflict = provider.create(
        _request(
            client=client,
            desired_state={
                **identity,
                "PrincipalTags": {"owned": "claim"},
                "UseDefaults": False,
            },
        )
    )
    assert conflict.status == OperationStatus.FAILED
    assert conflict.error_code == "AlreadyExists"
    client.set_principal_tag_attribute_map.assert_not_called()

    replacement = provider.update(
        _request(
            client=client,
            desired_state=identity | {"IdentityProviderName": "different"},
            previous_state=identity,
        )
    )
    assert replacement.status == OperationStatus.FAILED
    assert "replacement" in replacement.message.lower()

    for filters in ({}, {"IdentityPoolId": pool_id}, {"IdentityProviderName": PROVIDER_NAME}):
        invalid_list = provider.list(_request(client=client, desired_state=filters))
        assert invalid_list.status == OperationStatus.FAILED

    listed = provider.list(_request(client=client, desired_state=identity))
    assert listed.status == OperationStatus.SUCCESS
    assert listed.resource_models == [client.get_principal_tag_attribute_map.return_value]


def test_provider_accepts_only_botocore_response_metadata_outside_the_resource_model():
    client = MagicMock()
    pool_id = "us-east-1:00000000-0000-4000-8000-000000000001"
    desired = {
        "IdentityPoolId": pool_id,
        "IdentityProviderName": PROVIDER_NAME,
        "PrincipalTags": {"tenant": "custom:tenantId"},
        "UseDefaults": False,
    }
    client.set_principal_tag_attribute_map.return_value = {
        **desired,
        "ResponseMetadata": {"RequestId": "request-id"},
    }
    provider = CognitoIdentityPoolPrincipalTagProvider()

    created = provider._set(_request(client=client, desired_state=desired), desired)
    assert created.status == OperationStatus.SUCCESS
    assert created.resource_model == desired

    client.set_principal_tag_attribute_map.return_value["Unexpected"] = "injected"
    rejected = provider._set(_request(client=client, desired_state=desired), desired)
    assert rejected.status == OperationStatus.FAILED
    assert "unsupported fields" in rejected.message
