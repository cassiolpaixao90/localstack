import configparser
import copy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call

from botocore.exceptions import ClientError

from localstack.capabilities.catalog import scan_cloudformation_resources
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
)
from localstack.services.cognito_identity.resource_providers.aws_cognito_identitypool import (
    CognitoIdentityPoolProvider,
)
from localstack.services.cognito_identity.resource_providers.aws_cognito_identitypool_plugin import (
    CognitoIdentityPoolProviderPlugin,
)
from localstack.services.cognito_identity.resource_providers.aws_cognito_identitypoolroleattachment import (
    CognitoIdentityPoolRoleAttachmentProvider,
)
from localstack.services.cognito_identity.resource_providers.aws_cognito_identitypoolroleattachment_plugin import (
    CognitoIdentityPoolRoleAttachmentProviderPlugin,
)

PROJECT_ROOT = Path(__file__).resolve().parents[4]


def _request(*, client, desired_state, previous_state=None):
    return SimpleNamespace(
        aws_client_factory=SimpleNamespace(cognito_identity=client),
        custom_context={"attempt": 1},
        desired_state=desired_state,
        previous_state=previous_state,
        logical_resource_id="Identity",
        stack_name="enterprise",
        region_name="us-east-1",
    )


def _not_found(operation):
    return ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "missing"}},
        operation,
    )


def _pool_response(name="mobile", **overrides):
    return {
        "AllowClassicFlow": False,
        "AllowUnauthenticatedIdentities": True,
        "IdentityPoolId": "us-east-1:00000000-0000-4000-8000-000000000001",
        "IdentityPoolName": name,
        **overrides,
    }


def test_identity_pool_schema_and_physical_id_expose_ref_and_name_getatt():
    schema = CognitoIdentityPoolProvider.SCHEMA
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["AllowUnauthenticatedIdentities"]
    assert schema["primaryIdentifier"] == ["/properties/IdentityPoolId"]
    assert set(schema["readOnlyProperties"]) == {
        "/properties/IdentityPoolId",
        "/properties/Name",
    }
    assert set(schema["properties"]) == {
        "AllowClassicFlow",
        "AllowUnauthenticatedIdentities",
        "CognitoEvents",
        "CognitoIdentityProviders",
        "CognitoStreams",
        "DeveloperProviderName",
        "IdentityPoolId",
        "IdentityPoolName",
        "IdentityPoolTags",
        "Name",
        "OpenIdConnectProviderARNs",
        "PushSync",
        "SamlProviderARNs",
        "SupportedLoginProviders",
    }
    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")
    physical_id = executor.extract_physical_resource_id_from_model_with_schema(
        {
            "IdentityPoolId": "us-east-1:00000000-0000-4000-8000-000000000001",
            "Name": "mobile",
        },
        CognitoIdentityPoolProvider.TYPE,
        schema,
    )
    assert physical_id == "us-east-1:00000000-0000-4000-8000-000000000001"


def test_role_attachment_schema_and_physical_id_use_identity_pool_id():
    schema = CognitoIdentityPoolRoleAttachmentProvider.SCHEMA
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["IdentityPoolId"]
    assert schema["primaryIdentifier"] == ["/properties/IdentityPoolId"]
    assert schema["createOnlyProperties"] == ["/properties/IdentityPoolId"]
    assert schema["readOnlyProperties"] == ["/properties/Id"]
    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")
    physical_id = executor.extract_physical_resource_id_from_model_with_schema(
        {
            "Id": "us-east-1:00000000-0000-4000-8000-000000000001",
            "IdentityPoolId": "us-east-1:00000000-0000-4000-8000-000000000001",
        },
        CognitoIdentityPoolRoleAttachmentProvider.TYPE,
        schema,
    )
    assert physical_id == "us-east-1:00000000-0000-4000-8000-000000000001"


def test_plugins_load_fresh_provider_factories():
    pool_plugin = CognitoIdentityPoolProviderPlugin()
    attachment_plugin = CognitoIdentityPoolRoleAttachmentProviderPlugin()
    pool_plugin.load()
    attachment_plugin.load()
    assert pool_plugin.factory is CognitoIdentityPoolProvider
    assert attachment_plugin.factory is CognitoIdentityPoolRoleAttachmentProvider

    manifest = configparser.ConfigParser(delimiters=("=",), interpolation=None)
    manifest.read(PROJECT_ROOT / "plux.ini")
    plugins = manifest["localstack.cloudformation.resource_providers"]
    assert plugins["aws::cognito::identitypool"].endswith(":CognitoIdentityPoolProviderPlugin")
    assert plugins["aws::cognito::identitypoolroleattachment"].endswith(
        ":CognitoIdentityPoolRoleAttachmentProviderPlugin"
    )


def test_capability_scanner_discovers_both_native_resource_types():
    by_service, records = scan_cloudformation_resources(PROJECT_ROOT)

    expected = {
        "AWS::Cognito::IdentityPool",
        "AWS::Cognito::IdentityPoolPrincipalTag",
        "AWS::Cognito::IdentityPoolRoleAttachment",
    }
    assert set(by_service["cognito-identity"]) == expected
    assert {
        record["type"] for record in records if record["source_service"] == "cognito-identity"
    } == expected


def test_identity_pool_create_maps_supported_properties_without_mutating_desired(monkeypatch):
    client = MagicMock()
    client.create_identity_pool.return_value = _pool_response(
        "generated",
        AllowClassicFlow=True,
        CognitoIdentityProviders=[
            {"ClientId": "client", "ProviderName": "provider", "ServerSideTokenCheck": True}
        ],
        DeveloperProviderName="login.example",
        IdentityPoolTags={"environment": "test"},
        SupportedLoginProviders={"accounts.example": "app"},
    )
    desired = {
        "AllowClassicFlow": True,
        "AllowUnauthenticatedIdentities": True,
        "CognitoIdentityProviders": [
            {"ClientId": "client", "ProviderName": "provider", "ServerSideTokenCheck": True}
        ],
        "DeveloperProviderName": "login.example",
        "IdentityPoolTags": [{"Key": "environment", "Value": "test"}],
        "SupportedLoginProviders": {"accounts.example": "app"},
    }
    original = copy.deepcopy(desired)
    monkeypatch.setattr(
        "localstack.services.cognito_identity.resource_providers.aws_cognito_identitypool.util.generate_default_name",
        lambda stack_name, logical_resource_id: "generated",
    )

    result = CognitoIdentityPoolProvider().create(_request(client=client, desired_state=desired))

    assert result.status == OperationStatus.SUCCESS
    assert desired == original
    assert result.resource_model == {
        **original,
        "IdentityPoolId": _pool_response()["IdentityPoolId"],
        "IdentityPoolName": "generated",
        "Name": "generated",
    }
    client.create_identity_pool.assert_called_once_with(
        AllowClassicFlow=True,
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=desired["CognitoIdentityProviders"],
        DeveloperProviderName="login.example",
        IdentityPoolName="generated",
        IdentityPoolTags={"environment": "test"},
        OpenIdConnectProviderARNs=[],
        SamlProviderARNs=[],
        SupportedLoginProviders={"accounts.example": "app"},
    )


def test_identity_pool_rejects_read_only_and_unsupported_properties_before_service_call():
    client = MagicMock()
    provider = CognitoIdentityPoolProvider()
    read_only = provider.create(
        _request(
            client=client,
            desired_state={
                "AllowUnauthenticatedIdentities": True,
                "IdentityPoolId": _pool_response()["IdentityPoolId"],
            },
        )
    )
    unsupported = provider.create(
        _request(
            client=client,
            desired_state={
                "AllowUnauthenticatedIdentities": True,
                "CognitoEvents": {"SyncTrigger": "arn"},
            },
        )
    )
    assert read_only.status == OperationStatus.FAILED
    assert unsupported.status == OperationStatus.FAILED
    client.create_identity_pool.assert_not_called()


def test_identity_pool_read_update_delete_and_paginated_list_are_idempotent():
    client = MagicMock()
    pool_id = _pool_response()["IdentityPoolId"]
    client.describe_identity_pool.return_value = _pool_response(
        "renamed", IdentityPoolTags={"environment": "prod"}
    )
    provider = CognitoIdentityPoolProvider()

    read = provider.read(_request(client=client, desired_state={"IdentityPoolId": pool_id}))
    assert read.status == OperationStatus.SUCCESS
    assert read.resource_model["Name"] == "renamed"
    assert read.resource_model["IdentityPoolTags"] == [{"Key": "environment", "Value": "prod"}]

    previous = {
        "AllowClassicFlow": True,
        "AllowUnauthenticatedIdentities": True,
        "DeveloperProviderName": "login.example",
        "IdentityPoolId": pool_id,
        "IdentityPoolName": "old",
        "Name": "old",
    }
    desired = {
        "AllowUnauthenticatedIdentities": False,
        "DeveloperProviderName": "login.example",
        "IdentityPoolName": "renamed",
    }
    original = copy.deepcopy(desired)
    updated = provider.update(
        _request(client=client, desired_state=desired, previous_state=previous)
    )
    assert updated.status == OperationStatus.SUCCESS
    assert desired == original
    client.update_identity_pool.assert_called_once_with(
        AllowClassicFlow=False,
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[],
        DeveloperProviderName="login.example",
        IdentityPoolId=pool_id,
        IdentityPoolName="renamed",
        IdentityPoolTags={},
        OpenIdConnectProviderARNs=[],
        SamlProviderARNs=[],
        SupportedLoginProviders={},
    )

    deleted = provider.delete(
        _request(client=client, desired_state={}, previous_state={"IdentityPoolId": pool_id})
    )
    assert deleted.status == OperationStatus.SUCCESS
    client.delete_identity_pool.side_effect = _not_found("DeleteIdentityPool")
    repeated = provider.delete(
        _request(client=client, desired_state={}, previous_state={"IdentityPoolId": pool_id})
    )
    assert repeated.status == OperationStatus.SUCCESS

    first_page = {
        "IdentityPools": [
            {
                "IdentityPoolId": f"us-east-1:00000000-0000-4000-8000-{index:012d}",
                "IdentityPoolName": str(index),
            }
            for index in range(60)
        ],
        "NextToken": "next",
    }
    second_page = {
        "IdentityPools": [
            {
                "IdentityPoolId": "us-east-1:00000000-0000-4000-8000-000000000060",
                "IdentityPoolName": "60",
            }
        ]
    }
    client.list_identity_pools.side_effect = [first_page, second_page]
    listed = provider.list(_request(client=client, desired_state={}))
    assert listed.status == OperationStatus.SUCCESS
    assert len(listed.resource_models) == 61
    assert client.list_identity_pools.call_args_list == [
        call(MaxResults=60),
        call(MaxResults=60, NextToken="next"),
    ]


def test_identity_pool_update_rejects_identity_and_developer_provider_changes():
    client = MagicMock()
    pool_id = _pool_response()["IdentityPoolId"]
    previous = {
        "AllowUnauthenticatedIdentities": True,
        "DeveloperProviderName": "login.example",
        "IdentityPoolId": pool_id,
        "IdentityPoolName": "old",
    }
    provider = CognitoIdentityPoolProvider()
    changed_id = provider.update(
        _request(
            client=client,
            desired_state={
                "AllowUnauthenticatedIdentities": True,
                "IdentityPoolId": "us-east-1:00000000-0000-4000-8000-000000000099",
            },
            previous_state=previous,
        )
    )
    changed_provider = provider.update(
        _request(
            client=client,
            desired_state={
                "AllowUnauthenticatedIdentities": True,
                "DeveloperProviderName": "login.changed",
            },
            previous_state=previous,
        )
    )
    assert changed_id.status == OperationStatus.FAILED
    assert changed_provider.status == OperationStatus.FAILED
    client.update_identity_pool.assert_not_called()


def test_role_attachment_create_read_update_delete_and_list():
    client = MagicMock()
    pool_id = _pool_response()["IdentityPoolId"]
    auth = "arn:aws:iam::000000000000:role/auth"
    guest = "arn:aws:iam::000000000000:role/guest"
    identity_provider = "cognito-idp.us-east-1.amazonaws.com/us-east-1_example:client"
    role_mappings = {
        "mobile": {
            "IdentityProvider": identity_provider,
            "Type": "Token",
            "AmbiguousRoleResolution": "AuthenticatedRole",
        }
    }
    service_mappings = {
        identity_provider: {
            "Type": "Token",
            "AmbiguousRoleResolution": "AuthenticatedRole",
        }
    }
    client.get_identity_pool_roles.return_value = {
        "IdentityPoolId": pool_id,
        "Roles": {"authenticated": auth},
        "RoleMappings": service_mappings,
    }
    provider = CognitoIdentityPoolRoleAttachmentProvider()

    created = provider.create(
        _request(
            client=client,
            desired_state={
                "IdentityPoolId": pool_id,
                "Roles": {"authenticated": auth},
                "RoleMappings": role_mappings,
            },
        )
    )
    assert created.status == OperationStatus.SUCCESS
    assert created.resource_model == {
        "Id": pool_id,
        "IdentityPoolId": pool_id,
        "RoleMappings": role_mappings,
        "Roles": {"authenticated": auth},
    }
    client.set_identity_pool_roles.assert_called_once_with(
        IdentityPoolId=pool_id,
        Roles={"authenticated": auth},
        RoleMappings=service_mappings,
    )

    read = provider.read(_request(client=client, desired_state=created.resource_model))
    assert read.status == OperationStatus.SUCCESS
    assert read.resource_model == created.resource_model

    desired = {
        "IdentityPoolId": pool_id,
        "Roles": {"unauthenticated": guest},
        "RoleMappings": role_mappings,
    }
    original = copy.deepcopy(desired)
    updated = provider.update(
        _request(client=client, desired_state=desired, previous_state=created.resource_model)
    )
    assert updated.status == OperationStatus.SUCCESS
    assert desired == original
    assert client.set_identity_pool_roles.call_args_list[-1] == call(
        IdentityPoolId=pool_id,
        Roles={"unauthenticated": guest},
        RoleMappings=service_mappings,
    )

    deleted = provider.delete(
        _request(client=client, desired_state={}, previous_state=created.resource_model)
    )
    assert deleted.status == OperationStatus.SUCCESS
    assert client.set_identity_pool_roles.call_args_list[-1] == call(
        IdentityPoolId=pool_id, Roles={}, RoleMappings={}
    )

    client.list_identity_pools.return_value = {
        "IdentityPools": [{"IdentityPoolId": pool_id, "IdentityPoolName": "pool"}]
    }
    listed = provider.list(_request(client=client, desired_state={}))
    assert listed.status == OperationStatus.SUCCESS
    assert listed.resource_models == [
        {
            "Id": pool_id,
            "IdentityPoolId": pool_id,
            "Roles": {"authenticated": auth},
            "RoleMappings": service_mappings,
        }
    ]


def test_role_attachment_fails_closed_for_invalid_role_mappings_roles_and_replacement():
    client = MagicMock()
    pool_id = _pool_response()["IdentityPoolId"]
    provider = CognitoIdentityPoolRoleAttachmentProvider()
    requests = [
        {
            "IdentityPoolId": pool_id,
            "RoleMappings": {"provider": {"Type": "Token"}},
        },
        {"IdentityPoolId": pool_id, "Roles": {"administrator": "arn"}},
        {"IdentityPoolId": pool_id, "Roles": {"authenticated": ""}},
    ]
    for desired in requests:
        result = provider.create(_request(client=client, desired_state=desired))
        assert result.status == OperationStatus.FAILED
    changed = provider.update(
        _request(
            client=client,
            desired_state={"IdentityPoolId": "us-east-1:00000000-0000-4000-8000-000000000099"},
            previous_state={"IdentityPoolId": pool_id, "Roles": {}},
        )
    )
    assert changed.status == OperationStatus.FAILED
    client.set_identity_pool_roles.assert_not_called()
