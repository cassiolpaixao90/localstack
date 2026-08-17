import copy
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolresourceserver import (
    CognitoUserPoolResourceServerProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolresourceserver_plugin import (
    CognitoUserPoolResourceServerProviderPlugin,
)

POOL_ID = "us-east-1_pool"
RESOURCE_SERVER = {
    "Identifier": "billgym-api",
    "Name": "Billgym API",
    "Scopes": [
        {"ScopeDescription": "Read data", "ScopeName": "read"},
        {"ScopeDescription": "Write data", "ScopeName": "write"},
    ],
    "UserPoolId": POOL_ID,
}


def _request(*, client, desired_state, previous_state=None):
    return SimpleNamespace(
        aws_client_factory=SimpleNamespace(cognito_idp=client),
        custom_context={},
        desired_state=desired_state,
        previous_state=previous_state,
        logical_resource_id="ApiResourceServer",
        stack_name="enterprise",
        region_name="us-east-1",
    )


def _not_found(operation: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}}, operation
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
                    {"Error": {"Code": error.code, "Message": error.message}}, name
                ) from error

        return invoke


def test_resource_server_schema_plugin_and_ref_contract_are_closed():
    schema = CognitoUserPoolResourceServerProvider.SCHEMA
    plugin = CognitoUserPoolResourceServerProviderPlugin()

    plugin.load()

    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"Identifier", "Name", "UserPoolId"}
    assert schema["primaryIdentifier"] == [
        "/properties/UserPoolId",
        "/properties/Identifier",
    ]
    assert set(schema["createOnlyProperties"]) == {
        "/properties/Identifier",
        "/properties/UserPoolId",
    }
    assert PHYSICAL_RESOURCE_ID_SPECIAL_CASES["AWS::Cognito::UserPoolResourceServer"] == (
        "/properties/Identifier"
    )
    assert plugin.factory is CognitoUserPoolResourceServerProvider


def test_resource_server_create_read_update_delete_and_desired_immutability():
    client = MagicMock()
    client.create_resource_server.return_value = {"ResourceServer": RESOURCE_SERVER}
    client.describe_resource_server.return_value = {"ResourceServer": RESOURCE_SERVER}
    client.update_resource_server.return_value = {
        "ResourceServer": {**RESOURCE_SERVER, "Name": "Billgym Platform API"}
    }
    desired = copy.deepcopy(RESOURCE_SERVER)
    original = copy.deepcopy(desired)
    provider = CognitoUserPoolResourceServerProvider()

    created = provider.create(_request(client=client, desired_state=desired))
    read = provider.read(_request(client=client, desired_state=desired))
    updated = provider.update(
        _request(
            client=client,
            desired_state={**desired, "Name": "Billgym Platform API"},
            previous_state=desired,
        )
    )
    deleted = provider.delete(_request(client=client, desired_state=desired))

    assert desired == original
    assert created.status == OperationStatus.SUCCESS
    assert created.resource_model == RESOURCE_SERVER
    assert read.resource_model == RESOURCE_SERVER
    assert updated.resource_model["Name"] == "Billgym Platform API"
    assert deleted.status == OperationStatus.SUCCESS
    client.create_resource_server.assert_called_once_with(**RESOURCE_SERVER)
    client.describe_resource_server.assert_called_once_with(
        Identifier="billgym-api", UserPoolId=POOL_ID
    )
    client.update_resource_server.assert_called_once_with(
        Identifier="billgym-api",
        Name="Billgym Platform API",
        Scopes=RESOURCE_SERVER["Scopes"],
        UserPoolId=POOL_ID,
    )
    client.delete_resource_server.assert_called_once_with(
        Identifier="billgym-api", UserPoolId=POOL_ID
    )

    client.delete_resource_server.side_effect = _not_found("DeleteResourceServer")
    repeated = provider.delete(_request(client=client, desired_state=desired))
    assert repeated.status == OperationStatus.SUCCESS


def test_resource_server_cloudformation_contract_round_trips_against_native_provider():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    native_provider = CognitoIdpProvider()
    native_client = _NativeCognitoClient(native_provider, context)
    pool = native_provider.create_user_pool(context, {"PoolName": "resource-server-users"})[
        "UserPool"
    ]
    desired = {**RESOURCE_SERVER, "UserPoolId": pool["Id"]}
    resource_provider = CognitoUserPoolResourceServerProvider()

    try:
        created = resource_provider.create(_request(client=native_client, desired_state=desired))
        assert created.status == OperationStatus.SUCCESS
        assert created.resource_model == desired

        updated_state = {**desired, "Name": "Billgym Platform API", "Scopes": []}
        updated = resource_provider.update(
            _request(
                client=native_client,
                desired_state=updated_state,
                previous_state=created.resource_model,
            )
        )
        assert updated.status == OperationStatus.SUCCESS
        assert updated.resource_model == updated_state

        listed = resource_provider.list(
            _request(client=native_client, desired_state={"UserPoolId": pool["Id"]})
        )
        assert listed.resource_models == [updated_state]

        deleted = resource_provider.delete(
            _request(client=native_client, desired_state=updated.resource_model)
        )
        assert deleted.status == OperationStatus.SUCCESS
        repeated = resource_provider.delete(
            _request(client=native_client, desired_state=updated.resource_model)
        )
        assert repeated.status == OperationStatus.SUCCESS
    finally:
        native_provider.delete_user_pool(context, {"UserPoolId": pool["Id"]})


def test_resource_server_update_rejects_identity_change_before_io():
    client = MagicMock()
    provider = CognitoUserPoolResourceServerProvider()

    for desired in (
        {**RESOURCE_SERVER, "Identifier": "other"},
        {**RESOURCE_SERVER, "UserPoolId": "us-east-1_other"},
    ):
        result = provider.update(
            _request(client=client, desired_state=desired, previous_state=RESOURCE_SERVER)
        )
        assert result.status == OperationStatus.FAILED

    client.update_resource_server.assert_not_called()


def test_resource_server_list_is_complete_sorted_and_rejects_token_cycles():
    client = MagicMock()
    client.list_resource_servers.side_effect = [
        {
            "ResourceServers": [{**RESOURCE_SERVER, "Identifier": "z-api"}],
            "NextToken": "next",
        },
        {"ResourceServers": [{**RESOURCE_SERVER, "Identifier": "a-api"}]},
    ]
    provider = CognitoUserPoolResourceServerProvider()

    result = provider.list(_request(client=client, desired_state={"UserPoolId": POOL_ID}))

    assert result.status == OperationStatus.SUCCESS
    assert [model["Identifier"] for model in result.resource_models] == ["a-api", "z-api"]

    client.list_resource_servers.side_effect = [
        {"ResourceServers": [], "NextToken": "loop"},
        {"ResourceServers": [], "NextToken": "loop"},
    ]
    cycle = provider.list(_request(client=client, desired_state={"UserPoolId": POOL_ID}))
    assert cycle.status == OperationStatus.FAILED


def test_resource_server_rejects_unknown_or_invalid_properties_before_io():
    client = MagicMock()
    provider = CognitoUserPoolResourceServerProvider()

    cases = [
        {**RESOURCE_SERVER, "Unknown": True},
        {**RESOURCE_SERVER, "Name": ""},
        {**RESOURCE_SERVER, "Scopes": [{"ScopeName": "read"}]},
        {**RESOURCE_SERVER, "Scopes": RESOURCE_SERVER["Scopes"] * 51},
    ]
    for desired in cases:
        result = provider.create(_request(client=client, desired_state=desired))
        assert result.status == OperationStatus.FAILED

    client.create_resource_server.assert_not_called()
