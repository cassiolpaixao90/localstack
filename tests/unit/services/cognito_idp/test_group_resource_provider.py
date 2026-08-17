import copy
from types import SimpleNamespace
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolgroup import (
    CognitoUserPoolGroupProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolgroup_plugin import (
    CognitoUserPoolGroupProviderPlugin,
)

GROUP = {
    "Description": "Administrators",
    "GroupName": "admin",
    "Precedence": 1,
    "RoleArn": "arn:aws:iam::000000000000:role/admin",
}


def _request(*, client, desired_state, previous_state=None):
    return SimpleNamespace(
        aws_client_factory=SimpleNamespace(cognito_idp=client),
        custom_context={},
        desired_state=desired_state,
        previous_state=previous_state,
        logical_resource_id="AdminGroup",
        stack_name="enterprise",
        region_name="us-east-1",
    )


def _not_found(operation: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}}, operation
    )


def test_group_schema_plugin_and_ref_contract_are_closed():
    schema = CognitoUserPoolGroupProvider.SCHEMA
    plugin = CognitoUserPoolGroupProviderPlugin()

    plugin.load()

    assert schema["additionalProperties"] is False
    assert schema["primaryIdentifier"] == [
        "/properties/UserPoolId",
        "/properties/GroupName",
    ]
    assert schema["required"] == ["UserPoolId"]
    assert set(schema["createOnlyProperties"]) == {
        "/properties/GroupName",
        "/properties/UserPoolId",
    }
    assert PHYSICAL_RESOURCE_ID_SPECIAL_CASES["AWS::Cognito::UserPoolGroup"] == (
        "/properties/GroupName"
    )
    assert plugin.factory is CognitoUserPoolGroupProvider


def test_group_create_maps_state_without_mutating_desired():
    client = MagicMock()
    client.create_group.return_value = {"Group": GROUP}
    desired = {**GROUP, "UserPoolId": "us-east-1_pool"}
    original = copy.deepcopy(desired)

    result = CognitoUserPoolGroupProvider().create(_request(client=client, desired_state=desired))

    assert result.status == OperationStatus.SUCCESS
    assert desired == original
    assert result.resource_model == desired
    client.create_group.assert_called_once_with(**desired)


def test_group_read_and_delete_are_identity_bound_and_idempotent():
    client = MagicMock()
    client.get_group.return_value = {"Group": GROUP}
    state = {"GroupName": "admin", "UserPoolId": "us-east-1_pool"}
    provider = CognitoUserPoolGroupProvider()

    read = provider.read(_request(client=client, desired_state=state))
    deleted = provider.delete(_request(client=client, desired_state=state))

    assert read.status == OperationStatus.SUCCESS
    assert read.resource_model == {**GROUP, "UserPoolId": "us-east-1_pool"}
    assert deleted.status == OperationStatus.SUCCESS
    client.delete_group.assert_called_once_with(**state)

    client.delete_group.side_effect = _not_found("DeleteGroup")
    repeated = provider.delete(_request(client=client, desired_state=state))
    assert repeated.status == OperationStatus.SUCCESS


def test_group_update_changes_mutable_fields_and_reloads_state():
    client = MagicMock()
    client.get_group.return_value = {"Group": {**GROUP, "Description": "Updated"}}
    previous = {**GROUP, "UserPoolId": "us-east-1_pool"}
    desired = {
        **previous,
        "Description": "Updated",
    }

    result = CognitoUserPoolGroupProvider().update(
        _request(client=client, desired_state=desired, previous_state=previous)
    )

    assert result.status == OperationStatus.SUCCESS
    client.update_group.assert_called_once_with(
        Description="Updated", GroupName="admin", UserPoolId="us-east-1_pool"
    )
    assert result.resource_model["Description"] == "Updated"


def test_group_update_clears_string_properties_and_fails_closed_for_precedence_removal():
    client = MagicMock()
    client.get_group.return_value = {"Group": {"GroupName": "admin"}}
    previous = {**GROUP, "UserPoolId": "us-east-1_pool"}
    desired = {
        "GroupName": "admin",
        "Precedence": 1,
        "UserPoolId": "us-east-1_pool",
    }
    provider = CognitoUserPoolGroupProvider()

    cleared = provider.update(
        _request(client=client, desired_state=desired, previous_state=previous)
    )

    assert cleared.status == OperationStatus.SUCCESS
    client.update_group.assert_called_once_with(
        Description="", GroupName="admin", RoleArn="", UserPoolId="us-east-1_pool"
    )

    missing_precedence = {"GroupName": "admin", "UserPoolId": "us-east-1_pool"}
    rejected = provider.update(
        _request(client=client, desired_state=missing_precedence, previous_state=previous)
    )
    assert rejected.status == OperationStatus.FAILED
    assert "Precedence" in rejected.message


def test_group_list_is_complete_sorted_and_rejects_token_cycles():
    client = MagicMock()
    client.list_groups.side_effect = [
        {"Groups": [{"GroupName": "member"}], "NextToken": "next"},
        {"Groups": [{"GroupName": "admin"}]},
    ]
    provider = CognitoUserPoolGroupProvider()

    result = provider.list(_request(client=client, desired_state={"UserPoolId": "us-east-1_pool"}))

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_models == [
        {"GroupName": "admin", "UserPoolId": "us-east-1_pool"},
        {"GroupName": "member", "UserPoolId": "us-east-1_pool"},
    ]

    client.list_groups.side_effect = [
        {"Groups": [], "NextToken": "loop"},
        {"Groups": [], "NextToken": "loop"},
    ]
    cycle = provider.list(_request(client=client, desired_state={"UserPoolId": "us-east-1_pool"}))
    assert cycle.status == OperationStatus.FAILED
