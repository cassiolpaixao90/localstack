from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolregionalconfigurationattachment import (
    CognitoUserPoolRegionalConfigurationAttachmentProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolregionalconfigurationattachment_plugin import (
    CognitoUserPoolRegionalConfigurationAttachmentProviderPlugin,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolreplica import (
    CognitoUserPoolReplicaProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolreplica_plugin import (
    CognitoUserPoolReplicaProviderPlugin,
)

POOL_ID = "us-east-1_EXAMPLE"
REGION = "us-west-2"
ARN = f"arn:aws:cognito-idp:{REGION}:123456789012:userpool/{POOL_ID}"


def _request(client, desired, previous=None, custom_context=None):
    client.meta = SimpleNamespace(region_name=REGION)
    return SimpleNamespace(
        aws_client_factory=SimpleNamespace(cognito_idp=client),
        custom_context=custom_context if custom_context is not None else {},
        desired_state=desired,
        previous_state=previous,
        logical_resource_id="Replica",
        stack_name="enterprise",
    )


def _replica(status="INACTIVE"):
    return {
        "RegionName": REGION,
        "Role": "SECONDARY",
        "Status": status,
        "UserPoolArn": ARN,
    }


def test_official_replica_schemas_identifiers_and_registered_plugins():
    replica = CognitoUserPoolReplicaProvider.SCHEMA
    regional = CognitoUserPoolRegionalConfigurationAttachmentProvider.SCHEMA
    assert set(replica["properties"]) == {
        "RegionName",
        "UserPoolId",
        "UserPoolTagsAtCreate",
    }
    assert replica["primaryIdentifier"] == [
        "/properties/UserPoolId",
        "/properties/RegionName",
    ]
    assert set(replica["createOnlyProperties"]) == {
        "/properties/RegionName",
        "/properties/UserPoolId",
        "/properties/UserPoolTagsAtCreate",
    }
    assert set(regional["properties"]) == {
        "EmailConfiguration",
        "LambdaConfig",
        "SmsConfiguration",
        "Status",
        "UserPoolId",
        "UserPoolTags",
    }
    assert regional["primaryIdentifier"] == ["/properties/UserPoolId"]
    replica_plugin = CognitoUserPoolReplicaProviderPlugin()
    regional_plugin = CognitoUserPoolRegionalConfigurationAttachmentProviderPlugin()
    assert replica_plugin.factory is None
    assert regional_plugin.factory is None
    replica_plugin.load()
    regional_plugin.load()
    assert replica_plugin.factory is CognitoUserPoolReplicaProvider
    assert regional_plugin.factory is CognitoUserPoolRegionalConfigurationAttachmentProvider
    assert PHYSICAL_RESOURCE_ID_SPECIAL_CASES["AWS::Cognito::UserPoolReplica"] == (
        "</properties/UserPoolId>|</properties/RegionName>"
    )
    assert (
        PHYSICAL_RESOURCE_ID_SPECIAL_CASES["AWS::Cognito::UserPoolRegionalConfigurationAttachment"]
        == "/properties/UserPoolId"
    )
    plugin_index = (Path(__file__).parents[4] / "plux.ini").read_text()
    assert "aws::cognito::userpoolreplica =" in plugin_index
    assert "aws::cognito::userpoolregionalconfigurationattachment =" in plugin_index


def test_replica_create_polls_without_recreating_and_handles_response_loss():
    client = MagicMock()
    client.list_user_pool_replicas.side_effect = [
        {"UserPoolReplicas": []},
        {"UserPoolReplicas": [_replica("PENDING_CREATE")]},
        {"UserPoolReplicas": [_replica("INACTIVE")]},
    ]
    client.create_user_pool_replica.return_value = {"UserPoolReplica": _replica("PENDING_CREATE")}
    desired = {
        "RegionName": REGION,
        "UserPoolId": POOL_ID,
        "UserPoolTagsAtCreate": {"Owner": "stack"},
    }
    provider = CognitoUserPoolReplicaProvider()
    first = provider.create(_request(client, desired))
    second = provider.create(_request(client, desired, custom_context=first.custom_context))

    assert first.status == OperationStatus.IN_PROGRESS
    assert second.status == OperationStatus.SUCCESS
    client.create_user_pool_replica.assert_called_once_with(
        RegionName=REGION, UserPoolId=POOL_ID, UserPoolTags={"Owner": "stack"}
    )

    lost = MagicMock()
    lost.create_user_pool_replica.side_effect = RuntimeError("response lost")
    lost.list_user_pool_replicas.side_effect = [
        {"UserPoolReplicas": []},
        {"UserPoolReplicas": [_replica("INACTIVE")]},
    ]
    recovered = provider.create(_request(lost, desired))
    assert recovered.status == OperationStatus.SUCCESS

    preexisting = MagicMock()
    preexisting.list_user_pool_replicas.return_value = {"UserPoolReplicas": [_replica("INACTIVE")]}
    refused = provider.create(_request(preexisting, desired))
    assert refused.status == OperationStatus.FAILED
    assert refused.error_code == "AlreadyExists"
    preexisting.create_user_pool_replica.assert_not_called()


def test_replica_delete_transitions_inactive_then_polls_absence():
    client = MagicMock()
    client.list_user_pool_replicas.side_effect = [
        {"UserPoolReplicas": [_replica("ACTIVE")]},
        {"UserPoolReplicas": [_replica("INACTIVE")]},
        {"UserPoolReplicas": [_replica("PENDING_DELETE")]},
        {"UserPoolReplicas": []},
    ]
    state = {"RegionName": REGION, "UserPoolId": POOL_ID}
    provider = CognitoUserPoolReplicaProvider()

    first = provider.delete(_request(client, state, previous=state))
    second = provider.delete(
        _request(client, state, previous=state, custom_context=first.custom_context)
    )
    third = provider.delete(
        _request(client, state, previous=state, custom_context=second.custom_context)
    )

    assert [first.status, second.status, third.status] == [
        OperationStatus.IN_PROGRESS,
        OperationStatus.IN_PROGRESS,
        OperationStatus.SUCCESS,
    ]
    client.update_user_pool_replica.assert_called_once_with(
        RegionName=REGION, Status="INACTIVE", UserPoolId=POOL_ID
    )
    client.delete_user_pool_replica.assert_called_once_with(RegionName=REGION, UserPoolId=POOL_ID)


def test_replica_list_is_bounded_cycle_safe_and_returns_secondaries_only():
    client = MagicMock()
    client.list_user_pool_replicas.side_effect = [
        {
            "NextToken": "next",
            "UserPoolReplicas": [
                {**_replica("ACTIVE"), "RegionName": "us-east-1", "Role": "PRIMARY"}
            ],
        },
        {"UserPoolReplicas": [_replica()]},
    ]
    result = CognitoUserPoolReplicaProvider().list(_request(client, {"UserPoolId": POOL_ID}))
    assert result.status == OperationStatus.SUCCESS
    assert result.resource_models == [{"RegionName": REGION, "UserPoolId": POOL_ID}]

    cyclic = MagicMock()
    cyclic.list_user_pool_replicas.return_value = {
        "NextToken": "same",
        "UserPoolReplicas": [],
    }
    failed = CognitoUserPoolReplicaProvider().list(_request(cyclic, {"UserPoolId": POOL_ID}))
    assert failed.status == OperationStatus.FAILED


def test_regional_attachment_updates_only_official_apis_and_rolls_back():
    client = MagicMock()
    observed_pool = {
        "Arn": ARN,
        "EmailConfiguration": {"EmailSendingAccount": "COGNITO_DEFAULT"},
        "Id": POOL_ID,
        "LambdaConfig": {"PostConfirmation": "arn:old"},
        "Name": "users",
        "SmsConfiguration": {"SnsCallerArn": "arn:old-role"},
    }
    client.describe_user_pool.return_value = {"UserPool": observed_pool}
    client.list_user_pool_replicas.return_value = {"UserPoolReplicas": [_replica("INACTIVE")]}
    client.list_tags_for_resource.return_value = {"Tags": {"external": "preserve"}}
    desired = {
        "EmailConfiguration": {"EmailSendingAccount": "DEVELOPER"},
        "Status": "ACTIVE",
        "UserPoolId": POOL_ID,
        "UserPoolTags": {"owner": "stack"},
    }
    provider = CognitoUserPoolRegionalConfigurationAttachmentProvider()
    first = provider.create(_request(client, desired))
    client.list_user_pool_replicas.return_value = {"UserPoolReplicas": [_replica("ACTIVE")]}
    result = provider.create(_request(client, desired, custom_context=first.custom_context))
    assert first.status == OperationStatus.IN_PROGRESS
    assert result.status == OperationStatus.SUCCESS
    update = client.update_user_pool.call_args.kwargs
    assert update["EmailConfiguration"] == {"EmailSendingAccount": "DEVELOPER"}
    assert update["LambdaConfig"] == {"PostConfirmation": "arn:old"}
    assert update["UserPoolId"] == POOL_ID
    client.update_user_pool_replica.assert_called_once_with(
        RegionName=REGION, Status="ACTIVE", UserPoolId=POOL_ID
    )
    client.tag_resource.assert_called_once_with(ResourceArn=ARN, Tags={"owner": "stack"})
    client.untag_resource.assert_not_called()

    failing = MagicMock()
    failing.describe_user_pool.return_value = {"UserPool": observed_pool}
    failing.list_user_pool_replicas.return_value = {"UserPoolReplicas": [_replica("INACTIVE")]}
    failing.list_tags_for_resource.return_value = {"Tags": {"external": "preserve"}}
    failing.update_user_pool_replica.side_effect = [RuntimeError("lost"), None]
    try:
        CognitoUserPoolRegionalConfigurationAttachmentProvider().create(_request(failing, desired))
    except RuntimeError:
        pass
    assert failing.update_user_pool.call_count == 2


def test_regional_attachment_read_and_delete_preserve_external_tags():
    client = MagicMock()
    pool = {
        "Arn": ARN,
        "EmailConfiguration": {"EmailSendingAccount": "DEVELOPER"},
        "Id": POOL_ID,
        "Name": "users",
    }
    client.describe_user_pool.return_value = {"UserPool": pool}
    client.list_user_pool_replicas.return_value = {"UserPoolReplicas": [_replica("INACTIVE")]}
    client.list_tags_for_resource.return_value = {
        "Tags": {"external": "preserve", "owner": "stack"}
    }
    provider = CognitoUserPoolRegionalConfigurationAttachmentProvider()
    read = provider.read(_request(client, {"UserPoolId": POOL_ID}))
    assert read.status == OperationStatus.SUCCESS
    assert read.resource_model["Status"] == "INACTIVE"
    assert read.resource_model["UserPoolTags"] == {
        "external": "preserve",
        "owner": "stack",
    }

    state = {
        "EmailConfiguration": {"EmailSendingAccount": "DEVELOPER"},
        "Status": "INACTIVE",
        "UserPoolId": POOL_ID,
        "UserPoolTags": {"owner": "stack"},
    }
    deleted = provider.delete(_request(client, state, previous=state))
    assert deleted.status == OperationStatus.SUCCESS
    client.untag_resource.assert_called_once_with(ResourceArn=ARN, TagKeys=["owner"])
    assert client.update_user_pool.call_args.kwargs == {
        "PoolName": "users",
        "UserPoolId": POOL_ID,
    }
