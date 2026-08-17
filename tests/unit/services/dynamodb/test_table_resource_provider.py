import copy
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, call

import localstack.services.cloudformation.resource_provider as resource_provider_module
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
)
from localstack.services.dynamodb.resource_providers.aws_dynamodb_table import (
    CREATE_TABLE_ID,
    DDB_UPDATE_JOURNAL,
    DELETE_REQUESTED,
    DELETE_TABLE_ID,
    MAX_UPDATE_JOURNAL_FORWARD_ATTEMPTS,
    REPEATED_INVOCATION,
    UPDATE_TABLE_ID,
    DynamoDBTableProvider,
)


def test_create_applies_point_in_time_recovery_after_the_table_becomes_active():
    dynamodb = MagicMock()
    dynamodb.describe_table.return_value = {
        "Table": {
            "TableName": "enterprise-records",
            "TableId": "table-id-1",
            "TableStatus": "ACTIVE",
        }
    }
    request = SimpleNamespace(
        desired_state={
            "TableName": "enterprise-records",
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "PointInTimeRecoverySpecification": {
                "PointInTimeRecoveryEnabled": True,
            },
        },
        custom_context={REPEATED_INVOCATION: True, CREATE_TABLE_ID: "table-id-1"},
        aws_client_factory=SimpleNamespace(dynamodb=dynamodb),
    )

    result = DynamoDBTableProvider().create(request)

    assert result.status == OperationStatus.IN_PROGRESS
    dynamodb.update_continuous_backups.assert_called_once_with(
        TableName="enterprise-records",
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
    )


def test_create_translates_sse_without_mutating_the_resource_model():
    dynamodb = MagicMock()
    dynamodb.create_table.return_value = {
        "TableDescription": {
            "TableArn": "arn:aws:dynamodb:::table/enterprise-records",
            "TableId": "table-id-1",
        }
    }
    sse_specification = {
        "SSEEnabled": True,
        "SSEType": "KMS",
        "KMSMasterKeyId": "alias/enterprise",
    }
    request = SimpleNamespace(
        desired_state={
            "TableName": "enterprise-records",
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "SSESpecification": sse_specification,
        },
        custom_context={},
        aws_client_factory=SimpleNamespace(dynamodb=dynamodb),
    )

    result = DynamoDBTableProvider().create(request)

    assert result.status == OperationStatus.IN_PROGRESS
    assert result.resource_model["SSESpecification"] == {
        "SSEEnabled": True,
        "SSEType": "KMS",
        "KMSMasterKeyId": "alias/enterprise",
    }
    assert sse_specification == result.resource_model["SSESpecification"]
    dynamodb.create_table.assert_called_once_with(
        TableName="enterprise-records",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        SSESpecification={
            "Enabled": True,
            "SSEType": "KMS",
            "KMSMasterKeyId": "alias/enterprise",
        },
    )


def _dynamodb_with_table(*, status="ACTIVE", deletion_protection=False, pitr="DISABLED"):
    dynamodb = MagicMock()
    dynamodb.describe_table.return_value = {
        "Table": {
            "TableName": "enterprise-records",
            "TableId": "table-id-1",
            "TableArn": "arn:aws:dynamodb:us-east-1:000000000000:table/enterprise-records",
            "TableStatus": status,
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
            "DeletionProtectionEnabled": deletion_protection,
            "TableClassSummary": {"TableClass": "STANDARD"},
            "SSEDescription": {
                "Status": "ENABLED",
                "SSEType": "KMS",
                "KMSMasterKeyArn": "arn:aws:kms:us-east-1:000000000000:key/key-id",
            },
        }
    }
    dynamodb.describe_continuous_backups.return_value = {
        "ContinuousBackupsDescription": {
            "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": pitr}
        }
    }
    dynamodb.describe_time_to_live.return_value = {
        "TimeToLiveDescription": {
            "TimeToLiveStatus": "ENABLED",
            "AttributeName": "expiresAt",
        }
    }
    dynamodb.list_tags_of_resource.return_value = {
        "Tags": [{"Key": "Environment", "Value": "test"}]
    }
    dynamodb.describe_kinesis_streaming_destination.return_value = {
        "KinesisDataStreamDestinations": []
    }
    dynamodb.describe_contributor_insights.return_value = {"ContributorInsightsStatus": "DISABLED"}
    return dynamodb


def _request(*, dynamodb, desired_state, previous_state=None, custom_context=None):
    return SimpleNamespace(
        desired_state=desired_state,
        previous_state=previous_state or {},
        custom_context=custom_context or {},
        aws_client_factory=SimpleNamespace(dynamodb=dynamodb),
        stack_name="stack",
        logical_resource_id="Table",
    )


def test_create_stream_callback_does_not_create_the_table_twice():
    dynamodb = _dynamodb_with_table()
    desired_state = {
        "TableName": "enterprise-records",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "StreamSpecification": {"StreamViewType": "NEW_AND_OLD_IMAGES"},
    }

    result = DynamoDBTableProvider().create(
        _request(
            dynamodb=dynamodb,
            desired_state=desired_state,
            custom_context={REPEATED_INVOCATION: True, CREATE_TABLE_ID: "table-id-1"},
        )
    )

    assert result.status == OperationStatus.SUCCESS
    dynamodb.create_table.assert_not_called()


def test_create_does_not_mutate_nested_throughput_indexes_or_kinesis():
    dynamodb = MagicMock()
    dynamodb.create_table.return_value = {
        "TableDescription": {
            "TableArn": "arn:aws:dynamodb:us-east-1:000000000000:table/enterprise-records",
            "TableId": "table-id-1",
        }
    }
    desired_state = {
        "TableName": "enterprise-records",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "ProvisionedThroughput": {"ReadCapacityUnits": "5", "WriteCapacityUnits": "7"},
        "GlobalSecondaryIndexes": [
            {
                "IndexName": "by-kind",
                "KeySchema": [{"AttributeName": "kind", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": "3",
                    "WriteCapacityUnits": "4",
                },
            }
        ],
        "KinesisStreamSpecification": {"StreamArn": "arn:aws:kinesis:::stream/events"},
    }
    original = copy.deepcopy(desired_state)

    result = DynamoDBTableProvider().create(
        _request(dynamodb=dynamodb, desired_state=desired_state)
    )

    assert result.status == OperationStatus.IN_PROGRESS
    assert desired_state == original
    dynamodb.enable_kinesis_streaming_destination.assert_not_called()


def test_create_with_explicitly_disabled_ttl_does_not_send_redundant_disable():
    dynamodb = _dynamodb_with_table()
    dynamodb.describe_time_to_live.return_value = {
        "TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}
    }
    desired_state = {
        "TableName": "enterprise-records",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "TimeToLiveSpecification": {"Enabled": False, "AttributeName": "expiresAt"},
    }

    result = DynamoDBTableProvider().create(
        _request(
            dynamodb=dynamodb,
            desired_state=desired_state,
            custom_context={REPEATED_INVOCATION: True, CREATE_TABLE_ID: "table-id-1"},
        )
    )

    assert result.status == OperationStatus.SUCCESS
    dynamodb.update_time_to_live.assert_not_called()


def test_create_rejects_recreated_table_before_auxiliary_write():
    dynamodb = _dynamodb_with_table()
    dynamodb.describe_table.return_value["Table"]["TableId"] = "table-id-2"

    result = DynamoDBTableProvider().create(
        _request(
            dynamodb=dynamodb,
            desired_state={
                "TableName": "enterprise-records",
                "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
            },
            custom_context={REPEATED_INVOCATION: True, CREATE_TABLE_ID: "table-id-1"},
        )
    )

    assert result.status == OperationStatus.FAILED
    assert "identity changed" in result.message
    dynamodb.update_continuous_backups.assert_not_called()


def test_create_rechecks_table_identity_immediately_before_auxiliary_write():
    dynamodb = _dynamodb_with_table()
    original = copy.deepcopy(dynamodb.describe_table.return_value)
    replacement = copy.deepcopy(original)
    replacement["Table"]["TableId"] = "replacement-table-id"
    dynamodb.describe_table.side_effect = [original, replacement]

    result = DynamoDBTableProvider().create(
        _request(
            dynamodb=dynamodb,
            desired_state={
                "TableName": "enterprise-records",
                "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
            },
            custom_context={REPEATED_INVOCATION: True, CREATE_TABLE_ID: "table-id-1"},
        )
    )

    assert result.status == OperationStatus.FAILED
    assert "identity changed" in result.message
    dynamodb.update_continuous_backups.assert_not_called()


def test_read_reconstructs_table_and_auxiliary_settings():
    dynamodb = _dynamodb_with_table(pitr="ENABLED")
    request = _request(
        dynamodb=dynamodb,
        desired_state={"TableName": "enterprise-records"},
    )

    result = DynamoDBTableProvider().read(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {
        "TableName": "enterprise-records",
        "Arn": "arn:aws:dynamodb:us-east-1:000000000000:table/enterprise-records",
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "BillingMode": "PAY_PER_REQUEST",
        "DeletionProtectionEnabled": False,
        "TableClass": "STANDARD",
        "SSESpecification": {
            "SSEEnabled": True,
            "SSEType": "KMS",
            "KMSMasterKeyId": "arn:aws:kms:us-east-1:000000000000:key/key-id",
        },
        "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
        "TimeToLiveSpecification": {"Enabled": True, "AttributeName": "expiresAt"},
        "Tags": [{"Key": "Environment", "Value": "test"}],
    }


def test_read_omits_disabled_ttl_without_required_attribute_and_filters_gsi_metrics():
    dynamodb = _dynamodb_with_table()
    dynamodb.describe_table.return_value["Table"]["GlobalSecondaryIndexes"] = [
        {
            "IndexName": "by-kind",
            "KeySchema": [{"AttributeName": "kind", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
            "ProvisionedThroughput": {
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 7,
                "NumberOfDecreasesToday": 3,
            },
        }
    ]
    dynamodb.describe_time_to_live.return_value = {
        "TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}
    }

    result = DynamoDBTableProvider().read(
        _request(dynamodb=dynamodb, desired_state={"TableName": "enterprise-records"})
    )

    assert "TimeToLiveSpecification" not in result.resource_model
    assert result.resource_model["GlobalSecondaryIndexes"][0]["ProvisionedThroughput"] == {
        "ReadCapacityUnits": 5,
        "WriteCapacityUnits": 7,
    }


def test_read_returns_not_found_instead_of_raising():
    dynamodb = _dynamodb_with_table()
    dynamodb.exceptions.TableNotFoundException = type("TableNotFoundException", (Exception,), {})
    dynamodb.describe_table.side_effect = dynamodb.exceptions.TableNotFoundException()

    result = DynamoDBTableProvider().read(
        _request(dynamodb=dynamodb, desired_state={"TableName": "missing"})
    )

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "NotFound"
    assert "missing" in result.message


def test_read_rejects_hybrid_state_when_table_identity_changes():
    dynamodb = _dynamodb_with_table()
    old_description = copy.deepcopy(dynamodb.describe_table.return_value)
    new_description = copy.deepcopy(old_description)
    new_description["Table"]["TableId"] = "table-id-2"
    dynamodb.describe_table.side_effect = [old_description, new_description]

    result = DynamoDBTableProvider().read(
        _request(dynamodb=dynamodb, desired_state={"TableName": "enterprise-records"})
    )

    assert result.status == OperationStatus.FAILED
    assert "identity changed" in result.message


def test_update_waits_for_active_before_issuing_another_mutation():
    dynamodb = _dynamodb_with_table(status="UPDATING")
    desired_state = {
        "TableName": "enterprise-records",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "DeletionProtectionEnabled": True,
    }

    result = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired_state,
            previous_state={**desired_state, "DeletionProtectionEnabled": False},
            custom_context={"update_table_id": "table-id-1"},
        )
    )

    assert result.status == OperationStatus.IN_PROGRESS
    dynamodb.update_table.assert_not_called()
    dynamodb.update_continuous_backups.assert_not_called()


def test_update_waits_for_auxiliary_transition_before_issuing_another_mutation():
    dynamodb = _dynamodb_with_table(pitr="ENABLING")
    desired_state = {
        "TableName": "enterprise-records",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
        "Tags": [{"Key": "Environment", "Value": "production"}],
    }

    result = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired_state,
            previous_state={
                **desired_state,
                "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": False},
            },
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    assert result.status == OperationStatus.IN_PROGRESS
    dynamodb.update_continuous_backups.assert_not_called()
    dynamodb.tag_resource.assert_not_called()


def test_update_snapshots_table_identity_before_any_write():
    dynamodb = _dynamodb_with_table()
    state = {
        "TableName": "enterprise-records",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "DeletionProtectionEnabled": True,
    }

    result = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=state,
            previous_state={**state, "DeletionProtectionEnabled": False},
        )
    )

    assert result.status == OperationStatus.IN_PROGRESS
    assert result.custom_context[UPDATE_TABLE_ID] == "table-id-1"
    dynamodb.update_table.assert_not_called()
    dynamodb.update_continuous_backups.assert_not_called()


def test_update_rejects_recreated_table_before_any_write():
    dynamodb = _dynamodb_with_table()
    state = {
        "TableName": "enterprise-records",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
    }

    result = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=state,
            previous_state=state,
            custom_context={UPDATE_TABLE_ID: "old-table-id"},
        )
    )

    assert result.status == OperationStatus.FAILED
    assert "identity changed" in result.message
    dynamodb.update_table.assert_not_called()


def test_update_rechecks_identity_immediately_before_mutation():
    dynamodb = _dynamodb_with_table(pitr="ENABLED")
    old_description = copy.deepcopy(dynamodb.describe_table.return_value)
    new_description = copy.deepcopy(old_description)
    new_description["Table"]["TableId"] = "table-id-2"
    dynamodb.describe_table.side_effect = [old_description, new_description]
    state = {
        "TableName": "enterprise-records",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": False},
    }

    result = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=state,
            previous_state={
                **state,
                "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
            },
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    assert result.status == OperationStatus.FAILED
    assert "identity changed" in result.message
    dynamodb.update_continuous_backups.assert_not_called()


def test_update_changes_provisioned_throughput_when_billing_mode_is_omitted():
    dynamodb = _dynamodb_with_table()
    table = dynamodb.describe_table.return_value["Table"]
    table.pop("BillingModeSummary")
    table["ProvisionedThroughput"] = {
        "ReadCapacityUnits": 5,
        "WriteCapacityUnits": 5,
    }
    desired = {
        "TableName": "enterprise-records",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "ProvisionedThroughput": {"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
    }
    previous = {
        **desired,
        "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    }

    result = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    assert result.status == OperationStatus.IN_PROGRESS
    dynamodb.update_table.assert_called_once_with(
        TableName="enterprise-records",
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
    )


def test_update_waits_for_kinesis_updating_state():
    dynamodb = _dynamodb_with_table()
    dynamodb.describe_kinesis_streaming_destination.return_value = {
        "KinesisDataStreamDestinations": [
            {
                "StreamArn": "arn:aws:kinesis:::stream/events",
                "DestinationStatus": "UPDATING",
            }
        ]
    }
    state = {
        "TableName": "enterprise-records",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "KinesisStreamSpecification": {"StreamArn": "arn:aws:kinesis:::stream/events"},
    }

    result = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=state,
            previous_state=state,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    assert result.status == OperationStatus.IN_PROGRESS
    dynamodb.enable_kinesis_streaming_destination.assert_not_called()
    dynamodb.disable_kinesis_streaming_destination.assert_not_called()


def test_update_converges_one_mutation_at_a_time_without_mutating_desired_state():
    dynamodb = _dynamodb_with_table(deletion_protection=False, pitr="ENABLED")
    desired_state = {
        "TableName": "enterprise-records",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "DeletionProtectionEnabled": True,
        "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": False},
        "TimeToLiveSpecification": {"Enabled": True, "AttributeName": "expiresAt"},
        "Tags": [
            {"Key": "Environment", "Value": "production"},
            {"Key": "Owner", "Value": "platform"},
        ],
    }
    original = copy.deepcopy(desired_state)
    previous_state = {**copy.deepcopy(desired_state), "DeletionProtectionEnabled": False}
    previous_state["Tags"] = [
        {"Key": "Environment", "Value": "test"},
        {"Key": "Obsolete", "Value": "remove-me"},
    ]
    provider = DynamoDBTableProvider()
    dynamodb.list_tags_of_resource.return_value = {
        "Tags": [
            {"Key": "Environment", "Value": "test"},
            {"Key": "Obsolete", "Value": "remove-me"},
        ]
    }

    first = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired_state,
            previous_state=previous_state,
            custom_context={"update_table_id": "table-id-1"},
        )
    )
    assert first.status == OperationStatus.IN_PROGRESS
    dynamodb.update_continuous_backups.assert_called_once_with(
        TableName="enterprise-records",
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": False},
    )
    dynamodb.update_table.assert_not_called()

    dynamodb.update_continuous_backups.reset_mock()
    dynamodb.describe_continuous_backups.return_value["ContinuousBackupsDescription"][
        "PointInTimeRecoveryDescription"
    ]["PointInTimeRecoveryStatus"] = "DISABLED"
    second = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired_state,
            previous_state=previous_state,
            custom_context={"update_table_id": "table-id-1"},
        )
    )
    assert second.status == OperationStatus.IN_PROGRESS
    assert DDB_UPDATE_JOURNAL in second.custom_context
    assert second.custom_context[DDB_UPDATE_JOURNAL]["phase"] == "forward"
    dynamodb.untag_resource.assert_not_called()
    dynamodb.tag_resource.assert_not_called()

    assert desired_state == original


def test_update_rejects_unsupported_index_shape_changes_without_false_success():
    dynamodb = _dynamodb_with_table()
    desired_state = {
        "TableName": "enterprise-records",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "kind", "AttributeType": "S"},
        ],
        "BillingMode": "PAY_PER_REQUEST",
        "GlobalSecondaryIndexes": [
            {
                "IndexName": "by-kind",
                "KeySchema": [{"AttributeName": "kind", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    }

    result = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired_state,
            previous_state={
                "TableName": "enterprise-records",
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "BillingMode": "PAY_PER_REQUEST",
            },
            custom_context={"update_table_id": "table-id-1"},
        )
    )

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "InvalidRequest"
    assert "GlobalSecondaryIndexes" in result.message
    assert dynamodb.update_table.call_args_list == []


def test_delete_is_idempotent_when_the_table_is_already_missing():
    dynamodb = _dynamodb_with_table()
    dynamodb.exceptions.ResourceNotFoundException = type(
        "ResourceNotFoundException", (Exception,), {}
    )
    dynamodb.describe_table.side_effect = dynamodb.exceptions.ResourceNotFoundException()

    result = DynamoDBTableProvider().delete(
        _request(dynamodb=dynamodb, desired_state={"TableName": "missing"})
    )

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {}
    dynamodb.delete_table.assert_not_called()


def test_delete_waits_for_existing_delete_instead_of_sending_duplicate_request():
    dynamodb = _dynamodb_with_table(status="DELETING")

    result = DynamoDBTableProvider().delete(
        _request(
            dynamodb=dynamodb,
            desired_state={"TableName": "enterprise-records"},
            custom_context={DELETE_TABLE_ID: "table-id-1", DELETE_REQUESTED: True},
        )
    )

    assert result.status == OperationStatus.IN_PROGRESS
    dynamodb.delete_table.assert_not_called()


def test_list_paginates_all_tables():
    dynamodb = MagicMock()
    dynamodb.list_tables.side_effect = [
        {"TableNames": ["alpha"], "LastEvaluatedTableName": "alpha"},
        {"TableNames": ["beta"]},
    ]

    result = DynamoDBTableProvider().list(_request(dynamodb=dynamodb, desired_state={}))

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_models == [{"TableName": "alpha"}, {"TableName": "beta"}]
    assert dynamodb.list_tables.call_args_list == [
        call(),
        call(ExclusiveStartTableName="alpha"),
    ]


def test_mutation_descriptor_uses_live_tag_before_image_and_is_json_serializable():
    dynamodb = _dynamodb_with_table()
    provider = DynamoDBTableProvider()
    live = {
        "TableName": "enterprise-records",
        "Arn": "arn:aws:dynamodb:us-east-1:000000000000:table/enterprise-records",
        "Tags": [{"Key": "Owner", "Value": "external-live-value"}],
    }

    mutation = provider._next_auxiliary_mutation(
        dynamodb=dynamodb,
        desired={
            "TableName": "enterprise-records",
            "Tags": [{"Key": "Owner", "Value": "stack-value"}],
        },
        previous={
            "TableName": "enterprise-records",
            "Tags": [{"Key": "Owner", "Value": "stale-template-value"}],
        },
        live=live,
        create=False,
    )

    assert json.loads(json.dumps(mutation.descriptor)) == {
        "kind": "tag_upsert",
        "before": {"Owner": "external-live-value"},
        "after": {"Owner": "stack-value"},
    }
    mutation.apply()
    dynamodb.tag_resource.assert_called_once_with(
        ResourceArn=live["Arn"],
        Tags=[{"Key": "Owner", "Value": "stack-value"}],
    )


def test_stream_view_change_is_planned_as_disable_then_enable():
    dynamodb = _dynamodb_with_table()
    provider = DynamoDBTableProvider()
    desired = {
        "TableName": "enterprise-records",
        "StreamSpecification": {"StreamViewType": "NEW_AND_OLD_IMAGES"},
    }
    previous = {
        "TableName": "enterprise-records",
        "StreamSpecification": {"StreamViewType": "KEYS_ONLY"},
    }

    disable = provider._next_table_mutation(
        dynamodb,
        desired,
        previous,
        {
            "TableName": "enterprise-records",
            "StreamSpecification": {"StreamViewType": "KEYS_ONLY"},
        },
    )
    assert disable.descriptor == {
        "kind": "stream",
        "before": {"StreamViewType": "KEYS_ONLY"},
        "after": None,
    }
    disable.apply()
    dynamodb.update_table.assert_called_once_with(
        TableName="enterprise-records",
        StreamSpecification={"StreamEnabled": False},
    )

    dynamodb.update_table.reset_mock()
    enable = provider._next_table_mutation(
        dynamodb,
        desired,
        previous,
        {"TableName": "enterprise-records"},
    )
    assert enable.descriptor == {
        "kind": "stream",
        "before": None,
        "after": {"StreamViewType": "NEW_AND_OLD_IMAGES"},
    }
    enable.apply()
    dynamodb.update_table.assert_called_once_with(
        TableName="enterprise-records",
        StreamSpecification={
            "StreamEnabled": True,
            "StreamViewType": "NEW_AND_OLD_IMAGES",
        },
    )


def test_all_update_mutation_kinds_have_closed_serializable_before_after_descriptors():
    dynamodb = _dynamodb_with_table()
    provider = DynamoDBTableProvider()
    table_name = "enterprise-records"
    table_arn = "arn:aws:dynamodb:us-east-1:000000000000:table/enterprise-records"

    mutations = [
        provider._next_table_mutation(
            dynamodb,
            {
                "TableName": table_name,
                "BillingMode": "PROVISIONED",
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": 10,
                    "WriteCapacityUnits": 12,
                },
            },
            {"TableName": table_name, "BillingMode": "PAY_PER_REQUEST"},
            {"TableName": table_name, "BillingMode": "PAY_PER_REQUEST"},
        ),
        provider._next_table_mutation(
            dynamodb,
            {"TableName": table_name, "TableClass": "STANDARD_INFREQUENT_ACCESS"},
            {"TableName": table_name, "TableClass": "STANDARD"},
            {"TableName": table_name, "TableClass": "STANDARD"},
        ),
        provider._next_auxiliary_mutation(
            dynamodb=dynamodb,
            desired={
                "TableName": table_name,
                "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
            },
            previous={"TableName": table_name},
            live={
                "TableName": table_name,
                "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": False},
            },
            create=False,
        ),
        provider._next_auxiliary_mutation(
            dynamodb=dynamodb,
            desired={
                "TableName": table_name,
                "TimeToLiveSpecification": {"Enabled": True, "AttributeName": "expiresAt"},
            },
            previous={"TableName": table_name},
            live={"TableName": table_name},
            create=False,
        ),
        provider._next_auxiliary_mutation(
            dynamodb=dynamodb,
            desired={
                "TableName": table_name,
                "KinesisStreamSpecification": {"StreamArn": "arn:aws:kinesis:::stream/new"},
            },
            previous={"TableName": table_name},
            live={"TableName": table_name},
            create=False,
        ),
        provider._next_auxiliary_mutation(
            dynamodb=dynamodb,
            desired={"TableName": table_name, "Tags": []},
            previous={
                "TableName": table_name,
                "Tags": [{"Key": "Owned", "Value": "template-old"}],
            },
            live={
                "TableName": table_name,
                "Arn": table_arn,
                "Tags": [{"Key": "Owned", "Value": "live-old"}],
            },
            create=False,
        ),
        provider._next_auxiliary_mutation(
            dynamodb=dynamodb,
            desired={"TableName": table_name, "DeletionProtectionEnabled": True},
            previous={"TableName": table_name, "DeletionProtectionEnabled": False},
            live={"TableName": table_name, "DeletionProtectionEnabled": False},
            create=False,
        ),
    ]

    descriptors = [json.loads(json.dumps(mutation.descriptor)) for mutation in mutations]

    assert [descriptor["kind"] for descriptor in descriptors] == [
        "capacity",
        "table_class",
        "pitr",
        "ttl",
        "kinesis",
        "tag_remove",
        "deletion_protection",
    ]
    assert all(set(descriptor) == {"kind", "before", "after"} for descriptor in descriptors)
    assert descriptors[0]["before"] == {"BillingMode": "PAY_PER_REQUEST"}
    assert descriptors[0]["after"] == {
        "BillingMode": "PROVISIONED",
        "ProvisionedThroughput": {"ReadCapacityUnits": 10, "WriteCapacityUnits": 12},
    }
    assert descriptors[1] == {
        "kind": "table_class",
        "before": "STANDARD",
        "after": "STANDARD_INFREQUENT_ACCESS",
    }
    assert descriptors[2] == {
        "kind": "pitr",
        "before": {"PointInTimeRecoveryEnabled": False},
        "after": {"PointInTimeRecoveryEnabled": True},
    }
    assert descriptors[3] == {
        "kind": "ttl",
        "before": {"Enabled": False},
        "after": {"Enabled": True, "AttributeName": "expiresAt"},
    }
    assert descriptors[4] == {
        "kind": "kinesis",
        "before": None,
        "after": {"StreamArn": "arn:aws:kinesis:::stream/new"},
    }
    assert descriptors[5] == {
        "kind": "tag_remove",
        "before": {"Owned": "live-old"},
        "after": {},
    }
    assert descriptors[6] == {
        "kind": "deletion_protection",
        "before": False,
        "after": True,
    }


def _stateful_journal_dynamodb(*, tags: dict[str, str], deletion_protection: bool = False):
    dynamodb = _dynamodb_with_table(deletion_protection=deletion_protection)
    state = {
        "tags": copy.deepcopy(tags),
        "deletion_protection": deletion_protection,
    }

    def describe_table(**_kwargs):
        response = copy.deepcopy(dynamodb._journal_description)
        response["Table"]["DeletionProtectionEnabled"] = state["deletion_protection"]
        return response

    def list_tags(**_kwargs):
        return {
            "Tags": [{"Key": key, "Value": value} for key, value in sorted(state["tags"].items())]
        }

    def tag_resource(*, Tags, **_kwargs):
        state["tags"].update({tag["Key"]: tag["Value"] for tag in Tags})

    def untag_resource(*, TagKeys, **_kwargs):
        for key in TagKeys:
            state["tags"].pop(key, None)

    def update_table(*, DeletionProtectionEnabled, **_kwargs):
        state["deletion_protection"] = DeletionProtectionEnabled

    dynamodb._journal_description = copy.deepcopy(dynamodb.describe_table.return_value)
    dynamodb.describe_table.side_effect = describe_table
    dynamodb.list_tags_of_resource.side_effect = list_tags
    dynamodb.tag_resource.side_effect = tag_resource
    dynamodb.untag_resource.side_effect = untag_resource
    dynamodb.update_table.side_effect = update_table
    return dynamodb, state


def test_update_prepares_compensation_journal_before_reversible_writes():
    dynamodb, _state = _stateful_journal_dynamodb(tags={"Owner": "external-live"})
    desired = {
        "TableName": "enterprise-records",
        "Tags": [
            {"Key": "Owner", "Value": "stack"},
            {"Key": "Managed", "Value": "true"},
        ],
        "DeletionProtectionEnabled": True,
    }
    previous = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": "Owner", "Value": "template-old"}],
        "DeletionProtectionEnabled": False,
    }

    result = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    assert result.status == OperationStatus.IN_PROGRESS
    journal = result.custom_context[DDB_UPDATE_JOURNAL]
    assert journal["phase"] == "forward"
    assert [entry["kind"] for entry in journal["entries"]] == [
        "tag_upsert",
        "tag_create",
        "deletion_protection",
    ]
    assert journal["entries"][0]["before"] == {"Owner": "external-live"}
    assert all(entry["state"] == "prepared" for entry in journal["entries"])
    dynamodb.tag_resource.assert_not_called()
    dynamodb.untag_resource.assert_not_called()
    dynamodb.update_table.assert_not_called()


def test_update_compensates_live_tag_before_image_after_apply_then_raise():
    dynamodb, state = _stateful_journal_dynamodb(tags={"Owner": "external-live"})
    desired = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": "Owner", "Value": "stack"}],
        "DeletionProtectionEnabled": True,
    }
    previous = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": "Owner", "Value": "template-old"}],
        "DeletionProtectionEnabled": False,
    }
    original_desired = copy.deepcopy(desired)
    original_previous = copy.deepcopy(previous)
    provider = DynamoDBTableProvider()

    first = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )
    context = first.custom_context

    second = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=context,
        )
    )
    assert second.status == OperationStatus.IN_PROGRESS
    assert state["tags"] == {"Owner": "stack"}

    def apply_then_raise(*, DeletionProtectionEnabled, **_kwargs):
        state["deletion_protection"] = DeletionProtectionEnabled
        if DeletionProtectionEnabled:
            raise RuntimeError("simulated response loss")

    dynamodb.update_table.side_effect = apply_then_raise
    result = second
    for _ in range(8):
        result = provider.update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context=result.custom_context,
            )
        )
        if result.status == OperationStatus.FAILED:
            break

    assert result.status == OperationStatus.FAILED
    assert "simulated response loss" in result.message
    assert state == {
        "tags": {"Owner": "external-live"},
        "deletion_protection": False,
    }
    assert desired == original_desired
    assert previous == original_previous


def test_update_compensation_removes_tag_that_was_absent_from_live_state():
    dynamodb, state = _stateful_journal_dynamodb(tags={})
    desired = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": "Managed", "Value": "true"}],
        "DeletionProtectionEnabled": True,
    }
    previous = {"TableName": "enterprise-records", "DeletionProtectionEnabled": False}
    provider = DynamoDBTableProvider()

    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )

    def fail_deletion_protection(**_kwargs):
        raise RuntimeError("deletion protection rejected")

    dynamodb.update_table.side_effect = fail_deletion_protection
    for _ in range(8):
        result = provider.update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context=result.custom_context,
            )
        )
        if result.status == OperationStatus.FAILED:
            break

    assert result.status == OperationStatus.FAILED
    assert state["tags"] == {}


def test_journal_waits_for_deletion_protection_transition_instead_of_rolling_back():
    dynamodb, state = _stateful_journal_dynamodb(tags={})
    desired = {"TableName": "enterprise-records", "DeletionProtectionEnabled": True}
    previous = {"TableName": "enterprise-records", "DeletionProtectionEnabled": False}
    provider = DynamoDBTableProvider()

    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    def update_enters_transition(*, DeletionProtectionEnabled, **_kwargs):
        state["deletion_protection"] = DeletionProtectionEnabled
        dynamodb._journal_description["Table"]["TableStatus"] = "UPDATING"

    dynamodb.update_table.side_effect = update_enters_transition
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )

    journal = result.custom_context[DDB_UPDATE_JOURNAL]
    assert result.status == OperationStatus.IN_PROGRESS
    assert journal["phase"] == "forward"
    assert journal["entries"][0]["state"] == "applying"

    dynamodb._journal_description["Table"]["TableStatus"] = "ACTIVE"
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )

    assert result.status == OperationStatus.SUCCESS
    assert state["deletion_protection"] is True


def test_journal_waits_for_transition_while_compensating_deletion_protection():
    dynamodb, state = _stateful_journal_dynamodb(tags={})
    desired = {"TableName": "enterprise-records", "DeletionProtectionEnabled": True}
    previous = {"TableName": "enterprise-records", "DeletionProtectionEnabled": False}
    provider = DynamoDBTableProvider()
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    def forward_apply_then_raise(*, DeletionProtectionEnabled, **_kwargs):
        state["deletion_protection"] = DeletionProtectionEnabled
        raise RuntimeError("forward response lost")

    dynamodb.update_table.side_effect = forward_apply_then_raise
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    assert result.custom_context[DDB_UPDATE_JOURNAL]["phase"] == "rollback"

    def rollback_enters_transition(*, DeletionProtectionEnabled, **_kwargs):
        state["deletion_protection"] = DeletionProtectionEnabled
        dynamodb._journal_description["Table"]["TableStatus"] = "UPDATING"

    dynamodb.update_table.side_effect = rollback_enters_transition
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    assert result.custom_context[DDB_UPDATE_JOURNAL]["entries"][0]["state"] == "rolling_back"

    dynamodb._journal_description["Table"]["TableStatus"] = "ACTIVE"
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )

    assert result.status == OperationStatus.FAILED
    assert "forward response lost" in result.message
    assert state["deletion_protection"] is False


def test_mixed_update_does_not_claim_compensating_journal():
    dynamodb = _dynamodb_with_table()
    table = dynamodb.describe_table.return_value["Table"]
    table.pop("BillingModeSummary")
    table["ProvisionedThroughput"] = {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
    desired = {
        "TableName": "enterprise-records",
        "ProvisionedThroughput": {"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
        "Tags": [{"Key": "Owner", "Value": "stack"}],
    }
    previous = {
        "TableName": "enterprise-records",
        "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        "Tags": [{"Key": "Owner", "Value": "old"}],
    }

    result = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    assert result.status == OperationStatus.IN_PROGRESS
    assert DDB_UPDATE_JOURNAL not in result.custom_context


def test_journal_does_not_take_ownership_of_external_convergence():
    dynamodb, state = _stateful_journal_dynamodb(tags={"Owner": "external-old"})
    desired = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": "Owner", "Value": "stack"}],
        "DeletionProtectionEnabled": True,
    }
    previous = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": "Owner", "Value": "template-old"}],
        "DeletionProtectionEnabled": False,
    }
    provider = DynamoDBTableProvider()
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    state["tags"]["Owner"] = "stack"
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    assert result.custom_context[DDB_UPDATE_JOURNAL]["entries"][0]["state"] == "skipped"

    dynamodb.update_table.side_effect = RuntimeError("deletion protection rejected")
    for _ in range(5):
        result = provider.update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context=result.custom_context,
            )
        )
        if result.status == OperationStatus.FAILED:
            break

    assert result.status == OperationStatus.FAILED
    assert state["tags"] == {"Owner": "stack"}
    dynamodb.tag_resource.assert_not_called()
    dynamodb.untag_resource.assert_not_called()


def test_journal_reconciles_write_when_the_first_post_write_read_fails():
    dynamodb, state = _stateful_journal_dynamodb(tags={"Owner": "external-old"})
    desired = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": "Owner", "Value": "stack"}],
    }
    previous = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": "Owner", "Value": "template-old"}],
    }
    provider = DynamoDBTableProvider()
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    original_describe = dynamodb.describe_table.side_effect
    fail_next_describe = {"value": False}

    def describe_with_one_failure(**kwargs):
        if fail_next_describe["value"]:
            fail_next_describe["value"] = False
            raise RuntimeError("post-write read lost")
        return original_describe(**kwargs)

    def apply_then_break_observation(*, Tags, **_kwargs):
        state["tags"].update({tag["Key"]: tag["Value"] for tag in Tags})
        fail_next_describe["value"] = True

    dynamodb.describe_table.side_effect = describe_with_one_failure
    dynamodb.tag_resource.side_effect = apply_then_break_observation
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    journal = result.custom_context[DDB_UPDATE_JOURNAL]
    assert journal["phase"] == "rollback"
    assert journal["entries"][0]["state"] == "applying"

    for _ in range(4):
        result = provider.update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context=result.custom_context,
            )
        )
        if result.status == OperationStatus.FAILED:
            break

    assert result.status == OperationStatus.FAILED
    assert state["tags"] == {"Owner": "external-old"}


def test_journal_fails_closed_for_falsey_or_forged_context():
    desired = {"TableName": "enterprise-records", "Tags": [{"Key": "Owner", "Value": "x"}]}
    previous = {"TableName": "enterprise-records", "Tags": []}
    for invalid in ({}, [], False, None, 0):
        dynamodb = _dynamodb_with_table()
        result = DynamoDBTableProvider().update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context={UPDATE_TABLE_ID: "table-id-1", DDB_UPDATE_JOURNAL: invalid},
            )
        )
        assert result.status == OperationStatus.FAILED
        dynamodb.describe_table.assert_not_called()
        dynamodb.tag_resource.assert_not_called()
        dynamodb.untag_resource.assert_not_called()
        dynamodb.update_table.assert_not_called()

    dynamodb, _state = _stateful_journal_dynamodb(tags={})
    prepared = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )
    invalid_ownership = copy.deepcopy(prepared.custom_context)
    invalid_journal = invalid_ownership[DDB_UPDATE_JOURNAL]
    invalid_journal["phase"] = "rollback"
    invalid_journal["failure"] = "forged failure"
    invalid_journal["entries"][0]["state"] = "applied"
    invalid_journal["entries"][0]["owned_keys"] = []
    dynamodb.describe_table.reset_mock()
    result = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=invalid_ownership,
        )
    )
    assert result.status == OperationStatus.FAILED
    dynamodb.describe_table.assert_not_called()

    forged = copy.deepcopy(prepared.custom_context)
    forged[DDB_UPDATE_JOURNAL]["entries"][0]["after"] = {"Unexpected": "evil"}
    result = DynamoDBTableProvider().update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=forged,
        )
    )
    assert result.status == OperationStatus.FAILED
    dynamodb.tag_resource.assert_not_called()

    for field, invalid_value in (("phase", []), ("entries.kind", {})):
        malformed = copy.deepcopy(prepared.custom_context)
        if field == "phase":
            malformed[DDB_UPDATE_JOURNAL]["phase"] = invalid_value
        else:
            malformed[DDB_UPDATE_JOURNAL]["entries"][0]["kind"] = invalid_value
        dynamodb.describe_table.reset_mock()
        result = DynamoDBTableProvider().update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context=malformed,
            )
        )
        assert result.status == OperationStatus.FAILED
        dynamodb.describe_table.assert_not_called()


def test_journal_compensates_only_keys_proven_to_have_partially_applied():
    dynamodb, state = _stateful_journal_dynamodb(tags={"First": "old", "Second": "old"})
    desired = {
        "TableName": "enterprise-records",
        "Tags": [
            {"Key": "First", "Value": "new"},
            {"Key": "Second", "Value": "new"},
        ],
    }
    previous = {
        "TableName": "enterprise-records",
        "Tags": [
            {"Key": "First", "Value": "old"},
            {"Key": "Second", "Value": "old"},
        ],
    }
    provider = DynamoDBTableProvider()
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    def partially_apply_then_raise(*, Tags, **_kwargs):
        state["tags"][Tags[0]["Key"]] = Tags[0]["Value"]
        raise RuntimeError("partial tag application")

    dynamodb.tag_resource.side_effect = partially_apply_then_raise
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    owned = result.custom_context[DDB_UPDATE_JOURNAL]["entries"][0]["owned_keys"]
    assert owned == ["First"]

    dynamodb.tag_resource.side_effect = lambda *, Tags, **_kwargs: state["tags"].update(
        {tag["Key"]: tag["Value"] for tag in Tags}
    )
    for _ in range(4):
        result = provider.update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context=result.custom_context,
            )
        )
        if result.status == OperationStatus.FAILED:
            break

    assert result.status == OperationStatus.FAILED
    assert state["tags"] == {"First": "old", "Second": "old"}


def test_deploy_loop_propagates_journal_until_compensation_finishes(monkeypatch):
    dynamodb, state = _stateful_journal_dynamodb(tags={"Owner": "external-live"})
    desired = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": "Owner", "Value": "stack"}],
        "DeletionProtectionEnabled": True,
    }
    previous = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": "Owner", "Value": "template-old"}],
        "DeletionProtectionEnabled": False,
    }

    def apply_then_raise(*, DeletionProtectionEnabled, **_kwargs):
        state["deletion_protection"] = DeletionProtectionEnabled
        if DeletionProtectionEnabled:
            raise RuntimeError("response lost inside deploy loop")

    dynamodb.update_table.side_effect = apply_then_raise
    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")

    def execute_action(provider, payload):
        return provider.update(
            _request(
                dynamodb=dynamodb,
                desired_state=payload["requestData"]["resourceProperties"],
                previous_state=payload["requestData"]["previousResourceProperties"],
                custom_context=payload["callbackContext"],
            )
        )

    monkeypatch.setattr(executor, "execute_action", execute_action)
    monkeypatch.setattr(resource_provider_module.config, "CFN_NO_WAIT_ITERATIONS", 100)
    result = executor.deploy_loop(
        DynamoDBTableProvider(),
        resource={},
        raw_payload={
            "resourceType": "AWS::DynamoDB::Table",
            "action": "Modify",
            "callbackContext": {UPDATE_TABLE_ID: "table-id-1"},
            "requestData": {
                "logicalResourceId": "Table",
                "resourceProperties": desired,
                "previousResourceProperties": previous,
            },
        },
        max_timeout=1,
        sleep_time=0.001,
    )

    assert result.status == OperationStatus.FAILED
    assert "response lost inside deploy loop" in result.message
    assert state == {
        "tags": {"Owner": "external-live"},
        "deletion_protection": False,
    }


def test_journal_supports_replacing_fifty_tags_without_false_overflow():
    old_tags = {f"Old{index:02d}": "old" for index in range(50)}
    new_tags = {f"New{index:02d}": "new" for index in range(50)}
    dynamodb, _state = _stateful_journal_dynamodb(tags=old_tags)
    desired = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": key, "Value": value} for key, value in new_tags.items()],
    }
    previous = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": key, "Value": value} for key, value in old_tags.items()],
    }
    provider = DynamoDBTableProvider()

    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    assert result.status == OperationStatus.IN_PROGRESS
    entries = result.custom_context[DDB_UPDATE_JOURNAL]["entries"]
    assert len(entries) == 2
    assert [entry["kind"] for entry in entries] == ["tag_remove", "tag_create"]
    assert sum(len(entry["before"]) + len(entry["after"]) for entry in entries) == 100

    callbacks = 1
    while result.status == OperationStatus.IN_PROGRESS and callbacks < 10:
        callbacks += 1
        result = provider.update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context=result.custom_context,
            )
        )

    assert result.status == OperationStatus.SUCCESS
    assert callbacks <= 5
    assert dynamodb.describe_table.call_count <= 20
    assert dynamodb.list_tags_of_resource.call_count <= 10
    assert dynamodb.tag_resource.call_count == 1
    assert dynamodb.untag_resource.call_count == 1


def test_journal_rechecks_all_after_images_before_success():
    dynamodb, state = _stateful_journal_dynamodb(tags={"Owner": "old"})
    desired = {"TableName": "enterprise-records", "Tags": [{"Key": "Owner", "Value": "new"}]}
    previous = {"TableName": "enterprise-records", "Tags": [{"Key": "Owner", "Value": "old"}]}
    provider = DynamoDBTableProvider()
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    state["tags"]["Owner"] = "external-drift"
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )

    assert result.status == OperationStatus.IN_PROGRESS
    assert result.custom_context[DDB_UPDATE_JOURNAL]["phase"] == "rollback"


def test_journal_attempt_budget_is_checked_before_writes_and_during_transition_waits():
    dynamodb, _state = _stateful_journal_dynamodb(tags={"Owner": "old"})
    desired = {"TableName": "enterprise-records", "Tags": [{"Key": "Owner", "Value": "new"}]}
    previous = {"TableName": "enterprise-records", "Tags": [{"Key": "Owner", "Value": "old"}]}
    provider = DynamoDBTableProvider()
    prepared = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )
    exhausted = copy.deepcopy(prepared.custom_context)
    exhausted[DDB_UPDATE_JOURNAL]["attempts"] = MAX_UPDATE_JOURNAL_FORWARD_ATTEMPTS
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=exhausted,
        )
    )
    assert result.status == OperationStatus.IN_PROGRESS
    assert result.custom_context[DDB_UPDATE_JOURNAL]["phase"] == "rollback"
    dynamodb.tag_resource.assert_not_called()

    waiting = copy.deepcopy(prepared.custom_context)
    dynamodb._journal_description["Table"]["TableStatus"] = "UPDATING"
    for callbacks in range(1, 60):
        result = provider.update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context=waiting,
            )
        )
        if result.status == OperationStatus.FAILED:
            break
        waiting = result.custom_context

    assert result.status == OperationStatus.FAILED
    assert callbacks < 50
    dynamodb.tag_resource.assert_not_called()


def test_journal_compensates_prior_entry_when_next_projection_read_fails():
    dynamodb, state = _stateful_journal_dynamodb(tags={"Owner": "external"})
    desired = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": "Owner", "Value": "stack"}],
        "DeletionProtectionEnabled": True,
    }
    previous = {
        "TableName": "enterprise-records",
        "Tags": [{"Key": "Owner", "Value": "old"}],
        "DeletionProtectionEnabled": False,
    }
    provider = DynamoDBTableProvider()
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    assert state["tags"] == {"Owner": "stack"}

    original_describe = dynamodb.describe_table.side_effect
    calls = {"count": 0}

    def fail_second_describe(**kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise RuntimeError("projection temporarily unavailable")
        return original_describe(**kwargs)

    dynamodb.describe_table.side_effect = fail_second_describe
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    assert result.custom_context[DDB_UPDATE_JOURNAL]["phase"] == "rollback"

    for _ in range(4):
        result = provider.update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context=result.custom_context,
            )
        )
        if result.status == OperationStatus.FAILED:
            break

    assert result.status == OperationStatus.FAILED
    assert state["tags"] == {"Owner": "external"}


def test_journal_reconciles_lost_confirmation_after_inverse_write():
    dynamodb, state = _stateful_journal_dynamodb(tags={"Owner": "external"})
    desired = {"TableName": "enterprise-records", "Tags": [{"Key": "Owner", "Value": "stack"}]}
    previous = {"TableName": "enterprise-records", "Tags": [{"Key": "Owner", "Value": "old"}]}
    provider = DynamoDBTableProvider()
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    def forward_apply_then_raise(*, Tags, **_kwargs):
        state["tags"].update({tag["Key"]: tag["Value"] for tag in Tags})
        raise RuntimeError("forward response lost")

    dynamodb.tag_resource.side_effect = forward_apply_then_raise
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )

    original_describe = dynamodb.describe_table.side_effect
    fail_next = {"value": False}

    def describe_after_inverse(**kwargs):
        if fail_next["value"]:
            fail_next["value"] = False
            raise RuntimeError("inverse confirmation lost")
        return original_describe(**kwargs)

    def inverse_then_break_confirmation(*, Tags, **_kwargs):
        state["tags"].update({tag["Key"]: tag["Value"] for tag in Tags})
        fail_next["value"] = True

    dynamodb.describe_table.side_effect = describe_after_inverse
    dynamodb.tag_resource.side_effect = inverse_then_break_confirmation
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    assert result.custom_context[DDB_UPDATE_JOURNAL]["entries"][0]["state"] == "rolling_back"

    for _ in range(3):
        result = provider.update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context=result.custom_context,
            )
        )
        if result.status == OperationStatus.FAILED:
            break

    assert result.status == OperationStatus.FAILED
    assert state["tags"] == {"Owner": "external"}


def test_journal_retries_transient_projection_read_before_inverse():
    dynamodb, state = _stateful_journal_dynamodb(tags={"Owner": "external"})
    desired = {"TableName": "enterprise-records", "Tags": [{"Key": "Owner", "Value": "stack"}]}
    previous = {"TableName": "enterprise-records", "Tags": [{"Key": "Owner", "Value": "old"}]}
    provider = DynamoDBTableProvider()
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    def apply_then_raise(*, Tags, **_kwargs):
        state["tags"].update({tag["Key"]: tag["Value"] for tag in Tags})
        raise RuntimeError("forward response lost")

    dynamodb.tag_resource.side_effect = apply_then_raise
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    original_describe = dynamodb.describe_table.side_effect
    calls = {"count": 0}

    def fail_inner_describe_once(**kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise RuntimeError("rollback projection unavailable")
        return original_describe(**kwargs)

    dynamodb.describe_table.side_effect = fail_inner_describe_once
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    entry = result.custom_context[DDB_UPDATE_JOURNAL]["entries"][0]
    assert entry["state"] == "applied"
    assert entry["owned_keys"] == ["Owner"]

    dynamodb.tag_resource.side_effect = lambda *, Tags, **_kwargs: state["tags"].update(
        {tag["Key"]: tag["Value"] for tag in Tags}
    )
    for _ in range(3):
        result = provider.update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context=result.custom_context,
            )
        )
        if result.status == OperationStatus.FAILED:
            break
    assert result.status == OperationStatus.FAILED
    assert state["tags"] == {"Owner": "external"}


def test_journal_survives_transient_top_level_table_read_during_rollback():
    dynamodb, state = _stateful_journal_dynamodb(tags={"Owner": "external"})
    desired = {"TableName": "enterprise-records", "Tags": [{"Key": "Owner", "Value": "stack"}]}
    previous = {"TableName": "enterprise-records", "Tags": [{"Key": "Owner", "Value": "old"}]}
    provider = DynamoDBTableProvider()
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context={UPDATE_TABLE_ID: "table-id-1"},
        )
    )

    def apply_then_raise(*, Tags, **_kwargs):
        state["tags"].update({tag["Key"]: tag["Value"] for tag in Tags})
        raise RuntimeError("forward response lost")

    dynamodb.tag_resource.side_effect = apply_then_raise
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    original_describe = dynamodb.describe_table.side_effect
    failed = {"value": False}

    def fail_top_level_once(**kwargs):
        if not failed["value"]:
            failed["value"] = True
            raise RuntimeError("top-level read unavailable")
        return original_describe(**kwargs)

    dynamodb.describe_table.side_effect = fail_top_level_once
    result = provider.update(
        _request(
            dynamodb=dynamodb,
            desired_state=desired,
            previous_state=previous,
            custom_context=result.custom_context,
        )
    )
    assert result.status == OperationStatus.IN_PROGRESS
    assert result.custom_context[DDB_UPDATE_JOURNAL]["entries"][0]["state"] == "applied"

    dynamodb.tag_resource.side_effect = lambda *, Tags, **_kwargs: state["tags"].update(
        {tag["Key"]: tag["Value"] for tag in Tags}
    )
    for _ in range(3):
        result = provider.update(
            _request(
                dynamodb=dynamodb,
                desired_state=desired,
                previous_state=previous,
                custom_context=result.custom_context,
            )
        )
        if result.status == OperationStatus.FAILED:
            break
    assert result.status == OperationStatus.FAILED
    assert state["tags"] == {"Owner": "external"}
