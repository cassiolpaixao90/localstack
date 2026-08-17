import json

import pytest
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.testing.pytest import markers
from localstack.utils.sync import retry


@markers.aws.only_localstack
def test_create_table_applies_point_in_time_recovery(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template=json.dumps(
            {
                "Resources": {
                    "Table": {
                        "Type": "AWS::DynamoDB::Table",
                        "Properties": {
                            "BillingMode": "PAY_PER_REQUEST",
                            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                            "PointInTimeRecoverySpecification": {
                                "PointInTimeRecoveryEnabled": True
                            },
                        },
                    }
                },
                "Outputs": {"TableName": {"Value": {"Ref": "Table"}}},
            }
        )
    )

    response = aws_client.dynamodb.describe_continuous_backups(TableName=stack.outputs["TableName"])

    assert (
        response["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"][
            "PointInTimeRecoveryStatus"
        ]
        == "ENABLED"
    )


def _table_template(*, pitr: bool, phase: str) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Table": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": pitr},
                    "TimeToLiveSpecification": {
                        "AttributeName": "expiresAt",
                        "Enabled": True,
                    },
                    "Tags": [
                        {"Key": "Environment", "Value": phase},
                        {"Key": "Owner", "Value": "platform"},
                    ],
                },
            }
        },
        "Outputs": {"TableName": {"Value": {"Ref": "Table"}}},
    }


@skip_if_legacy_engine()
@markers.aws.only_localstack
def test_table_update_preserves_identity_and_data_and_converges_auxiliary_state(
    deploy_cfn_template, aws_client
):
    deployment = deploy_cfn_template(
        template=json.dumps(_table_template(pitr=True, phase="create")),
        max_wait=90,
        delay_between_polls=1,
    )
    table_name = deployment.outputs["TableName"]
    before = aws_client.dynamodb.describe_table(TableName=table_name)["Table"]
    aws_client.dynamodb.put_item(
        TableName=table_name,
        Item={"pk": {"S": "record-1"}, "payload": {"S": "preserve-me"}},
    )

    aws_client.cloudformation.update_stack(
        StackName=deployment.stack_id,
        TemplateBody=json.dumps(_table_template(pitr=False, phase="update")),
    )
    aws_client.cloudformation.get_waiter("stack_update_complete").wait(
        StackName=deployment.stack_id,
        WaiterConfig={"Delay": 1, "MaxAttempts": 90},
    )

    after = aws_client.dynamodb.describe_table(TableName=table_name)["Table"]
    assert after["TableId"] == before["TableId"]
    assert after["TableArn"] == before["TableArn"]
    assert aws_client.dynamodb.get_item(TableName=table_name, Key={"pk": {"S": "record-1"}})[
        "Item"
    ]["payload"] == {"S": "preserve-me"}
    backups = aws_client.dynamodb.describe_continuous_backups(TableName=table_name)
    assert (
        backups["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"][
            "PointInTimeRecoveryStatus"
        ]
        == "DISABLED"
    )
    ttl = aws_client.dynamodb.describe_time_to_live(TableName=table_name)["TimeToLiveDescription"]
    assert (ttl["TimeToLiveStatus"], ttl["AttributeName"]) == ("ENABLED", "expiresAt")
    tags = aws_client.dynamodb.list_tags_of_resource(ResourceArn=after["TableArn"])["Tags"]
    observed_tags = {
        tag["Key"]: tag["Value"] for tag in tags if tag["Key"] in {"Environment", "Owner"}
    }
    assert observed_tags == {"Environment": "update", "Owner": "platform"}
    resource = aws_client.cloudformation.describe_stack_resource(
        StackName=deployment.stack_id,
        LogicalResourceId="Table",
    )["StackResourceDetail"]
    assert resource["ResourceStatus"] == "UPDATE_COMPLETE"

    deployment.destroy()
    with pytest.raises(aws_client.dynamodb.exceptions.ResourceNotFoundException):
        aws_client.dynamodb.describe_table(TableName=table_name)


@skip_if_legacy_engine()
@markers.aws.only_localstack
def test_failed_table_update_fails_closed_and_preserves_committed_template(
    deploy_cfn_template, aws_client
):
    initial_template = _table_template(pitr=True, phase="create")
    deployment = deploy_cfn_template(
        template=json.dumps(initial_template),
        max_wait=90,
        delay_between_polls=1,
    )
    table_name = deployment.outputs["TableName"]
    before = aws_client.dynamodb.describe_table(TableName=table_name)["Table"]
    invalid_update = _table_template(pitr=True, phase="create")
    properties = invalid_update["Resources"]["Table"]["Properties"]
    properties["AttributeDefinitions"].append({"AttributeName": "kind", "AttributeType": "S"})
    properties["GlobalSecondaryIndexes"] = [
        {
            "IndexName": "by-kind",
            "KeySchema": [{"AttributeName": "kind", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }
    ]

    aws_client.cloudformation.update_stack(
        StackName=deployment.stack_id,
        TemplateBody=json.dumps(invalid_update),
    )

    def wait_for_failed_rollback():
        current = aws_client.cloudformation.describe_stacks(StackName=deployment.stack_id)[
            "Stacks"
        ][0]
        assert current["StackStatus"] == "UPDATE_ROLLBACK_FAILED"
        return current

    stack = retry(wait_for_failed_rollback, retries=90, sleep=1)
    retained_template = aws_client.cloudformation.get_template(
        StackName=deployment.stack_id,
        TemplateStage="Original",
    )["TemplateBody"]
    after = aws_client.dynamodb.describe_table(TableName=table_name)["Table"]
    singular_resource = aws_client.cloudformation.describe_stack_resource(
        StackName=deployment.stack_id,
        LogicalResourceId="Table",
    )["StackResourceDetail"]
    listed_resource = aws_client.cloudformation.describe_stack_resources(
        StackName=deployment.stack_id,
        LogicalResourceId="Table",
    )["StackResources"][0]
    assert "DeletionTime" not in stack
    assert retained_template == initial_template
    assert after["TableId"] == before["TableId"]
    assert "GlobalSecondaryIndexes" not in after
    assert singular_resource["ResourceStatus"] == "UPDATE_FAILED"
    assert listed_resource["ResourceStatus"] == "UPDATE_FAILED"
    assert singular_resource["PhysicalResourceId"] == table_name
    assert listed_resource["PhysicalResourceId"] == table_name
