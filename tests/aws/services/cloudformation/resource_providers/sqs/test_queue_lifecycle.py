import json

import pytest
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


def _policy(action: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "LifecycleContract",
                "Effect": "Allow",
                "Principal": "*",
                "Action": action,
                "Resource": "*",
            }
        ],
    }


def _template(
    *,
    main_queue_name: str,
    inline_queue_name: str,
    phase: str,
    delay: int | None,
    visibility: int,
    main_action: str,
    inline_action: str,
) -> dict:
    main_queue = {
        "QueueName": main_queue_name,
        "VisibilityTimeout": visibility,
        "Tags": [{"Key": "phase", "Value": phase}],
    }
    if delay is not None:
        main_queue["DelaySeconds"] = delay

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "MainQueue": {"Type": "AWS::SQS::Queue", "Properties": main_queue},
            "MainPolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "MainQueue"}],
                    "PolicyDocument": _policy(main_action),
                },
            },
            "InlineQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": inline_queue_name,
                    "VisibilityTimeout": visibility + 1,
                },
            },
            "InlinePolicy": {
                "Type": "AWS::SQS::QueueInlinePolicy",
                "Properties": {
                    "Queue": {"Ref": "InlineQueue"},
                    "PolicyDocument": _policy(inline_action),
                },
            },
        },
        "Outputs": {
            "MainQueueUrl": {"Value": {"Ref": "MainQueue"}},
            "InlineQueueUrl": {"Value": {"Ref": "InlineQueue"}},
        },
    }


def _queue_state(sqs, queue_url: str) -> tuple[dict, dict]:
    attributes = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])[
        "Attributes"
    ]
    tags = sqs.list_queue_tags(QueueUrl=queue_url).get("Tags", {})
    return attributes, tags


@skip_if_legacy_engine()
@markers.aws.only_localstack
def test_queue_policy_lifecycle_is_preserved_across_stack_update(
    deploy_cfn_template,
    aws_client,
):
    suffix = short_uid()
    main_queue_name = f"cfn-main-{suffix}"
    inline_queue_name = f"cfn-inline-{suffix}"
    initial_template = _template(
        main_queue_name=main_queue_name,
        inline_queue_name=inline_queue_name,
        phase="create",
        delay=7,
        visibility=31,
        main_action="sqs:GetQueueAttributes",
        inline_action="sqs:GetQueueUrl",
    )
    updated_template = _template(
        main_queue_name=main_queue_name,
        inline_queue_name=inline_queue_name,
        phase="update",
        delay=None,
        visibility=45,
        main_action="sqs:SendMessage",
        inline_action="sqs:ReceiveMessage",
    )

    deployment = deploy_cfn_template(
        template=json.dumps(initial_template), max_wait=90, delay_between_polls=1
    )
    main_queue_url = deployment.outputs["MainQueueUrl"]
    inline_queue_url = deployment.outputs["InlineQueueUrl"]
    main_attributes, main_tags = _queue_state(aws_client.sqs, main_queue_url)
    inline_attributes, _ = _queue_state(aws_client.sqs, inline_queue_url)
    assert (main_attributes["DelaySeconds"], main_attributes["VisibilityTimeout"]) == (
        "7",
        "31",
    )
    assert main_tags == {"phase": "create"}
    assert json.loads(main_attributes["Policy"])["Statement"][0]["Action"] == (
        "sqs:GetQueueAttributes"
    )
    assert inline_attributes["VisibilityTimeout"] == "32"
    assert json.loads(inline_attributes["Policy"])["Statement"][0]["Action"] == (
        "sqs:GetQueueUrl"
    )

    aws_client.cloudformation.update_stack(
        StackName=deployment.stack_id, TemplateBody=json.dumps(updated_template)
    )
    aws_client.cloudformation.get_waiter("stack_update_complete").wait(
        StackName=deployment.stack_id,
        WaiterConfig={"Delay": 1, "MaxAttempts": 90},
    )

    main_attributes, main_tags = _queue_state(aws_client.sqs, main_queue_url)
    inline_attributes, _ = _queue_state(aws_client.sqs, inline_queue_url)
    assert (main_attributes["DelaySeconds"], main_attributes["VisibilityTimeout"]) == (
        "0",
        "45",
    )
    assert main_tags == {"phase": "update"}
    assert json.loads(main_attributes["Policy"])["Statement"][0]["Action"] == "sqs:SendMessage"
    assert inline_attributes["VisibilityTimeout"] == "46"
    assert json.loads(inline_attributes["Policy"])["Statement"][0]["Action"] == (
        "sqs:ReceiveMessage"
    )

    resources = aws_client.cloudformation.list_stack_resources(
        StackName=deployment.stack_id
    )["StackResourceSummaries"]
    assert {
        (resource["LogicalResourceId"], resource["ResourceType"], resource["ResourceStatus"])
        for resource in resources
    } == {
        ("MainQueue", "AWS::SQS::Queue", "UPDATE_COMPLETE"),
        ("MainPolicy", "AWS::SQS::QueuePolicy", "UPDATE_COMPLETE"),
        ("InlineQueue", "AWS::SQS::Queue", "UPDATE_COMPLETE"),
        ("InlinePolicy", "AWS::SQS::QueueInlinePolicy", "UPDATE_COMPLETE"),
    }

    deployment.destroy()
    for queue_name in (main_queue_name, inline_queue_name):
        with pytest.raises(aws_client.sqs.exceptions.QueueDoesNotExist):
            aws_client.sqs.get_queue_url(QueueName=queue_name)
