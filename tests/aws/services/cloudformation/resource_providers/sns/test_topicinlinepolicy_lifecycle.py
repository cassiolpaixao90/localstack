import json

import pytest
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.services.sns.provider import create_default_topic_policy
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


def _topic_policy(topic_arn: dict, policy_id: str) -> dict:
    return {
        "Id": policy_id,
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPublish",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sns:Publish",
                "Resource": topic_arn,
            }
        ],
    }


def _template(*, topic_name: str, queue_name: str, policy_id: str) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": queue_name},
            },
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"TopicName": topic_name},
            },
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowTopicDelivery",
                                "Effect": "Allow",
                                "Principal": {"Service": "sns.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}
                                },
                            }
                        ],
                    },
                },
            },
            "TopicPolicy": {
                "Type": "AWS::SNS::TopicInlinePolicy",
                "Properties": {
                    "TopicArn": {"Ref": "Topic"},
                    "PolicyDocument": _topic_policy({"Ref": "Topic"}, policy_id),
                },
            },
            "Subscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "TopicArn": {"Ref": "Topic"},
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
                    "RawMessageDelivery": True,
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "TopicArn": {"Value": {"Ref": "Topic"}},
        },
    }


def _topic_policy_template(
    *, topic_a_name: str, topic_b_name: str, policy_id: str, include_topic_a: bool
) -> dict:
    topics = [{"Ref": "TopicB"}]
    if include_topic_a:
        topics.insert(0, {"Ref": "TopicA"})
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TopicA": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"TopicName": topic_a_name},
            },
            "TopicB": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"TopicName": topic_b_name},
            },
            "TopicPolicy": {
                "Type": "AWS::SNS::TopicPolicy",
                "Properties": {
                    "Topics": topics,
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Id": policy_id,
                        "Statement": [],
                    },
                },
            },
        },
        "Outputs": {
            "TopicAArn": {"Value": {"Ref": "TopicA"}},
            "TopicBArn": {"Value": {"Ref": "TopicB"}},
        },
    }


def _receive_body(sqs, queue_url: str) -> str:
    response = sqs.receive_message(
        QueueUrl=queue_url,
        WaitTimeSeconds=5,
        MaxNumberOfMessages=1,
    )
    messages = response.get("Messages", [])
    assert len(messages) == 1
    message = messages[0]
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
    return message["Body"]


@skip_if_legacy_engine()
@markers.aws.only_localstack
def test_topic_inline_policy_and_sqs_delivery_survive_stack_update(
    deploy_cfn_template,
    aws_client,
):
    suffix = short_uid()
    topic_name = f"cfn-topic-{suffix}"
    queue_name = f"cfn-topic-queue-{suffix}"
    initial_template = _template(
        topic_name=topic_name,
        queue_name=queue_name,
        policy_id="initial-policy",
    )
    updated_template = _template(
        topic_name=topic_name,
        queue_name=queue_name,
        policy_id="updated-policy",
    )

    deployment = deploy_cfn_template(
        template=json.dumps(initial_template), max_wait=90, delay_between_polls=1
    )
    queue_url = deployment.outputs["QueueUrl"]
    topic_arn = deployment.outputs["TopicArn"]
    initial_policy = json.loads(
        aws_client.sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"]
    )
    assert initial_policy["Id"] == "initial-policy"

    aws_client.sns.publish(TopicArn=topic_arn, Message="before-update")
    assert _receive_body(aws_client.sqs, queue_url) == "before-update"

    aws_client.cloudformation.update_stack(
        StackName=deployment.stack_id,
        TemplateBody=json.dumps(updated_template),
    )
    aws_client.cloudformation.get_waiter("stack_update_complete").wait(
        StackName=deployment.stack_id,
        WaiterConfig={"Delay": 1, "MaxAttempts": 90},
    )

    updated_policy = json.loads(
        aws_client.sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"]
    )
    assert updated_policy["Id"] == "updated-policy"
    resources = aws_client.cloudformation.list_stack_resources(
        StackName=deployment.stack_id
    )["StackResourceSummaries"]
    assert {
        (resource["LogicalResourceId"], resource["ResourceType"], resource["ResourceStatus"])
        for resource in resources
    } == {
        ("Queue", "AWS::SQS::Queue", "CREATE_COMPLETE"),
        ("QueuePolicy", "AWS::SQS::QueuePolicy", "CREATE_COMPLETE"),
        ("Subscription", "AWS::SNS::Subscription", "CREATE_COMPLETE"),
        ("Topic", "AWS::SNS::Topic", "CREATE_COMPLETE"),
        ("TopicPolicy", "AWS::SNS::TopicInlinePolicy", "UPDATE_COMPLETE"),
    }

    aws_client.sns.publish(TopicArn=topic_arn, Message="after-update")
    assert _receive_body(aws_client.sqs, queue_url) == "after-update"

    deployment.destroy()
    with pytest.raises(aws_client.sns.exceptions.NotFoundException):
        aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
    with pytest.raises(aws_client.sqs.exceptions.QueueDoesNotExist):
        aws_client.sqs.get_queue_url(QueueName=queue_name)


@skip_if_legacy_engine()
@markers.aws.only_localstack
def test_topic_policy_update_restores_removed_topic_and_updates_retained_topic(
    deploy_cfn_template,
    aws_client,
):
    suffix = short_uid()
    initial_template = _topic_policy_template(
        topic_a_name=f"cfn-policy-a-{suffix}",
        topic_b_name=f"cfn-policy-b-{suffix}",
        policy_id="initial-policy",
        include_topic_a=True,
    )
    updated_template = _topic_policy_template(
        topic_a_name=f"cfn-policy-a-{suffix}",
        topic_b_name=f"cfn-policy-b-{suffix}",
        policy_id="updated-policy",
        include_topic_a=False,
    )

    deployment = deploy_cfn_template(
        template=json.dumps(initial_template), max_wait=90, delay_between_polls=1
    )
    topic_a_arn = deployment.outputs["TopicAArn"]
    topic_b_arn = deployment.outputs["TopicBArn"]
    for topic_arn in (topic_a_arn, topic_b_arn):
        policy = json.loads(
            aws_client.sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"]
        )
        assert policy["Id"] == "initial-policy"

    aws_client.cloudformation.update_stack(
        StackName=deployment.stack_id,
        TemplateBody=json.dumps(updated_template),
    )
    aws_client.cloudformation.get_waiter("stack_update_complete").wait(
        StackName=deployment.stack_id,
        WaiterConfig={"Delay": 1, "MaxAttempts": 90},
    )

    topic_a_policy = aws_client.sns.get_topic_attributes(TopicArn=topic_a_arn)["Attributes"][
        "Policy"
    ]
    assert json.loads(topic_a_policy) == json.loads(create_default_topic_policy(topic_a_arn))
    topic_b_policy = json.loads(
        aws_client.sns.get_topic_attributes(TopicArn=topic_b_arn)["Attributes"]["Policy"]
    )
    assert topic_b_policy["Id"] == "updated-policy"
    resources = aws_client.cloudformation.list_stack_resources(
        StackName=deployment.stack_id
    )["StackResourceSummaries"]
    assert {
        (resource["LogicalResourceId"], resource["ResourceType"], resource["ResourceStatus"])
        for resource in resources
    } == {
        ("TopicA", "AWS::SNS::Topic", "CREATE_COMPLETE"),
        ("TopicB", "AWS::SNS::Topic", "CREATE_COMPLETE"),
        ("TopicPolicy", "AWS::SNS::TopicPolicy", "UPDATE_COMPLETE"),
    }

    deployment.destroy()
    for topic_arn in (topic_a_arn, topic_b_arn):
        with pytest.raises(aws_client.sns.exceptions.NotFoundException):
            aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
