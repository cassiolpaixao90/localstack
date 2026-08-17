import copy
from types import SimpleNamespace
from unittest.mock import MagicMock

from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.sqs.resource_providers.aws_sqs_queue import SQSQueueProvider


def test_read_reconstructs_the_typed_queue_model():
    sqs = MagicMock()
    sqs.get_queue_attributes.return_value = {
        "Attributes": {
            "ApproximateNumberOfMessages": "3",
            "ContentBasedDeduplication": "false",
            "DelaySeconds": "10",
            "FifoQueue": "false",
            "MaximumMessageSize": "262144",
            "QueueArn": "arn:aws:sqs:us-east-1:000000000000:enterprise-queue",
            "RedrivePolicy": '{"deadLetterTargetArn":"arn:aws:sqs:::dlq","maxReceiveCount":5}',
            "SqsManagedSseEnabled": "true",
            "VisibilityTimeout": "45",
        }
    }
    sqs.list_queue_tags.return_value = {"Tags": {"owner": "platform", "env": "dev"}}
    request = SimpleNamespace(
        desired_state={
            "QueueUrl": "http://sqs.us-east-1.localhost.localstack.cloud:4566/000000000000/enterprise-queue"
        },
        custom_context={"read": "context"},
        aws_client_factory=SimpleNamespace(sqs=sqs),
    )

    result = SQSQueueProvider().read(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.custom_context == {"read": "context"}
    assert result.resource_model == {
        "Arn": "arn:aws:sqs:us-east-1:000000000000:enterprise-queue",
        "ContentBasedDeduplication": False,
        "DelaySeconds": 10,
        "FifoQueue": False,
        "MaximumMessageSize": 262144,
        "QueueName": "enterprise-queue",
        "QueueUrl": request.desired_state["QueueUrl"],
        "RedrivePolicy": {
            "deadLetterTargetArn": "arn:aws:sqs:::dlq",
            "maxReceiveCount": 5,
        },
        "SqsManagedSseEnabled": True,
        "Tags": [
            {"Key": "env", "Value": "dev"},
            {"Key": "owner", "Value": "platform"},
        ],
        "VisibilityTimeout": 45,
    }
    sqs.get_queue_attributes.assert_called_once_with(
        QueueUrl=request.desired_state["QueueUrl"], AttributeNames=["All"]
    )
    sqs.list_queue_tags.assert_called_once_with(QueueUrl=request.desired_state["QueueUrl"])


def test_read_reports_a_missing_queue():
    class QueueDoesNotExist(Exception):
        pass

    sqs = MagicMock()
    sqs.exceptions.QueueDoesNotExist = QueueDoesNotExist
    sqs.get_queue_attributes.side_effect = QueueDoesNotExist()
    queue_url = "http://localhost:4566/000000000000/missing"
    request = SimpleNamespace(
        desired_state={"QueueUrl": queue_url},
        custom_context={},
        aws_client_factory=SimpleNamespace(sqs=sqs),
    )

    result = SQSQueueProvider().read(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "NotFound"
    assert queue_url in result.message
    sqs.list_queue_tags.assert_not_called()


def test_update_returns_typed_defaults_without_mutating_the_requested_model():
    sqs = MagicMock()
    desired_state = {"VisibilityTimeout": 45, "Tags": []}
    original_desired_state = copy.deepcopy(desired_state)
    request = SimpleNamespace(
        desired_state=desired_state,
        previous_state={
            "QueueUrl": "http://localhost:4566/000000000000/enterprise-queue",
            "QueueName": "enterprise-queue",
            "Arn": "arn:aws:sqs:us-east-1:000000000000:enterprise-queue",
            "FifoQueue": False,
            "Tags": [],
        },
        aws_client_factory=SimpleNamespace(sqs=sqs),
    )

    result = SQSQueueProvider().update(request)

    assert request.desired_state == original_desired_state
    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {
        "QueueUrl": request.previous_state["QueueUrl"],
        "QueueName": "enterprise-queue",
        "Arn": request.previous_state["Arn"],
        "FifoQueue": False,
        "VisibilityTimeout": 45,
        "ReceiveMessageWaitTimeSeconds": 0,
        "DelaySeconds": 0,
        "KmsMasterKeyId": "",
        "RedrivePolicy": "",
        "MessageRetentionPeriod": 345600,
        "MaximumMessageSize": 262144,
        "KmsDataKeyReusePeriodSeconds": 300,
        "Tags": [],
    }
    sqs.set_queue_attributes.assert_called_once_with(
        QueueUrl=request.previous_state["QueueUrl"],
        Attributes={
            "DelaySeconds": "0",
            "KmsDataKeyReusePeriodSeconds": "300",
            "KmsMasterKeyId": "",
            "MaximumMessageSize": "262144",
            "MessageRetentionPeriod": "345600",
            "ReceiveMessageWaitTimeSeconds": "0",
            "RedrivePolicy": "",
            "VisibilityTimeout": "45",
        },
    )
    sqs.untag_queue.assert_not_called()
    sqs.tag_queue.assert_not_called()
