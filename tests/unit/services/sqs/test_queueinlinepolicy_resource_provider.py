import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.sqs.resource_providers.aws_sqs_queueinlinepolicy import (
    SQSQueueInlinePolicyProvider,
)


def _request(sqs, queue_url="http://localhost:4566/000000000000/enterprise-queue"):
    return SimpleNamespace(
        desired_state={"Queue": queue_url},
        custom_context={"read": "context"},
        aws_client_factory=SimpleNamespace(sqs=sqs),
    )


def test_read_reconstructs_the_inline_policy():
    sqs = MagicMock()
    sqs.get_queue_attributes.return_value = {
        "Attributes": {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow"}]}'
        }
    }
    request = _request(sqs)

    result = SQSQueueInlinePolicyProvider().read(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.custom_context == {"read": "context"}
    assert result.resource_model == {
        "Queue": request.desired_state["Queue"],
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow"}],
        },
    }


def test_read_reports_a_queue_without_a_policy_as_missing():
    sqs = MagicMock()
    sqs.get_queue_attributes.return_value = {"Attributes": {}}
    request = _request(sqs)

    result = SQSQueueInlinePolicyProvider().read(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "NotFound"
    assert request.desired_state["Queue"] in result.message


def test_delete_is_idempotent_when_the_queue_is_missing():
    class QueueDoesNotExist(Exception):
        pass

    sqs = MagicMock()
    sqs.exceptions.QueueDoesNotExist = QueueDoesNotExist
    sqs.get_queue_attributes.side_effect = QueueDoesNotExist()
    request = _request(sqs)

    result = SQSQueueInlinePolicyProvider().delete(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {}
    sqs.set_queue_attributes.assert_not_called()


def test_delete_preserves_a_policy_owned_by_a_replacement():
    sqs = MagicMock()
    sqs.get_queue_attributes.return_value = {
        "Attributes": {
            "Policy": '{"Version":"2012-10-17","Statement":[{"Action":"sqs:SendMessage"}]}'
        }
    }
    request = _request(sqs)
    request.desired_state["PolicyDocument"] = {
        "Version": "2012-10-17",
        "Statement": [{"Action": "sqs:GetQueueAttributes"}],
    }

    result = SQSQueueInlinePolicyProvider().delete(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {}
    sqs.set_queue_attributes.assert_not_called()


def test_delete_removes_the_policy_still_owned_by_the_resource():
    sqs = MagicMock()
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Action": "sqs:GetQueueAttributes"}],
    }
    sqs.get_queue_attributes.return_value = {
        "Attributes": {"Policy": json.dumps(policy)}
    }
    request = _request(sqs)
    request.desired_state["PolicyDocument"] = policy

    result = SQSQueueInlinePolicyProvider().delete(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {}
    sqs.set_queue_attributes.assert_called_once_with(
        QueueUrl=request.desired_state["Queue"], Attributes={"Policy": ""}
    )
