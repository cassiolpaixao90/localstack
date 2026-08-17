from types import SimpleNamespace
from unittest.mock import MagicMock, call

from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.sqs.resource_providers.aws_sqs_queuepolicy import SQSQueuePolicyProvider


def _sqs_with_missing_queue_exception():
    class QueueDoesNotExist(Exception):
        pass

    sqs = MagicMock()
    sqs.exceptions.QueueDoesNotExist = QueueDoesNotExist
    return sqs, QueueDoesNotExist


def test_delete_continues_after_an_already_missing_queue():
    sqs, queue_does_not_exist = _sqs_with_missing_queue_exception()
    sqs.set_queue_attributes.side_effect = [queue_does_not_exist(), None]
    request = SimpleNamespace(
        desired_state={},
        previous_state={"Queues": ["missing-queue", "existing-queue"]},
        aws_client_factory=SimpleNamespace(sqs=sqs),
    )

    result = SQSQueuePolicyProvider().delete(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {}
    assert sqs.set_queue_attributes.call_args_list == [
        call(QueueUrl="missing-queue", Attributes={"Policy": ""}),
        call(QueueUrl="existing-queue", Attributes={"Policy": ""}),
    ]


def test_update_ignores_an_already_missing_outdated_queue():
    sqs, queue_does_not_exist = _sqs_with_missing_queue_exception()
    sqs.set_queue_attributes.side_effect = [None, queue_does_not_exist()]
    desired_state = {
        "Queues": ["retained-queue"],
        "PolicyDocument": {"Version": "2012-10-17", "Statement": []},
    }
    request = SimpleNamespace(
        desired_state=desired_state,
        previous_state={
            "Id": "stack-policy-id",
            "Queues": ["retained-queue", "missing-outdated-queue"],
        },
        aws_client_factory=SimpleNamespace(sqs=sqs),
    )

    result = SQSQueuePolicyProvider().update(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {**desired_state, "Id": "stack-policy-id"}
    assert sqs.set_queue_attributes.call_args_list == [
        call(
            QueueUrl="retained-queue",
            Attributes={"Policy": '{"Version": "2012-10-17", "Statement": []}'},
        ),
        call(QueueUrl="missing-outdated-queue", Attributes={"Policy": ""}),
    ]
