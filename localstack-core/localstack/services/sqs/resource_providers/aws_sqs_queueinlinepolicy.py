# LocalStack Resource Provider Scaffolding v2
import json

from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceRequest,
)
from localstack.services.sqs.resource_providers.generated.aws_sqs_queueinlinepolicy_base import (
    SQSQueueInlinePolicyProperties,
    SQSQueueInlinePolicyProviderBase,
)


def _not_found(queue: str) -> ProgressEvent[SQSQueueInlinePolicyProperties]:
    return ProgressEvent(
        status=OperationStatus.FAILED,
        message=(
            "Resource of type 'AWS::SQS::QueueInlinePolicy' "
            f"with identifier '{queue}' was not found."
        ),
        error_code="NotFound",
    )


class SQSQueueInlinePolicyProvider(SQSQueueInlinePolicyProviderBase):
    def create(
        self,
        request: ResourceRequest[SQSQueueInlinePolicyProperties],
    ) -> ProgressEvent[SQSQueueInlinePolicyProperties]:
        model = request.desired_state
        sqs = request.aws_client_factory.sqs

        queue = model.get("Queue")
        policy = model.get("PolicyDocument")
        sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": json.dumps(policy)})

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def read(
        self,
        request: ResourceRequest[SQSQueueInlinePolicyProperties],
    ) -> ProgressEvent[SQSQueueInlinePolicyProperties]:
        sqs = request.aws_client_factory.sqs
        queue = request.desired_state["Queue"]
        try:
            policy = sqs.get_queue_attributes(
                QueueUrl=queue, AttributeNames=["Policy"]
            ).get("Attributes", {}).get("Policy")
        except sqs.exceptions.QueueDoesNotExist:
            return _not_found(queue)
        if not policy:
            return _not_found(queue)

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=SQSQueueInlinePolicyProperties(
                Queue=queue,
                PolicyDocument=json.loads(policy),
            ),
            custom_context=request.custom_context,
        )

    def delete(
        self,
        request: ResourceRequest[SQSQueueInlinePolicyProperties],
    ) -> ProgressEvent[SQSQueueInlinePolicyProperties]:
        model = request.desired_state
        sqs = request.aws_client_factory.sqs

        queue = model.get("Queue")
        try:
            current_policy = sqs.get_queue_attributes(
                QueueUrl=queue, AttributeNames=["Policy"]
            ).get("Attributes", {}).get("Policy")
            expected_policy = model.get("PolicyDocument")
            if current_policy and expected_policy and json.loads(current_policy) == expected_policy:
                sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": ""})
        except sqs.exceptions.QueueDoesNotExist:
            pass

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})

    def update(
        self,
        request: ResourceRequest[SQSQueueInlinePolicyProperties],
    ) -> ProgressEvent[SQSQueueInlinePolicyProperties]:
        model = request.desired_state
        sqs = request.aws_client_factory.sqs

        queue = model.get("Queue")
        policy = model.get("PolicyDocument")
        sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": json.dumps(policy)})

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def list(
        self,
        request: ResourceRequest[SQSQueueInlinePolicyProperties],
    ) -> ProgressEvent[SQSQueueInlinePolicyProperties]:
        """
        List available resources of this type

        """
        raise NotImplementedError
