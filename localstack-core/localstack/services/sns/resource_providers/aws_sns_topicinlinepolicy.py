from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import TypedDict

from botocore.exceptions import ClientError

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)
from localstack.services.sns.provider import create_default_topic_policy


class SNSTopicInlinePolicyProperties(TypedDict):
    PolicyDocument: dict
    TopicArn: str


def _is_not_found(error: ClientError) -> bool:
    return error.response.get("Error", {}).get("Code") in {
        "NotFound",
        "NotFoundException",
    }


def _not_found(topic_arn: str) -> ProgressEvent[SNSTopicInlinePolicyProperties]:
    return ProgressEvent(
        status=OperationStatus.FAILED,
        message=(
            "Resource of type 'AWS::SNS::TopicInlinePolicy' "
            f"with identifier '{topic_arn}' was not found."
        ),
        error_code="NotFound",
    )


class SNSTopicInlinePolicyProvider(ResourceProvider[SNSTopicInlinePolicyProperties]):
    TYPE = "AWS::SNS::TopicInlinePolicy"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(
        self,
        request: ResourceRequest[SNSTopicInlinePolicyProperties],
    ) -> ProgressEvent[SNSTopicInlinePolicyProperties]:
        model = copy.deepcopy(request.desired_state)
        request.aws_client_factory.sns.set_topic_attributes(
            TopicArn=model["TopicArn"],
            AttributeName="Policy",
            AttributeValue=json.dumps(model["PolicyDocument"]),
        )
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def read(
        self,
        request: ResourceRequest[SNSTopicInlinePolicyProperties],
    ) -> ProgressEvent[SNSTopicInlinePolicyProperties]:
        topic_arn = request.desired_state["TopicArn"]
        try:
            policy = request.aws_client_factory.sns.get_topic_attributes(
                TopicArn=topic_arn
            )["Attributes"]["Policy"]
        except ClientError as error:
            if _is_not_found(error):
                return _not_found(topic_arn)
            raise

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=SNSTopicInlinePolicyProperties(
                TopicArn=topic_arn,
                PolicyDocument=json.loads(policy),
            ),
            custom_context=request.custom_context,
        )

    def update(
        self,
        request: ResourceRequest[SNSTopicInlinePolicyProperties],
    ) -> ProgressEvent[SNSTopicInlinePolicyProperties]:
        return self.create(request)

    def delete(
        self,
        request: ResourceRequest[SNSTopicInlinePolicyProperties],
    ) -> ProgressEvent[SNSTopicInlinePolicyProperties]:
        model = request.desired_state
        topic_arn = model["TopicArn"]
        sns = request.aws_client_factory.sns
        try:
            current_policy = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"].get(
                "Policy"
            )
            expected_policy = model.get("PolicyDocument")
            if current_policy and expected_policy and json.loads(current_policy) == expected_policy:
                sns.set_topic_attributes(
                    TopicArn=topic_arn,
                    AttributeName="Policy",
                    AttributeValue=create_default_topic_policy(topic_arn),
                )
        except ClientError as error:
            if not _is_not_found(error):
                raise

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})
