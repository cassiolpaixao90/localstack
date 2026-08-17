import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.sns.provider import create_default_topic_policy
from localstack.services.sns.resource_providers.aws_sns_topicinlinepolicy import (
    SNSTopicInlinePolicyProvider,
)

TOPIC_ARN = "arn:aws:sns:us-east-1:000000000000:enterprise-topic"
POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "sns:Publish", "Resource": TOPIC_ARN}],
}


def _request(sns, desired_state=None):
    return SimpleNamespace(
        desired_state=desired_state
        or {"TopicArn": TOPIC_ARN, "PolicyDocument": POLICY},
        custom_context={"contract": "topic-inline-policy"},
        aws_client_factory=SimpleNamespace(sns=sns),
    )


def test_create_applies_the_inline_policy():
    sns = MagicMock()
    request = _request(sns)

    result = SNSTopicInlinePolicyProvider().create(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == request.desired_state
    assert result.custom_context == request.custom_context
    sns.set_topic_attributes.assert_called_once_with(
        TopicArn=TOPIC_ARN,
        AttributeName="Policy",
        AttributeValue=json.dumps(POLICY),
    )


def test_read_reconstructs_the_inline_policy():
    sns = MagicMock()
    sns.get_topic_attributes.return_value = {
        "Attributes": {"Policy": json.dumps(POLICY)}
    }
    request = _request(sns, {"TopicArn": TOPIC_ARN})

    result = SNSTopicInlinePolicyProvider().read(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {"TopicArn": TOPIC_ARN, "PolicyDocument": POLICY}
    assert result.custom_context == request.custom_context


def test_read_reports_a_missing_topic():
    sns = MagicMock()
    sns.get_topic_attributes.side_effect = ClientError(
        {"Error": {"Code": "NotFound", "Message": "Topic does not exist"}},
        "GetTopicAttributes",
    )
    request = _request(sns, {"TopicArn": TOPIC_ARN})

    result = SNSTopicInlinePolicyProvider().read(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "NotFound"
    assert TOPIC_ARN in result.message


def test_update_replaces_the_inline_policy():
    sns = MagicMock()
    updated_policy = {**POLICY, "Id": "updated"}
    request = _request(
        sns, {"TopicArn": TOPIC_ARN, "PolicyDocument": updated_policy}
    )

    result = SNSTopicInlinePolicyProvider().update(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == request.desired_state
    sns.set_topic_attributes.assert_called_once_with(
        TopicArn=TOPIC_ARN,
        AttributeName="Policy",
        AttributeValue=json.dumps(updated_policy),
    )


def test_delete_preserves_a_policy_owned_by_a_replacement():
    sns = MagicMock()
    replacement_policy = {**POLICY, "Id": "replacement"}
    sns.get_topic_attributes.return_value = {
        "Attributes": {"Policy": json.dumps(replacement_policy)}
    }
    request = _request(sns)

    result = SNSTopicInlinePolicyProvider().delete(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {}
    sns.set_topic_attributes.assert_not_called()


def test_delete_restores_the_default_policy_when_still_owned():
    sns = MagicMock()
    sns.get_topic_attributes.return_value = {
        "Attributes": {"Policy": json.dumps(POLICY)}
    }
    request = _request(sns)

    result = SNSTopicInlinePolicyProvider().delete(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {}
    sns.set_topic_attributes.assert_called_once_with(
        TopicArn=TOPIC_ARN,
        AttributeName="Policy",
        AttributeValue=create_default_topic_policy(TOPIC_ARN),
    )
