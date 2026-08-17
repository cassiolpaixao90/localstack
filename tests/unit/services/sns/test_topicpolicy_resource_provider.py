import copy
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

from botocore.exceptions import ClientError

from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.sns.resource_providers.aws_sns_topicpolicy import SNSTopicPolicyProvider


def _request(*, desired_state=None, previous_state=None, sns=None):
    return SimpleNamespace(
        desired_state=desired_state or {},
        previous_state=previous_state or {},
        aws_client_factory=SimpleNamespace(sns=sns or MagicMock()),
        stack_name="stack",
        logical_resource_id="TopicPolicy",
        custom_context={"attempt": 1},
    )


def _not_found():
    return ClientError(
        {"Error": {"Code": "NotFoundException", "Message": "missing"}},
        "SetTopicAttributes",
    )


@patch(
    "localstack.services.sns.resource_providers.aws_sns_topicpolicy.util.generate_default_name",
    return_value="stack-TopicPolicy",
)
def test_create_preserves_input_and_does_not_double_encode_string_policy(generate_name):
    sns = MagicMock()
    desired_state = {
        "PolicyDocument": '{"Version":"2012-10-17","Statement":[]}',
        "Topics": ["arn:aws:sns:us-east-1:000000000000:first"],
    }
    original = copy.deepcopy(desired_state)

    result = SNSTopicPolicyProvider().create(
        _request(desired_state=desired_state, sns=sns)
    )

    assert desired_state == original
    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {**original, "Id": "stack-TopicPolicy"}
    assert result.custom_context == {"attempt": 1}
    sns.set_topic_attributes.assert_called_once_with(
        TopicArn="arn:aws:sns:us-east-1:000000000000:first",
        AttributeName="Policy",
        AttributeValue=original["PolicyDocument"],
    )
    generate_name.assert_called_once_with(
        stack_name="stack", logical_resource_id="TopicPolicy"
    )


@patch(
    "localstack.services.sns.resource_providers.aws_sns_topicpolicy.create_default_topic_policy",
    side_effect=lambda topic_arn: f"default:{topic_arn}",
)
def test_update_applies_policy_and_cleans_removed_topics(default_policy):
    sns = MagicMock()
    desired_state = {
        "PolicyDocument": {"Version": "2012-10-17", "Statement": []},
        "Topics": ["retained", "added"],
    }
    original = copy.deepcopy(desired_state)

    result = SNSTopicPolicyProvider().update(
        _request(
            desired_state=desired_state,
            previous_state={
                "Id": "existing-id",
                "PolicyDocument": {"Version": "2008-10-17", "Statement": []},
                "Topics": ["retained", "removed"],
            },
            sns=sns,
        )
    )

    assert desired_state == original
    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {**original, "Id": "existing-id"}
    assert sns.set_topic_attributes.call_args_list == [
        call(
            TopicArn="retained",
            AttributeName="Policy",
            AttributeValue='{"Version": "2012-10-17", "Statement": []}',
        ),
        call(
            TopicArn="added",
            AttributeName="Policy",
            AttributeValue='{"Version": "2012-10-17", "Statement": []}',
        ),
        call(
            TopicArn="removed",
            AttributeName="Policy",
            AttributeValue="default:removed",
        ),
    ]
    default_policy.assert_called_once_with("removed")


@patch(
    "localstack.services.sns.resource_providers.aws_sns_topicpolicy.create_default_topic_policy",
    side_effect=lambda topic_arn: f"default:{topic_arn}",
)
def test_delete_uses_previous_state_and_continues_after_missing_topic(default_policy):
    sns = MagicMock()
    sns.set_topic_attributes.side_effect = [_not_found(), None]

    result = SNSTopicPolicyProvider().delete(
        _request(
            desired_state={},
            previous_state={"Id": "existing-id", "Topics": ["missing", "existing"]},
            sns=sns,
        )
    )

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {}
    assert sns.set_topic_attributes.call_args_list == [
        call(
            TopicArn="missing",
            AttributeName="Policy",
            AttributeValue="default:missing",
        ),
        call(
            TopicArn="existing",
            AttributeName="Policy",
            AttributeValue="default:existing",
        ),
    ]


def test_delete_propagates_non_not_found_errors():
    sns = MagicMock()
    sns.set_topic_attributes.side_effect = ClientError(
        {"Error": {"Code": "InternalError", "Message": "boom"}},
        "SetTopicAttributes",
    )

    try:
        SNSTopicPolicyProvider().delete(
            _request(
                previous_state={
                    "Topics": ["arn:aws:sns:us-east-1:000000000000:topic"]
                },
                sns=sns,
            )
        )
    except ClientError as error:
        assert error.response["Error"]["Code"] == "InternalError"
    else:
        raise AssertionError("delete must propagate non-not-found service errors")
