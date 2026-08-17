import copy
from types import SimpleNamespace

import pytest

from localstack.aws.api.cloudformation import ChangeAction
from localstack.services.cloudformation.engine.template_deployer import TemplateDeployer
from localstack.services.cloudformation.engine.v2.change_set_model_executor import (
    ChangeSetModelExecutor,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    PreprocProperties,
)
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProviderExecutor,
)
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME


def _payload(
    *,
    action="Add",
    properties=None,
    stack_tags=None,
    system_tags=None,
):
    return {
        "awsAccountId": TEST_AWS_ACCOUNT_ID,
        "callbackContext": {},
        "stackId": "stack-id",
        "resourceType": "AWS::Test::Tagged",
        "resourceTypeVersion": "000000",
        "bearerToken": "token",
        "region": TEST_AWS_REGION_NAME,
        "action": action,
        "requestData": {
            "logicalResourceId": "Tagged",
            "resourceProperties": properties or {},
            "previousResourceProperties": None,
            "callerCredentials": {
                "accessKeyId": TEST_AWS_ACCOUNT_ID,
                "secretAccessKey": "test",
                "sessionToken": "",
            },
            "providerCredentials": {
                "accessKeyId": TEST_AWS_ACCOUNT_ID,
                "secretAccessKey": "test",
                "sessionToken": "",
            },
            "systemTags": system_tags or {},
            "previousSystemTags": {},
            "stackTags": stack_tags or {},
            "previousStackTags": {},
        },
    }


class _CapturingProvider:
    def __init__(self, schema):
        self.SCHEMA = schema
        self.requests = []

    def _success(self, request):
        self.requests.append(request)
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=copy.deepcopy(request.desired_state),
        )

    create = _success
    update = _success
    delete = _success


class _AsyncProvider(_CapturingProvider):
    def create(self, request):
        self.requests.append(request)
        if len(self.requests) == 1:
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model={"Id": request.desired_state["Id"]},
            )
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=copy.deepcopy(request.desired_state),
        )


def _deploy(provider, payload):
    resource = {"Type": payload["resourceType"]}
    original = copy.deepcopy(payload)
    event = ResourceProviderExecutor(
        stack_name="stack-name",
        stack_id="stack-id",
    ).deploy_loop(provider, resource, payload)
    assert payload == original
    return event, provider.requests[-1]


def test_object_tag_property_merges_stack_tags_without_mutating_the_payload():
    provider = _CapturingProvider(
        {
            "primaryIdentifier": ["/properties/Id"],
            "properties": {"UserPoolTags": {"type": "object"}},
            "tagging": {
                "taggable": True,
                "tagOnCreate": True,
                "tagUpdatable": True,
                "cloudFormationSystemTags": False,
                "tagProperty": "/properties/UserPoolTags",
            },
        }
    )
    payload = _payload(
        properties={"Id": "resource-id", "UserPoolTags": {"duplicate": "resource"}},
        stack_tags={"owner": "stack", "duplicate": "stack"},
        system_tags={"aws:cloudformation:stack-name": "must-remain-separate"},
    )

    event, request = _deploy(provider, payload)

    assert event.resource_model["UserPoolTags"] == {
        "duplicate": "resource",
        "owner": "stack",
    }
    assert request.tags == {"duplicate": "resource", "owner": "stack"}
    assert "aws:cloudformation:stack-name" not in request.tags


def test_array_tag_property_merges_stack_tags_with_resource_precedence():
    provider = _CapturingProvider(
        {
            "primaryIdentifier": ["/properties/Id"],
            "properties": {"Tags": {"type": "array"}},
            "tagging": {
                "taggable": True,
                "tagOnCreate": True,
                "tagUpdatable": True,
                "tagProperty": "/properties/Tags",
            },
        }
    )

    event, request = _deploy(
        provider,
        _payload(
            properties={
                "Id": "resource-id",
                "Tags": [{"Key": "duplicate", "Value": "resource"}],
            },
            stack_tags={"owner": "stack", "duplicate": "stack"},
        ),
    )

    assert event.resource_model["Tags"] == [
        {"Key": "duplicate", "Value": "resource"},
        {"Key": "owner", "Value": "stack"},
    ]
    assert request.tags == {"duplicate": "resource", "owner": "stack"}


def test_async_callback_reapplies_stack_tags_when_intermediate_model_omits_them(monkeypatch):
    monkeypatch.setattr("localstack.config.CFN_NO_WAIT_ITERATIONS", 10)
    provider = _AsyncProvider(
        {
            "primaryIdentifier": ["/properties/Id"],
            "properties": {"Tags": {"type": "object"}},
            "tagging": {
                "taggable": True,
                "tagOnCreate": True,
                "tagProperty": "/properties/Tags",
            },
        }
    )

    event, request = _deploy(
        provider,
        _payload(properties={"Id": "resource-id"}, stack_tags={"owner": "stack"}),
    )

    assert len(provider.requests) == 2
    assert request.tags == {"owner": "stack"}
    assert event.resource_model["Tags"] == {"owner": "stack"}


def test_update_exposes_previous_resource_tags_separately():
    provider = _CapturingProvider(
        {
            "primaryIdentifier": ["/properties/Id"],
            "properties": {"Tags": {"type": "object"}},
            "tagging": {
                "taggable": True,
                "tagUpdatable": True,
                "tagProperty": "/properties/Tags",
            },
        }
    )
    payload = _payload(
        action="Modify",
        properties={"Id": "resource-id", "Tags": {"version": "new"}},
        stack_tags={"owner": "stack"},
    )
    payload["requestData"]["previousResourceProperties"] = {
        "Id": "resource-id",
        "Tags": {"version": "old"},
    }

    _, request = _deploy(provider, payload)

    assert request.tags == {"owner": "stack", "version": "new"}
    assert request.previous_tags == {"version": "old"}


@pytest.mark.parametrize(
    ("action", "tagging", "expected_tags"),
    [
        ("Add", {"taggable": False}, {"resource": "only"}),
        (
            "Add",
            {"taggable": True, "tagOnCreate": False, "tagProperty": "/properties/Tags"},
            {"resource": "only"},
        ),
        (
            "Modify",
            {"taggable": True, "tagUpdatable": True, "tagProperty": "/properties/Tags"},
            {"owner": "stack", "resource": "only"},
        ),
        (
            "Modify",
            {"taggable": True, "tagUpdatable": False, "tagProperty": "/properties/Tags"},
            {"resource": "only"},
        ),
        (
            "Remove",
            {
                "taggable": True,
                "tagOnCreate": True,
                "tagUpdatable": True,
                "tagProperty": "/properties/Tags",
            },
            {"resource": "only"},
        ),
    ],
)
def test_stack_tag_injection_obeys_schema_action_contract(action, tagging, expected_tags):
    provider = _CapturingProvider(
        {
            "primaryIdentifier": ["/properties/Id"],
            "properties": {"Tags": {"type": "object"}},
            "tagging": tagging,
        }
    )

    event, request = _deploy(
        provider,
        _payload(
            action=action,
            properties={"Id": "resource-id", "Tags": {"resource": "only"}},
            stack_tags={"owner": "stack"},
        ),
    )

    assert event.resource_model["Tags"] == expected_tags
    assert request.tags == (expected_tags if tagging.get("taggable") is not False else {})


def test_v2_resource_provider_payload_carries_real_stack_tags():
    stack = SimpleNamespace(
        account_id=TEST_AWS_ACCOUNT_ID,
        region_name=TEST_AWS_REGION_NAME,
        stack_name="stack-name",
        tags=[{"Key": "owner", "Value": "stack"}],
    )
    executor = object.__new__(ChangeSetModelExecutor)
    executor._change_set = SimpleNamespace(stack=stack)

    payload = executor.create_resource_provider_payload(
        ChangeAction.Add,
        "Tagged",
        "AWS::Test::Tagged",
        None,
        PreprocProperties({"Id": "resource-id"}),
    )

    assert payload["requestData"]["stackTags"] == {"owner": "stack"}
    assert payload["requestData"]["systemTags"] == {}


def test_legacy_resource_provider_payload_carries_real_stack_tags():
    stack = SimpleNamespace(
        resources={
            "Tagged": {
                "Type": "AWS::Test::Tagged",
                "Properties": {"Id": "resource-id"},
            }
        },
        stack_id="stack-id",
        stack_name="stack-name",
        tags=[{"Key": "owner", "Value": "stack"}],
    )
    executor = TemplateDeployer(TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME, stack)

    payload = executor.create_resource_provider_payload("Add", "Tagged")

    assert payload["requestData"]["stackTags"] == {"owner": "stack"}
    assert payload["requestData"]["systemTags"] == {}
