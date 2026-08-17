import copy
from types import SimpleNamespace

import pytest

from localstack.aws.api.cloudformation import (
    ChangeAction,
    ChangeSetType,
    ResourceStatus,
    StackStatus,
)
from localstack.services.cloudformation.engine.v2.change_set_model_executor import (
    ChangeSetModelExecutor,
    TriggerRollback,
    _inject_single_primary_identifier,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    PreprocProperties,
    PreprocResource,
)
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
)
from localstack.services.cloudformation.v2.entities import Stack


def test_replacement_cleanup_events_preserve_the_current_resource_state():
    stack = Stack(
        account_id="000000000000",
        region_name="us-east-1",
        request_payload={"StackName": "replacement-stack"},
    )
    stack.set_resource_status(
        logical_resource_id="Policy",
        physical_resource_id="new-policy-id",
        resource_type="AWS::SQS::QueueInlinePolicy",
        status=ResourceStatus.UPDATE_COMPLETE,
    )
    current_state = copy.deepcopy(stack.resource_states["Policy"])

    stack.set_resource_status(
        logical_resource_id="Policy",
        physical_resource_id="old-policy-id",
        resource_type="AWS::SQS::QueueInlinePolicy",
        status=ResourceStatus.DELETE_IN_PROGRESS,
        update_resource_state=False,
    )
    stack.set_resource_status(
        logical_resource_id="Policy",
        physical_resource_id="old-policy-id",
        resource_type="AWS::SQS::QueueInlinePolicy",
        status=ResourceStatus.DELETE_COMPLETE,
        update_resource_state=False,
    )
    stack.set_resource_status(
        logical_resource_id="Policy",
        physical_resource_id="old-policy-id",
        resource_type="AWS::SQS::QueueInlinePolicy",
        status=ResourceStatus.DELETE_SKIPPED,
        update_resource_state=False,
    )

    assert stack.resource_states["Policy"] == current_state
    assert [event["ResourceStatus"] for event in stack.events[:3]] == [
        ResourceStatus.DELETE_SKIPPED,
        ResourceStatus.DELETE_COMPLETE,
        ResourceStatus.DELETE_IN_PROGRESS,
    ]


def test_resource_provider_payload_restores_generated_primary_identifier():
    payload = {
        "action": ChangeAction.Modify,
        "requestData": {
            "resourceProperties": {"BillingMode": "PAY_PER_REQUEST"},
            "previousResourceProperties": {"BillingMode": "PROVISIONED"},
        },
    }
    provider = SimpleNamespace(SCHEMA={"primaryIdentifier": ["/properties/TableName"]})

    _inject_single_primary_identifier(payload, provider, "generated-table-name")

    assert payload["requestData"]["resourceProperties"]["TableName"] == (
        "generated-table-name"
    )
    assert payload["requestData"]["previousResourceProperties"]["TableName"] == (
        "generated-table-name"
    )


def test_resource_provider_payload_never_overwrites_explicit_primary_identifier():
    payload = {
        "action": ChangeAction.Modify,
        "requestData": {
            "resourceProperties": {"TableName": "explicit-new"},
            "previousResourceProperties": {"TableName": "explicit-old"},
        },
    }
    provider = SimpleNamespace(SCHEMA={"primaryIdentifier": ["/properties/TableName"]})

    _inject_single_primary_identifier(payload, provider, "generated-table-name")

    assert payload["requestData"]["resourceProperties"]["TableName"] == "explicit-new"
    assert payload["requestData"]["previousResourceProperties"]["TableName"] == "explicit-old"


def test_type_migration_cleanup_preserves_the_new_resolved_resource():
    executor = object.__new__(ChangeSetModelExecutor)
    calls = []
    deferred = []
    executor._merge_before_properties = lambda name, before: before.properties
    executor._process_event = lambda **kwargs: calls.append(("event", kwargs))
    executor._defer_action = lambda name, action: deferred.append((name, action))

    def execute_action(**kwargs):
        calls.append(("action", kwargs))
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})

    executor._execute_resource_action = execute_action
    before = PreprocResource(
        logical_id="Data",
        physical_resource_id="old-resource-id",
        condition=True,
        resource_type="AWS::SQS::Queue",
        properties=PreprocProperties({"QueueName": "old-queue"}),
        depends_on=None,
        requires_replacement=True,
    )
    after = PreprocResource(
        logical_id="Data",
        physical_resource_id=None,
        condition=True,
        resource_type="AWS::DynamoDB::Table",
        properties=PreprocProperties({"TableName": "new-table"}),
        depends_on=None,
        requires_replacement=True,
    )

    executor._execute_resource_change("Data", before, after)

    assert calls[-1][0] == "event"
    assert calls[-1][1]["resource_type"] == "AWS::DynamoDB::Table"
    assert [name for name, _ in deferred] == ["type-migration-Data"]

    deferred[0][1]()

    cleanup = [kwargs for kind, kwargs in calls if kind == "action"][-1]
    assert cleanup["action"] == ChangeAction.Remove
    assert cleanup["physical_resource_id"] == "old-resource-id"
    assert cleanup["part_of_replacement"] is True


def test_failed_update_fails_closed_until_cross_resource_rollback_exists():
    stack = Stack(
        account_id="000000000000",
        region_name="us-east-1",
        request_payload={"StackName": "failed-update-stack"},
    )
    stack.set_stack_status(StackStatus.UPDATE_IN_PROGRESS)
    executor = object.__new__(ChangeSetModelExecutor)
    executor._change_set = SimpleNamespace(
        stack=stack,
        change_set_type=ChangeSetType.UPDATE,
    )
    executor.resources = {}
    executor.outputs = []
    executor._deferred_actions = []

    def fail_update():
        raise TriggerRollback("Table", "provider update failed")

    executor.process = fail_update

    result = executor.execute()

    assert result.failed is True
    assert result.failure_message == "provider update failed"
    assert stack.status == StackStatus.UPDATE_ROLLBACK_FAILED


def test_failed_update_with_empty_reason_is_never_success():
    stack = Stack(
        account_id="000000000000",
        region_name="us-east-1",
        request_payload={"StackName": "failed-update-stack"},
    )
    stack.set_stack_status(StackStatus.UPDATE_IN_PROGRESS)
    executor = object.__new__(ChangeSetModelExecutor)
    executor._change_set = SimpleNamespace(
        stack=stack,
        change_set_type=ChangeSetType.UPDATE,
    )
    executor.resources = {}
    executor.outputs = []
    executor._deferred_actions = []
    executor.process = lambda: (_ for _ in ()).throw(TriggerRollback("Table", None))

    result = executor.execute()

    assert result.failed is True
    assert result.failure_message == "Resource Table failed without a reason"
    assert stack.status == StackStatus.UPDATE_ROLLBACK_FAILED


def test_failed_update_does_not_run_forward_deferred_cleanup():
    stack = Stack(
        account_id="000000000000",
        region_name="us-east-1",
        request_payload={"StackName": "failed-update-stack"},
    )
    stack.set_stack_status(StackStatus.UPDATE_IN_PROGRESS)
    executor = object.__new__(ChangeSetModelExecutor)
    executor._change_set = SimpleNamespace(
        stack=stack,
        change_set_type=ChangeSetType.UPDATE,
    )
    executor.resources = {}
    executor.outputs = []
    cleanup_calls = []
    executor._deferred_actions = [
        SimpleNamespace(name="delete-old-resource", action=lambda: cleanup_calls.append("called"))
    ]
    executor.process = lambda: (_ for _ in ()).throw(TriggerRollback("Table", "failed"))

    result = executor.execute()

    assert result.failed is True
    assert cleanup_calls == []
    assert stack.status == StackStatus.UPDATE_ROLLBACK_FAILED


def test_deferred_cleanup_exception_is_reported_as_failure():
    stack = Stack(
        account_id="000000000000",
        region_name="us-east-1",
        request_payload={"StackName": "failed-update-stack"},
    )
    stack.set_stack_status(StackStatus.UPDATE_IN_PROGRESS)
    executor = object.__new__(ChangeSetModelExecutor)
    executor._change_set = SimpleNamespace(
        stack=stack,
        change_set_type=ChangeSetType.UPDATE,
    )
    executor.resources = {}
    executor.outputs = []
    executor._deferred_actions = [
        SimpleNamespace(
            name="delete-old-resource",
            action=lambda: (_ for _ in ()).throw(Exception()),
        )
    ]
    executor.process = lambda: None

    result = executor.execute()

    assert result.failed is True
    assert result.failure_message == "Exception"
    assert stack.status == StackStatus.UPDATE_ROLLBACK_FAILED
    stack_statuses = [
        event["ResourceStatus"]
        for event in reversed(stack.events)
        if event["LogicalResourceId"] == stack.stack_name
    ]
    assert stack_statuses[-3:] == [
        StackStatus.UPDATE_COMPLETE_CLEANUP_IN_PROGRESS,
        StackStatus.UPDATE_ROLLBACK_IN_PROGRESS,
        StackStatus.UPDATE_ROLLBACK_FAILED,
    ]


def test_failed_provider_event_propagates_out_of_deferred_action():
    stack = Stack(
        account_id="000000000000",
        region_name="us-east-1",
        request_payload={"StackName": "delete-stack"},
    )
    stack.set_stack_status(StackStatus.DELETE_IN_PROGRESS)
    executor = object.__new__(ChangeSetModelExecutor)
    executor._change_set = SimpleNamespace(stack=stack)
    executor._get_physical_id = lambda *args: "physical-id"

    with pytest.raises(TriggerRollback) as raised:
        executor._process_event(
            action=ChangeAction.Remove,
            logical_resource_id="Table",
            event_status=OperationStatus.FAILED,
            resource_type="AWS::DynamoDB::Table",
            reason="delete failed",
        )

    assert raised.value.reason == "delete failed"
    assert stack.status == StackStatus.DELETE_IN_PROGRESS


def test_failed_deferred_provider_event_uses_update_rollback_statuses():
    stack = Stack(
        account_id="000000000000",
        region_name="us-east-1",
        request_payload={"StackName": "update-stack"},
    )
    stack.set_stack_status(StackStatus.UPDATE_IN_PROGRESS)
    executor = object.__new__(ChangeSetModelExecutor)
    executor._change_set = SimpleNamespace(
        stack=stack,
        change_set_type=ChangeSetType.UPDATE,
    )
    executor.resources = {}
    executor.outputs = []
    executor._get_physical_id = lambda *args: "old-physical-id"
    executor.process = lambda: None

    def failed_cleanup():
        executor._process_event(
            action=ChangeAction.Remove,
            logical_resource_id="Table",
            event_status=OperationStatus.FAILED,
            resource_type="AWS::DynamoDB::Table",
            reason="provider delete failed",
            update_resource_state=False,
            physical_resource_id_override="old-physical-id",
        )

    executor._deferred_actions = [
        SimpleNamespace(name="delete-old-resource", action=failed_cleanup)
    ]

    result = executor.execute()

    assert result.failed is True
    assert result.failure_message == "provider delete failed"
    assert stack.status == StackStatus.UPDATE_ROLLBACK_FAILED
    stack_statuses = [
        event["ResourceStatus"]
        for event in reversed(stack.events)
        if event["LogicalResourceId"] == stack.stack_name
    ]
    assert stack_statuses[-3:] == [
        StackStatus.UPDATE_COMPLETE_CLEANUP_IN_PROGRESS,
        StackStatus.UPDATE_ROLLBACK_IN_PROGRESS,
        StackStatus.UPDATE_ROLLBACK_FAILED,
    ]
