from unittest.mock import MagicMock, call

import pytest

from localstack.testing.pytest.fixtures import deploy_cfn_template


@pytest.mark.parametrize("delay_between_polls", [None, 0, -1])
def test_deploy_cfn_template_rejects_invalid_poll_delay(delay_between_polls):
    aws_client = MagicMock()
    fixture = deploy_cfn_template.__wrapped__(aws_client)
    deploy = next(fixture)

    with pytest.raises(ValueError, match="delay_between_polls must be a positive integer"):
        deploy(
            template="{}",
            max_wait=60,
            delay_between_polls=delay_between_polls,
        )

    aws_client.cloudformation.create_change_set.assert_not_called()
    fixture.close()


@pytest.mark.parametrize(
    ("is_update", "stack_waiter_name"),
    [(False, "stack_create_complete"), (True, "stack_update_complete")],
)
def test_deploy_cfn_template_bounds_all_waiters(is_update, stack_waiter_name):
    cloudformation = MagicMock()
    waiters = {
        "change_set_create_complete": MagicMock(),
        stack_waiter_name: MagicMock(),
        "stack_delete_complete": MagicMock(),
    }
    cloudformation.get_waiter.side_effect = waiters.__getitem__
    cloudformation.create_change_set.return_value = {
        "Id": "change-set-id",
        "StackId": "stack-id",
    }
    cloudformation.describe_stacks.return_value = {"Stacks": [{"Outputs": []}]}
    aws_client = MagicMock(cloudformation=cloudformation)
    fixture = deploy_cfn_template.__wrapped__(aws_client)
    deploy = next(fixture)

    deploy(
        is_update=is_update,
        stack_name="stack-name" if is_update else None,
        template="{}",
        max_wait=61,
        delay_between_polls=3,
    )
    with pytest.raises(StopIteration):
        next(fixture)

    waiter_config = {"Delay": 3, "MaxAttempts": 21}
    assert cloudformation.get_waiter.call_args_list == [
        call("change_set_create_complete"),
        call(stack_waiter_name),
        call("stack_delete_complete"),
    ]
    waiters["change_set_create_complete"].wait.assert_called_once_with(
        ChangeSetName="change-set-id",
        WaiterConfig=waiter_config,
    )
    waiters[stack_waiter_name].wait.assert_called_once_with(
        StackName="stack-id",
        WaiterConfig=waiter_config,
    )
    waiters["stack_delete_complete"].wait.assert_called_once_with(
        StackName="stack-id",
        WaiterConfig=waiter_config,
    )
