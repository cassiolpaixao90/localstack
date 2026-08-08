import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import MagicMock, call

import pytest
from botocore.exceptions import ClientError

from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.iam.resource_providers.aws_iam_role import IAMRoleProvider


def _request(previous_state, desired_state):
    iam = MagicMock()
    previous_state = deepcopy(previous_state)
    desired_state = deepcopy(desired_state)
    role_name = (previous_state or desired_state).get("RoleName", "generated-role")
    role_id = (previous_state or {}).get("RoleId", "AROAUNIT")
    iam.get_role.return_value = {"Role": {"RoleName": role_name, "RoleId": role_id, "Tags": []}}
    iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [],
        "IsTruncated": False,
    }

    def missing_inline_policy(**kwargs):
        raise _no_such_entity("GetRolePolicy")

    iam.get_role_policy.side_effect = missing_inline_policy
    request = SimpleNamespace(
        previous_state=previous_state,
        desired_state=desired_state,
        aws_client_factory=SimpleNamespace(iam=iam),
        logger=MagicMock(),
        stack_name="stack",
        logical_resource_id="Role",
    )
    return request, iam


def test_update_reconciles_mutable_role_properties_in_place():
    previous = {
        "RoleName": "cdk-deploy-role",
        "Path": "/cdk/",
        "Arn": "arn:aws:iam::000000000000:role/cdk-deploy-role",
        "RoleId": "AROAPREVIOUS",
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
        "ManagedPolicyArns": ["arn:policy:keep", "arn:policy:remove"],
        "Policies": [
            {
                "PolicyName": "replace-inline",
                "PolicyDocument": {"Statement": {"Effect": "Deny", "Action": "s3:*"}},
            },
            {
                "PolicyName": "remove-inline",
                "PolicyDocument": {"Statement": []},
            },
        ],
        "Description": "old description",
        "MaxSessionDuration": 3600,
        "PermissionsBoundary": "arn:boundary:old",
        "Tags": [{"Key": "keep", "Value": "old"}, {"Key": "remove", "Value": "value"}],
    }
    desired = {
        "RoleName": "cdk-deploy-role",
        "Path": "/cdk/",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole"}],
        },
        "ManagedPolicyArns": ["arn:policy:add", "arn:policy:keep"],
        "Policies": [
            {
                "PolicyName": "replace-inline",
                "PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "s3:GetObject"}},
            },
            {
                "PolicyName": "add-inline",
                "PolicyDocument": {"Statement": []},
            },
        ],
        "Description": "new description",
        "MaxSessionDuration": 7200,
        "PermissionsBoundary": "arn:boundary:new",
        "Tags": [{"Key": "add", "Value": "value"}, {"Key": "keep", "Value": "new"}],
    }
    request, iam = _request(previous, desired)
    provider = IAMRoleProvider()
    provider.create = MagicMock()
    provider.delete = MagicMock()

    result = provider.update(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == {
        **desired,
        "Arn": previous["Arn"],
        "RoleId": previous["RoleId"],
    }
    provider.create.assert_not_called()
    provider.delete.assert_not_called()
    iam.update_assume_role_policy.assert_called_once_with(
        RoleName="cdk-deploy-role",
        PolicyDocument=json.dumps(desired["AssumeRolePolicyDocument"]),
    )
    assert iam.detach_role_policy.call_args_list == [
        call(RoleName="cdk-deploy-role", PolicyArn="arn:policy:remove")
    ]
    assert iam.attach_role_policy.call_args_list == [
        call(RoleName="cdk-deploy-role", PolicyArn="arn:policy:add")
    ]
    assert iam.delete_role_policy.call_args_list == [
        call(RoleName="cdk-deploy-role", PolicyName="remove-inline")
    ]
    assert iam.put_role_policy.call_count == 2
    iam.update_role.assert_called_once_with(
        RoleName="cdk-deploy-role",
        Description="new description",
        MaxSessionDuration=7200,
    )
    iam.put_role_permissions_boundary.assert_called_once_with(
        RoleName="cdk-deploy-role", PermissionsBoundary="arn:boundary:new"
    )
    iam.untag_role.assert_called_once_with(RoleName="cdk-deploy-role", TagKeys=["remove"])
    iam.tag_role.assert_called_once_with(
        RoleName="cdk-deploy-role",
        Tags=[{"Key": "add", "Value": "value"}, {"Key": "keep", "Value": "new"}],
    )
    assert [method_call[0] for method_call in iam.method_calls] == [
        "list_attached_role_policies",
        "get_role_policy",
        "get_role",
        "detach_role_policy",
        "attach_role_policy",
        "delete_role_policy",
        "put_role_policy",
        "put_role_policy",
        "untag_role",
        "tag_role",
        "put_role_permissions_boundary",
        "update_role",
        "update_assume_role_policy",
    ]
    iam.list_role_policies.assert_not_called()


def test_update_with_no_mutable_changes_only_checks_role_exists():
    state = {
        "RoleName": "unchanged-role",
        "Path": "/",
        "Arn": "arn:aws:iam::000000000000:role/unchanged-role",
        "RoleId": "AROAUNCHANGED",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": [],
        "Policies": [],
        "Tags": [],
    }
    request, iam = _request(state, state)

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model == state
    assert iam.method_calls == [call.get_role(RoleName="unchanged-role")]


def test_update_treats_unordered_collections_and_json_formatting_as_equal():
    previous = {
        "RoleName": "generated-role-name",
        "Arn": "arn:aws:iam::000000000000:role/generated-role-name",
        "RoleId": "AROAGENERATED",
        "AssumeRolePolicyDocument": '{"Statement": [], "Version": "2012-10-17"}',
        "ManagedPolicyArns": ["arn:policy:a", "arn:policy:b"],
        "Policies": [
            {"PolicyName": "a", "PolicyDocument": '{"Statement": [], "Version": "2012-10-17"}'},
            {"PolicyName": "b", "PolicyDocument": {"Version": "2012-10-17", "Statement": []}},
        ],
        "Tags": [{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}],
    }
    desired = {
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
        "ManagedPolicyArns": ["arn:policy:b", "arn:policy:a"],
        "Policies": [
            {"PolicyName": "b", "PolicyDocument": {"Statement": [], "Version": "2012-10-17"}},
            {"PolicyName": "a", "PolicyDocument": {"Version": "2012-10-17", "Statement": []}},
        ],
        "Tags": [{"Key": "b", "Value": "2"}, {"Key": "a", "Value": "1"}],
    }
    request, iam = _request(previous, desired)

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model["RoleName"] == previous["RoleName"]
    assert result.resource_model["RoleId"] == previous["RoleId"]
    assert iam.method_calls == [call.get_role(RoleName="generated-role-name")]


def test_update_resets_removed_optional_properties_to_aws_defaults():
    previous = {
        "RoleName": "role-with-options",
        "AssumeRolePolicyDocument": {"Statement": []},
        "Description": "remove me",
        "MaxSessionDuration": 7200,
        "PermissionsBoundary": "arn:boundary:remove",
    }
    desired = {
        "RoleName": "role-with-options",
        "AssumeRolePolicyDocument": {"Statement": []},
    }
    request, iam = _request(previous, desired)

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.SUCCESS
    iam.update_role.assert_called_once_with(
        RoleName="role-with-options", Description="", MaxSessionDuration=3600
    )
    iam.delete_role_permissions_boundary.assert_called_once_with(RoleName="role-with-options")


def test_update_rejects_ambiguous_owned_collections_before_iam_calls():
    previous = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {"Statement": []},
    }
    desired = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {"Statement": []},
        "Policies": [
            {"PolicyName": "duplicate", "PolicyDocument": {"Statement": []}},
            {"PolicyName": "duplicate", "PolicyDocument": {"Statement": []}},
        ],
    }
    request, iam = _request(previous, desired)

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "InvalidRequest"
    assert "duplicate inline policy" in result.message
    assert iam.method_calls == []


def test_update_without_previous_state_fails_closed():
    request, iam = _request(
        None,
        {
            "RoleName": "role",
            "AssumeRolePolicyDocument": {"Statement": []},
        },
    )

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "InvalidRequest"
    assert iam.method_calls == []


def test_update_rejects_create_only_property_changes_without_mutation():
    previous = {
        "RoleName": "old-role",
        "Path": "/old/",
        "AssumeRolePolicyDocument": {"Statement": []},
    }
    desired = {
        "RoleName": "new-role",
        "Path": "/new/",
        "AssumeRolePolicyDocument": {"Statement": []},
    }
    request, _ = _request(previous, desired)
    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "NotUpdatable"
    assert request.aws_client_factory.iam.method_calls == []


def _no_such_entity(operation):
    return ClientError({"Error": {"Code": "NoSuchEntity", "Message": "missing"}}, operation)


def test_update_fails_when_role_disappears_during_child_removal():
    previous = {
        "RoleName": "deleted-role",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": ["arn:policy:owned"],
    }
    desired = {
        "RoleName": "deleted-role",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": [],
    }
    request, iam = _request(previous, desired)
    iam.detach_role_policy.side_effect = _no_such_entity("DetachRolePolicy")
    iam.get_role.side_effect = [
        {"Role": {"RoleName": "deleted-role", "RoleId": "AROAUNIT"}},
        _no_such_entity("GetRole"),
    ]

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.resource_model == previous
    assert iam.get_role.call_count == 2


def test_update_ignores_an_already_removed_owned_child_when_role_exists():
    previous = {
        "RoleName": "existing-role",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": ["arn:policy:owned"],
    }
    desired = {
        "RoleName": "existing-role",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": [],
    }
    request, iam = _request(previous, desired)
    iam.detach_role_policy.side_effect = _no_such_entity("DetachRolePolicy")
    iam.get_role.return_value = {"Role": {"RoleName": "existing-role", "RoleId": "AROAUNIT"}}

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.SUCCESS
    assert iam.get_role.call_count == 2


def test_update_compensates_completed_operations_after_partial_failure():
    previous = {
        "RoleName": "quota-role",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": ["arn:policy:old"],
    }
    desired = {
        "RoleName": "quota-role",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": ["arn:policy:new"],
    }
    request, iam = _request(previous, desired)

    def attach_policy(*, RoleName, PolicyArn):
        if PolicyArn == "arn:policy:new":
            raise RuntimeError("injected attach failure")

    iam.attach_role_policy.side_effect = attach_policy

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.resource_model == previous
    assert iam.method_calls[:6] == [
        call.list_attached_role_policies(RoleName="quota-role"),
        call.get_role(RoleName="quota-role"),
        call.detach_role_policy(RoleName="quota-role", PolicyArn="arn:policy:old"),
        call.attach_role_policy(RoleName="quota-role", PolicyArn="arn:policy:new"),
        call.get_role(RoleName="quota-role"),
        call.attach_role_policy(RoleName="quota-role", PolicyArn="arn:policy:old"),
    ]


@pytest.mark.parametrize(
    "invalid_property",
    [
        {"MaxSessionDuration": True},
        {"MaxSessionDuration": 3599},
        {"ManagedPolicyArns": ["arn:policy:valid", 1]},
        {"Tags": [{"Key": "key", "Value": 1}]},
        {
            "Policies": [
                {
                    "PolicyName": "invalid",
                    "PolicyDocument": {"Statement": [], "invalid": {"set"}},
                }
            ]
        },
    ],
)
def test_update_rejects_invalid_property_types_before_mutating(invalid_property):
    previous = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {"Statement": []},
    }
    desired = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow"}]},
        **invalid_property,
    }
    request, iam = _request(previous, desired)

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "InvalidRequest"
    assert iam.method_calls == []


def test_create_rejects_invalid_scalar_before_creating_role():
    request, iam = _request(
        None,
        {
            "RoleName": "invalid-role",
            "AssumeRolePolicyDocument": {"Statement": []},
            "MaxSessionDuration": 1,
        },
    )

    result = IAMRoleProvider().create(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "InvalidRequest"
    assert iam.method_calls == []


def test_create_compensates_role_children_after_partial_failure():
    request, iam = _request(
        None,
        {
            "RoleName": "partially-created-role",
            "AssumeRolePolicyDocument": {"Statement": []},
            "ManagedPolicyArns": ["arn:policy:managed"],
            "Policies": [
                {"PolicyName": "created", "PolicyDocument": {"Statement": []}},
                {"PolicyName": "fails", "PolicyDocument": {"Statement": []}},
            ],
        },
    )
    iam.create_role.return_value = {
        "Role": {
            "Arn": "arn:aws:iam::000000000000:role/partially-created-role",
            "RoleId": "AROAPARTIAL",
        }
    }
    iam.get_role.return_value = {
        "Role": {
            "RoleName": "partially-created-role",
            "RoleId": "AROAPARTIAL",
            "Tags": [],
        }
    }

    def put_policy(*, RoleName, PolicyName, PolicyDocument):
        if PolicyName == "fails":
            raise RuntimeError("injected inline policy failure")

    iam.put_role_policy.side_effect = put_policy

    result = IAMRoleProvider().create(request)

    assert result.status == OperationStatus.FAILED
    assert iam.method_calls[-6:] == [
        call.get_role(RoleName="partially-created-role"),
        call.delete_role_policy(RoleName="partially-created-role", PolicyName="created"),
        call.get_role(RoleName="partially-created-role"),
        call.detach_role_policy(RoleName="partially-created-role", PolicyArn="arn:policy:managed"),
        call.get_role(RoleName="partially-created-role"),
        call.delete_role(RoleName="partially-created-role"),
    ]


def test_create_does_not_clean_up_a_recreated_role():
    request, iam = _request(
        None,
        {
            "RoleName": "recreated-role",
            "AssumeRolePolicyDocument": {"Statement": []},
            "ManagedPolicyArns": ["arn:policy:managed"],
            "Policies": [{"PolicyName": "fails", "PolicyDocument": {"Statement": []}}],
        },
    )
    iam.create_role.return_value = {
        "Role": {
            "Arn": "arn:aws:iam::000000000000:role/recreated-role",
            "RoleId": "AROAORIGINAL",
        }
    }
    iam.get_role.return_value = {
        "Role": {"RoleName": "recreated-role", "RoleId": "AROAREPLACEMENT", "Tags": []}
    }
    iam.put_role_policy.side_effect = RuntimeError("role was replaced before policy creation")

    result = IAMRoleProvider().create(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "NotFound"
    iam.detach_role_policy.assert_not_called()
    iam.delete_role.assert_not_called()


def test_create_does_not_delete_role_without_authoritative_identity():
    request, iam = _request(
        None,
        {
            "RoleName": "malformed-response-role",
            "AssumeRolePolicyDocument": {"Statement": []},
        },
    )
    iam.create_role.return_value = {"Role": {}}

    result = IAMRoleProvider().create(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "GeneralServiceException"
    iam.get_role.assert_not_called()
    iam.delete_role.assert_not_called()


def test_create_cleans_up_malformed_response_with_authoritative_role_id():
    request, iam = _request(
        None,
        {
            "RoleName": "missing-arn-role",
            "AssumeRolePolicyDocument": {"Statement": []},
        },
    )
    iam.create_role.return_value = {"Role": {"RoleId": "AROAORIGINAL"}}
    iam.get_role.return_value = {
        "Role": {"RoleName": "missing-arn-role", "RoleId": "AROAORIGINAL", "Tags": []}
    }

    result = IAMRoleProvider().create(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "GeneralServiceException"
    iam.get_role.assert_called_once_with(RoleName="missing-arn-role")
    iam.delete_role.assert_called_once_with(RoleName="missing-arn-role")


def test_update_schema_declares_get_role_for_missing_child_detection():
    permissions = set(IAMRoleProvider.SCHEMA["handlers"]["update"]["permissions"])
    assert {
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
    } <= permissions


def test_create_schema_declares_get_role_for_identity_safe_cleanup():
    permissions = set(IAMRoleProvider.SCHEMA["handlers"]["create"]["permissions"])
    assert "iam:GetRole" in permissions


def test_update_without_delta_fails_not_found_when_role_is_missing():
    state = {
        "RoleName": "missing-role",
        "AssumeRolePolicyDocument": {"Statement": []},
    }
    request, iam = _request(state, state)
    iam.get_role.side_effect = _no_such_entity("GetRole")

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "NotFound"
    assert result.resource_model == state


def test_update_with_delta_fails_not_found_when_role_is_missing():
    previous = {
        "RoleName": "missing-role",
        "AssumeRolePolicyDocument": {"Statement": []},
    }
    desired = {
        "RoleName": "missing-role",
        "AssumeRolePolicyDocument": {
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole"}]
        },
    }
    request, iam = _request(previous, desired)
    iam.update_assume_role_policy.side_effect = _no_such_entity("UpdateAssumeRolePolicy")
    iam.get_role.side_effect = _no_such_entity("GetRole")

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "NotFound"
    iam.get_role.assert_called_once_with(RoleName="missing-role")


def test_update_supports_cdk_bootstrap_v28_to_v32_deployment_role():
    read_only_policy = "arn:aws:iam::aws:policy/AWSCloudFormationReadOnlyAccess"
    previous = {
        "RoleName": "cdk-deployment-role",
        "Arn": "arn:aws:iam::000000000000:role/cdk-deployment-role",
        "RoleId": "AROACDKBOOTSTRAP",
        "AssumeRolePolicyDocument": {
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole"}]
        },
        "ManagedPolicyArns": [],
        "Policies": [
            {
                "PolicyName": "default",
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Sid": "CloudFormationPermissions",
                            "Effect": "Allow",
                            "Action": [
                                "cloudformation:DescribeChangeSet",
                                "cloudformation:DescribeStacks",
                                "s3:GetObject",
                            ],
                            "Resource": "*",
                        }
                    ]
                },
            }
        ],
    }
    desired = {
        "RoleName": "cdk-deployment-role",
        "AssumeRolePolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Condition": {"Null": {"sts:ExternalId": "true"}},
                }
            ]
        },
        "ManagedPolicyArns": [read_only_policy],
        "Policies": [
            {
                "PolicyName": "default",
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Sid": "DeployPermissions",
                            "Effect": "Allow",
                            "Action": ["s3:GetObject"],
                            "Resource": "*",
                        }
                    ]
                },
            }
        ],
    }
    request, iam = _request(previous, desired)
    provider = IAMRoleProvider()
    provider.create = MagicMock()
    provider.delete = MagicMock()

    result = provider.update(request)

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model["RoleId"] == previous["RoleId"]
    assert result.resource_model["Arn"] == previous["Arn"]
    assert [method_call[0] for method_call in iam.method_calls] == [
        "list_attached_role_policies",
        "get_role",
        "attach_role_policy",
        "put_role_policy",
        "update_assume_role_policy",
    ]
    iam.attach_role_policy.assert_called_once_with(
        RoleName="cdk-deployment-role", PolicyArn=read_only_policy
    )
    provider.create.assert_not_called()
    provider.delete.assert_not_called()


class _StatefulCollisionIam:
    def __init__(self):
        self.managed = {"arn:policy:external"}
        self.inline = {"external": {"Version": "2012-10-17", "Statement": [{"Effect": "Deny"}]}}
        self.tags = {"external": "old"}
        self.boundary = "arn:boundary:external"
        self.description = "external description"
        self.max_session_duration = 10800
        self.writes = []

    def get_role(self, **kwargs):
        return {
            "Role": {
                "RoleName": kwargs["RoleName"],
                "RoleId": "AROALIVE",
                "PermissionsBoundary": {
                    "PermissionsBoundaryArn": self.boundary,
                },
                "Description": self.description,
                "MaxSessionDuration": self.max_session_duration,
                "Tags": [{"Key": key, "Value": value} for key, value in sorted(self.tags.items())],
            }
        }

    def list_attached_role_policies(self, **kwargs):
        return {
            "AttachedPolicies": [{"PolicyArn": arn} for arn in sorted(self.managed)],
            "IsTruncated": False,
        }

    def get_role_policy(self, **kwargs):
        document = self.inline.get(kwargs["PolicyName"])
        if document is None:
            raise _no_such_entity("GetRolePolicy")
        return {"PolicyDocument": deepcopy(document)}

    def attach_role_policy(self, **kwargs):
        self.writes.append(("attach", kwargs["PolicyArn"]))
        self.managed.add(kwargs["PolicyArn"])

    def detach_role_policy(self, **kwargs):
        self.writes.append(("detach", kwargs["PolicyArn"]))
        self.managed.discard(kwargs["PolicyArn"])

    def put_role_policy(self, **kwargs):
        self.writes.append(("put-inline", kwargs["PolicyName"]))
        self.inline[kwargs["PolicyName"]] = json.loads(kwargs["PolicyDocument"])

    def delete_role_policy(self, **kwargs):
        self.writes.append(("delete-inline", kwargs["PolicyName"]))
        self.inline.pop(kwargs["PolicyName"], None)

    def tag_role(self, **kwargs):
        self.writes.append(("tag", tuple(tag["Key"] for tag in kwargs["Tags"])))
        self.tags.update({tag["Key"]: tag["Value"] for tag in kwargs["Tags"]})

    def untag_role(self, **kwargs):
        self.writes.append(("untag", tuple(kwargs["TagKeys"])))
        for key in kwargs["TagKeys"]:
            self.tags.pop(key, None)

    def put_role_permissions_boundary(self, **kwargs):
        self.writes.append(("put-boundary", kwargs["PermissionsBoundary"]))
        self.boundary = kwargs["PermissionsBoundary"]

    def delete_role_permissions_boundary(self, **kwargs):
        self.writes.append(("delete-boundary",))
        self.boundary = None

    def update_role(self, **kwargs):
        self.writes.append(("update-role",))
        if "Description" in kwargs:
            self.description = kwargs["Description"]
        if "MaxSessionDuration" in kwargs:
            self.max_session_duration = kwargs["MaxSessionDuration"]

    def update_assume_role_policy(self, **kwargs):
        self.writes.append(("trust",))
        raise RuntimeError("injected trust failure")


def test_update_rollback_restores_external_collisions():
    previous = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {"Statement": []},
    }
    desired = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole"}]
        },
        "ManagedPolicyArns": ["arn:policy:external"],
        "Policies": [
            {
                "PolicyName": "external",
                "PolicyDocument": {"Statement": [{"Effect": "Allow"}]},
            }
        ],
        "Tags": [{"Key": "external", "Value": "new"}],
        "PermissionsBoundary": "arn:boundary:desired",
        "Description": "desired description",
        "MaxSessionDuration": 7200,
    }
    request, _ = _request(previous, desired)
    iam = _StatefulCollisionIam()
    request.aws_client_factory.iam = iam

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert iam.managed == {"arn:policy:external"}
    assert iam.inline == {
        "external": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny"}],
        }
    }
    assert iam.tags == {"external": "old"}
    assert iam.boundary == "arn:boundary:external"
    assert iam.description == "external description"
    assert iam.max_session_duration == 10800
    assert not any(write[0] in {"attach", "detach"} for write in iam.writes)


def test_update_rejects_recreated_role_with_same_name_before_mutation():
    previous = {
        "RoleName": "role",
        "RoleId": "AROAORIGINAL",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": ["arn:policy:owned"],
    }
    desired = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": [],
    }
    request, iam = _request(previous, desired)
    iam.get_role.return_value = {"Role": {"RoleName": "role", "RoleId": "AROAREPLACEMENT"}}

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "NotFound"
    iam.detach_role_policy.assert_not_called()


def test_update_finds_external_managed_policy_on_later_page():
    previous = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {"Statement": []},
    }
    desired = {
        **previous,
        "ManagedPolicyArns": ["arn:policy:external"],
    }
    request, iam = _request(previous, desired)
    iam.list_attached_role_policies.side_effect = [
        {
            "AttachedPolicies": [{"PolicyArn": "arn:policy:unrelated"}],
            "IsTruncated": True,
            "Marker": "next-page",
        },
        {
            "AttachedPolicies": [{"PolicyArn": "arn:policy:external"}],
            "IsTruncated": False,
        },
    ]

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.SUCCESS
    assert iam.list_attached_role_policies.call_args_list == [
        call(RoleName="role"),
        call(RoleName="role", Marker="next-page"),
    ]
    iam.attach_role_policy.assert_not_called()


def test_update_snapshot_failure_happens_before_mutation():
    previous = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {"Statement": []},
    }
    desired = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole"}]
        },
        "ManagedPolicyArns": ["arn:policy:new"],
    }
    request, iam = _request(previous, desired)
    iam.list_attached_role_policies.side_effect = RuntimeError("snapshot failed")

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "GeneralServiceException"
    iam.attach_role_policy.assert_not_called()
    iam.update_assume_role_policy.assert_not_called()


@pytest.mark.parametrize(
    ("malformed_snapshot", "desired_properties", "mutating_method"),
    [
        ("get-role", {"ManagedPolicyArns": []}, "detach_role_policy"),
        (
            "managed",
            {"ManagedPolicyArns": ["arn:policy:new"]},
            "attach_role_policy",
        ),
        (
            "inline",
            {
                "Policies": [
                    {
                        "PolicyName": "new",
                        "PolicyDocument": {"Statement": []},
                    }
                ]
            },
            "put_role_policy",
        ),
    ],
)
def test_update_rejects_malformed_snapshots_before_mutation(
    malformed_snapshot, desired_properties, mutating_method
):
    previous = {
        "RoleName": "role",
        "RoleId": "AROAEXPECTED",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": ["arn:policy:owned"],
    }
    desired = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {"Statement": []},
        **desired_properties,
    }
    request, iam = _request(previous, desired)
    if malformed_snapshot == "get-role":
        iam.get_role.return_value = {}
    elif malformed_snapshot == "managed":
        iam.list_attached_role_policies.return_value = {}
    else:
        iam.get_role_policy.side_effect = None
        iam.get_role_policy.return_value = {}

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "GeneralServiceException"
    getattr(iam, mutating_method).assert_not_called()


@pytest.mark.parametrize(
    ("second_role_response", "expected_error"),
    [
        ({}, "GeneralServiceException"),
        (
            {"Role": {"RoleName": "role", "RoleId": "AROAREPLACEMENT", "Tags": []}},
            "NotFound",
        ),
    ],
)
def test_update_revalidates_identity_after_child_disappears(second_role_response, expected_error):
    previous = {
        "RoleName": "role",
        "RoleId": "AROAORIGINAL",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": ["arn:policy:owned"],
    }
    desired = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": [],
    }
    request, iam = _request(previous, desired)
    iam.get_role.side_effect = [
        {"Role": {"RoleName": "role", "RoleId": "AROAORIGINAL", "Tags": []}},
        second_role_response,
    ]
    iam.detach_role_policy.side_effect = _no_such_entity("DetachRolePolicy")

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == expected_error
    iam.attach_role_policy.assert_not_called()


def test_update_does_not_rollback_into_recreated_role():
    previous = {
        "RoleName": "role",
        "RoleId": "AROAORIGINAL",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": ["arn:policy:old"],
    }
    desired = {
        "RoleName": "role",
        "AssumeRolePolicyDocument": {"Statement": []},
        "ManagedPolicyArns": ["arn:policy:new"],
    }
    request, iam = _request(previous, desired)
    iam.get_role.side_effect = [
        {"Role": {"RoleName": "role", "RoleId": "AROAORIGINAL", "Tags": []}},
        {"Role": {"RoleName": "role", "RoleId": "AROAREPLACEMENT", "Tags": []}},
    ]

    def attach_policy(*, RoleName, PolicyArn):
        if PolicyArn == "arn:policy:new":
            raise RuntimeError("role was replaced before attach")

    iam.attach_role_policy.side_effect = attach_policy

    result = IAMRoleProvider().update(request)

    assert result.status == OperationStatus.FAILED
    assert result.error_code == "NotFound"
    assert iam.attach_role_policy.call_args_list == [
        call(RoleName="role", PolicyArn="arn:policy:new")
    ]
