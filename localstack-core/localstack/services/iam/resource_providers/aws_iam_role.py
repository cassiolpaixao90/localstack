# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypedDict

from botocore.exceptions import ClientError

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)
from localstack.utils.functions import call_safe


class IAMRoleProperties(TypedDict):
    AssumeRolePolicyDocument: dict | str | None
    Arn: str | None
    Description: str | None
    ManagedPolicyArns: list[str] | None
    MaxSessionDuration: int | None
    Path: str | None
    PermissionsBoundary: str | None
    Policies: list[Policy] | None
    RoleId: str | None
    RoleName: str | None
    Tags: list[Tag] | None


class Policy(TypedDict):
    PolicyDocument: str | dict | None
    PolicyName: str | None


class Tag(TypedDict):
    Key: str | None
    Value: str | None


REPEATED_INVOCATION = "repeated_invocation"

IAM_POLICY_VERSION = "2012-10-17"


@dataclass(frozen=True)
class _Call:
    function: Callable[..., Any]
    kwargs: dict[str, Any]


@dataclass(frozen=True)
class _UpdateOperation:
    apply: _Call
    rollback: tuple[_Call, ...]


@dataclass(frozen=True)
class _ExternalCollisions:
    managed_policy_arns: set[str]
    inline_policies: dict[str, dict]
    tags: dict[str, str]
    permissions_boundary: str | None
    description: str | None
    max_session_duration: int | None


class _RoleNotFound(Exception):
    pass


def _policy_document(value: dict | str, *, inline: bool = False) -> dict:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as error:
            raise ValueError("policy document must contain valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("policy document must be an object")

    document = util.remove_none_values(deepcopy(value))
    if not inline:
        return document

    document["Version"] = document.get("Version") or IAM_POLICY_VERSION
    statements = document.get("Statement", [])
    statements = statements if isinstance(statements, list) else [statements]
    for statement in statements:
        if isinstance(statement, dict) and isinstance(statement.get("Resource"), list):
            statement["Resource"] = [resource for resource in statement["Resource"] if resource]
    return document


def _canonical_policy(value: dict | str, *, inline: bool = False) -> str:
    return json.dumps(
        _policy_document(value, inline=inline),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _inline_policies(policies: list[Policy] | None) -> dict[str, dict]:
    if policies is not None and not isinstance(policies, list):
        raise ValueError("Policies must be a list")
    result = {}
    for policy in policies or []:
        if (
            not isinstance(policy, dict)
            or not isinstance(policy.get("PolicyName"), str)
            or not policy["PolicyName"]
        ):
            raise ValueError("inline policies require a PolicyName")
        name = policy["PolicyName"]
        if name in result:
            raise ValueError(f"duplicate inline policy name: {name}")
        document = _policy_document(policy.get("PolicyDocument"), inline=True)
        _canonical_policy(document, inline=True)
        result[name] = document
    return result


def _tags(tags: list[Tag] | None) -> dict[str, str]:
    if tags is not None and not isinstance(tags, list):
        raise ValueError("Tags must be a list")
    result = {}
    for tag in tags or []:
        if (
            not isinstance(tag, dict)
            or not isinstance(tag.get("Key"), str)
            or not tag["Key"]
            or not isinstance(tag.get("Value"), str)
        ):
            raise ValueError("tags require non-empty Key and Value properties")
        key = tag["Key"]
        if key.lower().startswith("aws:") or len(key) > 128 or len(tag["Value"]) > 256:
            raise ValueError(f"invalid tag: {key}")
        if key in result:
            raise ValueError(f"duplicate tag key: {key}")
        result[key] = tag["Value"]
    return result


def _managed_policy_arns(value: list[str] | None) -> set[str]:
    if value is not None and not isinstance(value, list):
        raise ValueError("ManagedPolicyArns must be a list")
    result = set()
    for policy_arn in value or []:
        if not isinstance(policy_arn, str) or not policy_arn.startswith("arn:"):
            raise ValueError("managed policy ARNs must be ARN strings")
        if policy_arn in result:
            raise ValueError(f"duplicate managed policy ARN: {policy_arn}")
        result.add(policy_arn)
    return result


def _validate_scalar_properties(model: IAMRoleProperties) -> None:
    if "RoleName" in model and (
        not isinstance(model["RoleName"], str)
        or not model["RoleName"]
        or len(model["RoleName"]) > 64
    ):
        raise ValueError("RoleName must be a non-empty string of at most 64 characters")
    if "Path" in model and (not isinstance(model["Path"], str) or not model["Path"]):
        raise ValueError("Path must be a non-empty string")
    if (description := model.get("Description")) is not None and not isinstance(description, str):
        raise ValueError("Description must be a string")
    if (duration := model.get("MaxSessionDuration")) is not None and (
        isinstance(duration, bool) or not isinstance(duration, int) or not 3600 <= duration <= 43200
    ):
        raise ValueError("MaxSessionDuration must be an integer from 3600 to 43200")
    if (boundary := model.get("PermissionsBoundary")) is not None and (
        not isinstance(boundary, str) or not boundary.startswith("arn:")
    ):
        raise ValueError("PermissionsBoundary must be an ARN string")


def _call_ignoring_missing_child(
    iam, function, expected_role_id: str | None = None, **kwargs
) -> None:
    try:
        function(**kwargs)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
        if _role_is_missing(iam, kwargs["RoleName"], expected_role_id):
            raise _RoleNotFound(kwargs["RoleName"]) from error


def _role_is_missing(iam, role_name: str, expected_role_id: str | None = None) -> bool:
    try:
        response = iam.get_role(RoleName=role_name)
        live_role = _validated_live_role(response, role_name)
        return expected_role_id is not None and live_role["RoleId"] != expected_role_id
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return True
        raise


def _ensure_role_identity(iam, role_name: str, expected_role_id: str) -> None:
    if _role_is_missing(iam, role_name, expected_role_id):
        raise _RoleNotFound(role_name)


def _validated_live_role(response: Any, role_name: str) -> dict:
    if not isinstance(response, dict) or not isinstance(response.get("Role"), dict):
        raise ValueError("GetRole returned an invalid role envelope")
    role = response["Role"]
    if role.get("RoleName") != role_name:
        raise ValueError("GetRole returned an unexpected role name")
    if not isinstance(role.get("RoleId"), str) or not role["RoleId"]:
        raise ValueError("GetRole returned an invalid RoleId")
    if "Tags" in role and (
        not isinstance(role["Tags"], list)
        or any(
            not isinstance(tag, dict)
            or not isinstance(tag.get("Key"), str)
            or not isinstance(tag.get("Value"), str)
            for tag in role["Tags"]
        )
    ):
        raise ValueError("GetRole returned invalid tags")
    if "PermissionsBoundary" in role:
        boundary = role["PermissionsBoundary"]
        if not isinstance(boundary, dict) or not isinstance(
            boundary.get("PermissionsBoundaryArn"), str
        ):
            raise ValueError("GetRole returned an invalid permissions boundary")
    if "Description" in role and not isinstance(role["Description"], str):
        raise ValueError("GetRole returned an invalid description")
    if "MaxSessionDuration" in role and (
        isinstance(role["MaxSessionDuration"], bool)
        or not isinstance(role["MaxSessionDuration"], int)
    ):
        raise ValueError("GetRole returned an invalid maximum session duration")
    return role


def _existing_managed_additions(iam, role_name: str, additions: set[str]) -> set[str]:
    existing = set()
    marker = None
    seen_markers = set()
    while additions - existing:
        kwargs = {"RoleName": role_name}
        if marker is not None:
            kwargs["Marker"] = marker
        response = iam.list_attached_role_policies(**kwargs)
        if not isinstance(response, dict) or not isinstance(response.get("AttachedPolicies"), list):
            raise ValueError("ListAttachedRolePolicies returned an invalid policy list")
        policies = response["AttachedPolicies"]
        if any(
            not isinstance(policy, dict)
            or not isinstance(policy.get("PolicyArn"), str)
            or not policy["PolicyArn"]
            for policy in policies
        ):
            raise ValueError("ListAttachedRolePolicies returned an invalid policy")
        existing.update(
            policy["PolicyArn"] for policy in policies if policy["PolicyArn"] in additions
        )
        is_truncated = response.get("IsTruncated")
        if not isinstance(is_truncated, bool):
            raise ValueError("ListAttachedRolePolicies returned invalid pagination state")
        if not is_truncated:
            break
        marker = response.get("Marker")
        if not isinstance(marker, str) or not marker or marker in seen_markers:
            raise ValueError("invalid IAM managed policy pagination marker")
        seen_markers.add(marker)
    return existing


def _capture_external_collisions(
    iam,
    role_name: str,
    managed_additions: set[str],
    inline_additions: set[str],
    tag_additions: set[str],
) -> tuple[_ExternalCollisions, dict]:
    existing_managed = (
        _existing_managed_additions(iam, role_name, managed_additions)
        if managed_additions
        else set()
    )

    existing_inline = {}
    for policy_name in sorted(inline_additions):
        try:
            response = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "NoSuchEntity":
                continue
            raise
        if not isinstance(response, dict) or "PolicyDocument" not in response:
            raise ValueError("GetRolePolicy returned an invalid policy document")
        existing_inline[policy_name] = _policy_document(response["PolicyDocument"], inline=True)

    live_role = _validated_live_role(iam.get_role(RoleName=role_name), role_name)
    existing_tags = {
        tag["Key"]: tag["Value"]
        for tag in live_role.get("Tags", [])
        if isinstance(tag, dict)
        and tag.get("Key") in tag_additions
        and isinstance(tag.get("Value"), str)
    }
    boundary = live_role.get("PermissionsBoundary")
    if isinstance(boundary, dict):
        boundary = boundary.get("PermissionsBoundaryArn")
    if not isinstance(boundary, str):
        boundary = None

    return (
        _ExternalCollisions(
            managed_policy_arns=existing_managed,
            inline_policies=existing_inline,
            tags=existing_tags,
            permissions_boundary=boundary,
            description=(
                live_role.get("Description")
                if isinstance(live_role.get("Description"), str)
                else None
            ),
            max_session_duration=(
                live_role.get("MaxSessionDuration")
                if isinstance(live_role.get("MaxSessionDuration"), int)
                and not isinstance(live_role.get("MaxSessionDuration"), bool)
                else None
            ),
        ),
        live_role,
    )


def _execute_update_operations(
    operations: list[_UpdateOperation], logger, iam, role_name: str, expected_role_id: str
) -> None:
    completed = []
    try:
        for operation in operations:
            operation.apply.function(**operation.apply.kwargs)
            completed.append(operation)
    except Exception as apply_error:
        for operation in reversed(completed):
            for rollback in operation.rollback:
                try:
                    _ensure_role_identity(iam, role_name, expected_role_id)
                except Exception as identity_error:
                    raise identity_error from apply_error
                try:
                    rollback.function(**rollback.kwargs)
                except _RoleNotFound as identity_error:
                    raise identity_error from apply_error
                except Exception as rollback_error:
                    logger.warning("Unable to compensate IAM role update: %s", rollback_error)
        raise


def _compensate_calls(
    calls: list[_Call], logger, iam, role_name: str, expected_role_id: str
) -> None:
    for rollback in reversed(calls):
        _ensure_role_identity(iam, role_name, expected_role_id)
        try:
            rollback.function(**rollback.kwargs)
        except _RoleNotFound:
            raise
        except Exception as rollback_error:
            logger.warning("Unable to compensate IAM role creation: %s", rollback_error)


class IAMRoleProvider(ResourceProvider[IAMRoleProperties]):
    TYPE = "AWS::IAM::Role"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[IAMRoleProperties],
    ) -> ProgressEvent[IAMRoleProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/RoleName

        Required properties:
          - AssumeRolePolicyDocument

        Create-only properties:
          - /properties/Path
          - /properties/RoleName

        Read-only properties:
          - /properties/Arn
          - /properties/RoleId

        IAM permissions required:
          - iam:CreateRole
          - iam:PutRolePolicy
          - iam:AttachRolePolicy
          - iam:DeleteRolePolicy
          - iam:DetachRolePolicy
          - iam:DeleteRole
          - iam:GetRole

        """
        model = request.desired_state
        iam = request.aws_client_factory.iam

        # defaults
        role_name = model.get("RoleName")
        if role_name is None:
            role_name = util.generate_default_name(request.stack_name, request.logical_resource_id)
            model["RoleName"] = role_name

        try:
            trust_policy = _policy_document(model["AssumeRolePolicyDocument"])
            _canonical_policy(trust_policy)
            managed_policy_arns = _managed_policy_arns(model.get("ManagedPolicyArns"))
            inline_policies = _inline_policies(model.get("Policies"))
            _tags(model.get("Tags"))
            _validate_scalar_properties(model)
        except (KeyError, TypeError, ValueError) as error:
            return ProgressEvent(
                status=OperationStatus.FAILED,
                resource_model={},
                error_code="InvalidRequest",
                message=str(error),
            )

        create_role_response = iam.create_role(
            **{
                k: v
                for k, v in model.items()
                if k not in ["ManagedPolicyArns", "Policies", "AssumeRolePolicyDocument"]
            },
            AssumeRolePolicyDocument=json.dumps(trust_policy),
        )
        created_role = (
            create_role_response.get("Role") if isinstance(create_role_response, dict) else None
        )
        created_role_id = created_role.get("RoleId") if isinstance(created_role, dict) else None
        if (
            not isinstance(created_role, dict)
            or not isinstance(created_role.get("Arn"), str)
            or not created_role["Arn"]
            or not isinstance(created_role_id, str)
            or not created_role_id
        ):
            failure = ValueError("CreateRole returned an invalid role identity")
            if isinstance(created_role_id, str) and created_role_id:
                try:
                    _compensate_calls(
                        [_Call(iam.delete_role, {"RoleName": role_name})],
                        request.logger,
                        iam,
                        role_name,
                        created_role_id,
                    )
                except Exception as cleanup_error:
                    failure = cleanup_error
            return ProgressEvent(
                status=OperationStatus.FAILED,
                resource_model={},
                error_code=(
                    "NotFound" if isinstance(failure, _RoleNotFound) else "GeneralServiceException"
                ),
                message=f"Unable to finish creating IAM role {role_name}: {failure}",
                custom_context={"exception": failure},
            )

        cleanup = [_Call(iam.delete_role, {"RoleName": role_name})]
        try:
            for arn in sorted(managed_policy_arns):
                iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
                cleanup.append(
                    _Call(
                        iam.detach_role_policy,
                        {"RoleName": role_name, "PolicyArn": arn},
                    )
                )

            for policy_name in sorted(inline_policies):
                iam.put_role_policy(
                    RoleName=model["RoleName"],
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(inline_policies[policy_name]),
                )
                cleanup.append(
                    _Call(
                        iam.delete_role_policy,
                        {"RoleName": role_name, "PolicyName": policy_name},
                    )
                )
        except Exception as error:
            failure = error
            try:
                _compensate_calls(cleanup, request.logger, iam, role_name, created_role_id)
            except Exception as cleanup_error:
                failure = cleanup_error
            return ProgressEvent(
                status=OperationStatus.FAILED,
                resource_model={},
                error_code=(
                    "NotFound" if isinstance(failure, _RoleNotFound) else "GeneralServiceException"
                ),
                message=f"Unable to finish creating IAM role {role_name}: {failure}",
                custom_context={"exception": failure},
            )
        model["Arn"] = created_role["Arn"]
        model["RoleId"] = created_role_id

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def read(
        self,
        request: ResourceRequest[IAMRoleProperties],
    ) -> ProgressEvent[IAMRoleProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - iam:GetRole
          - iam:ListAttachedRolePolicies
          - iam:ListRolePolicies
          - iam:GetRolePolicy
        """
        role_name = request.desired_state["RoleName"]
        get_role = request.aws_client_factory.iam.get_role(RoleName=role_name)

        model = {**get_role["Role"]}
        model.pop("CreateDate")
        model.pop("RoleLastUsed")

        list_managed_policies = request.aws_client_factory.iam.list_attached_role_policies(
            RoleName=role_name
        )
        model["ManagedPolicyArns"] = [
            policy["PolicyArn"] for policy in list_managed_policies["AttachedPolicies"]
        ]
        model["Policies"] = []

        policies = request.aws_client_factory.iam.list_role_policies(RoleName=role_name)
        for policy_name in policies["PolicyNames"]:
            policy = request.aws_client_factory.iam.get_role_policy(
                RoleName=role_name, PolicyName=policy_name
            )
            policy.pop("ResponseMetadata")
            policy.pop("RoleName")
            model["Policies"].append(policy)

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def delete(
        self,
        request: ResourceRequest[IAMRoleProperties],
    ) -> ProgressEvent[IAMRoleProperties]:
        """
        Delete a resource

        IAM permissions required:
          - iam:DeleteRole
          - iam:DetachRolePolicy
          - iam:DeleteRolePolicy
          - iam:GetRole
          - iam:ListAttachedRolePolicies
          - iam:ListRolePolicies
        """
        iam_client = request.aws_client_factory.iam
        role_name = request.previous_state["RoleName"]

        # detach managed policies
        for policy in iam_client.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            call_safe(
                iam_client.detach_role_policy,
                kwargs={"RoleName": role_name, "PolicyArn": policy["PolicyArn"]},
            )

        # delete inline policies
        for inline_policy_name in iam_client.list_role_policies(RoleName=role_name).get(
            "PolicyNames", []
        ):
            call_safe(
                iam_client.delete_role_policy,
                kwargs={"RoleName": role_name, "PolicyName": inline_policy_name},
            )

        iam_client.delete_role(RoleName=role_name)
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})

    def update(
        self,
        request: ResourceRequest[IAMRoleProperties],
    ) -> ProgressEvent[IAMRoleProperties]:
        """
        Update a resource

        IAM permissions required:
          - iam:UpdateRole
          - iam:UpdateRoleDescription
          - iam:UpdateAssumeRolePolicy
          - iam:GetRole
          - iam:GetRolePolicy
          - iam:ListAttachedRolePolicies
          - iam:DetachRolePolicy
          - iam:AttachRolePolicy
          - iam:DeleteRolePermissionsBoundary
          - iam:PutRolePermissionsBoundary
          - iam:DeleteRolePolicy
          - iam:PutRolePolicy
          - iam:TagRole
          - iam:UntagRole
        """
        desired = deepcopy(request.desired_state)
        previous = deepcopy(request.previous_state)
        if not previous or not previous.get("RoleName"):
            return ProgressEvent(
                status=OperationStatus.FAILED,
                resource_model=previous or {},
                error_code="InvalidRequest",
                message="AWS::IAM::Role update requires a previous resource state",
            )

        try:
            desired_trust = _policy_document(desired["AssumeRolePolicyDocument"])
            previous_trust = _policy_document(previous["AssumeRolePolicyDocument"])
            _canonical_policy(desired_trust)
            _canonical_policy(previous_trust)
            desired_managed = _managed_policy_arns(desired.get("ManagedPolicyArns"))
            previous_managed = _managed_policy_arns(previous.get("ManagedPolicyArns"))
            desired_inline = _inline_policies(desired.get("Policies"))
            previous_inline = _inline_policies(previous.get("Policies"))
            desired_tags = _tags(desired.get("Tags"))
            previous_tags = _tags(previous.get("Tags"))
            _validate_scalar_properties(desired)
            _validate_scalar_properties(previous)
        except (KeyError, TypeError, ValueError) as error:
            return ProgressEvent(
                status=OperationStatus.FAILED,
                resource_model=previous,
                error_code="InvalidRequest",
                message=str(error),
            )

        role_name = previous["RoleName"]
        desired_role_name = desired["RoleName"] if "RoleName" in desired else role_name
        previous_path = previous.get("Path", "/")
        desired_path = desired.get("Path", "/")
        if desired_role_name != role_name or desired_path != previous_path:
            return ProgressEvent(
                status=OperationStatus.FAILED,
                resource_model=previous,
                error_code="NotUpdatable",
                message="RoleName and Path are create-only and require replacement",
            )

        iam = request.aws_client_factory.iam
        operations = []
        managed_additions = desired_managed - previous_managed
        inline_additions = set(desired_inline.keys() - previous_inline.keys())
        tag_additions = set(desired_tags.keys() - previous_tags.keys())
        previous_boundary = previous.get("PermissionsBoundary")
        desired_boundary = desired.get("PermissionsBoundary")
        try:
            external, live_role = _capture_external_collisions(
                iam=iam,
                role_name=role_name,
                managed_additions=managed_additions,
                inline_additions=inline_additions,
                tag_additions=tag_additions,
            )
            previous_role_id = previous.get("RoleId")
            live_role_id = live_role["RoleId"]
            if isinstance(previous_role_id, str) and previous_role_id != live_role_id:
                return ProgressEvent(
                    status=OperationStatus.FAILED,
                    resource_model=previous,
                    error_code="NotFound",
                    message=f"IAM role {role_name} no longer has the expected identity",
                )
        except Exception as error:
            error_code = (
                "NotFound"
                if isinstance(error, ClientError)
                and error.response.get("Error", {}).get("Code") == "NoSuchEntity"
                else "GeneralServiceException"
            )
            return ProgressEvent(
                status=OperationStatus.FAILED,
                resource_model=previous,
                error_code=error_code,
                message=f"Unable to inspect IAM role {role_name}: {error}",
                custom_context={"exception": error},
            )

        for policy_arn in sorted(previous_managed - desired_managed):
            operations.append(
                _UpdateOperation(
                    apply=_Call(
                        _call_ignoring_missing_child,
                        {
                            "iam": iam,
                            "function": iam.detach_role_policy,
                            "expected_role_id": live_role_id,
                            "RoleName": role_name,
                            "PolicyArn": policy_arn,
                        },
                    ),
                    rollback=(
                        _Call(
                            iam.attach_role_policy,
                            {"RoleName": role_name, "PolicyArn": policy_arn},
                        ),
                    ),
                )
            )
        for policy_arn in sorted(managed_additions):
            if policy_arn in external.managed_policy_arns:
                continue
            operations.append(
                _UpdateOperation(
                    apply=_Call(
                        iam.attach_role_policy,
                        {"RoleName": role_name, "PolicyArn": policy_arn},
                    ),
                    rollback=(
                        _Call(
                            _call_ignoring_missing_child,
                            {
                                "iam": iam,
                                "function": iam.detach_role_policy,
                                "expected_role_id": live_role_id,
                                "RoleName": role_name,
                                "PolicyArn": policy_arn,
                            },
                        ),
                    ),
                )
            )

        for policy_name in sorted(previous_inline.keys() - desired_inline.keys()):
            operations.append(
                _UpdateOperation(
                    apply=_Call(
                        _call_ignoring_missing_child,
                        {
                            "iam": iam,
                            "function": iam.delete_role_policy,
                            "expected_role_id": live_role_id,
                            "RoleName": role_name,
                            "PolicyName": policy_name,
                        },
                    ),
                    rollback=(
                        _Call(
                            iam.put_role_policy,
                            {
                                "RoleName": role_name,
                                "PolicyName": policy_name,
                                "PolicyDocument": json.dumps(previous_inline[policy_name]),
                            },
                        ),
                    ),
                )
            )
        for policy_name in sorted(desired_inline):
            desired_document = desired_inline[policy_name]
            previous_document = previous_inline.get(policy_name)
            if previous_document is not None and _canonical_policy(
                desired_document, inline=True
            ) == _canonical_policy(previous_document, inline=True):
                continue
            external_document = external.inline_policies.get(policy_name)
            if previous_document is None and external_document is not None:
                if _canonical_policy(desired_document, inline=True) == _canonical_policy(
                    external_document, inline=True
                ):
                    continue
                rollback_document = external_document
            else:
                rollback_document = previous_document
            rollback = (
                (
                    _Call(
                        iam.put_role_policy,
                        {
                            "RoleName": role_name,
                            "PolicyName": policy_name,
                            "PolicyDocument": json.dumps(rollback_document),
                        },
                    ),
                )
                if rollback_document is not None
                else (
                    _Call(
                        _call_ignoring_missing_child,
                        {
                            "iam": iam,
                            "function": iam.delete_role_policy,
                            "expected_role_id": live_role_id,
                            "RoleName": role_name,
                            "PolicyName": policy_name,
                        },
                    ),
                )
            )
            operations.append(
                _UpdateOperation(
                    apply=_Call(
                        iam.put_role_policy,
                        {
                            "RoleName": role_name,
                            "PolicyName": policy_name,
                            "PolicyDocument": json.dumps(desired_document),
                        },
                    ),
                    rollback=rollback,
                )
            )

        removed_tag_keys = sorted(previous_tags.keys() - desired_tags.keys())
        if removed_tag_keys:
            operations.append(
                _UpdateOperation(
                    apply=_Call(
                        _call_ignoring_missing_child,
                        {
                            "iam": iam,
                            "function": iam.untag_role,
                            "expected_role_id": live_role_id,
                            "RoleName": role_name,
                            "TagKeys": removed_tag_keys,
                        },
                    ),
                    rollback=(
                        _Call(
                            iam.tag_role,
                            {
                                "RoleName": role_name,
                                "Tags": [
                                    {"Key": key, "Value": previous_tags[key]}
                                    for key in removed_tag_keys
                                ],
                            },
                        ),
                    ),
                )
            )
        changed_tag_keys = [
            key
            for key in sorted(desired_tags)
            if previous_tags.get(key) != desired_tags[key]
            and not (key not in previous_tags and external.tags.get(key) == desired_tags[key])
        ]
        if changed_tag_keys:
            new_tag_keys = [
                key
                for key in changed_tag_keys
                if key not in previous_tags and key not in external.tags
            ]
            changed_existing_tags = [
                {
                    "Key": key,
                    "Value": previous_tags.get(key, external.tags.get(key)),
                }
                for key in changed_tag_keys
                if key in previous_tags or key in external.tags
            ]
            rollback = []
            if new_tag_keys:
                rollback.append(
                    _Call(
                        _call_ignoring_missing_child,
                        {
                            "iam": iam,
                            "function": iam.untag_role,
                            "expected_role_id": live_role_id,
                            "RoleName": role_name,
                            "TagKeys": new_tag_keys,
                        },
                    )
                )
            if changed_existing_tags:
                rollback.append(
                    _Call(
                        iam.tag_role,
                        {"RoleName": role_name, "Tags": changed_existing_tags},
                    )
                )
            operations.append(
                _UpdateOperation(
                    apply=_Call(
                        iam.tag_role,
                        {
                            "RoleName": role_name,
                            "Tags": [
                                {"Key": key, "Value": desired_tags[key]} for key in changed_tag_keys
                            ],
                        },
                    ),
                    rollback=tuple(rollback),
                )
            )

        if desired_boundary != previous_boundary:
            if desired_boundary:
                rollback_boundary = previous_boundary or external.permissions_boundary
                if previous_boundary is None and desired_boundary == rollback_boundary:
                    rollback_boundary = desired_boundary
                boundary_rollback = (
                    (
                        _Call(
                            iam.put_role_permissions_boundary,
                            {"RoleName": role_name, "PermissionsBoundary": rollback_boundary},
                        ),
                    )
                    if rollback_boundary
                    else (
                        _Call(
                            _call_ignoring_missing_child,
                            {
                                "iam": iam,
                                "function": iam.delete_role_permissions_boundary,
                                "expected_role_id": live_role_id,
                                "RoleName": role_name,
                            },
                        ),
                    )
                )
                if previous_boundary is not None or desired_boundary != rollback_boundary:
                    operations.append(
                        _UpdateOperation(
                            apply=_Call(
                                iam.put_role_permissions_boundary,
                                {
                                    "RoleName": role_name,
                                    "PermissionsBoundary": desired_boundary,
                                },
                            ),
                            rollback=boundary_rollback,
                        )
                    )
            elif previous_boundary:
                operations.append(
                    _UpdateOperation(
                        apply=_Call(
                            _call_ignoring_missing_child,
                            {
                                "iam": iam,
                                "function": iam.delete_role_permissions_boundary,
                                "expected_role_id": live_role_id,
                                "RoleName": role_name,
                            },
                        ),
                        rollback=(
                            _Call(
                                iam.put_role_permissions_boundary,
                                {
                                    "RoleName": role_name,
                                    "PermissionsBoundary": previous_boundary,
                                },
                            ),
                        ),
                    )
                )

        role_update = {}
        previous_role_update = {}
        if desired.get("Description") != previous.get("Description") and (
            "Description" in desired or "Description" in previous
        ):
            desired_description = desired.get("Description") or ""
            rollback_description = (
                previous.get("Description") if "Description" in previous else external.description
            ) or ""
            if "Description" in previous or desired_description != rollback_description:
                role_update["Description"] = desired_description
                previous_role_update["Description"] = rollback_description
        if desired.get("MaxSessionDuration") != previous.get("MaxSessionDuration") and (
            "MaxSessionDuration" in desired or "MaxSessionDuration" in previous
        ):
            desired_duration = desired.get("MaxSessionDuration") or 3600
            rollback_duration = (
                previous.get("MaxSessionDuration")
                if "MaxSessionDuration" in previous
                else external.max_session_duration
            ) or 3600
            if "MaxSessionDuration" in previous or desired_duration != rollback_duration:
                role_update["MaxSessionDuration"] = desired_duration
                previous_role_update["MaxSessionDuration"] = rollback_duration
        if role_update:
            operations.append(
                _UpdateOperation(
                    apply=_Call(iam.update_role, {"RoleName": role_name, **role_update}),
                    rollback=(
                        _Call(
                            iam.update_role,
                            {"RoleName": role_name, **previous_role_update},
                        ),
                    ),
                )
            )

        if _canonical_policy(desired_trust) != _canonical_policy(previous_trust):
            operations.append(
                _UpdateOperation(
                    apply=_Call(
                        iam.update_assume_role_policy,
                        {
                            "RoleName": role_name,
                            "PolicyDocument": json.dumps(desired_trust),
                        },
                    ),
                    rollback=(
                        _Call(
                            iam.update_assume_role_policy,
                            {
                                "RoleName": role_name,
                                "PolicyDocument": json.dumps(previous_trust),
                            },
                        ),
                    ),
                )
            )

        try:
            _execute_update_operations(operations, request.logger, iam, role_name, live_role_id)
        except Exception as error:
            error_code = (
                "NotFound" if isinstance(error, _RoleNotFound) else "GeneralServiceException"
            )
            if error_code != "NotFound" and (
                isinstance(error, ClientError)
                and error.response.get("Error", {}).get("Code") == "NoSuchEntity"
            ):
                try:
                    if _role_is_missing(iam, role_name, live_role_id):
                        error_code = "NotFound"
                except ClientError:
                    pass
            return ProgressEvent(
                status=OperationStatus.FAILED,
                resource_model=previous,
                error_code=error_code,
                message=f"Unable to update IAM role {role_name}: {error}",
                custom_context={"exception": error},
            )

        desired["RoleName"] = role_name
        for attribute in ("Arn", "RoleId"):
            if previous.get(attribute) is not None:
                desired[attribute] = previous[attribute]
            elif live_role.get(attribute) is not None:
                desired[attribute] = live_role[attribute]
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=desired)

    def list(
        self,
        request: ResourceRequest[IAMRoleProperties],
    ) -> ProgressEvent[IAMRoleProperties]:
        resources = request.aws_client_factory.iam.list_roles()
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=[
                IAMRoleProperties(RoleName=resource["RoleName"]) for resource in resources["Roles"]
            ],
        )
