from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolreplica import (
    _list_replicas,
)
from localstack.services.cognito_idp.resource_providers.common import (
    failed,
    is_not_found,
    not_found,
    unsupported_properties,
)


class UserPoolRegionalConfigurationAttachmentProperties(TypedDict):
    EmailConfiguration: dict[str, Any] | None
    LambdaConfig: dict[str, Any] | None
    SmsConfiguration: dict[str, Any] | None
    Status: str | None
    UserPoolId: str
    UserPoolTags: dict[str, str] | None


_PROPERTIES = {
    "EmailConfiguration",
    "LambdaConfig",
    "SmsConfiguration",
    "Status",
    "UserPoolId",
    "UserPoolTags",
}
_REGIONAL_FIELDS = {"EmailConfiguration", "LambdaConfig", "SmsConfiguration"}
_UPDATE_POOL_FIELDS = {
    "AccountRecoverySetting",
    "AdminCreateUserConfig",
    "AutoVerifiedAttributes",
    "DeletionProtection",
    "DeviceConfiguration",
    "EmailAuthenticationMessage",
    "EmailAuthenticationSubject",
    "EmailConfiguration",
    "EmailVerificationMessage",
    "EmailVerificationSubject",
    "IssuerConfiguration",
    "KeyConfiguration",
    "LambdaConfig",
    "MfaConfiguration",
    "Policies",
    "SmsAuthenticationMessage",
    "SmsConfiguration",
    "SmsVerificationMessage",
    "UserAttributeUpdateSettings",
    "UserPoolAddOns",
    "UserPoolTier",
    "VerificationMessageTemplate",
}
_MAX_POLLS = 120


class CognitoUserPoolRegionalConfigurationAttachmentProvider(
    ResourceProvider[UserPoolRegionalConfigurationAttachmentProperties]
):
    TYPE = "AWS::Cognito::UserPoolRegionalConfigurationAttachment"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model):
            return invalid
        context = dict(request.custom_context)
        if not context.get("applied"):
            observed = _observe(request, model["UserPoolId"])
            if isinstance(observed, ProgressEvent):
                return observed
            context["rollback"] = observed
            context["applied"] = True
            try:
                _apply(request, model, observed)
            except Exception as error:
                _rollback(request, model, observed, error)
                raise
        return _poll(request, model, context)

    def read(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        observed = _observe(request, model["UserPoolId"])
        if isinstance(observed, ProgressEvent):
            return observed
        return _success(request, _observed_model(model["UserPoolId"], observed))

    def update(self, request: ResourceRequest) -> ProgressEvent:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        if invalid := _validate_model(desired):
            return invalid
        if desired.get("UserPoolId") != previous.get("UserPoolId"):
            return failed("UserPoolId is create-only and requires replacement")
        context = dict(request.custom_context)
        if not context.get("applied"):
            observed = _observe(request, desired["UserPoolId"])
            if isinstance(observed, ProgressEvent):
                return observed
            context.update(applied=True, rollback=observed)
            try:
                _apply(request, desired, observed, previous=previous)
            except Exception as error:
                _rollback(request, desired, observed, error)
                raise
        return _poll(request, desired, context)

    def delete(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        context = dict(request.custom_context)
        observed = _observe(request, model["UserPoolId"])
        if isinstance(observed, ProgressEvent):
            if observed.error_code == "NotFound":
                return _success(request, _identity_model(model["UserPoolId"]))
            return observed
        if not context.get("delete_applied"):
            client = request.aws_client_factory.cognito_idp
            client.update_user_pool(**_pool_update_params(observed["pool"], {}, reset=True))
            _remove_owned_tags(client, observed["arn"], observed["tags"], model.get("UserPoolTags"))
            if observed["status"] != "INACTIVE":
                client.update_user_pool_replica(
                    RegionName=observed["region"],
                    Status="INACTIVE",
                    UserPoolId=model["UserPoolId"],
                )
            context["delete_applied"] = True
        delete_model = _identity_model(model["UserPoolId"])
        delete_model["Status"] = "INACTIVE"
        return _poll(request, delete_model, context, deleting=True)


def _observe(request: ResourceRequest, pool_id: str) -> dict | ProgressEvent:
    client = request.aws_client_factory.cognito_idp
    region = _client_region(client)
    replicas = _list_replicas(client, pool_id)
    if isinstance(replicas, ProgressEvent):
        return replicas
    matches = [
        replica
        for replica in replicas
        if replica.get("RegionName") == region and replica.get("Role") == "SECONDARY"
    ]
    if not matches:
        return not_found(
            "AWS::Cognito::UserPoolRegionalConfigurationAttachment", f"{pool_id}|{region}"
        )
    if len(matches) != 1:
        return failed("The service returned duplicate regional replicas")
    try:
        pool = client.describe_user_pool(UserPoolId=pool_id).get("UserPool")
    except Exception as error:
        if is_not_found(error):
            return not_found("AWS::Cognito::UserPoolRegionalConfigurationAttachment", pool_id)
        raise
    if not isinstance(pool, dict) or pool.get("Id") != pool_id:
        return failed("The service returned invalid regional user pool configuration")
    arn = pool.get("Arn")
    if not isinstance(arn, str) or not arn:
        return failed("The regional user pool has no ARN")
    tag_response = client.list_tags_for_resource(ResourceArn=arn)
    tags = tag_response.get("Tags", {})
    if not isinstance(tags, dict):
        return failed("The service returned invalid regional user pool tags")
    return {
        "arn": arn,
        "pool": copy.deepcopy(pool),
        "region": region,
        "status": matches[0].get("Status"),
        "tags": copy.deepcopy(tags),
    }


def _apply(request, model: dict, observed: dict, previous: dict | None = None) -> None:
    client = request.aws_client_factory.cognito_idp
    client.update_user_pool(**_pool_update_params(observed["pool"], model))
    _reconcile_tags(
        client,
        observed["arn"],
        observed["tags"],
        (previous or {}).get("UserPoolTags", {}),
        model.get("UserPoolTags", {}),
    )
    target = model.get("Status")
    if target is not None and target != observed["status"]:
        client.update_user_pool_replica(
            RegionName=observed["region"], Status=target, UserPoolId=model["UserPoolId"]
        )


def _rollback(request, model: dict, observed: dict, primary_error: Exception) -> None:
    client = request.aws_client_factory.cognito_idp
    try:
        client.update_user_pool(**_pool_update_params(observed["pool"], observed["pool"]))
        _rollback_tags(
            client,
            observed["arn"],
            observed["tags"],
            model.get("UserPoolTags", {}),
        )
        if observed["status"] in {"ACTIVE", "INACTIVE"}:
            client.update_user_pool_replica(
                RegionName=observed["region"],
                Status=observed["status"],
                UserPoolId=model["UserPoolId"],
            )
    except Exception as rollback_error:
        primary_error.add_note(
            "Regional attachment rollback failed: "
            f"{type(rollback_error).__name__}: {rollback_error}"
        )


def _poll(request, model: dict, context: dict, *, deleting: bool = False) -> ProgressEvent:
    target = "INACTIVE" if deleting else model.get("Status")
    if target is None:
        return _success(request, copy.deepcopy(model))
    replicas = _list_replicas(request.aws_client_factory.cognito_idp, model["UserPoolId"])
    if isinstance(replicas, ProgressEvent):
        return replicas
    region = _client_region(request.aws_client_factory.cognito_idp)
    current = next(
        (
            replica
            for replica in replicas
            if replica.get("RegionName") == region and replica.get("Role") == "SECONDARY"
        ),
        None,
    )
    if current is None:
        return not_found(
            "AWS::Cognito::UserPoolRegionalConfigurationAttachment",
            f"{model['UserPoolId']}|{region}",
        )
    if current.get("Status") == target:
        return _success(request, copy.deepcopy(model))
    polls = context.get("polls", 0) + 1
    if not isinstance(polls, int) or polls > _MAX_POLLS:
        return failed("Regional attachment polling exceeded its bound")
    context["polls"] = polls
    return ProgressEvent(
        status=OperationStatus.IN_PROGRESS,
        resource_model=copy.deepcopy(model),
        custom_context=context,
    )


def _pool_update_params(pool: dict, overrides: dict, *, reset: bool = False) -> dict:
    pool_id = pool.get("Id")
    pool_name = pool.get("Name")
    if not isinstance(pool_id, str) or not isinstance(pool_name, str) or not pool_name:
        raise ValueError("Regional user pool identity is invalid")
    result: dict[str, Any] = {"PoolName": pool_name, "UserPoolId": pool_id}
    for field in sorted(_UPDATE_POOL_FIELDS):
        if field in pool and not (reset and field in _REGIONAL_FIELDS):
            result[field] = copy.deepcopy(pool[field])
    for field in _REGIONAL_FIELDS:
        if field in overrides:
            result[field] = copy.deepcopy(overrides[field])
    return result


def _reconcile_tags(client, arn: str, current: dict, previous: dict, desired: dict) -> None:
    removed = [
        key for key in previous if key not in desired and current.get(key) == previous.get(key)
    ]
    changed = {key: value for key, value in desired.items() if current.get(key) != value}
    if removed:
        client.untag_resource(ResourceArn=arn, TagKeys=sorted(removed))
    if changed:
        client.tag_resource(ResourceArn=arn, Tags=changed)


def _rollback_tags(client, arn: str, before: dict, attempted: dict) -> None:
    current = client.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
    restore = {
        key: before[key]
        for key, value in attempted.items()
        if key in before and current.get(key) == value
    }
    remove = [
        key for key, value in attempted.items() if key not in before and current.get(key) == value
    ]
    if remove:
        client.untag_resource(ResourceArn=arn, TagKeys=sorted(remove))
    if restore:
        client.tag_resource(ResourceArn=arn, Tags=restore)


def _remove_owned_tags(client, arn: str, current: dict, owned: dict | None) -> None:
    keys = [key for key, value in (owned or {}).items() if current.get(key) == value]
    if keys:
        client.untag_resource(ResourceArn=arn, TagKeys=sorted(keys))


def _observed_model(pool_id: str, observed: dict) -> dict:
    model = _identity_model(pool_id)
    for field in _REGIONAL_FIELDS:
        if field in observed["pool"]:
            model[field] = copy.deepcopy(observed["pool"][field])
    if observed["status"] is not None:
        model["Status"] = observed["status"]
    if observed["tags"]:
        model["UserPoolTags"] = copy.deepcopy(observed["tags"])
    return model


def _identity_model(pool_id: str) -> UserPoolRegionalConfigurationAttachmentProperties:
    return UserPoolRegionalConfigurationAttachmentProperties(UserPoolId=pool_id)


def _validate_identity(model: dict) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported regional attachment properties: {unsupported}")
    pool_id = model.get("UserPoolId")
    if not isinstance(pool_id, str) or not 1 <= len(pool_id) <= 55 or "_" not in pool_id:
        return failed("UserPoolId is required for the regional attachment")
    return None


def _validate_model(model: dict) -> ProgressEvent | None:
    if invalid := _validate_identity(model):
        return invalid
    status = model.get("Status")
    if status is not None and status not in {"ACTIVE", "INACTIVE"}:
        return failed("Status must be ACTIVE or INACTIVE")
    tags = model.get("UserPoolTags")
    if tags is not None and (
        not isinstance(tags, dict)
        or len(tags) > 50
        or not all(
            isinstance(key, str)
            and 1 <= len(key) <= 128
            and isinstance(value, str)
            and len(value) <= 256
            for key, value in tags.items()
        )
    ):
        return failed("Invalid UserPoolTags")
    for field in _REGIONAL_FIELDS:
        value = model.get(field)
        if value is not None and not isinstance(value, dict):
            return failed(f"{field} must be an object")
    return None


def _client_region(client) -> str:
    region = getattr(getattr(client, "meta", None), "region_name", None)
    if not isinstance(region, str) or not region:
        raise ValueError("Cognito client Region is required for the regional attachment")
    return region


def _success(request, model: dict) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=model,
        custom_context=request.custom_context,
    )
