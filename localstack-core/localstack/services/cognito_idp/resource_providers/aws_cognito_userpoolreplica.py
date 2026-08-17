from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)
from localstack.services.cognito_idp.resource_providers.common import (
    failed,
    is_not_found,
    not_found,
    unsupported_properties,
)


class UserPoolReplicaProperties(TypedDict):
    RegionName: str
    UserPoolId: str
    UserPoolTagsAtCreate: dict[str, str] | None


_PROPERTIES = {"RegionName", "UserPoolId", "UserPoolTagsAtCreate"}
_IDENTITY = ("UserPoolId", "RegionName")
_REGION = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]$")
_POOL_ID = re.compile(r"^[\w-]+_[0-9A-Za-z]+$")
_CREATING = {"CREATING", "PENDING_CREATE"}
_DELETING = {"DELETING", "PENDING_DELETE"}
_STABLE = {"ACTIVE", "INACTIVE"}
_MAX_PAGES = 1_000
_MAX_POLLS = 120


class CognitoUserPoolReplicaProvider(ResourceProvider[UserPoolReplicaProperties]):
    TYPE = "AWS::Cognito::UserPoolReplica"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model):
            return invalid
        context = dict(request.custom_context)
        client = request.aws_client_factory.cognito_idp
        if not context.get("create_started"):
            existing = _find_replica(client, model["UserPoolId"], model["RegionName"])
            if isinstance(existing, ProgressEvent):
                return existing
            if existing is not None:
                return failed("User pool replica already exists", error_code="AlreadyExists")
            context.update(create_started=True, owned=True, polls=0)
            params = {
                "RegionName": model["RegionName"],
                "UserPoolId": model["UserPoolId"],
            }
            if "UserPoolTagsAtCreate" in model:
                params["UserPoolTags"] = copy.deepcopy(model["UserPoolTagsAtCreate"])
            try:
                client.create_user_pool_replica(**params)
            except Exception:
                observed = _find_replica(client, model["UserPoolId"], model["RegionName"])
                if isinstance(observed, ProgressEvent) or observed is None:
                    raise
                if observed.get("Status") in _STABLE:
                    return _success(request, _resource_model(model))
                if observed.get("Status") in _CREATING:
                    return _in_progress(request, model, context, "create_wait_stable")
                raise
        return _poll_create(request, model, context)

    def read(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        replica = _find_replica(
            request.aws_client_factory.cognito_idp, model["UserPoolId"], model["RegionName"]
        )
        if isinstance(replica, ProgressEvent):
            return replica
        if replica is None:
            return not_found(self.TYPE, _identifier(model))
        return _success(request, _resource_model(model))

    def update(self, request: ResourceRequest) -> ProgressEvent:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        if invalid := _validate_model(desired):
            return invalid
        for field in _PROPERTIES:
            if desired.get(field) != previous.get(field):
                return failed(f"{field} is create-only and requires replacement")
        return self.read(request)

    def delete(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        context = dict(request.custom_context)
        client = request.aws_client_factory.cognito_idp
        replica = _find_replica(client, model["UserPoolId"], model["RegionName"])
        if isinstance(replica, ProgressEvent):
            return replica
        if replica is None:
            return _success(request, _resource_model(model))
        status = replica.get("Status")
        if status in _CREATING:
            return _in_progress(request, model, context, "delete_wait_create")
        if status == "ACTIVE":
            client.update_user_pool_replica(
                RegionName=model["RegionName"],
                Status="INACTIVE",
                UserPoolId=model["UserPoolId"],
            )
            return _in_progress(request, model, context, "delete_wait_inactive")
        if status == "INACTIVE" and not context.get("delete_started"):
            context["delete_started"] = True
            try:
                client.delete_user_pool_replica(
                    RegionName=model["RegionName"], UserPoolId=model["UserPoolId"]
                )
            except Exception as error:
                if not is_not_found(error):
                    observed = _find_replica(client, model["UserPoolId"], model["RegionName"])
                    if isinstance(observed, ProgressEvent) or observed is not None:
                        raise
            replica = _find_replica(client, model["UserPoolId"], model["RegionName"])
            if isinstance(replica, ProgressEvent):
                return replica
            if replica is None:
                return _success(request, _resource_model(model))
            status = replica.get("Status")
        if status in _DELETING or context.get("delete_started"):
            return _in_progress(request, model, context, "delete_wait_absent")
        return failed(f"Unexpected user pool replica status: {status}")

    def list(self, request: ResourceRequest) -> ProgressEvent:
        filters = copy.deepcopy(request.desired_state)
        if unsupported := unsupported_properties(filters, {"UserPoolId"}):
            return failed(f"Unsupported list filters for {self.TYPE}: {unsupported}")
        pool_id = filters.get("UserPoolId")
        if not isinstance(pool_id, str) or _POOL_ID.fullmatch(pool_id) is None:
            return failed("UserPoolId is required to list user pool replicas")
        replicas = _list_replicas(request.aws_client_factory.cognito_idp, pool_id)
        if isinstance(replicas, ProgressEvent):
            return replicas
        models = [
            UserPoolReplicaProperties(UserPoolId=pool_id, RegionName=item["RegionName"])
            for item in replicas
            if item.get("Role") == "SECONDARY"
        ]
        models.sort(key=lambda item: item["RegionName"])
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=models,
            custom_context=request.custom_context,
        )


def _poll_create(request, model: dict, context: dict) -> ProgressEvent:
    replica = _find_replica(
        request.aws_client_factory.cognito_idp, model["UserPoolId"], model["RegionName"]
    )
    if isinstance(replica, ProgressEvent):
        return replica
    if replica is None:
        return _in_progress(request, model, context, "create_wait_visible")
    status = replica.get("Status")
    if status in _STABLE:
        return _success(request, _resource_model(model))
    if status in _CREATING:
        return _in_progress(request, model, context, "create_wait_stable")
    return _rollback_failed_create(request, model, context, f"Unexpected replica status: {status}")


def _rollback_failed_create(request, model: dict, context: dict, message: str) -> ProgressEvent:
    if context.get("owned"):
        client = request.aws_client_factory.cognito_idp
        try:
            client.update_user_pool_replica(
                RegionName=model["RegionName"], Status="INACTIVE", UserPoolId=model["UserPoolId"]
            )
            client.delete_user_pool_replica(
                RegionName=model["RegionName"], UserPoolId=model["UserPoolId"]
            )
        except Exception:
            message = f"{message}; rollback could not be confirmed"
    return failed(message)


def _in_progress(request, model: dict, context: dict, stage: str) -> ProgressEvent:
    polls = context.get("polls", 0) + 1
    if not isinstance(polls, int) or polls > _MAX_POLLS:
        return _rollback_failed_create(
            request, model, context, "Replica polling exceeded its bound"
        )
    context.update(polls=polls, stage=stage)
    return ProgressEvent(
        status=OperationStatus.IN_PROGRESS,
        resource_model=_resource_model(model),
        custom_context=context,
    )


def _list_replicas(client, pool_id: str) -> list[dict] | ProgressEvent:
    items: list[dict] = []
    token = None
    seen: set[str] = set()
    try:
        for _page in range(_MAX_PAGES):
            params = {"UserPoolId": pool_id}
            if token is not None:
                params["NextToken"] = token
            response = client.list_user_pool_replicas(**params)
            page = response.get("UserPoolReplicas", [])
            if not isinstance(page, list) or not all(isinstance(item, dict) for item in page):
                return failed("The service returned invalid user pool replica data")
            items.extend(copy.deepcopy(page))
            token = response.get("NextToken")
            if token is None:
                return items
            if not isinstance(token, str) or not token or token in seen:
                return failed("The service returned an invalid replica continuation token")
            seen.add(token)
    except Exception as error:
        if is_not_found(error):
            return []
        raise
    return failed("The service exceeded the replica pagination bound")


def _find_replica(client, pool_id: str, region: str) -> dict | ProgressEvent | None:
    replicas = _list_replicas(client, pool_id)
    if isinstance(replicas, ProgressEvent):
        return replicas
    matches = [
        item
        for item in replicas
        if item.get("RegionName") == region and item.get("Role") == "SECONDARY"
    ]
    if len(matches) > 1:
        return failed("The service returned duplicate secondary replicas")
    return matches[0] if matches else None


def _validate_identity(model: dict) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported properties for AWS::Cognito::UserPoolReplica: {unsupported}")
    pool_id = model.get("UserPoolId")
    region = model.get("RegionName")
    if not isinstance(pool_id, str) or _POOL_ID.fullmatch(pool_id) is None:
        return failed("UserPoolId is required for AWS::Cognito::UserPoolReplica")
    if (
        not isinstance(region, str)
        or not 5 <= len(region) <= 32
        or _REGION.fullmatch(region) is None
    ):
        return failed("RegionName is required for AWS::Cognito::UserPoolReplica")
    return None


def _validate_model(model: dict) -> ProgressEvent | None:
    if invalid := _validate_identity(model):
        return invalid
    tags = model.get("UserPoolTagsAtCreate")
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
        return failed("Invalid UserPoolTagsAtCreate")
    return None


def _resource_model(model: dict) -> UserPoolReplicaProperties:
    result = UserPoolReplicaProperties(
        RegionName=model["RegionName"], UserPoolId=model["UserPoolId"]
    )
    if "UserPoolTagsAtCreate" in model:
        result["UserPoolTagsAtCreate"] = copy.deepcopy(model["UserPoolTagsAtCreate"])
    return result


def _identifier(model: dict) -> str:
    return f"{model.get('UserPoolId')}|{model.get('RegionName')}"


def _success(request, model: UserPoolReplicaProperties) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=model,
        custom_context=request.custom_context,
    )
