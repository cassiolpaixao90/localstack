from __future__ import annotations

import copy
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)
from localstack.utils.aws.arns import get_partition

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResourceConfig:
    create: str
    read: str
    list_operation: str
    update: str | None
    delete: str
    identifier: str
    parent: str | None
    create_fields: tuple[str, ...]
    update_fields: tuple[str, ...]
    response_fields: tuple[str, ...]
    reset_fields: tuple[tuple[str, Any], ...] = ()
    tag_path: str | None = None


class ApiGatewayV2ResourceProvider(ResourceProvider[dict[str, Any]]):
    CONFIG: ResourceConfig

    def create(self, request: ResourceRequest[dict[str, Any]]) -> ProgressEvent[dict[str, Any]]:
        model = copy.deepcopy(request.desired_state)
        response = getattr(request.aws_client_factory.apigatewayv2, self.CONFIG.create)(
            **_parameters(model, self.CONFIG.create_fields)
        )
        model.update(_response_model(response, self.CONFIG.response_fields))
        return _success(request, model)

    def read(self, request: ResourceRequest[dict[str, Any]]) -> ProgressEvent[dict[str, Any]]:
        model = request.desired_state
        try:
            response = getattr(request.aws_client_factory.apigatewayv2, self.CONFIG.read)(
                **_identity(model, self.CONFIG)
            )
        except ClientError as error:
            if _not_found(error):
                return ProgressEvent(
                    status=OperationStatus.FAILED,
                    message=f"{self.TYPE} was not found",
                    error_code="NotFound",
                )
            raise
        result = _identity(model, self.CONFIG)
        result.update(_response_model(response, self.CONFIG.response_fields))
        return _success(request, result)

    def list(self, request: ResourceRequest[dict[str, Any]]) -> ProgressEvent[dict[str, Any]]:
        filters = copy.deepcopy(request.desired_state or {})
        allowed = {self.CONFIG.parent} if self.CONFIG.parent else set()
        if unsupported := set(filters) - allowed:
            return ProgressEvent(
                status=OperationStatus.FAILED,
                message=f"Unsupported list filters for {self.TYPE}: {sorted(unsupported)}",
                error_code="InvalidRequest",
            )
        parameters: dict[str, Any] = {"MaxResults": "500"}
        if self.CONFIG.parent:
            parent_value = filters.get(self.CONFIG.parent)
            if not isinstance(parent_value, str) or not parent_value:
                return ProgressEvent(
                    status=OperationStatus.FAILED,
                    message=f"{self.CONFIG.parent} is required to list {self.TYPE}",
                    error_code="InvalidRequest",
                )
            parameters[self.CONFIG.parent] = parent_value
        models = []
        seen_tokens = set()
        for _ in range(128):
            response = getattr(request.aws_client_factory.apigatewayv2, self.CONFIG.list_operation)(
                **parameters
            )
            items = response.get("Items", [])
            if not isinstance(items, list) or len(models) + len(items) > 10_000:
                return ProgressEvent(
                    status=OperationStatus.FAILED,
                    message=f"Invalid or excessive list response for {self.TYPE}",
                    error_code="InternalFailure",
                )
            for item in items:
                if not isinstance(item, dict) or not isinstance(
                    item.get(self.CONFIG.identifier), str
                ):
                    return ProgressEvent(
                        status=OperationStatus.FAILED,
                        message=f"Invalid list item for {self.TYPE}",
                        error_code="InternalFailure",
                    )
                identity = {self.CONFIG.identifier: item[self.CONFIG.identifier]}
                if self.CONFIG.parent:
                    identity[self.CONFIG.parent] = parameters[self.CONFIG.parent]
                models.append(identity)
            token = response.get("NextToken")
            if token is None:
                break
            if not isinstance(token, str) or not token or token in seen_tokens:
                return ProgressEvent(
                    status=OperationStatus.FAILED,
                    message=f"Invalid continuation token while listing {self.TYPE}",
                    error_code="InternalFailure",
                )
            seen_tokens.add(token)
            parameters["NextToken"] = token
        else:
            return ProgressEvent(
                status=OperationStatus.FAILED,
                message=f"Page limit exceeded while listing {self.TYPE}",
                error_code="InternalFailure",
            )
        models.sort(
            key=lambda model: (
                model.get(self.CONFIG.parent, "") if self.CONFIG.parent else "",
                model[self.CONFIG.identifier],
            )
        )
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=models,
            custom_context=request.custom_context,
        )

    def update(self, request: ResourceRequest[dict[str, Any]]) -> ProgressEvent[dict[str, Any]]:
        if self.CONFIG.update is None:
            return _success(request, copy.deepcopy(request.desired_state))
        model = copy.deepcopy(request.desired_state)
        previous = request.previous_state or {}
        update_parameters = _update_parameters(model, previous, self.CONFIG)
        response = getattr(request.aws_client_factory.apigatewayv2, self.CONFIG.update)(
            **_identity(model, self.CONFIG),
            **update_parameters,
        )
        if self.CONFIG.tag_path is not None:
            try:
                _reconcile_tags(request, model, previous, self.CONFIG.tag_path)
            except Exception as error:
                rollback_failures = _compensate_failed_tag_update(
                    request, model, previous, self.CONFIG
                )
                if rollback_failures:
                    error.add_note(
                        "ApiGatewayV2 rollback incomplete: " + ", ".join(rollback_failures)
                    )
                raise
        model.update(_response_model(response, self.CONFIG.response_fields))
        if self.CONFIG.tag_path is not None:
            model["Tags"] = copy.deepcopy(request.desired_state.get("Tags", {}))
        return _success(request, model)

    def delete(self, request: ResourceRequest[dict[str, Any]]) -> ProgressEvent[dict[str, Any]]:
        model = request.previous_state or request.desired_state
        try:
            getattr(request.aws_client_factory.apigatewayv2, self.CONFIG.delete)(
                **_identity(model, self.CONFIG)
            )
        except ClientError as error:
            if not _not_found(error):
                raise
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})


def schema_path(module_file: str) -> str:
    return util.get_schema_path(Path(module_file))


def _identity(model: dict[str, Any], config: ResourceConfig) -> dict[str, Any]:
    result = {config.identifier: model[config.identifier]}
    if config.parent:
        result[config.parent] = model[config.parent]
    return result


def _parameters(model: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: copy.deepcopy(model[field]) for field in fields if field in model}


def _response_model(response: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: copy.deepcopy(response[field]) for field in fields if field in response}


def _update_parameters(
    model: dict[str, Any], previous: dict[str, Any], config: ResourceConfig
) -> dict[str, Any]:
    result = _parameters(model, config.update_fields)
    for field, reset in config.reset_fields:
        if field in previous and field not in model:
            result[field] = copy.deepcopy(reset)
    return result


def _not_found(error: ClientError) -> bool:
    return error.response.get("Error", {}).get("Code") in {
        "NotFound",
        "NotFoundException",
    }


def _reconcile_tags(request, model: dict[str, Any], previous: dict[str, Any], path: str) -> None:
    desired_tags = model.get("Tags", {})
    previous_tags = previous.get("Tags", {})
    if desired_tags == previous_tags:
        return
    arn = _tag_resource_arn(request, model, path)
    removed = sorted(set(previous_tags) - set(desired_tags))
    if removed:
        request.aws_client_factory.apigatewayv2.untag_resource(ResourceArn=arn, TagKeys=removed)
    changed = {key: value for key, value in desired_tags.items() if previous_tags.get(key) != value}
    if changed:
        request.aws_client_factory.apigatewayv2.tag_resource(ResourceArn=arn, Tags=changed)


def _compensate_failed_tag_update(
    request,
    model: dict[str, Any],
    previous: dict[str, Any],
    config: ResourceConfig,
) -> tuple[str, ...]:
    if not previous:
        return ("prior state unavailable",)
    failures: list[str] = []
    try:
        getattr(request.aws_client_factory.apigatewayv2, config.update)(
            **_identity(previous, config),
            **_update_parameters(previous, model, config),
        )
    except Exception as error:
        LOG.exception("Failed to restore %s configuration after a tag update failure", config)
        failures.append(f"configuration restore failed ({type(error).__name__[:64]})")
    try:
        _restore_tags(request, model, previous, config.tag_path)
    except Exception as error:
        LOG.exception("Failed to restore %s tags after a tag update failure", config)
        failures.append(f"tag restore failed ({type(error).__name__[:64]})")
    return tuple(failures)


def _restore_tags(request, model: dict[str, Any], previous: dict[str, Any], path: str) -> None:
    desired_tags = model.get("Tags", {})
    previous_tags = previous.get("Tags", {})
    arn = _tag_resource_arn(request, model, path)
    introduced = sorted(set(desired_tags) - set(previous_tags))
    if introduced:
        request.aws_client_factory.apigatewayv2.untag_resource(ResourceArn=arn, TagKeys=introduced)
    if previous_tags:
        request.aws_client_factory.apigatewayv2.tag_resource(ResourceArn=arn, Tags=previous_tags)


def _tag_resource_arn(request, model: dict[str, Any], path: str) -> str:
    partition = get_partition(request.region_name)
    if "ApiId" in model:
        resource_path = f"/apis/{model['ApiId']}{path.format(**model)}"
    elif "DomainName" in model and path == "":
        resource_path = f"/domainnames/{model['DomainName']}"
    else:
        raise ValueError("unsupported API Gateway v2 tag resource identity")
    return f"arn:{partition}:apigateway:{request.region_name}::{resource_path}"


def _success(request, model: dict[str, Any]) -> ProgressEvent[dict[str, Any]]:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=model,
        custom_context=request.custom_context,
    )
