from __future__ import annotations

import copy
from pathlib import Path
from typing import TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)
from localstack.services.cognito_idp.resource_providers.common import failed


class LogDeliveryConfigurationProperties(TypedDict, total=False):
    LogConfigurations: list[dict]
    UserPoolId: str


class CognitoLogDeliveryConfigurationProvider(ResourceProvider[LogDeliveryConfigurationProperties]):
    TYPE = "AWS::Cognito::LogDeliveryConfiguration"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate(model):
            return invalid
        response = request.aws_client_factory.cognito_idp.set_log_delivery_configuration(
            **_api_model(model)
        )
        return _success(request, _resource_model(response["LogDeliveryConfiguration"]))

    def read(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        response = request.aws_client_factory.cognito_idp.get_log_delivery_configuration(
            UserPoolId=model["UserPoolId"]
        )
        return _success(request, _resource_model(response["LogDeliveryConfiguration"]))

    def update(self, request: ResourceRequest) -> ProgressEvent:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        if invalid := _validate(desired):
            return invalid
        if desired.get("UserPoolId") != previous.get("UserPoolId"):
            return failed("UserPoolId is create-only and requires replacement")
        response = request.aws_client_factory.cognito_idp.set_log_delivery_configuration(
            **_api_model(desired)
        )
        return _success(request, _resource_model(response["LogDeliveryConfiguration"]))

    def delete(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        request.aws_client_factory.cognito_idp.set_log_delivery_configuration(
            UserPoolId=model["UserPoolId"], LogConfigurations=[]
        )
        return _success(request, {"UserPoolId": model["UserPoolId"], "LogConfigurations": []})


def _validate_identity(model: dict) -> ProgressEvent | None:
    if unsupported := sorted(set(model) - {"LogConfigurations", "UserPoolId"}):
        return failed(f"Unsupported log delivery properties: {unsupported}")
    pool_id = model.get("UserPoolId")
    if not isinstance(pool_id, str) or not 1 <= len(pool_id) <= 55:
        return failed("UserPoolId is required for log delivery")
    return None


def _validate(model: dict) -> ProgressEvent | None:
    if invalid := _validate_identity(model):
        return invalid
    configurations = model.get("LogConfigurations", [])
    if not isinstance(configurations, list) or len(configurations) > 2:
        return failed("LogConfigurations must contain at most 2 items")
    return None


def _api_model(model: dict) -> dict:
    return {
        "UserPoolId": model["UserPoolId"],
        "LogConfigurations": copy.deepcopy(model.get("LogConfigurations", [])),
    }


def _resource_model(configuration: dict) -> dict:
    return {
        "UserPoolId": configuration["UserPoolId"],
        "LogConfigurations": copy.deepcopy(configuration.get("LogConfigurations", [])),
    }


def _success(request: ResourceRequest, model: dict) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=model,
        custom_context=request.custom_context,
    )
