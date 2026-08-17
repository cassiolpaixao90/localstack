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


class RiskConfigurationAttachmentProperties(TypedDict):
    ClientId: str
    CompromisedCredentialsRiskConfiguration: dict | None
    RiskExceptionConfiguration: dict | None
    UserPoolId: str


_PROPERTIES = {
    "ClientId",
    "CompromisedCredentialsRiskConfiguration",
    "RiskExceptionConfiguration",
    "UserPoolId",
}


class CognitoUserPoolRiskConfigurationAttachmentProvider(
    ResourceProvider[RiskConfigurationAttachmentProperties]
):
    TYPE = "AWS::Cognito::UserPoolRiskConfigurationAttachment"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model):
            return invalid
        response = request.aws_client_factory.cognito_idp.set_risk_configuration(
            **_api_model(model)
        )
        return _success(request, _resource_model(model, response["RiskConfiguration"]))

    def read(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        response = request.aws_client_factory.cognito_idp.describe_risk_configuration(
            **_identity_api_model(model)
        )
        return _success(request, _resource_model(model, response["RiskConfiguration"]))

    def update(self, request: ResourceRequest) -> ProgressEvent:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        if invalid := _validate_model(desired):
            return invalid
        for field in ("ClientId", "UserPoolId"):
            if desired.get(field) != previous.get(field):
                return failed(f"{field} is create-only and requires replacement")
        response = request.aws_client_factory.cognito_idp.set_risk_configuration(
            **_api_model(desired)
        )
        return _success(request, _resource_model(desired, response["RiskConfiguration"]))

    def delete(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        request.aws_client_factory.cognito_idp.set_risk_configuration(**_identity_api_model(model))
        return _success(request, model)


def _validate_identity(model: dict) -> ProgressEvent | None:
    if unsupported := sorted(set(model) - _PROPERTIES):
        return failed(f"Unsupported risk configuration properties: {unsupported}")
    client_id = model.get("ClientId")
    pool_id = model.get("UserPoolId")
    if not isinstance(client_id, str) or not 1 <= len(client_id) <= 128:
        return failed("ClientId is required for the risk configuration attachment")
    if not isinstance(pool_id, str) or not 1 <= len(pool_id) <= 55:
        return failed("UserPoolId is required for the risk configuration attachment")
    return None


def _validate_model(model: dict) -> ProgressEvent | None:
    if invalid := _validate_identity(model):
        return invalid
    if not any(
        model.get(field) is not None
        for field in (
            "CompromisedCredentialsRiskConfiguration",
            "RiskExceptionConfiguration",
        )
    ):
        return failed("At least one executable risk configuration is required")
    return None


def _identity_api_model(model: dict) -> dict:
    return {"ClientId": model["ClientId"], "UserPoolId": model["UserPoolId"]}


def _api_model(model: dict) -> dict:
    result = _identity_api_model(model)
    for field in (
        "CompromisedCredentialsRiskConfiguration",
        "RiskExceptionConfiguration",
    ):
        if field in model:
            result[field] = copy.deepcopy(model[field])
    return result


def _resource_model(identity: dict, configuration: dict) -> dict:
    model = {
        "ClientId": identity["ClientId"],
        "UserPoolId": identity["UserPoolId"],
    }
    for field in (
        "CompromisedCredentialsRiskConfiguration",
        "RiskExceptionConfiguration",
    ):
        if field in configuration:
            model[field] = copy.deepcopy(configuration[field])
    return model


def _success(request: ResourceRequest, model: dict) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=model,
        custom_context=request.custom_context,
    )
