from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import TypedDict

from botocore.exceptions import ConnectionClosedError, ReadTimeoutError

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


class CognitoUserPoolUICustomizationAttachmentProperties(TypedDict):
    CSS: str | None
    ClientId: str | None
    UserPoolId: str | None


_PROPERTIES = {"CSS", "ClientId", "UserPoolId"}
_CREATE_ONLY = {"ClientId", "UserPoolId"}
_CLIENT_ID_PATTERN = re.compile(r"^[\w+]+$")
_POOL_ID_PATTERN = re.compile(r"^[\w-]+_[0-9A-Za-z]+$")


class CognitoUserPoolUICustomizationAttachmentProvider(
    ResourceProvider[CognitoUserPoolUICustomizationAttachmentProperties]
):
    TYPE = "AWS::Cognito::UserPoolUICustomizationAttachment"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate(model):
            return invalid
        try:
            response = _set(request.aws_client_factory.cognito_idp, model)
        except Exception as error:
            response = _reconcile_ambiguous_write(request, model, error)
        return _success(request, model, response)

    def read(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate(model):
            return invalid
        try:
            response = _get(request.aws_client_factory.cognito_idp, model)
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, _identifier(model))
            raise
        if not _belongs_to_attachment(response, model):
            return not_found(self.TYPE, _identifier(model))
        return _success(request, model, response)

    def update(self, request: ResourceRequest) -> ProgressEvent:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        if invalid := _validate(desired):
            return invalid
        for name in _CREATE_ONLY:
            if desired[name] != previous.get(name):
                return failed(f"{name} is create-only and requires replacement")
        client = request.aws_client_factory.cognito_idp
        try:
            before = _get(client, previous)
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, _identifier(previous))
            raise
        try:
            response = _set(client, desired)
        except Exception as error:
            if isinstance(error, (ConnectionClosedError, ReadTimeoutError)):
                observed = _get(client, desired)
                if _belongs_to_attachment(observed, desired) and _css(observed) == desired.get(
                    "CSS", ""
                ):
                    response = observed
                else:
                    _set(client, {**previous, "CSS": _css(before)})
                    raise
            else:
                raise
        return _success(request, desired, response)

    def delete(self, request: ResourceRequest) -> ProgressEvent:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate(state):
            return invalid
        try:
            _set(request.aws_client_factory.cognito_idp, {**state, "CSS": ""})
        except Exception as error:
            if not is_not_found(error):
                raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=state,
            custom_context=request.custom_context,
        )


def _set(client, model: dict) -> dict:
    return client.set_ui_customization(
        CSS=model.get("CSS", ""),
        ClientId=model["ClientId"],
        UserPoolId=model["UserPoolId"],
    ).get("UICustomization", {})


def _get(client, model: dict) -> dict:
    return client.get_ui_customization(
        ClientId=model["ClientId"], UserPoolId=model["UserPoolId"]
    ).get("UICustomization", {})


def _reconcile_ambiguous_write(request, model: dict, error: Exception) -> dict:
    if not isinstance(error, (ConnectionClosedError, ReadTimeoutError)):
        raise error
    observed = _get(request.aws_client_factory.cognito_idp, model)
    if not _belongs_to_attachment(observed, model) or _css(observed) != model.get("CSS", ""):
        raise error
    return observed


def _validate(model: dict) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported UI-customization attachment properties: {unsupported}")
    client_id = model.get("ClientId")
    if (
        not isinstance(client_id, str)
        or not 1 <= len(client_id) <= 128
        or _CLIENT_ID_PATTERN.fullmatch(client_id) is None
    ):
        return failed("ClientId is required and must match [\\w+]+")
    pool_id = model.get("UserPoolId")
    if (
        not isinstance(pool_id, str)
        or not 1 <= len(pool_id) <= 55
        or _POOL_ID_PATTERN.fullmatch(pool_id) is None
    ):
        return failed("UserPoolId is required and must identify a Cognito user pool")
    css = model.get("CSS", "")
    if not isinstance(css, str) or len(css) > 131_072:
        return failed("CSS must be a string with at most 131072 characters")
    return None


def _css(response: dict) -> str:
    value = response.get("CSS", "")
    return value if isinstance(value, str) else ""


def _belongs_to_attachment(response: dict, model: dict) -> bool:
    return (
        bool(response)
        and response.get("ClientId") == model.get("ClientId")
        and response.get("UserPoolId") == model.get("UserPoolId")
    )


def _identifier(model: dict) -> str:
    return (
        f"UserPoolUICustomizationAttachment-{model.get('UserPoolId', '')}-"
        f"{model.get('ClientId', '')}"
    )


def _success(request, model: dict, response: dict) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=CognitoUserPoolUICustomizationAttachmentProperties(
            CSS=_css(response),
            ClientId=model["ClientId"],
            UserPoolId=model["UserPoolId"],
        ),
        custom_context=request.custom_context,
    )
