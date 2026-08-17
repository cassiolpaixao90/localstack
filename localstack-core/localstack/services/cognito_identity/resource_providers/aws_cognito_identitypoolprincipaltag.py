from __future__ import annotations

import copy
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
from localstack.services.cognito_identity.resource_providers.common import (
    failed,
    is_not_found,
    not_found,
    unsupported_properties,
)


class CognitoIdentityPoolPrincipalTagProperties(TypedDict, total=False):
    IdentityPoolId: str
    IdentityProviderName: str
    PrincipalTags: dict[str, str]
    UseDefaults: bool


_PROPERTIES = {"IdentityPoolId", "IdentityProviderName", "PrincipalTags", "UseDefaults"}
_IDENTITY_PROPERTIES = ("IdentityPoolId", "IdentityProviderName")


class CognitoIdentityPoolPrincipalTagProvider(
    ResourceProvider[CognitoIdentityPoolPrincipalTagProperties]
):
    TYPE = "AWS::Cognito::IdentityPoolPrincipalTag"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(
        self, request: ResourceRequest[CognitoIdentityPoolPrincipalTagProperties]
    ) -> ProgressEvent[CognitoIdentityPoolPrincipalTagProperties]:
        desired = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(desired):
            return invalid
        target = _normalized_model(desired)
        identity = _identity(target)
        try:
            current = _normalized_response(
                request.aws_client_factory.cognito_identity.get_principal_tag_attribute_map(
                    **identity
                )
            )
        except Exception as error:
            if is_not_found(error):
                return not_found("AWS::Cognito::IdentityPool", target["IdentityPoolId"])
            if _error_code(error) == "InvalidParameterException":
                return failed("IdentityProviderName is not configured for the identity pool")
            raise
        if current == target:
            return _success(request, target)
        if not _is_default(current):
            return failed(
                f"Principal tag map {_physical_id(target)} already exists",
                error_code="AlreadyExists",
            )
        return self._set(request, target)

    def read(
        self, request: ResourceRequest[CognitoIdentityPoolPrincipalTagProperties]
    ) -> ProgressEvent[CognitoIdentityPoolPrincipalTagProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        try:
            response = request.aws_client_factory.cognito_identity.get_principal_tag_attribute_map(
                **_identity(model)
            )
        except Exception as error:
            if is_not_found(error) or _error_code(error) == "InvalidParameterException":
                return not_found(self.TYPE, _physical_id(model))
            raise
        try:
            current = _normalized_response(response)
        except ValueError as error:
            return failed(str(error))
        return _success(request, current)

    def update(
        self, request: ResourceRequest[CognitoIdentityPoolPrincipalTagProperties]
    ) -> ProgressEvent[CognitoIdentityPoolPrincipalTagProperties]:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        if invalid := _validate_model(desired):
            return invalid
        if invalid := _validate_model(previous):
            return invalid
        for key in _IDENTITY_PROPERTIES:
            if desired[key] != previous[key]:
                return failed(f"{key} is create-only and requires replacement")
        target = _normalized_model(desired)
        prior = _normalized_model(previous)
        try:
            current = _normalized_response(
                request.aws_client_factory.cognito_identity.get_principal_tag_attribute_map(
                    **_identity(target)
                )
            )
        except Exception as error:
            if is_not_found(error) or _error_code(error) == "InvalidParameterException":
                return not_found(self.TYPE, _physical_id(target))
            raise
        if current == target:
            return _success(request, target)
        if current != prior:
            return failed(
                "Principal tag map changed outside CloudFormation",
                error_code="ResourceConflict",
            )
        return self._set(request, target)

    def delete(
        self, request: ResourceRequest[CognitoIdentityPoolPrincipalTagProperties]
    ) -> ProgressEvent[CognitoIdentityPoolPrincipalTagProperties]:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_model(state):
            return invalid
        prior = _normalized_model(state)
        identity = _identity(prior)
        reset = {**identity, "PrincipalTags": {}, "UseDefaults": True}
        try:
            current = _normalized_response(
                request.aws_client_factory.cognito_identity.get_principal_tag_attribute_map(
                    **identity
                )
            )
        except Exception as error:
            if is_not_found(error) or _error_code(error) == "InvalidParameterException":
                return _delete_success(request, state)
            raise
        if current == reset or current != prior:
            return _delete_success(request, state)
        try:
            request.aws_client_factory.cognito_identity.set_principal_tag_attribute_map(**reset)
        except Exception as error:
            if not is_not_found(error) and _error_code(error) != "InvalidParameterException":
                raise
        return _delete_success(request, state)

    def list(
        self, request: ResourceRequest[CognitoIdentityPoolPrincipalTagProperties]
    ) -> ProgressEvent[CognitoIdentityPoolPrincipalTagProperties]:
        filters = copy.deepcopy(request.desired_state)
        if unsupported := unsupported_properties(filters, set(_IDENTITY_PROPERTIES)):
            return failed(f"Unsupported list filters for {self.TYPE}: {unsupported}")
        if set(filters) != set(_IDENTITY_PROPERTIES):
            return failed("IdentityPoolId and IdentityProviderName are required list filters")
        if invalid := _validate_identity(filters):
            return invalid
        try:
            response = request.aws_client_factory.cognito_identity.get_principal_tag_attribute_map(
                **_identity(filters)
            )
        except Exception as error:
            if is_not_found(error) or _error_code(error) == "InvalidParameterException":
                return _list_success(request, [])
            raise
        try:
            return _list_success(request, [_normalized_response(response)])
        except ValueError as error:
            return failed(str(error))

    @staticmethod
    def _set(request, target: CognitoIdentityPoolPrincipalTagProperties) -> ProgressEvent:
        try:
            response = request.aws_client_factory.cognito_identity.set_principal_tag_attribute_map(
                **target
            )
        except Exception as error:
            if is_not_found(error):
                return not_found("AWS::Cognito::IdentityPool", target["IdentityPoolId"])
            if _error_code(error) == "InvalidParameterException":
                return failed("IdentityProviderName is not configured for the identity pool")
            raise
        try:
            return _success(request, _normalized_response(response))
        except ValueError as error:
            return failed(str(error))


def _validate_identity(model: dict[str, Any]) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(
            f"Unsupported properties for {CognitoIdentityPoolPrincipalTagProvider.TYPE}: {unsupported}"
        )
    pool_id = model.get("IdentityPoolId")
    provider_name = model.get("IdentityProviderName")
    if not isinstance(pool_id, str) or not 1 <= len(pool_id) <= 55:
        return failed(
            f"IdentityPoolId is required for {CognitoIdentityPoolPrincipalTagProvider.TYPE}"
        )
    if not isinstance(provider_name, str) or not 1 <= len(provider_name) <= 128:
        return failed(
            f"IdentityProviderName is required for {CognitoIdentityPoolPrincipalTagProvider.TYPE}"
        )
    return None


def _validate_model(model: dict[str, Any]) -> ProgressEvent | None:
    if invalid := _validate_identity(model):
        return invalid
    use_defaults = model.get("UseDefaults", True)
    if not isinstance(use_defaults, bool):
        return failed("UseDefaults must be a boolean")
    tags = model.get("PrincipalTags", {})
    if not isinstance(tags, dict) or len(tags) > 50:
        return failed("PrincipalTags must be an object with at most 50 entries")
    for key, value in tags.items():
        if (
            not isinstance(key, str)
            or not 1 <= len(key) <= 128
            or not isinstance(value, str)
            or not 1 <= len(value) <= 256
        ):
            return failed("PrincipalTags keys and values must be non-empty bounded strings")
    if use_defaults == bool(tags):
        return failed(
            "UseDefaults requires no PrincipalTags; custom mappings require PrincipalTags"
        )
    return None


def _normalized_model(model: dict[str, Any]) -> CognitoIdentityPoolPrincipalTagProperties:
    return CognitoIdentityPoolPrincipalTagProperties(
        IdentityPoolId=model["IdentityPoolId"],
        IdentityProviderName=model["IdentityProviderName"],
        PrincipalTags=copy.deepcopy(model.get("PrincipalTags", {})),
        UseDefaults=model.get("UseDefaults", True),
    )


def _normalized_response(response: Any) -> CognitoIdentityPoolPrincipalTagProperties:
    if not isinstance(response, dict):
        raise ValueError("The service returned an invalid principal tag map")
    unsupported = set(response) - _PROPERTIES - {"ResponseMetadata"}
    if unsupported:
        raise ValueError(f"The service returned unsupported fields: {sorted(unsupported)}")
    model = {key: copy.deepcopy(response[key]) for key in _PROPERTIES if key in response}
    if invalid := _validate_model(model):
        raise ValueError(invalid.message)
    return _normalized_model(model)


def _identity(model: dict[str, Any]) -> dict[str, str]:
    return {key: model[key] for key in _IDENTITY_PROPERTIES}


def _physical_id(model: dict[str, Any]) -> str:
    return f"{model['IdentityPoolId']}|{model['IdentityProviderName']}"


def _is_default(model: dict[str, Any]) -> bool:
    return model.get("UseDefaults") is True and model.get("PrincipalTags") == {}


def _error_code(error: Exception) -> str | None:
    if isinstance(error, ClientError):
        return error.response.get("Error", {}).get("Code")
    return None


def _success(request, model: CognitoIdentityPoolPrincipalTagProperties) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=copy.deepcopy(model),
        custom_context=request.custom_context,
    )


def _delete_success(request, state: dict[str, Any]) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=copy.deepcopy(state),
        custom_context=request.custom_context,
    )


def _list_success(request, models: list[CognitoIdentityPoolPrincipalTagProperties]):
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_models=copy.deepcopy(models),
        custom_context=request.custom_context,
    )
