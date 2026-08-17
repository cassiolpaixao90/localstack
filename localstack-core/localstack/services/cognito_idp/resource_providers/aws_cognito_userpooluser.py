from __future__ import annotations

import copy
import hashlib
import secrets
from pathlib import Path
from typing import TypedDict

from botocore.exceptions import ClientError

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


class AttributeType(TypedDict):
    Name: str
    Value: str


class CognitoUserPoolUserProperties(TypedDict, total=False):
    ClientMetadata: dict[str, str]
    DesiredDeliveryMediums: list[str]
    ForceAliasCreation: bool
    MessageAction: str
    UserAttributes: list[AttributeType]
    Username: str
    UserPoolId: str
    ValidationData: list[AttributeType]


_PROPERTIES = {
    "ClientMetadata",
    "DesiredDeliveryMediums",
    "ForceAliasCreation",
    "MessageAction",
    "UserAttributes",
    "Username",
    "UserPoolId",
    "ValidationData",
}
_MAX_LIST_PAGES = 1_000
_MAX_ATTRIBUTES = 50


class CognitoUserPoolUserProvider(ResourceProvider[CognitoUserPoolUserProperties]):
    TYPE = "AWS::Cognito::UserPoolUser"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(
        self, request: ResourceRequest[CognitoUserPoolUserProperties]
    ) -> ProgressEvent[CognitoUserPoolUserProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_create(model):
            return invalid
        username = model.get("Username") or _generated_username(
            request.stack_name, request.logical_resource_id
        )
        params = {
            "TemporaryPassword": _temporary_password(),
            "UserPoolId": model["UserPoolId"],
            "Username": username,
        }
        if "UserAttributes" in model:
            params["UserAttributes"] = model["UserAttributes"]
        if "MessageAction" in model:
            params["MessageAction"] = model["MessageAction"]
        try:
            response = request.aws_client_factory.cognito_idp.admin_create_user(**params)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "UsernameExistsException":
                raise
            return failed(
                f"Cognito user {username} already exists",
                error_code="AlreadyExists",
            )
        return _success(request, response["User"], model["UserPoolId"])

    def read(
        self, request: ResourceRequest[CognitoUserPoolUserProperties]
    ) -> ProgressEvent[CognitoUserPoolUserProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        try:
            response = request.aws_client_factory.cognito_idp.admin_get_user(
                UserPoolId=model["UserPoolId"], Username=model["Username"]
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, model["Username"])
            raise
        return _success(request, response, model["UserPoolId"])

    def update(
        self, request: ResourceRequest[CognitoUserPoolUserProperties]
    ) -> ProgressEvent[CognitoUserPoolUserProperties]:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        state = {**previous, **desired}
        for key in _PROPERTIES:
            if desired.get(key) != previous.get(key):
                return failed(f"{key} is create-only and requires replacement")
        if invalid := _validate_identity(state):
            return invalid
        try:
            response = request.aws_client_factory.cognito_idp.admin_get_user(
                UserPoolId=state["UserPoolId"], Username=state["Username"]
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, state["Username"])
            raise
        return _success(request, response, state["UserPoolId"])

    def delete(
        self, request: ResourceRequest[CognitoUserPoolUserProperties]
    ) -> ProgressEvent[CognitoUserPoolUserProperties]:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_identity(state):
            return invalid
        try:
            request.aws_client_factory.cognito_idp.admin_delete_user(
                UserPoolId=state["UserPoolId"], Username=state["Username"]
            )
        except Exception as error:
            if not is_not_found(error):
                raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=state,
            custom_context=request.custom_context,
        )

    def list(
        self, request: ResourceRequest[CognitoUserPoolUserProperties]
    ) -> ProgressEvent[CognitoUserPoolUserProperties]:
        filters = copy.deepcopy(request.desired_state)
        if unsupported := unsupported_properties(filters, {"UserPoolId"}):
            return failed(f"Unsupported list filters for {self.TYPE}: {unsupported}")
        pool_id = filters.get("UserPoolId")
        if not isinstance(pool_id, str) or not pool_id:
            return failed(f"UserPoolId is required to list {self.TYPE}")
        users: list[dict] = []
        token = None
        seen_tokens: set[str] = set()
        for _ in range(_MAX_LIST_PAGES):
            params = {"Limit": 60, "UserPoolId": pool_id}
            if token is not None:
                params["PaginationToken"] = token
            response = request.aws_client_factory.cognito_idp.list_users(**params)
            users.extend(response.get("Users", []))
            token = response.get("PaginationToken")
            if token is None:
                break
            if not isinstance(token, str) or not token or token in seen_tokens:
                return failed("The service returned an invalid user continuation token")
            seen_tokens.add(token)
        else:
            return failed("The user listing exceeded the page limit")
        users.sort(key=lambda user: user["Username"])
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=[_user_model(user, pool_id) for user in users],
            custom_context=request.custom_context,
        )


def _validate_identity(model: dict) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported properties for Cognito user-pool user: {unsupported}")
    pool_id = model.get("UserPoolId")
    username = model.get("Username")
    if not isinstance(pool_id, str) or not 1 <= len(pool_id) <= 55:
        return failed("UserPoolId is required for AWS::Cognito::UserPoolUser")
    if not isinstance(username, str) or not 1 <= len(username) <= 128:
        return failed("Username is required for AWS::Cognito::UserPoolUser")
    return None


def _validate_create(model: dict) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported properties for Cognito user-pool user: {unsupported}")
    pool_id = model.get("UserPoolId")
    if not isinstance(pool_id, str) or not 1 <= len(pool_id) <= 55:
        return failed("UserPoolId is required for AWS::Cognito::UserPoolUser")
    username = model.get("Username")
    if username is not None and (not isinstance(username, str) or not 1 <= len(username) <= 128):
        return failed("Username must contain between 1 and 128 characters")
    if invalid := _validate_attributes(model.get("UserAttributes"), "UserAttributes"):
        return invalid
    for key in ("ClientMetadata", "DesiredDeliveryMediums", "ValidationData"):
        if model.get(key):
            return failed(
                f"{key} requires Cognito delivery or trigger behavior that is not supported"
            )
    if model.get("ForceAliasCreation") is True:
        return failed("ForceAliasCreation alias migration is not supported")
    if model.get("ForceAliasCreation") not in (None, False):
        return failed("ForceAliasCreation must be a boolean")
    if model.get("MessageAction") not in (None, "SUPPRESS"):
        return failed("Only MessageAction SUPPRESS is supported")
    return None


def _validate_attributes(value: object, property_name: str) -> ProgressEvent | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > _MAX_ATTRIBUTES:
        return failed(f"{property_name} must contain at most {_MAX_ATTRIBUTES} attributes")
    names: set[str] = set()
    for attribute in value:
        if not isinstance(attribute, dict) or set(attribute) != {"Name", "Value"}:
            return failed(f"Each {property_name} entry requires exactly Name and Value")
        name, attribute_value = attribute["Name"], attribute["Value"]
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 32
            or not isinstance(attribute_value, str)
            or len(attribute_value) > 2_048
            or name in names
        ):
            return failed(f"{property_name} contains an invalid or duplicate attribute")
        names.add(name)
    return None


def _temporary_password() -> str:
    return f"Aa1!{secrets.token_urlsafe(32)}"


def _generated_username(stack_name: str, logical_resource_id: str) -> str:
    identity = f"{stack_name}\0{logical_resource_id}".encode()
    suffix = hashlib.sha256(identity).hexdigest()[:12]
    return f"{stack_name[:80]}-{logical_resource_id[:24]}-{suffix}"


def _user_model(user: dict, pool_id: str) -> CognitoUserPoolUserProperties:
    model = CognitoUserPoolUserProperties(
        Username=user["Username"],
        UserPoolId=pool_id,
    )
    attributes = [
        copy.deepcopy(attribute)
        for attribute in user.get("UserAttributes", user.get("Attributes", []))
        if attribute.get("Name") != "sub"
    ]
    attributes.sort(key=lambda attribute: attribute["Name"])
    if attributes:
        model["UserAttributes"] = attributes
    return model


def _success(request, user: dict, pool_id: str) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=_user_model(user, pool_id),
        custom_context=request.custom_context,
    )
