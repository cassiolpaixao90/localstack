from __future__ import annotations

import copy
import hashlib
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


class CognitoUserPoolUserToGroupAttachmentProperties(TypedDict, total=False):
    GroupName: str
    Id: str
    Username: str
    UserPoolId: str


_PROPERTIES = {"GroupName", "Id", "Username", "UserPoolId"}
_IDENTITY_PROPERTIES = ("UserPoolId", "Username", "GroupName")
_MAX_LIST_CALLS = 1_000
_MAX_LIST_RESOURCES = 100_000


class CognitoUserPoolUserToGroupAttachmentProvider(
    ResourceProvider[CognitoUserPoolUserToGroupAttachmentProperties]
):
    TYPE = "AWS::Cognito::UserPoolUserToGroupAttachment"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(
        self, request: ResourceRequest[CognitoUserPoolUserToGroupAttachmentProperties]
    ) -> ProgressEvent[CognitoUserPoolUserToGroupAttachmentProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_identity(model, allow_id=False):
            return invalid
        request.aws_client_factory.cognito_idp.admin_add_user_to_group(
            GroupName=model["GroupName"],
            Username=model["Username"],
            UserPoolId=model["UserPoolId"],
        )
        return _success(request, model)

    def read(
        self, request: ResourceRequest[CognitoUserPoolUserToGroupAttachmentProperties]
    ) -> ProgressEvent[CognitoUserPoolUserToGroupAttachmentProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        try:
            groups, error = _list_groups_for_user(
                request.aws_client_factory.cognito_idp,
                model["UserPoolId"],
                model["Username"],
            )
        except Exception as exception:
            if is_not_found(exception):
                return not_found(self.TYPE, _attachment_id(model))
            raise
        if error is not None:
            return failed(error)
        if not any(group.get("GroupName") == model["GroupName"] for group in groups):
            return not_found(self.TYPE, _attachment_id(model))
        return _success(request, model)

    def update(
        self, request: ResourceRequest[CognitoUserPoolUserToGroupAttachmentProperties]
    ) -> ProgressEvent[CognitoUserPoolUserToGroupAttachmentProperties]:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        state = {**previous, **desired}
        for key in _IDENTITY_PROPERTIES:
            if desired.get(key) != previous.get(key):
                return failed(f"{key} is create-only and requires replacement")
        if invalid := _validate_identity(state):
            return invalid
        try:
            groups, error = _list_groups_for_user(
                request.aws_client_factory.cognito_idp,
                state["UserPoolId"],
                state["Username"],
            )
        except Exception as exception:
            if is_not_found(exception):
                return not_found(self.TYPE, _attachment_id(state))
            raise
        if error is not None:
            return failed(error)
        if not any(group.get("GroupName") == state["GroupName"] for group in groups):
            return not_found(self.TYPE, _attachment_id(state))
        return _success(request, state)

    def delete(
        self, request: ResourceRequest[CognitoUserPoolUserToGroupAttachmentProperties]
    ) -> ProgressEvent[CognitoUserPoolUserToGroupAttachmentProperties]:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_identity(state):
            if "Id" not in state:
                return ProgressEvent(
                    status=OperationStatus.SUCCESS,
                    resource_model=state,
                    custom_context=request.custom_context,
                )
            return invalid
        try:
            request.aws_client_factory.cognito_idp.admin_remove_user_from_group(
                GroupName=state["GroupName"],
                Username=state["Username"],
                UserPoolId=state["UserPoolId"],
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
        self, request: ResourceRequest[CognitoUserPoolUserToGroupAttachmentProperties]
    ) -> ProgressEvent[CognitoUserPoolUserToGroupAttachmentProperties]:
        filters = copy.deepcopy(request.desired_state)
        if unsupported := unsupported_properties(filters, {"GroupName", "Username", "UserPoolId"}):
            return failed(f"Unsupported list filters for {self.TYPE}: {unsupported}")
        pool_id = filters.get("UserPoolId")
        if not isinstance(pool_id, str) or not pool_id:
            return failed(f"UserPoolId is required to list {self.TYPE}")
        username = filters.get("Username")
        group_name = filters.get("GroupName")
        for key, value in (("Username", username), ("GroupName", group_name)):
            if value is not None and (not isinstance(value, str) or not value):
                return failed(f"{key} must be a non-empty string")

        try:
            models, error = _list_attachments(
                request.aws_client_factory.cognito_idp,
                pool_id,
                username=username,
                group_name=group_name,
            )
        except Exception as exception:
            if is_not_found(exception):
                return ProgressEvent(
                    status=OperationStatus.SUCCESS,
                    resource_models=[],
                    custom_context=request.custom_context,
                )
            raise
        if error is not None:
            return failed(error)
        models.sort(key=lambda model: (model["Username"], model["GroupName"]))
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=models,
            custom_context=request.custom_context,
        )


def _validate_identity(model: dict, *, allow_id: bool = True) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported properties for Cognito user-group attachment: {unsupported}")
    for key in _IDENTITY_PROPERTIES:
        value = model.get(key)
        maximum = 55 if key == "UserPoolId" else 128
        if not isinstance(value, str) or not 1 <= len(value) <= maximum:
            return failed(f"{key} is required for AWS::Cognito::UserPoolUserToGroupAttachment")
    if "Id" in model:
        if not allow_id:
            return failed("Id is read-only")
        if model["Id"] != _attachment_id(model):
            return failed("Id does not match the user-group attachment identity")
    return None


def _attachment_id(model: dict) -> str:
    identity = "\0".join(model[key] for key in _IDENTITY_PROPERTIES).encode()
    digest = hashlib.sha256(identity).hexdigest()[:16]
    return f"UserToGroupAttachment-{digest}"


def _model(pool_id: str, username: str, group_name: str):
    model = CognitoUserPoolUserToGroupAttachmentProperties(
        GroupName=group_name,
        Username=username,
        UserPoolId=pool_id,
    )
    model["Id"] = _attachment_id(model)
    return model


def _success(request, model: dict) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=_model(model["UserPoolId"], model["Username"], model["GroupName"]),
        custom_context=request.custom_context,
    )


def _list_groups_for_user(client, pool_id: str, username: str):
    groups: list[dict] = []
    token = None
    seen_tokens: set[str] = set()
    for _ in range(_MAX_LIST_CALLS):
        params = {"Limit": 60, "Username": username, "UserPoolId": pool_id}
        if token is not None:
            params["NextToken"] = token
        response = client.admin_list_groups_for_user(**params)
        groups.extend(response.get("Groups", []))
        token = response.get("NextToken")
        if token is None:
            return groups, None
        if not isinstance(token, str) or not token or token in seen_tokens:
            return [], "The service returned an invalid membership continuation token"
        seen_tokens.add(token)
    return [], "The membership listing exceeded the call limit"


def _list_attachments(client, pool_id: str, *, username: str | None, group_name: str | None):
    calls = 0
    models: list[CognitoUserPoolUserToGroupAttachmentProperties] = []

    def add(candidate_username: str, candidate_group: str):
        if username is not None and candidate_username != username:
            return None
        if group_name is not None and candidate_group != group_name:
            return None
        if len(models) >= _MAX_LIST_RESOURCES:
            return "The membership listing exceeded the resource limit"
        models.append(_model(pool_id, candidate_username, candidate_group))
        return None

    if username is not None:
        groups, error = _list_groups_for_user(client, pool_id, username)
        if error is not None:
            return [], error
        for group in groups:
            if error := add(username, group["GroupName"]):
                return [], error
        return models, None

    if group_name is not None:
        token = None
        seen_tokens: set[str] = set()
        while calls < _MAX_LIST_CALLS:
            calls += 1
            params = {"GroupName": group_name, "Limit": 60, "UserPoolId": pool_id}
            if token is not None:
                params["NextToken"] = token
            response = client.list_users_in_group(**params)
            for user in response.get("Users", []):
                if error := add(user["Username"], group_name):
                    return [], error
            token = response.get("NextToken")
            if token is None:
                return models, None
            if not isinstance(token, str) or not token or token in seen_tokens:
                return [], "The service returned an invalid membership continuation token"
            seen_tokens.add(token)
        return [], "The membership listing exceeded the call limit"

    user_token = None
    seen_user_tokens: set[str] = set()
    while calls < _MAX_LIST_CALLS:
        calls += 1
        params = {"Limit": 60, "UserPoolId": pool_id}
        if user_token is not None:
            params["PaginationToken"] = user_token
        response = client.list_users(**params)
        for user in response.get("Users", []):
            group_token = None
            seen_group_tokens: set[str] = set()
            while calls < _MAX_LIST_CALLS:
                calls += 1
                group_params = {
                    "Limit": 60,
                    "Username": user["Username"],
                    "UserPoolId": pool_id,
                }
                if group_token is not None:
                    group_params["NextToken"] = group_token
                group_response = client.admin_list_groups_for_user(**group_params)
                for group in group_response.get("Groups", []):
                    if error := add(user["Username"], group["GroupName"]):
                        return [], error
                group_token = group_response.get("NextToken")
                if group_token is None:
                    break
                if (
                    not isinstance(group_token, str)
                    or not group_token
                    or group_token in seen_group_tokens
                ):
                    return [], "The service returned an invalid membership continuation token"
                seen_group_tokens.add(group_token)
            else:
                return [], "The membership listing exceeded the call limit"
        user_token = response.get("PaginationToken")
        if user_token is None:
            return models, None
        if not isinstance(user_token, str) or not user_token or user_token in seen_user_tokens:
            return [], "The service returned an invalid user continuation token"
        seen_user_tokens.add(user_token)
    return [], "The membership listing exceeded the call limit"
