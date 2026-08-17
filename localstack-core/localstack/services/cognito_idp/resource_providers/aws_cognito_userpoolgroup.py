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
from localstack.services.cognito_idp.resource_providers.common import (
    failed,
    is_not_found,
    not_found,
    unsupported_properties,
)


class CognitoUserPoolGroupProperties(TypedDict):
    Description: str | None
    GroupName: str | None
    Precedence: int | None
    RoleArn: str | None
    UserPoolId: str | None


_PROPERTIES = {"Description", "GroupName", "Precedence", "RoleArn", "UserPoolId"}


class CognitoUserPoolGroupProvider(ResourceProvider[CognitoUserPoolGroupProperties]):
    TYPE = "AWS::Cognito::UserPoolGroup"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(
        self, request: ResourceRequest[CognitoUserPoolGroupProperties]
    ) -> ProgressEvent[CognitoUserPoolGroupProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model, require_name=False):
            return invalid
        name = model.get("GroupName") or util.generate_default_name(
            request.stack_name, request.logical_resource_id
        )
        params = {"GroupName": name, "UserPoolId": model["UserPoolId"]}
        for key in ("Description", "Precedence", "RoleArn"):
            if key in model:
                params[key] = model[key]
        response = request.aws_client_factory.cognito_idp.create_group(**params)
        return _success(request, response["Group"], model["UserPoolId"])

    def read(
        self, request: ResourceRequest[CognitoUserPoolGroupProperties]
    ) -> ProgressEvent[CognitoUserPoolGroupProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model):
            return invalid
        try:
            response = request.aws_client_factory.cognito_idp.get_group(
                GroupName=model["GroupName"], UserPoolId=model["UserPoolId"]
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, model["GroupName"])
            raise
        return _success(request, response["Group"], model["UserPoolId"])

    def update(
        self, request: ResourceRequest[CognitoUserPoolGroupProperties]
    ) -> ProgressEvent[CognitoUserPoolGroupProperties]:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        state = {**previous, **desired}
        if invalid := _validate_model(state):
            return invalid
        for key in ("GroupName", "UserPoolId"):
            if key in desired and key in previous and desired[key] != previous[key]:
                return failed(f"{key} is create-only and requires replacement")
        params = {"GroupName": state["GroupName"], "UserPoolId": state["UserPoolId"]}
        for key in ("Description", "RoleArn"):
            target = desired.get(key)
            if target != previous.get(key):
                params[key] = target or ""
        target_precedence = desired.get("Precedence")
        if target_precedence != previous.get("Precedence"):
            if target_precedence is None:
                return failed("Removing Precedence is not supported without replacing the group")
            params["Precedence"] = target_precedence
        try:
            if len(params) > 2:
                request.aws_client_factory.cognito_idp.update_group(**params)
            response = request.aws_client_factory.cognito_idp.get_group(
                GroupName=state["GroupName"], UserPoolId=state["UserPoolId"]
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, state["GroupName"])
            raise
        return _success(request, response["Group"], state["UserPoolId"])

    def delete(
        self, request: ResourceRequest[CognitoUserPoolGroupProperties]
    ) -> ProgressEvent[CognitoUserPoolGroupProperties]:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_model(state):
            return invalid
        try:
            request.aws_client_factory.cognito_idp.delete_group(
                GroupName=state["GroupName"], UserPoolId=state["UserPoolId"]
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
        self, request: ResourceRequest[CognitoUserPoolGroupProperties]
    ) -> ProgressEvent[CognitoUserPoolGroupProperties]:
        filters = copy.deepcopy(request.desired_state)
        if unsupported := unsupported_properties(filters, {"UserPoolId"}):
            return failed(f"Unsupported list filters for {self.TYPE}: {unsupported}")
        pool_id = filters.get("UserPoolId")
        if not isinstance(pool_id, str) or not pool_id:
            return failed("UserPoolId is required to list AWS::Cognito::UserPoolGroup")
        groups = []
        next_token = None
        seen_tokens = set()
        while True:
            params = {"Limit": 60, "UserPoolId": pool_id}
            if next_token is not None:
                params["NextToken"] = next_token
            response = request.aws_client_factory.cognito_idp.list_groups(**params)
            groups.extend(response.get("Groups", []))
            next_token = response.get("NextToken")
            if next_token is None:
                break
            if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
                return failed("The service returned an invalid group continuation token")
            seen_tokens.add(next_token)
        groups.sort(key=lambda group: group["GroupName"])
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=[_group_model(group, pool_id) for group in groups],
            custom_context=request.custom_context,
        )


def _validate_model(model: dict, *, require_name: bool = True) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported properties for Cognito user-pool group: {unsupported}")
    pool_id = model.get("UserPoolId")
    if not isinstance(pool_id, str) or not pool_id:
        return failed("UserPoolId is required for AWS::Cognito::UserPoolGroup")
    name = model.get("GroupName")
    if require_name and (not isinstance(name, str) or not name):
        return failed("GroupName is required for AWS::Cognito::UserPoolGroup")
    precedence = model.get("Precedence")
    if precedence is not None and (
        not isinstance(precedence, int)
        or isinstance(precedence, bool)
        or not 0 <= precedence <= 2**31 - 1
    ):
        return failed("Precedence is invalid for AWS::Cognito::UserPoolGroup")
    return None


def _group_model(group: dict, pool_id: str) -> CognitoUserPoolGroupProperties:
    model = CognitoUserPoolGroupProperties(GroupName=group["GroupName"], UserPoolId=pool_id)
    for key in ("Description", "Precedence", "RoleArn"):
        if key in group:
            model[key] = group[key]
    return model


def _success(request, group: dict, pool_id: str) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=_group_model(group, pool_id),
        custom_context=request.custom_context,
    )
