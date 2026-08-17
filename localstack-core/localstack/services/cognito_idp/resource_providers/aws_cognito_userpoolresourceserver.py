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


class ResourceServerScope(TypedDict):
    ScopeDescription: str
    ScopeName: str


class CognitoUserPoolResourceServerProperties(TypedDict):
    Identifier: str
    Name: str
    Scopes: list[ResourceServerScope]
    UserPoolId: str


_PROPERTIES = {"Identifier", "Name", "Scopes", "UserPoolId"}
_MAX_LIST_PAGES = 1_000


class CognitoUserPoolResourceServerProvider(
    ResourceProvider[CognitoUserPoolResourceServerProperties]
):
    TYPE = "AWS::Cognito::UserPoolResourceServer"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(
        self, request: ResourceRequest[CognitoUserPoolResourceServerProperties]
    ) -> ProgressEvent[CognitoUserPoolResourceServerProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model):
            return invalid
        response = request.aws_client_factory.cognito_idp.create_resource_server(**model)
        return _success(request, response["ResourceServer"])

    def read(
        self, request: ResourceRequest[CognitoUserPoolResourceServerProperties]
    ) -> ProgressEvent[CognitoUserPoolResourceServerProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        try:
            response = request.aws_client_factory.cognito_idp.describe_resource_server(
                Identifier=model["Identifier"], UserPoolId=model["UserPoolId"]
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, model["Identifier"])
            raise
        return _success(request, response["ResourceServer"])

    def update(
        self, request: ResourceRequest[CognitoUserPoolResourceServerProperties]
    ) -> ProgressEvent[CognitoUserPoolResourceServerProperties]:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        if invalid := _validate_model(desired):
            return invalid
        for key in ("Identifier", "UserPoolId"):
            if desired.get(key) != previous.get(key):
                return failed(f"{key} is create-only and requires replacement")
        try:
            response = request.aws_client_factory.cognito_idp.update_resource_server(
                Identifier=desired["Identifier"],
                Name=desired["Name"],
                Scopes=desired.get("Scopes", []),
                UserPoolId=desired["UserPoolId"],
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, desired["Identifier"])
            raise
        return _success(request, response["ResourceServer"])

    def delete(
        self, request: ResourceRequest[CognitoUserPoolResourceServerProperties]
    ) -> ProgressEvent[CognitoUserPoolResourceServerProperties]:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_identity(state):
            return invalid
        try:
            request.aws_client_factory.cognito_idp.delete_resource_server(
                Identifier=state["Identifier"], UserPoolId=state["UserPoolId"]
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
        self, request: ResourceRequest[CognitoUserPoolResourceServerProperties]
    ) -> ProgressEvent[CognitoUserPoolResourceServerProperties]:
        filters = copy.deepcopy(request.desired_state)
        if unsupported := unsupported_properties(filters, {"UserPoolId"}):
            return failed(f"Unsupported list filters for {self.TYPE}: {unsupported}")
        pool_id = filters.get("UserPoolId")
        if not isinstance(pool_id, str) or not pool_id:
            return failed(f"UserPoolId is required to list {self.TYPE}")
        servers: list[dict] = []
        next_token = None
        seen_tokens: set[str] = set()
        for _ in range(_MAX_LIST_PAGES):
            params = {"MaxResults": 50, "UserPoolId": pool_id}
            if next_token is not None:
                params["NextToken"] = next_token
            response = request.aws_client_factory.cognito_idp.list_resource_servers(**params)
            servers.extend(response.get("ResourceServers", []))
            next_token = response.get("NextToken")
            if next_token is None:
                break
            if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
                return failed("The service returned an invalid resource-server continuation token")
            seen_tokens.add(next_token)
        else:
            return failed("The resource-server listing exceeded the page limit")
        servers.sort(key=lambda server: server["Identifier"])
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=[_resource_server_model(server) for server in servers],
            custom_context=request.custom_context,
        )


def _validate_identity(model: dict) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported properties for Cognito resource server: {unsupported}")
    for key in ("Identifier", "UserPoolId"):
        if not isinstance(model.get(key), str) or not model[key]:
            return failed(f"{key} is required for AWS::Cognito::UserPoolResourceServer")
    return None


def _validate_model(model: dict) -> ProgressEvent | None:
    if invalid := _validate_identity(model):
        return invalid
    name = model.get("Name")
    if not isinstance(name, str) or not name:
        return failed("Name is required for AWS::Cognito::UserPoolResourceServer")
    scopes = model.get("Scopes", [])
    if not isinstance(scopes, list) or len(scopes) > 100:
        return failed("Scopes must be an array with at most 100 entries")
    seen_names: set[str] = set()
    for scope in scopes:
        if not isinstance(scope, dict) or set(scope) != {"ScopeDescription", "ScopeName"}:
            return failed("Each scope requires exactly ScopeName and ScopeDescription")
        scope_name = scope.get("ScopeName")
        description = scope.get("ScopeDescription")
        if (
            not isinstance(scope_name, str)
            or not scope_name
            or not isinstance(description, str)
            or not description
            or scope_name in seen_names
        ):
            return failed(
                "Resource-server scopes must have unique non-empty names and descriptions"
            )
        seen_names.add(scope_name)
    return None


def _resource_server_model(server: dict) -> CognitoUserPoolResourceServerProperties:
    return CognitoUserPoolResourceServerProperties(
        Identifier=server["Identifier"],
        Name=server["Name"],
        Scopes=copy.deepcopy(server.get("Scopes", [])),
        UserPoolId=server["UserPoolId"],
    )


def _success(request, server: dict) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=_resource_server_model(server),
        custom_context=request.custom_context,
    )
