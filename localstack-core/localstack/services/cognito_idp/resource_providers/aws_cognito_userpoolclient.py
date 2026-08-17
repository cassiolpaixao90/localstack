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
from localstack.services.cognito_idp.client_configuration import (
    AnalyticsConfiguration,
    ClientConfigurationError,
    ClientScope,
    analytics_resolvers,
    normalize_explicit_auth_flows,
    parse_analytics_configuration,
    revalidate_analytics_configuration,
    validate_propagate_additional_context,
)
from localstack.services.cognito_idp.resource_providers.common import (
    failed,
    is_not_found,
    not_found,
    unsupported_properties,
)
from localstack.utils.aws.arns import get_partition


class CognitoUserPoolClientProperties(TypedDict):
    AccessTokenValidity: int | None
    AllowedOAuthFlows: list[str] | None
    AllowedOAuthFlowsUserPoolClient: bool | None
    AllowedOAuthScopes: list[str] | None
    AnalyticsConfiguration: dict[str, object] | None
    AuthSessionValidity: int | None
    CallbackURLs: list[str] | None
    ClientId: str | None
    ClientName: str | None
    ClientSecret: str | None
    DefaultRedirectURI: str | None
    EnableTokenRevocation: bool | None
    EnablePropagateAdditionalUserContextData: bool | None
    ExplicitAuthFlows: list[str] | None
    GenerateSecret: bool | None
    IdTokenValidity: int | None
    LogoutURLs: list[str] | None
    Name: str | None
    PreventUserExistenceErrors: str | None
    ReadAttributes: list[str] | None
    RefreshTokenValidity: int | None
    RefreshTokenRotation: dict[str, object] | None
    SupportedIdentityProviders: list[str] | None
    TokenValidityUnits: dict[str, str] | None
    UserPoolId: str | None
    WriteAttributes: list[str] | None


_PROPERTIES = {
    "AccessTokenValidity",
    "AllowedOAuthFlows",
    "AllowedOAuthFlowsUserPoolClient",
    "AllowedOAuthScopes",
    "AnalyticsConfiguration",
    "AuthSessionValidity",
    "CallbackURLs",
    "ClientId",
    "ClientName",
    "ClientSecret",
    "DefaultRedirectURI",
    "EnableTokenRevocation",
    "EnablePropagateAdditionalUserContextData",
    "ExplicitAuthFlows",
    "GenerateSecret",
    "IdTokenValidity",
    "LogoutURLs",
    "Name",
    "PreventUserExistenceErrors",
    "ReadAttributes",
    "RefreshTokenValidity",
    "RefreshTokenRotation",
    "SupportedIdentityProviders",
    "TokenValidityUnits",
    "UserPoolId",
    "WriteAttributes",
}
_CREATE_ONLY = {"GenerateSecret", "UserPoolId"}
_DEFAULT_AUTH_FLOWS = list(normalize_explicit_auth_flows(None))
_MAX_LIST_PAGES = 1_000
_MUTABLE_DEFAULTS = {
    "AccessTokenValidity": 1,
    "AllowedOAuthFlows": [],
    "AllowedOAuthFlowsUserPoolClient": False,
    "AllowedOAuthScopes": [],
    "CallbackURLs": [],
    "AuthSessionValidity": 3,
    "AnalyticsConfiguration": None,
    "EnablePropagateAdditionalUserContextData": False,
    "EnableTokenRevocation": True,
    "ExplicitAuthFlows": _DEFAULT_AUTH_FLOWS,
    "IdTokenValidity": 1,
    "LogoutURLs": [],
    "PreventUserExistenceErrors": "LEGACY",
    "RefreshTokenValidity": 30,
    "RefreshTokenRotation": {"Feature": "DISABLED", "RetryGracePeriodSeconds": 0},
    "SupportedIdentityProviders": ["COGNITO"],
    "TokenValidityUnits": {
        "AccessToken": "hours",
        "IdToken": "hours",
        "RefreshToken": "days",
    },
}
_MUTABLE_API_FIELDS = _PROPERTIES - {
    "ClientId",
    "ClientSecret",
    "GenerateSecret",
    "Name",
    "UserPoolId",
}


class CognitoUserPoolClientProvider(ResourceProvider[CognitoUserPoolClientProperties]):
    TYPE = "AWS::Cognito::UserPoolClient"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(
        self, request: ResourceRequest[CognitoUserPoolClientProperties]
    ) -> ProgressEvent[CognitoUserPoolClientProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model, allow_read_only=False):
            return invalid
        if invalid := _prepare_client_configuration(
            request,
            model,
            has_client_secret=model.get("GenerateSecret") is True,
        ):
            return invalid
        client_name = model.get("ClientName")
        if client_name is None:
            client_name = util.generate_default_name(
                request.stack_name, request.logical_resource_id
            )
        params = {"ClientName": client_name, "UserPoolId": model["UserPoolId"]}
        for name in sorted((_MUTABLE_API_FIELDS | {"GenerateSecret"}) - {"ClientName"}):
            if name in model:
                params[name] = model[name]
        response = request.aws_client_factory.cognito_idp.create_user_pool_client(**params)
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_client_model(response["UserPoolClient"], client_name=client_name),
            custom_context=request.custom_context,
        )

    def read(
        self, request: ResourceRequest[CognitoUserPoolClientProperties]
    ) -> ProgressEvent[CognitoUserPoolClientProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model):
            return invalid
        identity = _identity(model)
        if isinstance(identity, ProgressEvent):
            return identity
        pool_id, client_id = identity
        try:
            response = request.aws_client_factory.cognito_idp.describe_user_pool_client(
                ClientId=client_id, UserPoolId=pool_id
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, client_id)
            raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_client_model(response["UserPoolClient"]),
            custom_context=request.custom_context,
        )

    def update(
        self, request: ResourceRequest[CognitoUserPoolClientProperties]
    ) -> ProgressEvent[CognitoUserPoolClientProperties]:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        if invalid := _validate_model(desired):
            return invalid
        identity = _identity({**desired, **previous})
        if isinstance(identity, ProgressEvent):
            return identity
        pool_id, client_id = identity
        if desired.get("ClientId", client_id) != client_id:
            return failed("ClientId is immutable for AWS::Cognito::UserPoolClient")
        for name in _CREATE_ONLY:
            default = False if name == "GenerateSecret" else None
            if desired.get(name, default) != previous.get(name, default):
                return failed(f"{name} is create-only and requires replacement")
        if invalid := _prepare_client_configuration(
            request,
            desired,
            has_client_secret=(
                previous.get("GenerateSecret") is True
                or isinstance(previous.get("ClientSecret"), str)
            ),
        ):
            return invalid
        if "ExplicitAuthFlows" in previous:
            try:
                previous["ExplicitAuthFlows"] = list(
                    normalize_explicit_auth_flows(previous["ExplicitAuthFlows"])
                )
            except ClientConfigurationError as error:
                return failed(str(error))

        client_name = desired.get("ClientName", previous.get("ClientName"))
        if not isinstance(client_name, str) or not client_name:
            return failed("ClientName is required to update AWS::Cognito::UserPoolClient")
        desired_mutable = {
            name: desired[name]
            for name in sorted(_MUTABLE_API_FIELDS - {"ClientName"})
            if name in desired
        }
        normalized_desired = {
            name: copy.deepcopy(desired.get(name, default))
            for name, default in _MUTABLE_DEFAULTS.items()
        }
        normalized_previous = {
            name: copy.deepcopy(previous.get(name, default))
            for name, default in _MUTABLE_DEFAULTS.items()
        }
        mutable = dict(desired_mutable)
        for name, value in normalized_desired.items():
            if value != normalized_previous[name]:
                if not (name == "AnalyticsConfiguration" and value is None):
                    mutable[name] = value
        if (
            client_name == previous.get("ClientName")
            and normalized_desired == normalized_previous
            and all(
                desired.get(name) == previous.get(name)
                for name in _MUTABLE_API_FIELDS - {"ClientName"} - set(_MUTABLE_DEFAULTS)
            )
        ):
            read_request = copy.copy(request)
            read_request.desired_state = {"ClientId": client_id, "UserPoolId": pool_id}
            return self.read(read_request)

        try:
            response = request.aws_client_factory.cognito_idp.update_user_pool_client(
                ClientId=client_id,
                ClientName=client_name,
                UserPoolId=pool_id,
                **mutable,
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, client_id)
            raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_client_model(response["UserPoolClient"]),
            custom_context=request.custom_context,
        )

    def delete(
        self, request: ResourceRequest[CognitoUserPoolClientProperties]
    ) -> ProgressEvent[CognitoUserPoolClientProperties]:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_model(state):
            return invalid
        identity = _identity(state)
        if isinstance(identity, ProgressEvent):
            return identity
        pool_id, client_id = identity
        try:
            request.aws_client_factory.cognito_idp.delete_user_pool_client(
                ClientId=client_id, UserPoolId=pool_id
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
        self, request: ResourceRequest[CognitoUserPoolClientProperties]
    ) -> ProgressEvent[CognitoUserPoolClientProperties]:
        filters = copy.deepcopy(request.desired_state)
        if unsupported := unsupported_properties(filters, {"UserPoolId"}):
            return failed(f"Unsupported list filters for {self.TYPE}: {unsupported}")
        pool_id = filters.get("UserPoolId")
        if not isinstance(pool_id, str) or not pool_id:
            return failed("UserPoolId is required to list AWS::Cognito::UserPoolClient")
        resources = []
        next_token = None
        seen_tokens = set()
        for _ in range(_MAX_LIST_PAGES):
            params = {"MaxResults": 60, "UserPoolId": pool_id}
            if next_token is not None:
                params["NextToken"] = next_token
            try:
                response = request.aws_client_factory.cognito_idp.list_user_pool_clients(**params)
            except Exception as error:
                if is_not_found(error):
                    return not_found("AWS::Cognito::UserPool", pool_id)
                raise
            page = response.get("UserPoolClients", [])
            resources.extend(page)
            next_token = response.get("NextToken")
            if next_token is None:
                break
            if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
                return failed("The service returned an invalid client continuation token")
            seen_tokens.add(next_token)
        else:
            return failed("The service exceeded the user-pool client pagination limit")
        resources.sort(key=lambda item: item["ClientId"])
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=[
                CognitoUserPoolClientProperties(
                    ClientId=client["ClientId"],
                    ClientName=client.get("ClientName"),
                    UserPoolId=pool_id,
                )
                for client in resources
            ],
            custom_context=request.custom_context,
        )


def _validate_model(model: dict, *, allow_read_only: bool = True) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported properties for AWS::Cognito::UserPoolClient: {unsupported}")
    if not allow_read_only and any(name in model for name in ("ClientId", "ClientSecret", "Name")):
        return failed("Read-only properties cannot be supplied for AWS::Cognito::UserPoolClient")
    pool_id = model.get("UserPoolId")
    if not isinstance(pool_id, str) or not pool_id:
        return failed("UserPoolId is required for AWS::Cognito::UserPoolClient")
    return None


def _identity(model: dict) -> tuple[str, str] | ProgressEvent:
    pool_id = model.get("UserPoolId")
    client_id = model.get("ClientId")
    if not isinstance(pool_id, str) or not pool_id:
        return failed("UserPoolId is required for AWS::Cognito::UserPoolClient")
    if not isinstance(client_id, str) or not client_id:
        return failed("ClientId is required for AWS::Cognito::UserPoolClient")
    return pool_id, client_id


def _client_model(
    client: dict, *, client_name: str | None = None
) -> CognitoUserPoolClientProperties:
    model = CognitoUserPoolClientProperties(
        ClientId=client["ClientId"],
        ClientName=client.get("ClientName", client_name),
        ExplicitAuthFlows=list(normalize_explicit_auth_flows(client.get("ExplicitAuthFlows"))),
        GenerateSecret="ClientSecret" in client,
        Name=client.get("ClientName", client_name),
        UserPoolId=client["UserPoolId"],
    )
    for name in sorted(_MUTABLE_API_FIELDS - {"ClientName", "ExplicitAuthFlows"}):
        if name not in client:
            continue
        value = client[name]
        model[name] = copy.deepcopy(value)
    if secret := client.get("ClientSecret"):
        model["ClientSecret"] = secret
    return model


def _prepare_client_configuration(
    request: ResourceRequest[CognitoUserPoolClientProperties],
    model: dict,
    *,
    has_client_secret: bool,
) -> ProgressEvent | None:
    analytics: AnalyticsConfiguration | None = None
    try:
        if "ExplicitAuthFlows" in model:
            model["ExplicitAuthFlows"] = list(
                normalize_explicit_auth_flows(model["ExplicitAuthFlows"])
            )
        if "EnablePropagateAdditionalUserContextData" in model:
            model["EnablePropagateAdditionalUserContextData"] = (
                validate_propagate_additional_context(
                    model["EnablePropagateAdditionalUserContextData"],
                    has_client_secret=has_client_secret,
                )
            )
        if "AnalyticsConfiguration" in model:
            analytics = _analytics_configuration(request, model["AnalyticsConfiguration"])
            model["AnalyticsConfiguration"] = analytics.to_api()
            project_resolver, role_resolver = _analytics_resolvers(request)
            revalidate_analytics_configuration(
                analytics,
                project_resolver=project_resolver,
                role_resolver=role_resolver,
            )
    except ClientConfigurationError as error:
        return failed(str(error))
    return None


def _analytics_configuration(
    request: ResourceRequest[CognitoUserPoolClientProperties], value: object
) -> AnalyticsConfiguration:
    project_resolver, role_resolver = _analytics_resolvers(request)
    return parse_analytics_configuration(
        value,
        scope=ClientScope(
            partition=get_partition(request.region_name),
            region=request.region_name,
            account_id=request.account_id,
        ),
        project_resolver=project_resolver,
        role_resolver=role_resolver,
    )


def _analytics_resolvers(request: ResourceRequest[CognitoUserPoolClientProperties]):
    return analytics_resolvers(request.aws_client_factory)
