from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, TypedDict

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


class CognitoIdentityPoolProperties(TypedDict):
    AllowClassicFlow: bool | None
    AllowUnauthenticatedIdentities: bool | None
    CognitoIdentityProviders: list[dict[str, Any]] | None
    DeveloperProviderName: str | None
    IdentityPoolId: str | None
    IdentityPoolName: str | None
    IdentityPoolTags: list[dict[str, str]] | None
    Name: str | None
    OpenIdConnectProviderARNs: list[str] | None
    SamlProviderARNs: list[str] | None
    SupportedLoginProviders: dict[str, str] | None


_SUPPORTED_PROPERTIES = {
    "AllowClassicFlow",
    "AllowUnauthenticatedIdentities",
    "CognitoIdentityProviders",
    "DeveloperProviderName",
    "IdentityPoolId",
    "IdentityPoolName",
    "IdentityPoolTags",
    "Name",
    "OpenIdConnectProviderARNs",
    "SamlProviderARNs",
    "SupportedLoginProviders",
}
_READ_ONLY = {"IdentityPoolId", "Name"}
_UNSUPPORTED_PROPERTIES = {"CognitoEvents", "CognitoStreams", "PushSync"}


class CognitoIdentityPoolProvider(ResourceProvider[CognitoIdentityPoolProperties]):
    TYPE = "AWS::Cognito::IdentityPool"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(
        self, request: ResourceRequest[CognitoIdentityPoolProperties]
    ) -> ProgressEvent[CognitoIdentityPoolProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model, allow_read_only=False, require_configuration=True):
            return invalid
        pool_name = model.get("IdentityPoolName")
        if pool_name is None:
            pool_name = util.generate_default_name(request.stack_name, request.logical_resource_id)
        params = _pool_configuration(model, pool_name=pool_name)
        response = request.aws_client_factory.cognito_identity.create_identity_pool(**params)
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_pool_model(response),
            custom_context=request.custom_context,
        )

    def read(
        self, request: ResourceRequest[CognitoIdentityPoolProperties]
    ) -> ProgressEvent[CognitoIdentityPoolProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model):
            return invalid
        pool_id = _pool_id(model)
        if isinstance(pool_id, ProgressEvent):
            return pool_id
        try:
            response = request.aws_client_factory.cognito_identity.describe_identity_pool(
                IdentityPoolId=pool_id
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, pool_id)
            raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_pool_model(response),
            custom_context=request.custom_context,
        )

    def update(
        self, request: ResourceRequest[CognitoIdentityPoolProperties]
    ) -> ProgressEvent[CognitoIdentityPoolProperties]:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        if invalid := _validate_model(desired, require_configuration=True):
            return invalid
        pool_id = previous.get("IdentityPoolId") or desired.get("IdentityPoolId")
        if not isinstance(pool_id, str) or not pool_id:
            return failed("IdentityPoolId is required to update AWS::Cognito::IdentityPool")
        if desired.get("IdentityPoolId", pool_id) != pool_id:
            return failed("IdentityPoolId is immutable for AWS::Cognito::IdentityPool")
        previous_developer = previous.get("DeveloperProviderName")
        desired_developer = desired.get("DeveloperProviderName", previous_developer)
        if previous_developer is not None and desired_developer != previous_developer:
            return failed("DeveloperProviderName cannot be changed after creation")
        pool_name = desired.get("IdentityPoolName", previous.get("IdentityPoolName"))
        if not isinstance(pool_name, str) or not pool_name:
            return failed("IdentityPoolName is required to update AWS::Cognito::IdentityPool")
        params = _pool_configuration(desired, pool_name=pool_name)
        params["IdentityPoolId"] = pool_id
        if desired_developer is not None:
            params["DeveloperProviderName"] = desired_developer
        try:
            response = request.aws_client_factory.cognito_identity.update_identity_pool(**params)
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, pool_id)
            raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_pool_model(response),
            custom_context=request.custom_context,
        )

    def delete(
        self, request: ResourceRequest[CognitoIdentityPoolProperties]
    ) -> ProgressEvent[CognitoIdentityPoolProperties]:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_model(state):
            return invalid
        pool_id = _pool_id(state)
        if isinstance(pool_id, ProgressEvent):
            return pool_id
        try:
            request.aws_client_factory.cognito_identity.delete_identity_pool(IdentityPoolId=pool_id)
        except Exception as error:
            if not is_not_found(error):
                raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=state,
            custom_context=request.custom_context,
        )

    def list(
        self, request: ResourceRequest[CognitoIdentityPoolProperties]
    ) -> ProgressEvent[CognitoIdentityPoolProperties]:
        if unsupported := unsupported_properties(request.desired_state, set()):
            return failed(f"Unsupported list filters for {self.TYPE}: {unsupported}")
        resources: list[dict[str, Any]] = []
        next_token = None
        seen_tokens: set[str] = set()
        while True:
            params: dict[str, Any] = {"MaxResults": 60}
            if next_token is not None:
                params["NextToken"] = next_token
            response = request.aws_client_factory.cognito_identity.list_identity_pools(**params)
            page = response.get("IdentityPools", [])
            if not isinstance(page, list) or len(page) > 60:
                return failed("The service returned an invalid identity-pool page")
            resources.extend(page)
            next_token = response.get("NextToken")
            if next_token is None:
                break
            if (
                not isinstance(next_token, str)
                or not next_token
                or next_token in seen_tokens
                or len(seen_tokens) >= 1_000
            ):
                return failed("The service returned an invalid identity-pool continuation token")
            seen_tokens.add(next_token)
        try:
            resources.sort(key=lambda item: item["IdentityPoolId"])
            models = [
                CognitoIdentityPoolProperties(
                    IdentityPoolId=item["IdentityPoolId"],
                    IdentityPoolName=item.get("IdentityPoolName"),
                    Name=item.get("IdentityPoolName"),
                )
                for item in resources
            ]
        except (KeyError, TypeError):
            return failed("The service returned an invalid identity-pool list")
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=models,
            custom_context=request.custom_context,
        )


def _validate_model(
    model: dict[str, Any],
    *,
    allow_read_only: bool = True,
    require_configuration: bool = False,
) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _SUPPORTED_PROPERTIES):
        if set(unsupported).issubset(_UNSUPPORTED_PROPERTIES):
            return failed(f"Unsupported properties for AWS::Cognito::IdentityPool: {unsupported}")
        return failed(f"Unknown properties for AWS::Cognito::IdentityPool: {unsupported}")
    if not allow_read_only and any(name in model for name in _READ_ONLY):
        return failed("Read-only properties cannot be supplied for AWS::Cognito::IdentityPool")
    if require_configuration and not isinstance(model.get("AllowUnauthenticatedIdentities"), bool):
        return failed("AllowUnauthenticatedIdentities is required for AWS::Cognito::IdentityPool")
    if "IdentityPoolTags" in model:
        tags = _tags(model.get("IdentityPoolTags"))
        if isinstance(tags, ProgressEvent):
            return tags
    return None


def _pool_id(model: dict[str, Any]) -> str | ProgressEvent:
    pool_id = model.get("IdentityPoolId")
    if not isinstance(pool_id, str) or not pool_id:
        return failed("IdentityPoolId is required for AWS::Cognito::IdentityPool")
    return pool_id


def _tags(value: Any) -> dict[str, str] | ProgressEvent:
    if not isinstance(value, list) or len(value) > 50:
        return failed("IdentityPoolTags must contain at most 50 tags")
    result: dict[str, str] = {}
    for tag in value:
        if (
            not isinstance(tag, dict)
            or set(tag) != {"Key", "Value"}
            or not isinstance(tag["Key"], str)
            or not tag["Key"]
            or not isinstance(tag["Value"], str)
            or tag["Key"] in result
        ):
            return failed("IdentityPoolTags contains an invalid or duplicate tag")
        result[tag["Key"]] = tag["Value"]
    return result


def _pool_configuration(model: dict[str, Any], *, pool_name: str) -> dict[str, Any]:
    tags = _tags(model.get("IdentityPoolTags", []))
    if isinstance(tags, ProgressEvent):
        raise ValueError(tags.message)
    params: dict[str, Any] = {
        "AllowClassicFlow": model.get("AllowClassicFlow", False),
        "AllowUnauthenticatedIdentities": model["AllowUnauthenticatedIdentities"],
        "CognitoIdentityProviders": copy.deepcopy(model.get("CognitoIdentityProviders", [])),
        "IdentityPoolName": pool_name,
        "IdentityPoolTags": tags,
        "OpenIdConnectProviderARNs": list(model.get("OpenIdConnectProviderARNs", [])),
        "SamlProviderARNs": list(model.get("SamlProviderARNs", [])),
        "SupportedLoginProviders": copy.deepcopy(model.get("SupportedLoginProviders", {})),
    }
    if developer_provider := model.get("DeveloperProviderName"):
        params["DeveloperProviderName"] = developer_provider
    return params


def _pool_model(response: dict[str, Any]) -> CognitoIdentityPoolProperties:
    model = CognitoIdentityPoolProperties(
        AllowClassicFlow=response.get("AllowClassicFlow", False),
        AllowUnauthenticatedIdentities=response["AllowUnauthenticatedIdentities"],
        IdentityPoolId=response["IdentityPoolId"],
        IdentityPoolName=response["IdentityPoolName"],
        Name=response["IdentityPoolName"],
    )
    for name in (
        "CognitoIdentityProviders",
        "DeveloperProviderName",
        "OpenIdConnectProviderARNs",
        "SamlProviderARNs",
        "SupportedLoginProviders",
    ):
        if name in response:
            model[name] = copy.deepcopy(response[name])
    if tags := response.get("IdentityPoolTags"):
        model["IdentityPoolTags"] = [
            {"Key": key, "Value": value} for key, value in sorted(tags.items())
        ]
    return model
