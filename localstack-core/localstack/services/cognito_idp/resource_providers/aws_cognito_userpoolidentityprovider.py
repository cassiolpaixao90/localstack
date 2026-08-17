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


class UserPoolIdentityProviderProperties(TypedDict):
    AttributeMapping: dict[str, str]
    IdpIdentifiers: list[str]
    ProviderDetails: dict[str, str]
    ProviderName: str
    ProviderType: str
    UserPoolId: str


_PROPERTIES = {
    "AttributeMapping",
    "IdpIdentifiers",
    "ProviderDetails",
    "ProviderName",
    "ProviderType",
    "UserPoolId",
}
_MAX_LIST_PAGES = 1_000


class CognitoUserPoolIdentityProviderProvider(ResourceProvider[UserPoolIdentityProviderProperties]):
    TYPE = "AWS::Cognito::UserPoolIdentityProvider"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model):
            return invalid
        response = request.aws_client_factory.cognito_idp.create_identity_provider(**model)
        return _success(request, response["IdentityProvider"])

    def read(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_identity(model):
            return invalid
        try:
            response = request.aws_client_factory.cognito_idp.describe_identity_provider(
                ProviderName=model["ProviderName"], UserPoolId=model["UserPoolId"]
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, model["ProviderName"])
            raise
        return _success(request, response["IdentityProvider"])

    def update(self, request: ResourceRequest) -> ProgressEvent:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        if invalid := _validate_model(desired):
            return invalid
        for field in ("ProviderName", "ProviderType", "UserPoolId"):
            if desired.get(field) != previous.get(field):
                return failed(f"{field} is create-only and requires replacement")
        try:
            response = request.aws_client_factory.cognito_idp.update_identity_provider(
                AttributeMapping=desired.get("AttributeMapping", {}),
                IdpIdentifiers=desired.get("IdpIdentifiers", []),
                ProviderDetails=desired["ProviderDetails"],
                ProviderName=desired["ProviderName"],
                UserPoolId=desired["UserPoolId"],
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, desired["ProviderName"])
            raise
        return _success(request, response["IdentityProvider"])

    def delete(self, request: ResourceRequest) -> ProgressEvent:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_identity(state):
            return invalid
        try:
            request.aws_client_factory.cognito_idp.delete_identity_provider(
                ProviderName=state["ProviderName"], UserPoolId=state["UserPoolId"]
            )
        except Exception as error:
            if not is_not_found(error):
                raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=state,
            custom_context=request.custom_context,
        )

    def list(self, request: ResourceRequest) -> ProgressEvent:
        filters = copy.deepcopy(request.desired_state)
        if unsupported := unsupported_properties(filters, {"UserPoolId"}):
            return failed(f"Unsupported list filters for {self.TYPE}: {unsupported}")
        pool_id = filters.get("UserPoolId")
        if not isinstance(pool_id, str) or not pool_id:
            return failed(f"UserPoolId is required to list {self.TYPE}")
        providers = []
        next_token = None
        seen_tokens = set()
        for _ in range(_MAX_LIST_PAGES):
            parameters = {"MaxResults": 60, "UserPoolId": pool_id}
            if next_token is not None:
                parameters["NextToken"] = next_token
            response = request.aws_client_factory.cognito_idp.list_identity_providers(**parameters)
            providers.extend(response.get("Providers", []))
            next_token = response.get("NextToken")
            if next_token is None:
                break
            if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
                return failed(
                    "The service returned an invalid identity-provider continuation token"
                )
            seen_tokens.add(next_token)
        else:
            return failed("The identity-provider listing exceeded the page limit")
        models = []
        for summary in sorted(providers, key=lambda item: item["ProviderName"]):
            described = request.aws_client_factory.cognito_idp.describe_identity_provider(
                ProviderName=summary["ProviderName"], UserPoolId=pool_id
            )["IdentityProvider"]
            models.append(_resource_model(described))
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=models,
            custom_context=request.custom_context,
        )


def _validate_identity(model: dict) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported Cognito identity-provider properties: {unsupported}")
    for field in ("ProviderName", "UserPoolId"):
        if not isinstance(model.get(field), str) or not model[field]:
            return failed(f"{field} is required for AWS::Cognito::UserPoolIdentityProvider")
    return None


def _validate_model(model: dict) -> ProgressEvent | None:
    if invalid := _validate_identity(model):
        return invalid
    if model.get("ProviderType") not in {
        "OIDC",
        "SAML",
        "Google",
        "Facebook",
        "LoginWithAmazon",
        "SignInWithApple",
    }:
        return failed("Unsupported Cognito identity-provider type")
    if not isinstance(model.get("ProviderDetails"), dict) or not model["ProviderDetails"]:
        return failed("ProviderDetails is required")
    for field, default in (("AttributeMapping", {}), ("IdpIdentifiers", [])):
        if field not in model:
            model[field] = default
    return None


def _resource_model(provider: dict) -> UserPoolIdentityProviderProperties:
    return UserPoolIdentityProviderProperties(
        AttributeMapping=copy.deepcopy(provider.get("AttributeMapping", {})),
        IdpIdentifiers=list(provider.get("IdpIdentifiers", [])),
        ProviderDetails=copy.deepcopy(provider["ProviderDetails"]),
        ProviderName=provider["ProviderName"],
        ProviderType=provider["ProviderType"],
        UserPoolId=provider["UserPoolId"],
    )


def _success(request, provider: dict) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=_resource_model(provider),
        custom_context=request.custom_context,
    )
