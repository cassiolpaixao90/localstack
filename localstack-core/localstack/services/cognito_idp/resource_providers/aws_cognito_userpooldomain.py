from __future__ import annotations

import copy
import re
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


class CognitoUserPoolDomainProperties(TypedDict):
    CloudFrontDistribution: str | None
    CustomDomainConfig: dict[str, str] | None
    Domain: str | None
    ManagedLoginVersion: int | None
    Routing: dict[str, object] | None
    UserPoolId: str | None


_PROPERTIES = {
    "CloudFrontDistribution",
    "CustomDomainConfig",
    "Domain",
    "ManagedLoginVersion",
    "Routing",
    "UserPoolId",
}
_UNSUPPORTED_RUNTIME_FIELDS = {"CustomDomainConfig", "Routing"}
_CREATE_ONLY = {"Domain", "UserPoolId"}
_DOMAIN_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class CognitoUserPoolDomainProvider(ResourceProvider[CognitoUserPoolDomainProperties]):
    TYPE = "AWS::Cognito::UserPoolDomain"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(
        self, request: ResourceRequest[CognitoUserPoolDomainProperties]
    ) -> ProgressEvent[CognitoUserPoolDomainProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model, require_pool=True):
            return invalid
        if "CloudFrontDistribution" in model:
            return failed(f"Read-only properties cannot be supplied for {self.TYPE}")
        params = {"Domain": model["Domain"], "UserPoolId": model["UserPoolId"]}
        if "ManagedLoginVersion" in model:
            params["ManagedLoginVersion"] = model["ManagedLoginVersion"]
        created = False
        try:
            request.aws_client_factory.cognito_idp.create_user_pool_domain(**params)
            created = True
            description = request.aws_client_factory.cognito_idp.describe_user_pool_domain(
                Domain=model["Domain"]
            )["DomainDescription"]
        except Exception as error:
            if created:
                try:
                    request.aws_client_factory.cognito_idp.delete_user_pool_domain(
                        Domain=model["Domain"], UserPoolId=model["UserPoolId"]
                    )
                except Exception as cleanup_error:
                    error.add_note(
                        "CreateUserPoolDomain rollback failed for "
                        f"{model['Domain']}: {type(cleanup_error).__name__}: {cleanup_error}"
                    )
            if is_not_found(error):
                return not_found(self.TYPE, model["Domain"])
            raise
        return _success(request, description)

    def read(
        self, request: ResourceRequest[CognitoUserPoolDomainProperties]
    ) -> ProgressEvent[CognitoUserPoolDomainProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model):
            return invalid
        try:
            description = request.aws_client_factory.cognito_idp.describe_user_pool_domain(
                Domain=model["Domain"]
            )["DomainDescription"]
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, model["Domain"])
            raise
        return _success(request, description)

    def update(
        self, request: ResourceRequest[CognitoUserPoolDomainProperties]
    ) -> ProgressEvent[CognitoUserPoolDomainProperties]:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        state = {**previous, **desired}
        if invalid := _validate_model(state):
            return invalid
        for name in _CREATE_ONLY:
            if name in desired and name in previous and desired[name] != previous[name]:
                return failed(f"{name} is create-only and requires replacement")
        try:
            description = request.aws_client_factory.cognito_idp.describe_user_pool_domain(
                Domain=state["Domain"]
            )["DomainDescription"]
            pool_id = description.get("UserPoolId")
            if not isinstance(pool_id, str) or not pool_id:
                return failed("The service returned a domain without UserPoolId")
            target_version = desired.get(
                "ManagedLoginVersion", previous.get("ManagedLoginVersion", 1)
            )
            if target_version != description.get("ManagedLoginVersion", 1):
                request.aws_client_factory.cognito_idp.update_user_pool_domain(
                    Domain=state["Domain"],
                    ManagedLoginVersion=target_version,
                    UserPoolId=pool_id,
                )
                description = request.aws_client_factory.cognito_idp.describe_user_pool_domain(
                    Domain=state["Domain"]
                )["DomainDescription"]
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, state["Domain"])
            raise
        return _success(request, description)

    def delete(
        self, request: ResourceRequest[CognitoUserPoolDomainProperties]
    ) -> ProgressEvent[CognitoUserPoolDomainProperties]:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_model(state):
            return invalid
        domain = state["Domain"]
        try:
            pool_id = state.get("UserPoolId")
            if not isinstance(pool_id, str) or not pool_id:
                description = request.aws_client_factory.cognito_idp.describe_user_pool_domain(
                    Domain=domain
                )["DomainDescription"]
                pool_id = description.get("UserPoolId")
            if not isinstance(pool_id, str) or not pool_id:
                return failed("The service returned a domain without UserPoolId")
            request.aws_client_factory.cognito_idp.delete_user_pool_domain(
                Domain=domain, UserPoolId=pool_id
            )
        except Exception as error:
            if not is_not_found(error):
                raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=state,
            custom_context=request.custom_context,
        )


def _validate_model(model: dict, *, require_pool: bool = False) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported properties for Cognito user-pool domain: {unsupported}")
    if unsupported := sorted(set(model) & _UNSUPPORTED_RUNTIME_FIELDS):
        return failed(f"Properties are not implemented for Cognito user-pool domain: {unsupported}")
    domain = model.get("Domain")
    if not isinstance(domain, str) or _DOMAIN_PATTERN.fullmatch(domain) is None:
        return failed("Domain is required for AWS::Cognito::UserPoolDomain")
    pool_id = model.get("UserPoolId")
    if require_pool and (not isinstance(pool_id, str) or not pool_id):
        return failed("UserPoolId is required for AWS::Cognito::UserPoolDomain")
    version = model.get("ManagedLoginVersion")
    if version is not None and (isinstance(version, bool) or version not in {1, 2}):
        return failed("ManagedLoginVersion must be 1 or 2")
    return None


def _success(request, description: dict) -> ProgressEvent[CognitoUserPoolDomainProperties]:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=CognitoUserPoolDomainProperties(
            CloudFrontDistribution=description.get("CloudFrontDistribution"),
            Domain=description["Domain"],
            ManagedLoginVersion=description.get("ManagedLoginVersion", 1),
            UserPoolId=description["UserPoolId"],
        ),
        custom_context=request.custom_context,
    )
