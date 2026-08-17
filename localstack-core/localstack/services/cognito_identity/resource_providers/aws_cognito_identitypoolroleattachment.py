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


class CognitoIdentityPoolRoleAttachmentProperties(TypedDict):
    Id: str | None
    IdentityPoolId: str | None
    RoleMappings: dict[str, Any] | None
    Roles: dict[str, str] | None


_PROPERTIES = {"Id", "IdentityPoolId", "RoleMappings", "Roles"}


class CognitoIdentityPoolRoleAttachmentProvider(
    ResourceProvider[CognitoIdentityPoolRoleAttachmentProperties]
):
    TYPE = "AWS::Cognito::IdentityPoolRoleAttachment"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(
        self, request: ResourceRequest[CognitoIdentityPoolRoleAttachmentProperties]
    ) -> ProgressEvent[CognitoIdentityPoolRoleAttachmentProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model, allow_read_only=False):
            return invalid
        pool_id = model["IdentityPoolId"]
        roles = copy.deepcopy(model.get("Roles", {}))
        role_mappings = _service_role_mappings(model.get("RoleMappings", {}))
        try:
            request.aws_client_factory.cognito_identity.set_identity_pool_roles(
                IdentityPoolId=pool_id,
                Roles=roles,
                RoleMappings=role_mappings,
            )
        except Exception as error:
            if is_not_found(error):
                return not_found("AWS::Cognito::IdentityPool", pool_id)
            raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_attachment_model(
                pool_id, roles, role_mappings, model.get("RoleMappings")
            ),
            custom_context=request.custom_context,
        )

    def read(
        self, request: ResourceRequest[CognitoIdentityPoolRoleAttachmentProperties]
    ) -> ProgressEvent[CognitoIdentityPoolRoleAttachmentProperties]:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate_model(model):
            return invalid
        pool_id = model["IdentityPoolId"]
        try:
            response = request.aws_client_factory.cognito_identity.get_identity_pool_roles(
                IdentityPoolId=pool_id
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, pool_id)
            raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_attachment_model(
                pool_id,
                response.get("Roles", {}),
                response.get("RoleMappings", {}),
                model.get("RoleMappings"),
            ),
            custom_context=request.custom_context,
        )

    def update(
        self, request: ResourceRequest[CognitoIdentityPoolRoleAttachmentProperties]
    ) -> ProgressEvent[CognitoIdentityPoolRoleAttachmentProperties]:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        if invalid := _validate_model(desired):
            return invalid
        pool_id = previous.get("IdentityPoolId") or desired.get("IdentityPoolId")
        if not isinstance(pool_id, str) or not pool_id:
            return failed(f"IdentityPoolId is required for {self.TYPE}")
        if desired.get("IdentityPoolId", pool_id) != pool_id:
            return failed(f"IdentityPoolId is immutable for {self.TYPE}")
        roles = copy.deepcopy(desired.get("Roles", {}))
        role_mappings = _service_role_mappings(desired.get("RoleMappings", {}))
        try:
            request.aws_client_factory.cognito_identity.set_identity_pool_roles(
                IdentityPoolId=pool_id,
                Roles=roles,
                RoleMappings=role_mappings,
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, pool_id)
            raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_attachment_model(
                pool_id, roles, role_mappings, desired.get("RoleMappings")
            ),
            custom_context=request.custom_context,
        )

    def delete(
        self, request: ResourceRequest[CognitoIdentityPoolRoleAttachmentProperties]
    ) -> ProgressEvent[CognitoIdentityPoolRoleAttachmentProperties]:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate_model(state):
            return invalid
        pool_id = state["IdentityPoolId"]
        try:
            request.aws_client_factory.cognito_identity.set_identity_pool_roles(
                IdentityPoolId=pool_id,
                Roles={},
                RoleMappings={},
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
        self, request: ResourceRequest[CognitoIdentityPoolRoleAttachmentProperties]
    ) -> ProgressEvent[CognitoIdentityPoolRoleAttachmentProperties]:
        if unsupported := unsupported_properties(request.desired_state, set()):
            return failed(f"Unsupported list filters for {self.TYPE}: {unsupported}")
        pools: list[str] = []
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
            try:
                pools.extend(item["IdentityPoolId"] for item in page)
            except (KeyError, TypeError):
                return failed("The service returned an invalid identity-pool list")
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

        models: list[CognitoIdentityPoolRoleAttachmentProperties] = []
        for pool_id in sorted(pools):
            try:
                response = request.aws_client_factory.cognito_identity.get_identity_pool_roles(
                    IdentityPoolId=pool_id
                )
            except Exception as error:
                if is_not_found(error):
                    continue
                raise
            roles = response.get("Roles", {})
            role_mappings = response.get("RoleMappings", {})
            if roles or role_mappings:
                if invalid := _roles(roles):
                    return invalid
                if invalid := _role_mappings(role_mappings):
                    return invalid
                models.append(_attachment_model(pool_id, roles, role_mappings))
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=models,
            custom_context=request.custom_context,
        )


def _validate_model(model: dict[str, Any], *, allow_read_only: bool = True) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(
            f"Unsupported properties for AWS::Cognito::IdentityPoolRoleAttachment: {unsupported}"
        )
    if not allow_read_only and "Id" in model:
        return failed("Id is read-only for AWS::Cognito::IdentityPoolRoleAttachment")
    pool_id = model.get("IdentityPoolId")
    if not isinstance(pool_id, str) or not pool_id:
        return failed("IdentityPoolId is required for AWS::Cognito::IdentityPoolRoleAttachment")
    if "RoleMappings" in model:
        if invalid := _role_mappings(model["RoleMappings"]):
            return invalid
    if "Roles" in model:
        return _roles(model["Roles"])
    return None


def _roles(value: Any) -> ProgressEvent | None:
    if not isinstance(value, dict) or set(value) - {"authenticated", "unauthenticated"}:
        return failed("Roles may contain only authenticated and unauthenticated entries")
    if any(not isinstance(role, str) or not role for role in value.values()):
        return failed("Role values must be non-empty IAM role ARNs")
    return None


def _role_mappings(value: Any) -> ProgressEvent | None:
    if not isinstance(value, dict) or len(value) > 10:
        return failed("RoleMappings must be an object with at most 10 entries")
    identity_providers: set[str] = set()
    for name, mapping in value.items():
        if not isinstance(name, str) or not name or len(name) > 128:
            return failed("RoleMappings keys must be non-empty strings of at most 128 characters")
        if not isinstance(mapping, dict) or set(mapping) - {
            "AmbiguousRoleResolution",
            "IdentityProvider",
            "RulesConfiguration",
            "Type",
        }:
            return failed("RoleMappings entries contain unsupported properties")
        if mapping.get("Type") not in {"Token", "Rules"} or mapping.get(
            "AmbiguousRoleResolution"
        ) not in {"AuthenticatedRole", "Deny"}:
            return failed("RoleMappings require a valid Type and AmbiguousRoleResolution")
        identity_provider = mapping.get("IdentityProvider")
        if identity_provider is not None and (
            not isinstance(identity_provider, str) or not 1 <= len(identity_provider) <= 128
        ):
            return failed("IdentityProvider must be a non-empty string")
        effective_provider = identity_provider or name
        if effective_provider in identity_providers:
            return failed("RoleMappings must not contain duplicate IdentityProvider values")
        identity_providers.add(effective_provider)
        configuration = mapping.get("RulesConfiguration")
        if mapping["Type"] == "Token":
            if configuration is not None:
                return failed("Token role mappings cannot contain RulesConfiguration")
            continue
        if not isinstance(configuration, dict) or set(configuration) != {"Rules"}:
            return failed("Rules role mappings require RulesConfiguration")
        rules = configuration["Rules"]
        if not isinstance(rules, list) or not 1 <= len(rules) <= 25:
            return failed("RulesConfiguration must contain between 1 and 25 rules")
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {
                "Claim",
                "MatchType",
                "RoleARN",
                "Value",
            }:
                return failed("Role mapping rules require Claim, MatchType, RoleARN, and Value")
            if (
                not isinstance(rule["Claim"], str)
                or not 1 <= len(rule["Claim"]) <= 64
                or rule["MatchType"] not in {"Equals", "Contains", "StartsWith", "NotEqual"}
                or not isinstance(rule["RoleARN"], str)
                or not 20 <= len(rule["RoleARN"]) <= 2048
                or not isinstance(rule["Value"], str)
                or not 1 <= len(rule["Value"]) <= 128
            ):
                return failed("Role mapping rule values are invalid")
    return None


def _service_role_mappings(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, mapping in value.items():
        service_mapping = copy.deepcopy(mapping)
        provider_name = service_mapping.pop("IdentityProvider", name)
        if provider_name in result:
            raise ValueError("RoleMappings contain duplicate IdentityProvider values")
        result[provider_name] = service_mapping
    return result


def _attachment_model(
    pool_id: str,
    roles: dict[str, str],
    role_mappings: dict[str, Any],
    desired_role_mappings: dict[str, Any] | None = None,
) -> CognitoIdentityPoolRoleAttachmentProperties:
    output_mappings: dict[str, Any] = {}
    if desired_role_mappings is not None:
        for name, desired in desired_role_mappings.items():
            provider_name = desired.get("IdentityProvider", name)
            if provider_name not in role_mappings:
                continue
            output = copy.deepcopy(role_mappings[provider_name])
            if "IdentityProvider" in desired:
                output["IdentityProvider"] = provider_name
            output_mappings[name] = output
    else:
        output_mappings = copy.deepcopy(role_mappings)
    model = CognitoIdentityPoolRoleAttachmentProperties(
        Id=pool_id,
        IdentityPoolId=pool_id,
        Roles=copy.deepcopy(roles),
    )
    if output_mappings or desired_role_mappings is not None:
        model["RoleMappings"] = output_mappings
    return model
