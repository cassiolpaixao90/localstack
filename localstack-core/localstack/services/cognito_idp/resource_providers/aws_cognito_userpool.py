from __future__ import annotations

import copy
from functools import cache
from pathlib import Path
from typing import Any, TypedDict

from botocore.loaders import create_loader

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


class CognitoUserPoolProperties(TypedDict):
    AccountRecoverySetting: dict[str, Any] | None
    AdminCreateUserConfig: dict[str, Any] | None
    Arn: str | None
    AutoVerifiedAttributes: list[str] | None
    AliasAttributes: list[str] | None
    DeletionProtection: str | None
    DeviceConfiguration: dict[str, Any] | None
    EmailAuthenticationMessage: str | None
    EmailAuthenticationSubject: str | None
    EmailConfiguration: dict[str, Any] | None
    EmailVerificationMessage: str | None
    EmailVerificationSubject: str | None
    EnabledMfas: list[str] | None
    LambdaConfig: dict[str, Any] | None
    IssuerConfiguration: dict[str, Any] | None
    KeyConfiguration: dict[str, Any] | None
    MfaConfiguration: str | None
    Policies: dict[str, Any] | None
    ProviderName: str | None
    ProviderURL: str | None
    Schema: list[dict[str, Any]] | None
    SmsVerificationMessage: str | None
    SmsAuthenticationMessage: str | None
    SmsConfiguration: dict[str, Any] | None
    UserAttributeUpdateSettings: dict[str, Any] | None
    UserPoolAddOns: dict[str, Any] | None
    UserPoolId: str | None
    UserPoolName: str | None
    UserPoolTags: dict[str, str] | None
    UserPoolTier: str | None
    UsernameAttributes: list[str] | None
    UsernameConfiguration: dict[str, Any] | None
    VerificationMessageTemplate: dict[str, Any] | None
    WebAuthnFactorConfiguration: dict[str, Any] | None
    WebAuthnRelyingPartyID: str | None
    WebAuthnUserVerification: str | None


_PROPERTIES = {
    "AccountRecoverySetting",
    "AdminCreateUserConfig",
    "AliasAttributes",
    "Arn",
    "AutoVerifiedAttributes",
    "DeletionProtection",
    "DeviceConfiguration",
    "EmailAuthenticationMessage",
    "EmailAuthenticationSubject",
    "EmailConfiguration",
    "EmailVerificationMessage",
    "EmailVerificationSubject",
    "EnabledMfas",
    "LambdaConfig",
    "IssuerConfiguration",
    "KeyConfiguration",
    "MfaConfiguration",
    "Policies",
    "ProviderName",
    "ProviderURL",
    "Schema",
    "SmsVerificationMessage",
    "SmsAuthenticationMessage",
    "SmsConfiguration",
    "UserAttributeUpdateSettings",
    "UserPoolAddOns",
    "UserPoolId",
    "UserPoolName",
    "UserPoolTags",
    "UserPoolTier",
    "UsernameAttributes",
    "UsernameConfiguration",
    "VerificationMessageTemplate",
    "WebAuthnFactorConfiguration",
    "WebAuthnRelyingPartyID",
    "WebAuthnUserVerification",
}
_READ_ONLY = {"Arn", "ProviderName", "ProviderURL", "UserPoolId"}
_UNSUPPORTED_RUNTIME_FIELDS = {
    "EmailAuthenticationMessage",
    "EmailAuthenticationSubject",
    "WebAuthnFactorConfiguration",
    "WebAuthnRelyingPartyID",
    "WebAuthnUserVerification",
}
_CREATE_API_FIELDS = _PROPERTIES - _READ_ONLY - {"UserPoolName"}
_MFA_FIELDS = {"EnabledMfas", "MfaConfiguration"}
_CREATE_DIRECT_FIELDS = _CREATE_API_FIELDS - _MFA_FIELDS
_UPDATE_API_FIELDS = _CREATE_API_FIELDS - {
    "AliasAttributes",
    "EnabledMfas",
    "MfaConfiguration",
    "Schema",
    "UsernameAttributes",
    "UsernameConfiguration",
    "UserPoolTags",
}
_MAX_LIST_PAGES = 1_000


class _IndeterminateSchemaUpdate(RuntimeError):
    pass


class CognitoUserPoolProvider(ResourceProvider[CognitoUserPoolProperties]):
    TYPE = "AWS::Cognito::UserPool"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(
        self, request: ResourceRequest[CognitoUserPoolProperties]
    ) -> ProgressEvent[CognitoUserPoolProperties]:
        model = copy.deepcopy(request.desired_state)
        if unsupported := unsupported_properties(model, _PROPERTIES):
            return failed(f"Unsupported properties for {self.TYPE}: {unsupported}")
        if unsupported := sorted(set(model) & _UNSUPPORTED_RUNTIME_FIELDS):
            return failed(f"Properties are not implemented for {self.TYPE}: {unsupported}")
        if any(name in model for name in _READ_ONLY):
            return failed(f"Read-only properties cannot be supplied for {self.TYPE}")

        pool_name = model.get("UserPoolName")
        if pool_name is None:
            pool_name = util.generate_default_name(request.stack_name, request.logical_resource_id)
        mfa_configuration, software_token_enabled = _mfa_settings(model)
        params = {"PoolName": pool_name}
        for name in sorted(_CREATE_DIRECT_FIELDS):
            if name in model:
                params[name] = copy.deepcopy(model[name])
        response = request.aws_client_factory.cognito_idp.create_user_pool(**params)
        pool_id = response["UserPool"]["Id"]
        try:
            if _MFA_FIELDS & set(model):
                request.aws_client_factory.cognito_idp.set_user_pool_mfa_config(
                    MfaConfiguration=mfa_configuration,
                    SoftwareTokenMfaConfiguration={"Enabled": software_token_enabled},
                    UserPoolId=pool_id,
                )
        except Exception as error:
            try:
                request.aws_client_factory.cognito_idp.delete_user_pool(UserPoolId=pool_id)
            except Exception as cleanup_error:
                error.add_note(
                    "CreateUserPool rollback failed for "
                    f"{pool_id}: {type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise
        pool = copy.deepcopy(response["UserPool"])
        if _MFA_FIELDS & set(model):
            pool["MfaConfiguration"] = mfa_configuration
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_pool_model(
                pool,
                enabled_mfas=["SOFTWARE_TOKEN_MFA"] if software_token_enabled else [],
                pool_name=pool_name,
            ),
            custom_context=request.custom_context,
        )

    def read(
        self, request: ResourceRequest[CognitoUserPoolProperties]
    ) -> ProgressEvent[CognitoUserPoolProperties]:
        model = copy.deepcopy(request.desired_state)
        if unsupported := unsupported_properties(model, _PROPERTIES):
            return failed(f"Unsupported properties for {self.TYPE}: {unsupported}")
        pool_id = model.get("UserPoolId")
        if not isinstance(pool_id, str) or not pool_id:
            return failed("UserPoolId is required to read AWS::Cognito::UserPool")
        try:
            response = request.aws_client_factory.cognito_idp.describe_user_pool(UserPoolId=pool_id)
            mfa = request.aws_client_factory.cognito_idp.get_user_pool_mfa_config(
                UserPoolId=pool_id
            )
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, pool_id)
            raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_pool_model(
                response["UserPool"],
                enabled_mfas=(
                    ["SOFTWARE_TOKEN_MFA"]
                    if mfa.get("SoftwareTokenMfaConfiguration", {}).get("Enabled") is True
                    else []
                ),
            ),
            custom_context=request.custom_context,
        )

    def update(
        self, request: ResourceRequest[CognitoUserPoolProperties]
    ) -> ProgressEvent[CognitoUserPoolProperties]:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        if unsupported := unsupported_properties(desired, _PROPERTIES):
            return failed(f"Unsupported properties for {self.TYPE}: {unsupported}")
        if unsupported := sorted(set(desired) & _UNSUPPORTED_RUNTIME_FIELDS):
            return failed(f"Properties are not implemented for {self.TYPE}: {unsupported}")

        pool_id = previous.get("UserPoolId") or desired.get("UserPoolId")
        if not isinstance(pool_id, str) or not pool_id:
            return failed("UserPoolId is required to update AWS::Cognito::UserPool")
        if desired.get("UserPoolId", pool_id) != pool_id:
            return failed("UserPoolId is immutable for AWS::Cognito::UserPool")

        try:
            schema_additions = _schema_additions(previous.get("Schema"), desired.get("Schema"))
        except ValueError as error:
            return failed(str(error))
        if desired.get("UsernameAttributes") != previous.get("UsernameAttributes"):
            return failed(
                "Updating UsernameAttributes is not supported without replacing the user pool"
            )

        previous_name = previous.get("UserPoolName")
        desired_name = desired.get("UserPoolName", previous_name)
        if not isinstance(desired_name, str) or not desired_name:
            return failed("UserPoolName is required to update AWS::Cognito::UserPool")

        mfa_configuration, software_token_enabled = _mfa_settings(desired)
        previous_mfa_configuration, previous_software_token_enabled = _mfa_settings(previous)
        try:
            params = _update_params(desired, pool_id, desired_name)
            request.aws_client_factory.cognito_idp.update_user_pool(**params)
            request.aws_client_factory.cognito_idp.set_user_pool_mfa_config(
                MfaConfiguration=mfa_configuration,
                SoftwareTokenMfaConfiguration={"Enabled": software_token_enabled},
                UserPoolId=pool_id,
            )
            if desired.get("UserPoolTags") != previous.get("UserPoolTags"):
                _update_tags(
                    request.aws_client_factory.cognito_idp,
                    previous.get("Arn") or desired.get("Arn"),
                    previous.get("UserPoolTags") or {},
                    desired.get("UserPoolTags") or {},
                )
            response = request.aws_client_factory.cognito_idp.describe_user_pool(UserPoolId=pool_id)
            mfa = request.aws_client_factory.cognito_idp.get_user_pool_mfa_config(
                UserPoolId=pool_id
            )
            if schema_additions:
                try:
                    request.aws_client_factory.cognito_idp.add_custom_attributes(
                        CustomAttributes=copy.deepcopy(schema_additions),
                        UserPoolId=pool_id,
                    )
                except Exception as add_error:
                    try:
                        state, observed = _observe_schema_additions(
                            request.aws_client_factory.cognito_idp,
                            pool_id,
                            response["UserPool"],
                            schema_additions,
                        )
                    except Exception as observe_error:
                        raise _IndeterminateSchemaUpdate(
                            "indeterminate schema update: AddCustomAttributes failed and "
                            f"reconciliation failed ({type(observe_error).__name__}: "
                            f"{observe_error})"
                        ) from add_error
                    if state == "applied":
                        response = observed
                        response["UserPool"]["SchemaAttributes"] = copy.deepcopy(desired["Schema"])
                    elif state == "absent":
                        raise
                    else:
                        raise _IndeterminateSchemaUpdate(
                            "indeterminate schema update: custom attributes were only "
                            "partially or incompatibly observed"
                        ) from add_error
                else:
                    response["UserPool"]["SchemaAttributes"] = copy.deepcopy(desired["Schema"])
        except _IndeterminateSchemaUpdate:
            raise
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, pool_id)
            try:
                request.aws_client_factory.cognito_idp.update_user_pool(
                    **_update_params(previous, pool_id, previous_name)
                )
                request.aws_client_factory.cognito_idp.set_user_pool_mfa_config(
                    MfaConfiguration=previous_mfa_configuration,
                    SoftwareTokenMfaConfiguration={"Enabled": previous_software_token_enabled},
                    UserPoolId=pool_id,
                )
                if desired.get("UserPoolTags") != previous.get("UserPoolTags"):
                    _update_tags(
                        request.aws_client_factory.cognito_idp,
                        previous.get("Arn") or desired.get("Arn"),
                        desired.get("UserPoolTags") or {},
                        previous.get("UserPoolTags") or {},
                    )
            except Exception as rollback_error:
                error.add_note(
                    "UpdateUserPool rollback failed for "
                    f"{pool_id}: {type(rollback_error).__name__}: {rollback_error}"
                )
            raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_pool_model(
                response["UserPool"],
                enabled_mfas=(
                    ["SOFTWARE_TOKEN_MFA"]
                    if mfa.get("SoftwareTokenMfaConfiguration", {}).get("Enabled") is True
                    else []
                ),
            ),
            custom_context=request.custom_context,
        )

    def delete(
        self, request: ResourceRequest[CognitoUserPoolProperties]
    ) -> ProgressEvent[CognitoUserPoolProperties]:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if unsupported := unsupported_properties(state, _PROPERTIES):
            return failed(f"Unsupported properties for {self.TYPE}: {unsupported}")
        pool_id = state.get("UserPoolId")
        if not isinstance(pool_id, str) or not pool_id:
            return failed("UserPoolId is required to delete AWS::Cognito::UserPool")
        try:
            request.aws_client_factory.cognito_idp.delete_user_pool(UserPoolId=pool_id)
        except Exception as error:
            if not is_not_found(error):
                raise
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=state,
            custom_context=request.custom_context,
        )

    def list(
        self, request: ResourceRequest[CognitoUserPoolProperties]
    ) -> ProgressEvent[CognitoUserPoolProperties]:
        if unsupported := unsupported_properties(request.desired_state, set()):
            return failed(f"Unsupported list filters for {self.TYPE}: {unsupported}")
        resources = []
        next_token = None
        seen_tokens = set()
        for _ in range(_MAX_LIST_PAGES):
            params = {"MaxResults": 60}
            if next_token is not None:
                params["NextToken"] = next_token
            response = request.aws_client_factory.cognito_idp.list_user_pools(**params)
            page = response.get("UserPools", [])
            resources.extend(page)
            next_token = response.get("NextToken")
            if next_token is None:
                break
            if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
                return failed("The service returned an invalid user-pool continuation token")
            seen_tokens.add(next_token)
        else:
            return failed("The service exceeded the user-pool pagination limit")
        resources.sort(key=lambda item: item["Id"])
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=[
                CognitoUserPoolProperties(UserPoolId=pool["Id"], UserPoolName=pool.get("Name"))
                for pool in resources
            ],
            custom_context=request.custom_context,
        )


def _pool_model(
    pool: dict,
    *,
    enabled_mfas: list[str] | None = None,
    pool_name: str | None = None,
) -> CognitoUserPoolProperties:
    pool_id = pool["Id"]
    region = pool_id.split("_", 1)[0]
    partition = pool["Arn"].split(":", 2)[1]
    provider_name = f"cognito-idp.{region}.{_dns_suffix(partition)}/{pool_id}"
    model = CognitoUserPoolProperties(
        Arn=pool["Arn"],
        ProviderName=provider_name,
        ProviderURL=f"https://{provider_name}",
        UserPoolId=pool_id,
        UserPoolName=pool.get("Name", pool_name),
    )
    for name in sorted(_CREATE_API_FIELDS - {"Schema"}):
        if name in pool and not (name == "LambdaConfig" and not pool[name]):
            if name == "UserPoolTier" and pool[name] == "ESSENTIALS":
                continue
            model[name] = copy.deepcopy(pool[name])
    if "SchemaAttributes" in pool:
        model["Schema"] = [
            _cloudformation_schema_attribute(attribute) for attribute in pool["SchemaAttributes"]
        ]
    if enabled_mfas:
        model["EnabledMfas"] = list(enabled_mfas)
    return model


def _mfa_settings(model: dict[str, Any]) -> tuple[str, bool]:
    enabled_mfas = model.get("EnabledMfas", [])
    if enabled_mfas not in ([], ["SOFTWARE_TOKEN_MFA"]):
        raise ValueError("Only SOFTWARE_TOKEN_MFA is supported in EnabledMfas")
    configuration = model.get("MfaConfiguration", "OFF")
    if configuration not in {"OFF", "ON", "OPTIONAL"}:
        raise ValueError("Invalid MfaConfiguration")
    enabled = enabled_mfas == ["SOFTWARE_TOKEN_MFA"]
    if configuration == "ON" and not enabled:
        raise ValueError("MfaConfiguration ON requires SOFTWARE_TOKEN_MFA")
    return configuration, enabled


def _schema_additions(previous: Any, desired: Any) -> list[dict[str, Any]]:
    previous_items = [] if previous is None else previous
    desired_items = [] if desired is None else desired
    if not isinstance(previous_items, list) or not isinstance(desired_items, list):
        raise ValueError("Schema must be a list")

    def by_name(items: list[Any]) -> dict[str, dict[str, Any]]:
        result = {}
        for raw in items:
            if not isinstance(raw, dict):
                raise ValueError("Schema entries must be objects")
            item = _schema_attribute_semantics(raw)
            name = item.get("Name")
            if not isinstance(name, str) or not name or name in result:
                raise ValueError("Schema attribute names must be unique non-empty strings")
            result[name] = item
        return result

    previous_by_name = by_name(previous_items)
    desired_by_name = by_name(desired_items)
    for name, previous_attribute in previous_by_name.items():
        if name not in desired_by_name:
            raise ValueError(f"Schema attribute removal is not supported: {name}")
        if desired_by_name[name] != previous_attribute:
            raise ValueError(f"Schema attribute mutation is not supported: {name}")
    additions = [
        copy.deepcopy(_cloudformation_schema_attribute(attribute))
        for attribute in desired_items
        if _cloudformation_schema_attribute(attribute).get("Name") not in previous_by_name
    ]
    standard_names = {
        "address",
        "birthdate",
        "email",
        "family_name",
        "gender",
        "given_name",
        "locale",
        "middle_name",
        "name",
        "nickname",
        "phone_number",
        "picture",
        "preferred_username",
        "profile",
        "sub",
        "updated_at",
        "website",
        "zoneinfo",
    }
    if standard := sorted(
        attribute["Name"] for attribute in additions if attribute["Name"] in standard_names
    ):
        raise ValueError(f"Standard Schema attributes cannot be added after create: {standard}")
    return additions


def _cloudformation_schema_attribute(attribute: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(attribute)
    name = result.get("Name")
    if isinstance(name, str) and name.startswith("custom:"):
        result["Name"] = name.removeprefix("custom:")
    elif isinstance(name, str) and name.startswith("dev:"):
        result["Name"] = name.removeprefix("dev:")
        result["DeveloperOnlyAttribute"] = True
    return result


def _schema_attribute_semantics(attribute: dict[str, Any]) -> dict[str, Any]:
    item = _cloudformation_schema_attribute(attribute)
    result = {
        "AttributeDataType": item.get("AttributeDataType", "String"),
        "DeveloperOnlyAttribute": item.get("DeveloperOnlyAttribute", False),
        "Mutable": item.get("Mutable", False),
        "Name": item.get("Name"),
        "Required": item.get("Required", False),
    }
    if result["AttributeDataType"] == "String":
        result["StringAttributeConstraints"] = item.get("StringAttributeConstraints", {})
    elif result["AttributeDataType"] == "Number":
        result["NumberAttributeConstraints"] = item.get("NumberAttributeConstraints", {})
    return result


def _observe_schema_additions(
    client,
    pool_id: str,
    expected_pool: dict[str, Any],
    additions: list[dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    observed = client.describe_user_pool(UserPoolId=pool_id)
    pool = observed.get("UserPool")
    if (
        not isinstance(pool, dict)
        or pool.get("Id") != expected_pool.get("Id")
        or pool.get("Arn") != expected_pool.get("Arn")
    ):
        return "indeterminate", observed
    observed_by_name = {
        item.get("Name"): item
        for raw in pool.get("SchemaAttributes", [])
        if isinstance(raw, dict)
        for item in [_schema_attribute_semantics(raw)]
    }
    states = []
    for addition in additions:
        expected = _schema_attribute_semantics(addition)
        actual = observed_by_name.get(expected["Name"])
        states.append("absent" if actual is None else "applied" if actual == expected else "other")
    if states and all(state == "applied" for state in states):
        return "applied", observed
    if states and all(state == "absent" for state in states):
        return "absent", observed
    return "indeterminate", observed


def _update_params(model: dict[str, Any], pool_id: str, pool_name: Any) -> dict[str, Any]:
    if not isinstance(pool_name, str) or not pool_name:
        raise ValueError("UserPoolName is required to update AWS::Cognito::UserPool")
    params: dict[str, Any] = {"PoolName": pool_name, "UserPoolId": pool_id}
    for name in sorted(_UPDATE_API_FIELDS):
        if name in model:
            params[name] = copy.deepcopy(model[name])
    return params


def _update_tags(client, arn: Any, previous: dict[str, str], desired: dict[str, str]) -> None:
    if not isinstance(arn, str) or not arn:
        raise ValueError("User-pool ARN is required to reconcile tags")
    removed = sorted(set(previous) - set(desired))
    changed = {key: value for key, value in desired.items() if previous.get(key) != value}
    if removed:
        client.untag_resource(ResourceArn=arn, TagKeys=removed)
    if changed:
        client.tag_resource(ResourceArn=arn, Tags=changed)


@cache
def _dns_suffix(partition: str) -> str:
    for candidate in create_loader().load_data("endpoints")["partitions"]:
        if candidate["partition"] == partition:
            return candidate["dnsSuffix"]
    raise ValueError(f"unknown AWS partition: {partition}")
