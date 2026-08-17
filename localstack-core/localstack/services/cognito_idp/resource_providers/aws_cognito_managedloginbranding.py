from __future__ import annotations

import base64
import copy
from pathlib import Path
from typing import Any, TypedDict

from botocore.exceptions import ConnectionClosedError, ReadTimeoutError

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


class ManagedLoginBrandingProperties(TypedDict):
    Assets: list[dict] | None
    ClientId: str | None
    ManagedLoginBrandingId: str | None
    ReturnMergedResources: bool | None
    Settings: dict | None
    UseCognitoProvidedValues: bool | None
    UserPoolId: str | None


_PROPERTIES = {
    "Assets",
    "ClientId",
    "ManagedLoginBrandingId",
    "ReturnMergedResources",
    "Settings",
    "UseCognitoProvidedValues",
    "UserPoolId",
}
_CREATE_ONLY = {"ClientId", "UserPoolId"}


class CognitoManagedLoginBrandingProvider(ResourceProvider[ManagedLoginBrandingProperties]):
    TYPE = "AWS::Cognito::ManagedLoginBranding"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate(model, creating=True):
            return invalid
        params = _write_params(model, creating=True)
        client = request.aws_client_factory.cognito_idp
        existing = _find_by_client(client, model["UserPoolId"], model["ClientId"])
        if existing is not None:
            return failed(
                "A managed login branding style already exists for this app client",
                error_code="AlreadyExists",
            )
        try:
            response = client.create_managed_login_branding(**params)
            description = response["ManagedLoginBranding"]
        except Exception as error:
            if not isinstance(error, (ConnectionClosedError, ReadTimeoutError)):
                raise
            description = _find_by_client(client, model["UserPoolId"], model["ClientId"])
            if description is None or not _branding_matches(model, description):
                raise error
        return _success(request, model, description)

    def read(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate(model, reading=True):
            return invalid
        try:
            description = request.aws_client_factory.cognito_idp.describe_managed_login_branding(
                ManagedLoginBrandingId=model["ManagedLoginBrandingId"],
                ReturnMergedResources=model.get("ReturnMergedResources", False),
                UserPoolId=model["UserPoolId"],
            )["ManagedLoginBranding"]
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, model["ManagedLoginBrandingId"])
            raise
        return _success(request, model, description)

    def update(self, request: ResourceRequest) -> ProgressEvent:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        state = desired
        if (
            "ManagedLoginBrandingId" not in state
            and previous.get("ManagedLoginBrandingId") is not None
        ):
            state["ManagedLoginBrandingId"] = previous["ManagedLoginBrandingId"]
        state.setdefault("UseCognitoProvidedValues", False)
        if invalid := _validate(state):
            return invalid
        for name in _CREATE_ONLY:
            if desired.get(name, previous.get(name)) != previous.get(name):
                return failed(f"{name} is create-only and requires replacement")
        client = request.aws_client_factory.cognito_idp
        before = client.describe_managed_login_branding(
            ManagedLoginBrandingId=state["ManagedLoginBrandingId"],
            ReturnMergedResources=False,
            UserPoolId=state["UserPoolId"],
        )["ManagedLoginBranding"]
        try:
            client.update_managed_login_branding(
                ManagedLoginBrandingId=state["ManagedLoginBrandingId"],
                UseCognitoProvidedValues=True,
                UserPoolId=state["UserPoolId"],
            )
            if not state.get("UseCognitoProvidedValues", False):
                client.update_managed_login_branding(**_write_params(state, creating=False))
            description = client.describe_managed_login_branding(
                ManagedLoginBrandingId=state["ManagedLoginBrandingId"],
                ReturnMergedResources=state.get("ReturnMergedResources", False),
                UserPoolId=state["UserPoolId"],
            )["ManagedLoginBranding"]
        except Exception as original:
            try:
                _restore(client, state["UserPoolId"], state["ManagedLoginBrandingId"], before)
            except Exception as rollback:
                raise RuntimeError(
                    f"Managed login branding update failed and rollback was incomplete: "
                    f"{type(original).__name__}; {type(rollback).__name__}"
                ) from original
            raise
        return _success(request, state, description)

    def delete(self, request: ResourceRequest) -> ProgressEvent:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate(state, reading=True):
            return invalid
        try:
            request.aws_client_factory.cognito_idp.delete_managed_login_branding(
                ManagedLoginBrandingId=state["ManagedLoginBrandingId"],
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

    def list(self, request: ResourceRequest) -> ProgressEvent:
        filters = copy.deepcopy(request.desired_state)
        if unsupported := unsupported_properties(filters, {"UserPoolId"}):
            return failed(f"Unsupported list filters for {self.TYPE}: {unsupported}")
        client = request.aws_client_factory.cognito_idp
        models = []
        pool_ids = _pool_ids(client, filters.get("UserPoolId"))
        visited_clients = 0
        for pool_id in pool_ids:
            app_clients = _list_app_clients(client, pool_id)
            visited_clients += len(app_clients)
            if visited_clients > 1024:
                return failed("The managed-login branding listing exceeded its safety bound")
            for summary in sorted(app_clients, key=lambda item: item["ClientId"]):
                description = _find_by_client(client, pool_id, summary["ClientId"])
                if description is None:
                    continue
                models.append(
                    _resource_model(
                        {"ClientId": summary["ClientId"], "UserPoolId": pool_id},
                        description,
                    )
                )
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=models,
            custom_context=request.custom_context,
        )


def _write_params(model: dict, *, creating: bool) -> dict[str, Any]:
    params = {"UserPoolId": model["UserPoolId"]}
    if creating:
        params["ClientId"] = model["ClientId"]
    else:
        params["ManagedLoginBrandingId"] = model["ManagedLoginBrandingId"]
    for name in ("Assets", "Settings", "UseCognitoProvidedValues"):
        if name in model:
            params[name] = copy.deepcopy(model[name])
    if "Assets" in params:
        params["Assets"] = _api_assets(params["Assets"])
    return params


def _api_assets(assets: list[dict]) -> list[dict]:
    result = copy.deepcopy(assets)
    for asset in result:
        content = asset.get("Bytes")
        if isinstance(content, str):
            try:
                asset["Bytes"] = base64.b64decode(content, validate=True)
            except (ValueError, TypeError):
                raise ValueError("Managed login asset Bytes must be valid base64") from None
    return result


def _restore(client, pool_id: str, branding_id: str, before: dict) -> None:
    client.update_managed_login_branding(
        ManagedLoginBrandingId=branding_id,
        UseCognitoProvidedValues=True,
        UserPoolId=pool_id,
    )
    if not before.get("UseCognitoProvidedValues", False):
        params = {
            "ManagedLoginBrandingId": branding_id,
            "UserPoolId": pool_id,
        }
        for name in ("Assets", "Settings"):
            if name in before:
                params[name] = before[name]
        client.update_managed_login_branding(**params)


def _validate(
    model: dict, *, creating: bool = False, reading: bool = False
) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported managed-login branding properties: {unsupported}")
    required = ("UserPoolId",) if reading else ("ClientId", "UserPoolId")
    for name in required:
        if not isinstance(model.get(name), str) or not model[name]:
            return failed(f"{name} is required for AWS::Cognito::ManagedLoginBranding")
    if not creating and (
        not isinstance(model.get("ManagedLoginBrandingId"), str)
        or not model["ManagedLoginBrandingId"]
    ):
        return failed("ManagedLoginBrandingId is required")
    if model.get("UseCognitoProvidedValues") is True and ("Assets" in model or "Settings" in model):
        return failed("Settings and Assets must be omitted with UseCognitoProvidedValues")
    return None


def _pool_ids(client, supplied: object) -> list[str]:
    if supplied is not None:
        if not isinstance(supplied, str) or not supplied:
            raise ValueError("Invalid Cognito user pool ID")
        return [supplied]
    pools = []
    token = None
    seen = set()
    for _ in range(16):
        params = {"MaxResults": 60}
        if token is not None:
            params["NextToken"] = token
        response = client.list_user_pools(**params)
        pools.extend(item["Id"] for item in response.get("UserPools", []))
        if len(pools) > 512:
            raise RuntimeError("The Cognito user-pool listing exceeded its safety bound")
        token = response.get("NextToken")
        if token is None:
            return sorted(pools)
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError("The service returned an invalid user-pool continuation token")
        seen.add(token)
    raise RuntimeError("The Cognito user-pool listing exceeded its page bound")


def _list_app_clients(client, pool_id: str) -> list[dict]:
    result = []
    token = None
    seen = set()
    for _ in range(18):
        params = {"MaxResults": 60, "UserPoolId": pool_id}
        if token is not None:
            params["NextToken"] = token
        response = client.list_user_pool_clients(**params)
        result.extend(response.get("UserPoolClients", []))
        token = response.get("NextToken")
        if token is None:
            return result
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError("The service returned an invalid app-client continuation token")
        seen.add(token)
    raise RuntimeError("The app-client listing exceeded its page bound")


def _success(request, desired: dict, description: dict) -> ProgressEvent:
    model = _resource_model(desired, description)
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=ManagedLoginBrandingProperties(**model),
        custom_context=request.custom_context,
    )


def _resource_model(desired: dict, description: dict) -> dict:
    model = copy.deepcopy(desired)
    model["ManagedLoginBrandingId"] = description["ManagedLoginBrandingId"]
    model["UserPoolId"] = description["UserPoolId"]
    model["UseCognitoProvidedValues"] = description.get("UseCognitoProvidedValues", False)
    for name in ("Settings", "Assets"):
        if name in description:
            model[name] = (
                _json_assets(description[name])
                if name == "Assets"
                else copy.deepcopy(description[name])
            )
        else:
            model.pop(name, None)
    return model


def _json_assets(assets: list[dict]) -> list[dict]:
    result = copy.deepcopy(assets)
    for asset in result:
        if isinstance(asset.get("Bytes"), bytes):
            asset["Bytes"] = base64.b64encode(asset["Bytes"]).decode()
    return result


def _find_by_client(client, pool_id: str, client_id: str) -> dict | None:
    try:
        return client.describe_managed_login_branding_by_client(
            ClientId=client_id,
            ReturnMergedResources=False,
            UserPoolId=pool_id,
        )["ManagedLoginBranding"]
    except Exception as error:
        if is_not_found(error):
            return None
        raise


def _branding_matches(desired: dict, actual: dict) -> bool:
    if actual.get("UserPoolId") != desired.get("UserPoolId") or actual.get(
        "UseCognitoProvidedValues", False
    ) != desired.get("UseCognitoProvidedValues", False):
        return False
    if desired.get("UseCognitoProvidedValues", False):
        return True
    if actual.get("Settings", {}) != desired.get("Settings", {}):
        return False
    return _asset_fingerprints(actual.get("Assets", [])) == _asset_fingerprints(
        desired.get("Assets", [])
    )


def _asset_fingerprints(assets: list[dict]) -> set[tuple]:
    result = set()
    for asset in assets:
        content = asset.get("Bytes", b"")
        if isinstance(content, str):
            try:
                content = base64.b64decode(content, validate=True)
            except ValueError:
                content = content.encode()
        result.add(
            (
                asset.get("Category"),
                asset.get("ColorMode"),
                asset.get("Extension"),
                bytes(content),
            )
        )
    return result
