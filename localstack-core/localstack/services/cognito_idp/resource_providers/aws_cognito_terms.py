from __future__ import annotations

import copy
from pathlib import Path
from typing import TypedDict

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


class TermsProperties(TypedDict):
    ClientId: str | None
    Enforcement: str | None
    Links: dict[str, str] | None
    TermsId: str | None
    TermsName: str | None
    TermsSource: str | None
    UserPoolId: str | None


_PROPERTIES = {
    "ClientId",
    "Enforcement",
    "Links",
    "TermsId",
    "TermsName",
    "TermsSource",
    "UserPoolId",
}
_CREATE_ONLY = {"ClientId", "UserPoolId"}


class CognitoTermsProvider(ResourceProvider[TermsProperties]):
    TYPE = "AWS::Cognito::Terms"
    SCHEMA = util.get_schema_path(Path(__file__))

    def create(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate(model, creating=True):
            return invalid
        client = request.aws_client_factory.cognito_idp
        existing = _find_terms(client, model["UserPoolId"], model["ClientId"], model["TermsName"])
        if existing is not None:
            return failed(
                "Terms already exist for this app client and document type",
                error_code="AlreadyExists",
            )
        try:
            terms = client.create_terms(**_write_params(model))["Terms"]
        except Exception as error:
            if not isinstance(error, (ConnectionClosedError, ReadTimeoutError)):
                raise
            terms = _find_terms(client, model["UserPoolId"], model["ClientId"], model["TermsName"])
            if terms is None or not _terms_match(model, terms):
                raise error
        return _success(request, terms)

    def read(self, request: ResourceRequest) -> ProgressEvent:
        model = copy.deepcopy(request.desired_state)
        if invalid := _validate(model, reading=True):
            return invalid
        try:
            terms = request.aws_client_factory.cognito_idp.describe_terms(
                TermsId=model["TermsId"], UserPoolId=model["UserPoolId"]
            )["Terms"]
        except Exception as error:
            if is_not_found(error):
                return not_found(self.TYPE, model["TermsId"])
            raise
        return _success(request, terms)

    def update(self, request: ResourceRequest) -> ProgressEvent:
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        state = desired
        if "TermsId" not in state and previous.get("TermsId") is not None:
            state["TermsId"] = previous["TermsId"]
        if invalid := _validate(state):
            return invalid
        for name in _CREATE_ONLY:
            if desired.get(name, previous.get(name)) != previous.get(name):
                return failed(f"{name} is create-only and requires replacement")
        client = request.aws_client_factory.cognito_idp
        before = client.describe_terms(TermsId=state["TermsId"], UserPoolId=state["UserPoolId"])[
            "Terms"
        ]
        try:
            terms = client.update_terms(**_write_params(state, update=True))["Terms"]
        except Exception as original:
            try:
                client.update_terms(**_write_params(before, update=True))
            except Exception as rollback:
                raise RuntimeError(
                    f"Terms update failed and rollback was incomplete: "
                    f"{type(original).__name__}; {type(rollback).__name__}"
                ) from original
            raise
        return _success(request, terms)

    def delete(self, request: ResourceRequest) -> ProgressEvent:
        state = copy.deepcopy(request.previous_state or request.desired_state)
        if invalid := _validate(state, reading=True):
            return invalid
        try:
            request.aws_client_factory.cognito_idp.delete_terms(
                TermsId=state["TermsId"], UserPoolId=state["UserPoolId"]
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
        for pool_id in _pool_ids(client, filters.get("UserPoolId")):
            summaries = _list_term_summaries(client, pool_id)
            if len(models) + len(summaries) > 1024:
                return failed("The Cognito Terms listing exceeded its safety bound")
            for summary in summaries:
                terms = client.describe_terms(TermsId=summary["TermsId"], UserPoolId=pool_id)[
                    "Terms"
                ]
                models.append(_terms_model(terms))
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=models,
            custom_context=request.custom_context,
        )


def _write_params(model: dict, *, update: bool = False) -> dict:
    names = ["Enforcement", "Links", "TermsName", "TermsSource", "UserPoolId"]
    params = {name: copy.deepcopy(model[name]) for name in names if name in model}
    if update:
        params["TermsId"] = model["TermsId"]
    else:
        params["ClientId"] = model["ClientId"]
    return params


def _validate(
    model: dict, *, creating: bool = False, reading: bool = False
) -> ProgressEvent | None:
    if unsupported := unsupported_properties(model, _PROPERTIES):
        return failed(f"Unsupported Cognito Terms properties: {unsupported}")
    required = (
        {"TermsId", "UserPoolId"}
        if reading
        else {"ClientId", "Enforcement", "Links", "TermsName", "TermsSource", "UserPoolId"}
    )
    if not creating and not reading:
        required.add("TermsId")
    missing = sorted(name for name in required if model.get(name) is None)
    if missing:
        return failed(f"Missing required Cognito Terms properties: {missing}")
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


def _success(request, terms: dict) -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.SUCCESS,
        resource_model=TermsProperties(**_terms_model(terms)),
        custom_context=request.custom_context,
    )


def _terms_model(terms: dict) -> dict:
    return {
        "ClientId": terms["ClientId"],
        "Enforcement": terms["Enforcement"],
        "Links": copy.deepcopy(terms["Links"]),
        "TermsId": terms["TermsId"],
        "TermsName": terms["TermsName"],
        "TermsSource": terms["TermsSource"],
        "UserPoolId": terms["UserPoolId"],
    }


def _list_term_summaries(client, pool_id: str) -> list[dict]:
    result = []
    token = None
    seen = set()
    for _ in range(64):
        params = {"MaxResults": 60, "UserPoolId": pool_id}
        if token is not None:
            params["NextToken"] = token
        response = client.list_terms(**params)
        result.extend(response.get("Terms", []))
        token = response.get("NextToken")
        if token is None:
            return sorted(result, key=lambda item: item["TermsId"])
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError("The service returned an invalid terms continuation token")
        seen.add(token)
    raise RuntimeError("The terms listing exceeded the page limit")


def _find_terms(client, pool_id: str, client_id: str, terms_name: str) -> dict | None:
    for summary in _list_term_summaries(client, pool_id):
        if summary.get("TermsName") != terms_name:
            continue
        terms = client.describe_terms(TermsId=summary["TermsId"], UserPoolId=pool_id)["Terms"]
        if terms.get("ClientId") == client_id:
            return terms
    return None


def _terms_match(desired: dict, actual: dict) -> bool:
    return all(
        actual.get(name) == desired.get(name)
        for name in (
            "ClientId",
            "Enforcement",
            "Links",
            "TermsName",
            "TermsSource",
            "UserPoolId",
        )
    )
