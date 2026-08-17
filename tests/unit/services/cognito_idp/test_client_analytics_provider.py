import pickle
import uuid
from types import SimpleNamespace

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolclient import (
    CognitoUserPoolClientProvider,
)


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    yield value
    with cognito_idp_stores.lock:
        cognito_idp_stores.pop(value.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def _project_arn(context):
    return (
        f"arn:{context.partition}:mobiletargeting:{context.region}:"
        f"{context.account_id}:apps/abcdef0123456789"
    )


def _pinpoint_connection(context, *, ids=("abcdef0123456789", "abcdef0123456789")):
    values = iter(ids)

    class Pinpoint:
        def get_app(self, **_request):
            return {
                "ApplicationResponse": {
                    "Arn": _project_arn(context),
                    "Id": next(values),
                }
            }

    return SimpleNamespace(iam=None, pinpoint=Pinpoint())


def test_client_analytics_direct_api_round_trip_persistence_and_reset(
    context, provider, monkeypatch
):
    monkeypatch.setattr(
        provider_module,
        "connect_to",
        lambda **_: _pinpoint_connection(context),
    )
    pool = provider.create_user_pool(context, {"PoolName": "analytics-users"})["UserPool"]
    created = provider.create_user_pool_client(
        context,
        {
            "AnalyticsConfiguration": {
                "ApplicationArn": _project_arn(context),
                "UserDataShared": True,
            },
            "ClientName": "analytics-client",
            "EnablePropagateAdditionalUserContextData": True,
            "ExplicitAuthFlows": ["CUSTOM_AUTH_FLOW_ONLY", "USER_PASSWORD_AUTH"],
            "GenerateSecret": True,
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]

    assert created["AnalyticsConfiguration"] == {
        "ApplicationArn": _project_arn(context),
        "UserDataShared": True,
    }
    assert created["EnablePropagateAdditionalUserContextData"] is True
    assert created["ExplicitAuthFlows"] == [
        "ALLOW_CUSTOM_AUTH",
        "ALLOW_USER_PASSWORD_AUTH",
    ]
    described = provider.describe_user_pool_client(
        context,
        {"ClientId": created["ClientId"], "UserPoolId": pool["Id"]},
    )["UserPoolClient"]
    assert described["AnalyticsConfiguration"] == created["AnalyticsConfiguration"]
    assert "abcdef0123456789" in pickle.dumps(provider.get_store(context)).decode("latin-1")

    reset = provider.update_user_pool_client(
        context,
        {
            "ClientId": created["ClientId"],
            "ClientName": "analytics-client",
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    assert "AnalyticsConfiguration" not in reset
    assert reset["EnablePropagateAdditionalUserContextData"] is False
    assert reset["ExplicitAuthFlows"] == [
        "ALLOW_CUSTOM_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
        "ALLOW_USER_SRP_AUTH",
    ]


def test_client_analytics_requires_secret_and_aba_fails_without_mutation(
    context, provider, monkeypatch
):
    pool = provider.create_user_pool(context, {"PoolName": "analytics-guards"})["UserPool"]
    with pytest.raises(CommonServiceException, match="client secret"):
        provider.create_user_pool_client(
            context,
            {
                "ClientName": "no-secret",
                "EnablePropagateAdditionalUserContextData": True,
                "UserPoolId": pool["Id"],
            },
        )

    monkeypatch.setattr(
        provider_module,
        "connect_to",
        lambda **_: _pinpoint_connection(
            context,
            ids=("abcdef0123456789", "ffffffffffffffff"),
        ),
    )
    with pytest.raises(CommonServiceException, match="changed"):
        provider.create_user_pool_client(
            context,
            {
                "AnalyticsConfiguration": {"ApplicationArn": _project_arn(context)},
                "ClientName": "aba-client",
                "UserPoolId": pool["Id"],
            },
        )
    assert (
        provider.list_user_pool_clients(context, {"MaxResults": 60, "UserPoolId": pool["Id"]})[
            "UserPoolClients"
        ]
        == []
    )


def test_client_analytics_cfn_round_trip_against_native_provider(context, provider, monkeypatch):
    connection = _pinpoint_connection(context)
    monkeypatch.setattr(provider_module, "connect_to", lambda **_: connection)
    pool = provider.create_user_pool(context, {"PoolName": "analytics-cfn"})["UserPool"]

    class NativeClient:
        def __getattr__(self, name):
            handler = getattr(provider, name)
            return lambda **request: handler(context, request)

    request = SimpleNamespace(
        account_id=context.account_id,
        aws_client_factory=SimpleNamespace(
            cognito_idp=NativeClient(),
            iam=None,
            pinpoint=_pinpoint_connection(context).pinpoint,
        ),
        custom_context={},
        desired_state={
            "AnalyticsConfiguration": {"ApplicationArn": _project_arn(context)},
            "ClientName": "analytics-cfn-client",
            "EnablePropagateAdditionalUserContextData": True,
            "GenerateSecret": True,
            "UserPoolId": pool["Id"],
        },
        logical_resource_id="Client",
        previous_state=None,
        region_name=context.region,
        stack_name="analytics",
    )
    resource_provider = CognitoUserPoolClientProvider()

    created = resource_provider.create(request)

    assert created.status == OperationStatus.SUCCESS
    assert created.resource_model["AnalyticsConfiguration"] == {
        "ApplicationArn": _project_arn(context),
        "UserDataShared": False,
    }
    assert created.resource_model["EnablePropagateAdditionalUserContextData"] is True

    request.previous_state = created.resource_model
    request.desired_state = {
        "ClientId": created.resource_model["ClientId"],
        "ClientName": "analytics-cfn-client",
        "GenerateSecret": True,
        "UserPoolId": pool["Id"],
    }
    reset = resource_provider.update(request)
    assert reset.status == OperationStatus.SUCCESS
    assert "AnalyticsConfiguration" not in reset.resource_model
    assert reset.resource_model["EnablePropagateAdditionalUserContextData"] is False


def test_client_analytics_update_detects_client_race(context, provider, monkeypatch):
    pool = provider.create_user_pool(context, {"PoolName": "analytics-race"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {"ClientName": "before", "UserPoolId": pool["Id"]},
    )["UserPoolClient"]
    calls = 0

    class Pinpoint:
        def get_app(self, **_request):
            nonlocal calls
            calls += 1
            if calls == 2:
                provider.update_user_pool_client(
                    context,
                    {
                        "ClientId": client["ClientId"],
                        "ClientName": "concurrent",
                        "UserPoolId": pool["Id"],
                    },
                )
            return {
                "ApplicationResponse": {
                    "Arn": _project_arn(context),
                    "Id": "abcdef0123456789",
                }
            }

    monkeypatch.setattr(
        provider_module,
        "connect_to",
        lambda **_: SimpleNamespace(iam=None, pinpoint=Pinpoint()),
    )
    with pytest.raises(CommonServiceException) as raced:
        provider.update_user_pool_client(
            context,
            {
                "AnalyticsConfiguration": {"ApplicationArn": _project_arn(context)},
                "ClientId": client["ClientId"],
                "ClientName": "outer",
                "UserPoolId": pool["Id"],
            },
        )
    assert raced.value.code == "ResourceConflictException"
    current = provider.describe_user_pool_client(
        context,
        {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]},
    )["UserPoolClient"]
    assert current["ClientName"] == "concurrent"
    assert "AnalyticsConfiguration" not in current


def test_additional_user_context_runtime_marker_is_gated_and_never_retains_encoded_data():
    encoded_data = "sensitive-device-fingerprint"

    disabled = provider_module._runtime_user_context(
        SimpleNamespace(enable_propagate_additional_user_context_data=False),
        {"EncodedData": encoded_data, "IpAddress": "127.0.0.1"},
    )
    enabled = provider_module._runtime_user_context(
        SimpleNamespace(enable_propagate_additional_user_context_data=True),
        {"EncodedData": encoded_data, "IpAddress": "127.0.0.1"},
    )

    assert disabled == {"IpAddress": "127.0.0.1"}
    assert enabled == {
        "IpAddress": "127.0.0.1",
        provider_module._PROPAGATED_CONTEXT_MARKER: "true",
    }
    assert encoded_data not in repr(disabled)
    assert encoded_data not in repr(enabled)
