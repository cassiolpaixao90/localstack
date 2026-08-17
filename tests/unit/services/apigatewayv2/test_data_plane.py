import copy
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import BoundedSemaphore, Event

import pytest
import requests
from rolo import Router
from werkzeug.exceptions import NotFound

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.http import Request, Response
from localstack.services.apigateway.next_gen.execute_api.router import (
    ApiGatewayEndpoint,
    ApiGatewayRouter,
    get_api_gateway_router,
)
from localstack.services.apigateway.next_gen.provider import ApigatewayNextGenProvider
from localstack.services.apigatewayv2 import execute_api as execute_api_v2
from localstack.services.apigatewayv2.execute_api import HttpApiGatewayEndpoint
from localstack.services.apigatewayv2.models import apigatewayv2_stores
from localstack.services.apigatewayv2.provider import ApiGatewayV2Provider
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.plugins import Service


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    value.partition = "aws"
    yield value
    with apigatewayv2_stores.lock:
        apigatewayv2_stores.pop(value.account_id, None)
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(value.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(value.account_id, None)


@pytest.fixture
def provider():
    return ApiGatewayV2Provider(clock=lambda: datetime(2026, 8, 10, 12, 0, tzinfo=UTC))


def _native_token(context):
    provider = CognitoIdpProvider()
    pool = provider.create_user_pool(context, {"PoolName": "http-data-plane"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "UserPoolId": pool["Id"],
            "ClientName": "amplify-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "web@example.test",
            "TemporaryPassword": "Temporary9!",
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "web@example.test",
            "Password": "Permanent9!",
            "Permanent": True,
        },
    )
    provider.create_group(context, {"UserPoolId": pool["Id"], "GroupName": "trainer"})
    provider.admin_add_user_to_group(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "web@example.test",
            "GroupName": "trainer",
        },
    )
    tokens = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {
                "USERNAME": "web@example.test",
                "PASSWORD": "Permanent9!",
            },
        },
    )["AuthenticationResult"]
    issuer = f"https://cognito-idp.{context.region}.amazonaws.com/{pool['Id']}"
    return client["ClientId"], issuer, tokens["IdToken"]


def _deployed_api(
    provider,
    context,
    client_id,
    issuer,
    *,
    stage_name="prod",
    api_fields=None,
    integration_fields=None,
    route_key="GET /orders",
):
    api = provider.create_api(
        context,
        {"Name": "orders", "ProtocolType": "HTTP", **(api_fields or {})},
    )
    authorizer = provider.create_authorizer(
        context,
        {
            "ApiId": api["ApiId"],
            "AuthorizerType": "JWT",
            "IdentitySource": ["$request.header.Authorization"],
            "JwtConfiguration": {"Audience": [client_id], "Issuer": issuer},
            "Name": "users",
        },
    )
    integration_request = {
        "ApiId": api["ApiId"],
        "ConnectionType": "INTERNET",
        "IntegrationMethod": "ANY",
        "IntegrationType": "HTTP_PROXY",
        "IntegrationUri": "https://backend.example.test/orders",
        "PayloadFormatVersion": "1.0",
        "TimeoutInMillis": 2500,
    }
    integration_request.update(integration_fields or {})
    integration = provider.create_integration(
        context,
        integration_request,
    )
    route = provider.create_route(
        context,
        {
            "ApiId": api["ApiId"],
            "AuthorizationScopes": [],
            "AuthorizationType": "JWT",
            "AuthorizerId": authorizer["AuthorizerId"],
            "RouteKey": route_key,
            "Target": f"integrations/{integration['IntegrationId']}",
        },
    )
    deployment = provider.create_deployment(context, {"ApiId": api["ApiId"]})
    stage = provider.create_stage(
        context,
        {
            "ApiId": api["ApiId"],
            "AutoDeploy": False,
            "DeploymentId": deployment["DeploymentId"],
            "StageName": stage_name,
        },
    )
    return api, authorizer, integration, route, deployment, stage


def _assert_error(code, status, call):
    with pytest.raises(CommonServiceException) as raised:
        call()
    assert raised.value.code == code
    assert raised.value.status_code == status


def test_dispatch_exposes_complete_minimal_deployable_http_api_surface(provider):
    operations = set(Service.for_provider(provider).skeleton.dispatch_table)

    assert {
        "CreateIntegration",
        "GetIntegration",
        "GetIntegrations",
        "UpdateIntegration",
        "DeleteIntegration",
        "CreateRoute",
        "GetRoute",
        "GetRoutes",
        "UpdateRoute",
        "DeleteRoute",
        "CreateDeployment",
        "GetDeployment",
        "GetDeployments",
        "DeleteDeployment",
        "CreateStage",
        "GetStage",
        "GetStages",
        "UpdateStage",
        "DeleteStage",
    } <= operations
    assert all(
        not handler.expand_parameters
        for operation, handler in Service.for_provider(provider).skeleton.dispatch_table.items()
        if operation in operations
    )


def test_apigateway_v1_and_v2_share_one_idempotent_execute_api_router(provider):
    router = get_api_gateway_router()
    Service.for_provider(provider)
    registered = list(router.registered_rules)

    Service.for_provider(ApiGatewayV2Provider())

    assert registered
    assert router.registered_rules == registered
    assert ApigatewayNextGenProvider().router is router


def test_resource_chain_crud_references_and_deployment_snapshot(provider, context):
    client_id, issuer, _ = _native_token(context)
    api, _, integration, route, deployment, stage = _deployed_api(
        provider, context, client_id, issuer
    )

    assert integration == {
        "ApiGatewayManaged": False,
        "ConnectionType": "INTERNET",
        "IntegrationId": integration["IntegrationId"],
        "IntegrationMethod": "ANY",
        "IntegrationType": "HTTP_PROXY",
        "IntegrationUri": "https://backend.example.test/orders",
        "PayloadFormatVersion": "1.0",
        "TimeoutInMillis": 2500,
    }
    assert route["AuthorizationType"] == "JWT"
    assert route["Target"] == f"integrations/{integration['IntegrationId']}"
    assert deployment["DeploymentStatus"] == "DEPLOYED"
    assert deployment["AutoDeployed"] is False
    assert stage["DeploymentId"] == deployment["DeploymentId"]
    assert provider.get_integrations(context, {"ApiId": api["ApiId"]})["Items"] == [integration]
    assert provider.get_routes(context, {"ApiId": api["ApiId"]})["Items"] == [route]
    assert provider.get_deployments(context, {"ApiId": api["ApiId"]})["Items"] == [deployment]
    assert provider.get_stages(context, {"ApiId": api["ApiId"]})["Items"] == [stage]

    _assert_error(
        "ConflictException",
        409,
        lambda: provider.delete_integration(
            context, {"ApiId": api["ApiId"], "IntegrationId": integration["IntegrationId"]}
        ),
    )
    _assert_error(
        "ConflictException",
        409,
        lambda: provider.delete_deployment(
            context, {"ApiId": api["ApiId"], "DeploymentId": deployment["DeploymentId"]}
        ),
    )

    provider.update_integration(
        context,
        {
            "ApiId": api["ApiId"],
            "IntegrationId": integration["IntegrationId"],
            "IntegrationUri": "https://changed.example.test/orders",
        },
    )
    with apigatewayv2_stores.lock:
        model = apigatewayv2_stores[context.account_id][context.region].apis[api["ApiId"]]
        frozen = model.deployments[deployment["DeploymentId"]].snapshot
        assert frozen.integrations[integration["IntegrationId"]].properties["IntegrationUri"] == (
            "https://backend.example.test/orders"
        )

    provider.delete_stage(context, {"ApiId": api["ApiId"], "StageName": "prod"})
    provider.delete_deployment(
        context, {"ApiId": api["ApiId"], "DeploymentId": deployment["DeploymentId"]}
    )
    provider.delete_route(context, {"ApiId": api["ApiId"], "RouteId": route["RouteId"]})
    provider.delete_integration(
        context, {"ApiId": api["ApiId"], "IntegrationId": integration["IntegrationId"]}
    )


def test_real_invoke_requires_native_cognito_jwt_before_http_proxy(monkeypatch, provider, context):
    client_id, issuer, token = _native_token(context)
    api, *_ = _deployed_api(provider, context, client_id, issuer)
    upstream_calls = []

    def proxy(**kwargs):
        upstream_calls.append(kwargs)
        response = requests.Response()
        response.status_code = 202
        response._content = b'{"accepted":true}'
        response.headers["Content-Type"] = "application/json"
        return response

    monkeypatch.setattr("localstack.services.apigatewayv2.execute_api.requests.request", proxy)
    endpoint = HttpApiGatewayEndpoint()

    unauthorized = endpoint(
        Request(method="GET", path="/orders"),
        api_id=api["ApiId"],
        stage="prod",
        path="orders",
    )
    assert unauthorized.status_code == 401
    assert upstream_calls == []

    authorized = endpoint(
        Request(
            method="GET",
            path="/orders",
            query_string="limit=2",
            headers={"Authorization": f"Bearer {token}", "X-Trace": "one"},
        ),
        api_id=api["ApiId"],
        stage="prod",
        path="orders",
    )

    assert authorized.status_code == 202
    assert json.loads(authorized.data) == {"accepted": True}
    assert len(upstream_calls) == 1
    assert upstream_calls[0]["method"] == "GET"
    assert upstream_calls[0]["url"] == "https://backend.example.test/orders"
    assert upstream_calls[0]["params"] == {"limit": "2"}
    assert upstream_calls[0]["timeout"] == 2.5


def test_custom_domain_mapping_selects_longest_key_and_strips_base_path(
    monkeypatch, provider, context
):
    client_id, issuer, token = _native_token(context)
    api, *_ = _deployed_api(provider, context, client_id, issuer)
    certificate_arn = (
        f"arn:{context.partition}:acm:{context.region}:{context.account_id}:certificate/"
        "11111111-2222-3333-4444-555555555555"
    )
    provider._certificate_resolver = lambda *_: {
        "CertificateArn": certificate_arn,
        "DomainName": "api.example.test",
        "Status": "ISSUED",
        "SubjectAlternativeNames": ["api.example.test"],
    }
    provider.create_domain_name(
        context,
        {
            "DomainName": "api.example.test",
            "DomainNameConfigurations": [{"CertificateArn": certificate_arn}],
        },
    )
    provider.create_api_mapping(
        context,
        {
            "ApiId": api["ApiId"],
            "ApiMappingKey": "v1",
            "DomainName": "api.example.test",
            "Stage": "prod",
        },
    )
    upstream_calls = []

    def proxy(**kwargs):
        upstream_calls.append(kwargs)
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"custom":true}'
        return response

    monkeypatch.setattr("localstack.services.apigatewayv2.execute_api.requests.request", proxy)
    response = HttpApiGatewayEndpoint()(
        Request(
            method="GET",
            path="/v1/orders",
            scheme="https",
            headers={"Authorization": f"Bearer {token}", "Host": "api.example.test"},
        ),
        custom_domain="api.example.test",
        path="v1/orders",
    )

    assert response.status_code == 200
    assert json.loads(response.data) == {"custom": True}
    assert len(upstream_calls) == 1
    assert upstream_calls[0]["method"] == "GET"
    assert upstream_calls[0]["url"] == "https://backend.example.test/orders"
    assert upstream_calls[0]["params"] == {}
    assert upstream_calls[0]["timeout"] == 2.5
    provider.delete_domain_name(context, {"DomainName": "api.example.test"})


def test_custom_domain_router_dispatches_exact_and_wildcard_hosts_and_unregisters():
    calls = []

    def http_endpoint(request, **kwargs):
        calls.append((request.path, kwargs))
        return Response("custom", status=200)

    router = Router(dispatcher=lambda request, endpoint, arguments: endpoint(request, **arguments))
    api_router = ApiGatewayRouter(
        router=router,
        handler=ApiGatewayEndpoint(http_endpoint=http_endpoint),
    )
    api_router.register_custom_domain("api.example.test")
    api_router.register_custom_domain("*.apps.example.test")

    exact = router.dispatch(
        Request("GET", "/v1/orders", scheme="https", server=("api.example.test", 4566))
    )
    wildcard = router.dispatch(
        Request("GET", "/orders", scheme="https", server=("tenant.apps.example.test", 4566))
    )

    assert exact.data == b"custom"
    assert wildcard.data == b"custom"
    assert calls == [
        ("/v1/orders", {"custom_domain": "api.example.test", "path": "v1/orders"}),
        ("/orders", {"custom_domain": "*.apps.example.test", "path": "orders"}),
    ]
    api_router.unregister_custom_domain("api.example.test")
    with pytest.raises(NotFound):
        router.dispatch(Request("GET", "/v1/orders", server=("api.example.test", 4566)))


def test_custom_domain_rejects_plain_http_before_mapping_or_integration_lookup():
    endpoint = HttpApiGatewayEndpoint()

    response = endpoint(
        Request("GET", "/v1/orders", scheme="http", server=("api.example.test", 4566)),
        custom_domain="api.example.test",
        path="v1/orders",
    )

    assert response.status_code == 403
    assert json.loads(response.data) == {"message": "Forbidden"}


def test_custom_domain_router_registration_is_atomic_when_second_rule_fails():
    class FailingRouter:
        def __init__(self):
            self.rules = []

        def add(self, **kwargs):
            if self.rules:
                raise RuntimeError("second rule rejected")
            rule = object()
            self.rules.append(rule)
            return rule

        def remove(self, rules):
            for rule in rules:
                self.rules.remove(rule)

    router = FailingRouter()
    api_router = ApiGatewayRouter(router=router)

    with pytest.raises(RuntimeError, match="second rule rejected"):
        api_router.register_custom_domain("api.example.test")

    assert router.rules == []
    assert api_router.custom_domain_rules == {}


def test_shared_execute_api_endpoint_dispatches_deployed_http_api_default_stage(
    monkeypatch, provider, context
):
    client_id, issuer, token = _native_token(context)
    api, *_ = _deployed_api(provider, context, client_id, issuer, stage_name="$default")

    response = requests.Response()
    response.status_code = 200
    response._content = b"default-stage"
    monkeypatch.setattr(
        "localstack.services.apigatewayv2.execute_api.requests.request", lambda **_: response
    )

    result = ApiGatewayEndpoint()(
        Request(method="GET", path="/orders", headers={"Authorization": f"Bearer {token}"}),
        api_id=api["ApiId"],
        stage="orders",
        path="",
    )

    assert result.status_code == 200
    assert result.data == b"default-stage"


def test_cors_preflight_is_independent_from_jwt_and_backend(monkeypatch, provider, context):
    client_id, issuer, _ = _native_token(context)
    api, *_ = _deployed_api(
        provider,
        context,
        client_id,
        issuer,
        api_fields={
            "CorsConfiguration": {
                "AllowHeaders": ["authorization"],
                "AllowMethods": ["GET", "OPTIONS"],
                "AllowOrigins": ["https://app.example.test"],
                "MaxAge": 600,
            }
        },
    )
    monkeypatch.setattr(
        "localstack.services.apigatewayv2.execute_api.requests.request",
        lambda **_: pytest.fail("preflight must not invoke the integration"),
    )

    result = HttpApiGatewayEndpoint()(
        Request(
            method="OPTIONS",
            path="/orders",
            headers={
                "Access-Control-Request-Method": "GET",
                "Origin": "https://app.example.test",
            },
        ),
        api_id=api["ApiId"],
        stage="prod",
        path="orders",
    )

    assert result.status_code == 204
    assert result.headers["Access-Control-Allow-Origin"] == "https://app.example.test"
    assert result.headers["Access-Control-Max-Age"] == "600"

    unauthorized = HttpApiGatewayEndpoint()(
        Request(
            method="GET",
            path="/orders",
            headers={"Origin": "https://app.example.test"},
        ),
        api_id=api["ApiId"],
        stage="prod",
        path="orders",
    )
    assert unauthorized.status_code == 401
    assert unauthorized.headers["Access-Control-Allow-Origin"] == "https://app.example.test"


def test_native_cognito_token_reaches_local_lambda_payload_v2(monkeypatch, provider, context):
    client_id, issuer, token = _native_token(context)
    function_arn = (
        f"arn:aws:lambda:{context.region}:{context.account_id}:function:billgym-http-handler"
    )
    api, *_ = _deployed_api(
        provider,
        context,
        client_id,
        issuer,
        integration_fields={
            "IntegrationMethod": "POST",
            "IntegrationType": "AWS_PROXY",
            "IntegrationUri": function_arn,
            "PayloadFormatVersion": "2.0",
            "TimeoutInMillis": 200,
        },
        route_key="GET /v1/exercises/{id}",
    )
    calls = []

    def invoke_lambda(function_arn, event, source_arn, credentials=None):
        assert credentials is None
        calls.append((function_arn, json.loads(event), source_arn))
        return json.dumps(
            {
                "statusCode": 201,
                "headers": {"content-type": "application/json", "x-handler": "billgym"},
                "cookies": ["session=rotated; Secure; HttpOnly"],
                "body": json.dumps({"created": True}),
                "isBase64Encoded": False,
            }
        ).encode()

    monkeypatch.setattr(
        "localstack.services.apigateway.next_gen.execute_api.integrations.aws."
        "RestApiAwsProxyIntegration.call_lambda",
        invoke_lambda,
    )
    expected_source_arn = (
        f"arn:aws:execute-api:{context.region}:{context.account_id}:"
        f"{api['ApiId']}/prod/GET/v1/exercises/{{id}}"
    )
    exact_permission = {
        "Action": "lambda:InvokeFunction",
        "Effect": "Allow",
        "Principal": {"Service": "apigateway.amazonaws.com"},
        "Resource": function_arn,
        "Condition": {"ArnLike": {"AWS:SourceArn": expected_source_arn}},
    }
    monkeypatch.setattr(
        execute_api_v2,
        "_function_policy_statements",
        lambda _: (exact_permission,),
    )
    response = HttpApiGatewayEndpoint()(
        Request(
            method="GET",
            path="/v1/exercises/squat-01",
            query_string="limit=2&limit=3",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Cookie": "device=mobile",
            },
        ),
        api_id=api["ApiId"],
        stage="prod",
        path="v1/exercises/squat-01",
    )

    assert response.status_code == 201
    assert json.loads(response.data) == {"created": True}
    assert response.headers["x-handler"] == "billgym"
    assert response.headers.getlist("Set-Cookie") == ["session=rotated; Secure; HttpOnly"]
    assert len(calls) == 1
    received_arn, event, source_arn = calls[0]
    assert received_arn == function_arn
    assert source_arn == expected_source_arn
    assert event["version"] == "2.0"
    assert event["routeKey"] == "GET /v1/exercises/{id}"
    assert event["rawPath"] == "/v1/exercises/squat-01"
    assert event["pathParameters"] == {"id": "squat-01"}
    assert event["rawQueryString"] == "limit=2&limit=3"
    assert event["queryStringParameters"] == {"limit": "2,3"}
    assert event["cookies"] == ["device=mobile"]
    assert event["requestContext"]["authorizer"]["jwt"]["claims"]["aud"] == client_id
    assert event["requestContext"]["authorizer"]["jwt"]["claims"]["cognito:groups"] == ("[trainer]")
    assert event["requestContext"]["authorizer"]["jwt"]["scopes"] == []
    assert event["isBase64Encoded"] is False

    wrong_source_permission = copy.deepcopy(exact_permission)
    wrong_source_permission["Condition"]["ArnLike"]["AWS:SourceArn"] = (
        f"arn:aws:execute-api:{context.region}:{context.account_id}:wrong-api/*/GET/*"
    )
    monkeypatch.setattr(
        execute_api_v2,
        "_function_policy_statements",
        lambda _: (wrong_source_permission,),
    )
    denied = HttpApiGatewayEndpoint()(
        Request(
            method="GET",
            path="/v1/exercises/squat-01",
            headers={"Authorization": f"Bearer {token}"},
        ),
        api_id=api["ApiId"],
        stage="prod",
        path="v1/exercises/squat-01",
    )
    assert denied.status_code == 500
    assert len(calls) == 1

    monkeypatch.setattr(execute_api_v2, "_function_policy_statements", lambda _: ())
    missing = HttpApiGatewayEndpoint()(
        Request(
            method="GET",
            path="/v1/exercises/squat-01",
            headers={"Authorization": f"Bearer {token}"},
        ),
        api_id=api["ApiId"],
        stage="prod",
        path="v1/exercises/squat-01",
    )
    assert missing.status_code == 500
    assert len(calls) == 1

    malformed = HttpApiGatewayEndpoint(lambda_invoker=lambda *_: b"not-json")(
        Request(
            method="GET",
            path="/v1/exercises/squat-01",
            headers={"Authorization": f"Bearer {token}"},
        ),
        api_id=api["ApiId"],
        stage="prod",
        path="v1/exercises/squat-01",
    )
    assert malformed.status_code == 502

    def slow_lambda(*_):
        time.sleep(0.3)
        return b"{}"

    timed_out = HttpApiGatewayEndpoint(lambda_invoker=slow_lambda)(
        Request(
            method="GET",
            path="/v1/exercises/squat-01",
            headers={"Authorization": f"Bearer {token}"},
        ),
        api_id=api["ApiId"],
        stage="prod",
        path="v1/exercises/squat-01",
    )
    assert timed_out.status_code == 504

    started = Event()
    release = Event()

    def blocked_lambda(*_):
        started.set()
        release.wait(0.5)
        return b"{}"

    monkeypatch.setattr(
        "localstack.services.apigatewayv2.execute_api._LAMBDA_ADMISSION",
        BoundedSemaphore(1),
    )
    bounded_endpoint = HttpApiGatewayEndpoint(lambda_invoker=blocked_lambda)

    def invocation():
        return bounded_endpoint(
            Request(
                method="GET",
                path="/v1/exercises/squat-01",
                headers={"Authorization": f"Bearer {token}"},
            ),
            api_id=api["ApiId"],
            stage="prod",
            path="v1/exercises/squat-01",
        )

    with ThreadPoolExecutor(max_workers=1) as callers:
        admitted = callers.submit(invocation)
        assert started.wait(0.2)
        overflow = invocation()
        assert overflow.status_code == 503
        release.set()
        assert admitted.result().status_code == 200


def test_billgym_default_stage_auto_deploys_lambda_routes_and_stage_settings(provider, context):
    api = provider.create_api(context, {"Name": "billgym", "ProtocolType": "HTTP"})
    stage = provider.create_stage(
        context,
        {
            "AccessLogSettings": {
                "DestinationArn": (
                    f"arn:aws:logs:{context.region}:{context.account_id}:log-group:billgym-api"
                ),
                "Format": '{"requestId":"$context.requestId"}',
            },
            "ApiId": api["ApiId"],
            "AutoDeploy": True,
            "DefaultRouteSettings": {
                "ThrottlingBurstLimit": 100,
                "ThrottlingRateLimit": 50,
            },
            "StageName": "$default",
        },
    )
    function_arn = f"arn:aws:lambda:{context.region}:{context.account_id}:function:billgym-workouts"
    integration = provider.create_integration(
        context,
        {
            "ApiId": api["ApiId"],
            "IntegrationType": "AWS_PROXY",
            "IntegrationUri": function_arn,
            "PayloadFormatVersion": "2.0",
        },
    )
    route = provider.create_route(
        context,
        {
            "ApiId": api["ApiId"],
            "AuthorizationType": "NONE",
            "RouteKey": "PATCH /v1/workout-sessions/{id}",
            "Target": f"integrations/{integration['IntegrationId']}",
        },
    )

    refreshed = provider.get_stage(context, {"ApiId": api["ApiId"], "StageName": "$default"})
    assert stage["AutoDeploy"] is True
    assert refreshed["DeploymentId"] != stage["DeploymentId"]
    assert refreshed["DefaultRouteSettings"] == {
        "ThrottlingBurstLimit": 100,
        "ThrottlingRateLimit": 50,
    }
    with apigatewayv2_stores.lock:
        model = apigatewayv2_stores[context.account_id][context.region].apis[api["ApiId"]]
        snapshot = model.deployments[refreshed["DeploymentId"]].snapshot
        assert snapshot.routes[route["RouteId"]].properties["RouteKey"] == (
            "PATCH /v1/workout-sessions/{id}"
        )
        assert (
            snapshot.integrations[integration["IntegrationId"]].properties["IntegrationUri"]
            == function_arn
        )

    provider.update_stage(
        context,
        {
            "ApiId": api["ApiId"],
            "DefaultRouteSettings": {
                "ThrottlingBurstLimit": 1,
                "ThrottlingRateLimit": 0.001,
            },
            "StageName": "$default",
        },
    )
    endpoint = HttpApiGatewayEndpoint(lambda_invoker=lambda *_: b"{}")

    def invoke():
        return endpoint(
            Request(method="PATCH", path="/v1/workout-sessions/session-1"),
            api_id=api["ApiId"],
            stage="$default",
            path="v1/workout-sessions/session-1",
        )

    assert invoke().status_code == 200
    assert invoke().status_code == 429


def test_lambda_integration_rejects_cross_scope_arns_before_invocation(provider, context):
    api = provider.create_api(context, {"Name": "scoped", "ProtocolType": "HTTP"})
    wrong_scope_arns = [
        f"arn:aws:lambda:eu-west-1:{context.account_id}:function:handler",
        f"arn:aws:lambda:{context.region}:999999999999:function:handler",
        f"arn:aws-cn:lambda:{context.region}:{context.account_id}:function:handler",
    ]

    for function_arn in wrong_scope_arns:
        _assert_error(
            "BadRequestException",
            400,
            lambda function_arn=function_arn: provider.create_integration(
                context,
                {
                    "ApiId": api["ApiId"],
                    "IntegrationType": "AWS_PROXY",
                    "IntegrationUri": function_arn,
                    "PayloadFormatVersion": "2.0",
                },
            ),
        )

    assert provider.get_integrations(context, {"ApiId": api["ApiId"]}) == {"Items": []}


@pytest.mark.parametrize(
    "factory,payload",
    [
        (
            "integration",
            {"IntegrationType": "AWS_PROXY", "IntegrationUri": "arn:aws:lambda:x"},
        ),
        (
            "integration",
            {"IntegrationType": "HTTP_PROXY", "IntegrationUri": "file:///etc/passwd"},
        ),
        (
            "integration",
            {
                "IntegrationType": "HTTP_PROXY",
                "IntegrationUri": "https://backend.example.test",
                "PayloadFormatVersion": "2.0",
            },
        ),
        ("route", {"RouteKey": "GET /missing", "Target": "integrations/deadbeef"}),
    ],
)
def test_unsupported_data_plane_features_fail_closed_atomically(
    provider, context, factory, payload
):
    api = provider.create_api(context, {"Name": "fail-closed", "ProtocolType": "HTTP"})
    request = {"ApiId": api["ApiId"], **payload}

    if factory == "integration":
        _assert_error(
            "BadRequestException", 400, lambda: provider.create_integration(context, request)
        )
    else:
        _assert_error("BadRequestException", 400, lambda: provider.create_route(context, request))

    assert provider.get_integrations(context, {"ApiId": api["ApiId"]}) == {"Items": []}
    assert provider.get_routes(context, {"ApiId": api["ApiId"]}) == {"Items": []}
