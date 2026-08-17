import uuid
from datetime import UTC, datetime

from localstack.aws.api import RequestContext
from localstack.services.apigatewayv2.models import apigatewayv2_stores
from localstack.services.apigatewayv2.provider import ApiGatewayV2Provider
from localstack.state import pickle
from localstack.state.inspect import ServiceBackendCollectorVisitor


def test_api_authorizer_and_hmac_cursor_survive_pickle_restart(monkeypatch):
    import localstack.services.apigatewayv2.provider as provider_module

    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    context.partition = "aws"
    provider = ApiGatewayV2Provider(clock=lambda: datetime(2026, 8, 10, tzinfo=UTC))
    try:
        api_ids = [
            provider.create_api(
                context,
                {"Name": name, "ProtocolType": "HTTP"},
            )["ApiId"]
            for name in ("persistent-one", "persistent-two")
        ]
        authorizer = provider.create_authorizer(
            context,
            {
                "ApiId": api_ids[0],
                "AuthorizerType": "JWT",
                "IdentitySource": ["$request.header.Authorization"],
                "JwtConfiguration": {
                    "Audience": ["amplify"],
                    "Issuer": ("https://cognito-idp.us-east-1.amazonaws.com/us-east-1_persistent"),
                },
                "Name": "persistent",
            },
        )
        integration = provider.create_integration(
            context,
            {
                "ApiId": api_ids[0],
                "IntegrationType": "HTTP_PROXY",
                "IntegrationMethod": "GET",
                "IntegrationUri": "https://backend.example.test/persistent",
            },
        )
        route = provider.create_route(
            context,
            {
                "ApiId": api_ids[0],
                "AuthorizationType": "JWT",
                "AuthorizerId": authorizer["AuthorizerId"],
                "RouteKey": "GET /persistent",
                "Target": f"integrations/{integration['IntegrationId']}",
            },
        )
        deployment = provider.create_deployment(context, {"ApiId": api_ids[0]})
        provider.create_stage(
            context,
            {
                "ApiId": api_ids[0],
                "DeploymentId": deployment["DeploymentId"],
                "StageName": "$default",
            },
        )
        first = provider.get_apis(context, {"MaxResults": "1"})

        restored = pickle.loads(pickle.dumps(apigatewayv2_stores))
        monkeypatch.setattr(provider_module, "apigatewayv2_stores", restored)
        restarted = ApiGatewayV2Provider()
        second = restarted.get_apis(
            context,
            {"MaxResults": "1", "NextToken": first["NextToken"]},
        )

        assert {first["Items"][0]["ApiId"], second["Items"][0]["ApiId"]} == set(api_ids)
        assert (
            restarted.get_authorizer(
                context,
                {"ApiId": api_ids[0], "AuthorizerId": authorizer["AuthorizerId"]},
            )["Name"]
            == "persistent"
        )
        assert (
            restarted.get_integration(
                context,
                {"ApiId": api_ids[0], "IntegrationId": integration["IntegrationId"]},
            )["IntegrationUri"]
            == "https://backend.example.test/persistent"
        )
        assert (
            restarted.get_route(
                context,
                {"ApiId": api_ids[0], "RouteId": route["RouteId"]},
            )["Target"]
            == f"integrations/{integration['IntegrationId']}"
        )
        assert (
            restarted.get_stage(
                context,
                {"ApiId": api_ids[0], "StageName": "$default"},
            )["DeploymentId"]
            == deployment["DeploymentId"]
        )
        with restored.lock:
            frozen = (
                restored[context.account_id][context.region]
                .apis[api_ids[0]]
                .deployments[deployment["DeploymentId"]]
                .snapshot
            )
            assert frozen.routes[route["RouteId"]].properties["RouteKey"] == "GET /persistent"
        assert len(restored[context.account_id][context.region].pagination_secret) == 32
    finally:
        with apigatewayv2_stores.lock:
            apigatewayv2_stores.pop(context.account_id, None)


def test_provider_persistence_visits_only_native_store():
    visitor = ServiceBackendCollectorVisitor()

    ApiGatewayV2Provider().accept_state_visitor(visitor)

    assert visitor.store is apigatewayv2_stores
    assert visitor.backend_dict is None
