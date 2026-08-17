import copy
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.spec import load_service
from localstack.http import Request
from localstack.services.apigatewayv2.models import apigatewayv2_stores
from localstack.services.apigatewayv2.provider import ApiGatewayV2Provider
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
    from localstack.services.apigateway.next_gen.execute_api.router import (
        get_api_gateway_router,
    )

    get_api_gateway_router().sync_custom_domains()


@pytest.fixture
def provider():
    return ApiGatewayV2Provider(clock=lambda: datetime(2026, 8, 10, 12, 0, tzinfo=UTC))


@pytest.fixture
def domain_provider(context):
    certificate_arn = (
        f"arn:{context.partition}:acm:{context.region}:{context.account_id}:certificate/"
        "11111111-2222-3333-4444-555555555555"
    )

    def certificate_resolver(_context, arn):
        if arn != certificate_arn:
            return None
        return {
            "CertificateArn": arn,
            "DomainName": "api.example.test",
            "Status": "ISSUED",
            "SubjectAlternativeNames": ["api.example.test", "*.apps.example.test"],
        }

    return (
        ApiGatewayV2Provider(
            clock=lambda: datetime(2026, 8, 10, 12, 0, tzinfo=UTC),
            certificate_resolver=certificate_resolver,
        ),
        certificate_arn,
    )


def _api(provider, context, name="orders"):
    return provider.create_api(context, {"Name": name, "ProtocolType": "HTTP"})


def _authorizer(provider, context, api_id, *, name="cognito"):
    return provider.create_authorizer(
        context,
        {
            "ApiId": api_id,
            "AuthorizerType": "JWT",
            "IdentitySource": ["$request.header.Authorization"],
            "JwtConfiguration": {
                "Audience": ["amplify-web", "amplify-mobile"],
                "Issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_nativePool",
            },
            "Name": name,
        },
    )


def _assert_error(code, status, call):
    with pytest.raises(CommonServiceException) as raised:
        call()
    assert raised.value.code == code
    assert raised.value.status_code == status


def test_service_dispatches_only_the_native_deployable_http_api_operations(provider):
    service = Service.for_provider(provider)

    assert set(service.skeleton.dispatch_table) == {
        "CreateApi",
        "CreateAuthorizer",
        "DeleteApi",
        "DeleteAuthorizer",
        "GetApi",
        "GetApis",
        "GetAuthorizer",
        "GetAuthorizers",
        "UpdateApi",
        "UpdateAuthorizer",
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
        "GetTags",
        "TagResource",
        "UntagResource",
        "UpdateStage",
        "DeleteStage",
        "CreateDomainName",
        "GetDomainName",
        "GetDomainNames",
        "UpdateDomainName",
        "DeleteDomainName",
        "CreateApiMapping",
        "GetApiMapping",
        "GetApiMappings",
        "UpdateApiMapping",
        "DeleteApiMapping",
    }
    assert "CreateVpcLink" not in service.skeleton.dispatch_table
    assert all(
        not handler.expand_parameters for handler in service.skeleton.dispatch_table.values()
    )


def test_service_catalog_loads_native_provider_without_fallback():
    from localstack.services.providers import apigatewayv2

    plugin = apigatewayv2.factory()
    assert plugin.api == "apigatewayv2"
    service = plugin.load()
    assert service.name() == "apigatewayv2"
    assert isinstance(service._provider, ApiGatewayV2Provider)
    assert set(service.skeleton.dispatch_table) == {
        "CreateApi",
        "CreateAuthorizer",
        "DeleteApi",
        "DeleteAuthorizer",
        "GetApi",
        "GetApis",
        "GetAuthorizer",
        "GetAuthorizers",
        "UpdateApi",
        "UpdateAuthorizer",
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
        "GetTags",
        "TagResource",
        "UntagResource",
        "UpdateStage",
        "DeleteStage",
        "CreateDomainName",
        "GetDomainName",
        "GetDomainNames",
        "UpdateDomainName",
        "DeleteDomainName",
        "CreateApiMapping",
        "GetApiMapping",
        "GetApiMappings",
        "UpdateApiMapping",
        "DeleteApiMapping",
    }


def test_domain_and_api_mapping_crud_tags_pagination_and_references(domain_provider, context):
    provider, certificate_arn = domain_provider
    api = _api(provider, context)
    integration = provider.create_integration(
        context,
        {
            "ApiId": api["ApiId"],
            "IntegrationType": "HTTP_PROXY",
            "IntegrationUri": "https://backend.example.test",
        },
    )
    provider.create_route(
        context,
        {
            "ApiId": api["ApiId"],
            "RouteKey": "GET /orders",
            "Target": f"integrations/{integration['IntegrationId']}",
        },
    )
    stage = provider.create_stage(
        context, {"ApiId": api["ApiId"], "AutoDeploy": True, "StageName": "prod"}
    )
    domain = provider.create_domain_name(
        context,
        {
            "DomainName": "api.example.test",
            "DomainNameConfigurations": [
                {
                    "CertificateArn": certificate_arn,
                    "EndpointType": "REGIONAL",
                    "IpAddressType": "dualstack",
                    "SecurityPolicy": "TLS_1_2",
                }
            ],
            "RoutingMode": "API_MAPPING_ONLY",
            "Tags": {"owner": "unit"},
        },
    )
    assert domain["DomainName"] == "api.example.test"
    assert domain["ApiMappingSelectionExpression"] == "$request.basepath"
    assert domain["DomainNameConfigurations"][0]["DomainNameStatus"] == "AVAILABLE"
    domain_arn = domain["DomainNameArn"]
    provider.tag_resource(context, {"ResourceArn": domain_arn, "Tags": {"env": "test"}})
    assert provider.get_tags(context, {"ResourceArn": domain_arn}) == {
        "Tags": {"env": "test", "owner": "unit"}
    }

    root = provider.create_api_mapping(
        context,
        {
            "ApiId": api["ApiId"],
            "ApiMappingKey": "",
            "DomainName": domain["DomainName"],
            "Stage": stage["StageName"],
        },
    )
    versioned = provider.create_api_mapping(
        context,
        {
            "ApiId": api["ApiId"],
            "ApiMappingKey": "v1",
            "DomainName": domain["DomainName"],
            "Stage": stage["StageName"],
        },
    )
    first = provider.get_api_mappings(
        context, {"DomainName": domain["DomainName"], "MaxResults": "1"}
    )
    assert len(first["Items"]) == 1
    assert first["NextToken"]
    second = provider.get_api_mappings(
        context,
        {
            "DomainName": domain["DomainName"],
            "MaxResults": "1",
            "NextToken": first["NextToken"],
        },
    )
    assert len(second["Items"]) == 1
    assert {first["Items"][0]["ApiMappingId"], second["Items"][0]["ApiMappingId"]} == {
        root["ApiMappingId"],
        versioned["ApiMappingId"],
    }

    updated = provider.update_api_mapping(
        context,
        {
            "ApiMappingId": versioned["ApiMappingId"],
            "ApiMappingKey": "v2/admin",
            "DomainName": domain["DomainName"],
        },
    )
    assert updated["ApiMappingKey"] == "v2/admin"
    _assert_error(
        "ConflictException",
        409,
        lambda: provider.delete_stage(
            context, {"ApiId": api["ApiId"], "StageName": stage["StageName"]}
        ),
    )
    provider.delete_domain_name(context, {"DomainName": domain["DomainName"]})
    _assert_error(
        "NotFoundException",
        404,
        lambda: provider.get_api_mapping(
            context,
            {"DomainName": domain["DomainName"], "ApiMappingId": root["ApiMappingId"]},
        ),
    )


@pytest.mark.parametrize(
    "configuration,domain_name",
    [
        ({"EndpointType": "EDGE", "SecurityPolicy": "TLS_1_2"}, "api.example.test"),
        ({"EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_0"}, "api.example.test"),
        ({"EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}, "other.example.test"),
    ],
)
def test_domain_validation_fails_closed(domain_provider, context, configuration, domain_name):
    provider, certificate_arn = domain_provider
    configuration = {"CertificateArn": certificate_arn, **configuration}

    _assert_error(
        "BadRequestException",
        400,
        lambda: provider.create_domain_name(
            context,
            {
                "DomainName": domain_name,
                "DomainNameConfigurations": [configuration],
            },
        ),
    )


def test_domain_listing_token_supports_dns_names_and_is_store_scoped(domain_provider, context):
    provider, certificate_arn = domain_provider
    for domain_name in ("one.apps.example.test", "two.apps.example.test"):
        provider.create_domain_name(
            context,
            {
                "DomainName": domain_name,
                "DomainNameConfigurations": [{"CertificateArn": certificate_arn}],
            },
        )

    first = provider.get_domain_names(context, {"MaxResults": "1"})
    second = provider.get_domain_names(
        context, {"MaxResults": "1", "NextToken": first["NextToken"]}
    )

    assert [item["DomainName"] for item in first["Items"] + second["Items"]] == [
        "one.apps.example.test",
        "two.apps.example.test",
    ]
    other = RequestContext(None)
    other.account_id = f"{(int(context.account_id) + 1) % 10**12:012d}"
    other.region = context.region
    other.partition = context.partition
    _assert_error(
        "BadRequestException",
        400,
        lambda: provider.get_domain_names(other, {"NextToken": first["NextToken"]}),
    )
    with apigatewayv2_stores.lock:
        apigatewayv2_stores.pop(other.account_id, None)


@pytest.mark.parametrize("arn_part", ["account", "region", "partition"])
def test_domain_rejects_certificate_outside_api_topology(context, arn_part):
    partition = "aws-us-gov" if arn_part == "partition" else context.partition
    region = "us-west-2" if arn_part == "region" else context.region
    account = "999999999999" if arn_part == "account" else context.account_id
    certificate_arn = (
        f"arn:{partition}:acm:{region}:{account}:certificate/11111111-2222-3333-4444-555555555555"
    )
    provider = ApiGatewayV2Provider(certificate_resolver=lambda *_: pytest.fail("resolver called"))

    _assert_error(
        "BadRequestException",
        400,
        lambda: provider.create_domain_name(
            context,
            {
                "DomainName": "api.example.test",
                "DomainNameConfigurations": [{"CertificateArn": certificate_arn}],
            },
        ),
    )


def test_domain_requires_issued_local_certificate(context):
    certificate_arn = (
        f"arn:{context.partition}:acm:{context.region}:{context.account_id}:certificate/"
        "11111111-2222-3333-4444-555555555555"
    )
    provider = ApiGatewayV2Provider(
        certificate_resolver=lambda *_: {
            "DomainName": "api.example.test",
            "Status": "PENDING_VALIDATION",
        }
    )

    _assert_error(
        "BadRequestException",
        400,
        lambda: provider.create_domain_name(
            context,
            {
                "DomainName": "api.example.test",
                "DomainNameConfigurations": [{"CertificateArn": certificate_arn}],
            },
        ),
    )


def test_skeleton_serializes_native_create_and_keeps_unsupported_operation_at_501(
    provider, context
):
    service_model = load_service("apigatewayv2")
    service = Service.for_provider(provider)
    invocation = RequestContext(
        Request(method="POST", path="/v2/apis", headers={"content-type": "application/json"})
    )
    invocation.account_id = context.account_id
    invocation.region = context.region
    invocation.partition = context.partition
    invocation.service = service_model
    invocation.operation = service_model.operation_model("CreateApi")
    invocation.service_request = {"Name": "dispatch", "ProtocolType": "HTTP"}

    response = service.skeleton.invoke(invocation)

    assert response.status_code == 201
    assert json.loads(response.data)["name"] == "dispatch"

    unsupported = RequestContext(Request(method="POST", path="/v2/vpclinks", headers={}))
    unsupported.account_id = context.account_id
    unsupported.region = context.region
    unsupported.partition = context.partition
    unsupported.service = service_model
    unsupported.operation = service_model.operation_model("CreateVpcLink")
    unsupported.service_request = {"Name": "unsupported"}

    response = service.skeleton.invoke(unsupported)

    assert response.status_code == 501


def test_api_crud_defaults_local_endpoint_arn_and_cleanup(provider, context):
    request = {
        "Name": "orders",
        "ProtocolType": "HTTP",
        "Description": "Orders API",
        "DisableExecuteApiEndpoint": True,
        "IpAddressType": "dualstack",
        "Tags": {"environment": "test"},
        "Version": "v1",
        "CorsConfiguration": {
            "AllowCredentials": True,
            "AllowHeaders": ["authorization"],
            "AllowMethods": ["GET", "OPTIONS"],
            "AllowOrigins": ["https://app.example.test"],
            "ExposeHeaders": ["x-request-id"],
            "MaxAge": 300,
        },
    }
    original = copy.deepcopy(request)

    created = provider.create_api(context, request)

    assert request == original
    assert len(created["ApiId"]) == 8
    assert created == {
        "ApiEndpoint": (f"http://{created['ApiId']}.execute-api.localhost.localstack.cloud:4566"),
        "ApiGatewayManaged": False,
        "ApiId": created["ApiId"],
        "ApiKeySelectionExpression": "$request.header.x-api-key",
        "CorsConfiguration": request["CorsConfiguration"],
        "CreatedDate": datetime(2026, 8, 10, 12, 0, tzinfo=UTC),
        "Description": "Orders API",
        "DisableExecuteApiEndpoint": True,
        "IpAddressType": "dualstack",
        "Name": "orders",
        "ProtocolType": "HTTP",
        "RouteSelectionExpression": "$request.method $request.path",
        "Tags": {"environment": "test"},
        "Version": "v1",
    }
    with apigatewayv2_stores.lock:
        model = apigatewayv2_stores[context.account_id][context.region].apis[created["ApiId"]]
        assert model.arn == (f"arn:aws:apigateway:{context.region}::/apis/{created['ApiId']}")

    authorizer = _authorizer(provider, context, created["ApiId"])
    updated = provider.update_api(
        context,
        {
            "ApiId": created["ApiId"],
            "Description": "Updated",
            "DisableExecuteApiEndpoint": False,
            "Name": "orders-v2",
            "Version": "v2",
        },
    )
    assert updated["Name"] == "orders-v2"
    assert updated["Description"] == "Updated"
    assert updated["DisableExecuteApiEndpoint"] is False
    assert updated["Tags"] == created["Tags"]
    assert provider.get_api(context, {"ApiId": created["ApiId"]}) == updated

    assert provider.delete_api(context, {"ApiId": created["ApiId"]}) is None
    _assert_error(
        "NotFoundException",
        404,
        lambda: provider.get_api(context, {"ApiId": created["ApiId"]}),
    )
    _assert_error(
        "NotFoundException",
        404,
        lambda: provider.get_authorizer(
            context,
            {"ApiId": created["ApiId"], "AuthorizerId": authorizer["AuthorizerId"]},
        ),
    )


def test_api_and_stage_tags_are_mutable_and_isolated(provider, context):
    api = provider.create_api(
        context,
        {"Name": "tags", "ProtocolType": "HTTP", "Tags": {"old": "1", "keep": "v1"}},
    )
    integration = provider.create_integration(
        context,
        {
            "ApiId": api["ApiId"],
            "IntegrationType": "HTTP_PROXY",
            "IntegrationUri": "https://example.test",
        },
    )
    provider.create_route(
        context,
        {
            "ApiId": api["ApiId"],
            "RouteKey": "GET /tags",
            "Target": f"integrations/{integration['IntegrationId']}",
        },
    )
    stage = provider.create_stage(
        context,
        {"ApiId": api["ApiId"], "AutoDeploy": True, "StageName": "prod", "Tags": {"s": "1"}},
    )
    api_arn = f"arn:aws:apigateway:{context.region}::/apis/{api['ApiId']}"
    stage_arn = f"{api_arn}/stages/{stage['StageName']}"

    provider.tag_resource(context, {"ResourceArn": api_arn, "Tags": {"keep": "v2", "new": "2"}})
    provider.untag_resource(context, {"ResourceArn": api_arn, "TagKeys": ["old"]})
    provider.tag_resource(context, {"ResourceArn": stage_arn, "Tags": {"stage": "prod"}})

    assert provider.get_tags(context, {"ResourceArn": api_arn}) == {
        "Tags": {"keep": "v2", "new": "2"}
    }
    assert provider.get_api(context, {"ApiId": api["ApiId"]})["Tags"] == {
        "keep": "v2",
        "new": "2",
    }
    assert provider.get_tags(context, {"ResourceArn": stage_arn}) == {
        "Tags": {"s": "1", "stage": "prod"}
    }
    assert provider.get_stage(context, {"ApiId": api["ApiId"], "StageName": stage["StageName"]})[
        "Tags"
    ] == {"s": "1", "stage": "prod"}


def test_updates_clear_optional_properties_instead_of_preserving_drift(provider, context):
    api = provider.create_api(
        context,
        {
            "Name": "drift",
            "ProtocolType": "HTTP",
            "CorsConfiguration": {"AllowOrigins": ["https://old.example"]},
            "Description": "remove",
            "Version": "v1",
        },
    )
    integration = provider.create_integration(
        context,
        {
            "ApiId": api["ApiId"],
            "Description": "remove",
            "IntegrationType": "HTTP_PROXY",
            "IntegrationUri": "https://example.test",
        },
    )
    authorizer = _authorizer(provider, context, api["ApiId"])
    route = provider.create_route(
        context,
        {
            "ApiId": api["ApiId"],
            "AuthorizationScopes": ["profile.read"],
            "AuthorizationType": "JWT",
            "AuthorizerId": authorizer["AuthorizerId"],
            "OperationName": "profile",
            "RouteKey": "GET /profile",
            "Target": f"integrations/{integration['IntegrationId']}",
        },
    )
    stage = provider.create_stage(
        context,
        {
            "AccessLogSettings": {
                "DestinationArn": "arn:aws:logs:us-east-1:123456789012:log-group:api",
                "Format": "$context.requestId",
            },
            "ApiId": api["ApiId"],
            "AutoDeploy": True,
            "DefaultRouteSettings": {"ThrottlingBurstLimit": 10},
            "Description": "remove",
            "StageName": "$default",
            "StageVariables": {"old": "value"},
        },
    )

    provider.update_api(
        context,
        {
            "ApiId": api["ApiId"],
            "CorsConfiguration": None,
            "Description": None,
            "Version": None,
        },
    )
    provider.update_integration(
        context,
        {
            "ApiId": api["ApiId"],
            "IntegrationId": integration["IntegrationId"],
            "Description": None,
        },
    )
    provider.update_route(
        context,
        {
            "ApiId": api["ApiId"],
            "AuthorizationScopes": [],
            "AuthorizationType": "NONE",
            "AuthorizerId": None,
            "OperationName": None,
            "RouteId": route["RouteId"],
        },
    )
    provider.update_stage(
        context,
        {
            "AccessLogSettings": None,
            "ApiId": api["ApiId"],
            "DefaultRouteSettings": None,
            "Description": None,
            "StageName": stage["StageName"],
            "StageVariables": {},
        },
    )

    read_api = provider.get_api(context, {"ApiId": api["ApiId"]})
    assert "CorsConfiguration" not in read_api
    assert "Description" not in read_api
    assert "Version" not in read_api
    assert "Description" not in provider.get_integration(
        context,
        {"ApiId": api["ApiId"], "IntegrationId": integration["IntegrationId"]},
    )
    read_route = provider.get_route(context, {"ApiId": api["ApiId"], "RouteId": route["RouteId"]})
    assert read_route["AuthorizationType"] == "NONE"
    assert read_route["AuthorizationScopes"] == []
    assert "AuthorizerId" not in read_route
    assert "OperationName" not in read_route
    read_stage = provider.get_stage(
        context, {"ApiId": api["ApiId"], "StageName": stage["StageName"]}
    )
    assert read_stage["StageVariables"] == {}
    assert "AccessLogSettings" not in read_stage
    assert "DefaultRouteSettings" not in read_stage
    assert "Description" not in read_stage


@pytest.mark.parametrize(
    "operation,payload",
    [
        ("get_tags", {"ResourceArn": "arn:aws:apigateway:us-west-2::/apis/api12345"}),
        (
            "tag_resource",
            {
                "ResourceArn": "arn:aws-cn:apigateway:us-east-1::/apis/api12345",
                "Tags": {"a": "b"},
            },
        ),
        (
            "untag_resource",
            {
                "ResourceArn": "arn:aws:apigateway:us-east-1::/apis/api12345/authorizers/a",
                "TagKeys": ["a"],
            },
        ),
    ],
)
def test_tag_operations_reject_foreign_or_unsupported_arns(provider, context, operation, payload):
    _api(provider, context)

    _assert_error("NotFoundException", 404, lambda: getattr(provider, operation)(context, payload))


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"Name": "", "ProtocolType": "HTTP"},
        {"Name": "websocket", "ProtocolType": "WEBSOCKET"},
        {"Name": "quick", "ProtocolType": "HTTP", "Target": "https://example.test"},
        {"Name": "quick", "ProtocolType": "HTTP", "RouteKey": "$default"},
        {"Name": "schema", "ProtocolType": "HTTP", "DisableSchemaValidation": True},
        {
            "Name": "route",
            "ProtocolType": "HTTP",
            "RouteSelectionExpression": "$request.body.action",
        },
        {"Name": "ip", "ProtocolType": "HTTP", "IpAddressType": "ipv6"},
        {
            "Name": "cors",
            "ProtocolType": "HTTP",
            "CorsConfiguration": {"AllowMethods": "GET"},
        },
        {"Name": "tags", "ProtocolType": "HTTP", "Tags": {"aws:owner": "forbidden"}},
    ],
)
def test_create_api_rejects_unsupported_or_malformed_input_atomically(provider, context, payload):
    _assert_error(
        "BadRequestException",
        400,
        lambda: provider.create_api(context, payload),
    )
    assert provider.get_apis(context, {}) == {"Items": []}


def test_update_api_is_atomic_on_invalid_input(provider, context):
    created = _api(provider, context)
    before = provider.get_api(context, {"ApiId": created["ApiId"]})

    _assert_error(
        "BadRequestException",
        400,
        lambda: provider.update_api(
            context,
            {"ApiId": created["ApiId"], "Name": "", "IpAddressType": "invalid"},
        ),
    )

    assert provider.get_api(context, {"ApiId": created["ApiId"]}) == before


def test_authorizer_crud_validates_native_cognito_jwt_configuration(provider, context):
    api = _api(provider, context)
    request = {
        "ApiId": api["ApiId"],
        "AuthorizerType": "JWT",
        "IdentitySource": ["$request.header.Authorization"],
        "JwtConfiguration": {
            "Audience": ["amplify-web", "amplify-mobile"],
            "Issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_nativePool",
        },
        "Name": "cognito",
    }
    original = copy.deepcopy(request)

    created = provider.create_authorizer(context, request)

    assert request == original
    assert created == {
        "AuthorizerId": created["AuthorizerId"],
        "AuthorizerType": "JWT",
        "IdentitySource": ["$request.header.Authorization"],
        "JwtConfiguration": request["JwtConfiguration"],
        "Name": "cognito",
    }
    with apigatewayv2_stores.lock:
        model = apigatewayv2_stores[context.account_id][context.region].apis[api["ApiId"]]
        assert model.authorizers[created["AuthorizerId"]].arn == (
            f"arn:aws:apigateway:{context.region}::/apis/{api['ApiId']}"
            f"/authorizers/{created['AuthorizerId']}"
        )

    updated = provider.update_authorizer(
        context,
        {
            "ApiId": api["ApiId"],
            "AuthorizerId": created["AuthorizerId"],
            "JwtConfiguration": {
                "Audience": ["amplify-web-v2"],
                "Issuer": request["JwtConfiguration"]["Issuer"],
            },
            "Name": "cognito-v2",
        },
    )
    assert updated["Name"] == "cognito-v2"
    assert updated["JwtConfiguration"]["Audience"] == ["amplify-web-v2"]
    assert (
        provider.get_authorizer(
            context,
            {"ApiId": api["ApiId"], "AuthorizerId": created["AuthorizerId"]},
        )
        == updated
    )

    assert (
        provider.delete_authorizer(
            context,
            {"ApiId": api["ApiId"], "AuthorizerId": created["AuthorizerId"]},
        )
        is None
    )
    _assert_error(
        "NotFoundException",
        404,
        lambda: provider.get_authorizer(
            context,
            {"ApiId": api["ApiId"], "AuthorizerId": created["AuthorizerId"]},
        ),
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"AuthorizerType": "REQUEST"},
        {"IdentitySource": ["$request.querystring.access_token"]},
        {"IdentitySource": ["$request.header.Authorization", "$request.header.Other"]},
        {"JwtConfiguration": {"Audience": [], "Issuer": "https://example.test"}},
        {
            "JwtConfiguration": {
                "Audience": ["same", "same"],
                "Issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            }
        },
        {
            "JwtConfiguration": {
                "Audience": [f"client-{index}" for index in range(51)],
                "Issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            }
        },
        {
            "JwtConfiguration": {
                "Audience": ["client"],
                "Issuer": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_pool",
            }
        },
        {"AuthorizerUri": "arn:aws:lambda:us-east-1:000000000000:function:request"},
        {"AuthorizerResultTtlInSeconds": 300},
    ],
)
def test_create_authorizer_rejects_non_native_or_request_authorizer_fields(
    provider, context, changes
):
    api = _api(provider, context)
    request = {
        "ApiId": api["ApiId"],
        "AuthorizerType": "JWT",
        "IdentitySource": ["$request.header.Authorization"],
        "JwtConfiguration": {
            "Audience": ["client"],
            "Issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
        },
        "Name": "cognito",
        **changes,
    }

    _assert_error(
        "BadRequestException",
        400,
        lambda: provider.create_authorizer(context, request),
    )
    assert provider.get_authorizers(context, {"ApiId": api["ApiId"]}) == {"Items": []}


def test_authorizer_name_conflict_quota_and_invalid_update_are_atomic(
    provider, context, monkeypatch
):
    import localstack.services.apigatewayv2.provider as provider_module

    api = _api(provider, context)
    first = _authorizer(provider, context, api["ApiId"])
    _assert_error(
        "ConflictException",
        409,
        lambda: _authorizer(provider, context, api["ApiId"]),
    )
    before = provider.get_authorizer(
        context,
        {"ApiId": api["ApiId"], "AuthorizerId": first["AuthorizerId"]},
    )
    _assert_error(
        "BadRequestException",
        400,
        lambda: provider.update_authorizer(
            context,
            {
                "ApiId": api["ApiId"],
                "AuthorizerId": first["AuthorizerId"],
                "IdentitySource": ["$request.querystring.token"],
                "Name": "mutated",
            },
        ),
    )
    assert (
        provider.get_authorizer(
            context,
            {"ApiId": api["ApiId"], "AuthorizerId": first["AuthorizerId"]},
        )
        == before
    )

    monkeypatch.setattr(provider_module, "_MAX_AUTHORIZERS_PER_API", 2)
    _authorizer(provider, context, api["ApiId"], name="second")
    _assert_error(
        "LimitExceededException",
        429,
        lambda: _authorizer(provider, context, api["ApiId"], name="third"),
    )


def test_hmac_pagination_is_bounded_tamper_proof_and_scope_bound(provider, context):
    apis = [_api(provider, context, name) for name in ("one", "two", "three")]
    first = provider.get_apis(context, {"MaxResults": "1"})
    assert len(first["Items"]) == 1
    assert "NextToken" in first

    second = provider.get_apis(
        context,
        {"MaxResults": "1", "NextToken": first["NextToken"]},
    )
    third = provider.get_apis(
        context,
        {"MaxResults": "1", "NextToken": second["NextToken"]},
    )
    assert {item["ApiId"] for item in first["Items"] + second["Items"] + third["Items"]} == {
        item["ApiId"] for item in apis
    }
    assert "NextToken" not in third

    tampered = f"{first['NextToken'][:-1]}{'A' if first['NextToken'][-1] != 'A' else 'B'}"
    for token in (tampered, "not-a-token", "x" * 2049):
        _assert_error(
            "BadRequestException",
            400,
            lambda token=token: provider.get_apis(context, {"NextToken": token}),
        )
    for value in ("0", "501", "1.5", "", True):
        _assert_error(
            "BadRequestException",
            400,
            lambda value=value: provider.get_apis(context, {"MaxResults": value}),
        )

    authorizer = _authorizer(provider, context, apis[0]["ApiId"])
    second_authorizer = _authorizer(provider, context, apis[0]["ApiId"], name="second")
    authorizer_page = provider.get_authorizers(
        context,
        {"ApiId": apis[0]["ApiId"], "MaxResults": "1"},
    )
    assert authorizer_page["Items"][0]["AuthorizerId"] in {
        authorizer["AuthorizerId"],
        second_authorizer["AuthorizerId"],
    }
    _assert_error(
        "BadRequestException",
        400,
        lambda: provider.get_apis(context, {"NextToken": authorizer_page["NextToken"]}),
    )


def test_account_region_isolation_and_concurrent_creation(provider, context):
    other_account = RequestContext(None)
    other_account.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    other_account.region = context.region
    other_account.partition = context.partition
    other_region = RequestContext(None)
    other_region.account_id = context.account_id
    other_region.region = "us-west-2"
    other_region.partition = context.partition
    try:
        created = _api(provider, context)
        for foreign in (other_account, other_region):
            _assert_error(
                "NotFoundException",
                404,
                lambda foreign=foreign: provider.get_api(foreign, {"ApiId": created["ApiId"]}),
            )
            assert provider.get_apis(foreign, {}) == {"Items": []}

        with ThreadPoolExecutor(max_workers=16) as executor:
            results = list(
                executor.map(
                    lambda index: _api(provider, context, f"api-{index}"),
                    range(64),
                )
            )
        assert len({result["ApiId"] for result in results}) == 64
        assert len(provider.get_apis(context, {"MaxResults": "500"})["Items"]) == 65
    finally:
        with apigatewayv2_stores.lock:
            apigatewayv2_stores.pop(other_account.account_id, None)


def test_api_quota_is_atomic_under_concurrency(provider, context, monkeypatch):
    import localstack.services.apigatewayv2.provider as provider_module

    monkeypatch.setattr(provider_module, "_MAX_APIS_PER_REGION", 8)

    def create(index):
        try:
            return _api(provider, context, f"quota-{index}")["ApiId"]
        except CommonServiceException as error:
            assert error.code == "LimitExceededException"
            return None

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(create, range(32)))

    assert len({result for result in results if result is not None}) == 8
    assert len(provider.get_apis(context, {})["Items"]) == 8
