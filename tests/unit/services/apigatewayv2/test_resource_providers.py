import json
from types import SimpleNamespace
from unittest.mock import MagicMock, call

import pytest

from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_api import (
    ApiGatewayV2ApiProvider,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_api_plugin import (
    ApiGatewayV2ApiProviderPlugin,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_apimapping import (
    ApiGatewayV2ApiMappingProvider,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_apimapping_plugin import (
    ApiGatewayV2ApiMappingProviderPlugin,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_authorizer import (
    ApiGatewayV2AuthorizerProvider,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_authorizer_plugin import (
    ApiGatewayV2AuthorizerProviderPlugin,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_deployment import (
    ApiGatewayV2DeploymentProvider,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_deployment_plugin import (
    ApiGatewayV2DeploymentProviderPlugin,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_domainname import (
    ApiGatewayV2DomainNameProvider,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_domainname_plugin import (
    ApiGatewayV2DomainNameProviderPlugin,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_integration import (
    ApiGatewayV2IntegrationProvider,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_integration_plugin import (
    ApiGatewayV2IntegrationProviderPlugin,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_route import (
    ApiGatewayV2RouteProvider,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_route_plugin import (
    ApiGatewayV2RouteProviderPlugin,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_stage import (
    ApiGatewayV2StageProvider,
)
from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_stage_plugin import (
    ApiGatewayV2StageProviderPlugin,
)
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
)


def _request(client, desired, *, previous=None):
    return SimpleNamespace(
        aws_client_factory=SimpleNamespace(apigatewayv2=client),
        custom_context={"source": "cfn"},
        desired_state=desired,
        previous_state=previous,
        region_name="us-east-1",
    )


@pytest.mark.parametrize(
    "provider_type,operation,desired,response,identifier",
    [
        (
            ApiGatewayV2ApiProvider,
            "create_api",
            {"Name": "billgym", "ProtocolType": "HTTP"},
            {
                "ApiEndpoint": "http://api.execute-api.localhost.localstack.cloud:4566",
                "ApiId": "api12345",
                "Name": "billgym",
                "ProtocolType": "HTTP",
            },
            ("ApiId", "api12345"),
        ),
        (
            ApiGatewayV2IntegrationProvider,
            "create_integration",
            {
                "ApiId": "api12345",
                "IntegrationType": "AWS_PROXY",
                "IntegrationUri": "arn:aws:lambda:us-east-1:123456789012:function:handler",
                "PayloadFormatVersion": "2.0",
            },
            {"IntegrationId": "int12345", "IntegrationType": "AWS_PROXY"},
            ("IntegrationId", "int12345"),
        ),
        (
            ApiGatewayV2RouteProvider,
            "create_route",
            {
                "ApiId": "api12345",
                "AuthorizationType": "JWT",
                "AuthorizerId": "auth1234",
                "RouteKey": "GET /v1/profile",
                "Target": "integrations/int12345",
            },
            {"RouteId": "route123", "RouteKey": "GET /v1/profile"},
            ("RouteId", "route123"),
        ),
        (
            ApiGatewayV2DeploymentProvider,
            "create_deployment",
            {"ApiId": "api12345", "Description": "release"},
            {"DeploymentId": "dep12345", "DeploymentStatus": "DEPLOYED"},
            ("DeploymentId", "dep12345"),
        ),
        (
            ApiGatewayV2StageProvider,
            "create_stage",
            {"ApiId": "api12345", "AutoDeploy": True, "StageName": "$default"},
            {"AutoDeploy": True, "DeploymentId": "dep12345", "StageName": "$default"},
            ("StageName", "$default"),
        ),
        (
            ApiGatewayV2AuthorizerProvider,
            "create_authorizer",
            {
                "ApiId": "api12345",
                "AuthorizerType": "JWT",
                "IdentitySource": ["$request.header.Authorization"],
                "JwtConfiguration": {"Audience": ["client"], "Issuer": "https://issuer"},
                "Name": "cognito",
            },
            {"AuthorizerId": "auth1234", "AuthorizerType": "JWT", "Name": "cognito"},
            ("AuthorizerId", "auth1234"),
        ),
        (
            ApiGatewayV2DomainNameProvider,
            "create_domain_name",
            {
                "DomainName": "api.example.test",
                "DomainNameConfigurations": [
                    {"CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/cert"}
                ],
            },
            {
                "DomainName": "api.example.test",
                "DomainNameArn": "arn:aws:apigateway:us-east-1::/domainnames/api.example.test",
                "DomainNameConfigurations": [
                    {
                        "ApiGatewayDomainName": "d-id.execute-api.localhost.localstack.cloud",
                        "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/cert",
                        "HostedZoneId": "ZLOCAL",
                    }
                ],
            },
            ("DomainName", "api.example.test"),
        ),
        (
            ApiGatewayV2ApiMappingProvider,
            "create_api_mapping",
            {
                "ApiId": "api12345",
                "ApiMappingKey": "v1",
                "DomainName": "api.example.test",
                "Stage": "prod",
            },
            {
                "ApiId": "api12345",
                "ApiMappingId": "mapping1",
                "ApiMappingKey": "v1",
                "Stage": "prod",
            },
            ("ApiMappingId", "mapping1"),
        ),
    ],
)
def test_resource_provider_create_preserves_parent_and_returns_official_ref(
    provider_type, operation, desired, response, identifier
):
    client = MagicMock()
    getattr(client, operation).return_value = response

    result = provider_type().create(_request(client, desired))

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model[identifier[0]] == identifier[1]
    if "ApiId" in desired:
        assert result.resource_model["ApiId"] == desired["ApiId"]
    assert result.custom_context == {"source": "cfn"}


@pytest.mark.parametrize(
    "plugin_type,provider_type",
    [
        (ApiGatewayV2ApiProviderPlugin, ApiGatewayV2ApiProvider),
        (ApiGatewayV2IntegrationProviderPlugin, ApiGatewayV2IntegrationProvider),
        (ApiGatewayV2RouteProviderPlugin, ApiGatewayV2RouteProvider),
        (ApiGatewayV2DeploymentProviderPlugin, ApiGatewayV2DeploymentProvider),
        (ApiGatewayV2StageProviderPlugin, ApiGatewayV2StageProvider),
        (ApiGatewayV2AuthorizerProviderPlugin, ApiGatewayV2AuthorizerProvider),
        (ApiGatewayV2DomainNameProviderPlugin, ApiGatewayV2DomainNameProvider),
        (ApiGatewayV2ApiMappingProviderPlugin, ApiGatewayV2ApiMappingProvider),
    ],
)
def test_resource_provider_plugins_load_native_factories(plugin_type, provider_type):
    plugin = plugin_type()

    plugin.load()

    assert plugin.factory is provider_type
    assert plugin.name == provider_type.TYPE


@pytest.mark.parametrize(
    "provider_type,identifier",
    [
        (ApiGatewayV2ApiProvider, ["/properties/ApiId"]),
        (
            ApiGatewayV2IntegrationProvider,
            ["/properties/ApiId", "/properties/IntegrationId"],
        ),
        (ApiGatewayV2RouteProvider, ["/properties/ApiId", "/properties/RouteId"]),
        (
            ApiGatewayV2DeploymentProvider,
            ["/properties/ApiId", "/properties/DeploymentId"],
        ),
        (ApiGatewayV2StageProvider, ["/properties/ApiId", "/properties/StageName"]),
        (
            ApiGatewayV2AuthorizerProvider,
            ["/properties/ApiId", "/properties/AuthorizerId"],
        ),
        (ApiGatewayV2DomainNameProvider, ["/properties/DomainName"]),
        (
            ApiGatewayV2ApiMappingProvider,
            ["/properties/DomainName", "/properties/ApiMappingId"],
        ),
    ],
)
def test_resource_provider_schemas_are_closed_and_fail_closed(provider_type, identifier):
    schema = provider_type.SCHEMA
    serialized = json.dumps(schema)

    assert schema["typeName"] == provider_type.TYPE
    assert schema["additionalProperties"] is False
    assert schema["primaryIdentifier"] == identifier
    assert schema["handlers"]["list"]["permissions"] == ["apigateway:GET"]
    assert "WEBSOCKET" not in serialized
    assert "VPC_LINK" not in serialized
    assert '"REQUEST"' not in serialized
    assert '"AWS_IAM"' not in serialized
    if provider_type in {
        ApiGatewayV2ApiProvider,
        ApiGatewayV2DomainNameProvider,
        ApiGatewayV2StageProvider,
    }:
        assert schema["tagging"] == {
            "taggable": True,
            "tagOnCreate": True,
            "tagUpdatable": True,
            "cloudFormationSystemTags": True,
            "tagProperty": "/properties/Tags",
        }
        assert set(schema["handlers"]["update"]["permissions"]) == {
            "apigateway:PATCH",
            "apigateway:PUT",
            "apigateway:DELETE",
        }


def test_api_update_resets_removed_properties_and_reconciles_mutable_tags():
    client = MagicMock()
    client.update_api.return_value = {
        "ApiId": "api12345",
        "Name": "billgym",
        "ProtocolType": "HTTP",
        "Tags": {"old": "1", "keep": "old"},
    }
    previous = {
        "ApiId": "api12345",
        "Name": "billgym",
        "ProtocolType": "HTTP",
        "CorsConfiguration": {"AllowOrigins": ["https://old.example"]},
        "Description": "remove me",
        "Version": "v1",
        "Tags": {"old": "1", "keep": "old"},
    }
    desired = {
        "ApiId": "api12345",
        "Name": "billgym",
        "ProtocolType": "HTTP",
        "Tags": {"keep": "new", "added": "2"},
    }

    result = ApiGatewayV2ApiProvider().update(_request(client, desired, previous=previous))

    client.update_api.assert_called_once_with(
        ApiId="api12345", CorsConfiguration=None, Description=None, Name="billgym", Version=None
    )
    arn = "arn:aws:apigateway:us-east-1::/apis/api12345"
    client.untag_resource.assert_called_once_with(ResourceArn=arn, TagKeys=["old"])
    client.tag_resource.assert_called_once_with(ResourceArn=arn, Tags={"keep": "new", "added": "2"})
    assert result.resource_model["Tags"] == desired["Tags"]
    assert "Description" not in result.resource_model
    assert "CorsConfiguration" not in result.resource_model
    assert "Version" not in result.resource_model


def test_domain_update_exposes_regional_attributes_and_reconciles_tags():
    client = MagicMock()
    client.update_domain_name.return_value = {
        "DomainName": "api.example.test",
        "DomainNameConfigurations": [
            {
                "ApiGatewayDomainName": "d-id.execute-api.localhost.localstack.cloud",
                "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/cert",
                "HostedZoneId": "ZLOCAL",
            }
        ],
        "Tags": {"old": "1"},
    }
    previous = {
        "DomainName": "api.example.test",
        "DomainNameConfigurations": [
            {"CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/old"}
        ],
        "Tags": {"old": "1"},
    }
    desired = {
        "DomainName": "api.example.test",
        "DomainNameConfigurations": [
            {"CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/cert"}
        ],
        "Tags": {"owner": "stack"},
    }

    result = ApiGatewayV2DomainNameProvider().update(_request(client, desired, previous=previous))

    client.update_domain_name.assert_called_once_with(
        DomainName="api.example.test",
        DomainNameConfigurations=desired["DomainNameConfigurations"],
    )
    arn = "arn:aws:apigateway:us-east-1::/domainnames/api.example.test"
    client.untag_resource.assert_called_once_with(ResourceArn=arn, TagKeys=["old"])
    client.tag_resource.assert_called_once_with(ResourceArn=arn, Tags={"owner": "stack"})
    assert result.resource_model["RegionalDomainName"] == (
        "d-id.execute-api.localhost.localstack.cloud"
    )
    assert result.resource_model["RegionalHostedZoneId"] == "ZLOCAL"
    assert result.resource_model["Tags"] == {"owner": "stack"}


def test_api_mapping_update_resets_removed_mapping_key():
    client = MagicMock()
    client.update_api_mapping.return_value = {
        "ApiId": "api12345",
        "ApiMappingId": "mapping1",
        "ApiMappingKey": "",
        "Stage": "prod",
    }
    previous = {
        "ApiId": "api12345",
        "ApiMappingId": "mapping1",
        "ApiMappingKey": "v1",
        "DomainName": "api.example.test",
        "Stage": "prod",
    }
    desired = {
        "ApiId": "api12345",
        "ApiMappingId": "mapping1",
        "DomainName": "api.example.test",
        "Stage": "prod",
    }

    result = ApiGatewayV2ApiMappingProvider().update(_request(client, desired, previous=previous))

    client.update_api_mapping.assert_called_once_with(
        ApiId="api12345",
        ApiMappingId="mapping1",
        ApiMappingKey="",
        DomainName="api.example.test",
        Stage="prod",
    )
    assert result.resource_model["ApiMappingKey"] == ""


def test_stage_update_resets_removed_properties_and_removes_all_tags():
    client = MagicMock()
    client.update_stage.return_value = {
        "AutoDeploy": True,
        "DeploymentId": "dep12345",
        "StageName": "$default",
    }
    previous = {
        "ApiId": "api12345",
        "AccessLogSettings": {
            "DestinationArn": "arn:aws:logs:us-east-1:123:log-group:x",
            "Format": "$context.requestId",
        },
        "AutoDeploy": True,
        "DefaultRouteSettings": {"ThrottlingBurstLimit": 10},
        "DeploymentId": "dep12345",
        "Description": "remove me",
        "StageName": "$default",
        "StageVariables": {"old": "value"},
        "Tags": {"old": "1"},
    }
    desired = {
        "ApiId": "api12345",
        "AutoDeploy": True,
        "DeploymentId": "dep12345",
        "StageName": "$default",
    }

    result = ApiGatewayV2StageProvider().update(_request(client, desired, previous=previous))

    client.update_stage.assert_called_once_with(
        ApiId="api12345",
        AccessLogSettings=None,
        AutoDeploy=True,
        DefaultRouteSettings=None,
        DeploymentId="dep12345",
        Description=None,
        StageName="$default",
        StageVariables={},
    )
    client.untag_resource.assert_called_once_with(
        ResourceArn="arn:aws:apigateway:us-east-1::/apis/api12345/stages/$default",
        TagKeys=["old"],
    )
    client.tag_resource.assert_not_called()
    assert result.resource_model["Tags"] == {}


@pytest.mark.parametrize(
    "provider_type,model,expected_ref",
    [
        (
            ApiGatewayV2IntegrationProvider,
            {"ApiId": "api12345", "IntegrationId": "int12345"},
            "int12345",
        ),
        (
            ApiGatewayV2StageProvider,
            {"ApiId": "api12345", "StageName": "$default"},
            "$default",
        ),
        (
            ApiGatewayV2ApiMappingProvider,
            {"DomainName": "api.example.test", "ApiMappingId": "mapping1"},
            "mapping1",
        ),
    ],
)
def test_executor_uses_aws_ref_value_instead_of_composite_primary_identifier(
    provider_type, model, expected_ref
):
    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")

    physical_id = executor.extract_physical_resource_id_from_model_with_schema(
        model, provider_type.TYPE, provider_type.SCHEMA
    )

    assert physical_id == expected_ref


def test_failed_tag_reconciliation_compensates_configuration_and_partial_tags():
    client = MagicMock()
    client.update_api.side_effect = [
        {"ApiId": "api12345", "Name": "new", "ProtocolType": "HTTP"},
        {"ApiId": "api12345", "Name": "old", "ProtocolType": "HTTP"},
    ]
    client.tag_resource.side_effect = [RuntimeError("tag write failed"), None]
    previous = {
        "ApiId": "api12345",
        "CorsConfiguration": {"AllowOrigins": ["https://old.example"]},
        "Description": "old description",
        "Name": "old",
        "ProtocolType": "HTTP",
        "Tags": {"old": "1", "keep": "old"},
        "Version": "v1",
    }
    desired = {
        "ApiId": "api12345",
        "Name": "new",
        "ProtocolType": "HTTP",
        "Tags": {"keep": "new", "added": "2"},
    }

    with pytest.raises(RuntimeError, match="tag write failed"):
        ApiGatewayV2ApiProvider().update(_request(client, desired, previous=previous))

    assert client.update_api.call_args_list == [
        call(
            ApiId="api12345",
            CorsConfiguration=None,
            Description=None,
            Name="new",
            Version=None,
        ),
        call(
            ApiId="api12345",
            CorsConfiguration={"AllowOrigins": ["https://old.example"]},
            Description="old description",
            Name="old",
            Version="v1",
        ),
    ]
    arn = "arn:aws:apigateway:us-east-1::/apis/api12345"
    assert client.untag_resource.call_args_list == [
        call(ResourceArn=arn, TagKeys=["old"]),
        call(ResourceArn=arn, TagKeys=["added"]),
    ]
    assert client.tag_resource.call_args_list == [
        call(ResourceArn=arn, Tags={"keep": "new", "added": "2"}),
        call(ResourceArn=arn, Tags=previous["Tags"]),
    ]


def test_tag_apply_then_raise_is_restored_idempotently():
    class ApplyThenRaiseClient:
        def __init__(self):
            self.tags = {"old": "1", "keep": "old"}
            self.update_calls = []
            self.fail_next_tag = True

        def update_api(self, **kwargs):
            self.update_calls.append(kwargs)
            return {"ApiId": "api12345", "Name": kwargs["Name"], "ProtocolType": "HTTP"}

        def untag_resource(self, *, ResourceArn, TagKeys):
            for key in TagKeys:
                self.tags.pop(key, None)

        def tag_resource(self, *, ResourceArn, Tags):
            self.tags.update(Tags)
            if self.fail_next_tag:
                self.fail_next_tag = False
                raise RuntimeError("write committed before transport failure")

    client = ApplyThenRaiseClient()
    previous = {
        "ApiId": "api12345",
        "Name": "old",
        "ProtocolType": "HTTP",
        "Tags": {"old": "1", "keep": "old"},
    }
    desired = {
        "ApiId": "api12345",
        "Name": "new",
        "ProtocolType": "HTTP",
        "Tags": {"keep": "new", "added": "2"},
    }

    with pytest.raises(RuntimeError, match="committed before transport"):
        ApiGatewayV2ApiProvider().update(_request(client, desired, previous=previous))

    assert client.tags == previous["Tags"]
    assert [item["Name"] for item in client.update_calls] == ["new", "old"]


@pytest.mark.parametrize(
    "configuration_restore_error,tag_restore_error,expected_note",
    [
        (RuntimeError("config rollback"), None, "configuration restore failed (RuntimeError)"),
        (None, RuntimeError("tag rollback"), "tag restore failed (RuntimeError)"),
    ],
)
def test_incomplete_compensation_is_attached_to_primary_error(
    configuration_restore_error, tag_restore_error, expected_note
):
    client = MagicMock()
    update_effects = [
        {"ApiId": "api12345", "Name": "new", "ProtocolType": "HTTP"},
        {"ApiId": "api12345", "Name": "old", "ProtocolType": "HTTP"},
    ]
    if configuration_restore_error:
        update_effects[1] = configuration_restore_error
    client.update_api.side_effect = update_effects
    tag_effects = [RuntimeError("primary tag failure"), None]
    if tag_restore_error:
        tag_effects[1] = tag_restore_error
    client.tag_resource.side_effect = tag_effects
    previous = {
        "ApiId": "api12345",
        "Name": "old",
        "ProtocolType": "HTTP",
        "Tags": {"old": "1"},
    }
    desired = {
        "ApiId": "api12345",
        "Name": "new",
        "ProtocolType": "HTTP",
        "Tags": {"added": "2"},
    }

    with pytest.raises(RuntimeError, match="primary tag failure") as raised:
        ApiGatewayV2ApiProvider().update(_request(client, desired, previous=previous))

    notes = getattr(raised.value, "__notes__", [])
    assert notes == [f"ApiGatewayV2 rollback incomplete: {expected_note}"]


@pytest.mark.parametrize(
    "provider_type,operation,parent,identifier",
    [
        (ApiGatewayV2ApiProvider, "get_apis", None, "ApiId"),
        (ApiGatewayV2AuthorizerProvider, "get_authorizers", "ApiId", "AuthorizerId"),
        (ApiGatewayV2DeploymentProvider, "get_deployments", "ApiId", "DeploymentId"),
        (ApiGatewayV2IntegrationProvider, "get_integrations", "ApiId", "IntegrationId"),
        (ApiGatewayV2RouteProvider, "get_routes", "ApiId", "RouteId"),
        (ApiGatewayV2StageProvider, "get_stages", "ApiId", "StageName"),
        (ApiGatewayV2DomainNameProvider, "get_domain_names", None, "DomainName"),
        (ApiGatewayV2ApiMappingProvider, "get_api_mappings", "DomainName", "ApiMappingId"),
    ],
)
def test_resource_provider_list_is_bounded_paginated_and_returns_primary_identifiers(
    provider_type, operation, parent, identifier
):
    client = MagicMock()
    list_operation = getattr(client, operation)
    list_operation.side_effect = [
        {"Items": [{identifier: "z-id"}], "NextToken": "next"},
        {"Items": [{identifier: "a-id"}]},
    ]
    desired = {parent: "api12345"} if parent else {}

    result = provider_type().list(_request(client, desired))

    assert result.status == OperationStatus.SUCCESS
    expected = [{identifier: "a-id"}, {identifier: "z-id"}]
    if parent:
        expected = [{parent: "api12345", **model} for model in expected]
    assert result.resource_models == expected
    base_parameters = {"MaxResults": "500"}
    if parent:
        base_parameters[parent] = "api12345"
    assert list_operation.call_args_list == [
        call(**base_parameters),
        call(**base_parameters, NextToken="next"),
    ]


def test_resource_provider_list_rejects_missing_parent_and_token_cycles():
    client = MagicMock()
    provider = ApiGatewayV2RouteProvider()

    missing = provider.list(_request(client, {}))

    assert missing.status == OperationStatus.FAILED
    assert missing.error_code == "InvalidRequest"
    client.get_routes.side_effect = [
        {"Items": [{"RouteId": "route1"}], "NextToken": "cycle"},
        {"Items": [{"RouteId": "route2"}], "NextToken": "cycle"},
    ]

    cycle = provider.list(_request(client, {"ApiId": "api12345"}))

    assert cycle.status == OperationStatus.FAILED
    assert cycle.error_code == "InternalFailure"
    assert "continuation token" in cycle.message
