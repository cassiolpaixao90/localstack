from .base import ApiGatewayV2ResourceProvider, ResourceConfig, schema_path


class ApiGatewayV2ApiProvider(ApiGatewayV2ResourceProvider):
    TYPE = "AWS::ApiGatewayV2::Api"
    SCHEMA = schema_path(__file__)
    CONFIG = ResourceConfig(
        create="create_api",
        read="get_api",
        list_operation="get_apis",
        update="update_api",
        delete="delete_api",
        identifier="ApiId",
        parent=None,
        create_fields=(
            "ApiKeySelectionExpression",
            "CorsConfiguration",
            "Description",
            "DisableExecuteApiEndpoint",
            "IpAddressType",
            "Name",
            "ProtocolType",
            "RouteSelectionExpression",
            "Tags",
            "Version",
        ),
        update_fields=(
            "ApiKeySelectionExpression",
            "CorsConfiguration",
            "Description",
            "DisableExecuteApiEndpoint",
            "IpAddressType",
            "Name",
            "RouteSelectionExpression",
            "Version",
        ),
        response_fields=(
            "ApiEndpoint",
            "ApiId",
            "ApiKeySelectionExpression",
            "CorsConfiguration",
            "Description",
            "DisableExecuteApiEndpoint",
            "IpAddressType",
            "Name",
            "ProtocolType",
            "RouteSelectionExpression",
            "Tags",
            "Version",
        ),
        reset_fields=(
            ("CorsConfiguration", None),
            ("Description", None),
            ("Version", None),
        ),
        tag_path="",
    )
