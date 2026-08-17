from .base import ApiGatewayV2ResourceProvider, ResourceConfig, schema_path


class ApiGatewayV2RouteProvider(ApiGatewayV2ResourceProvider):
    TYPE = "AWS::ApiGatewayV2::Route"
    SCHEMA = schema_path(__file__)
    CONFIG = ResourceConfig(
        create="create_route",
        read="get_route",
        list_operation="get_routes",
        update="update_route",
        delete="delete_route",
        identifier="RouteId",
        parent="ApiId",
        create_fields=(
            "ApiId",
            "ApiKeyRequired",
            "AuthorizationScopes",
            "AuthorizationType",
            "AuthorizerId",
            "OperationName",
            "RouteKey",
            "Target",
        ),
        update_fields=(
            "ApiKeyRequired",
            "AuthorizationScopes",
            "AuthorizationType",
            "AuthorizerId",
            "OperationName",
            "RouteKey",
            "Target",
        ),
        response_fields=(
            "ApiGatewayManaged",
            "ApiKeyRequired",
            "AuthorizationScopes",
            "AuthorizationType",
            "AuthorizerId",
            "OperationName",
            "RouteId",
            "RouteKey",
            "Target",
        ),
        reset_fields=(
            ("AuthorizationScopes", []),
            ("AuthorizerId", None),
            ("OperationName", None),
        ),
    )
