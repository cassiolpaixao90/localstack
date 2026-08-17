from .base import ApiGatewayV2ResourceProvider, ResourceConfig, schema_path


class ApiGatewayV2AuthorizerProvider(ApiGatewayV2ResourceProvider):
    TYPE = "AWS::ApiGatewayV2::Authorizer"
    SCHEMA = schema_path(__file__)
    CONFIG = ResourceConfig(
        create="create_authorizer",
        read="get_authorizer",
        list_operation="get_authorizers",
        update="update_authorizer",
        delete="delete_authorizer",
        identifier="AuthorizerId",
        parent="ApiId",
        create_fields=(
            "ApiId",
            "AuthorizerType",
            "IdentitySource",
            "JwtConfiguration",
            "Name",
        ),
        update_fields=(
            "AuthorizerType",
            "IdentitySource",
            "JwtConfiguration",
            "Name",
        ),
        response_fields=(
            "ApiId",
            "AuthorizerId",
            "AuthorizerType",
            "IdentitySource",
            "JwtConfiguration",
            "Name",
        ),
    )
