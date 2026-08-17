from .base import ApiGatewayV2ResourceProvider, ResourceConfig, schema_path


class ApiGatewayV2IntegrationProvider(ApiGatewayV2ResourceProvider):
    TYPE = "AWS::ApiGatewayV2::Integration"
    SCHEMA = schema_path(__file__)
    CONFIG = ResourceConfig(
        create="create_integration",
        read="get_integration",
        list_operation="get_integrations",
        update="update_integration",
        delete="delete_integration",
        identifier="IntegrationId",
        parent="ApiId",
        create_fields=(
            "ApiId",
            "ConnectionType",
            "Description",
            "IntegrationMethod",
            "IntegrationType",
            "IntegrationUri",
            "PayloadFormatVersion",
            "TimeoutInMillis",
        ),
        update_fields=(
            "ConnectionType",
            "Description",
            "IntegrationMethod",
            "IntegrationType",
            "IntegrationUri",
            "PayloadFormatVersion",
            "TimeoutInMillis",
        ),
        response_fields=(
            "ApiGatewayManaged",
            "ConnectionType",
            "Description",
            "IntegrationId",
            "IntegrationMethod",
            "IntegrationType",
            "IntegrationUri",
            "PayloadFormatVersion",
            "TimeoutInMillis",
        ),
        reset_fields=(("Description", None),),
    )
