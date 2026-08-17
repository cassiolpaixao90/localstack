from .base import ApiGatewayV2ResourceProvider, ResourceConfig, schema_path


class ApiGatewayV2ApiMappingProvider(ApiGatewayV2ResourceProvider):
    TYPE = "AWS::ApiGatewayV2::ApiMapping"
    SCHEMA = schema_path(__file__)
    CONFIG = ResourceConfig(
        create="create_api_mapping",
        read="get_api_mapping",
        list_operation="get_api_mappings",
        update="update_api_mapping",
        delete="delete_api_mapping",
        identifier="ApiMappingId",
        parent="DomainName",
        create_fields=("ApiId", "ApiMappingKey", "DomainName", "Stage"),
        update_fields=("ApiId", "ApiMappingKey", "Stage"),
        response_fields=("ApiId", "ApiMappingId", "ApiMappingKey", "Stage"),
        reset_fields=(("ApiMappingKey", ""),),
    )
