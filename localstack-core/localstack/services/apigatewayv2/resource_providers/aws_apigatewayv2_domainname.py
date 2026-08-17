from localstack.services.cloudformation.resource_provider import ProgressEvent

from .base import ApiGatewayV2ResourceProvider, ResourceConfig, schema_path


class ApiGatewayV2DomainNameProvider(ApiGatewayV2ResourceProvider):
    TYPE = "AWS::ApiGatewayV2::DomainName"
    SCHEMA = schema_path(__file__)
    CONFIG = ResourceConfig(
        create="create_domain_name",
        read="get_domain_name",
        list_operation="get_domain_names",
        update="update_domain_name",
        delete="delete_domain_name",
        identifier="DomainName",
        parent=None,
        create_fields=("DomainName", "DomainNameConfigurations", "RoutingMode", "Tags"),
        update_fields=("DomainNameConfigurations", "RoutingMode"),
        response_fields=(
            "DomainName",
            "DomainNameArn",
            "DomainNameConfigurations",
            "RoutingMode",
            "Tags",
        ),
        tag_path="",
    )

    def create(self, request) -> ProgressEvent[dict]:
        return _with_regional_attributes(super().create(request))

    def read(self, request) -> ProgressEvent[dict]:
        return _with_regional_attributes(super().read(request))

    def update(self, request) -> ProgressEvent[dict]:
        return _with_regional_attributes(super().update(request))


def _with_regional_attributes(event: ProgressEvent[dict]) -> ProgressEvent[dict]:
    model = event.resource_model
    if not isinstance(model, dict):
        return event
    configurations = model.get("DomainNameConfigurations")
    if isinstance(configurations, list) and len(configurations) == 1:
        configuration = configurations[0]
        if isinstance(configuration, dict):
            if value := configuration.get("ApiGatewayDomainName"):
                model["RegionalDomainName"] = value
            if value := configuration.get("HostedZoneId"):
                model["RegionalHostedZoneId"] = value
    return event
