from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayV2ApiMappingProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGatewayV2::ApiMapping"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_apimapping import (
            ApiGatewayV2ApiMappingProvider,
        )

        self.factory = ApiGatewayV2ApiMappingProvider
