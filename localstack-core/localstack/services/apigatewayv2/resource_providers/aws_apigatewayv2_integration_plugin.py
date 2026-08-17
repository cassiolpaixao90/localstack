from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayV2IntegrationProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGatewayV2::Integration"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_integration import (
            ApiGatewayV2IntegrationProvider,
        )

        self.factory = ApiGatewayV2IntegrationProvider
