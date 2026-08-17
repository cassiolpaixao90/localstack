from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayV2ApiProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGatewayV2::Api"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_api import (
            ApiGatewayV2ApiProvider,
        )

        self.factory = ApiGatewayV2ApiProvider
