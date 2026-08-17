from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayV2AuthorizerProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGatewayV2::Authorizer"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_authorizer import (
            ApiGatewayV2AuthorizerProvider,
        )

        self.factory = ApiGatewayV2AuthorizerProvider
