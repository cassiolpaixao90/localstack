from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayV2RouteProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGatewayV2::Route"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_route import (
            ApiGatewayV2RouteProvider,
        )

        self.factory = ApiGatewayV2RouteProvider
