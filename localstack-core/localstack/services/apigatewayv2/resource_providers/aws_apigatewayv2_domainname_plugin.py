from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayV2DomainNameProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGatewayV2::DomainName"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_domainname import (
            ApiGatewayV2DomainNameProvider,
        )

        self.factory = ApiGatewayV2DomainNameProvider
