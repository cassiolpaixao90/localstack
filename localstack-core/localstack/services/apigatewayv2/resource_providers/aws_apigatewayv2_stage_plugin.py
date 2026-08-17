from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayV2StageProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGatewayV2::Stage"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.apigatewayv2.resource_providers.aws_apigatewayv2_stage import (
            ApiGatewayV2StageProvider,
        )

        self.factory = ApiGatewayV2StageProvider
