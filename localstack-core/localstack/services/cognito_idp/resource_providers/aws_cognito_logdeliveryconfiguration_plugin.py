from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoLogDeliveryConfigurationProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::LogDeliveryConfiguration"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_logdeliveryconfiguration import (
            CognitoLogDeliveryConfigurationProvider,
        )

        self.factory = CognitoLogDeliveryConfigurationProvider
