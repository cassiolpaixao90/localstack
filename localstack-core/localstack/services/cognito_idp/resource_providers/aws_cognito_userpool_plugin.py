from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoUserPoolProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::UserPool"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_userpool import (
            CognitoUserPoolProvider,
        )

        self.factory = CognitoUserPoolProvider
