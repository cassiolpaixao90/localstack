from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoUserPoolClientProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::UserPoolClient"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolclient import (
            CognitoUserPoolClientProvider,
        )

        self.factory = CognitoUserPoolClientProvider
