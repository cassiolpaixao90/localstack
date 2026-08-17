from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoUserPoolResourceServerProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::UserPoolResourceServer"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolresourceserver import (
            CognitoUserPoolResourceServerProvider,
        )

        self.factory = CognitoUserPoolResourceServerProvider
