from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoUserPoolIdentityProviderProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::UserPoolIdentityProvider"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolidentityprovider import (
            CognitoUserPoolIdentityProviderProvider,
        )

        self.factory = CognitoUserPoolIdentityProviderProvider
