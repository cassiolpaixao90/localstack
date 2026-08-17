from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoUserPoolUserProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::UserPoolUser"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_userpooluser import (
            CognitoUserPoolUserProvider,
        )

        self.factory = CognitoUserPoolUserProvider
