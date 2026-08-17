from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoUserPoolGroupProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::UserPoolGroup"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolgroup import (
            CognitoUserPoolGroupProvider,
        )

        self.factory = CognitoUserPoolGroupProvider
