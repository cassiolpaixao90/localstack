from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoIdentityPoolProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::IdentityPool"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_identity.resource_providers.aws_cognito_identitypool import (
            CognitoIdentityPoolProvider,
        )

        self.factory = CognitoIdentityPoolProvider
