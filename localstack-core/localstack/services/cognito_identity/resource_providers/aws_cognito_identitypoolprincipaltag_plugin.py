from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoIdentityPoolPrincipalTagProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::IdentityPoolPrincipalTag"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_identity.resource_providers.aws_cognito_identitypoolprincipaltag import (
            CognitoIdentityPoolPrincipalTagProvider,
        )

        self.factory = CognitoIdentityPoolPrincipalTagProvider
