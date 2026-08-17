from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoTermsProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::Terms"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_terms import (
            CognitoTermsProvider,
        )

        self.factory = CognitoTermsProvider
