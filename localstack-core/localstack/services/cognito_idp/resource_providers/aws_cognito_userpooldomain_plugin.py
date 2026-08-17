from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoUserPoolDomainProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::UserPoolDomain"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_userpooldomain import (
            CognitoUserPoolDomainProvider,
        )

        self.factory = CognitoUserPoolDomainProvider
