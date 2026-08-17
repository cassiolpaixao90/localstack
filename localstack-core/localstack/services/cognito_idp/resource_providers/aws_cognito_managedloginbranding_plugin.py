from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoManagedLoginBrandingProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::ManagedLoginBranding"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_managedloginbranding import (
            CognitoManagedLoginBrandingProvider,
        )

        self.factory = CognitoManagedLoginBrandingProvider
