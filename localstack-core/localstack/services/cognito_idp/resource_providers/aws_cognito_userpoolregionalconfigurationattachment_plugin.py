from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoUserPoolRegionalConfigurationAttachmentProviderPlugin(
    CloudFormationResourceProviderPlugin
):
    name = "AWS::Cognito::UserPoolRegionalConfigurationAttachment"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolregionalconfigurationattachment import (
            CognitoUserPoolRegionalConfigurationAttachmentProvider,
        )

        self.factory = CognitoUserPoolRegionalConfigurationAttachmentProvider
