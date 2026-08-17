from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoUserPoolUICustomizationAttachmentProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::UserPoolUICustomizationAttachment"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_userpooluicustomizationattachment import (
            CognitoUserPoolUICustomizationAttachmentProvider,
        )

        self.factory = CognitoUserPoolUICustomizationAttachmentProvider
