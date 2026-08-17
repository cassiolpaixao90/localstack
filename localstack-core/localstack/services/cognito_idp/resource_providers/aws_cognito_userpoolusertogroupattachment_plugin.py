from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoUserPoolUserToGroupAttachmentProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::UserPoolUserToGroupAttachment"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolusertogroupattachment import (
            CognitoUserPoolUserToGroupAttachmentProvider,
        )

        self.factory = CognitoUserPoolUserToGroupAttachmentProvider
