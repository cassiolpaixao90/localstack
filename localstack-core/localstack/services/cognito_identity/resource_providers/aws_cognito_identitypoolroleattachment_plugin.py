from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoIdentityPoolRoleAttachmentProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::IdentityPoolRoleAttachment"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_identity.resource_providers.aws_cognito_identitypoolroleattachment import (
            CognitoIdentityPoolRoleAttachmentProvider,
        )

        self.factory = CognitoIdentityPoolRoleAttachmentProvider
