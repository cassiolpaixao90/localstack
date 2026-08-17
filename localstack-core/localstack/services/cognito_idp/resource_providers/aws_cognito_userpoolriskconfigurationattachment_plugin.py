from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoUserPoolRiskConfigurationAttachmentProviderPlugin(
    CloudFormationResourceProviderPlugin
):
    name = "AWS::Cognito::UserPoolRiskConfigurationAttachment"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolriskconfigurationattachment import (
            CognitoUserPoolRiskConfigurationAttachmentProvider,
        )

        self.factory = CognitoUserPoolRiskConfigurationAttachmentProvider
