from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CognitoUserPoolReplicaProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Cognito::UserPoolReplica"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolreplica import (
            CognitoUserPoolReplicaProvider,
        )

        self.factory = CognitoUserPoolReplicaProvider
