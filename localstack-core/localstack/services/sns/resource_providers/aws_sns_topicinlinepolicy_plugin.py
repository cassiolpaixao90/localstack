from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SNSTopicInlinePolicyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SNS::TopicInlinePolicy"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.sns.resource_providers.aws_sns_topicinlinepolicy import (
            SNSTopicInlinePolicyProvider,
        )

        self.factory = SNSTopicInlinePolicyProvider
