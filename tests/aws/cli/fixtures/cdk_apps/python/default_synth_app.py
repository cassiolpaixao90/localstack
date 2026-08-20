import os
import re
from pathlib import Path

from aws_cdk import (
    App,
    CfnOutput,
    DefaultStackSynthesizer,
    Duration,
    Environment,
    Stack,
    Tags,
    aws_lambda,
    aws_sqs,
)

CONTEXT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
OWNER_PATTERN = re.compile(r"^[a-f0-9]{24}$")
QUALIFIER_PATTERN = re.compile(r"^[a-z0-9]{1,10}$")
ASSET_DIR = Path(__file__).parent / "default_synth_asset"


def context_value(app: App, name: str, pattern: re.Pattern) -> str:
    value = app.node.try_get_context(name)
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"CDK context {name!r} must match {pattern.pattern}")
    return value


def required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"required environment variable {name} is missing")
    return value


if not ASSET_DIR.is_dir():
    raise ValueError("the Lambda asset directory is missing")

app = App()
deployment = context_value(app, "deployment", CONTEXT_PATTERN)
owner = context_value(app, "owner", OWNER_PATTERN)
qualifier = context_value(app, "qualifier", QUALIFIER_PATTERN)
account = required_environment("CDK_DEFAULT_ACCOUNT")
region = required_environment("CDK_DEFAULT_REGION")
prefix = f"localstack-defsynth-{deployment}"

# DefaultStackSynthesizer with the same qualifier used by `cdk bootstrap`: it requires
# a bootstrapped environment and forces file-asset publishing to the bootstrap S3 bucket.
stack = Stack(
    app,
    "DefaultSynthApp",
    stack_name=prefix,
    env=Environment(account=account, region=region),
    synthesizer=DefaultStackSynthesizer(qualifier=qualifier),
    description="DefaultStackSynthesizer bootstrap and file-asset contract stack",
)
for key, value in {
    "component": "default-synth",
    "deployment": deployment,
    "managed-by": "cdk",
    "localstack:diagnostic-owner": owner,
}.items():
    Tags.of(stack).add(key, value)

queue = aws_sqs.Queue(stack, "WorkQueue", queue_name=f"{prefix}-work")

function = aws_lambda.Function(
    stack,
    "Handler",
    function_name=f"{prefix}-handler",
    runtime=aws_lambda.Runtime.PYTHON_3_12,
    architecture=aws_lambda.Architecture.X86_64,
    handler="index.handler",
    code=aws_lambda.Code.from_asset(str(ASSET_DIR)),
    timeout=Duration.seconds(10),
)
queue.grant_consume_messages(function)

CfnOutput(stack, "DeploymentAccount", value=stack.account)
CfnOutput(stack, "DeploymentRegion", value=stack.region)
CfnOutput(stack, "FunctionName", value=function.function_name)
CfnOutput(stack, "QueueName", value=queue.queue_name)

app.synth()
