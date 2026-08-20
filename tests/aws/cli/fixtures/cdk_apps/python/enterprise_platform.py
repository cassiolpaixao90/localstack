import os
import re

from aws_cdk import (
    App,
    CfnOutput,
    Duration,
    Environment,
    LegacyStackSynthesizer,
    RemovalPolicy,
    Stack,
    Tags,
    aws_apigatewayv2,
    aws_apigatewayv2_integrations,
    aws_cognito,
    aws_dynamodb,
    aws_lambda,
    aws_sns,
    aws_sns_subscriptions,
    aws_sqs,
)

CONTEXT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
OWNER_PATTERN = re.compile(r"^[a-f0-9]{24}$")
TIMEOUT_PATTERN = re.compile(r"^(30|60|120)$")
LAMBDA_SOURCE = r"""
import json
import os


def handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({
            "queue": os.environ["QUEUE_NAME"],
            "table": os.environ["TABLE_NAME"],
            "topic": os.environ["TOPIC_ARN"],
        }, sort_keys=True),
    }
"""


def context_value(app: App, name: str, pattern: re.Pattern = CONTEXT_PATTERN) -> str:
    value = app.node.try_get_context(name)
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"CDK context {name!r} must match {pattern.pattern}")
    return value


def required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"required environment variable {name} is missing")
    return value


app = App()
deployment = context_value(app, "deployment")
owner = context_value(app, "owner", OWNER_PATTERN)
visibility_timeout = int(context_value(app, "visibilityTimeout", TIMEOUT_PATTERN))
account = required_environment("CDK_DEFAULT_ACCOUNT")
region = required_environment("CDK_DEFAULT_REGION")
prefix = f"localstack-platform-{deployment}"

stack = Stack(
    app,
    "EnterprisePlatform",
    stack_name=prefix,
    env=Environment(account=account, region=region),
    synthesizer=LegacyStackSynthesizer(),
    description="Multi-service CDK lifecycle contract stack for the LocalStack Docker gate",
)
for key, value in {
    "component": "enterprise-platform",
    "deployment": deployment,
    "managed-by": "cdk",
    "localstack:diagnostic-owner": owner,
}.items():
    Tags.of(stack).add(key, value)

queue = aws_sqs.Queue(
    stack,
    "WorkQueue",
    queue_name=f"{prefix}-work",
    visibility_timeout=Duration.seconds(visibility_timeout),
)
queue.apply_removal_policy(RemovalPolicy.DESTROY)

topic = aws_sns.Topic(stack, "WorkEvents", topic_name=f"{prefix}-events")
topic.add_subscription(aws_sns_subscriptions.SqsSubscription(queue))

table = aws_dynamodb.Table(
    stack,
    "WorkTable",
    table_name=f"{prefix}-items",
    partition_key=aws_dynamodb.Attribute(name="pk", type=aws_dynamodb.AttributeType.STRING),
    billing_mode=aws_dynamodb.BillingMode.PAY_PER_REQUEST,
    removal_policy=RemovalPolicy.DESTROY,
)

function = aws_lambda.Function(
    stack,
    "Handler",
    function_name=f"{prefix}-handler",
    runtime=aws_lambda.Runtime.PYTHON_3_12,
    architecture=aws_lambda.Architecture.X86_64,
    handler="index.handler",
    code=aws_lambda.Code.from_inline(LAMBDA_SOURCE),
    environment={
        "QUEUE_NAME": queue.queue_name,
        "TABLE_NAME": table.table_name,
        "TOPIC_ARN": topic.topic_arn,
    },
    timeout=Duration.seconds(10),
)
function.apply_removal_policy(RemovalPolicy.DESTROY)
queue.grant_consume_messages(function)
topic.grant_publish(function)
table.grant_read_write_data(function)

pool = aws_cognito.UserPool(
    stack,
    "UserPool",
    user_pool_name=f"{prefix}-pool",
    self_sign_up_enabled=False,
    sign_in_aliases=aws_cognito.SignInAliases(email=True),
    removal_policy=RemovalPolicy.DESTROY,
)
client = pool.add_client(
    "UserPoolClient",
    user_pool_client_name=f"{prefix}-client",
    auth_flows=aws_cognito.AuthFlow(user_password=True, user_srp=True),
    generate_secret=False,
    prevent_user_existence_errors=True,
)

api = aws_apigatewayv2.HttpApi(
    stack,
    "HttpApi",
    api_name=f"{prefix}-api",
    create_default_stage=False,
)
integration = aws_apigatewayv2_integrations.HttpLambdaIntegration(
    "LambdaIntegration",
    function,
    payload_format_version=aws_apigatewayv2.PayloadFormatVersion.VERSION_2_0,
)
routes = api.add_routes(
    path="/work/{id}",
    methods=[aws_apigatewayv2.HttpMethod.GET],
    integration=integration,
)

deployment_resource = aws_apigatewayv2.CfnDeployment(
    stack,
    "Deployment",
    api_id=api.api_id,
    description="Explicit platform route deployment",
)
for route in routes:
    deployment_resource.add_dependency(route.node.default_child)

stage = aws_apigatewayv2.CfnStage(
    stack,
    "Stage",
    api_id=api.api_id,
    auto_deploy=False,
    deployment_id=deployment_resource.ref,
    description="Explicit default stage for the platform contract",
    stage_name="$default",
    tags={
        "component": "enterprise-platform",
        "deployment": deployment,
        "localstack:diagnostic-owner": owner,
    },
)

CfnOutput(stack, "ApiEndpoint", value=api.api_endpoint)
CfnOutput(stack, "ApiId", value=api.api_id)
CfnOutput(stack, "DeploymentAccount", value=stack.account)
CfnOutput(stack, "DeploymentId", value=deployment_resource.ref)
CfnOutput(stack, "DeploymentRegion", value=stack.region)
CfnOutput(stack, "FunctionName", value=function.function_name)
CfnOutput(stack, "QueueName", value=queue.queue_name)
CfnOutput(stack, "QueueUrl", value=queue.queue_url)
CfnOutput(stack, "StageName", value=stage.ref)
CfnOutput(stack, "TableName", value=table.table_name)
CfnOutput(stack, "TopicArn", value=topic.topic_arn)
CfnOutput(stack, "UserPoolClientId", value=client.user_pool_client_id)
CfnOutput(stack, "UserPoolId", value=pool.user_pool_id)

app.synth()
