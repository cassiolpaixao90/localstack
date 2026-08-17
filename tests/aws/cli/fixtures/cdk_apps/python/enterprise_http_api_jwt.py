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
    aws_lambda,
)

CONTEXT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
OWNER_PATTERN = re.compile(r"^[a-f0-9]{24}$")
ORIGIN = "https://app.example.test"
LAMBDA_SOURCE = r"""
import json


def handler(event, context):
    jwt = event["requestContext"]["authorizer"]["jwt"]
    claims = jwt["claims"]
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json", "x-authenticated": "true"},
        "cookies": ["localstack-session=authenticated; Secure; HttpOnly; SameSite=Lax"],
        "body": json.dumps({
            "groups": claims.get("cognito:groups"),
            "pathId": event["pathParameters"]["id"],
            "scopes": jwt["scopes"],
            "subject": claims["sub"],
            "version": event["version"],
        }, sort_keys=True),
    }
"""


def context_value(app: App, name: str, default: str | None = None) -> str:
    value = app.node.try_get_context(name)
    if value is None:
        value = default
    if not isinstance(value, str) or not CONTEXT_PATTERN.fullmatch(value):
        raise ValueError(f"CDK context {name!r} must match {CONTEXT_PATTERN.pattern}")
    return value


def required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"required environment variable {name} is missing")
    return value


app = App()
deployment = context_value(app, "deployment")
owner = app.node.try_get_context("owner")
if not isinstance(owner, str) or not OWNER_PATTERN.fullmatch(owner):
    raise ValueError("CDK context 'owner' must be a 96-bit lowercase hexadecimal value")
account = required_environment("CDK_DEFAULT_ACCOUNT")
region = required_environment("CDK_DEFAULT_REGION")
prefix = f"localstack-http-jwt-{deployment}"
aws_dns_suffix = "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"

stack = Stack(
    app,
    "EnterpriseHttpApiJwt",
    stack_name=prefix,
    env=Environment(account=account, region=region),
    synthesizer=LegacyStackSynthesizer(),
    description="Native Cognito JWT to HTTP API Lambda verification stack",
)
for key, value in {
    "component": "http-api-jwt",
    "deployment": deployment,
    "managed-by": "cdk",
    "localstack:diagnostic-owner": owner,
}.items():
    Tags.of(stack).add(key, value)

pool = aws_cognito.UserPool(
    stack,
    "UserPool",
    user_pool_name=f"{prefix}-pool",
    account_recovery=aws_cognito.AccountRecovery.EMAIL_ONLY,
    self_sign_up_enabled=False,
    sign_in_aliases=aws_cognito.SignInAliases(email=True),
    password_policy=aws_cognito.PasswordPolicy(
        min_length=12,
        require_digits=True,
        require_lowercase=True,
        require_symbols=True,
        require_uppercase=True,
    ),
    removal_policy=RemovalPolicy.DESTROY,
)
client = pool.add_client(
    "UserPoolClient",
    user_pool_client_name=f"{prefix}-client",
    auth_flows=aws_cognito.AuthFlow(user_password=True, user_srp=True),
    generate_secret=False,
    prevent_user_existence_errors=True,
)

function = aws_lambda.Function(
    stack,
    "Handler",
    function_name=f"{prefix}-handler",
    runtime=aws_lambda.Runtime.PYTHON_3_12,
    architecture=aws_lambda.Architecture.X86_64,
    handler="index.handler",
    code=aws_lambda.Code.from_inline(LAMBDA_SOURCE),
    timeout=Duration.seconds(10),
)
function.apply_removal_policy(RemovalPolicy.DESTROY)

api = aws_apigatewayv2.HttpApi(
    stack,
    "HttpApi",
    api_name=f"{prefix}-api",
    create_default_stage=False,
    cors_preflight=aws_apigatewayv2.CorsPreflightOptions(
        allow_credentials=True,
        allow_headers=["authorization", "content-type"],
        allow_methods=[aws_apigatewayv2.CorsHttpMethod.GET],
        allow_origins=[ORIGIN],
        max_age=Duration.minutes(10),
    ),
)
integration = aws_apigatewayv2_integrations.HttpLambdaIntegration(
    "LambdaIntegration",
    function,
    payload_format_version=aws_apigatewayv2.PayloadFormatVersion.VERSION_2_0,
)
routes = api.add_routes(
    path="/private/{id}",
    methods=[aws_apigatewayv2.HttpMethod.GET],
    integration=integration,
)

authorizer = aws_apigatewayv2.CfnAuthorizer(
    stack,
    "JwtAuthorizer",
    api_id=api.api_id,
    authorizer_type="JWT",
    identity_source=["$request.header.Authorization"],
    jwt_configuration=aws_apigatewayv2.CfnAuthorizer.JWTConfigurationProperty(
        audience=[client.user_pool_client_id],
        issuer=f"https://cognito-idp.{region}.{aws_dns_suffix}/{pool.user_pool_id}",
    ),
    name=f"{prefix}-authorizer",
)
for route in routes:
    cfn_route = route.node.default_child
    if not isinstance(cfn_route, aws_apigatewayv2.CfnRoute):
        raise TypeError("HttpRoute did not synthesize an AWS::ApiGatewayV2::Route")
    cfn_route.authorization_type = "JWT"
    cfn_route.authorizer_id = authorizer.ref
    cfn_route.add_dependency(authorizer)

deployment_resource = aws_apigatewayv2.CfnDeployment(
    stack,
    "Deployment",
    api_id=api.api_id,
    description="Explicit JWT Lambda route deployment",
)
for route in routes:
    deployment_resource.add_dependency(route.node.default_child)

stage = aws_apigatewayv2.CfnStage(
    stack,
    "Stage",
    api_id=api.api_id,
    auto_deploy=False,
    deployment_id=deployment_resource.ref,
    description="Explicit default stage for JWT Lambda verification",
    stage_name="$default",
    stage_variables={"environment": "test"},
    tags={
        "component": "http-api-jwt",
        "deployment": deployment,
        "localstack:diagnostic-owner": owner,
    },
)

CfnOutput(stack, "ApiEndpoint", value=api.api_endpoint)
CfnOutput(stack, "ApiId", value=api.api_id)
CfnOutput(stack, "AuthorizerId", value=authorizer.ref)
CfnOutput(stack, "DeploymentId", value=deployment_resource.ref)
CfnOutput(stack, "DeploymentAccount", value=stack.account)
CfnOutput(stack, "DeploymentRegion", value=stack.region)
CfnOutput(stack, "FunctionName", value=function.function_name)
CfnOutput(stack, "StageName", value=stage.ref)
CfnOutput(stack, "UserPoolClientId", value=client.user_pool_client_id)
CfnOutput(stack, "UserPoolId", value=pool.user_pool_id)

app.synth()
