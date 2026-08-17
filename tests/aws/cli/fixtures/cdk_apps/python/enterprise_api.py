import hashlib
import json
import os
import re

from aws_cdk import (
    App,
    CfnOutput,
    CfnTag,
    Environment,
    LegacyStackSynthesizer,
    RemovalPolicy,
    Stack,
    Tags,
    aws_apigateway,
)

CONTEXT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
HEALTH_METHOD_MODEL = {
    "AuthorizationType": "NONE",
    "HttpMethod": "GET",
    "Integration": {
        "Type": "MOCK",
        "PassthroughBehavior": "NEVER",
        "RequestTemplates": {"application/json": '{"statusCode": 200}'},
        "IntegrationResponses": [
            {
                "StatusCode": "200",
                "ResponseTemplates": {"application/json": '{"service":"localstack","status":"ok"}'},
            }
        ],
    },
    "MethodResponses": [{"StatusCode": "200"}],
}


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
project = context_value(app, "project", "localstack-enterprise")
stage = context_value(app, "stage", "dev")
deployment = context_value(app, "deployment")
owner = context_value(app, "owner", "platform")
account = required_environment("CDK_DEFAULT_ACCOUNT")
region = required_environment("CDK_DEFAULT_REGION")
prefix = f"{project}-{stage}-{deployment}"
if len(prefix) > 52:
    raise ValueError("combined project, stage, and deployment name exceeds 52 characters")

stack = Stack(
    app,
    "EnterpriseApi",
    stack_name=f"{prefix}-api",
    env=Environment(account=account, region=region),
    synthesizer=LegacyStackSynthesizer(),
    description="LocalStack enterprise API Gateway CDK verification stack",
)

for key, value in {
    "project": project,
    "env": stage,
    "component": "api",
    "managed-by": "cdk",
    "owner": owner,
}.items():
    Tags.of(stack).add(key, value)

api = aws_apigateway.CfnRestApi(
    stack,
    "Api",
    name=f"{prefix}-api",
    description="LocalStack enterprise API Gateway verification API",
    endpoint_configuration=aws_apigateway.CfnRestApi.EndpointConfigurationProperty(
        types=["REGIONAL"]
    ),
    tags=[
        CfnTag(key="project", value=project),
        CfnTag(key="env", value=stage),
        CfnTag(key="component", value="api"),
        CfnTag(key="managed-by", value="cdk"),
        CfnTag(key="owner", value=owner),
    ],
)
api.apply_removal_policy(RemovalPolicy.DESTROY)

method = aws_apigateway.CfnMethod(
    stack,
    "HealthMethod",
    rest_api_id=api.ref,
    resource_id=api.attr_root_resource_id,
    authorization_type=HEALTH_METHOD_MODEL["AuthorizationType"],
    http_method=HEALTH_METHOD_MODEL["HttpMethod"],
    integration=aws_apigateway.CfnMethod.IntegrationProperty(
        type=HEALTH_METHOD_MODEL["Integration"]["Type"],
        passthrough_behavior=HEALTH_METHOD_MODEL["Integration"]["PassthroughBehavior"],
        request_templates=HEALTH_METHOD_MODEL["Integration"]["RequestTemplates"],
        integration_responses=[
            aws_apigateway.CfnMethod.IntegrationResponseProperty(
                status_code=response["StatusCode"],
                response_templates=response["ResponseTemplates"],
            )
            for response in HEALTH_METHOD_MODEL["Integration"]["IntegrationResponses"]
        ],
    ),
    method_responses=[
        aws_apigateway.CfnMethod.MethodResponseProperty(status_code=response["StatusCode"])
        for response in HEALTH_METHOD_MODEL["MethodResponses"]
    ],
)

gateway_deployment = aws_apigateway.CfnDeployment(
    stack,
    "ApiDeployment",
    rest_api_id=api.ref,
    description="LocalStack enterprise API Gateway deployment",
)
method_fingerprint = hashlib.sha256(
    json.dumps(HEALTH_METHOD_MODEL, separators=(",", ":"), sort_keys=True).encode()
).hexdigest()[:12]
gateway_deployment.override_logical_id(f"ApiDeployment{method_fingerprint}")
gateway_deployment.add_dependency(method)

gateway_stage = aws_apigateway.CfnStage(
    stack,
    "ApiStage",
    rest_api_id=api.ref,
    deployment_id=gateway_deployment.ref,
    stage_name="local",
    description="LocalStack enterprise API Gateway local stage",
    tags=[
        CfnTag(key="project", value=project),
        CfnTag(key="env", value=stage),
        CfnTag(key="component", value="api"),
        CfnTag(key="managed-by", value="cdk"),
        CfnTag(key="owner", value=owner),
    ],
)

CfnOutput(stack, "ApiId", value=api.ref)
CfnOutput(stack, "ApiRootResourceId", value=api.attr_root_resource_id)
CfnOutput(stack, "ApiStageName", value=gateway_stage.stage_name)
CfnOutput(stack, "DeploymentAccount", value=stack.account)
CfnOutput(stack, "DeploymentRegion", value=stack.region)

app.synth()
