import os
import re

from aws_cdk import (
    App,
    CfnOutput,
    Environment,
    LegacyStackSynthesizer,
    Stack,
    Tags,
    aws_apigatewayv2,
)

CONTEXT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
OWNER_PATTERN = re.compile(r"^[a-f0-9]{24}$")
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"required environment variable {name} is missing")
    return value


app = App()
deployment = app.node.try_get_context("deployment")
owner = app.node.try_get_context("owner")
if not isinstance(deployment, str) or not CONTEXT_PATTERN.fullmatch(deployment):
    raise ValueError("CDK context 'deployment' is invalid")
if not isinstance(owner, str) or not OWNER_PATTERN.fullmatch(owner):
    raise ValueError("CDK context 'owner' must be a 96-bit lowercase hexadecimal value")
account = required_environment("CDK_DEFAULT_ACCOUNT")
region = required_environment("CDK_DEFAULT_REGION")
certificate_arn = required_environment("CUSTOM_DOMAIN_CERTIFICATE_ARN")
domain_name = required_environment("CUSTOM_DOMAIN_NAME")
if not DOMAIN_PATTERN.fullmatch(domain_name):
    raise ValueError("CUSTOM_DOMAIN_NAME is invalid")
prefix = f"localstack-http-domain-{deployment}"

stack = Stack(
    app,
    "EnterpriseHttpApiCustomDomain",
    stack_name=prefix,
    env=Environment(account=account, region=region),
    synthesizer=LegacyStackSynthesizer(),
    description="Native HTTP API custom domain and mapping verification stack",
)
for key, value in {
    "component": "http-api-custom-domain",
    "deployment": deployment,
    "managed-by": "cdk",
    "localstack:diagnostic-owner": owner,
}.items():
    Tags.of(stack).add(key, value)

api = aws_apigatewayv2.CfnApi(
    stack,
    "HttpApi",
    name=f"{prefix}-api",
    protocol_type="HTTP",
    tags={"localstack:diagnostic-owner": owner},
)
integration = aws_apigatewayv2.CfnIntegration(
    stack,
    "HealthIntegration",
    api_id=api.ref,
    integration_method="GET",
    integration_type="HTTP_PROXY",
    integration_uri="http://localhost:4566/_localstack/health",
    payload_format_version="1.0",
)
route = aws_apigatewayv2.CfnRoute(
    stack,
    "HealthRoute",
    api_id=api.ref,
    route_key="GET /health",
    target=f"integrations/{integration.ref}",
)
deployment_resource = aws_apigatewayv2.CfnDeployment(
    stack,
    "Deployment",
    api_id=api.ref,
    description="Custom-domain route deployment",
)
deployment_resource.add_dependency(route)
stage = aws_apigatewayv2.CfnStage(
    stack,
    "Stage",
    api_id=api.ref,
    auto_deploy=False,
    deployment_id=deployment_resource.ref,
    stage_name="prod",
    tags={"localstack:diagnostic-owner": owner},
)
domain = aws_apigatewayv2.CfnDomainName(
    stack,
    "CustomDomain",
    domain_name=domain_name,
    domain_name_configurations=[
        aws_apigatewayv2.CfnDomainName.DomainNameConfigurationProperty(
            certificate_arn=certificate_arn,
            endpoint_type="REGIONAL",
            ip_address_type="ipv4",
            security_policy="TLS_1_2",
        )
    ],
    routing_mode="API_MAPPING_ONLY",
    tags={"localstack:diagnostic-owner": owner},
)
mapping = aws_apigatewayv2.CfnApiMapping(
    stack,
    "ApiMapping",
    api_id=api.ref,
    api_mapping_key="v1",
    domain_name=domain.ref,
    stage=stage.ref,
)
mapping.add_dependency(stage)

CfnOutput(stack, "ApiId", value=api.ref)
CfnOutput(stack, "ApiMappingId", value=mapping.ref)
CfnOutput(stack, "DeploymentAccount", value=stack.account)
CfnOutput(stack, "DeploymentId", value=deployment_resource.ref)
CfnOutput(stack, "DeploymentRegion", value=stack.region)
CfnOutput(stack, "DomainName", value=domain.ref)
CfnOutput(stack, "RegionalDomainName", value=domain.attr_regional_domain_name)
CfnOutput(stack, "StageName", value=stage.ref)

app.synth()
