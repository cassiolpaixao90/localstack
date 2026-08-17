import os
import re

from aws_cdk import (
    App,
    CfnOutput,
    Environment,
    LegacyStackSynthesizer,
    RemovalPolicy,
    Stack,
    Tags,
    aws_dynamodb,
    aws_s3,
)

CONTEXT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,23}$")


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
    "EnterpriseData",
    stack_name=f"{prefix}-data",
    env=Environment(account=account, region=region),
    synthesizer=LegacyStackSynthesizer(),
    description="LocalStack enterprise data-plane CDK verification stack",
)

for key, value in {
    "project": project,
    "env": stage,
    "component": "data",
    "managed-by": "cdk",
    "owner": owner,
}.items():
    Tags.of(stack).add(key, value)

table = aws_dynamodb.CfnTable(
    stack,
    "Records",
    table_name=f"{prefix}-records",
    billing_mode="PAY_PER_REQUEST",
    attribute_definitions=[
        aws_dynamodb.CfnTable.AttributeDefinitionProperty(
            attribute_name="pk",
            attribute_type="S",
        )
    ],
    key_schema=[
        aws_dynamodb.CfnTable.KeySchemaProperty(
            attribute_name="pk",
            key_type="HASH",
        )
    ],
    point_in_time_recovery_specification=(
        aws_dynamodb.CfnTable.PointInTimeRecoverySpecificationProperty(
            point_in_time_recovery_enabled=True,
        )
    ),
    sse_specification=aws_dynamodb.CfnTable.SSESpecificationProperty(sse_enabled=True),
)
table.apply_removal_policy(RemovalPolicy.DESTROY)

bucket = aws_s3.CfnBucket(
    stack,
    "Artifacts",
    bucket_name=f"{prefix}-artifacts".lower(),
    bucket_encryption=aws_s3.CfnBucket.BucketEncryptionProperty(
        server_side_encryption_configuration=[
            aws_s3.CfnBucket.ServerSideEncryptionRuleProperty(
                server_side_encryption_by_default=(
                    aws_s3.CfnBucket.ServerSideEncryptionByDefaultProperty(sse_algorithm="AES256")
                )
            )
        ]
    ),
    ownership_controls=aws_s3.CfnBucket.OwnershipControlsProperty(
        rules=[
            aws_s3.CfnBucket.OwnershipControlsRuleProperty(object_ownership="BucketOwnerEnforced")
        ]
    ),
    public_access_block_configuration=aws_s3.CfnBucket.PublicAccessBlockConfigurationProperty(
        block_public_acls=True,
        block_public_policy=True,
        ignore_public_acls=True,
        restrict_public_buckets=True,
    ),
    versioning_configuration=aws_s3.CfnBucket.VersioningConfigurationProperty(status="Enabled"),
)
bucket.apply_removal_policy(RemovalPolicy.DESTROY)

CfnOutput(stack, "TableName", value=table.ref)
CfnOutput(stack, "BucketName", value=bucket.ref)
CfnOutput(stack, "DeploymentAccount", value=stack.account)
CfnOutput(stack, "DeploymentRegion", value=stack.region)

app.synth()
