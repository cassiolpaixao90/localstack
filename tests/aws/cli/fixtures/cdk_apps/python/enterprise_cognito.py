import os
import re

from aws_cdk import (
    App,
    CfnOutput,
    Environment,
    Fn,
    LegacyStackSynthesizer,
    RemovalPolicy,
    Stack,
    aws_cognito,
    aws_iam,
)

CONTEXT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
EXPLICIT_AUTH_FLOWS = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
]
CALLBACK_URL = "https://app.example.test/auth/callback"


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
account = required_environment("CDK_DEFAULT_ACCOUNT")
region = required_environment("CDK_DEFAULT_REGION")
prefix = f"{project}-{stage}-{deployment}"
if len(prefix) > 64:
    raise ValueError("combined project, stage, and deployment name exceeds 64 characters")

stack = Stack(
    app,
    "EnterpriseCognito",
    stack_name=f"{prefix}-auth",
    env=Environment(account=account, region=region),
    synthesizer=LegacyStackSynthesizer(),
    description="LocalStack diagnostic Cognito CDK verification stack",
)

user_pool = aws_cognito.CfnUserPool(
    stack,
    "UserPool",
    user_pool_name=f"{prefix}-auth",
)
for path, value in {
    "AccountRecoverySetting": {"RecoveryMechanisms": [{"Name": "verified_email", "Priority": 1}]},
    "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
    "AutoVerifiedAttributes": ["email"],
    "EmailVerificationMessage": "The verification code to your new account is {####}",
    "EmailVerificationSubject": "Verify your new account",
    "EnabledMfas": ["SOFTWARE_TOKEN_MFA"],
    "MfaConfiguration": "OPTIONAL",
    "Policies": {
        "PasswordPolicy": {
            "MinimumLength": 8,
            "RequireLowercase": True,
            "RequireNumbers": True,
            "RequireSymbols": True,
            "RequireUppercase": True,
        }
    },
    "Schema": [
        {"Mutable": False, "Name": "email", "Required": True},
        {
            "AttributeDataType": "String",
            "Mutable": True,
            "Name": "tenantId",
        },
    ],
    "SmsVerificationMessage": "The verification code to your new account is {####}",
    "UserPoolTags": {
        "component": "auth",
        "managed-by": "cdk",
        "project": project,
        "stage": stage,
    },
    "UsernameAttributes": ["email"],
    "VerificationMessageTemplate": {
        "DefaultEmailOption": "CONFIRM_WITH_CODE",
        "EmailMessage": "The verification code to your new account is {####}",
        "EmailSubject": "Verify your new account",
        "SmsMessage": "The verification code to your new account is {####}",
    },
}.items():
    user_pool.add_override(f"Properties.{path}", value)
user_pool.apply_removal_policy(RemovalPolicy.DESTROY)

resource_server_identifier = f"{prefix}-api"
resource_server = aws_cognito.CfnUserPoolResourceServer(
    stack,
    "UserPoolResourceServer",
    identifier=resource_server_identifier,
    name="Billgym API",
    scopes=[
        aws_cognito.CfnUserPoolResourceServer.ResourceServerScopeTypeProperty(
            scope_description="Read Billgym data",
            scope_name="read",
        ),
        aws_cognito.CfnUserPoolResourceServer.ResourceServerScopeTypeProperty(
            scope_description="Write Billgym data",
            scope_name="write",
        ),
    ],
    user_pool_id=user_pool.ref,
)
resource_server.apply_removal_policy(RemovalPolicy.DESTROY)

user_pool_client = aws_cognito.CfnUserPoolClient(
    stack,
    "UserPoolClient",
    client_name=f"{prefix}-web",
    explicit_auth_flows=EXPLICIT_AUTH_FLOWS,
    generate_secret=False,
    user_pool_id=user_pool.ref,
)
for path, value in {
    "AccessTokenValidity": 60,
    "AllowedOAuthFlows": ["implicit", "code"],
    "AllowedOAuthFlowsUserPoolClient": True,
    "AllowedOAuthScopes": [
        "profile",
        "phone",
        "email",
        "openid",
        "aws.cognito.signin.user.admin",
        Fn.join("/", [resource_server.ref, "read"]),
    ],
    "CallbackURLs": [CALLBACK_URL],
    "IdTokenValidity": 60,
    "PreventUserExistenceErrors": "ENABLED",
    "ReadAttributes": ["custom:tenantId", "email", "email_verified", "name"],
    "RefreshTokenValidity": 43200,
    "SupportedIdentityProviders": ["COGNITO"],
    "TokenValidityUnits": {
        "AccessToken": "minutes",
        "IdToken": "minutes",
        "RefreshToken": "minutes",
    },
    "WriteAttributes": ["email", "name", "preferred_username"],
}.items():
    user_pool_client.add_override(f"Properties.{path}", value)
user_pool_client.apply_removal_policy(RemovalPolicy.DESTROY)

user_pool_domain = aws_cognito.CfnUserPoolDomain(
    stack,
    "UserPoolDomain",
    domain=f"ls-{deployment}",
    managed_login_version=2,
    user_pool_id=user_pool.ref,
)
user_pool_domain.apply_removal_policy(RemovalPolicy.DESTROY)

groups = {}
for logical_id, group_name, precedence, description in (
    ("AdminGroup", "admin", 0, "Platform administrators"),
    ("TrainerGroup", "trainer", 1, "Tenant owners"),
    ("MemberGroup", "member", 10, "Tenant members"),
):
    group = aws_cognito.CfnUserPoolGroup(
        stack,
        logical_id,
        description=description,
        group_name=group_name,
        precedence=precedence,
        user_pool_id=user_pool.ref,
    )
    group.apply_removal_policy(RemovalPolicy.DESTROY)
    groups[group_name] = group

for logical_id, username, group_name in (
    ("Admin", "admin@example.test", "admin"),
    ("Trainer", "trainer@example.test", "trainer"),
    ("Member", "member@example.test", "member"),
):
    user = aws_cognito.CfnUserPoolUser(
        stack,
        f"{logical_id}User",
        message_action="SUPPRESS",
        user_attributes=[
            aws_cognito.CfnUserPoolUser.AttributeTypeProperty(
                name="email",
                value=username,
            ),
            aws_cognito.CfnUserPoolUser.AttributeTypeProperty(
                name="custom:tenantId",
                value="diagnostic",
            ),
        ],
        username=username,
        user_pool_id=user_pool.ref,
    )
    user.apply_removal_policy(RemovalPolicy.DESTROY)
    aws_cognito.CfnUserPoolUserToGroupAttachment(
        stack,
        f"{logical_id}Membership",
        group_name=groups[group_name].ref,
        username=user.ref,
        user_pool_id=user_pool.ref,
    )

identity_provider_name = user_pool.attr_provider_name
identity_pool = aws_cognito.CfnIdentityPool(
    stack,
    "IdentityPool",
    allow_unauthenticated_identities=False,
    cognito_identity_providers=[
        aws_cognito.CfnIdentityPool.CognitoIdentityProviderProperty(
            client_id=user_pool_client.ref,
            provider_name=identity_provider_name,
            server_side_token_check=True,
        )
    ],
    identity_pool_name=f"{prefix}-identity",
)
identity_pool.apply_removal_policy(RemovalPolicy.DESTROY)

authenticated_role = aws_iam.CfnRole(
    stack,
    "AuthenticatedRole",
    assume_role_policy_document={
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "ForAnyValue:StringEquals": {
                        "cognito-identity.amazonaws.com:amr": "authenticated"
                    },
                    "StringEquals": {
                        "cognito-identity.amazonaws.com:aud": identity_pool.ref
                    },
                },
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            }
        ],
    },
)
authenticated_role.apply_removal_policy(RemovalPolicy.DESTROY)

role_attachment = aws_cognito.CfnIdentityPoolRoleAttachment(
    stack,
    "IdentityPoolRoleAttachment",
    identity_pool_id=identity_pool.ref,
    roles={"authenticated": authenticated_role.attr_arn},
)
role_attachment.apply_removal_policy(RemovalPolicy.DESTROY)

principal_tag = aws_cognito.CfnIdentityPoolPrincipalTag(
    stack,
    "IdentityPoolPrincipalTag",
    identity_pool_id=identity_pool.ref,
    identity_provider_name=identity_provider_name,
    principal_tags={"tenant": "custom:tenantId"},
    use_defaults=False,
)
principal_tag.apply_removal_policy(RemovalPolicy.DESTROY)

CfnOutput(stack, "UserPoolId", value=user_pool.ref)
CfnOutput(stack, "UserPoolArn", value=user_pool.attr_arn)
CfnOutput(stack, "UserPoolClientId", value=user_pool_client.ref)
CfnOutput(stack, "AuthenticatedRoleArn", value=authenticated_role.attr_arn)
CfnOutput(stack, "IdentityPoolId", value=identity_pool.ref)
CfnOutput(stack, "IdentityPoolPrincipalTagId", value=principal_tag.ref)
CfnOutput(stack, "IdentityProviderName", value=identity_provider_name)
CfnOutput(stack, "DeploymentAccount", value=stack.account)
CfnOutput(stack, "DeploymentRegion", value=stack.region)

app.synth()
