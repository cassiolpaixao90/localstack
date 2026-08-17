import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.aws.cli.test_cdk_cli_cognito_deploy import (
    _assert_no_baseline_collision,
    _delete_pool_clients,
    _deployment_from_owner_nonce,
    _load_outputs,
    _new_owner_nonce,
    _pool_inventory,
    _record_post_stack_delete_leaks,
    _record_stack_id,
    _rpc_client_config,
    _stack_is_absent,
    _validate_owned_stack,
    _validated_stack_resource_ids,
)

from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.utils.aws.arns import get_partition

PROJECT_ROOT = Path(__file__).parents[3]
APP_PATH = PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/enterprise_cognito.py"
TEST_OWNER_NONCE = "0123456789abcdef01234567"
TEST_DEPLOYMENT = f"d{TEST_OWNER_NONCE[:23]}"


def _deployment_outputs() -> dict:
    pool_id = f"{TEST_AWS_REGION_NAME}_pool"
    identity_pool_id = f"{TEST_AWS_REGION_NAME}:00000000-0000-4000-8000-000000000001"
    provider_name = f"cognito-idp.{TEST_AWS_REGION_NAME}.amazonaws.com/{pool_id}"
    return {
        "AuthenticatedRoleArn": (
            f"arn:{get_partition(TEST_AWS_REGION_NAME)}:iam::{TEST_AWS_ACCOUNT_ID}:"
            "role/authenticated-role"
        ),
        "DeploymentAccount": TEST_AWS_ACCOUNT_ID,
        "DeploymentRegion": TEST_AWS_REGION_NAME,
        "IdentityPoolId": identity_pool_id,
        "IdentityPoolPrincipalTagId": f"{identity_pool_id}|{provider_name}",
        "IdentityProviderName": provider_name,
        "UserPoolArn": (
            f"arn:{get_partition(TEST_AWS_REGION_NAME)}:cognito-idp:"
            f"{TEST_AWS_REGION_NAME}:{TEST_AWS_ACCOUNT_ID}:"
            f"userpool/{pool_id}"
        ),
        "UserPoolClientId": "clientid",
        "UserPoolId": pool_id,
    }


def test_enterprise_cognito_output_parser_accepts_only_the_expected_deployment(tmp_path):
    path = tmp_path / "outputs.json"
    expected = _deployment_outputs()
    path.write_text(json.dumps({"expected-stack": expected}))

    assert (
        _load_outputs(
            path,
            stack_name="expected-stack",
            account_id=TEST_AWS_ACCOUNT_ID,
            region_name=TEST_AWS_REGION_NAME,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("payload", "stack_name", "account_id", "message"),
    [
        (
            {"wrong-stack": _deployment_outputs()},
            "expected-stack",
            TEST_AWS_ACCOUNT_ID,
            "exactly the deployed stack",
        ),
        (
            {"expected-stack": _deployment_outputs() | {"Unexpected": "value"}},
            "expected-stack",
            TEST_AWS_ACCOUNT_ID,
            "closed Cognito contract",
        ),
        (
            {"expected-stack": _deployment_outputs()},
            "expected-stack",
            "mismatched-account",
            "account does not match",
        ),
        (
            {
                "expected-stack": _deployment_outputs()
                | {"UserPoolArn": "arn:aws:cognito-idp:invalid:invalid:userpool/invalid"}
            },
            "expected-stack",
            TEST_AWS_ACCOUNT_ID,
            "ARN does not match",
        ),
    ],
)
def test_enterprise_cognito_output_parser_fails_closed(
    tmp_path,
    payload: dict,
    stack_name: str,
    account_id: str,
    message: str,
):
    path = tmp_path / "outputs.json"
    path.write_text(json.dumps(payload))

    with pytest.raises(ValueError, match=message):
        _load_outputs(
            path,
            stack_name=stack_name,
            account_id=account_id,
            region_name=TEST_AWS_REGION_NAME,
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"UserPoolArn": f"arn:wrong:cognito-idp:{TEST_AWS_REGION_NAME}:x:userpool/x"},
            "ARN does not match",
        ),
        ({"UserPoolId": "invalid-pool-id"}, "UserPoolId"),
        ({"UserPoolClientId": "invalid client id"}, "UserPoolClientId"),
    ],
)
def test_enterprise_cognito_output_parser_rejects_partition_and_unbounded_identities(
    tmp_path,
    overrides: dict,
    message: str,
):
    path = tmp_path / "outputs.json"
    path.write_text(json.dumps({"expected-stack": _deployment_outputs() | overrides}))

    with pytest.raises(ValueError, match=message):
        _load_outputs(
            path,
            stack_name="expected-stack",
            account_id=TEST_AWS_ACCOUNT_ID,
            region_name=TEST_AWS_REGION_NAME,
        )


def test_cognito_ownership_rejects_baseline_collisions():
    baseline = {
        "baseline-id": "baseline-name",
        "collision-id": "owned-name",
    }
    with pytest.raises(RuntimeError, match="pool name collision"):
        _assert_no_baseline_collision(
            stack_absent=True,
            baseline_pools=baseline,
            pool_name="owned-name",
        )
    with pytest.raises(RuntimeError, match="stack name collision"):
        _assert_no_baseline_collision(
            stack_absent=False,
            baseline_pools={},
            pool_name="owned-name",
        )


def test_cognito_ownership_uses_a_96_bit_nonce_and_immutable_stack_id():
    nonce = _new_owner_nonce()
    assert len(nonce) == 24
    assert int(nonce, 16) >= 0

    stack_id = (
        f"arn:{get_partition(TEST_AWS_REGION_NAME)}:cloudformation:"
        f"{TEST_AWS_REGION_NAME}:{TEST_AWS_ACCOUNT_ID}:"
        "stack/expected-stack/12345678-1234-1234-1234-123456789012"
    )
    assert _record_stack_id(None, stack_id) == stack_id
    assert _record_stack_id(stack_id, stack_id) == stack_id
    with pytest.raises(RuntimeError, match="StackId changed"):
        _record_stack_id(stack_id, f"{stack_id}-replacement")


def test_cognito_deployment_context_is_valid_when_owner_nonce_starts_with_a_digit():
    assert _deployment_from_owner_nonce(TEST_OWNER_NONCE) == TEST_DEPLOYMENT
    assert len(TEST_DEPLOYMENT) == 24
    assert TEST_DEPLOYMENT.startswith("d0")


def test_cognito_owned_stack_requires_tag_identity_and_create_complete():
    nonce = TEST_OWNER_NONCE
    stack_id = (
        f"arn:{get_partition(TEST_AWS_REGION_NAME)}:cloudformation:"
        f"{TEST_AWS_REGION_NAME}:{TEST_AWS_ACCOUNT_ID}:"
        "stack/expected-stack/12345678-1234-1234-1234-123456789012"
    )
    stack = {
        "StackId": stack_id,
        "StackName": "expected-stack",
        "StackStatus": "CREATE_COMPLETE",
        "Tags": [{"Key": "localstack:diagnostic-owner", "Value": nonce}],
    }
    assert (
        _validate_owned_stack(
            stack,
            stack_name="expected-stack",
            owner_nonce=nonce,
            account_id=TEST_AWS_ACCOUNT_ID,
            region_name=TEST_AWS_REGION_NAME,
            require_create_complete=True,
        )
        == stack_id
    )

    with pytest.raises(RuntimeError, match="owner tag"):
        _validate_owned_stack(
            stack | {"Tags": []},
            stack_name="expected-stack",
            owner_nonce=nonce,
            account_id=TEST_AWS_ACCOUNT_ID,
            region_name=TEST_AWS_REGION_NAME,
            require_create_complete=True,
        )
    with pytest.raises(RuntimeError, match="CREATE_COMPLETE"):
        _validate_owned_stack(
            stack | {"StackStatus": "CREATE_FAILED"},
            stack_name="expected-stack",
            owner_nonce=nonce,
            account_id=TEST_AWS_ACCOUNT_ID,
            region_name=TEST_AWS_REGION_NAME,
            require_create_complete=True,
        )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("DELETE_COMPLETE", True),
        ("DELETE_FAILED", False),
        ("CREATE_COMPLETE", False),
    ],
)
def test_cognito_cleanup_treats_only_terminal_delete_complete_as_absent(status, expected):
    cloudformation = MagicMock()
    cloudformation.describe_stacks.return_value = {"Stacks": [{"StackStatus": status}]}

    assert _stack_is_absent(cloudformation, "immutable-stack-arn") is expected


def test_cognito_stack_resources_are_closed_and_bind_outputs_to_physical_ids():
    stack_id = "owned-stack-id"
    pool_id = f"{TEST_AWS_REGION_NAME}_pool"
    identity_pool_id = f"{TEST_AWS_REGION_NAME}:00000000-0000-4000-8000-000000000001"
    provider_name = f"cognito-idp.{TEST_AWS_REGION_NAME}.amazonaws.com/{pool_id}"
    principal_tag_id = f"{identity_pool_id}|{provider_name}"
    role_arn = (
        f"arn:{get_partition(TEST_AWS_REGION_NAME)}:iam::{TEST_AWS_ACCOUNT_ID}:"
        "role/authenticated-role"
    )
    resources = [
        {
            "StackId": stack_id,
            "LogicalResourceId": "AdminGroup",
            "PhysicalResourceId": "admin",
            "ResourceType": "AWS::Cognito::UserPoolGroup",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "AdminUser",
            "PhysicalResourceId": "admin@example.test",
            "ResourceType": "AWS::Cognito::UserPoolUser",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "AdminMembership",
            "PhysicalResourceId": "UserToGroupAttachment-0123456789abcdef",
            "ResourceType": "AWS::Cognito::UserPoolUserToGroupAttachment",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "MemberGroup",
            "PhysicalResourceId": "member",
            "ResourceType": "AWS::Cognito::UserPoolGroup",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "MemberUser",
            "PhysicalResourceId": "member@example.test",
            "ResourceType": "AWS::Cognito::UserPoolUser",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "MemberMembership",
            "PhysicalResourceId": "UserToGroupAttachment-1234567890abcdef",
            "ResourceType": "AWS::Cognito::UserPoolUserToGroupAttachment",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "TrainerGroup",
            "PhysicalResourceId": "trainer",
            "ResourceType": "AWS::Cognito::UserPoolGroup",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "TrainerUser",
            "PhysicalResourceId": "trainer@example.test",
            "ResourceType": "AWS::Cognito::UserPoolUser",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "TrainerMembership",
            "PhysicalResourceId": "UserToGroupAttachment-abcdef0123456789",
            "ResourceType": "AWS::Cognito::UserPoolUserToGroupAttachment",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "UserPool",
            "PhysicalResourceId": pool_id,
            "ResourceType": "AWS::Cognito::UserPool",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "UserPoolClient",
            "PhysicalResourceId": "clientid",
            "ResourceType": "AWS::Cognito::UserPoolClient",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "UserPoolDomain",
            "PhysicalResourceId": f"ls-{TEST_DEPLOYMENT}",
            "ResourceType": "AWS::Cognito::UserPoolDomain",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "UserPoolResourceServer",
            "PhysicalResourceId": f"localstack-enterprise-dev-{TEST_DEPLOYMENT}-api",
            "ResourceType": "AWS::Cognito::UserPoolResourceServer",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "AuthenticatedRole",
            "PhysicalResourceId": "authenticated-role",
            "ResourceType": "AWS::IAM::Role",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "IdentityPool",
            "PhysicalResourceId": identity_pool_id,
            "ResourceType": "AWS::Cognito::IdentityPool",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "IdentityPoolRoleAttachment",
            "PhysicalResourceId": identity_pool_id,
            "ResourceType": "AWS::Cognito::IdentityPoolRoleAttachment",
        },
        {
            "StackId": stack_id,
            "LogicalResourceId": "IdentityPoolPrincipalTag",
            "PhysicalResourceId": principal_tag_id,
            "ResourceType": "AWS::Cognito::IdentityPoolPrincipalTag",
        },
    ]
    assert _validated_stack_resource_ids(
        resources,
        stack_id=stack_id,
        expected_pool_id=pool_id,
        expected_client_id="clientid",
        expected_identity_pool_id=identity_pool_id,
        expected_principal_tag_id=principal_tag_id,
        expected_role_arn=role_arn,
        expected_resource_server_id=f"localstack-enterprise-dev-{TEST_DEPLOYMENT}-api",
    ) == {
        "AdminGroup": "admin",
        "AdminMembership": "UserToGroupAttachment-0123456789abcdef",
        "AdminUser": "admin@example.test",
        "MemberGroup": "member",
        "MemberMembership": "UserToGroupAttachment-1234567890abcdef",
        "MemberUser": "member@example.test",
        "TrainerGroup": "trainer",
        "TrainerMembership": "UserToGroupAttachment-abcdef0123456789",
        "TrainerUser": "trainer@example.test",
        "UserPool": pool_id,
        "UserPoolClient": "clientid",
        "UserPoolDomain": f"ls-{TEST_DEPLOYMENT}",
        "UserPoolResourceServer": f"localstack-enterprise-dev-{TEST_DEPLOYMENT}-api",
        "AuthenticatedRole": "authenticated-role",
        "IdentityPool": identity_pool_id,
        "IdentityPoolRoleAttachment": identity_pool_id,
        "IdentityPoolPrincipalTag": principal_tag_id,
    }

    with pytest.raises(RuntimeError, match="resource contract"):
        _validated_stack_resource_ids(
            resources
            + [
                {
                    "StackId": stack_id,
                    "LogicalResourceId": "Foreign",
                    "PhysicalResourceId": "foreign",
                    "ResourceType": "AWS::Cognito::UserPool",
                }
            ],
            stack_id=stack_id,
            expected_pool_id=pool_id,
            expected_client_id="clientid",
        )

    assert (
        _validated_stack_resource_ids(
            [
                {
                    "StackId": stack_id,
                    "LogicalResourceId": "IdentityPoolPrincipalTag",
                    "ResourceType": "AWS::Cognito::IdentityPoolPrincipalTag",
                    "ResourceStatus": "CREATE_FAILED",
                }
            ],
            stack_id=stack_id,
            require_complete=False,
        )
        == {}
    )


def test_cognito_post_delete_leak_is_reported_before_fallback_cleanup():
    pool_id = f"{TEST_AWS_REGION_NAME}_pool"
    cleanup_errors = []
    current_pools = {pool_id: "owned-name"}
    assert _record_post_stack_delete_leaks(
        cleanup_errors,
        owned_pool_ids={pool_id},
        current_pools=current_pools,
        stack_delete_completed=True,
    ) == {pool_id}

    current_pools.clear()
    assert len(cleanup_errors) == 1
    assert "delete completed" in str(cleanup_errors[0])


def test_cognito_rpc_clients_have_short_timeouts_and_one_total_attempt():
    config = _rpc_client_config()
    assert config.connect_timeout == 2
    assert config.read_timeout == 2
    assert config.retries == {"mode": "standard", "total_max_attempts": 1}


def test_pool_inventory_fails_closed_at_page_limit_and_deadline():
    cognito_idp = MagicMock()
    cognito_idp.list_user_pools.side_effect = [
        {"NextToken": "page-2", "UserPools": []},
        {"NextToken": "page-3", "UserPools": []},
    ]
    with pytest.raises(RuntimeError, match="maximum page count"):
        _pool_inventory(
            cognito_idp,
            max_pages=2,
            deadline_seconds=10,
            clock=lambda: 0,
        )

    with pytest.raises(RuntimeError, match="deadline"):
        _pool_inventory(
            cognito_idp,
            max_pages=2,
            deadline_seconds=0,
            clock=lambda: 1,
        )


def test_client_cleanup_fails_closed_before_deleting_when_pagination_is_unbounded():
    cognito_idp = MagicMock()
    cognito_idp.list_user_pool_clients.side_effect = [
        {
            "NextToken": "page-2",
            "UserPoolClients": [{"ClientId": "clientone"}],
        },
        {
            "NextToken": "page-3",
            "UserPoolClients": [{"ClientId": "clienttwo"}],
        },
    ]

    with pytest.raises(RuntimeError, match="maximum page count"):
        _delete_pool_clients(
            cognito_idp,
            f"{TEST_AWS_REGION_NAME}_pool",
            max_pages=2,
            deadline_seconds=10,
            clock=lambda: 0,
        )

    cognito_idp.delete_user_pool_client.assert_not_called()


def test_client_cleanup_uses_one_deadline_for_listing_and_deletion():
    cognito_idp = MagicMock()
    cognito_idp.list_user_pool_clients.return_value = {
        "UserPoolClients": [{"ClientId": "clientone"}],
    }
    clock_values = iter([0, 0, 2])

    with pytest.raises(RuntimeError, match="cleanup exceeded its deadline"):
        _delete_pool_clients(
            cognito_idp,
            f"{TEST_AWS_REGION_NAME}_pool",
            deadline_seconds=1,
            clock=lambda: next(clock_values),
        )

    cognito_idp.delete_user_pool_client.assert_not_called()


def test_enterprise_cognito_app_synthesizes_the_closed_contract(tmp_path):
    output = tmp_path / "cdk.out"
    environment = {
        **os.environ,
        "CDK_CONTEXT_JSON": json.dumps(
            {
                "deployment": TEST_DEPLOYMENT,
                "project": "localstack-enterprise",
                "stage": "dev",
            },
            sort_keys=True,
        ),
        "CDK_DEFAULT_ACCOUNT": TEST_AWS_ACCOUNT_ID,
        "CDK_DEFAULT_REGION": TEST_AWS_REGION_NAME,
        "CDK_OUTDIR": str(output),
    }
    subprocess.run(
        [sys.executable, "-I", "-B", str(APP_PATH)],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=30,
    )

    template = json.loads((output / "EnterpriseCognito.template.json").read_bytes())
    assert template == {
        "Description": "LocalStack diagnostic Cognito CDK verification stack",
        "Resources": {
            "UserPool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {
                    "AccountRecoverySetting": {
                        "RecoveryMechanisms": [{"Name": "verified_email", "Priority": 1}]
                    },
                    "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
                    "AutoVerifiedAttributes": ["email"],
                    "EmailVerificationMessage": (
                        "The verification code to your new account is {####}"
                    ),
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
                    "SmsVerificationMessage": (
                        "The verification code to your new account is {####}"
                    ),
                    "UserPoolName": f"localstack-enterprise-dev-{TEST_DEPLOYMENT}-auth",
                    "UserPoolTags": {
                        "component": "auth",
                        "managed-by": "cdk",
                        "project": "localstack-enterprise",
                        "stage": "dev",
                    },
                    "UsernameAttributes": ["email"],
                    "VerificationMessageTemplate": {
                        "DefaultEmailOption": "CONFIRM_WITH_CODE",
                        "EmailMessage": "The verification code to your new account is {####}",
                        "EmailSubject": "Verify your new account",
                        "SmsMessage": "The verification code to your new account is {####}",
                    },
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "UserPoolClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "AccessTokenValidity": 60,
                    "AllowedOAuthFlows": ["implicit", "code"],
                    "AllowedOAuthFlowsUserPoolClient": True,
                    "AllowedOAuthScopes": [
                        "profile",
                        "phone",
                        "email",
                        "openid",
                        "aws.cognito.signin.user.admin",
                        {
                            "Fn::Join": [
                                "/",
                                [{"Ref": "UserPoolResourceServer"}, "read"],
                            ]
                        },
                    ],
                    "CallbackURLs": ["https://app.example.test/auth/callback"],
                    "ClientName": f"localstack-enterprise-dev-{TEST_DEPLOYMENT}-web",
                    "ExplicitAuthFlows": [
                        "ALLOW_REFRESH_TOKEN_AUTH",
                        "ALLOW_USER_SRP_AUTH",
                    ],
                    "GenerateSecret": False,
                    "IdTokenValidity": 60,
                    "PreventUserExistenceErrors": "ENABLED",
                    "ReadAttributes": [
                        "custom:tenantId",
                        "email",
                        "email_verified",
                        "name",
                    ],
                    "RefreshTokenValidity": 43200,
                    "SupportedIdentityProviders": ["COGNITO"],
                    "TokenValidityUnits": {
                        "AccessToken": "minutes",
                        "IdToken": "minutes",
                        "RefreshToken": "minutes",
                    },
                    "UserPoolId": {"Ref": "UserPool"},
                    "WriteAttributes": ["email", "name", "preferred_username"],
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "UserPoolResourceServer": {
                "Type": "AWS::Cognito::UserPoolResourceServer",
                "Properties": {
                    "Identifier": f"localstack-enterprise-dev-{TEST_DEPLOYMENT}-api",
                    "Name": "Billgym API",
                    "Scopes": [
                        {
                            "ScopeDescription": "Read Billgym data",
                            "ScopeName": "read",
                        },
                        {
                            "ScopeDescription": "Write Billgym data",
                            "ScopeName": "write",
                        },
                    ],
                    "UserPoolId": {"Ref": "UserPool"},
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "UserPoolDomain": {
                "Type": "AWS::Cognito::UserPoolDomain",
                "Properties": {
                    "Domain": f"ls-{TEST_DEPLOYMENT}",
                    "ManagedLoginVersion": 2,
                    "UserPoolId": {"Ref": "UserPool"},
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "AdminGroup": {
                "Type": "AWS::Cognito::UserPoolGroup",
                "Properties": {
                    "Description": "Platform administrators",
                    "GroupName": "admin",
                    "Precedence": 0,
                    "UserPoolId": {"Ref": "UserPool"},
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "TrainerGroup": {
                "Type": "AWS::Cognito::UserPoolGroup",
                "Properties": {
                    "Description": "Tenant owners",
                    "GroupName": "trainer",
                    "Precedence": 1,
                    "UserPoolId": {"Ref": "UserPool"},
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "MemberGroup": {
                "Type": "AWS::Cognito::UserPoolGroup",
                "Properties": {
                    "Description": "Tenant members",
                    "GroupName": "member",
                    "Precedence": 10,
                    "UserPoolId": {"Ref": "UserPool"},
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "AdminUser": {
                "Type": "AWS::Cognito::UserPoolUser",
                "Properties": {
                    "MessageAction": "SUPPRESS",
                    "UserAttributes": [
                        {"Name": "email", "Value": "admin@example.test"},
                        {"Name": "custom:tenantId", "Value": "diagnostic"},
                    ],
                    "Username": "admin@example.test",
                    "UserPoolId": {"Ref": "UserPool"},
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "TrainerUser": {
                "Type": "AWS::Cognito::UserPoolUser",
                "Properties": {
                    "MessageAction": "SUPPRESS",
                    "UserAttributes": [
                        {"Name": "email", "Value": "trainer@example.test"},
                        {"Name": "custom:tenantId", "Value": "diagnostic"},
                    ],
                    "Username": "trainer@example.test",
                    "UserPoolId": {"Ref": "UserPool"},
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "MemberUser": {
                "Type": "AWS::Cognito::UserPoolUser",
                "Properties": {
                    "MessageAction": "SUPPRESS",
                    "UserAttributes": [
                        {"Name": "email", "Value": "member@example.test"},
                        {"Name": "custom:tenantId", "Value": "diagnostic"},
                    ],
                    "Username": "member@example.test",
                    "UserPoolId": {"Ref": "UserPool"},
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "AdminMembership": {
                "Type": "AWS::Cognito::UserPoolUserToGroupAttachment",
                "Properties": {
                    "GroupName": {"Ref": "AdminGroup"},
                    "Username": {"Ref": "AdminUser"},
                    "UserPoolId": {"Ref": "UserPool"},
                },
            },
            "TrainerMembership": {
                "Type": "AWS::Cognito::UserPoolUserToGroupAttachment",
                "Properties": {
                    "GroupName": {"Ref": "TrainerGroup"},
                    "Username": {"Ref": "TrainerUser"},
                    "UserPoolId": {"Ref": "UserPool"},
                },
            },
            "MemberMembership": {
                "Type": "AWS::Cognito::UserPoolUserToGroupAttachment",
                "Properties": {
                    "GroupName": {"Ref": "MemberGroup"},
                    "Username": {"Ref": "MemberUser"},
                    "UserPoolId": {"Ref": "UserPool"},
                },
            },
            "IdentityPool": {
                "Type": "AWS::Cognito::IdentityPool",
                "Properties": {
                    "AllowUnauthenticatedIdentities": False,
                    "CognitoIdentityProviders": [
                        {
                            "ClientId": {"Ref": "UserPoolClient"},
                            "ProviderName": {"Fn::GetAtt": ["UserPool", "ProviderName"]},
                            "ServerSideTokenCheck": True,
                        }
                    ],
                    "IdentityPoolName": (f"localstack-enterprise-dev-{TEST_DEPLOYMENT}-identity"),
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "AuthenticatedRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Action": "sts:AssumeRoleWithWebIdentity",
                                "Condition": {
                                    "ForAnyValue:StringEquals": {
                                        "cognito-identity.amazonaws.com:amr": "authenticated"
                                    },
                                    "StringEquals": {
                                        "cognito-identity.amazonaws.com:aud": {
                                            "Ref": "IdentityPool"
                                        }
                                    },
                                },
                                "Effect": "Allow",
                                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                            }
                        ],
                    }
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "IdentityPoolRoleAttachment": {
                "Type": "AWS::Cognito::IdentityPoolRoleAttachment",
                "Properties": {
                    "IdentityPoolId": {"Ref": "IdentityPool"},
                    "Roles": {"authenticated": {"Fn::GetAtt": ["AuthenticatedRole", "Arn"]}},
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "IdentityPoolPrincipalTag": {
                "Type": "AWS::Cognito::IdentityPoolPrincipalTag",
                "Properties": {
                    "IdentityPoolId": {"Ref": "IdentityPool"},
                    "IdentityProviderName": {"Fn::GetAtt": ["UserPool", "ProviderName"]},
                    "PrincipalTags": {"tenant": "custom:tenantId"},
                    "UseDefaults": False,
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
        },
        "Outputs": {
            "AuthenticatedRoleArn": {"Value": {"Fn::GetAtt": ["AuthenticatedRole", "Arn"]}},
            "IdentityPoolId": {"Value": {"Ref": "IdentityPool"}},
            "IdentityPoolPrincipalTagId": {"Value": {"Ref": "IdentityPoolPrincipalTag"}},
            "IdentityProviderName": {"Value": {"Fn::GetAtt": ["UserPool", "ProviderName"]}},
            "UserPoolId": {"Value": {"Ref": "UserPool"}},
            "UserPoolArn": {"Value": {"Fn::GetAtt": ["UserPool", "Arn"]}},
            "UserPoolClientId": {"Value": {"Ref": "UserPoolClient"}},
            "DeploymentAccount": {"Value": TEST_AWS_ACCOUNT_ID},
            "DeploymentRegion": {"Value": TEST_AWS_REGION_NAME},
        },
    }


def test_enterprise_cognito_identity_federation_contract_is_strict(tmp_path):
    output = tmp_path / "cdk.out"
    environment = {
        **os.environ,
        "CDK_CONTEXT_JSON": json.dumps(
            {
                "deployment": TEST_DEPLOYMENT,
                "project": "localstack-enterprise",
                "stage": "dev",
            },
            sort_keys=True,
        ),
        "CDK_DEFAULT_ACCOUNT": TEST_AWS_ACCOUNT_ID,
        "CDK_DEFAULT_REGION": TEST_AWS_REGION_NAME,
        "CDK_OUTDIR": str(output),
    }
    subprocess.run(
        [sys.executable, "-I", "-B", str(APP_PATH)],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=30,
    )
    template = json.loads((output / "EnterpriseCognito.template.json").read_bytes())
    resources = template["Resources"]
    prefix = f"localstack-enterprise-dev-{TEST_DEPLOYMENT}"

    assert resources["IdentityPool"] == {
        "Type": "AWS::Cognito::IdentityPool",
        "Properties": {
            "AllowUnauthenticatedIdentities": False,
            "CognitoIdentityProviders": [
                {
                    "ClientId": {"Ref": "UserPoolClient"},
                    "ProviderName": {"Fn::GetAtt": ["UserPool", "ProviderName"]},
                    "ServerSideTokenCheck": True,
                }
            ],
            "IdentityPoolName": f"{prefix}-identity",
        },
        "UpdateReplacePolicy": "Delete",
        "DeletionPolicy": "Delete",
    }
    assert resources["AuthenticatedRole"] == {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "ForAnyValue:StringEquals": {
                                "cognito-identity.amazonaws.com:amr": "authenticated"
                            },
                            "StringEquals": {
                                "cognito-identity.amazonaws.com:aud": {"Ref": "IdentityPool"}
                            },
                        },
                        "Effect": "Allow",
                        "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                    }
                ],
            }
        },
        "UpdateReplacePolicy": "Delete",
        "DeletionPolicy": "Delete",
    }
    assert resources["IdentityPoolRoleAttachment"] == {
        "Type": "AWS::Cognito::IdentityPoolRoleAttachment",
        "Properties": {
            "IdentityPoolId": {"Ref": "IdentityPool"},
            "Roles": {"authenticated": {"Fn::GetAtt": ["AuthenticatedRole", "Arn"]}},
        },
        "UpdateReplacePolicy": "Delete",
        "DeletionPolicy": "Delete",
    }
    assert resources["IdentityPoolPrincipalTag"] == {
        "Type": "AWS::Cognito::IdentityPoolPrincipalTag",
        "Properties": {
            "IdentityPoolId": {"Ref": "IdentityPool"},
            "IdentityProviderName": {"Fn::GetAtt": ["UserPool", "ProviderName"]},
            "PrincipalTags": {"tenant": "custom:tenantId"},
            "UseDefaults": False,
        },
        "UpdateReplacePolicy": "Delete",
        "DeletionPolicy": "Delete",
    }
    assert {
        "AdminUser",
        "TrainerUser",
        "MemberUser",
        "AdminMembership",
        "TrainerMembership",
        "MemberMembership",
    } <= set(resources)
    expected_outputs = {
        "AuthenticatedRoleArn": {"Value": {"Fn::GetAtt": ["AuthenticatedRole", "Arn"]}},
        "IdentityPoolId": {"Value": {"Ref": "IdentityPool"}},
        "IdentityPoolPrincipalTagId": {"Value": {"Ref": "IdentityPoolPrincipalTag"}},
        "IdentityProviderName": {"Value": {"Fn::GetAtt": ["UserPool", "ProviderName"]}},
    }
    assert {key: template["Outputs"].get(key) for key in expected_outputs} == expected_outputs
