import copy
import uuid
from unittest.mock import MagicMock

import pytest

from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.cognito_idp.client_configuration import (
    ClientConfigurationError,
    ClientScope,
    ProjectSnapshot,
    RoleSnapshot,
    normalize_explicit_auth_flows,
    parse_analytics_configuration,
    revalidate_analytics_configuration,
    validate_propagate_additional_context,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolclient import (
    CognitoUserPoolClientProvider,
)

ACCOUNT_ID = f"{uuid.uuid4().int % 10**12:012d}"
SCOPE = ClientScope(partition="aws", region="us-east-1", account_id=ACCOUNT_ID)
PROJECT_ARN = f"arn:aws:mobiletargeting:us-east-1:{ACCOUNT_ID}:apps/abcdef0123456789"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/cognito-pinpoint"


def _project(_reference):
    return ProjectSnapshot(
        application_arn=PROJECT_ARN,
        application_id="abcdef0123456789",
    )


def _role(*, external_id="analytics-external", deny=False, missing_action=False):
    actions = ["mobiletargeting:PutEvents"]
    if not missing_action:
        actions.append("mobiletargeting:UpdateEndpoint")
    statements = [
        {
            "Action": actions,
            "Effect": "Allow",
            "Resource": PROJECT_ARN,
        },
        {
            "Action": "cognito-idp:Describe*",
            "Effect": "Allow",
            "Resource": "*",
        },
    ]
    if deny:
        statements.append(
            {
                "Action": "mobiletargeting:PutEvents",
                "Effect": "Deny",
                "Resource": PROJECT_ARN,
            }
        )
    return RoleSnapshot(
        assume_role_policy={
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
                    "Effect": "Allow",
                    "Principal": {"Service": "cognito-idp.amazonaws.com"},
                }
            ],
            "Version": "2012-10-17",
        },
        permission_policies=({"Statement": statements, "Version": "2012-10-17"},),
        role_arn=ROLE_ARN,
        role_id="AROAEXAMPLE",
    )


def test_explicit_auth_defaults_and_deprecated_aliases_are_canonical():
    assert normalize_explicit_auth_flows(None) == (
        "ALLOW_CUSTOM_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
        "ALLOW_USER_SRP_AUTH",
    )
    assert normalize_explicit_auth_flows(
        ["ADMIN_NO_SRP_AUTH", "CUSTOM_AUTH_FLOW_ONLY", "USER_PASSWORD_AUTH"]
    ) == (
        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        "ALLOW_CUSTOM_AUTH",
        "ALLOW_USER_PASSWORD_AUTH",
    )


def test_additional_context_requires_a_client_secret():
    assert validate_propagate_additional_context(None, has_client_secret=False) is False
    assert validate_propagate_additional_context(True, has_client_secret=True) is True
    with pytest.raises(ClientConfigurationError, match="client secret"):
        validate_propagate_additional_context(True, has_client_secret=False)


def test_custom_role_analytics_is_scoped_and_snapshotted():
    role = _role()
    configuration = parse_analytics_configuration(
        {
            "ApplicationId": "abcdef0123456789",
            "ExternalId": "analytics-external",
            "RoleArn": ROLE_ARN,
            "UserDataShared": True,
        },
        scope=SCOPE,
        project_resolver=_project,
        role_resolver=lambda _: role,
    )

    assert configuration.to_api() == {
        "ApplicationId": "abcdef0123456789",
        "ExternalId": "analytics-external",
        "RoleArn": ROLE_ARN,
        "UserDataShared": True,
    }
    assert configuration.resource_snapshot
    revalidate_analytics_configuration(
        configuration,
        project_resolver=_project,
        role_resolver=lambda _: copy.deepcopy(role),
    )


@pytest.mark.parametrize(
    "role",
    [
        _role(external_id="wrong"),
        _role(deny=True),
        _role(missing_action=True),
    ],
)
def test_custom_role_analytics_fails_closed_on_trust_or_policy(role):
    with pytest.raises(ClientConfigurationError):
        parse_analytics_configuration(
            {
                "ApplicationId": "abcdef0123456789",
                "ExternalId": "analytics-external",
                "RoleArn": ROLE_ARN,
            },
            scope=SCOPE,
            project_resolver=_project,
            role_resolver=lambda _: role,
        )


def test_analytics_rejects_cross_scope_project_and_detects_aba():
    with pytest.raises(ClientConfigurationError, match="scope"):
        parse_analytics_configuration(
            {
                "ApplicationArn": (
                    f"arn:aws:mobiletargeting:eu-west-1:{ACCOUNT_ID}:apps/abcdef0123456789"
                )
            },
            scope=SCOPE,
            project_resolver=_project,
            role_resolver=lambda _: _role(),
        )

    configuration = parse_analytics_configuration(
        {"ApplicationArn": PROJECT_ARN},
        scope=SCOPE,
        project_resolver=_project,
        role_resolver=lambda _: _role(),
    )
    changed = ProjectSnapshot(
        application_arn=PROJECT_ARN,
        application_id="ffffffffffffffff",
    )
    with pytest.raises(ClientConfigurationError, match="changed"):
        revalidate_analytics_configuration(
            configuration,
            project_resolver=lambda _: changed,
            role_resolver=lambda _: _role(),
        )


def _request(*, cognito, desired_state, previous_state=None, pinpoint=None, iam=None):
    return type(
        "Request",
        (),
        {
            "account_id": SCOPE.account_id,
            "aws_client_factory": type(
                "Factory",
                (),
                {"cognito_idp": cognito, "iam": iam, "pinpoint": pinpoint},
            )(),
            "custom_context": {},
            "desired_state": desired_state,
            "logical_resource_id": "Client",
            "previous_state": previous_state,
            "region_name": SCOPE.region,
            "stack_name": "enterprise",
        },
    )()


def test_client_resource_provider_normalizes_aliases_and_validates_analytics():
    cognito = MagicMock()
    pinpoint = MagicMock()
    iam = MagicMock()
    pinpoint.get_app.return_value = {
        "ApplicationResponse": {"Arn": PROJECT_ARN, "Id": "abcdef0123456789"}
    }
    iam.get_role.return_value = {
        "Role": {
            "Arn": ROLE_ARN,
            "AssumeRolePolicyDocument": _role().assume_role_policy,
            "RoleId": "AROAEXAMPLE",
        }
    }
    iam.list_role_policies.return_value = {
        "IsTruncated": False,
        "PolicyNames": ["analytics"],
    }
    iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [],
        "IsTruncated": False,
    }
    iam.get_role_policy.return_value = {"PolicyDocument": _role().permission_policies[0]}
    desired = {
        "AnalyticsConfiguration": {
            "ApplicationId": "abcdef0123456789",
            "ExternalId": "analytics-external",
            "RoleArn": ROLE_ARN,
            "UserDataShared": True,
        },
        "ClientName": "analytics-client",
        "EnablePropagateAdditionalUserContextData": True,
        "ExplicitAuthFlows": ["CUSTOM_AUTH_FLOW_ONLY", "USER_PASSWORD_AUTH"],
        "GenerateSecret": True,
        "UserPoolId": "us-east-1_pool",
    }
    original = copy.deepcopy(desired)
    cognito.create_user_pool_client.return_value = {
        "UserPoolClient": {
            **desired,
            "ClientId": "client-id",
            "ClientSecret": "secret",
            "ExplicitAuthFlows": ["ALLOW_CUSTOM_AUTH", "ALLOW_USER_PASSWORD_AUTH"],
        }
    }

    result = CognitoUserPoolClientProvider().create(
        _request(
            cognito=cognito,
            desired_state=desired,
            pinpoint=pinpoint,
            iam=iam,
        )
    )

    assert result.status == OperationStatus.SUCCESS
    assert desired == original
    assert cognito.create_user_pool_client.call_args.kwargs["ExplicitAuthFlows"] == [
        "ALLOW_CUSTOM_AUTH",
        "ALLOW_USER_PASSWORD_AUTH",
    ]
    assert (
        cognito.create_user_pool_client.call_args.kwargs["AnalyticsConfiguration"]
        == (desired["AnalyticsConfiguration"])
    )
    assert pinpoint.get_app.call_count == 2
    assert iam.get_role.call_count == 2


def test_client_resource_provider_gates_context_and_resets_mutable_defaults():
    cognito = MagicMock()
    provider = CognitoUserPoolClientProvider()
    denied = provider.create(
        _request(
            cognito=cognito,
            desired_state={
                "EnablePropagateAdditionalUserContextData": True,
                "GenerateSecret": False,
                "UserPoolId": "us-east-1_pool",
            },
        )
    )
    assert denied.status == OperationStatus.FAILED
    assert "client secret" in denied.message
    cognito.assert_not_called()

    previous = {
        "AnalyticsConfiguration": {"ApplicationArn": PROJECT_ARN},
        "ClientId": "client-id",
        "ClientName": "analytics-client",
        "EnablePropagateAdditionalUserContextData": True,
        "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
        "GenerateSecret": True,
        "UserPoolId": "us-east-1_pool",
    }
    desired = {
        "ClientId": "client-id",
        "ClientName": "analytics-client",
        "GenerateSecret": True,
        "UserPoolId": "us-east-1_pool",
    }
    cognito.update_user_pool_client.return_value = {
        "UserPoolClient": {
            **desired,
            "ClientSecret": "secret",
            "ExplicitAuthFlows": list(normalize_explicit_auth_flows(None)),
        }
    }
    result = provider.update(
        _request(
            cognito=cognito,
            desired_state=desired,
            previous_state=previous,
        )
    )
    assert result.status == OperationStatus.SUCCESS
    assert cognito.update_user_pool_client.call_args.kwargs == {
        "ClientId": "client-id",
        "ClientName": "analytics-client",
        "EnablePropagateAdditionalUserContextData": False,
        "ExplicitAuthFlows": list(normalize_explicit_auth_flows(None)),
        "UserPoolId": "us-east-1_pool",
    }


def test_client_resource_provider_schema_permissions_and_read_contract():
    schema = CognitoUserPoolClientProvider.SCHEMA
    analytics = schema["properties"]["AnalyticsConfiguration"]
    assert analytics["additionalProperties"] is False
    assert set(analytics["properties"]) == {
        "ApplicationArn",
        "ApplicationId",
        "ExternalId",
        "RoleArn",
        "UserDataShared",
    }
    assert "ALLOW_CUSTOM_AUTH" in schema["properties"]["ExplicitAuthFlows"]["items"]["enum"]
    for operation in ("create", "update"):
        permissions = set(schema["handlers"][operation]["permissions"])
        assert {
            "iam:GetRole",
            "iam:GetRolePolicy",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "mobiletargeting:GetApp",
        } <= permissions

    cognito = MagicMock()
    cognito.describe_user_pool_client.return_value = {
        "UserPoolClient": {
            "AnalyticsConfiguration": {"ApplicationArn": PROJECT_ARN},
            "ClientId": "client-id",
            "ClientName": "analytics-client",
            "EnablePropagateAdditionalUserContextData": True,
            "ExplicitAuthFlows": ["CUSTOM_AUTH_FLOW_ONLY"],
            "UserPoolId": "us-east-1_pool",
        }
    }
    result = CognitoUserPoolClientProvider().read(
        _request(
            cognito=cognito,
            desired_state={"ClientId": "client-id", "UserPoolId": "us-east-1_pool"},
        )
    )
    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model["AnalyticsConfiguration"] == {"ApplicationArn": PROJECT_ARN}
    assert result.resource_model["EnablePropagateAdditionalUserContextData"] is True
    assert result.resource_model["ExplicitAuthFlows"] == ["ALLOW_CUSTOM_AUTH"]
