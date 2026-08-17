import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.cognito_idp.resource_providers import (
    aws_cognito_userpool,
    aws_cognito_userpoolclient,
    aws_cognito_userpooldomain,
)

# AWS CloudFormation registry schema 260.0.0, downloaded from the official
# us-east-1 schema endpoint on 2026-08-10.
OFFICIAL_PROPERTIES = {
    "AWS::Cognito::UserPool": {
        "AccountRecoverySetting",
        "AdminCreateUserConfig",
        "AliasAttributes",
        "Arn",
        "AutoVerifiedAttributes",
        "DeletionProtection",
        "DeviceConfiguration",
        "EmailAuthenticationMessage",
        "EmailAuthenticationSubject",
        "EmailConfiguration",
        "EmailVerificationMessage",
        "EmailVerificationSubject",
        "EnabledMfas",
        "IssuerConfiguration",
        "KeyConfiguration",
        "LambdaConfig",
        "MfaConfiguration",
        "Policies",
        "ProviderName",
        "ProviderURL",
        "Schema",
        "SmsAuthenticationMessage",
        "SmsConfiguration",
        "SmsVerificationMessage",
        "UserAttributeUpdateSettings",
        "UserPoolAddOns",
        "UserPoolId",
        "UserPoolName",
        "UserPoolTags",
        "UserPoolTier",
        "UsernameAttributes",
        "UsernameConfiguration",
        "VerificationMessageTemplate",
        "WebAuthnFactorConfiguration",
        "WebAuthnRelyingPartyID",
        "WebAuthnUserVerification",
    },
    "AWS::Cognito::UserPoolClient": {
        "AccessTokenValidity",
        "AllowedOAuthFlows",
        "AllowedOAuthFlowsUserPoolClient",
        "AllowedOAuthScopes",
        "AnalyticsConfiguration",
        "AuthSessionValidity",
        "CallbackURLs",
        "ClientId",
        "ClientName",
        "ClientSecret",
        "DefaultRedirectURI",
        "EnablePropagateAdditionalUserContextData",
        "EnableTokenRevocation",
        "ExplicitAuthFlows",
        "GenerateSecret",
        "IdTokenValidity",
        "LogoutURLs",
        "Name",
        "PreventUserExistenceErrors",
        "ReadAttributes",
        "RefreshTokenRotation",
        "RefreshTokenValidity",
        "SupportedIdentityProviders",
        "TokenValidityUnits",
        "UserPoolId",
        "WriteAttributes",
    },
    "AWS::Cognito::UserPoolDomain": {
        "CloudFrontDistribution",
        "CustomDomainConfig",
        "Domain",
        "ManagedLoginVersion",
        "Routing",
        "UserPoolId",
    },
}

CONTRACTS = {
    "AWS::Cognito::UserPool": (
        aws_cognito_userpool.CognitoUserPoolProvider,
        aws_cognito_userpool._PROPERTIES,
    ),
    "AWS::Cognito::UserPoolClient": (
        aws_cognito_userpoolclient.CognitoUserPoolClientProvider,
        aws_cognito_userpoolclient._PROPERTIES,
    ),
    "AWS::Cognito::UserPoolDomain": (
        aws_cognito_userpooldomain.CognitoUserPoolDomainProvider,
        aws_cognito_userpooldomain._PROPERTIES,
    ),
}


def _request(*, client, desired_state, previous_state=None):
    return SimpleNamespace(
        aws_client_factory=SimpleNamespace(cognito_idp=client),
        custom_context={},
        desired_state=desired_state,
        previous_state=previous_state,
        logical_resource_id="AuthResource",
        stack_name="enterprise",
    )


@pytest.mark.parametrize("type_name", sorted(CONTRACTS))
def test_schema_and_resource_provider_cover_current_official_properties(type_name):
    provider, provider_properties = CONTRACTS[type_name]
    expected = OFFICIAL_PROPERTIES[type_name]
    schema_properties = set(provider.SCHEMA["properties"])

    assert {
        "resource_provider_missing": sorted(expected - provider_properties),
        "schema_missing": sorted(expected - schema_properties),
    } == {"resource_provider_missing": [], "schema_missing": []}


def test_current_official_identifier_write_only_and_tagging_metadata():
    pool = aws_cognito_userpool.CognitoUserPoolProvider.SCHEMA
    client = aws_cognito_userpoolclient.CognitoUserPoolClientProvider.SCHEMA
    domain = aws_cognito_userpooldomain.CognitoUserPoolDomainProvider.SCHEMA

    assert {
        "client_primary": client["primaryIdentifier"],
        "domain_primary": domain["primaryIdentifier"],
        "domain_write_only": domain.get("writeOnlyProperties", []),
        "pool_primary": pool["primaryIdentifier"],
        "pool_system_tags": pool["tagging"]["cloudFormationSystemTags"],
        "pool_write_only": pool.get("writeOnlyProperties", []),
    } == {
        "client_primary": ["/properties/UserPoolId", "/properties/ClientId"],
        "domain_primary": ["/properties/UserPoolId", "/properties/Domain"],
        "domain_write_only": ["/properties/ManagedLoginVersion"],
        "pool_primary": ["/properties/UserPoolId"],
        "pool_system_tags": True,
        "pool_write_only": ["/properties/EnabledMfas"],
    }


def test_user_pool_domain_ref_uses_domain_despite_composite_registry_identifier():
    assert PHYSICAL_RESOURCE_ID_SPECIAL_CASES["AWS::Cognito::UserPoolDomain"] == (
        "/properties/Domain"
    )


@pytest.mark.parametrize(
    "property_name,value",
    [
        ("AliasAttributes", ["email"]),
        (
            "DeviceConfiguration",
            {
                "ChallengeRequiredOnNewDevice": True,
                "DeviceOnlyRememberedOnUserPrompt": False,
            },
        ),
        ("EmailConfiguration", {"EmailSendingAccount": "COGNITO_DEFAULT"}),
        ("SmsConfiguration", {"SnsCallerArn": "<role-arn>"}),
        ("UsernameConfiguration", {"CaseSensitive": False}),
    ],
)
def test_user_pool_cfn_exposes_properties_already_accepted_by_native_provider(
    property_name, region_name, value
):
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    if property_name == "SmsConfiguration":
        value = {
            "SnsCallerArn": f"arn:aws:iam::{account_id}:role/sms",
        }
    pool_id = f"{region_name}_pool"
    client = MagicMock()
    client.create_user_pool.return_value = {
        "UserPool": {
            "Arn": f"arn:aws:cognito-idp:{region_name}:{account_id}:userpool/{pool_id}",
            "Id": pool_id,
            "Name": "enterprise",
            property_name: value,
        }
    }

    result = aws_cognito_userpool.CognitoUserPoolProvider().create(
        _request(
            client=client,
            desired_state={"UserPoolName": "enterprise", property_name: value},
        )
    )

    assert result.status == OperationStatus.SUCCESS
    client.create_user_pool.assert_called_once_with(PoolName="enterprise", **{property_name: value})


def test_domain_create_compensates_when_post_create_describe_fails(region_name):
    client = MagicMock()
    primary = RuntimeError("DescribeUserPoolDomain response lost")
    client.describe_user_pool_domain.side_effect = primary
    desired = {
        "Domain": "enterprise",
        "ManagedLoginVersion": 2,
        "UserPoolId": f"{region_name}_pool",
    }

    with pytest.raises(RuntimeError, match="response lost") as raised:
        aws_cognito_userpooldomain.CognitoUserPoolDomainProvider().create(
            _request(client=client, desired_state=desired)
        )

    assert raised.value is primary
    client.delete_user_pool_domain.assert_called_once_with(
        Domain="enterprise", UserPoolId=f"{region_name}_pool"
    )
