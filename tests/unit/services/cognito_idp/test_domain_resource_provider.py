import copy
from types import SimpleNamespace
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from localstack.services.cloudformation.resource_provider import OperationStatus
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpooldomain import (
    CognitoUserPoolDomainProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpooldomain_plugin import (
    CognitoUserPoolDomainProviderPlugin,
)

DOMAIN_DESCRIPTION = {
    "CloudFrontDistribution": "enterprise.localhost.localstack.cloud",
    "Domain": "enterprise",
    "ManagedLoginVersion": 2,
    "Status": "ACTIVE",
    "UserPoolId": "us-east-1_pool",
}


def _request(*, client, desired_state, previous_state=None):
    return SimpleNamespace(
        aws_client_factory=SimpleNamespace(cognito_idp=client),
        custom_context={},
        desired_state=desired_state,
        previous_state=previous_state,
        logical_resource_id="Domain",
        stack_name="enterprise",
        region_name="us-east-1",
    )


def _not_found(operation: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}}, operation
    )


def test_domain_schema_and_plugin_expose_the_closed_cloudformation_contract():
    schema = CognitoUserPoolDomainProvider.SCHEMA
    plugin = CognitoUserPoolDomainProviderPlugin()

    plugin.load()

    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {
        "CloudFrontDistribution",
        "CustomDomainConfig",
        "Domain",
        "ManagedLoginVersion",
        "Routing",
        "UserPoolId",
    }
    assert schema["primaryIdentifier"] == [
        "/properties/UserPoolId",
        "/properties/Domain",
    ]
    assert set(schema["required"]) == {"Domain", "UserPoolId"}
    assert set(schema["createOnlyProperties"]) == {
        "/properties/Domain",
        "/properties/UserPoolId",
    }
    assert plugin.factory is CognitoUserPoolDomainProvider


def test_create_describes_the_domain_and_preserves_the_desired_model():
    client = MagicMock()
    client.describe_user_pool_domain.return_value = {"DomainDescription": DOMAIN_DESCRIPTION}
    desired = {
        "Domain": "enterprise",
        "ManagedLoginVersion": 2,
        "UserPoolId": "us-east-1_pool",
    }
    original = copy.deepcopy(desired)

    result = CognitoUserPoolDomainProvider().create(_request(client=client, desired_state=desired))

    assert result.status == OperationStatus.SUCCESS
    assert desired == original
    assert result.resource_model == {
        "CloudFrontDistribution": "enterprise.localhost.localstack.cloud",
        "Domain": "enterprise",
        "ManagedLoginVersion": 2,
        "UserPoolId": "us-east-1_pool",
    }
    client.create_user_pool_domain.assert_called_once_with(
        Domain="enterprise", ManagedLoginVersion=2, UserPoolId="us-east-1_pool"
    )
    client.describe_user_pool_domain.assert_called_once_with(Domain="enterprise")


def test_read_maps_state_and_reports_not_found():
    client = MagicMock()
    client.describe_user_pool_domain.return_value = {"DomainDescription": DOMAIN_DESCRIPTION}
    provider = CognitoUserPoolDomainProvider()

    result = provider.read(_request(client=client, desired_state={"Domain": "enterprise"}))

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model["UserPoolId"] == "us-east-1_pool"

    client.describe_user_pool_domain.side_effect = _not_found("DescribeUserPoolDomain")
    missing = provider.read(_request(client=client, desired_state={"Domain": "missing"}))

    assert missing.status == OperationStatus.FAILED
    assert missing.error_code == "NotFound"


def test_update_changes_only_the_managed_login_version_and_reloads_state():
    client = MagicMock()
    before = {**DOMAIN_DESCRIPTION, "ManagedLoginVersion": 1}
    client.describe_user_pool_domain.side_effect = [
        {"DomainDescription": before},
        {"DomainDescription": DOMAIN_DESCRIPTION},
    ]
    desired = {"Domain": "enterprise", "ManagedLoginVersion": 2}
    previous = {
        "Domain": "enterprise",
        "ManagedLoginVersion": 1,
        "UserPoolId": "us-east-1_pool",
    }

    result = CognitoUserPoolDomainProvider().update(
        _request(client=client, desired_state=desired, previous_state=previous)
    )

    assert result.status == OperationStatus.SUCCESS
    assert result.resource_model["ManagedLoginVersion"] == 2
    client.update_user_pool_domain.assert_called_once_with(
        Domain="enterprise", ManagedLoginVersion=2, UserPoolId="us-east-1_pool"
    )


def test_delete_can_rehydrate_user_pool_id_and_is_idempotent():
    client = MagicMock()
    client.describe_user_pool_domain.return_value = {"DomainDescription": DOMAIN_DESCRIPTION}
    provider = CognitoUserPoolDomainProvider()

    result = provider.delete(_request(client=client, desired_state={"Domain": "enterprise"}))

    assert result.status == OperationStatus.SUCCESS
    client.delete_user_pool_domain.assert_called_once_with(
        Domain="enterprise", UserPoolId="us-east-1_pool"
    )

    client.reset_mock()
    client.describe_user_pool_domain.side_effect = _not_found("DescribeUserPoolDomain")
    repeated = provider.delete(_request(client=client, desired_state={"Domain": "enterprise"}))

    assert repeated.status == OperationStatus.SUCCESS
    client.delete_user_pool_domain.assert_not_called()


def test_domain_rejects_read_only_unsupported_and_invalid_version_before_io():
    client = MagicMock()
    provider = CognitoUserPoolDomainProvider()

    cases = [
        {
            "CloudFrontDistribution": "injected.example",
            "Domain": "enterprise",
            "UserPoolId": "us-east-1_pool",
        },
        {"Domain": "enterprise", "Unsupported": True, "UserPoolId": "us-east-1_pool"},
        {
            "Domain": "enterprise",
            "ManagedLoginVersion": 3,
            "UserPoolId": "us-east-1_pool",
        },
    ]

    for desired in cases:
        result = provider.create(_request(client=client, desired_state=desired))
        assert result.status == OperationStatus.FAILED

    client.create_user_pool_domain.assert_not_called()
