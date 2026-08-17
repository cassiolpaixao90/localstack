import copy
import uuid
from unittest.mock import MagicMock

from localstack.aws.api import RequestContext
from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
)
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolidentityprovider import (
    CognitoUserPoolIdentityProviderProvider,
)
from tests.unit.services.cognito_idp.test_resource_providers import _NativeCognitoClient, _request


def _desired(pool_id="us-east-1_pool"):
    return {
        "AttributeMapping": {"email": "email"},
        "IdpIdentifiers": ["corp"],
        "ProviderDetails": {
            "attributes_request_method": "GET",
            "attributes_url": "https://idp.example.test/userinfo",
            "authorize_scopes": "openid email",
            "authorize_url": "https://idp.example.test/authorize",
            "client_id": "corp-client",
            "client_secret": "corp-secret-value",
            "jwks_uri": "https://idp.example.test/jwks",
            "oidc_issuer": "https://idp.example.test",
            "token_url": "https://idp.example.test/token",
        },
        "ProviderName": "CorporateOIDC",
        "ProviderType": "OIDC",
        "UserPoolId": pool_id,
    }


def test_identity_provider_resource_maps_crud_without_mutating_desired():
    client = MagicMock()
    desired = _desired()
    original = copy.deepcopy(desired)
    service_model = {**desired, "CreationDate": 1, "LastModifiedDate": 1}
    client.create_identity_provider.return_value = {"IdentityProvider": service_model}
    client.describe_identity_provider.return_value = {"IdentityProvider": service_model}
    client.update_identity_provider.return_value = {"IdentityProvider": service_model}
    provider = CognitoUserPoolIdentityProviderProvider()

    created = provider.create(_request(client=client, desired_state=desired))
    read = provider.read(_request(client=client, desired_state=desired))
    updated = provider.update(
        _request(client=client, desired_state=desired, previous_state=desired)
    )
    deleted = provider.delete(
        _request(client=client, desired_state=desired, previous_state=desired)
    )

    assert (
        created.status == read.status == updated.status == deleted.status == OperationStatus.SUCCESS
    )
    assert created.resource_model == desired == original
    client.delete_identity_provider.assert_called_once_with(
        ProviderName="CorporateOIDC", UserPoolId="us-east-1_pool"
    )
    schema = provider.SCHEMA
    assert schema["properties"]["ProviderType"]["enum"] == [
        "OIDC",
        "SAML",
        "Google",
        "Facebook",
        "LoginWithAmazon",
        "SignInWithApple",
    ]
    assert PHYSICAL_RESOURCE_ID_SPECIAL_CASES[provider.TYPE] == "/properties/ProviderName"
    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")
    assert (
        executor.extract_physical_resource_id_from_model_with_schema(desired, provider.TYPE, schema)
        == "CorporateOIDC"
    )


def test_identity_provider_resource_round_trips_against_native_provider():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    native = CognitoIdpProvider()
    client = _NativeCognitoClient(native, context)
    pool = native.create_user_pool(context, {"PoolName": "idp-cfn"})["UserPool"]
    desired = _desired(pool["Id"])
    provider = CognitoUserPoolIdentityProviderProvider()
    try:
        created = provider.create(_request(client=client, desired_state=desired))
        read = provider.read(_request(client=client, desired_state=created.resource_model))
        deleted = provider.delete(
            _request(
                client=client,
                desired_state=read.resource_model,
                previous_state=read.resource_model,
            )
        )

        assert created.status == read.status == deleted.status == OperationStatus.SUCCESS
        assert read.resource_model["ProviderName"] == "CorporateOIDC"
        assert read.resource_model["ProviderDetails"]["client_secret"] == "corp-secret-value"
    finally:
        try:
            native.delete_user_pool(context, {"UserPoolId": pool["Id"]})
        finally:
            with cognito_idp_stores.lock:
                cognito_idp_stores.pop(context.account_id, None)
