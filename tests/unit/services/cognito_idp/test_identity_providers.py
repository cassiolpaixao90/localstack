import pickle
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.tokens import decode_jwt_segment


@pytest.fixture
def context():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    yield context
    with cognito_idp_stores.lock:
        cognito_idp_stores.pop(context.account_id, None)


@pytest.fixture
def stack(context):
    provider = CognitoIdpProvider()
    pool = provider.create_user_pool(context, {"PoolName": "federation"})["UserPool"]
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "TemporaryPass9!",
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": "PermanentPass9!",
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    return provider, pool


def _oidc_request(pool, name="CorporateOIDC", identifier="corp"):
    return {
        "AttributeMapping": {"email": "email", "preferred_username": "preferred_username"},
        "IdpIdentifiers": [identifier],
        "ProviderDetails": {
            "attributes_request_method": "GET",
            "attributes_url": "https://idp.example.test/userinfo",
            "authorize_scopes": "openid email profile",
            "authorize_url": "https://idp.example.test/authorize",
            "client_id": f"{name}-client",
            "client_secret": f"{name}-secret-value",
            "jwks_uri": "https://idp.example.test/jwks",
            "oidc_issuer": "https://idp.example.test",
            "token_url": "https://idp.example.test/token",
        },
        "ProviderName": name,
        "ProviderType": "OIDC",
        "UserPoolId": pool["Id"],
    }


def test_oidc_identity_provider_crud_pagination_and_encrypted_secret(stack, context):
    provider, pool = stack
    created = provider.create_identity_provider(context, _oidc_request(pool))["IdentityProvider"]
    provider.create_identity_provider(context, _oidc_request(pool, "Partners", "partners"))

    assert created["ProviderType"] == "OIDC"
    assert created["AttributeMapping"]["username"] == "sub"
    assert created["ProviderDetails"]["client_secret"] == "CorporateOIDC-secret-value"
    stored = provider.get_store(context).user_pools[pool["Id"]].identity_providers
    serialized = pickle.dumps(stored)
    assert b"CorporateOIDC-secret-value" not in serialized

    first = provider.list_identity_providers(context, {"MaxResults": 1, "UserPoolId": pool["Id"]})
    assert [item["ProviderName"] for item in first["Providers"]] == ["CorporateOIDC"]
    second = provider.list_identity_providers(
        context,
        {"MaxResults": 1, "NextToken": first["NextToken"], "UserPoolId": pool["Id"]},
    )
    assert [item["ProviderName"] for item in second["Providers"]] == ["Partners"]
    with pytest.raises(CommonServiceException) as tampered:
        provider.list_identity_providers(
            context,
            {
                "MaxResults": 1,
                "NextToken": first["NextToken"] + "x",
                "UserPoolId": pool["Id"],
            },
        )
    assert tampered.value.code == "InvalidParameterException"

    updated = provider.update_identity_provider(
        context,
        {
            "IdpIdentifiers": ["employees"],
            "ProviderName": "CorporateOIDC",
            "UserPoolId": pool["Id"],
        },
    )["IdentityProvider"]
    assert updated["IdpIdentifiers"] == ["employees"]
    assert updated["ProviderDetails"]["client_secret"] == "CorporateOIDC-secret-value"
    by_identifier = provider.get_identity_provider_by_identifier(
        context, {"IdpIdentifier": "employees", "UserPoolId": pool["Id"]}
    )["IdentityProvider"]
    assert by_identifier["ProviderName"] == "CorporateOIDC"

    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "federated-web",
            "SupportedIdentityProviders": ["COGNITO", "CorporateOIDC"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    assert client["SupportedIdentityProviders"] == ["COGNITO", "CorporateOIDC"]

    provider.delete_identity_provider(
        context, {"ProviderName": "CorporateOIDC", "UserPoolId": pool["Id"]}
    )
    with pytest.raises(CommonServiceException) as missing:
        provider.describe_identity_provider(
            context, {"ProviderName": "CorporateOIDC", "UserPoolId": pool["Id"]}
        )
    assert missing.value.code == "ResourceNotFoundException"


def test_identity_provider_validation_is_atomic_and_unsupported_types_fail_closed(stack, context):
    provider, pool = stack
    provider.create_identity_provider(context, _oidc_request(pool))
    before = provider.describe_identity_provider(
        context, {"ProviderName": "CorporateOIDC", "UserPoolId": pool["Id"]}
    )["IdentityProvider"]

    with pytest.raises(CommonServiceException) as duplicate_identifier:
        provider.create_identity_provider(context, _oidc_request(pool, "Other", "corp"))
    assert duplicate_identifier.value.code == "DuplicateProviderException"
    with pytest.raises(CommonServiceException) as unsupported:
        provider.create_identity_provider(
            context,
            {
                "ProviderDetails": {"MetadataURL": "https://idp.example.test/metadata"},
                "ProviderName": "Unsupported",
                "ProviderType": "ADFS",
                "UserPoolId": pool["Id"],
            },
        )
    assert unsupported.value.code == "InvalidParameterException"
    assert (
        provider.describe_identity_provider(
            context, {"ProviderName": "CorporateOIDC", "UserPoolId": pool["Id"]}
        )["IdentityProvider"]
        == before
    )


def test_social_identity_provider_contracts_encrypt_credentials(stack, context):
    provider, pool = stack
    apple_key = (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    requests = {
        "Google": {
            "authorize_scopes": "openid email profile",
            "client_id": "google-client",
            "client_secret": "google-secret",
        },
        "Facebook": {
            "api_version": "v17.0",
            "authorize_scopes": "public_profile,email",
            "client_id": "facebook-client",
            "client_secret": "facebook-secret",
        },
        "LoginWithAmazon": {
            "authorize_scopes": "profile postal_code",
            "client_id": "amazon-client",
            "client_secret": "amazon-secret",
        },
        "SignInWithApple": {
            "authorize_scopes": "name email",
            "client_id": "apple-client",
            "key_id": "APPLEKEY",
            "private_key": apple_key,
            "team_id": "APPLETEAM",
        },
    }
    for provider_type, details in requests.items():
        result = provider.create_identity_provider(
            context,
            {
                "AttributeMapping": {"email": "email"},
                "ProviderDetails": details,
                "ProviderName": provider_type,
                "ProviderType": provider_type,
                "UserPoolId": pool["Id"],
            },
        )["IdentityProvider"]
        assert result["ProviderType"] == provider_type
        if provider_type == "SignInWithApple":
            assert "private_key" not in result["ProviderDetails"]
        else:
            assert result["ProviderDetails"]["client_secret"] == details["client_secret"]

    stored = provider.get_store(context).user_pools[pool["Id"]].identity_providers
    serialized = pickle.dumps(stored)
    for secret in (
        *[value["client_secret"] for value in requests.values() if "client_secret" in value],
        apple_key,
    ):
        assert secret.encode() not in serialized


def test_saml_control_plane_rejects_metadata_without_executable_trust(stack, context):
    provider, pool = stack
    with pytest.raises(CommonServiceException):
        provider.create_identity_provider(
            context,
            {
                "AttributeMapping": {"email": "mail"},
                "ProviderDetails": {
                    "MetadataFile": "<EntityDescriptor/>",
                },
                "ProviderName": "CorporateSAML",
                "ProviderType": "SAML",
                "UserPoolId": pool["Id"],
            },
        )


def test_admin_link_and_disable_provider_identity_are_atomic_and_bounded(stack, context):
    provider, pool = stack
    provider.create_identity_provider(context, _oidc_request(pool))

    def link(value):
        return provider.admin_link_provider_for_user(
            context,
            {
                "DestinationUser": {
                    "ProviderAttributeName": "ignored",
                    "ProviderAttributeValue": "alice",
                    "ProviderName": "Cognito",
                },
                "SourceUser": {
                    "ProviderAttributeName": "preferred_username",
                    "ProviderAttributeValue": value,
                    "ProviderName": "CorporateOIDC",
                },
                "UserPoolId": pool["Id"],
            },
        )

    for index in range(5):
        assert link(f"alice-{index}@example.test") == {}
    assert link("alice-0@example.test") == {}
    with pytest.raises(CommonServiceException) as quota:
        link("alice-5@example.test")
    assert quota.value.code == "LimitExceededException"

    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "password-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    result = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]
    claims = decode_jwt_segment(result["IdToken"].split(".")[1])
    assert len(claims["identities"]) == 5
    assert claims["identities"][0]["providerName"] == "CorporateOIDC"

    assert (
        provider.admin_disable_provider_for_user(
            context,
            {
                "User": {
                    "ProviderAttributeName": "preferred_username",
                    "ProviderAttributeValue": "alice-0@example.test",
                    "ProviderName": "CorporateOIDC",
                },
                "UserPoolId": pool["Id"],
            },
        )
        == {}
    )
    user = provider.get_store(context).user_pools[pool["Id"]].users["alice"]
    assert len(user.federated_identities) == 4
    provider.delete_identity_provider(
        context, {"ProviderName": "CorporateOIDC", "UserPoolId": pool["Id"]}
    )
    assert len(user.federated_identities) == 4
    provider.create_identity_provider(context, _oidc_request(pool))
    provider.admin_disable_provider_for_user(
        context,
        {
            "User": {
                "ProviderAttributeName": "Cognito_Subject",
                "ProviderAttributeValue": "alice",
                "ProviderName": "Cognito",
            },
            "UserPoolId": pool["Id"],
        },
    )
    assert user.enabled is False
