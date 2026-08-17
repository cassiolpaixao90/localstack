import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp.models import cognito_idp_stores, resolve_domain_location
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.tokens import decode_jwt_segment


@pytest.fixture
def context():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    yield context
    with cognito_idp_stores.lock:
        region_bundle = cognito_idp_stores.get(context.account_id)
        if region_bundle is not None:
            for store in region_bundle.values():
                for pool_id in list(store.user_pools):
                    if store.POOL_LOCATIONS.get(pool_id) == (
                        context.account_id,
                        store._region_name,
                    ):
                        store.POOL_LOCATIONS.pop(pool_id, None)
                for domain in list(store.user_pool_domains.values()):
                    if store.DOMAIN_LOCATIONS.get(domain.local_hostname) == (
                        context.account_id,
                        store._region_name,
                    ):
                        store.DOMAIN_LOCATIONS.pop(domain.local_hostname, None)
            cognito_idp_stores.pop(context.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def _pool(provider, context):
    return provider.create_user_pool(context, {"PoolName": "oauth-users"})["UserPool"]


def _oauth_client_request(pool_id):
    return {
        "AllowedOAuthFlows": ["code"],
        "AllowedOAuthFlowsUserPoolClient": True,
        "AllowedOAuthScopes": [
            "openid",
            "email",
            "profile",
            "aws.cognito.signin.user.admin",
        ],
        "CallbackURLs": [
            "https://app.example.test/callback",
            "http://localhost:3000/callback",
            "myapp://callback",
        ],
        "ClientName": "amplify-public-client",
        "DefaultRedirectURI": "https://app.example.test/callback",
        "EnableTokenRevocation": True,
        "LogoutURLs": ["https://app.example.test/logout", "myapp://signout"],
        "ReadAttributes": ["email", "custom:secret"],
        "SupportedIdentityProviders": ["COGNITO"],
        "UserPoolId": pool_id,
    }


def test_oauth_client_create_describe_and_update_round_trip(provider, context):
    pool = _pool(provider, context)
    created = provider.create_user_pool_client(context, _oauth_client_request(pool["Id"]))[
        "UserPoolClient"
    ]

    assert created["AllowedOAuthFlows"] == ["code"]
    assert created["AllowedOAuthFlowsUserPoolClient"] is True
    assert created["AllowedOAuthScopes"] == [
        "openid",
        "email",
        "profile",
        "aws.cognito.signin.user.admin",
    ]
    assert created["CallbackURLs"] == [
        "https://app.example.test/callback",
        "http://localhost:3000/callback",
        "myapp://callback",
    ]
    assert created["DefaultRedirectURI"] == "https://app.example.test/callback"
    assert created["EnableTokenRevocation"] is True
    assert created["LogoutURLs"] == [
        "https://app.example.test/logout",
        "myapp://signout",
    ]
    assert created["ReadAttributes"] == ["email", "custom:secret"]
    assert created["SupportedIdentityProviders"] == ["COGNITO"]
    assert "ClientSecret" not in created

    described = provider.describe_user_pool_client(
        context,
        {"ClientId": created["ClientId"], "UserPoolId": pool["Id"]},
    )["UserPoolClient"]
    assert described == created

    updated = provider.update_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "phone"],
            "CallbackURLs": ["myapp://new-callback"],
            "ClientId": created["ClientId"],
            "DefaultRedirectURI": "myapp://new-callback",
            "LogoutURLs": ["myapp://new-signout"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    assert updated["AllowedOAuthFlows"] == ["code"]
    assert updated["AllowedOAuthScopes"] == ["openid", "phone"]
    assert updated["CallbackURLs"] == ["myapp://new-callback"]
    assert updated["DefaultRedirectURI"] == "myapp://new-callback"
    assert updated["LogoutURLs"] == ["myapp://new-signout"]
    assert "ReadAttributes" not in updated


@pytest.mark.parametrize(
    "changes",
    [
        {"AllowedOAuthFlowsUserPoolClient": "true"},
        {"AllowedOAuthFlows": ["client_credentials"]},
        {"AllowedOAuthFlows": ["code", "code"]},
        {"AllowedOAuthScopes": ["resource.example/read"]},
        {"AllowedOAuthScopes": ["email"]},
        {"CallbackURLs": ["http://app.example.test/callback"]},
        {"CallbackURLs": ["https://app.example.test/callback#fragment"]},
        {"CallbackURLs": ["https://user@app.example.test/callback"]},
        {"CallbackURLs": ["https://:443/callback"]},
        {"CallbackURLs": ["https://app.example.test/callback%0aLocation:evil"]},
        {"CallbackURLs": ["relative/callback"]},
        {"DefaultRedirectURI": "https://other.example.test/callback"},
        {"EnableTokenRevocation": "true"},
        {"ReadAttributes": ["email", "email"]},
        {"SupportedIdentityProviders": ["Google"]},
    ],
)
def test_oauth_client_configuration_fails_closed(provider, context, changes):
    pool = _pool(provider, context)
    request = _oauth_client_request(pool["Id"])
    request.update(changes)

    with pytest.raises(CommonServiceException) as invalid:
        provider.create_user_pool_client(context, request)

    assert invalid.value.code == "InvalidParameterException"


def test_oauth_fields_require_authorization_server_activation(provider, context):
    pool = _pool(provider, context)
    request = _oauth_client_request(pool["Id"])
    request["AllowedOAuthFlowsUserPoolClient"] = False

    with pytest.raises(CommonServiceException) as inactive:
        provider.create_user_pool_client(context, request)

    assert inactive.value.code == "InvalidParameterException"


def test_oauth_client_models_code_and_implicit_for_cdk_parity(provider, context):
    pool = _pool(provider, context)
    request = _oauth_client_request(pool["Id"])
    request["AllowedOAuthFlows"] = ["implicit", "code"]

    client = provider.create_user_pool_client(context, request)["UserPoolClient"]

    assert client["AllowedOAuthFlows"] == ["implicit", "code"]


def test_invalid_oauth_update_is_atomic(provider, context):
    pool = _pool(provider, context)
    client = provider.create_user_pool_client(context, _oauth_client_request(pool["Id"]))[
        "UserPoolClient"
    ]

    with pytest.raises(CommonServiceException) as invalid:
        provider.update_user_pool_client(
            context,
            {
                "AllowedOAuthScopes": ["resource.example/read"],
                "ClientId": client["ClientId"],
                "ClientName": "must-not-stick",
                "UserPoolId": pool["Id"],
            },
        )

    assert invalid.value.code == "InvalidParameterException"
    described = provider.describe_user_pool_client(
        context,
        {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]},
    )["UserPoolClient"]
    assert described["ClientName"] == "amplify-public-client"
    assert described["AllowedOAuthScopes"] == client["AllowedOAuthScopes"]


def test_revoke_token_requires_client_feature(provider, context):
    pool = _pool(provider, context)
    request = _oauth_client_request(pool["Id"])
    request["EnableTokenRevocation"] = False
    client = provider.create_user_pool_client(context, request)["UserPoolClient"]

    with pytest.raises(CommonServiceException) as disabled:
        provider.revoke_token(
            context,
            {"ClientId": client["ClientId"], "Token": "not-a-token"},
        )

    assert disabled.value.code == "UnsupportedOperationException"


def test_prefix_domain_crud_and_local_hostname_index(provider, context):
    pool = _pool(provider, context)

    created = provider.create_user_pool_domain(
        context,
        {"Domain": "amplify-login", "ManagedLoginVersion": 2, "UserPoolId": pool["Id"]},
    )
    assert created == {"ManagedLoginVersion": 2}
    assert resolve_domain_location("amplify-login.localhost.localstack.cloud") == (
        context.account_id,
        context.region,
    )

    description = provider.describe_user_pool_domain(context, {"Domain": "amplify-login"})[
        "DomainDescription"
    ]
    assert description == {
        "AWSAccountId": context.account_id,
        "CloudFrontDistribution": "amplify-login.localhost.localstack.cloud",
        "Domain": "amplify-login",
        "ManagedLoginVersion": 2,
        "Status": "ACTIVE",
        "UserPoolId": pool["Id"],
    }

    assert provider.update_user_pool_domain(
        context,
        {"Domain": "amplify-login", "ManagedLoginVersion": 1, "UserPoolId": pool["Id"]},
    ) == {"ManagedLoginVersion": 1}
    assert (
        provider.describe_user_pool_domain(context, {"Domain": "amplify-login"})[
            "DomainDescription"
        ]["ManagedLoginVersion"]
        == 1
    )

    assert (
        provider.delete_user_pool_domain(
            context, {"Domain": "amplify-login", "UserPoolId": pool["Id"]}
        )
        == {}
    )
    assert resolve_domain_location("amplify-login.localhost.localstack.cloud") is None
    with pytest.raises(CommonServiceException) as deleted:
        provider.describe_user_pool_domain(context, {"Domain": "amplify-login"})
    assert deleted.value.code == "ResourceNotFoundException"


def test_domain_index_is_account_region_isolated_and_pool_delete_cleans_it(provider, context):
    other_context = RequestContext(None)
    other_context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    other_context.region = "eu-west-1"
    first = _pool(provider, context)
    second = _pool(provider, other_context)
    provider.create_user_pool_domain(context, {"Domain": "shared-login", "UserPoolId": first["Id"]})

    with pytest.raises(CommonServiceException) as duplicate:
        provider.create_user_pool_domain(
            other_context, {"Domain": "shared-login", "UserPoolId": second["Id"]}
        )
    assert duplicate.value.code == "InvalidParameterException"

    with pytest.raises(CommonServiceException) as hidden:
        provider.describe_user_pool_domain(other_context, {"Domain": "shared-login"})
    assert hidden.value.code == "ResourceNotFoundException"

    provider.delete_user_pool(context, {"UserPoolId": first["Id"]})
    assert resolve_domain_location("shared-login.localhost.localstack.cloud") is None

    provider.delete_user_pool(other_context, {"UserPoolId": second["Id"]})
    with cognito_idp_stores.lock:
        cognito_idp_stores.pop(other_context.account_id, None)


@pytest.mark.parametrize(
    "request_update",
    [
        {"Domain": "UpperCase"},
        {"Domain": "-leading"},
        {"Domain": "trailing-"},
        {"Domain": "contains-aws-name"},
        {"Domain": "x" * 64},
        {"ManagedLoginVersion": 3},
        {"CustomDomainConfig": {"CertificateArn": "arn:aws:acm:us-east-1:1:certificate/x"}},
        {"Routing": {}},
    ],
)
def test_prefix_domain_configuration_fails_closed(provider, context, request_update):
    pool = _pool(provider, context)
    request = {"Domain": "valid-login", "UserPoolId": pool["Id"]}
    request.update(request_update)

    with pytest.raises(CommonServiceException) as invalid:
        provider.create_user_pool_domain(context, request)

    assert invalid.value.code == "InvalidParameterException"


def test_native_token_issuer_uses_partition_dns_suffix(provider):
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.partition = "aws-cn"
    context.region = "cn-north-1"
    try:
        pool = _pool(provider, context)
        client = provider.create_user_pool_client(
            context,
            {
                "ClientName": "china-client",
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
                "UserPoolId": pool["Id"],
            },
        )["UserPoolClient"]
        provider.admin_create_user(
            context,
            {
                "TemporaryPassword": "TempPass9!",
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

        token = provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": "alice"},
                "ClientId": client["ClientId"],
            },
        )["AuthenticationResult"]["IdToken"]
        claims = decode_jwt_segment(token.split(".")[1])

        assert claims["iss"] == (f"https://cognito-idp.cn-north-1.amazonaws.com.cn/{pool['Id']}")
    finally:
        with cognito_idp_stores.lock:
            region_bundle = cognito_idp_stores.get(context.account_id)
            if region_bundle is not None:
                for store in region_bundle.values():
                    for pool_id in list(store.user_pools):
                        store.POOL_LOCATIONS.pop(pool_id, None)
                cognito_idp_stores.pop(context.account_id, None)
