import base64
import json
import socket
import time
import uuid

import pytest

from localstack.aws.api import RequestContext
from localstack.services.apigatewayv2.jwt_authorizer import (
    HttpApiJwtAuthorizerConfiguration,
    HttpApiJwtConfigurationError,
    HttpApiJwtUnauthorized,
    authorize_native_cognito_jwt,
)
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.tokens import sign_jwt


@pytest.fixture
def aws_context():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    context.partition = "aws"
    yield context
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(context.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(context.account_id, None)


@pytest.fixture
def native_tokens(aws_context):
    provider = CognitoIdpProvider()
    pool = provider.create_user_pool(aws_context, {"PoolName": "http-api-users"})["UserPool"]
    client = provider.create_user_pool_client(
        aws_context,
        {
            "UserPoolId": pool["Id"],
            "ClientName": "http-api-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        aws_context,
        {
            "UserPoolId": pool["Id"],
            "Username": "http-api@example.test",
            "TemporaryPassword": "Temporary9!",
        },
    )
    provider.admin_set_user_password(
        aws_context,
        {
            "UserPoolId": pool["Id"],
            "Username": "http-api@example.test",
            "Password": "Permanent9!",
            "Permanent": True,
        },
    )
    provider.create_group(
        aws_context,
        {"UserPoolId": pool["Id"], "GroupName": "operators"},
    )
    provider.admin_add_user_to_group(
        aws_context,
        {
            "UserPoolId": pool["Id"],
            "Username": "http-api@example.test",
            "GroupName": "operators",
        },
    )
    authentication = provider.initiate_auth(
        aws_context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {
                "USERNAME": "http-api@example.test",
                "PASSWORD": "Permanent9!",
            },
        },
    )["AuthenticationResult"]
    issuer = f"https://cognito-idp.{aws_context.region}.amazonaws.com/{pool['Id']}"
    configuration = HttpApiJwtAuthorizerConfiguration(
        identity_source=("$request.header.Authorization",),
        issuer=issuer,
        audience=(client["ClientId"],),
    )
    return pool, client, authentication, configuration


def _authorize(context, configuration, token, *, scopes=()):
    return authorize_native_cognito_jwt(
        authorization_headers=(f"Bearer {token}",),
        configuration=configuration,
        authorization_scopes=scopes,
        api_account_id=context.account_id,
        api_region=context.region,
    )


def _claims(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def _resign(context, pool_id, token, *, access=False, now=None, remove=(), **updates):
    claims = _claims(token)
    for key in remove:
        claims.pop(key, None)
    claims.update(updates)
    with cognito_idp_stores.lock:
        pool = cognito_idp_stores[context.account_id][context.region].user_pools[pool_id]
        private_key = (
            pool.access_signing_private_key_pem if access else pool.id_signing_private_key_pem
        )
        key_id = pool.access_signing_key_id if access else pool.id_signing_key_id
    return sign_jwt(private_key, key_id, claims, now=claims["iat"] if now is None else now)


def _replace_header(token, **updates):
    encoded_header, payload, signature = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(encoded_header + "=" * (-len(encoded_header) % 4)))
    header.update(updates)
    replacement = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=")
    return f"{replacement.decode()}.{payload}.{signature}"


def _replace_unsigned_claims(token, **updates):
    header, encoded_claims, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(encoded_claims + "=" * (-len(encoded_claims) % 4)))
    claims.update(updates)
    replacement = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=")
    return f"{header}.{replacement.decode()}.{signature}"


def test_id_token_authorizes_and_preserves_groups_as_claim_context(aws_context, native_tokens):
    _, _, authentication, configuration = native_tokens

    result = _authorize(aws_context, configuration, authentication["IdToken"])

    assert result.claims["token_use"] == "id"
    assert result.claims["cognito:groups"] == ["operators"]
    assert result.scopes == ()


def test_access_token_requires_any_route_scope_and_groups_do_not_grant_access(
    aws_context, native_tokens
):
    pool, _, authentication, configuration = native_tokens

    result = _authorize(
        aws_context,
        configuration,
        authentication["AccessToken"],
        scopes=("api/read", "aws.cognito.signin.user.admin"),
    )
    assert result.scopes == ("aws.cognito.signin.user.admin",)

    group_only = _resign(
        aws_context,
        pool["Id"],
        authentication["AccessToken"],
        access=True,
        scope="unrelated",
        **{"cognito:groups": ["api/read"]},
    )
    with pytest.raises(HttpApiJwtUnauthorized):
        _authorize(aws_context, configuration, group_only, scopes=("api/read",))


def test_scope_or_scp_claim_is_supported_but_must_be_well_formed(aws_context, native_tokens):
    pool, _, authentication, configuration = native_tokens
    scp_token = _resign(
        aws_context,
        pool["Id"],
        authentication["AccessToken"],
        access=True,
        remove=("scope",),
        scp=["documents/read", "profile"],
    )

    result = _authorize(
        aws_context,
        configuration,
        scp_token,
        scopes=("documents/write", "documents/read"),
    )
    assert result.scopes == ("documents/read", "profile")

    malformed = _resign(
        aws_context,
        pool["Id"],
        authentication["AccessToken"],
        access=True,
        remove=("scope",),
        scp=["documents/read", "documents/read"],
    )
    with pytest.raises(HttpApiJwtUnauthorized):
        _authorize(aws_context, configuration, malformed, scopes=("documents/read",))


def test_aud_takes_precedence_over_client_id_and_must_match_configured_audience(
    aws_context, native_tokens
):
    pool, client, authentication, configuration = native_tokens
    wrong_audience = _resign(
        aws_context,
        pool["Id"],
        authentication["AccessToken"],
        access=True,
        aud="different-client",
        client_id=client["ClientId"],
    )
    with pytest.raises(HttpApiJwtUnauthorized):
        _authorize(aws_context, configuration, wrong_audience)

    multiple_audiences = _resign(
        aws_context,
        pool["Id"],
        authentication["IdToken"],
        aud=["different-client", client["ClientId"]],
    )
    assert _authorize(aws_context, configuration, multiple_audiences).claims["token_use"] == "id"


@pytest.mark.parametrize(
    "value",
    [
        "{token}",
        "bearer {token}",
        "BEARER {token}",
        "Bearer  {token}",
        "Bearer\t{token}",
        " Bearer {token}",
        "Bearer {token} ",
        "Bearer {token} extra",
        "",
    ],
)
def test_authorization_header_requires_one_exact_bearer_value(aws_context, native_tokens, value):
    _, _, authentication, configuration = native_tokens
    header = value.format(token=authentication["IdToken"])

    with pytest.raises(HttpApiJwtUnauthorized):
        authorize_native_cognito_jwt(
            authorization_headers=(header,),
            configuration=configuration,
            authorization_scopes=(),
            api_account_id=aws_context.account_id,
            api_region=aws_context.region,
        )

    with pytest.raises(HttpApiJwtUnauthorized):
        authorize_native_cognito_jwt(
            authorization_headers=(
                f"Bearer {authentication['IdToken']}",
                f"Bearer {authentication['IdToken']}",
            ),
            configuration=configuration,
            authorization_scopes=(),
            api_account_id=aws_context.account_id,
            api_region=aws_context.region,
        )


def test_signature_algorithm_key_and_time_claims_are_fail_closed(aws_context, native_tokens):
    pool, _, authentication, configuration = native_tokens
    now = int(time.time())
    invalid = (
        _replace_header(authentication["IdToken"], alg="HS256"),
        _replace_header(authentication["IdToken"], kid="unknown"),
        _replace_unsigned_claims(authentication["IdToken"], email="tampered@example.test"),
        _resign(
            aws_context,
            pool["Id"],
            authentication["IdToken"],
            nbf=now + 60,
        ),
        _resign(
            aws_context,
            pool["Id"],
            authentication["IdToken"],
            exp=now - 1,
        ),
        _resign(
            aws_context,
            pool["Id"],
            authentication["IdToken"],
            now=now + 60,
        ),
    )
    for token in invalid:
        with pytest.raises(HttpApiJwtUnauthorized):
            _authorize(aws_context, configuration, token)


def test_malformed_group_claim_is_rejected_instead_of_becoming_authority(
    aws_context, native_tokens
):
    pool, _, authentication, configuration = native_tokens
    malformed = _resign(
        aws_context,
        pool["Id"],
        authentication["IdToken"],
        **{"cognito:groups": "operators"},
    )

    with pytest.raises(HttpApiJwtUnauthorized):
        _authorize(aws_context, configuration, malformed)


def test_native_jwks_verification_has_no_network_path(aws_context, native_tokens, monkeypatch):
    _, _, authentication, configuration = native_tokens

    def reject_network(*_args, **_kwargs):
        pytest.fail("native Cognito JWT verification attempted network egress")

    monkeypatch.setattr(socket.socket, "connect", reject_network)

    result = _authorize(aws_context, configuration, authentication["IdToken"])
    assert result.claims["iss"] == configuration.issuer


def test_native_pool_must_match_api_account_region_partition_and_exact_issuer(
    aws_context, native_tokens
):
    _, _, authentication, configuration = native_tokens

    for account_id, region, issuer in (
        ("999999999999", aws_context.region, configuration.issuer),
        (aws_context.account_id, "us-west-2", configuration.issuer),
        (
            aws_context.account_id,
            aws_context.region,
            configuration.issuer.replace("amazonaws.com", "amazonaws.com.cn"),
        ),
    ):
        modified = HttpApiJwtAuthorizerConfiguration(
            identity_source=configuration.identity_source,
            issuer=issuer,
            audience=configuration.audience,
        )
        with pytest.raises(HttpApiJwtUnauthorized):
            authorize_native_cognito_jwt(
                authorization_headers=(f"Bearer {authentication['IdToken']}",),
                configuration=modified,
                authorization_scopes=(),
                api_account_id=account_id,
                api_region=region,
            )

    with pytest.raises(HttpApiJwtConfigurationError):
        HttpApiJwtAuthorizerConfiguration(
            identity_source=configuration.identity_source,
            issuer=f"{configuration.issuer}/",
            audience=configuration.audience,
        )


@pytest.mark.parametrize(
    ("identity_source", "issuer", "audience", "scopes"),
    [
        ((), "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool", ("client",), ()),
        (
            ("$request.querystring.access_token",),
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            ("client",),
            (),
        ),
        (
            ("$request.header.Authorization",),
            "http://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            ("client",),
            (),
        ),
        (
            ("$request.header.Authorization",),
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            (),
            (),
        ),
        (
            ("$request.header.Authorization",),
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            ("client", "client"),
            (),
        ),
        (
            ("$request.header.Authorization",),
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            ("client",),
            ("scope", "scope"),
        ),
    ],
)
def test_authorizer_configuration_and_route_scopes_are_validated(
    aws_context, native_tokens, identity_source, issuer, audience, scopes
):
    _, _, authentication, _ = native_tokens
    with pytest.raises(HttpApiJwtConfigurationError):
        configuration = HttpApiJwtAuthorizerConfiguration(
            identity_source=identity_source,
            issuer=issuer,
            audience=audience,
        )
        authorize_native_cognito_jwt(
            authorization_headers=(f"Bearer {authentication['IdToken']}",),
            configuration=configuration,
            authorization_scopes=scopes,
            api_account_id=aws_context.account_id,
            api_region=aws_context.region,
        )


def test_no_cors_or_method_bypass_exists_when_authorization_is_missing(aws_context, native_tokens):
    _, _, _, configuration = native_tokens

    with pytest.raises(HttpApiJwtUnauthorized):
        authorize_native_cognito_jwt(
            authorization_headers=(),
            configuration=configuration,
            authorization_scopes=(),
            api_account_id=aws_context.account_id,
            api_region=aws_context.region,
        )
