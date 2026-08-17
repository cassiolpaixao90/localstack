import base64
import json
import time
import uuid

import pytest
from werkzeug.datastructures import Headers

from localstack.aws.api import RequestContext
from localstack.aws.api.apigateway import Authorizer, Method, RestApi
from localstack.http import Request, Response
from localstack.services.apigateway.models import MergedRestApi, RestApiDeployment
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import (
    InvocationRequest,
    RestApiInvocationContext,
)
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    AuthorizerConfigurationError,
    UnauthorizedError,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import (
    CognitoUserPoolsAuthorizerHandler,
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
    _remove_account(context.account_id)


def _remove_account(account_id):
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(account_id, None)


def _tokens(context):
    provider = CognitoIdpProvider()
    pool = provider.create_user_pool(context, {"PoolName": "gateway-users"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "UserPoolId": pool["Id"],
            "ClientName": "gateway-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "gateway@example.test",
            "TemporaryPassword": "Temporary9!",
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "gateway@example.test",
            "Password": "Permanent9!",
            "Permanent": True,
        },
    )
    provider.create_group(
        context,
        {"UserPoolId": pool["Id"], "GroupName": "operators"},
    )
    provider.admin_add_user_to_group(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "gateway@example.test",
            "GroupName": "operators",
        },
    )
    authentication = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {
                "USERNAME": "gateway@example.test",
                "PASSWORD": "Permanent9!",
            },
        },
    )["AuthenticationResult"]
    return pool, client, authentication


def _invoke(
    context,
    pool_arn,
    token,
    *,
    scopes=None,
    validation_expression=None,
    authorization_headers=None,
):
    invocation = RestApiInvocationContext(Request())
    rest_api = MergedRestApi(rest_api=RestApi())
    authorizer = Authorizer(
        id="native-cognito",
        name="native-cognito",
        type="COGNITO_USER_POOLS",
        identitySource="method.request.header.Authorization",
        providerARNs=[pool_arn],
    )
    if validation_expression is not None:
        authorizer["identityValidationExpression"] = validation_expression
    rest_api.authorizers = {authorizer["id"]: authorizer}
    invocation.deployment = RestApiDeployment(context.account_id, context.region, rest_api=rest_api)
    invocation.account_id = context.account_id
    invocation.region = context.region
    invocation.resource_method = Method(
        authorizationType="COGNITO_USER_POOLS",
        authorizerId=authorizer["id"],
        authorizationScopes=scopes or [],
    )
    headers = authorization_headers or [("Authorization", token)]
    invocation.invocation_request = InvocationRequest(headers=Headers(headers))
    invocation.context_variables = {}
    CognitoUserPoolsAuthorizerHandler()(RestApiGatewayHandlerChain(), invocation, Response())
    return invocation


def _replace_header(token, **updates):
    encoded_header, payload, signature = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(encoded_header + "=" * (-len(encoded_header) % 4)))
    header.update(updates)
    replacement = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=")
    return f"{replacement.decode()}.{payload}.{signature}"


def _resign_id_token(context, pool_id, token, *, issued_at=None, **updates):
    encoded_claims = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(encoded_claims + "=" * (-len(encoded_claims) % 4)))
    claims.update(updates)
    issued_at = claims["iat"] if issued_at is None else issued_at
    with cognito_idp_stores.lock:
        pool = cognito_idp_stores[context.account_id][context.region].user_pools[pool_id]
        return sign_jwt(
            pool.id_signing_private_key_pem,
            pool.id_signing_key_id,
            claims,
            now=issued_at,
        )


def test_id_token_authorizes_without_scopes_and_exposes_signed_groups(aws_context):
    pool, _, authentication = _tokens(aws_context)

    invocation = _invoke(aws_context, pool["Arn"], authentication["IdToken"])

    claims = invocation.context_variables["authorizer"]["claims"]
    assert claims["token_use"] == "id"
    assert claims["cognito:groups"] == ["operators"]
    assert invocation.context_variables["authorizer"]["principalId"] == claims["sub"]


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER"])
def test_authorizer_accepts_strict_bearer_scheme_for_amplify_clients(aws_context, scheme):
    pool, _, authentication = _tokens(aws_context)

    invocation = _invoke(
        aws_context,
        pool["Arn"],
        f"{scheme} {authentication['IdToken']}",
    )

    assert invocation.context_variables["authorizer"]["claims"]["token_use"] == "id"


def test_authorizer_rejects_ambiguous_bearer_and_duplicate_headers(aws_context):
    pool, _, authentication = _tokens(aws_context)
    token = authentication["IdToken"]
    invalid_values = (
        f"Bearer  {token}",
        f"Bearer\t{token}",
        f" Bearer {token}",
        f"Bearer {token} ",
        f"Bearer {token} extra",
        "Bearer",
    )

    for value in invalid_values:
        with pytest.raises(UnauthorizedError):
            _invoke(aws_context, pool["Arn"], value)

    with pytest.raises(UnauthorizedError):
        _invoke(
            aws_context,
            pool["Arn"],
            token,
            authorization_headers=[("Authorization", token), ("Authorization", token)],
        )


def test_access_token_requires_any_configured_scope_and_rejects_id_token(aws_context):
    pool, _, authentication = _tokens(aws_context)
    required = ["api/unknown", "aws.cognito.signin.user.admin"]

    invocation = _invoke(
        aws_context,
        pool["Arn"],
        authentication["AccessToken"],
        scopes=required,
    )
    assert invocation.context_variables["authorizer"]["claims"]["token_use"] == "access"

    with pytest.raises(UnauthorizedError):
        _invoke(aws_context, pool["Arn"], authentication["IdToken"], scopes=required)
    with pytest.raises(UnauthorizedError):
        _invoke(
            aws_context,
            pool["Arn"],
            authentication["AccessToken"],
            scopes=["api/unknown"],
        )


def test_authorizer_rejects_access_without_scopes_and_alg_kid_confusion(aws_context):
    pool, _, authentication = _tokens(aws_context)

    invalid_tokens = (
        authentication["AccessToken"],
        _replace_header(authentication["IdToken"], alg="HS256"),
        _replace_header(authentication["IdToken"], kid="unknown"),
        "not-a-jwt",
        "",
    )
    for token in invalid_tokens:
        with pytest.raises(UnauthorizedError):
            _invoke(aws_context, pool["Arn"], token)


def test_authorizer_rejects_expired_and_malformed_signed_group_claims(aws_context):
    pool, _, authentication = _tokens(aws_context)
    issued_at = int(time.time()) - 3_600
    expired = _resign_id_token(
        aws_context,
        pool["Id"],
        authentication["IdToken"],
        issued_at=issued_at,
        auth_time=issued_at,
        exp=issued_at + 60,
    )
    malformed_groups = _resign_id_token(
        aws_context,
        pool["Id"],
        authentication["IdToken"],
        **{"cognito:groups": "operators"},
    )

    for token in (expired, malformed_groups):
        with pytest.raises(UnauthorizedError):
            _invoke(aws_context, pool["Arn"], token)


def test_authorizer_pool_audience_and_validation_expression_are_exact(aws_context):
    pool, client, authentication = _tokens(aws_context)
    other_pool, _, _ = _tokens(aws_context)

    with pytest.raises(UnauthorizedError):
        _invoke(aws_context, other_pool["Arn"], authentication["IdToken"])
    with pytest.raises(UnauthorizedError):
        _invoke(
            aws_context,
            pool["Arn"],
            authentication["IdToken"],
            validation_expression="different-client",
        )

    _invoke(
        aws_context,
        pool["Arn"],
        authentication["IdToken"],
        validation_expression=client["ClientId"],
    )

    with pytest.raises(UnauthorizedError):
        _invoke(
            aws_context,
            pool["Arn"],
            authentication["AccessToken"],
            scopes=["aws.cognito.signin.user.admin"],
            validation_expression=".*",
        )


def test_authorizer_invalid_regex_is_configuration_error(aws_context):
    pool, _, authentication = _tokens(aws_context)

    with pytest.raises(AuthorizerConfigurationError):
        _invoke(
            aws_context,
            pool["Arn"],
            authentication["IdToken"],
            validation_expression="[",
        )


def test_authorizer_accepts_configured_native_pool_from_another_account(aws_context):
    foreign = RequestContext(None)
    foreign.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    foreign.region = aws_context.region
    foreign.partition = aws_context.partition
    try:
        pool, _, authentication = _tokens(foreign)

        invocation = _invoke(aws_context, pool["Arn"], authentication["IdToken"])

        assert invocation.context_variables["authorizer"]["claims"]["token_use"] == "id"
    finally:
        _remove_account(foreign.account_id)
