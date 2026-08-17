import re
import time
from typing import Any

from localstack.aws.api.apigateway import Authorizer, Method
from localstack.http import Response
from localstack.services.apigateway.cognito_jwt import (
    MAX_JWT_BYTES,
    CognitoTokenError,
    decode_jwt,
    numeric_date,
    partition_dns_suffix,
    verify_rs256,
)
from localstack.services.cognito_idp.models import cognito_idp_stores, resolve_pool_location
from localstack.utils.aws.arns import get_partition

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext
from ..gateway_response import AuthorizerConfigurationError, UnauthorizedError
from ..helpers import render_uri_with_stage_variables

_MAX_VALIDATION_EXPRESSION = 1_024
_BEARER_TOKEN_RE = re.compile(
    r"(?i:bearer) (?P<token>[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
)
_IDENTITY_SOURCE_RE = re.compile(r"^method\.request\.header\.(?P<header>[A-Za-z0-9-]{1,128})$")
_USER_POOL_ARN_RE = re.compile(
    r"^arn:(?P<partition>aws(?:-[a-z0-9-]+)?):cognito-idp:(?P<region>[a-z0-9-]+):"
    r"(?P<account>\d{12}):userpool/(?P<pool>[a-z0-9-]+_[A-Za-z0-9]+)$"
)


class CognitoUserPoolsAuthorizerHandler(RestApiGatewayHandler):
    """Authorize REST API methods against native Cognito user-pool JWTs."""

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        method = context.resource_method
        if method.get("authorizationType") != "COGNITO_USER_POOLS":
            return
        authorizer = self._authorizer(context, method)
        token = self._identity_token(context, authorizer)
        scopes = method.get("authorizationScopes") or []
        if (
            not isinstance(scopes, list)
            or any(not isinstance(scope, str) or not scope or len(scope) > 256 for scope in scopes)
            or len(set(scopes)) != len(scopes)
        ):
            raise AuthorizerConfigurationError()
        validation_expression = _validation_expression(authorizer)
        try:
            claims = _verify_token(
                token=token,
                provider_arns=_provider_arns(authorizer, context),
                expected_token_use="access" if scopes else "id",
                required_scopes=scopes,
                identity_validation_expression=validation_expression,
                api_region=context.region,
            )
        except CognitoTokenError as error:
            raise UnauthorizedError() from error
        context.context_variables["authorizer"] = {
            "claims": claims,
            "principalId": claims["sub"],
        }

    @staticmethod
    def _authorizer(context: RestApiInvocationContext, method: Method) -> Authorizer:
        authorizer_id = method.get("authorizerId")
        if not isinstance(authorizer_id, str) or not authorizer_id:
            raise AuthorizerConfigurationError()
        authorizer = context.deployment.rest_api.authorizers.get(authorizer_id)
        if authorizer is None or authorizer.get("type") != "COGNITO_USER_POOLS":
            raise AuthorizerConfigurationError()
        return authorizer

    @staticmethod
    def _identity_token(context: RestApiInvocationContext, authorizer: Authorizer) -> str:
        identity_source = authorizer.get("identitySource")
        if (
            not isinstance(identity_source, str)
            or (match := _IDENTITY_SOURCE_RE.fullmatch(identity_source)) is None
        ):
            raise AuthorizerConfigurationError()
        values = context.invocation_request["headers"].getlist(match.group("header"))
        if len(values) != 1 or not values[0] or len(values[0]) > MAX_JWT_BYTES + 7:
            raise UnauthorizedError()
        value = values[0]
        if bearer := _BEARER_TOKEN_RE.fullmatch(value):
            return bearer.group("token")
        if any(character.isspace() for character in value) or len(value) > MAX_JWT_BYTES:
            raise UnauthorizedError()
        return value


def _provider_arns(authorizer: Authorizer, context: RestApiInvocationContext) -> list[str]:
    values = authorizer.get("providerARNs")
    if not isinstance(values, list) or not 1 <= len(values) <= 1_000:
        raise AuthorizerConfigurationError()
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise AuthorizerConfigurationError()
        rendered = render_uri_with_stage_variables(value, context.stage_variables)
        if not isinstance(rendered, str) or _USER_POOL_ARN_RE.fullmatch(rendered) is None:
            raise AuthorizerConfigurationError()
        result.append(rendered)
    if len(set(result)) != len(result):
        raise AuthorizerConfigurationError()
    return result


def _validation_expression(authorizer: Authorizer) -> re.Pattern[str] | None:
    value = authorizer.get("identityValidationExpression")
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > _MAX_VALIDATION_EXPRESSION:
        raise AuthorizerConfigurationError()
    try:
        return re.compile(value)
    except re.error as error:
        raise AuthorizerConfigurationError() from error


def _verify_token(
    *,
    token: str,
    provider_arns: list[str],
    expected_token_use: str,
    required_scopes: list[str],
    identity_validation_expression: re.Pattern[str] | None,
    api_region: str,
) -> dict[str, Any]:
    decoded = decode_jwt(token)
    claims = decoded.claims
    issuer = claims.get("iss")
    candidates = [
        match
        for arn in provider_arns
        if (match := _USER_POOL_ARN_RE.fullmatch(arn)) is not None
        and issuer
        == f"https://cognito-idp.{match.group('region')}.{partition_dns_suffix(match.group('partition'))}/{match.group('pool')}"
    ]
    if len(candidates) != 1:
        raise CognitoTokenError("Token issuer is not configured")
    provider = candidates[0]
    if provider.group("partition") != get_partition(api_region):
        raise CognitoTokenError("User pool partition does not match")
    account_id, region, pool_id = (
        provider.group("account"),
        provider.group("region"),
        provider.group("pool"),
    )
    if region != api_region or resolve_pool_location(pool_id) != (account_id, region):
        raise CognitoTokenError("User pool is outside the API scope")

    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(account_id)
        store = bundle.get(region) if bundle is not None else None
        pool = store.user_pools.get(pool_id) if store is not None else None
        if pool is None:
            raise CognitoTokenError("User pool does not exist")
        if expected_token_use == "id":
            key_id, jwk = pool.id_signing_key_id, pool.id_signing_jwk
        else:
            key_id, jwk = pool.access_signing_key_id, pool.access_signing_jwk
        verify_rs256(decoded, key_id=key_id, jwk=jwk)
        _validate_claims(
            claims=claims,
            pool=pool,
            expected_token_use=expected_token_use,
            required_scopes=required_scopes,
            identity_validation_expression=identity_validation_expression,
        )
    return claims


def _validate_claims(
    *,
    claims: dict[str, Any],
    pool,
    expected_token_use: str,
    required_scopes: list[str],
    identity_validation_expression: re.Pattern[str] | None,
) -> None:
    now = int(time.time())
    subject = claims.get("sub")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    auth_time = claims.get("auth_time")
    if (
        claims.get("token_use") != expected_token_use
        or not isinstance(subject, str)
        or not 1 <= len(subject) <= 128
        or not numeric_date(issued_at)
        or not numeric_date(expires_at)
        or not numeric_date(auth_time)
        or issued_at > now
        or expires_at <= now
        or expires_at <= issued_at
        or auth_time > issued_at
    ):
        raise CognitoTokenError("Invalid token claims")
    groups = claims.get("cognito:groups")
    if groups is not None and (
        not isinstance(groups, list)
        or len(groups) > 100
        or len({item for item in groups if isinstance(item, str)}) != len(groups)
        or any(not isinstance(item, str) or not 1 <= len(item) <= 128 for item in groups)
    ):
        raise CognitoTokenError("Invalid group claims")

    if expected_token_use == "id":
        audience = claims.get("aud")
        if not isinstance(audience, str) or audience not in pool.clients:
            raise CognitoTokenError("Invalid token audience")
        if identity_validation_expression is not None:
            if identity_validation_expression.fullmatch(audience) is None:
                raise CognitoTokenError("Token audience was rejected")
        return

    if identity_validation_expression is not None:
        raise CognitoTokenError("Audience validation expressions reject access tokens")
    client_id = claims.get("client_id")
    raw_scopes = claims.get("scope")
    if not isinstance(client_id, str) or client_id not in pool.clients:
        raise CognitoTokenError("Invalid token client")
    if not isinstance(raw_scopes, str) or len(raw_scopes) > 10_000:
        raise CognitoTokenError("Invalid token scopes")
    token_scopes = raw_scopes.split()
    if not token_scopes or len(set(token_scopes)) != len(token_scopes):
        raise CognitoTokenError("Invalid token scopes")
    if not set(required_scopes).intersection(token_scopes):
        raise CognitoTokenError("Token has no required scope")
