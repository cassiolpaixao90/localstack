import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

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

_AUTHORIZATION_SOURCE = "$request.header.Authorization"
_BEARER_TOKEN_RE = re.compile(r"Bearer (?P<token>[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)")
_COGNITO_ISSUER_RE = re.compile(
    r"^https://cognito-idp\.(?P<region>[a-z0-9-]+)\.(?P<suffix>[a-z0-9.-]+)/"
    r"(?P<pool>[a-z0-9-]+_[A-Za-z0-9]+)$"
)
_MAX_AUDIENCES = 100
_MAX_SCOPES = 100
_MAX_SCOPE_LENGTH = 256


class HttpApiJwtConfigurationError(ValueError):
    pass


class HttpApiJwtUnauthorized(ValueError):
    pass


@dataclass(frozen=True)
class HttpApiJwtAuthorizerConfiguration:
    identity_source: tuple[str, ...]
    issuer: str
    audience: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.identity_source != (_AUTHORIZATION_SOURCE,):
            raise HttpApiJwtConfigurationError(
                "The native Cognito JWT foundation requires the Authorization header"
            )
        if not isinstance(self.issuer, str) or _COGNITO_ISSUER_RE.fullmatch(self.issuer) is None:
            raise HttpApiJwtConfigurationError("Invalid native Cognito issuer")
        if not _valid_string_set(
            self.audience, minimum=1, maximum=_MAX_AUDIENCES, item_maximum=128
        ):
            raise HttpApiJwtConfigurationError("Invalid JWT audience configuration")


@dataclass(frozen=True)
class HttpApiJwtAuthorization:
    claims: dict[str, Any]
    scopes: tuple[str, ...]


def authorize_native_cognito_jwt(
    *,
    authorization_headers: Sequence[str],
    configuration: HttpApiJwtAuthorizerConfiguration,
    authorization_scopes: Sequence[str],
    api_account_id: str,
    api_region: str,
) -> HttpApiJwtAuthorization:
    """Validate one native Cognito JWT without discovery or network access.

    This is a data-plane foundation. API Gateway v2 routing and integration are
    intentionally outside this module until that data plane exists.
    """
    if not isinstance(configuration, HttpApiJwtAuthorizerConfiguration):
        raise HttpApiJwtConfigurationError("Invalid JWT authorizer configuration")
    route_scopes = _validated_route_scopes(authorization_scopes)
    token = _bearer_token(authorization_headers)
    try:
        decoded = decode_jwt(token)
        with cognito_idp_stores.lock:
            pool = _native_pool(
                configuration.issuer,
                api_account_id=api_account_id,
                api_region=api_region,
            )
            token_use = decoded.claims.get("token_use")
            if token_use == "id":
                key_id, jwk = pool.id_signing_key_id, pool.id_signing_jwk
            elif token_use == "access":
                key_id, jwk = pool.access_signing_key_id, pool.access_signing_jwk
            else:
                raise CognitoTokenError("Invalid Cognito token use")
            verify_rs256(decoded, key_id=key_id, jwk=jwk)
            token_scopes = _validate_claims(
                claims=decoded.claims,
                issuer=configuration.issuer,
                audience=configuration.audience,
                route_scopes=route_scopes,
                pool=pool,
            )
    except CognitoTokenError as error:
        raise HttpApiJwtUnauthorized() from error
    return HttpApiJwtAuthorization(claims=decoded.claims, scopes=token_scopes)


def _bearer_token(values: Sequence[str]) -> str:
    if (
        not isinstance(values, (list, tuple))
        or len(values) != 1
        or not isinstance(values[0], str)
        or len(values[0]) > MAX_JWT_BYTES + len("Bearer ")
    ):
        raise HttpApiJwtUnauthorized()
    match = _BEARER_TOKEN_RE.fullmatch(values[0])
    if match is None:
        raise HttpApiJwtUnauthorized()
    return match.group("token")


def _native_pool(issuer: str, *, api_account_id: str, api_region: str):
    match = _COGNITO_ISSUER_RE.fullmatch(issuer)
    if (
        match is None
        or not isinstance(api_account_id, str)
        or re.fullmatch(r"\d{12}", api_account_id) is None
        or not isinstance(api_region, str)
        or match.group("region") != api_region
    ):
        raise CognitoTokenError("Issuer is outside the API scope")
    partition = get_partition(api_region)
    if match.group("suffix") != partition_dns_suffix(partition):
        raise CognitoTokenError("Issuer partition does not match the API")
    pool_id = match.group("pool")
    if resolve_pool_location(pool_id) != (api_account_id, api_region):
        raise CognitoTokenError("User pool is outside the API scope")
    bundle = cognito_idp_stores.get(api_account_id)
    store = bundle.get(api_region) if bundle is not None else None
    pool = store.user_pools.get(pool_id) if store is not None else None
    if pool is None:
        raise CognitoTokenError("User pool does not exist")
    return pool


def _validate_claims(
    *,
    claims: dict[str, Any],
    issuer: str,
    audience: tuple[str, ...],
    route_scopes: tuple[str, ...],
    pool,
) -> tuple[str, ...]:
    now = int(time.time())
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    not_before = claims.get("nbf")
    auth_time = claims.get("auth_time")
    subject = claims.get("sub")
    if (
        claims.get("iss") != issuer
        or not isinstance(subject, str)
        or not 1 <= len(subject) <= 128
        or not numeric_date(issued_at)
        or not numeric_date(expires_at)
        or issued_at > now
        or expires_at <= now
        or expires_at <= issued_at
        or (not_before is not None and (not numeric_date(not_before) or not_before > now))
        or not numeric_date(auth_time)
        or auth_time > issued_at
    ):
        raise CognitoTokenError("Invalid token claims")
    _validate_groups(claims.get("cognito:groups"))
    _validate_audience(claims, audience=audience, pool=pool)
    token_scopes = _token_scopes(claims)
    if route_scopes and not set(route_scopes).intersection(token_scopes):
        raise CognitoTokenError("Token has no required scope")
    return token_scopes


def _validate_audience(claims: dict[str, Any], *, audience: tuple[str, ...], pool) -> None:
    raw_audience = claims.get("aud")
    if raw_audience is None:
        client_id = claims.get("client_id")
        candidates = (client_id,) if isinstance(client_id, str) else ()
    elif isinstance(raw_audience, str):
        candidates = (raw_audience,)
    elif _valid_string_set(raw_audience, minimum=1, maximum=_MAX_AUDIENCES, item_maximum=128):
        candidates = tuple(raw_audience)
    else:
        candidates = ()
    if not candidates or not set(candidates).intersection(audience):
        raise CognitoTokenError("Invalid token audience")
    if not any(candidate in pool.clients for candidate in candidates):
        raise CognitoTokenError("Unknown user-pool client")


def _token_scopes(claims: dict[str, Any]) -> tuple[str, ...]:
    value = claims.get("scope") if "scope" in claims else claims.get("scp")
    if value is None:
        return ()
    if isinstance(value, str):
        scopes = tuple(value.split())
    elif _valid_string_set(value, minimum=1, maximum=_MAX_SCOPES, item_maximum=_MAX_SCOPE_LENGTH):
        scopes = tuple(value)
    else:
        raise CognitoTokenError("Invalid token scopes")
    if not _valid_string_set(
        scopes, minimum=1, maximum=_MAX_SCOPES, item_maximum=_MAX_SCOPE_LENGTH
    ):
        raise CognitoTokenError("Invalid token scopes")
    return scopes


def _validated_route_scopes(value: Sequence[str]) -> tuple[str, ...]:
    if not _valid_string_set(value, minimum=0, maximum=_MAX_SCOPES, item_maximum=_MAX_SCOPE_LENGTH):
        raise HttpApiJwtConfigurationError("Invalid route authorization scopes")
    return tuple(value)


def _validate_groups(value: Any) -> None:
    if value is not None and not _valid_string_set(value, minimum=1, maximum=100, item_maximum=128):
        raise CognitoTokenError("Invalid Cognito groups")


def _valid_string_set(value: Any, *, minimum: int, maximum: int, item_maximum: int) -> bool:
    if not isinstance(value, (list, tuple)) or not minimum <= len(value) <= maximum:
        return False
    if not all(isinstance(item, str) and 1 <= len(item) <= item_maximum for item in value):
        return False
    return len(set(value)) == len(value)
