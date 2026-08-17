import base64
import functools
import json
import re
import secrets
import time
from typing import Any

import botocore.loaders
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from localstack.services.cognito_identity.models import CognitoIdentityStore
from localstack.services.cognito_idp.tokens import (
    generate_signing_key,
    public_key_from_jwk,
    sign_jwt,
)

_MAX_TOKEN_BYTES = 50_000
_MAX_SEGMENT_BYTES = 32_768
_MAX_TOKEN_DURATION = 86_400
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_GLOBAL_ISSUER_REGIONS = {
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ca-central-1",
    "eu-central-1",
    "eu-north-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "sa-east-1",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
}


class OpenIdTokenError(ValueError):
    """Raised when an identity-pool OpenID token cannot be issued or trusted."""


def identity_issuer(partition: str, region: str) -> str:
    if not isinstance(region, str) or not region:
        raise OpenIdTokenError("Invalid identity token region")
    suffix = _partition_dns_suffix(partition)
    if partition == "aws" and region in _GLOBAL_ISSUER_REGIONS:
        return "https://cognito-identity.amazonaws.com"
    return f"https://cognito-identity.{region}.{suffix}"


def ensure_open_id_signing_key(store: CognitoIdentityStore) -> None:
    existing = (
        bool(store.open_id_signing_key_id),
        bool(store.open_id_signing_private_key),
        bool(store.open_id_signing_jwk),
    )
    if all(existing):
        return
    if any(existing):
        raise OpenIdTokenError("Identity token signing key state is incomplete")
    key_id, private_key, jwk = generate_signing_key()
    store.open_id_signing_key_id = key_id
    store.open_id_signing_private_key = private_key
    store.open_id_signing_jwk = jwk


def issue_open_id_token(
    store: CognitoIdentityStore,
    *,
    partition: str,
    region: str,
    pool_id: str,
    identity_id: str,
    authenticated: bool,
    provider_names: list[str],
    duration: int,
    principal_tags: dict[str, str] | None = None,
    now: int | None = None,
) -> str:
    if (
        not isinstance(duration, int)
        or isinstance(duration, bool)
        or not 1 <= duration <= _MAX_TOKEN_DURATION
    ):
        raise OpenIdTokenError("Invalid identity token duration")
    if len(provider_names) > 20 or any(
        not isinstance(name, str) or not 1 <= len(name) <= 128 for name in provider_names
    ):
        raise OpenIdTokenError("Invalid identity token providers")
    if not authenticated and provider_names:
        raise OpenIdTokenError("Guest identity token cannot contain providers")
    ensure_open_id_signing_key(store)
    issued_at = int(time.time()) if now is None else now
    amr = ["authenticated", *sorted(provider_names)] if authenticated else ["unauthenticated"]
    claims: dict[str, Any] = {
        "amr": amr,
        "aud": pool_id,
        "exp": issued_at + duration,
        "iss": identity_issuer(partition, region),
        "jti": secrets.token_urlsafe(18),
        "sub": identity_id,
    }
    if principal_tags:
        claims["principal_tags"] = dict(sorted(principal_tags.items()))
    token = sign_jwt(
        store.open_id_signing_private_key,
        store.open_id_signing_key_id,
        claims,
        now=issued_at,
    )
    if len(token) > _MAX_TOKEN_BYTES:
        raise OpenIdTokenError("Identity token is too large")
    return token


def verify_open_id_token(
    store: CognitoIdentityStore,
    *,
    token: str,
    partition: str,
    region: str,
    pool_id: str,
    identity_id: str,
    authenticated: bool,
    now: int | None = None,
) -> dict[str, Any]:
    if not isinstance(token, str) or not 1 <= len(token) <= _MAX_TOKEN_BYTES:
        raise OpenIdTokenError("Invalid identity token")
    header_segment, claims_segment, signature_segment = _segments(token)
    header = _json_segment(header_segment)
    claims = _json_segment(claims_segment)
    if header != {
        "alg": "RS256",
        "kid": store.open_id_signing_key_id,
        "typ": "JWT",
    }:
        raise OpenIdTokenError("Invalid identity token header")
    jwk = store.open_id_signing_jwk
    if (
        not store.open_id_signing_key_id
        or jwk.get("alg") != "RS256"
        or jwk.get("kid") != store.open_id_signing_key_id
        or jwk.get("kty") != "RSA"
        or jwk.get("use") != "sig"
    ):
        raise OpenIdTokenError("Invalid identity token signing key")
    try:
        public_key_from_jwk(jwk).verify(
            _decode_segment(signature_segment),
            f"{header_segment}.{claims_segment}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (InvalidSignature, KeyError, OverflowError, TypeError, ValueError) as error:
        raise OpenIdTokenError("Invalid identity token signature") from error
    _validate_claims(
        claims,
        issuer=identity_issuer(partition, region),
        pool_id=pool_id,
        identity_id=identity_id,
        authenticated=authenticated,
        now=int(time.time()) if now is None else now,
    )
    return claims


def _validate_claims(
    claims: dict[str, Any],
    *,
    issuer: str,
    pool_id: str,
    identity_id: str,
    authenticated: bool,
    now: int,
) -> None:
    required = {"amr", "aud", "exp", "iat", "iss", "jti", "sub"}
    if set(claims) not in (required, required | {"principal_tags"}):
        raise OpenIdTokenError("Invalid identity token claims")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    amr = claims.get("amr")
    expected_method = "authenticated" if authenticated else "unauthenticated"
    if (
        claims.get("iss") != issuer
        or claims.get("aud") != pool_id
        or claims.get("sub") != identity_id
        or not _numeric_date(issued_at)
        or not _numeric_date(expires_at)
        or issued_at > now
        or expires_at <= now
        or expires_at <= issued_at
        or expires_at - issued_at > _MAX_TOKEN_DURATION
        or not isinstance(amr, list)
        or not amr
        or amr[0] != expected_method
        or len(amr) > 21
        or any(not isinstance(item, str) or not 1 <= len(item) <= 128 for item in amr)
        or len(set(amr)) != len(amr)
        or (not authenticated and amr != ["unauthenticated"])
        or not isinstance(claims.get("jti"), str)
        or not 16 <= len(claims["jti"]) <= 128
    ):
        raise OpenIdTokenError("Invalid identity token claims")
    principal_tags = claims.get("principal_tags")
    if principal_tags is not None and (
        not authenticated
        or not isinstance(principal_tags, dict)
        or not 1 <= len(principal_tags) <= 50
        or any(
            not isinstance(key, str)
            or not 1 <= len(key) <= 128
            or not isinstance(value, str)
            or not 1 <= len(value) <= 256
            for key, value in principal_tags.items()
        )
    ):
        raise OpenIdTokenError("Invalid identity token principal tags")


def _segments(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3 or any(not part or len(part) > _MAX_SEGMENT_BYTES for part in parts):
        raise OpenIdTokenError("Invalid identity token shape")
    return parts[0], parts[1], parts[2]


def _json_segment(segment: str) -> dict[str, Any]:
    try:
        value = json.loads(
            _decode_segment(segment),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as error:
        raise OpenIdTokenError("Invalid identity token JSON") from error
    if not isinstance(value, dict):
        raise OpenIdTokenError("Invalid identity token JSON")
    return value


def _decode_segment(value: str) -> bytes:
    if _BASE64URL_RE.fullmatch(value) is None:
        raise OpenIdTokenError("Invalid identity token encoding")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (TypeError, ValueError) as error:
        raise OpenIdTokenError("Invalid identity token encoding") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise OpenIdTokenError("Non-canonical identity token encoding")
    return decoded


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON key")
        value[key] = item
    return value


def _numeric_date(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


@functools.cache
def _partition_dns_suffix(partition: str) -> str:
    endpoint_data = botocore.loaders.create_loader().load_data("endpoints")
    for partition_data in endpoint_data["partitions"]:
        if partition_data.get("partition") != partition:
            continue
        suffix = partition_data.get("dnsSuffix")
        if isinstance(suffix, str) and suffix:
            return suffix
        break
    raise OpenIdTokenError("Unknown AWS partition")
