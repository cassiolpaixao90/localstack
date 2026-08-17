import base64
import functools
import json
import re
import time
from typing import Any

import botocore.loaders
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from localstack.services.cognito_idp.models import cognito_idp_stores, resolve_pool_location

_MAX_JWT_BYTES = 50_000
_MAX_JWT_SEGMENT_BYTES = 32_768
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_PROVIDER_RE = re.compile(
    r"^cognito-idp\.(?P<region>[a-z0-9-]+)\.(?P<suffix>[a-z0-9.-]+)/"
    r"(?P<pool>[a-z0-9-]+_[A-Za-z0-9]+)$"
)


class TokenValidationError(ValueError):
    """Raised when a login is not a trusted native Cognito ID token."""


def verify_native_id_token(
    *,
    account_id: str,
    region: str,
    partition: str,
    provider_name: str,
    client_id: str,
    token: str,
    server_side_token_check: bool,
    now: int | None = None,
) -> str:
    """Validate one native Cognito User Pool login and return its subject."""
    return verify_native_id_token_claims(
        account_id=account_id,
        region=region,
        partition=partition,
        provider_name=provider_name,
        client_id=client_id,
        token=token,
        server_side_token_check=server_side_token_check,
        now=now,
    )["sub"]


def verify_native_id_token_claims(
    *,
    account_id: str,
    region: str,
    partition: str,
    provider_name: str,
    client_id: str,
    token: str,
    server_side_token_check: bool,
    now: int | None = None,
) -> dict[str, Any]:
    """Validate one native Cognito User Pool ID token and return trusted claims."""
    if not isinstance(token, str) or not 1 <= len(token) <= _MAX_JWT_BYTES:
        raise TokenValidationError("Invalid login token")
    match = _PROVIDER_RE.fullmatch(provider_name)
    if match is None or match.group("region") != region:
        raise TokenValidationError("Unsupported login provider")
    pool_id = match.group("pool")
    if resolve_pool_location(pool_id) != (account_id, region):
        raise TokenValidationError("User pool is outside the identity pool scope")

    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(account_id)
        store = bundle.get(region) if bundle is not None else None
        pool = store.user_pools.get(pool_id) if store is not None else None
        if pool is None or client_id not in pool.clients:
            raise TokenValidationError("Unknown user pool or app client")
        arn_parts = pool.arn.split(":", 5)
        if len(arn_parts) != 6 or arn_parts[0] != "arn":
            raise TokenValidationError("Invalid user pool ARN")
        pool_partition = arn_parts[1]
        if pool_partition != partition:
            raise TokenValidationError("User pool partition does not match")
        expected_provider = f"cognito-idp.{region}.{_partition_dns_suffix(partition)}/{pool_id}"
        if provider_name != expected_provider:
            raise TokenValidationError("Login provider does not match the user pool")

        header_segment, payload_segment, signature_segment = _jwt_segments(token)
        header = _json_segment(header_segment)
        claims = _json_segment(payload_segment)
        if (
            set(header) not in ({"alg", "kid"}, {"alg", "kid", "typ"})
            or header.get("alg") != "RS256"
            or header.get("kid") != pool.id_signing_key_id
            or ("typ" in header and header["typ"] != "JWT")
        ):
            raise TokenValidationError("Invalid ID token header")
        jwk = pool.id_signing_jwk
        if (
            jwk.get("alg") != "RS256"
            or jwk.get("kid") != pool.id_signing_key_id
            or jwk.get("kty") != "RSA"
            or jwk.get("use") != "sig"
        ):
            raise TokenValidationError("Invalid user pool signing key")
        signature = _decode_segment(signature_segment)
        try:
            _public_key(jwk).verify(
                signature,
                f"{header_segment}.{payload_segment}".encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except (InvalidSignature, OverflowError, TypeError, ValueError, KeyError) as error:
            raise TokenValidationError("Invalid ID token signature") from error

        current_time = int(time.time()) if now is None else now
        subject = _validated_claims(
            claims,
            issuer=f"https://{expected_provider}",
            client_id=client_id,
            now=current_time,
        )
        if server_side_token_check:
            user = next((item for item in pool.users.values() if item.sub == subject), None)
            if user is None or not user.enabled or user.status != "CONFIRMED":
                raise TokenValidationError("User is not active")
        return claims


def _validated_claims(claims: dict[str, Any], *, issuer: str, client_id: str, now: int) -> str:
    subject = claims.get("sub")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    auth_time = claims.get("auth_time")
    if (
        claims.get("iss") != issuer
        or claims.get("token_use") != "id"
        or claims.get("aud") != client_id
        or not isinstance(subject, str)
        or not 1 <= len(subject) <= 128
        or not _numeric_date(issued_at)
        or not _numeric_date(expires_at)
        or not _numeric_date(auth_time)
        or issued_at > now
        or expires_at <= now
        or expires_at <= issued_at
        or auth_time > issued_at
    ):
        raise TokenValidationError("Invalid ID token claims")
    return subject


def _numeric_date(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _jwt_segments(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise TokenValidationError("Invalid JWT shape")
    if any(len(part) > _MAX_JWT_SEGMENT_BYTES for part in parts):
        raise TokenValidationError("JWT segment is too large")
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
        ValueError,
        TypeError,
    ) as error:
        raise TokenValidationError("Invalid JWT JSON") from error
    if not isinstance(value, dict):
        raise TokenValidationError("Invalid JWT JSON")
    return value


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON key")
        value[key] = item
    return value


def _decode_segment(value: str) -> bytes:
    if _BASE64URL_RE.fullmatch(value) is None:
        raise TokenValidationError("Invalid base64url segment")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise TokenValidationError("Invalid base64url segment") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise TokenValidationError("Non-canonical base64url segment")
    return decoded


def _public_key(jwk: dict[str, str]):
    if not isinstance(jwk.get("e"), str) or not isinstance(jwk.get("n"), str):
        raise TokenValidationError("Invalid RSA public key")
    if len(jwk["e"]) > 16 or len(jwk["n"]) > 4096:
        raise TokenValidationError("Invalid RSA public key")
    exponent = int.from_bytes(_decode_segment(jwk["e"]), "big")
    modulus = int.from_bytes(_decode_segment(jwk["n"]), "big")
    if exponent < 3 or modulus.bit_length() < 2048:
        raise TokenValidationError("Invalid RSA public key")
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()


@functools.cache
def _partition_dns_suffix(partition: str) -> str:
    endpoint_data = botocore.loaders.create_loader().load_data("endpoints")
    for partition_data in endpoint_data["partitions"]:
        if partition_data.get("partition") == partition:
            suffix = partition_data.get("dnsSuffix")
            if isinstance(suffix, str) and suffix:
                return suffix
            break
    raise TokenValidationError("Unknown AWS partition")
