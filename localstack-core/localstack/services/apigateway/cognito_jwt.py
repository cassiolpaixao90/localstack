import base64
import functools
import json
import re
from dataclasses import dataclass
from typing import Any

import botocore.loaders
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MAX_JWT_BYTES = 50_000
MAX_JWT_SEGMENT_BYTES = 32_768

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class CognitoTokenError(ValueError):
    pass


@dataclass(frozen=True)
class DecodedJwt:
    header: dict[str, Any]
    claims: dict[str, Any]
    header_segment: str
    payload_segment: str
    signature_segment: str


def decode_jwt(token: str) -> DecodedJwt:
    header_segment, payload_segment, signature_segment = _jwt_segments(token)
    return DecodedJwt(
        header=_json_segment(header_segment),
        claims=_json_segment(payload_segment),
        header_segment=header_segment,
        payload_segment=payload_segment,
        signature_segment=signature_segment,
    )


def verify_rs256(decoded: DecodedJwt, *, key_id: str, jwk: dict[str, str]) -> None:
    if (
        set(decoded.header) != {"alg", "kid", "typ"}
        or decoded.header.get("alg") != "RS256"
        or decoded.header.get("kid") != key_id
        or decoded.header.get("typ") != "JWT"
    ):
        raise CognitoTokenError("Invalid token header")
    if (
        jwk.get("alg") != "RS256"
        or jwk.get("kid") != key_id
        or jwk.get("kty") != "RSA"
        or jwk.get("use") != "sig"
    ):
        raise CognitoTokenError("Invalid signing key")
    try:
        _public_key(jwk).verify(
            _decode_segment(decoded.signature_segment),
            f"{decoded.header_segment}.{decoded.payload_segment}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (InvalidSignature, OverflowError, TypeError, ValueError, KeyError) as error:
        raise CognitoTokenError("Invalid token signature") from error


def numeric_date(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


@functools.cache
def partition_dns_suffix(partition: str) -> str:
    endpoint_data = botocore.loaders.create_loader().load_data("endpoints")
    for partition_data in endpoint_data["partitions"]:
        if partition_data.get("partition") == partition:
            suffix = partition_data.get("dnsSuffix")
            if isinstance(suffix, str) and suffix:
                return suffix
            break
    raise CognitoTokenError("Unsupported partition")


def _jwt_segments(token: str) -> tuple[str, str, str]:
    if not isinstance(token, str) or not 1 <= len(token) <= MAX_JWT_BYTES:
        raise CognitoTokenError("Invalid token")
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise CognitoTokenError("Invalid token shape")
    if any(len(part) > MAX_JWT_SEGMENT_BYTES for part in parts):
        raise CognitoTokenError("Token segment is too large")
    return parts[0], parts[1], parts[2]


def _json_segment(segment: str) -> dict[str, Any]:
    try:
        value = json.loads(_decode_segment(segment), object_pairs_hook=_reject_duplicate_json_keys)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
        TypeError,
    ) as error:
        raise CognitoTokenError("Invalid token JSON") from error
    if not isinstance(value, dict):
        raise CognitoTokenError("Invalid token JSON")
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
        raise CognitoTokenError("Invalid base64url segment")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise CognitoTokenError("Invalid base64url segment") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise CognitoTokenError("Non-canonical base64url segment")
    return decoded


def _public_key(jwk: dict[str, str]):
    if not isinstance(jwk.get("e"), str) or not isinstance(jwk.get("n"), str):
        raise CognitoTokenError("Invalid RSA public key")
    if len(jwk["e"]) > 16 or len(jwk["n"]) > 4096:
        raise CognitoTokenError("Invalid RSA public key")
    exponent = int.from_bytes(_decode_segment(jwk["e"]), "big")
    modulus = int.from_bytes(_decode_segment(jwk["n"]), "big")
    if exponent < 3 or modulus.bit_length() < 2048:
        raise CognitoTokenError("Invalid RSA public key")
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()
