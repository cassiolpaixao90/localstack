import base64
import json
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _integer_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def decode_jwt_segment(value: str) -> dict[str, Any]:
    padding_length = (-len(value)) % 4
    return json.loads(base64.urlsafe_b64decode(value + "=" * padding_length))


def generate_signing_key() -> tuple[str, bytes, dict[str, str]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_id = secrets.token_urlsafe(16)
    public_numbers = private_key.public_key().public_numbers()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    jwk = {
        "alg": "RS256",
        "e": _b64url(_integer_bytes(public_numbers.e)),
        "kid": key_id,
        "kty": "RSA",
        "n": _b64url(_integer_bytes(public_numbers.n)),
        "use": "sig",
    }
    return key_id, private_pem, jwk


def public_key_from_jwk(jwk: dict[str, str]):
    exponent = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=="), "big")
    modulus = int.from_bytes(
        base64.urlsafe_b64decode(jwk["n"] + "=" * ((-len(jwk["n"])) % 4)), "big"
    )
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()


def sign_jwt(
    private_key_pem: bytes,
    key_id: str,
    claims: dict[str, Any],
    *,
    now: int | None = None,
) -> str:
    issued_at = int(time.time()) if now is None else now
    payload = {**claims, "iat": issued_at}
    header = {"alg": "RS256", "kid": key_id, "typ": "JWT"}
    encoded_header = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode()}.{_b64url(signature)}"
