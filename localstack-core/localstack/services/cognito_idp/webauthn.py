from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from localstack import config

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_CLIENT_DATA = 16 * 1024
_MAX_CREDENTIAL_JSON = 128 * 1024
_MAX_CBOR = 128 * 1024
_TRANSPORTS = {"ble", "hybrid", "internal", "nfc", "smart-card", "usb"}


class WebAuthnError(ValueError):
    pass


@dataclass(frozen=True)
class RegisteredCredential:
    credential_id: str
    public_key_pem: bytes
    algorithm: int
    sign_count: int
    authenticator_attachment: str | None
    authenticator_transports: list[str]


def credential_challenge_hash(credential: Any, *, string_input: bool) -> str:
    document = _credential_document(credential, string_input=string_input)
    response = document["response"]
    client_data_value = response.get("clientDataJSON")
    client_data = _strict_json_object(_base64url(client_data_value, maximum=_MAX_CLIENT_DATA))
    challenge = _base64url(client_data.get("challenge"), minimum=16, maximum=128)
    return hashlib.sha256(challenge).hexdigest()


def canonical_credential_id(value: Any) -> str:
    return _base64(_base64url(value, minimum=1, maximum=1023))


def response_credential_id(credential: Any, *, string_input: bool) -> str:
    return _credential_document(credential, string_input=string_input)["id"]


def registration_response(
    credential: Any,
    *,
    challenge_hash: str,
    relying_party_id: str,
    user_verification: str,
) -> RegisteredCredential:
    document = _credential_document(credential, string_input=False)
    response = document["response"]
    allowed_response = {
        "attestationObject",
        "authenticatorData",
        "clientDataJSON",
        "publicKey",
        "publicKeyAlgorithm",
        "transports",
    }
    if set(response) - allowed_response or not {
        "attestationObject",
        "clientDataJSON",
    } <= set(response):
        raise WebAuthnError("Invalid WebAuthn registration response")
    client_data = _base64url(response["clientDataJSON"], maximum=_MAX_CLIENT_DATA)
    _verify_client_data(
        client_data,
        expected_type="webauthn.create",
        challenge_hash=challenge_hash,
        relying_party_id=relying_party_id,
    )
    attestation_object = _base64url(response["attestationObject"], maximum=_MAX_CBOR)
    decoded, consumed = _decode_cbor(attestation_object)
    if consumed != len(attestation_object) or not isinstance(decoded, dict):
        raise WebAuthnError("Invalid WebAuthn attestation object")
    if set(decoded) != {"attStmt", "authData", "fmt"}:
        raise WebAuthnError("Invalid WebAuthn attestation object")
    if decoded["fmt"] != "none" or decoded["attStmt"] != {}:
        raise WebAuthnError("Unsupported WebAuthn attestation format")
    auth_data = decoded["authData"]
    if not isinstance(auth_data, bytes):
        raise WebAuthnError("Invalid WebAuthn authenticator data")
    parsed = _registration_authenticator_data(
        auth_data,
        relying_party_id=relying_party_id,
        require_user_verification=user_verification == "required",
    )
    credential_id = document["id"]
    if not _constant_text(credential_id, _base64(parsed["credential_id"])):
        raise WebAuthnError("WebAuthn credential ID mismatch")
    optional_auth_data = response.get("authenticatorData")
    if (
        optional_auth_data is not None
        and _base64url(optional_auth_data, maximum=_MAX_CBOR) != auth_data
    ):
        raise WebAuthnError("WebAuthn authenticator data mismatch")
    optional_algorithm = response.get("publicKeyAlgorithm")
    if optional_algorithm is not None and optional_algorithm != parsed["algorithm"]:
        raise WebAuthnError("WebAuthn public-key algorithm mismatch")
    optional_public_key = response.get("publicKey")
    if optional_public_key is not None:
        supplied_key = _base64url(optional_public_key, maximum=4096)
        expected_key = serialization.load_pem_public_key(parsed["public_key_pem"]).public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if supplied_key != expected_key:
            raise WebAuthnError("WebAuthn public key mismatch")
    transports = response.get("transports", [])
    if (
        not isinstance(transports, list)
        or len(transports) > len(_TRANSPORTS)
        or len(set(transports)) != len(transports)
        or any(item not in _TRANSPORTS for item in transports)
    ):
        raise WebAuthnError("Invalid WebAuthn authenticator transports")
    return RegisteredCredential(
        credential_id=credential_id,
        public_key_pem=parsed["public_key_pem"],
        algorithm=parsed["algorithm"],
        sign_count=parsed["sign_count"],
        authenticator_attachment=document.get("authenticatorAttachment"),
        authenticator_transports=list(transports),
    )


def authentication_response(
    credential_json: Any,
    *,
    challenge_hash: str,
    relying_party_id: str,
    user_verification: str,
    public_key_pem: bytes,
    algorithm: int,
    expected_user_handle: bytes,
) -> tuple[str, int]:
    document = _credential_document(credential_json, string_input=True)
    response = document["response"]
    if set(response) != {
        "authenticatorData",
        "clientDataJSON",
        "signature",
        "userHandle",
    }:
        raise WebAuthnError("Invalid WebAuthn authentication response")
    client_data = _base64url(response["clientDataJSON"], maximum=_MAX_CLIENT_DATA)
    _verify_client_data(
        client_data,
        expected_type="webauthn.get",
        challenge_hash=challenge_hash,
        relying_party_id=relying_party_id,
    )
    auth_data = _base64url(response["authenticatorData"], maximum=4096)
    sign_count = _authentication_authenticator_data(
        auth_data,
        relying_party_id=relying_party_id,
        require_user_verification=user_verification == "required",
    )
    user_handle = response["userHandle"]
    if (
        not isinstance(user_handle, str)
        or _base64url(user_handle, minimum=1, maximum=1024) != expected_user_handle
    ):
        raise WebAuthnError("WebAuthn user handle mismatch")
    signature = _base64url(response["signature"], maximum=4096)
    signed = auth_data + hashlib.sha256(client_data).digest()
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        if algorithm == -7 and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif algorithm == -257 and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise WebAuthnError("Unsupported WebAuthn credential algorithm")
    except (InvalidSignature, TypeError, ValueError) as error:
        raise WebAuthnError("Invalid WebAuthn assertion signature") from error
    return document["id"], sign_count


def _credential_document(value: Any, *, string_input: bool) -> dict[str, Any]:
    if string_input:
        if not isinstance(value, str) or not 1 <= len(value) <= _MAX_CREDENTIAL_JSON:
            raise WebAuthnError("Invalid WebAuthn credential")
        document = _strict_json_object(value.encode())
    else:
        if not isinstance(value, dict):
            raise WebAuthnError("Invalid WebAuthn credential")
        # Round-trip through the strict parser to reject values outside the JSON model,
        # excessive nesting, NaN and duplicate-like non-string keys.
        try:
            encoded = json.dumps(value, allow_nan=False, separators=(",", ":")).encode()
        except (TypeError, ValueError) as error:
            raise WebAuthnError("Invalid WebAuthn credential") from error
        document = _strict_json_object(encoded)
    if set(document) - {
        "authenticatorAttachment",
        "clientExtensionResults",
        "id",
        "rawId",
        "response",
        "type",
    } or not {"clientExtensionResults", "id", "rawId", "response", "type"} <= set(document):
        raise WebAuthnError("Invalid WebAuthn credential shape")
    if document["type"] != "public-key" or document["clientExtensionResults"] != {}:
        raise WebAuthnError("Unsupported WebAuthn credential extensions")
    attachment = document.get("authenticatorAttachment")
    if attachment not in {None, "platform", "cross-platform"}:
        raise WebAuthnError("Invalid WebAuthn authenticator attachment")
    if not isinstance(document["response"], dict):
        raise WebAuthnError("Invalid WebAuthn credential response")
    credential_id = _base64url(document["id"], minimum=1, maximum=1023)
    raw_id = _base64url(document["rawId"], minimum=1, maximum=1023)
    if credential_id != raw_id:
        raise WebAuthnError("WebAuthn credential ID mismatch")
    document["id"] = _base64(credential_id)
    return document


def _verify_client_data(
    encoded: bytes,
    *,
    expected_type: str,
    challenge_hash: str,
    relying_party_id: str,
) -> None:
    document = _strict_json_object(encoded)
    required = {"challenge", "origin", "type"}
    if not required <= set(document):
        raise WebAuthnError("Incomplete WebAuthn client data")
    if document.get("type") != expected_type:
        raise WebAuthnError("WebAuthn ceremony type mismatch")
    challenge = document.get("challenge")
    challenge_bytes = _base64url(challenge, minimum=16, maximum=128)
    if not _constant_text(hashlib.sha256(challenge_bytes).hexdigest(), challenge_hash):
        raise WebAuthnError("WebAuthn challenge mismatch")
    if document.get("origin") not in _expected_origins(relying_party_id):
        raise WebAuthnError("WebAuthn origin mismatch")
    if document.get("crossOrigin", False) is not False or "topOrigin" in document:
        raise WebAuthnError("Cross-origin WebAuthn is not enabled")


def _registration_authenticator_data(
    value: bytes, *, relying_party_id: str, require_user_verification: bool
) -> dict[str, Any]:
    if not 58 <= len(value) <= _MAX_CBOR:
        raise WebAuthnError("Invalid WebAuthn authenticator data")
    flags, sign_count = _authenticator_data_prefix(
        value,
        relying_party_id=relying_party_id,
        require_user_verification=require_user_verification,
    )
    if not flags & 0x40 or flags & 0x80:
        raise WebAuthnError("Invalid WebAuthn attested credential flags")
    credential_length = struct.unpack(">H", value[53:55])[0]
    if not 1 <= credential_length <= 1023 or 55 + credential_length >= len(value):
        raise WebAuthnError("Invalid WebAuthn credential ID")
    credential_id = value[55 : 55 + credential_length]
    cose, consumed = _decode_cbor(value, 55 + credential_length)
    if consumed != len(value) or not isinstance(cose, dict):
        raise WebAuthnError("Invalid WebAuthn credential public key")
    public_key, algorithm = _public_key_from_cose(cose)
    return {
        "algorithm": algorithm,
        "credential_id": credential_id,
        "public_key_pem": public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        "sign_count": sign_count,
    }


def _authentication_authenticator_data(
    value: bytes, *, relying_party_id: str, require_user_verification: bool
) -> int:
    if len(value) != 37:
        raise WebAuthnError("Invalid WebAuthn assertion authenticator data")
    flags, sign_count = _authenticator_data_prefix(
        value,
        relying_party_id=relying_party_id,
        require_user_verification=require_user_verification,
    )
    if flags & (0x40 | 0x80):
        raise WebAuthnError("Unsupported WebAuthn assertion flags")
    return sign_count


def _authenticator_data_prefix(
    value: bytes, *, relying_party_id: str, require_user_verification: bool
) -> tuple[int, int]:
    if len(value) < 37 or value[:32] != hashlib.sha256(relying_party_id.encode()).digest():
        raise WebAuthnError("WebAuthn relying party mismatch")
    flags = value[32]
    if flags & 0x22:
        raise WebAuthnError("Unsupported WebAuthn authenticator flags")
    if not flags & 0x01 or (require_user_verification and not flags & 0x04):
        raise WebAuthnError("WebAuthn user presence or verification is missing")
    if flags & 0x10 and not flags & 0x08:
        raise WebAuthnError("Invalid WebAuthn backup flags")
    return flags, struct.unpack(">I", value[33:37])[0]


def _public_key_from_cose(value: dict[Any, Any]):
    if value.get(1) == 2 and value.get(3) == -7:
        if set(value) != {1, 3, -1, -2, -3} or value.get(-1) != 1:
            raise WebAuthnError("Invalid ES256 COSE key")
        x, y = value.get(-2), value.get(-3)
        if not isinstance(x, bytes) or len(x) != 32 or not isinstance(y, bytes) or len(y) != 32:
            raise WebAuthnError("Invalid ES256 COSE coordinates")
        try:
            return ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
            ).public_key(), -7
        except ValueError as error:
            raise WebAuthnError("Invalid ES256 COSE point") from error
    if value.get(1) == 3 and value.get(3) == -257:
        if set(value) != {1, 3, -1, -2}:
            raise WebAuthnError("Invalid RS256 COSE key")
        modulus, exponent = value.get(-1), value.get(-2)
        if (
            not isinstance(modulus, bytes)
            or not 256 <= len(modulus) <= 512
            or modulus[0] == 0
            or not isinstance(exponent, bytes)
            or not 1 <= len(exponent) <= 4
            or exponent[0] == 0
        ):
            raise WebAuthnError("Invalid RS256 COSE parameters")
        n, e = int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")
        if n.bit_length() < 2048 or not 3 <= e <= 0xFFFFFFFF or e % 2 == 0:
            raise WebAuthnError("Unsafe RS256 COSE key")
        try:
            return rsa.RSAPublicNumbers(e, n).public_key(), -257
        except ValueError as error:
            raise WebAuthnError("Invalid RS256 COSE key") from error
    raise WebAuthnError("Unsupported WebAuthn COSE algorithm")


def _decode_cbor(value: bytes, offset: int = 0, depth: int = 0):
    if not isinstance(value, bytes) or len(value) > _MAX_CBOR or depth > 8 or offset >= len(value):
        raise WebAuthnError("Invalid CBOR data")
    initial = value[offset]
    offset += 1
    major, additional = initial >> 5, initial & 31
    number, offset = _cbor_number(value, offset, additional)
    if major == 0:
        return number, offset
    if major == 1:
        return -1 - number, offset
    if major in {2, 3}:
        end = offset + number
        if end > len(value):
            raise WebAuthnError("Truncated CBOR data")
        raw = value[offset:end]
        if major == 2:
            return raw, end
        try:
            return raw.decode("utf-8"), end
        except UnicodeDecodeError as error:
            raise WebAuthnError("Invalid CBOR text") from error
    if major == 4:
        if number > 64:
            raise WebAuthnError("CBOR array exceeds limit")
        result = []
        for _ in range(number):
            item, offset = _decode_cbor(value, offset, depth + 1)
            result.append(item)
        return result, offset
    if major == 5:
        if number > 64:
            raise WebAuthnError("CBOR map exceeds limit")
        result = {}
        previous_key_encoding = None
        for _ in range(number):
            key_start = offset
            key, offset = _decode_cbor(value, offset, depth + 1)
            key_encoding = value[key_start:offset]
            ordering = (len(key_encoding), key_encoding)
            if previous_key_encoding is not None and ordering <= previous_key_encoding:
                raise WebAuthnError("Non-canonical or duplicate CBOR map key")
            previous_key_encoding = ordering
            if not isinstance(key, (int, str)) or key in result:
                raise WebAuthnError("Invalid CBOR map key")
            item, offset = _decode_cbor(value, offset, depth + 1)
            result[key] = item
        return result, offset
    raise WebAuthnError("Unsupported CBOR data type")


def _cbor_number(value: bytes, offset: int, additional: int) -> tuple[int, int]:
    if additional < 24:
        return additional, offset
    sizes = {24: (1, 24), 25: (2, 256), 26: (4, 65536), 27: (8, 2**32)}
    if additional not in sizes:
        raise WebAuthnError("Indefinite CBOR is unsupported")
    size, minimum = sizes[additional]
    if offset + size > len(value):
        raise WebAuthnError("Truncated CBOR number")
    number = int.from_bytes(value[offset : offset + size], "big")
    if number < minimum:
        raise WebAuthnError("Non-canonical CBOR number")
    return number, offset + size


def _strict_json_object(value: bytes) -> dict[str, Any]:
    if not isinstance(value, bytes) or not 1 <= len(value) <= _MAX_CREDENTIAL_JSON:
        raise WebAuthnError("Invalid WebAuthn JSON")

    def pairs(items):
        result = {}
        for key, item in items:
            if not isinstance(key, str) or key in result:
                raise WebAuthnError("Duplicate WebAuthn JSON member")
            result[key] = item
        return result

    try:
        result = json.loads(
            value,
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                WebAuthnError("Invalid WebAuthn JSON number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise WebAuthnError("Invalid WebAuthn JSON") from error
    if not isinstance(result, dict):
        raise WebAuthnError("WebAuthn JSON must be an object")

    def check(item: Any, depth: int) -> None:
        if depth > 8:
            raise WebAuthnError("WebAuthn JSON nesting exceeds limit")
        if isinstance(item, dict):
            if len(item) > 64:
                raise WebAuthnError("WebAuthn JSON object exceeds limit")
            for key, child in item.items():
                if len(key) > 256:
                    raise WebAuthnError("WebAuthn JSON key exceeds limit")
                check(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 64:
                raise WebAuthnError("WebAuthn JSON array exceeds limit")
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, str) and len(item) > _MAX_CREDENTIAL_JSON:
            raise WebAuthnError("WebAuthn JSON string exceeds limit")
        elif not isinstance(item, (str, int, float, bool, type(None))):
            raise WebAuthnError("Invalid WebAuthn JSON value")

    check(result, 0)
    return result


def _base64url(value: Any, *, minimum: int = 0, maximum: int) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum * 2
        or _BASE64URL.fullmatch(value) is None
    ):
        raise WebAuthnError("Invalid WebAuthn base64url value")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (TypeError, ValueError) as error:
        raise WebAuthnError("Invalid WebAuthn base64url value") from error
    if not minimum <= len(decoded) <= maximum or _base64(decoded) != value:
        raise WebAuthnError("Non-canonical WebAuthn base64url value")
    return decoded


def _base64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _expected_origins(relying_party_id: str) -> set[str]:
    result = {
        (
            f"http://{relying_party_id}"
            if relying_party_id in {"localhost", "127.0.0.1", "::1"}
            else f"https://{relying_party_id}"
        )
    }
    # LocalStack's edge URL can carry an explicit development port. It is
    # accepted only when its host is exactly the configured RP ID; no suffix,
    # wildcard, alternate scheme downgrade, or arbitrary port is accepted.
    try:
        external = urlsplit(config.external_service_url())
        if external.hostname == relying_party_id and external.port is not None:
            host = external.hostname
            if ":" in host:
                host = f"[{host}]"
            result.add(f"https://{host}:{external.port}")
            if relying_party_id in {"localhost", "127.0.0.1", "::1"}:
                result.add(f"http://{host}:{external.port}")
    except (TypeError, ValueError):
        pass
    return result


def _constant_text(first: str, second: str) -> bool:
    import hmac

    return hmac.compare_digest(first.encode(), second.encode())
