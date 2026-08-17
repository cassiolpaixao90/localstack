from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import hmac
import re
from collections.abc import Callable

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

_MAX_ENCODED_HASH_BYTES = 4096
_MAX_PASSWORD_BYTES = 131_072
_MAX_COMPONENT_BYTES = 1024
_BCRYPT = re.compile(r"^\$2[abxy]\$(?P<cost>[0-9]{2})\$(?P<body>[./A-Za-z0-9]{53})$")
_SCRYPT = re.compile(
    r"^(?P<n>[0-9]+)\$(?P<r>[0-9]+)\$(?P<p>[0-9]+)\$"
    r"(?P<salt>[0-9a-fA-F]+)\$(?P<digest>[0-9a-fA-F]+)$"
)
_ARGON2ID = re.compile(
    r"^\$argon2id\$v=(?P<version>[0-9]+)\$m=(?P<memory>[0-9]+),"
    r"t=(?P<iterations>[0-9]+),p=(?P<parallelism>[0-9]+)\$"
    r"(?P<salt>[A-Za-z0-9+/]+={0,2})\$(?P<digest>[A-Za-z0-9+/]+={0,2})$"
)
_PBKDF2 = re.compile(
    r"^\$pbkdf2-sha256\$(?P<iterations>[0-9]+)\$"
    r"(?P<salt>[A-Za-z0-9+/]+={0,2})\$(?P<digest>[A-Za-z0-9+/]+={0,2})$"
)
_ALGORITHMS = frozenset({"BCRYPT", "SCRYPT", "ARGON2ID", "PBKDF2_SHA256"})


class ImportedPasswordHashError(ValueError):
    """The imported credential isn't a supported, bounded self-describing hash."""


@dataclasses.dataclass(frozen=True)
class ImportedPasswordHash:
    algorithm: str
    encoded: str
    parameters: dict[str, int | bytes]


def normalize_imported_password_hash(algorithm: object, encoded: object) -> ImportedPasswordHash:
    if not isinstance(algorithm, str) or algorithm not in _ALGORITHMS:
        raise ImportedPasswordHashError("Unsupported password hashing algorithm")
    if (
        not isinstance(encoded, str)
        or not encoded
        or len(encoded.encode()) > _MAX_ENCODED_HASH_BYTES
    ):
        raise ImportedPasswordHashError("Invalid imported password hash")
    parser = {
        "BCRYPT": _parse_bcrypt,
        "SCRYPT": _parse_scrypt,
        "ARGON2ID": _parse_argon2id,
        "PBKDF2_SHA256": _parse_pbkdf2,
    }[algorithm]
    return ImportedPasswordHash(algorithm=algorithm, encoded=encoded, parameters=parser(encoded))


def verify_imported_password(
    password: object,
    algorithm: object,
    encoded: object,
    *,
    bcrypt_verifier: Callable[[bytes, str], bool] | None = None,
) -> bool:
    """Verify a first-login imported credential, returning false on every backend failure."""
    try:
        if not isinstance(password, str):
            return False
        password_bytes = password.encode()
        if len(password_bytes) > _MAX_PASSWORD_BYTES:
            return False
        imported = normalize_imported_password_hash(algorithm, encoded)
        parameters = imported.parameters
        if imported.algorithm == "BCRYPT":
            return bool(bcrypt_verifier and bcrypt_verifier(password_bytes, imported.encoded))
        if imported.algorithm == "SCRYPT":
            expected = parameters["digest"]
            actual = hashlib.scrypt(
                password_bytes,
                salt=parameters["salt"],
                n=parameters["n"],
                r=parameters["r"],
                p=parameters["p"],
                dklen=len(expected),
                maxmem=256 * 1024 * 1024,
            )
        elif imported.algorithm == "ARGON2ID":
            expected = parameters["digest"]
            actual = Argon2id(
                salt=parameters["salt"],
                length=len(expected),
                iterations=parameters["iterations"],
                lanes=parameters["parallelism"],
                memory_cost=parameters["memory"],
            ).derive(password_bytes)
        else:
            expected = parameters["digest"]
            actual = hashlib.pbkdf2_hmac(
                "sha256",
                password_bytes,
                parameters["salt"],
                parameters["iterations"],
                dklen=len(expected),
            )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _parse_bcrypt(encoded: str) -> dict[str, int | bytes]:
    match = _BCRYPT.fullmatch(encoded)
    if match is None:
        raise ImportedPasswordHashError("Malformed BCRYPT hash")
    cost = int(match.group("cost"))
    if not 4 <= cost <= 10:
        raise ImportedPasswordHashError("BCRYPT cost is outside supported bounds")
    return {"cost": cost}


def _parse_scrypt(encoded: str) -> dict[str, int | bytes]:
    match = _SCRYPT.fullmatch(encoded)
    if match is None:
        raise ImportedPasswordHashError("Malformed SCRYPT hash")
    n, block_size, parallelism = (int(match.group(name)) for name in ("n", "r", "p"))
    if n < 2 or n > 65_536 or n & (n - 1):
        raise ImportedPasswordHashError("SCRYPT N is outside supported bounds")
    if not 1 <= block_size <= 8 or parallelism != 1:
        raise ImportedPasswordHashError("SCRYPT parameters are outside supported bounds")
    salt = _hex_component(match.group("salt"))
    digest = _hex_component(match.group("digest"))
    return {"n": n, "r": block_size, "p": parallelism, "salt": salt, "digest": digest}


def _parse_argon2id(encoded: str) -> dict[str, int | bytes]:
    match = _ARGON2ID.fullmatch(encoded)
    if match is None:
        raise ImportedPasswordHashError("Malformed ARGON2ID hash")
    version = int(match.group("version"))
    memory = int(match.group("memory"))
    iterations = int(match.group("iterations"))
    parallelism = int(match.group("parallelism"))
    if version != 19:
        raise ImportedPasswordHashError("Unsupported ARGON2ID version")
    if not 8 <= memory <= 19_456 or not 1 <= iterations <= 2 or parallelism != 1:
        raise ImportedPasswordHashError("ARGON2ID parameters are outside supported bounds")
    return {
        "memory": memory,
        "iterations": iterations,
        "parallelism": parallelism,
        "salt": _base64_component(match.group("salt")),
        "digest": _base64_component(match.group("digest")),
    }


def _parse_pbkdf2(encoded: str) -> dict[str, int | bytes]:
    match = _PBKDF2.fullmatch(encoded)
    if match is None:
        raise ImportedPasswordHashError("Malformed PBKDF2_SHA256 hash")
    iterations = int(match.group("iterations"))
    if not 1 <= iterations <= 600_000:
        raise ImportedPasswordHashError("PBKDF2_SHA256 iterations are outside supported bounds")
    return {
        "iterations": iterations,
        "salt": _base64_component(match.group("salt")),
        "digest": _base64_component(match.group("digest")),
    }


def _hex_component(value: str) -> bytes:
    if len(value) % 2:
        raise ImportedPasswordHashError("Malformed hexadecimal hash component")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ImportedPasswordHashError("Malformed hexadecimal hash component") from error
    return _bounded_component(decoded)


def _base64_component(value: str) -> bytes:
    if "=" in value[:-2]:
        raise ImportedPasswordHashError("Malformed base64 hash component")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except (ValueError, binascii.Error) as error:
        raise ImportedPasswordHashError("Malformed base64 hash component") from error
    return _bounded_component(decoded)


def _bounded_component(value: bytes) -> bytes:
    if not 1 <= len(value) <= _MAX_COMPONENT_BYTES:
        raise ImportedPasswordHashError("Hash component is outside supported bounds")
    return value
