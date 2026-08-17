import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from localstack.services.cognito_idp.imported_password_hashes import (
    ImportedPasswordHashError,
    normalize_imported_password_hash,
    verify_imported_password,
)


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode().rstrip("=")


def test_accepts_all_official_self_describing_formats():
    values = {
        "BCRYPT": "$2b$10$CtA.Rcu/szzn9U00wpUjOuN3vrgJRZycv4aOzcP3GzqzO8UDPEFq6",
        "SCRYPT": "65536$8$1$304dbaef7c5e828dc19c98f0600d18fe$"
        "4f69c498c12cd102d057356facf8d77e8d42407090491ea32c5b038f5a18c099",
        "ARGON2ID": "$argon2id$v=19$m=19456,t=2,p=1$ko/G5o1ms+ML08P95sQ8DA$"
        "AkVbvWSOqz7Hs3qthhWKxicOWnGLN+MBmpwc3emi5VA",
        "PBKDF2_SHA256": "$pbkdf2-sha256$600000$1XZlmwLQ2hhM3JYuCPiArQ$"
        "Pfheg9Zi/v5lXU4yyLA0WFUYEd/rlaVbzrM9oMD6IrA",
    }

    for algorithm, encoded in values.items():
        normalized = normalize_imported_password_hash(algorithm, encoded)
        assert normalized.algorithm == algorithm
        assert normalized.encoded == encoded


@pytest.mark.parametrize(
    ("algorithm", "encoded"),
    [
        ("BCRYPT", "$2b$11$CtA.Rcu/szzn9U00wpUjOuN3vrgJRZycv4aOzcP3GzqzO8UDPEFq6"),
        ("SCRYPT", "131072$8$1$00$00"),
        ("SCRYPT", "65536$9$1$00$00"),
        ("SCRYPT", "65536$8$2$00$00"),
        ("ARGON2ID", "$argon2id$v=19$m=19457,t=2,p=1$YWJjZA$YWJjZA"),
        ("ARGON2ID", "$argon2id$v=19$m=19456,t=3,p=1$YWJjZA$YWJjZA"),
        ("PBKDF2_SHA256", "$pbkdf2-sha256$600001$YWJjZA$YWJjZA"),
    ],
)
def test_rejects_parameters_above_aws_bounds(algorithm, encoded):
    with pytest.raises(ImportedPasswordHashError):
        normalize_imported_password_hash(algorithm, encoded)


@pytest.mark.parametrize(
    ("algorithm", "encoded"),
    [
        ("UNKNOWN", "anything"),
        ("BCRYPT", "$2b$10$not-base64"),
        ("SCRYPT", "3$8$1$00$00"),
        ("SCRYPT", "65536$8$1$odd$00"),
        ("ARGON2ID", "$argon2i$v=19$m=16,t=2,p=1$YWJjZA$YWJjZA"),
        ("ARGON2ID", "$argon2id$v=16$m=16,t=2,p=1$YWJjZA$YWJjZA"),
        ("PBKDF2_SHA256", "$pbkdf2-sha256$1$***$YWJjZA"),
    ],
)
def test_rejects_malformed_or_mismatched_hashes(algorithm, encoded):
    with pytest.raises(ImportedPasswordHashError):
        normalize_imported_password_hash(algorithm, encoded)


def test_verifies_pbkdf2_and_scrypt_vectors_and_rejects_wrong_password():
    password = "correct horse battery staple"
    salt = b"independent-client-salt"
    pbkdf_digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 12_345, dklen=32)
    pbkdf = f"$pbkdf2-sha256$12345${_b64(salt)}${_b64(pbkdf_digest)}"
    scrypt_digest = hashlib.scrypt(password.encode(), salt=salt, n=1024, r=8, p=1, dklen=32)
    scrypt = f"1024$8$1${salt.hex()}${scrypt_digest.hex()}"

    assert verify_imported_password(password, "PBKDF2_SHA256", pbkdf)
    assert not verify_imported_password("wrong", "PBKDF2_SHA256", pbkdf)
    assert verify_imported_password(password, "SCRYPT", scrypt)
    assert not verify_imported_password("wrong", "SCRYPT", scrypt)


def test_verifies_argon2id_vector_with_existing_runtime_crypto():
    password = "argon-password"
    salt = b"sixteen-byte-slt"
    digest = Argon2id(salt=salt, length=32, iterations=2, lanes=1, memory_cost=1024).derive(
        password.encode()
    )
    encoded = f"$argon2id$v=19$m=1024,t=2,p=1${_b64(salt)}${_b64(digest)}"

    assert verify_imported_password(password, "ARGON2ID", encoded)
    assert not verify_imported_password("wrong", "ARGON2ID", encoded)


def test_bcrypt_is_fail_closed_without_backend_and_backend_exceptions_are_hidden():
    encoded = "$2b$10$CtA.Rcu/szzn9U00wpUjOuN3vrgJRZycv4aOzcP3GzqzO8UDPEFq6"
    calls = []

    assert not verify_imported_password("password", "BCRYPT", encoded)
    assert verify_imported_password(
        "password",
        "BCRYPT",
        encoded,
        bcrypt_verifier=lambda password, value: calls.append((password, value)) or True,
    )
    assert calls == [(b"password", encoded)]
    assert not verify_imported_password(
        "password",
        "BCRYPT",
        encoded,
        bcrypt_verifier=lambda *_: (_ for _ in ()).throw(RuntimeError("backend detail")),
    )


def test_verification_fails_closed_for_invalid_input_and_excessive_password_size():
    assert not verify_imported_password("password", "PBKDF2_SHA256", "malformed")
    encoded = "$pbkdf2-sha256$1$YWJjZA$YWJjZA"
    assert not verify_imported_password("x" * 131_073, "PBKDF2_SHA256", encoded)
