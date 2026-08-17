import pytest

from localstack.services.cognito_idp import bcrypt_verify
from localstack.services.cognito_idp.bcrypt_verify import BcryptWorkBudget, verify_bcrypt


@pytest.mark.parametrize("version", ["2a", "2b", "2y"])
def test_verifies_modular_bcrypt_versions_against_independent_vector(version):
    encoded = f"${version}$04$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW"

    assert verify_bcrypt("password", encoded)
    assert not verify_bcrypt("not-password", encoded)


@pytest.mark.parametrize(
    ("password", "encoded"),
    [
        (
            "pässwörd",
            "$2b$04$abcdefghijklmnopqrstuuyx2n0Zzopyr9QuYTMCfOJJOj526QVoC",
        ),
        (
            b"\x80\x81\xfe\xffpass",
            "$2a$04$abcdefghijklmnopqrstuuMvAge.iiUYfoD9cQ1skSAWWEYQEryl6",
        ),
        (
            b"ab\x00cd",
            "$2b$04$......................vxymo.bL21vnFbVevfpQ6Of0ISKU.Zy",
        ),
    ],
)
def test_verifies_utf8_high_bit_and_embedded_nul_passwords(password, encoded):
    assert verify_bcrypt(password, encoded)


def test_uses_the_standard_72_byte_password_boundary():
    encoded = "$2b$04$......................UaUp2CqHXn14N7RprrzoDsNv91ahi36"

    assert verify_bcrypt(b"a" * 72, encoded)
    assert verify_bcrypt(b"a" * 73, encoded)
    assert not verify_bcrypt(b"a" * 71, encoded)


def test_verifies_the_maximum_aws_import_cost_vector():
    encoded = "$2b$10$CtA.Rcu/szzn9U00wpUjOuvX2WwIsmGJq7qh/NNv7sYonMQD2H9dS"

    assert verify_bcrypt("password", encoded)


@pytest.mark.parametrize(
    "encoded",
    [
        "$2x$04$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW",
        "$2c$04$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW",
        "$2b$03$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW",
        "$2b$11$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW",
        "$2b$4$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW",
        "$2b$04$DCq7YPn5Rq63x1Lad4cll!V212arh7HmBEQj/tjT9AzbAGCgFF0eW",
        "$2b$04$DCq7YPn5Rq63x1Lad4cln.V212arh7HmBEQj/tjT9AzbAGCgFF0eW",
        "$2b$04$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0e",
    ],
)
def test_rejects_unsupported_noncanonical_and_out_of_budget_hashes(encoded):
    assert not verify_bcrypt("password", encoded)


@pytest.mark.parametrize(
    ("password", "encoded"),
    [
        (object(), "$2b$04$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW"),
        ("password", object()),
        ("password", "$2b$04$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0éW"),
        (b"a" * 131_073, "$2b$04$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW"),
    ],
)
def test_fails_closed_for_invalid_types_encodings_and_excessive_input(password, encoded):
    assert not verify_bcrypt(password, encoded)


def test_custom_work_budget_rejects_before_expensive_key_setup(monkeypatch):
    encoded = "$2b$05$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW"
    called = False

    def unexpected_raw(*_):
        nonlocal called
        called = True
        raise AssertionError("key setup must not run")

    monkeypatch.setattr(bcrypt_verify, "_bcrypt_raw", unexpected_raw)

    assert not verify_bcrypt("password", encoded, budget=BcryptWorkBudget(maximum_cost=4))
    assert not called


def test_cost_controls_the_exact_bounded_number_of_key_expansions(monkeypatch):
    encoded = "$2b$04$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW"
    original = bcrypt_verify._expand_zero
    calls = 0

    def counted_expand_zero(p, s, key):
        nonlocal calls
        calls += 1
        return original(p, s, key)

    monkeypatch.setattr(bcrypt_verify, "_expand_zero", counted_expand_zero)

    assert verify_bcrypt("password", encoded)
    assert calls == 2 * (1 << 4)


def test_valid_hashes_use_constant_time_digest_comparison(monkeypatch):
    encoded = "$2b$04$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW"
    original = bcrypt_verify.hmac.compare_digest
    comparisons = []

    def recording_compare(left, right):
        comparisons.append((left, right))
        return original(left, right)

    monkeypatch.setattr(bcrypt_verify.hmac, "compare_digest", recording_compare)

    assert verify_bcrypt("password", encoded)
    assert not verify_bcrypt("wrong", encoded)
    assert len(comparisons) == 2
    assert all(len(left) == len(right) == 31 for left, right in comparisons)


def test_internal_errors_fail_closed(monkeypatch):
    encoded = "$2b$04$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW"

    monkeypatch.setattr(
        bcrypt_verify,
        "_bcrypt_raw",
        lambda *_: (_ for _ in ()).throw(RuntimeError("internal detail")),
    )

    assert not verify_bcrypt("password", encoded)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"minimum_cost": 3},
        {"minimum_cost": 11, "maximum_cost": 10},
        {"maximum_cost": 32},
        {"minimum_cost": True},
        {"maximum_cost": False},
        {"maximum_password_bytes": 71},
    ],
)
def test_work_budget_configuration_is_validated(kwargs):
    with pytest.raises(ValueError, match="invalid bcrypt work budget"):
        BcryptWorkBudget(**kwargs)
