import base64
import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from localstack.services.cognito_idp import federation
from localstack.services.cognito_idp.federation import OidcFederationError
from localstack.services.cognito_idp.tokens import generate_signing_key


def test_private_egress_requires_exact_allowlist_and_rejects_redirect_json_ambiguity(httpserver):
    authority = httpserver.url_for("").split("//", 1)[1].rstrip("/")
    httpserver.expect_request("/ok").respond_with_json({"ok": True})
    with pytest.raises(OidcFederationError):
        federation.secure_json_request(httpserver.url_for("/ok"), allowlist=[])
    assert federation.secure_json_request(httpserver.url_for("/ok"), allowlist=[authority]) == {
        "ok": True
    }

    httpserver.expect_request("/duplicate").respond_with_data(
        '{"issuer":"one","issuer":"two"}', content_type="application/json"
    )
    with pytest.raises(OidcFederationError, match="Duplicate"):
        federation.secure_json_request(httpserver.url_for("/duplicate"), allowlist=[authority])
    httpserver.expect_request("/nan").respond_with_data(
        '{"value":NaN}', content_type="application/json"
    )
    with pytest.raises(OidcFederationError, match="Non-finite"):
        federation.secure_json_request(httpserver.url_for("/nan"), allowlist=[authority])
    httpserver.expect_request("/redirect").respond_with_data(
        "", status=302, headers={"Location": "http://169.254.169.254/latest/meta-data"}
    )
    with pytest.raises(OidcFederationError, match="redirects"):
        federation.secure_json_request(httpserver.url_for("/redirect"), allowlist=[authority])


def test_dns_rebinding_and_metadata_are_denied_before_connect(monkeypatch):
    answers = iter([{"198.51.100.10"}, {"127.0.0.1"}])
    monkeypatch.setattr(federation, "_resolve_addresses", lambda *_: next(answers))
    with pytest.raises(OidcFederationError, match="DNS resolution changed"):
        federation.secure_json_request("https://idp.example.test/document", allowlist=[])
    with pytest.raises(OidcFederationError, match="Unsafe"):
        federation.secure_json_request(
            "http://169.254.169.254/latest/meta-data", allowlist=["169.254.169.254"]
        )


def test_strict_json_depth_bound():
    value = "0"
    for _ in range(18):
        value = f'{{"nested":{value}}}'
    with pytest.raises(OidcFederationError, match="nesting"):
        federation._strict_json_object(value.encode())


def _encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _signed_token(private_key_pem, header: bytes, payload: bytes) -> str:
    signing_input = f"{_encoded(header)}.{_encoded(payload)}".encode()
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode()}.{_encoded(signature)}"


def _provider_and_configuration():
    key_id, private_key, jwk = generate_signing_key()
    provider = SimpleNamespace(
        provider_details={"client_id": "client"},
        jwks_document={"keys": [jwk]},
        jwks_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    return key_id, private_key, provider, {"issuer": "https://issuer.example.test"}


def _claims(nonce, **changes):
    now = int(time.time())
    result = {
        "aud": "client",
        "exp": now + 300,
        "iat": now,
        "iss": "https://issuer.example.test",
        "nonce": nonce,
        "sub": "subject",
    }
    result.update(changes)
    return result


def _verify(token, provider, configuration, nonce):
    return federation.verify_id_token(
        token,
        provider=provider,
        configuration=configuration,
        nonce_hash=hashlib.sha256(nonce.encode()).hexdigest(),
        access_token="access",
    )


def test_id_token_parser_rejects_duplicate_claims_multiaudience_and_noncanonical_base64():
    key_id, private_key, provider, configuration = _provider_and_configuration()
    nonce = "nonce"
    header = json.dumps({"alg": "RS256", "kid": key_id, "typ": "JWT"}).encode()
    duplicate = (
        f'{{"aud":"client","exp":{int(time.time()) + 300},"iat":{int(time.time())},'
        f'"iss":"https://issuer.example.test","nonce":"{nonce}",'
        f'"nonce":"replacement","sub":"subject"}}'
    ).encode()
    with pytest.raises(OidcFederationError, match="Duplicate"):
        _verify(_signed_token(private_key, header, duplicate), provider, configuration, nonce)

    multi_audience = json.dumps(_claims(nonce, aud=["client", "other"])).encode()
    with pytest.raises(OidcFederationError, match="claims"):
        _verify(_signed_token(private_key, header, multi_audience), provider, configuration, nonce)
    valid_multi = json.dumps(_claims(nonce, aud=["client", "other"], azp="client")).encode()
    token = _signed_token(private_key, header, valid_multi)
    assert _verify(token, provider, configuration, nonce)["sub"] == "subject"

    parts = token.split(".")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(parts[2][-1])
    parts[2] = f"{parts[2][:-1]}{alphabet[(last // 16) * 16 + ((last + 1) % 16)]}"
    with pytest.raises(OidcFederationError, match="Non-canonical"):
        _verify(".".join(parts), provider, configuration, nonce)


@pytest.mark.parametrize(
    "changes",
    [
        {"iat": True},
        {"exp": True},
        {"iat": int(time.time()) - 25 * 60 * 60},
        {"exp": int(time.time()) + 25 * 60 * 60},
        {"nbf": int(time.time()) + 300},
    ],
)
def test_id_token_temporal_claims_are_bounded(changes):
    key_id, private_key, provider, configuration = _provider_and_configuration()
    nonce = "nonce"
    header = json.dumps({"alg": "RS256", "kid": key_id, "typ": "JWT"}).encode()
    payload = json.dumps(_claims(nonce, **changes)).encode()
    with pytest.raises(OidcFederationError, match="claims"):
        _verify(_signed_token(private_key, header, payload), provider, configuration, nonce)
