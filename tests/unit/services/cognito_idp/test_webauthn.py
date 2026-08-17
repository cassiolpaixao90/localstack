import base64
import hashlib
import json
import pickle
import struct
import threading
import uuid

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider

RP_ID = "auth.example.test"
ORIGIN = f"https://{RP_ID}"
USERNAME = "alice"
PASSWORD = "PermanentPass9!"


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    yield value
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(value.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(value.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _cbor(value) -> bytes:
    def header(major, number):
        if number < 24:
            return bytes([(major << 5) | number])
        if number < 256:
            return bytes([(major << 5) | 24, number])
        if number < 65536:
            return bytes([(major << 5) | 25]) + struct.pack(">H", number)
        return bytes([(major << 5) | 26]) + struct.pack(">I", number)

    if isinstance(value, int):
        return header(0, value) if value >= 0 else header(1, -1 - value)
    if isinstance(value, bytes):
        return header(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return header(3, len(encoded)) + encoded
    if isinstance(value, list):
        return header(4, len(value)) + b"".join(_cbor(item) for item in value)
    if isinstance(value, dict):
        encoded = [(_cbor(key), _cbor(item)) for key, item in value.items()]
        encoded.sort(key=lambda item: (len(item[0]), item[0]))
        return header(5, len(encoded)) + b"".join(key + item for key, item in encoded)
    raise TypeError(value)


def _stack(provider, context):
    pool = provider.create_user_pool(
        context,
        {
            "Policies": {"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
            "PoolName": "passkey-users",
        },
    )["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "passkey-client",
            "ExplicitAuthFlows": [
                "ALLOW_USER_AUTH",
                "ALLOW_USER_PASSWORD_AUTH",
                "ALLOW_REFRESH_TOKEN_AUTH",
            ],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "TemporaryPassword": "TemporaryPass9!",
            "UserPoolId": pool["Id"],
            "Username": USERNAME,
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": PASSWORD,
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": USERNAME,
        },
    )
    provider.set_user_pool_mfa_config(
        context,
        {
            "MfaConfiguration": "OFF",
            "SoftwareTokenMfaConfiguration": {"Enabled": False},
            "UserPoolId": pool["Id"],
            "WebAuthnConfiguration": {
                "FactorConfiguration": "SINGLE_FACTOR",
                "RelyingPartyId": RP_ID,
                "UserVerification": "required",
            },
        },
    )
    tokens = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": PASSWORD, "USERNAME": USERNAME},
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]
    return pool, client, tokens


def _registration(
    provider,
    context,
    token,
    *,
    algorithm=-7,
    credential_id=None,
    origin=ORIGIN,
    relying_party_id=RP_ID,
    completion_token=None,
):
    started = provider.start_web_authn_registration(context, {"AccessToken": token})[
        "CredentialCreationOptions"
    ]
    credential, private_key = _registration_credential(
        started,
        algorithm=algorithm,
        credential_id=credential_id,
        origin=origin,
        relying_party_id=relying_party_id,
    )
    provider.complete_web_authn_registration(
        context,
        {"AccessToken": completion_token or token, "Credential": credential},
    )
    encoded_id = credential["id"]
    return base64.urlsafe_b64decode(encoded_id + "=" * (-len(encoded_id) % 4)), private_key


def _registration_credential(
    started,
    *,
    algorithm=-7,
    credential_id=None,
    origin=ORIGIN,
    relying_party_id=RP_ID,
):
    challenge = started["challenge"]
    credential_id = credential_id or hashlib.sha256(challenge.encode()).digest()
    client_data = json.dumps(
        {
            "challenge": challenge,
            "crossOrigin": False,
            "origin": origin,
            "type": "webauthn.create",
        },
        separators=(",", ":"),
    ).encode()
    if algorithm == -7:
        private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        cose_key = {
            1: 2,
            3: -7,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private_key.public_key().public_numbers()
        cose_key = {
            1: 3,
            3: -257,
            -1: numbers.n.to_bytes(256, "big"),
            -2: numbers.e.to_bytes(3, "big"),
        }
    auth_data = (
        hashlib.sha256(relying_party_id.encode()).digest()
        + b"\x45"
        + struct.pack(">I", 0)
        + b"\0" * 16
        + struct.pack(">H", len(credential_id))
        + credential_id
        + _cbor(cose_key)
    )
    credential = {
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "id": _b64(credential_id),
        "rawId": _b64(credential_id),
        "response": {
            "attestationObject": _b64(_cbor({"attStmt": {}, "authData": auth_data, "fmt": "none"})),
            "clientDataJSON": _b64(client_data),
            "transports": ["internal"],
        },
        "type": "public-key",
    }
    return credential, private_key


def _assertion(
    provider,
    context,
    client_id,
    credential_id,
    private_key,
    counter,
    *,
    username=USERNAME,
    origin=ORIGIN,
    relying_party_id=RP_ID,
):
    started = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_AUTH",
            "AuthParameters": {
                "PREFERRED_CHALLENGE": "WEB_AUTHN",
                "USERNAME": username,
            },
            "ClientId": client_id,
        },
    )
    return started, _assertion_credential(
        provider,
        context,
        client_id,
        started,
        credential_id,
        private_key,
        counter,
        username=username,
        origin=origin,
        relying_party_id=relying_party_id,
    )


def _assertion_credential(
    provider,
    context,
    client_id,
    started,
    credential_id,
    private_key,
    counter,
    *,
    username=USERNAME,
    origin=ORIGIN,
    relying_party_id=RP_ID,
):
    options = json.loads(started["ChallengeParameters"]["CREDENTIAL_REQUEST_OPTIONS"])
    client_data = json.dumps(
        {
            "challenge": options["challenge"],
            "crossOrigin": False,
            "origin": origin,
            "type": "webauthn.get",
        },
        separators=(",", ":"),
    ).encode()
    auth_data = (
        hashlib.sha256(relying_party_id.encode()).digest() + b"\x05" + struct.pack(">I", counter)
    )
    signed = auth_data + hashlib.sha256(client_data).digest()
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    else:
        signature = private_key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    stored_pool = next(
        pool
        for pool in provider.get_store(context).user_pools.values()
        if client_id in pool.clients
    )
    credential = {
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "id": _b64(credential_id),
        "rawId": _b64(credential_id),
        "response": {
            "authenticatorData": _b64(auth_data),
            "clientDataJSON": _b64(client_data),
            "signature": _b64(signature),
            "userHandle": _b64(stored_pool.users[username].sub.encode()),
        },
        "type": "public-key",
    }
    return credential


@pytest.mark.parametrize("algorithm", [-7, -257])
def test_real_registration_and_user_auth_signature_flow(provider, context, algorithm):
    pool, client, tokens = _stack(provider, context)
    credential_id, private_key = _registration(
        provider, context, tokens["AccessToken"], algorithm=algorithm
    )
    assert provider.get_user_auth_factors(context, {"AccessToken": tokens["AccessToken"]})[
        "ConfiguredUserAuthFactors"
    ] == ["PASSWORD", "WEB_AUTHN"]
    listed = provider.list_web_authn_credentials(
        context, {"AccessToken": tokens["AccessToken"], "MaxResults": 1}
    )
    assert listed["Credentials"] == [
        {
            "AuthenticatorAttachment": "platform",
            "AuthenticatorTransports": ["internal"],
            "CreatedAt": listed["Credentials"][0]["CreatedAt"],
            "CredentialId": _b64(credential_id),
            "FriendlyCredentialName": "Passkey",
            "RelyingPartyId": RP_ID,
        }
    ]
    started, credential = _assertion(
        provider, context, client["ClientId"], credential_id, private_key, 1
    )
    completed = provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "WEB_AUTHN",
            "ChallengeResponses": {
                "CREDENTIAL": json.dumps(credential, separators=(",", ":")),
                "USERNAME": USERNAME,
            },
            "ClientId": client["ClientId"],
            "Session": started["Session"],
        },
    )
    assert completed["AuthenticationResult"]["AccessToken"]
    with pytest.raises(CommonServiceException):
        provider.respond_to_auth_challenge(
            context,
            {
                "ChallengeName": "WEB_AUTHN",
                "ChallengeResponses": {
                    "CREDENTIAL": json.dumps(credential),
                    "USERNAME": USERNAME,
                },
                "ClientId": client["ClientId"],
                "Session": started["Session"],
            },
        )

    serialized = pickle.dumps(provider.get_store(context).user_pools[pool["Id"]])
    assert _b64(credential_id).encode() in serialized
    authenticator_private_key = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    assert authenticator_private_key not in serialized
    restored = pickle.loads(serialized)
    assert restored.users[USERNAME].web_authn_credentials[_b64(credential_id)].sign_count == 1


def test_registration_binding_origin_one_use_pagination_delete_and_counter_replay(
    provider, context
):
    pool, client, tokens = _stack(provider, context)
    started = provider.start_web_authn_registration(
        context, {"AccessToken": tokens["AccessToken"]}
    )["CredentialCreationOptions"]
    assert started["rp"] == {"id": RP_ID, "name": RP_ID}
    assert started["user"]["name"] == USERNAME
    assert started["pubKeyCredParams"] == [
        {"alg": -7, "type": "public-key"},
        {"alg": -257, "type": "public-key"},
    ]
    with cognito_idp_stores.lock:
        store = provider.get_store(context)
        assert started["challenge"] not in repr(store.web_authn_challenges)

    with pytest.raises(CommonServiceException) as wrong_origin:
        _registration(
            provider,
            context,
            tokens["AccessToken"],
            origin="https://evil.example.test",
        )
    assert wrong_origin.value.code == "WebAuthnOriginNotAllowedException"

    other_client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "other-passkey-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    other_token = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": PASSWORD, "USERNAME": USERNAME},
            "ClientId": other_client["ClientId"],
        },
    )["AuthenticationResult"]["AccessToken"]
    bound_options = provider.start_web_authn_registration(
        context, {"AccessToken": tokens["AccessToken"]}
    )["CredentialCreationOptions"]
    bound_credential, _ = _registration_credential(bound_options)
    with pytest.raises(CommonServiceException) as cross_client:
        provider.complete_web_authn_registration(
            context,
            {"AccessToken": other_token, "Credential": bound_credential},
        )
    assert cross_client.value.code == "WebAuthnClientMismatchException"
    assert (
        provider.complete_web_authn_registration(
            context,
            {"AccessToken": tokens["AccessToken"], "Credential": bound_credential},
        )
        == {}
    )

    first_id, first_key = _registration(provider, context, tokens["AccessToken"])
    second_id, _ = _registration(provider, context, tokens["AccessToken"])
    page = provider.list_web_authn_credentials(
        context, {"AccessToken": tokens["AccessToken"], "MaxResults": 1}
    )
    assert len(page["Credentials"]) == 1 and page["NextToken"]
    second_page = provider.list_web_authn_credentials(
        context,
        {
            "AccessToken": tokens["AccessToken"],
            "MaxResults": 1,
            "NextToken": page["NextToken"],
        },
    )
    assert len(second_page["Credentials"]) == 1
    with pytest.raises(CommonServiceException):
        provider.list_web_authn_credentials(
            context,
            {
                "AccessToken": tokens["AccessToken"],
                "MaxResults": 1,
                "NextToken": page["NextToken"] + "x",
            },
        )

    provider.admin_create_user(
        context,
        {
            "TemporaryPassword": "TemporaryPass9!",
            "UserPoolId": pool["Id"],
            "Username": "bob",
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": PASSWORD,
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": "bob",
        },
    )
    bob_token = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": PASSWORD, "USERNAME": "bob"},
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]["AccessToken"]
    with pytest.raises(CommonServiceException):
        provider.delete_web_authn_credential(
            context,
            {"AccessToken": bob_token, "CredentialId": _b64(first_id)},
        )

    started_auth, assertion = _assertion(
        provider, context, client["ClientId"], first_id, first_key, 1
    )
    competing_auth, competing_assertion = _assertion(
        provider, context, client["ClientId"], first_id, first_key, 1
    )
    requests = [
        {
            "ChallengeName": "WEB_AUTHN",
            "ChallengeResponses": {
                "CREDENTIAL": json.dumps(assertion),
                "USERNAME": USERNAME,
            },
            "ClientId": client["ClientId"],
            "Session": started_auth["Session"],
        },
        {
            "ChallengeName": "WEB_AUTHN",
            "ChallengeResponses": {
                "CREDENTIAL": json.dumps(competing_assertion),
                "USERNAME": USERNAME,
            },
            "ClientId": client["ClientId"],
            "Session": competing_auth["Session"],
        },
    ]
    outcomes = []

    def run(request):
        try:
            outcomes.append(("ok", provider.respond_to_auth_challenge(context, request)))
        except CommonServiceException as error:
            outcomes.append(("error", error.code))

    threads = [threading.Thread(target=run, args=(request,)) for request in requests]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(kind for kind, _ in outcomes) == ["error", "ok"]

    downgrade_started, downgrade_assertion = _assertion(
        provider, context, client["ClientId"], first_id, first_key, 0
    )
    with pytest.raises(CommonServiceException):
        provider.respond_to_auth_challenge(
            context,
            {
                "ChallengeName": "WEB_AUTHN",
                "ChallengeResponses": {
                    "CREDENTIAL": json.dumps(downgrade_assertion),
                    "USERNAME": USERNAME,
                },
                "ClientId": client["ClientId"],
                "Session": downgrade_started["Session"],
            },
        )
    assert (
        provider.get_store(context)
        .user_pools[pool["Id"]]
        .users[USERNAME]
        .web_authn_credentials[_b64(first_id)]
        .sign_count
        == 1
    )

    replay_started, replay_assertion = _assertion(
        provider, context, client["ClientId"], first_id, first_key, 1
    )
    with pytest.raises(CommonServiceException):
        provider.respond_to_auth_challenge(
            context,
            {
                "ChallengeName": "WEB_AUTHN",
                "ChallengeResponses": {
                    "CREDENTIAL": json.dumps(replay_assertion),
                    "USERNAME": USERNAME,
                },
                "ClientId": client["ClientId"],
                "Session": replay_started["Session"],
            },
        )

    aba_started, aba_assertion = _assertion(
        provider, context, client["ClientId"], first_id, first_key, 2
    )
    provider.delete_web_authn_credential(
        context,
        {"AccessToken": tokens["AccessToken"], "CredentialId": _b64(first_id)},
    )
    _registration(
        provider,
        context,
        tokens["AccessToken"],
        credential_id=first_id,
    )
    with pytest.raises(CommonServiceException):
        provider.respond_to_auth_challenge(
            context,
            {
                "ChallengeName": "WEB_AUTHN",
                "ChallengeResponses": {
                    "CREDENTIAL": json.dumps(aba_assertion),
                    "USERNAME": USERNAME,
                },
                "ClientId": client["ClientId"],
                "Session": aba_started["Session"],
            },
        )
    provider.delete_web_authn_credential(
        context,
        {"AccessToken": tokens["AccessToken"], "CredentialId": _b64(first_id)},
    )
    remaining = provider.list_web_authn_credentials(
        context, {"AccessToken": tokens["AccessToken"]}
    )["Credentials"]
    assert {item["CredentialId"] for item in remaining} == {
        bound_credential["id"],
        _b64(second_id),
    }


def test_user_existence_protection_and_live_challenge_quota(provider, context, monkeypatch):
    pool, _, tokens = _stack(provider, context)
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "pue-passkey-client",
            "ExplicitAuthFlows": ["ALLOW_USER_AUTH"],
            "PreventUserExistenceErrors": "ENABLED",
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    credential_id, private_key = _registration(provider, context, tokens["AccessToken"])
    for username in ("bob", "disabled"):
        provider.admin_create_user(
            context,
            {
                "TemporaryPassword": "TemporaryPass9!",
                "UserPoolId": pool["Id"],
                "Username": username,
            },
        )
        provider.admin_set_user_password(
            context,
            {
                "Password": PASSWORD,
                "Permanent": True,
                "UserPoolId": pool["Id"],
                "Username": username,
            },
        )
    provider.admin_disable_user(context, {"UserPoolId": pool["Id"], "Username": "disabled"})

    def start(username):
        return provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_AUTH",
                "AuthParameters": {
                    "PREFERRED_CHALLENGE": "WEB_AUTHN",
                    "USERNAME": username,
                },
                "ClientId": client["ClientId"],
            },
        )

    responses = {username: start(username) for username in (USERNAME, "ghost", "bob", "disabled")}
    normalized = []
    for response in responses.values():
        options = json.loads(response["ChallengeParameters"]["CREDENTIAL_REQUEST_OPTIONS"])
        assert options["allowCredentials"] == []
        options["challenge"] = "<challenge>"
        normalized.append(
            {
                **response,
                "ChallengeParameters": {
                    "CREDENTIAL_REQUEST_OPTIONS": json.dumps(options, sort_keys=True)
                },
                "Session": "<session>",
            }
        )
    assert normalized.count(normalized[0]) == len(normalized)
    with pytest.raises(CommonServiceException) as hidden:
        provider.respond_to_auth_challenge(
            context,
            {
                "ChallengeName": "WEB_AUTHN",
                "ChallengeResponses": {"CREDENTIAL": "{}", "USERNAME": "ghost"},
                "ClientId": client["ClientId"],
                "Session": responses["ghost"]["Session"],
            },
        )
    assert hidden.value.code == "NotAuthorizedException"

    with cognito_idp_stores.lock:
        provider.get_store(context).web_authn_challenges.clear()
    monkeypatch.setattr(provider_module, "_MAX_WEB_AUTHN_CHALLENGES_PER_USER", 2)
    victim = start(USERNAME)
    start(USERNAME)
    with pytest.raises(CommonServiceException) as flooded:
        start(USERNAME)
    assert flooded.value.code == "LimitExceededException"
    victim_credential = _assertion_credential(
        provider,
        context,
        client["ClientId"],
        victim,
        credential_id,
        private_key,
        1,
    )
    completed = provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "WEB_AUTHN",
            "ChallengeResponses": {
                "CREDENTIAL": json.dumps(victim_credential),
                "USERNAME": USERNAME,
            },
            "ClientId": client["ClientId"],
            "Session": victim["Session"],
        },
    )
    assert completed["AuthenticationResult"]["AccessToken"]


def test_sign_in_policy_uv_and_exact_local_edge_origin(provider, context, monkeypatch):
    before = set(provider.get_store(context).user_pools)
    with pytest.raises(CommonServiceException):
        provider.create_user_pool(
            context,
            {
                "Policies": {"SignInPolicy": {"AllowedFirstAuthFactors": ["WEB_AUTHN"]}},
                "PoolName": "passkey-only-is-invalid",
            },
        )
    assert set(provider.get_store(context).user_pools) == before

    pool = provider.create_user_pool(context, {"PoolName": "password-default"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "default-client",
            "ExplicitAuthFlows": ["ALLOW_USER_AUTH", "ALLOW_USER_PASSWORD_AUTH"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "TemporaryPassword": "TemporaryPass9!",
            "UserPoolId": pool["Id"],
            "Username": USERNAME,
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": PASSWORD,
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": USERNAME,
        },
    )
    with pytest.raises(CommonServiceException):
        provider.set_user_pool_mfa_config(
            context,
            {
                "MfaConfiguration": "OFF",
                "SoftwareTokenMfaConfiguration": {"Enabled": False},
                "UserPoolId": pool["Id"],
                "WebAuthnConfiguration": {
                    "FactorConfiguration": "MULTI_FACTOR_WITH_USER_VERIFICATION",
                    "RelyingPartyId": "localhost.localstack.cloud",
                    "UserVerification": "preferred",
                },
            },
        )
    provider.set_user_pool_mfa_config(
        context,
        {
            "MfaConfiguration": "OFF",
            "SoftwareTokenMfaConfiguration": {"Enabled": False},
            "UserPoolId": pool["Id"],
            "WebAuthnConfiguration": {
                "FactorConfiguration": "SINGLE_FACTOR",
                "RelyingPartyId": "localhost.localstack.cloud",
                "UserVerification": "required",
            },
        },
    )
    password_tokens = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": PASSWORD, "USERNAME": USERNAME},
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]
    with pytest.raises(CommonServiceException) as not_enabled:
        provider.start_web_authn_registration(
            context, {"AccessToken": password_tokens["AccessToken"]}
        )
    assert not_enabled.value.code == "WebAuthnNotEnabledException"

    provider.update_user_pool(
        context,
        {
            "Policies": {"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
            "UserPoolId": pool["Id"],
        },
    )
    monkeypatch.setattr(
        "localstack.services.cognito_idp.webauthn.config.external_service_url",
        lambda: "http://localhost.localstack.cloud:4566",
    )
    local_rp = "localhost.localstack.cloud"
    local_origin = "https://localhost.localstack.cloud:4566"
    credential_id, private_key = _registration(
        provider,
        context,
        password_tokens["AccessToken"],
        origin=local_origin,
        relying_party_id=local_rp,
    )
    started, assertion = _assertion(
        provider,
        context,
        client["ClientId"],
        credential_id,
        private_key,
        1,
        origin=local_origin,
        relying_party_id=local_rp,
    )
    assert provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "WEB_AUTHN",
            "ChallengeResponses": {
                "CREDENTIAL": json.dumps(assertion),
                "USERNAME": USERNAME,
            },
            "ClientId": client["ClientId"],
            "Session": started["Session"],
        },
    )["AuthenticationResult"]["AccessToken"]
