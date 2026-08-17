import base64
import hashlib
import hmac
import pickle
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp.device_srp import (
    DeviceSrpError,
    consume_device_srp_session,
    normalize_device_verifier,
    reserve_device_srp_session,
    start_device_srp,
    verify_device_password,
)
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider

# Independent client-side equations from the Cognito/Amplify device SRP contract.
N = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16,
)
G = 2
POOL_ID = "us-east-1_pool123"
CLIENT_ID = "client123"
USERNAME = "alice"
DEVICE_KEY = "us-east-1_2a859a59-722d-4db3-a77b-76cb3f65aa00"
DEVICE_GROUP_KEY = "device-group-key"
DEVICE_SECRET = "M7GfYk9PSYVn0OhX2NVq4THQCcbGi4osq9cH1MGEX7Q"
NOW = datetime(2026, 8, 10, 15, 4, 5, tzinfo=UTC)


def _pad(value):
    encoded = format(value, "x")
    if len(encoded) % 2:
        encoded = f"0{encoded}"
    if encoded[0] in "89abcdefABCDEF":
        encoded = f"00{encoded}"
    return encoded


def _hex_hash(value):
    return hashlib.sha256(bytes.fromhex(value)).hexdigest()


K = int(_hex_hash(f"{_pad(N)}{_pad(G)}"), 16)


def _hkdf(shared_secret, scrambling):
    pseudo_random_key = hmac.new(
        bytes.fromhex(_pad(scrambling)),
        bytes.fromhex(_pad(shared_secret)),
        hashlib.sha256,
    ).digest()
    return hmac.new(pseudo_random_key, b"Caldera Derived Key\x01", hashlib.sha256).digest()[:16]


def _device_verifier(salt_bytes, *, device_key=DEVICE_KEY, device_group_key=DEVICE_GROUP_KEY):
    identity_hash = hashlib.sha256(
        f"{device_group_key}{device_key}:{DEVICE_SECRET}".encode()
    ).hexdigest()
    private_x = int(_hex_hash(f"{_pad(int.from_bytes(salt_bytes, 'big'))}{identity_hash}"), 16)
    verifier = pow(G, private_x, N)
    return (
        base64.b64encode(salt_bytes).decode(),
        base64.b64encode(bytes.fromhex(_pad(verifier))).decode(),
        private_x,
    )


def _started(*, now=NOW, private_a=0x123456789ABCDEF, **overrides):
    salt, verifier, private_x = _device_verifier(bytes.fromhex("00112233445566778899aabbccddeeff"))
    parameters = {
        "pool_id": POOL_ID,
        "client_id": CLIENT_ID,
        "username": USERNAME,
        "device_key": DEVICE_KEY,
        "device_group_key": DEVICE_GROUP_KEY,
        "salt": salt,
        "verifier": verifier,
        "public_a": format(pow(G, private_a, N), "x"),
        "private_b": 0xFEDCBA987654321,
        "secret_block": bytes(range(32)),
        "session_token": "s" * 64,
        "now": now,
        "auth_context": {"IpAddress": "192.0.2.10"},
        "client_metadata": {"platform": "android"},
    }
    parameters.update(overrides)
    return start_device_srp(**parameters), private_a, private_x


def _client_response(started, private_a, private_x, *, now=NOW):
    challenge = started.challenge_parameters
    public_a = pow(G, private_a, N)
    public_b = int(challenge["SRP_B"], 16)
    scrambling = int(_hex_hash(f"{_pad(public_a)}{_pad(public_b)}"), 16)
    base = (public_b - K * pow(G, private_x, N)) % N
    shared_secret = pow(base, private_a + scrambling * private_x, N)
    shared_key = _hkdf(shared_secret, scrambling)
    timestamp = f"Mon Aug {now.day} {now:%H:%M:%S} UTC {now.year}"
    secret_block = base64.b64decode(challenge["SECRET_BLOCK"], validate=True)
    signature = hmac.new(
        shared_key,
        DEVICE_GROUP_KEY.encode() + DEVICE_KEY.encode() + secret_block + timestamp.encode(),
        hashlib.sha256,
    ).digest()
    return {
        "secret_block": challenge["SECRET_BLOCK"],
        "timestamp": timestamp,
        "signature": base64.b64encode(signature).decode(),
    }


def test_independent_amplify_device_vector_completes_password_verifier():
    started, private_a, private_x = _started()

    assert started.challenge_parameters == {
        "DEVICE_KEY": DEVICE_KEY,
        "SALT": "00112233445566778899aabbccddeeff",
        "SECRET_BLOCK": base64.b64encode(bytes(range(32))).decode(),
        "SRP_B": started.challenge_parameters["SRP_B"],
        "USERNAME": USERNAME,
    }
    sessions = {}
    reserve_device_srp_session(sessions, started, now=NOW)
    session = consume_device_srp_session(
        sessions,
        started.session_token,
        pool_id=POOL_ID,
        client_id=CLIENT_ID,
        username=USERNAME,
        device_key=DEVICE_KEY,
        now=NOW,
    )
    verify_device_password(
        session,
        device_group_key=DEVICE_GROUP_KEY,
        now=NOW,
        **_client_response(started, private_a, private_x),
    )


def test_session_is_hash_only_bound_and_persists_without_raw_device_secret():
    started, private_a, private_x = _started()
    serialized = pickle.dumps({started.session.token_hash: started.session})
    restored = pickle.loads(serialized)

    representation = repr(restored)
    assert started.session_token not in representation
    assert DEVICE_SECRET not in representation
    assert bytes(range(32)) not in serialized
    assert started.session.token_hash in restored
    assert restored[started.session.token_hash].auth_context == {"IpAddress": "192.0.2.10"}
    assert restored[started.session.token_hash].client_metadata == {"platform": "android"}

    session = consume_device_srp_session(
        restored,
        started.session_token,
        pool_id=POOL_ID,
        client_id=CLIENT_ID,
        username=USERNAME,
        device_key=DEVICE_KEY,
        now=NOW,
    )
    verify_device_password(
        session,
        device_group_key=DEVICE_GROUP_KEY,
        now=NOW,
        **_client_response(started, private_a, private_x),
    )


def test_mismatched_binding_cannot_consume_session_and_replay_is_rejected():
    started, _, _ = _started()
    sessions = {}
    reserve_device_srp_session(sessions, started, now=NOW)

    for bindings in (
        {"pool_id": "us-east-1_other"},
        {"client_id": "another-client"},
        {"username": "bob"},
        {"device_key": "us-east-1_1a859a59-722d-4db3-a77b-76cb3f65aa00"},
    ):
        parameters = {
            "pool_id": POOL_ID,
            "client_id": CLIENT_ID,
            "username": USERNAME,
            "device_key": DEVICE_KEY,
            **bindings,
        }
        with pytest.raises(DeviceSrpError, match="Invalid authentication session"):
            consume_device_srp_session(sessions, started.session_token, now=NOW, **parameters)
        assert started.session.token_hash in sessions

    consume_device_srp_session(
        sessions,
        started.session_token,
        pool_id=POOL_ID,
        client_id=CLIENT_ID,
        username=USERNAME,
        device_key=DEVICE_KEY,
        now=NOW,
    )
    with pytest.raises(DeviceSrpError, match="Invalid authentication session"):
        consume_device_srp_session(
            sessions,
            started.session_token,
            pool_id=POOL_ID,
            client_id=CLIENT_ID,
            username=USERNAME,
            device_key=DEVICE_KEY,
            now=NOW,
        )


def test_session_consumption_is_atomic_under_concurrent_replay():
    started, _, _ = _started()
    sessions = {}
    reserve_device_srp_session(sessions, started, now=NOW)
    lock = threading.Lock()

    def consume_once():
        try:
            with lock:
                consume_device_srp_session(
                    sessions,
                    started.session_token,
                    pool_id=POOL_ID,
                    client_id=CLIENT_ID,
                    username=USERNAME,
                    device_key=DEVICE_KEY,
                    now=NOW,
                )
            return "success"
        except DeviceSrpError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: consume_once(), range(8)))
    assert results.count("success") == 1
    assert results.count("NotAuthorizedException") == 7


def test_invalid_password_response_is_fail_closed_after_one_use():
    started, private_a, private_x = _started()
    sessions = {}
    reserve_device_srp_session(sessions, started, now=NOW)
    session = consume_device_srp_session(
        sessions,
        started.session_token,
        pool_id=POOL_ID,
        client_id=CLIENT_ID,
        username=USERNAME,
        device_key=DEVICE_KEY,
        now=NOW,
    )
    response = _client_response(started, private_a, private_x)
    response["signature"] = base64.b64encode(b"\0" * 32).decode()
    with pytest.raises(DeviceSrpError, match="Incorrect device key or password"):
        verify_device_password(session, device_group_key=DEVICE_GROUP_KEY, now=NOW, **response)
    assert sessions == {}


def test_expiry_and_quota_prune_sessions_deterministically():
    old, _, _ = _started(now=NOW - timedelta(minutes=4), session_token="o" * 64)
    current, _, _ = _started(session_token="c" * 64)
    latest, _, _ = _started(
        now=NOW + timedelta(seconds=1), session_token="l" * 64, secret_block=b"l" * 32
    )
    sessions = {old.session.token_hash: old.session}

    reserve_device_srp_session(sessions, current, now=NOW, maximum=1)
    assert set(sessions) == {current.session.token_hash}
    reserve_device_srp_session(sessions, latest, now=NOW + timedelta(seconds=1), maximum=1)
    assert set(sessions) == {latest.session.token_hash}
    with pytest.raises(DeviceSrpError, match="Invalid authentication session"):
        consume_device_srp_session(
            sessions,
            current.session_token,
            pool_id=POOL_ID,
            client_id=CLIENT_ID,
            username=USERNAME,
            device_key=DEVICE_KEY,
            now=NOW,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("public_a", "0"),
        ("public_a", format(N, "x")),
        ("public_a", "xyz"),
        ("device_key", "wrong"),
        ("device_group_key", ""),
        ("username", ""),
        ("salt", "not-base64"),
        ("verifier", base64.b64encode(b"\0").decode()),
        ("verifier", base64.b64encode(N.to_bytes(384, "big")).decode()),
    ),
)
def test_start_rejects_malformed_or_degenerate_values(field, value):
    with pytest.raises(DeviceSrpError):
        _started(**{field: value})


def test_verifier_normalization_rejects_oversized_material():
    with pytest.raises(DeviceSrpError, match="Invalid Salt"):
        normalize_device_verifier(base64.b64encode(b"s" * 129).decode(), "AQ==")
    with pytest.raises(DeviceSrpError, match="Invalid PasswordVerifier"):
        normalize_device_verifier("AQ==", base64.b64encode(b"v" * 386).decode())


def test_timestamp_secret_block_and_signature_are_strictly_validated():
    started, private_a, private_x = _started()
    valid = _client_response(started, private_a, private_x)
    cases = (
        {**valid, "timestamp": "Sun Aug 10 15:04:05 UTC 2026"},
        {**valid, "timestamp": "Mon Aug 10 15:14:05 UTC 2026"},
        {**valid, "secret_block": base64.b64encode(b"short").decode()},
        {**valid, "signature": "%%%"},
    )
    for response in cases:
        with pytest.raises(DeviceSrpError):
            verify_device_password(
                started.session,
                device_group_key=DEVICE_GROUP_KEY,
                now=NOW,
                **response,
            )


@pytest.fixture
def context():
    context = RequestContext(None)
    context.account_id = "123456789012"
    context.region = "us-east-1"
    yield context
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(context.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(context.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def _provider_stack(provider, context, *, secret=False, prompt=False):
    pool = provider.create_user_pool(
        context,
        {
            "DeviceConfiguration": {
                "ChallengeRequiredOnNewDevice": True,
                "DeviceOnlyRememberedOnUserPrompt": prompt,
            },
            "PoolName": "device-srp-users",
        },
    )["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "amplify-device-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            "GenerateSecret": secret,
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
            "Password": "PermanentPass9!",
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": USERNAME,
        },
    )
    return pool, client


def _secret_hash(client):
    return base64.b64encode(
        hmac.new(
            client["ClientSecret"].encode(),
            f"{USERNAME}{client['ClientId']}".encode(),
            hashlib.sha256,
        ).digest()
    ).decode()


def _provider_initial_auth(provider, context, client, *, device_key=None):
    parameters = {"PASSWORD": "PermanentPass9!", "USERNAME": USERNAME}
    if device_key is not None:
        parameters["DEVICE_KEY"] = device_key
    if "ClientSecret" in client:
        parameters["SECRET_HASH"] = _secret_hash(client)
    return provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": parameters,
            "ClientId": client["ClientId"],
        },
    )


def _confirm_provider_device(provider, context, tokens, metadata, *, prompt=False):
    salt, verifier, private_x = _device_verifier(
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        device_key=metadata["DeviceKey"],
        device_group_key=metadata["DeviceGroupKey"],
    )
    response = provider.confirm_device(
        context,
        {
            "AccessToken": tokens["AccessToken"],
            "DeviceKey": metadata["DeviceKey"],
            "DeviceName": "Amplify Android",
            "DeviceSecretVerifierConfig": {"PasswordVerifier": verifier, "Salt": salt},
        },
    )
    assert response == {"UserConfirmationNecessary": prompt}
    return private_x


def _provider_device_password_response(challenge, private_a, private_x, metadata, *, now):
    parameters = challenge["ChallengeParameters"]
    public_a = pow(G, private_a, N)
    public_b = int(parameters["SRP_B"], 16)
    scrambling = int(_hex_hash(f"{_pad(public_a)}{_pad(public_b)}"), 16)
    base = (public_b - K * pow(G, private_x, N)) % N
    shared_secret = pow(base, private_a + scrambling * private_x, N)
    shared_key = _hkdf(shared_secret, scrambling)
    timestamp = (
        f"{['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][now.weekday()]} "
        f"{['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][now.month - 1]} "
        f"{now.day} {now:%H:%M:%S} UTC {now.year}"
    )
    secret_block = base64.b64decode(parameters["SECRET_BLOCK"], validate=True)
    signature = hmac.new(
        shared_key,
        metadata["DeviceGroupKey"].encode()
        + metadata["DeviceKey"].encode()
        + secret_block
        + timestamp.encode(),
        hashlib.sha256,
    ).digest()
    return {
        "DEVICE_KEY": metadata["DeviceKey"],
        "PASSWORD_CLAIM_SECRET_BLOCK": parameters["SECRET_BLOCK"],
        "PASSWORD_CLAIM_SIGNATURE": base64.b64encode(signature).decode(),
        "TIMESTAMP": timestamp,
        "USERNAME": USERNAME,
    }


def test_provider_remembered_device_srp_and_device_bound_refresh(provider, context):
    pool, client = _provider_stack(provider, context)
    first = _provider_initial_auth(provider, context, client)["AuthenticationResult"]
    metadata = first["NewDeviceMetadata"]
    private_x = _confirm_provider_device(provider, context, first, metadata)
    provider.set_user_pool_mfa_config(
        context,
        {
            "MfaConfiguration": "ON",
            "SoftwareTokenMfaConfiguration": {"Enabled": True},
            "UserPoolId": pool["Id"],
        },
    )

    parent = _provider_initial_auth(provider, context, client, device_key=metadata["DeviceKey"])
    assert parent["ChallengeName"] == "DEVICE_SRP_AUTH"
    assert parent["ChallengeParameters"]["DEVICE_KEY"] == metadata["DeviceKey"]
    private_a = 0x123456789ABCDEF
    password_challenge = provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "DEVICE_SRP_AUTH",
            "ChallengeResponses": {
                "DEVICE_KEY": metadata["DeviceKey"],
                "SRP_A": format(pow(G, private_a, N), "x"),
                "USERNAME": USERNAME,
            },
            "ClientId": client["ClientId"],
            "Session": parent["Session"],
        },
    )
    assert password_challenge["ChallengeName"] == "DEVICE_PASSWORD_VERIFIER"
    assert set(password_challenge["ChallengeParameters"]) == {
        "DEVICE_KEY",
        "SALT",
        "SECRET_BLOCK",
        "SRP_B",
        "USERNAME",
    }
    responses = _provider_device_password_response(
        password_challenge, private_a, private_x, metadata, now=datetime.now(UTC)
    )
    result = provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "DEVICE_PASSWORD_VERIFIER",
            "ChallengeResponses": responses,
            "ClientId": client["ClientId"],
            "Session": password_challenge["Session"],
        },
    )["AuthenticationResult"]
    assert "NewDeviceMetadata" not in result

    for device_key in (None, "us-east-1_1a859a59-722d-4db3-a77b-76cb3f65aa00"):
        request = {"ClientId": client["ClientId"], "RefreshToken": result["RefreshToken"]}
        if device_key is not None:
            request["DeviceKey"] = device_key
        with pytest.raises(CommonServiceException) as invalid:
            provider.get_tokens_from_refresh_token(context, request)
        assert invalid.value.code == "NotAuthorizedException"
    refreshed = provider.get_tokens_from_refresh_token(
        context,
        {
            "ClientId": client["ClientId"],
            "DeviceKey": metadata["DeviceKey"],
            "RefreshToken": result["RefreshToken"],
        },
    )["AuthenticationResult"]
    assert refreshed["AccessToken"]
    assert "NewDeviceMetadata" not in refreshed


def test_provider_device_srp_secret_hash_replay_and_not_remembered_behavior(provider, context):
    pool, client = _provider_stack(provider, context, secret=True, prompt=True)
    first = _provider_initial_auth(provider, context, client)["AuthenticationResult"]
    metadata = first["NewDeviceMetadata"]
    private_x = _confirm_provider_device(provider, context, first, metadata, prompt=True)
    provider.set_user_pool_mfa_config(
        context,
        {
            "MfaConfiguration": "ON",
            "SoftwareTokenMfaConfiguration": {"Enabled": True},
            "UserPoolId": pool["Id"],
        },
    )
    not_remembered = _provider_initial_auth(
        provider, context, client, device_key=metadata["DeviceKey"]
    )
    assert not_remembered["ChallengeName"] == "MFA_SETUP"
    provider.admin_update_device_status(
        context,
        {
            "DeviceKey": metadata["DeviceKey"],
            "DeviceRememberedStatus": "remembered",
            "UserPoolId": pool["Id"],
            "Username": USERNAME,
        },
    )

    parent = _provider_initial_auth(provider, context, client, device_key=metadata["DeviceKey"])
    request = {
        "ChallengeName": "DEVICE_SRP_AUTH",
        "ChallengeResponses": {
            "DEVICE_KEY": metadata["DeviceKey"],
            "SRP_A": format(pow(G, 0x123456789ABCDEF, N), "x"),
            "USERNAME": USERNAME,
        },
        "ClientId": client["ClientId"],
        "Session": parent["Session"],
    }
    with pytest.raises(CommonServiceException) as missing_hash:
        provider.respond_to_auth_challenge(context, request)
    assert missing_hash.value.code == "NotAuthorizedException"
    with pytest.raises(CommonServiceException) as replay:
        provider.respond_to_auth_challenge(
            context,
            {
                **request,
                "ChallengeResponses": {
                    **request["ChallengeResponses"],
                    "SECRET_HASH": _secret_hash(client),
                },
            },
        )
    assert replay.value.code == "NotAuthorizedException"

    parent = _provider_initial_auth(provider, context, client, device_key=metadata["DeviceKey"])
    password_challenge = provider.respond_to_auth_challenge(
        context,
        {
            **request,
            "ChallengeResponses": {
                **request["ChallengeResponses"],
                "SECRET_HASH": _secret_hash(client),
            },
            "Session": parent["Session"],
        },
    )
    responses = _provider_device_password_response(
        password_challenge,
        0x123456789ABCDEF,
        private_x,
        metadata,
        now=datetime.now(UTC),
    )
    with pytest.raises(CommonServiceException) as second_missing_hash:
        provider.respond_to_auth_challenge(
            context,
            {
                "ChallengeName": "DEVICE_PASSWORD_VERIFIER",
                "ChallengeResponses": responses,
                "ClientId": client["ClientId"],
                "Session": password_challenge["Session"],
            },
        )
    assert second_missing_hash.value.code == "NotAuthorizedException"
