import base64
import hashlib
import hmac
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider

# Independent client-side vector matching the equations used by Amplify v6.
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
PASSWORD = "PermanentPass9!"
TEMPORARY_PASSWORD = "TemporaryPass9!"
NEW_PASSWORD = "ChangedPass9!"


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
    ikm = bytes.fromhex(_pad(shared_secret))
    salt = bytes.fromhex(_pad(scrambling))
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, b"Caldera Derived Key\x01", hashlib.sha256).digest()[:16]


def _timestamp(now=None):
    now = datetime.now(UTC) if now is None else now
    weekdays = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return (
        f"{weekdays[now.weekday()]} {months[now.month - 1]} {now.day} {now:%H:%M:%S} UTC {now.year}"
    )


def _secret_hash(username, client):
    digest = hmac.new(
        client["ClientSecret"].encode(),
        f"{username}{client['ClientId']}".encode(),
        hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode()


@pytest.fixture
def context():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
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


def _stack(provider, context, *, permanent=True, prevent="ENABLED", secret=False):
    pool = provider.create_user_pool(context, {"PoolName": "srp-users"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "amplify-srp-client",
            "ExplicitAuthFlows": ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            "GenerateSecret": secret,
            "PreventUserExistenceErrors": prevent,
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "TemporaryPassword": TEMPORARY_PASSWORD,
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    if permanent:
        provider.admin_set_user_password(
            context,
            {
                "Password": PASSWORD,
                "Permanent": True,
                "UserPoolId": pool["Id"],
                "Username": "alice",
            },
        )
    return pool, client


def _begin(
    provider,
    context,
    client,
    username="alice",
    *,
    private_a=0x123456789ABCDEF,
    user_context=None,
    client_metadata=None,
):
    public_a = pow(G, private_a, N)
    parameters = {"SRP_A": format(public_a, "x"), "USERNAME": username}
    if "ClientSecret" in client:
        parameters["SECRET_HASH"] = _secret_hash(username, client)
    response = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_SRP_AUTH",
            "AuthParameters": parameters,
            "ClientId": client["ClientId"],
            **({"ClientMetadata": client_metadata} if client_metadata is not None else {}),
            **({"UserContextData": user_context} if user_context is not None else {}),
        },
    )
    return response, private_a


def _password_verifier_request(pool, client, response, private_a, password, *, now=None):
    challenge = response["ChallengeParameters"]
    username = challenge["USER_ID_FOR_SRP"]
    salt = int(challenge["SALT"], 16)
    public_b = int(challenge["SRP_B"], 16)
    public_a = pow(G, private_a, N)
    scrambling = int(_hex_hash(f"{_pad(public_a)}{_pad(public_b)}"), 16)
    username_password_hash = hashlib.sha256(
        f"{pool['Id'].split('_', 1)[1]}{username}:{password}".encode()
    ).hexdigest()
    private_x = int(_hex_hash(f"{_pad(salt)}{username_password_hash}"), 16)
    base = (public_b - K * pow(G, private_x, N)) % N
    shared_secret = pow(base, private_a + scrambling * private_x, N)
    key = _hkdf(shared_secret, scrambling)
    timestamp = _timestamp(now)
    secret_block = base64.b64decode(challenge["SECRET_BLOCK"], validate=True)
    signature = hmac.new(
        key,
        pool["Id"].split("_", 1)[1].encode()
        + username.encode()
        + secret_block
        + timestamp.encode(),
        hashlib.sha256,
    ).digest()
    responses = {
        "PASSWORD_CLAIM_SECRET_BLOCK": challenge["SECRET_BLOCK"],
        "PASSWORD_CLAIM_SIGNATURE": base64.b64encode(signature).decode(),
        "TIMESTAMP": timestamp,
        "USERNAME": username,
    }
    if "ClientSecret" in client:
        responses["SECRET_HASH"] = _secret_hash(username, client)
    return {
        "ChallengeName": "PASSWORD_VERIFIER",
        "ChallengeResponses": responses,
        "ClientId": client["ClientId"],
        "Session": response["Session"],
    }


def test_amplify_compatible_srp_vector_returns_tokens(provider, context):
    pool, client = _stack(provider, context)
    challenge, private_a = _begin(
        provider, context, client, user_context={"IpAddress": "192.0.2.10"}
    )

    assert challenge["ChallengeName"] == "PASSWORD_VERIFIER"
    assert set(challenge["ChallengeParameters"]) == {
        "SALT",
        "SECRET_BLOCK",
        "SRP_B",
        "USER_ID_FOR_SRP",
        "USERNAME",
    }
    result = provider.respond_to_auth_challenge(
        context,
        _password_verifier_request(pool, client, challenge, private_a, PASSWORD),
    )

    assert result["AuthenticationResult"]["AccessToken"]
    assert result["AuthenticationResult"]["IdToken"]
    assert result["AuthenticationResult"]["RefreshToken"]
    events = provider.admin_list_user_auth_events(
        context, {"UserPoolId": pool["Id"], "Username": "alice"}
    )["AuthEvents"]
    assert events[0]["EventResponse"] == "Pass"
    assert events[0]["EventContextData"] == {"IpAddress": "192.0.2.10"}


def test_amplify_client_metadata_is_bounded_and_preserved_through_srp_challenge(
    provider, context, monkeypatch
):
    pool, client = _stack(provider, context)
    metadata = {"amplify-device": "android", "tenant": "billgym"}
    challenge, private_a = _begin(provider, context, client, client_metadata=metadata)
    stored = provider.get_store(context).srp_sessions[
        provider_module._token_hash(challenge["Session"])
    ]
    assert stored.client_metadata == metadata

    captured = {}
    original = provider_module._pre_token_generation_overrides

    def capture(*args, **kwargs):
        captured.update(kwargs.get("client_metadata") or {})
        return original(*args, **kwargs)

    monkeypatch.setattr(provider_module, "_pre_token_generation_overrides", capture)
    completed = provider.respond_to_auth_challenge(
        context,
        _password_verifier_request(pool, client, challenge, private_a, PASSWORD),
    )
    assert completed["AuthenticationResult"]["AccessToken"]
    assert captured == metadata

    with pytest.raises(CommonServiceException) as oversized:
        _begin(provider, context, client, client_metadata={"key": "x" * 131_073})
    assert oversized.value.code == "InvalidParameterException"


def test_srp_password_verifier_enforces_ip_risk_and_records_failure(provider, context):
    pool, client = _stack(provider, context)
    provider.set_risk_configuration(
        context,
        {
            "ClientId": "ALL",
            "RiskExceptionConfiguration": {"BlockedIPRangeList": ["192.0.2.0/24"]},
            "UserPoolId": pool["Id"],
        },
    )
    challenge, private_a = _begin(
        provider, context, client, user_context={"IpAddress": "192.0.2.10"}
    )

    with pytest.raises(CommonServiceException) as blocked:
        provider.respond_to_auth_challenge(
            context,
            _password_verifier_request(pool, client, challenge, private_a, PASSWORD),
        )
    assert blocked.value.code == "NotAuthorizedException"
    event = provider.admin_list_user_auth_events(
        context, {"UserPoolId": pool["Id"], "Username": "alice"}
    )["AuthEvents"][0]
    assert event["EventResponse"] == "Fail"
    assert event["EventRisk"]["RiskDecision"] == "Block"


def test_temporary_password_completes_new_password_required(provider, context):
    pool, client = _stack(provider, context, permanent=False)
    challenge, private_a = _begin(provider, context, client)
    password_result = provider.respond_to_auth_challenge(
        context,
        _password_verifier_request(pool, client, challenge, private_a, TEMPORARY_PASSWORD),
    )

    assert password_result["ChallengeName"] == "NEW_PASSWORD_REQUIRED"
    assert json.loads(password_result["ChallengeParameters"]["requiredAttributes"]) == []
    completed = provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "ChallengeResponses": {
                "NEW_PASSWORD": NEW_PASSWORD,
                "USERNAME": "alice",
            },
            "ClientId": client["ClientId"],
            "Session": password_result["Session"],
        },
    )
    assert completed["AuthenticationResult"]["IdToken"]

    authenticated, next_a = _begin(provider, context, client, private_a=0x23456789ABCDEF)
    assert "AuthenticationResult" in provider.respond_to_auth_challenge(
        context,
        _password_verifier_request(pool, client, authenticated, next_a, NEW_PASSWORD),
    )


def test_respond_to_auth_challenge_accepts_bounded_user_context_data(provider, context):
    pool, client = _stack(provider, context, permanent=False)
    challenge, private_a = _begin(provider, context, client)
    password_result = provider.respond_to_auth_challenge(
        context,
        _password_verifier_request(pool, client, challenge, private_a, TEMPORARY_PASSWORD),
    )

    # the Amplify Android SDK sends UserContextData at the top level and an
    # empty DEVICE_KEY when no device is registered
    completed = provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "ChallengeResponses": {
                "DEVICE_KEY": "",
                "NEW_PASSWORD": NEW_PASSWORD,
                "USERNAME": "alice",
            },
            "ClientId": client["ClientId"],
            "Session": password_result["Session"],
            "UserContextData": {
                "EncodedData": "android-device-context",
                "IpAddress": "192.0.2.10",
            },
        },
    )
    assert completed["AuthenticationResult"]["IdToken"]

    with pytest.raises(CommonServiceException) as error:
        provider.respond_to_auth_challenge(
            context,
            {
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "ChallengeResponses": {},
                "ClientId": client["ClientId"],
                "UserContextData": {"Unexpected": "field"},
            },
        )
    assert error.value.code == "InvalidParameterException"


def test_password_verifier_session_is_hash_only_bounded_and_single_use(
    provider, context, monkeypatch
):
    pool, client = _stack(provider, context)
    monkeypatch.setattr(provider_module, "_MAX_AUTH_CHALLENGE_SESSIONS", 2)
    challenges = [
        _begin(provider, context, client, private_a=0x123456789ABCDEF + index)[0]
        for index in range(3)
    ]
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert len(store.srp_sessions) == 2
        assert not {challenge["Session"] for challenge in challenges} & set(store.srp_sessions)
        assert all(
            challenge["ChallengeParameters"]["SECRET_BLOCK"]
            not in repr(list(store.srp_sessions.values()))
            for challenge in challenges
        )

    challenge, private_a = _begin(provider, context, client, private_a=0x3456789ABCDEF)
    request = _password_verifier_request(pool, client, challenge, private_a, PASSWORD)
    request["ChallengeResponses"]["PASSWORD_CLAIM_SIGNATURE"] = base64.b64encode(b"x" * 32).decode()
    with pytest.raises(CommonServiceException) as invalid:
        provider.respond_to_auth_challenge(context, request)
    assert invalid.value.code == "NotAuthorizedException"

    request = _password_verifier_request(pool, client, challenge, private_a, PASSWORD)
    with pytest.raises(CommonServiceException) as replay:
        provider.respond_to_auth_challenge(context, request)
    assert replay.value.code == "NotAuthorizedException"


def test_expired_and_cross_client_sessions_fail_closed(provider, context):
    pool, client = _stack(provider, context)
    challenge, private_a = _begin(provider, context, client)
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        session_hash = hashlib.sha256(challenge["Session"].encode()).hexdigest()
        store.srp_sessions[session_hash].expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(CommonServiceException) as expired:
        provider.respond_to_auth_challenge(
            context,
            _password_verifier_request(pool, client, challenge, private_a, PASSWORD),
        )
    assert expired.value.code == "NotAuthorizedException"

    other_pool, other_client = _stack(provider, context)
    challenge, private_a = _begin(provider, context, client, private_a=0x456789ABCDEF)
    cross_request = _password_verifier_request(pool, client, challenge, private_a, PASSWORD)
    cross_request["ClientId"] = other_client["ClientId"]
    with pytest.raises(CommonServiceException) as cross_client:
        provider.respond_to_auth_challenge(context, cross_request)
    assert cross_client.value.code == "NotAuthorizedException"
    assert other_pool["Id"] != pool["Id"]


@pytest.mark.parametrize("public_a", ["0", format(N, "x"), "not-hex", "-1"])
def test_srp_rejects_degenerate_or_malformed_public_a(provider, context, public_a):
    _, client = _stack(provider, context)
    with pytest.raises(CommonServiceException) as invalid:
        provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_SRP_AUTH",
                "AuthParameters": {"SRP_A": public_a, "USERNAME": "alice"},
                "ClientId": client["ClientId"],
            },
        )
    assert invalid.value.code == "InvalidParameterException"


def test_prevent_user_existence_errors_returns_indistinguishable_first_challenge(provider, context):
    pool, client = _stack(provider, context, prevent="ENABLED")
    known, _ = _begin(provider, context, client, username="alice")
    missing, _ = _begin(provider, context, client, username="missing")
    missing_again, _ = _begin(
        provider, context, client, username="missing", private_a=0x23456789ABCDEF
    )

    assert known["ChallengeName"] == missing["ChallengeName"] == "PASSWORD_VERIFIER"
    assert set(known["ChallengeParameters"]) == set(missing["ChallengeParameters"])
    assert missing["ChallengeParameters"]["SALT"] == missing_again["ChallengeParameters"]["SALT"]
    missing_request = _password_verifier_request(pool, client, missing, 0x123456789ABCDEF, PASSWORD)
    with pytest.raises(CommonServiceException) as hidden:
        provider.respond_to_auth_challenge(context, missing_request)
    assert hidden.value.code == "NotAuthorizedException"


def test_password_verifier_rejects_secret_block_and_stale_timestamp_once(provider, context):
    pool, client = _stack(provider, context)
    challenge, private_a = _begin(provider, context, client)
    request = _password_verifier_request(pool, client, challenge, private_a, PASSWORD)
    request["ChallengeResponses"]["PASSWORD_CLAIM_SECRET_BLOCK"] = base64.b64encode(
        b"z" * 32
    ).decode()
    with pytest.raises(CommonServiceException) as bad_block:
        provider.respond_to_auth_challenge(context, request)
    assert bad_block.value.code == "NotAuthorizedException"
    with pytest.raises(CommonServiceException) as consumed:
        provider.respond_to_auth_challenge(context, request)
    assert consumed.value.code == "NotAuthorizedException"

    challenge, private_a = _begin(provider, context, client, private_a=0x7654321ABCDEF)
    stale = datetime.now(UTC) - timedelta(minutes=6)
    with pytest.raises(CommonServiceException) as bad_time:
        provider.respond_to_auth_challenge(
            context,
            _password_verifier_request(pool, client, challenge, private_a, PASSWORD, now=stale),
        )
    assert bad_time.value.code == "NotAuthorizedException"


def test_secret_client_requires_hash_on_both_srp_steps(provider, context):
    pool, client = _stack(provider, context, secret=True)
    public_a = format(pow(G, 0x123456789ABCDEF, N), "x")
    with pytest.raises(CommonServiceException) as missing:
        provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_SRP_AUTH",
                "AuthParameters": {"SRP_A": public_a, "USERNAME": "alice"},
                "ClientId": client["ClientId"],
            },
        )
    assert missing.value.code == "NotAuthorizedException"

    challenge, private_a = _begin(provider, context, client)
    request = _password_verifier_request(pool, client, challenge, private_a, PASSWORD)
    request["ChallengeResponses"].pop("SECRET_HASH")
    with pytest.raises(CommonServiceException) as second_step:
        provider.respond_to_auth_challenge(context, request)
    assert second_step.value.code == "NotAuthorizedException"
    request["ChallengeResponses"]["SECRET_HASH"] = _secret_hash("alice", client)
    with pytest.raises(CommonServiceException) as consumed:
        provider.respond_to_auth_challenge(context, request)
    assert consumed.value.code == "NotAuthorizedException"


def test_password_verifier_session_has_exactly_one_concurrent_winner(provider, context):
    pool, client = _stack(provider, context)
    challenge, private_a = _begin(provider, context, client)
    request = _password_verifier_request(pool, client, challenge, private_a, PASSWORD)

    def complete():
        try:
            return provider.respond_to_auth_challenge(context, request)
        except CommonServiceException as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: complete(), range(2)))

    assert sum(isinstance(result, dict) for result in results) == 1
    assert results.count("NotAuthorizedException") == 1


def test_client_control_plane_round_trips_prevent_user_existence_errors(provider, context):
    pool, client = _stack(provider, context)
    assert client["PreventUserExistenceErrors"] == "ENABLED"
    updated = provider.update_user_pool_client(
        context,
        {
            "ClientId": client["ClientId"],
            "PreventUserExistenceErrors": "LEGACY",
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    assert updated["PreventUserExistenceErrors"] == "LEGACY"
    with pytest.raises(CommonServiceException) as invalid:
        provider.update_user_pool_client(
            context,
            {
                "ClientId": client["ClientId"],
                "PreventUserExistenceErrors": "UNKNOWN",
                "UserPoolId": pool["Id"],
            },
        )
    assert invalid.value.code == "InvalidParameterException"


def test_deleting_client_removes_srp_and_new_password_sessions(provider, context):
    pool, client = _stack(provider, context, permanent=False)
    challenge, private_a = _begin(provider, context, client)
    new_password = provider.respond_to_auth_challenge(
        context,
        _password_verifier_request(pool, client, challenge, private_a, TEMPORARY_PASSWORD),
    )
    assert new_password["ChallengeName"] == "NEW_PASSWORD_REQUIRED"
    _begin(provider, context, client, private_a=0x87654321ABCDEF)
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert store.srp_sessions
        assert store.new_password_sessions

    provider.delete_user_pool_client(
        context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
    )
    with cognito_idp_stores.lock:
        assert not store.srp_sessions
        assert not store.new_password_sessions


def test_srp_credentials_never_store_plaintext_password(provider, context):
    pool, _ = _stack(provider, context)
    with cognito_idp_stores.lock:
        user = (
            cognito_idp_stores[context.account_id][context.region]
            .user_pools[pool["Id"]]
            .users["alice"]
        )
        serialized = repr(user)

    assert PASSWORD not in serialized
    assert TEMPORARY_PASSWORD not in serialized
    assert user.srp_salt
    assert user.srp_verifier
