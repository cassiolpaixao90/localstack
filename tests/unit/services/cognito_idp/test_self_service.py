import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider


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


def _pool_client(provider, context, *, prevent="ENABLED", admin_only=False):
    request = {"PoolName": "self-service-users"}
    if admin_only:
        request["AdminCreateUserConfig"] = {"AllowAdminCreateUserOnly": True}
    pool = provider.create_user_pool(context, request)["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "web-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            "PreventUserExistenceErrors": prevent,
            "UserPoolId": pool["Id"],
            "WriteAttributes": ["email", "custom:plan"],
        },
    )["UserPoolClient"]
    return pool, client


def _auth(provider, context, client, password="PermanentPass9!"):
    return provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": password, "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]


def _signup(provider, context, client):
    return provider.sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "Password": "PermanentPass9!",
            "UserAttributes": [{"Name": "email", "Value": "alice@example.com"}],
            "Username": "alice",
        },
    )


def test_attribute_update_keeps_verified_value_until_new_destination_is_confirmed(
    provider, context, monkeypatch
):
    pool = provider.create_user_pool(
        context,
        {
            "PoolName": "verified-attribute-updates",
            "UserAttributeUpdateSettings": {
                "AttributesRequireVerificationBeforeUpdate": ["email"]
            },
        },
    )["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "web-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
            "UserPoolId": pool["Id"],
            "WriteAttributes": ["email"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "TemporaryPass9!",
            "UserAttributes": [
                {"Name": "email", "Value": "old@example.test"},
                {"Name": "email_verified", "Value": "true"},
            ],
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": "PermanentPass9!",
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    token = _auth(provider, context, client)["AccessToken"]
    deliveries = []
    monkeypatch.setattr(
        provider,
        "_deliver_reserved_user_code",
        lambda *args, **kwargs: deliveries.append(kwargs),
    )

    response = provider.update_user_attributes(
        context,
        {
            "AccessToken": token,
            "UserAttributes": [{"Name": "email", "Value": "new@example.test"}],
        },
    )

    assert response["CodeDeliveryDetailsList"] == [
        {
            "AttributeName": "email",
            "DeliveryMedium": "EMAIL",
            "Destination": "n***@example.test",
        }
    ]
    assert deliveries[0]["destination"] == "new@example.test"
    before = provider.admin_get_user(
        context, {"UserPoolId": pool["Id"], "Username": "alice"}
    )
    before_attributes = {item["Name"]: item["Value"] for item in before["UserAttributes"]}
    assert before_attributes["email"] == "old@example.test"
    assert before_attributes["email_verified"] == "true"

    monkeypatch.setattr(provider_module, "_verify_user_code", lambda *args, **kwargs: None)
    provider.verify_user_attribute(
        context,
        {"AccessToken": token, "AttributeName": "email", "Code": "123456"},
    )
    after = provider.admin_get_user(
        context, {"UserPoolId": pool["Id"], "Username": "alice"}
    )
    after_attributes = {item["Name"]: item["Value"] for item in after["UserAttributes"]}
    assert after_attributes["email"] == "new@example.test"
    assert after_attributes["email_verified"] == "true"
    with cognito_idp_stores.lock:
        user = provider.get_store(context).user_pools[pool["Id"]].users["alice"]
        assert user.pending_attribute_updates == {}


def test_signup_resend_confirm_codes_are_hash_only_and_single_use(provider, context, monkeypatch):
    pool, client = _pool_client(provider, context)
    codes = iter(("111111", "222222"))
    monkeypatch.setattr(provider_module, "_new_numeric_code", lambda: next(codes))
    signed_up = _signup(provider, context, client)
    assert signed_up["UserConfirmed"] is False
    assert signed_up["CodeDeliveryDetails"]["DeliveryMedium"] == "EMAIL"
    with cognito_idp_stores.lock:
        store = provider.get_store(context)
        assert "111111" not in repr(store.user_codes)

    provider.resend_confirmation_code(
        context, {"ClientId": client["ClientId"], "Username": "alice"}
    )
    with pytest.raises(CommonServiceException) as old_code:
        provider.confirm_sign_up(
            context,
            {
                "ClientId": client["ClientId"],
                "ConfirmationCode": "111111",
                "Username": "alice",
            },
        )
    assert old_code.value.code == "CodeMismatchException"
    provider.confirm_sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "ConfirmationCode": "222222",
            "Username": "alice",
        },
    )
    with pytest.raises(CommonServiceException) as replay:
        provider.confirm_sign_up(
            context,
            {
                "ClientId": client["ClientId"],
                "ConfirmationCode": "222222",
                "Username": "alice",
            },
        )
    assert replay.value.code == "NotAuthorizedException"
    assert _auth(provider, context, client)["AccessToken"]

    admin_pool, admin_client = _pool_client(provider, context, admin_only=True)
    with pytest.raises(CommonServiceException) as disabled:
        provider.sign_up(
            context,
            {
                "ClientId": admin_client["ClientId"],
                "Password": "PermanentPass9!",
                "UserAttributes": [{"Name": "email", "Value": "blocked@example.com"}],
                "Username": "blocked",
            },
        )
    assert disabled.value.code == "NotAuthorizedException"
    assert admin_pool["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] is True
    assert pool["Id"] != admin_pool["Id"]


def test_forgot_password_rotates_srp_and_prevents_user_oracle(provider, context, monkeypatch):
    _, client = _pool_client(provider, context)
    codes = iter(("333333", "444444"))
    monkeypatch.setattr(provider_module, "_new_numeric_code", lambda: next(codes))
    _signup(provider, context, client)
    provider.confirm_sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "ConfirmationCode": "333333",
            "Username": "alice",
        },
    )
    known = provider.forgot_password(context, {"ClientId": client["ClientId"], "Username": "alice"})
    missing = provider.forgot_password(
        context, {"ClientId": client["ClientId"], "Username": "missing"}
    )
    assert set(known) == set(missing) == {"CodeDeliveryDetails"}
    provider.confirm_forgot_password(
        context,
        {
            "ClientId": client["ClientId"],
            "ConfirmationCode": "444444",
            "Password": "ChangedPass9!",
            "Username": "alice",
        },
    )
    with pytest.raises(CommonServiceException) as replay:
        provider.confirm_forgot_password(
            context,
            {
                "ClientId": client["ClientId"],
                "ConfirmationCode": "444444",
                "Password": "AnotherPass9!",
                "Username": "alice",
            },
        )
    assert replay.value.code == "CodeMismatchException"
    assert _auth(provider, context, client, "ChangedPass9!")["IdToken"]


def test_self_service_attributes_password_signout_and_delete(provider, context, monkeypatch):
    _, client = _pool_client(provider, context)
    codes = iter(("555555", "666666"))
    monkeypatch.setattr(provider_module, "_new_numeric_code", lambda: next(codes))
    _signup(provider, context, client)
    provider.confirm_sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "ConfirmationCode": "555555",
            "Username": "alice",
        },
    )
    tokens = _auth(provider, context, client)
    access_token = tokens["AccessToken"]
    assert provider.get_user(context, {"AccessToken": access_token})["Username"] == "alice"
    delivery = provider.update_user_attributes(
        context,
        {
            "AccessToken": access_token,
            "UserAttributes": [
                {"Name": "email", "Value": "new@example.com"},
                {"Name": "custom:plan", "Value": "enterprise"},
            ],
        },
    )
    assert delivery["CodeDeliveryDetailsList"][0]["AttributeName"] == "email"
    provider.verify_user_attribute(
        context,
        {"AccessToken": access_token, "AttributeName": "email", "Code": "666666"},
    )
    attributes = {
        item["Name"]: item["Value"]
        for item in provider.get_user(context, {"AccessToken": access_token})["UserAttributes"]
    }
    assert attributes["email_verified"] == "true"
    provider.delete_user_attributes(
        context,
        {"AccessToken": access_token, "UserAttributeNames": ["custom:plan"]},
    )
    provider.change_password(
        context,
        {
            "AccessToken": access_token,
            "PreviousPassword": "PermanentPass9!",
            "ProposedPassword": "ChangedPass9!",
        },
    )
    provider.global_sign_out(context, {"AccessToken": access_token})
    with pytest.raises(CommonServiceException) as signed_out:
        provider.get_user(context, {"AccessToken": access_token})
    assert signed_out.value.code == "NotAuthorizedException"

    new_token = _auth(provider, context, client, "ChangedPass9!")["AccessToken"]
    provider.delete_user(context, {"AccessToken": new_token})
    with pytest.raises(CommonServiceException) as deleted:
        provider.get_user(context, {"AccessToken": new_token})
    assert deleted.value.code == "NotAuthorizedException"


def test_change_password_revalidates_token_after_waiting_for_pool_lock(
    provider, context, monkeypatch
):
    pool, client = _pool_client(provider, context)
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "TemporaryPass9!",
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": "PermanentPass9!",
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    access_token = _auth(provider, context, client)["AccessToken"]
    looked_up = threading.Event()
    release = threading.Event()
    original = provider._access_token_user
    calls = 0

    def pause_first_lookup(candidate_context, token):
        nonlocal calls
        result = original(candidate_context, token)
        calls += 1
        if calls == 1:
            looked_up.set()
            assert release.wait(2)
        return result

    monkeypatch.setattr(provider, "_access_token_user", pause_first_lookup)
    errors = []

    def change_password():
        try:
            provider.change_password(
                context,
                {
                    "AccessToken": access_token,
                    "PreviousPassword": "PermanentPass9!",
                    "ProposedPassword": "ChangedPass9!",
                },
            )
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=change_password)
    worker.start()
    assert looked_up.wait(2)
    provider.delete_user_pool(context, {"UserPoolId": pool["Id"]})
    release.set()
    worker.join(2)

    assert not worker.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], CommonServiceException)
    assert errors[0].code == "NotAuthorizedException"


def test_admin_global_signout_and_explicit_verification_code(provider, context, monkeypatch):
    pool, client = _pool_client(provider, context)
    codes = iter(("777777", "888888"))
    monkeypatch.setattr(provider_module, "_new_numeric_code", lambda: next(codes))
    _signup(provider, context, client)
    provider.confirm_sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "ConfirmationCode": "777777",
            "Username": "alice",
        },
    )
    access_token = _auth(provider, context, client)["AccessToken"]
    provider.get_user_attribute_verification_code(
        context, {"AccessToken": access_token, "AttributeName": "email"}
    )
    provider.verify_user_attribute(
        context,
        {"AccessToken": access_token, "AttributeName": "email", "Code": "888888"},
    )
    provider.admin_user_global_sign_out(context, {"Username": "alice", "UserPoolId": pool["Id"]})
    with pytest.raises(CommonServiceException) as revoked:
        provider.get_user(context, {"AccessToken": access_token})
    assert revoked.value.code == "NotAuthorizedException"


def test_verification_codes_expire_bound_attempts_and_enforce_store_quota(
    provider, context, monkeypatch
):
    pool, client = _pool_client(provider, context)
    codes = iter(("101010", "202020"))
    monkeypatch.setattr(provider_module, "_new_numeric_code", lambda: next(codes))
    _signup(provider, context, client)
    with cognito_idp_stores.lock:
        store = provider.get_store(context)
        state = next(iter(store.user_codes.values()))
        state.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(CommonServiceException) as expired:
        provider.confirm_sign_up(
            context,
            {
                "ClientId": client["ClientId"],
                "ConfirmationCode": "101010",
                "Username": "alice",
            },
        )
    assert expired.value.code == "ExpiredCodeException"

    provider.resend_confirmation_code(
        context, {"ClientId": client["ClientId"], "Username": "alice"}
    )
    monkeypatch.setattr(provider_module, "_MAX_USER_CODE_ATTEMPTS", 2)
    for _ in range(2):
        with pytest.raises(CommonServiceException) as mismatch:
            provider.confirm_sign_up(
                context,
                {
                    "ClientId": client["ClientId"],
                    "ConfirmationCode": "000000",
                    "Username": "alice",
                },
            )
        assert mismatch.value.code == "CodeMismatchException"
    with pytest.raises(CommonServiceException) as exhausted:
        provider.confirm_sign_up(
            context,
            {
                "ClientId": client["ClientId"],
                "ConfirmationCode": "202020",
                "Username": "alice",
            },
        )
    assert exhausted.value.code == "CodeMismatchException"

    monkeypatch.setattr(provider_module, "_MAX_USER_CODES_PER_STORE", 1)
    monkeypatch.setattr(provider_module, "_new_numeric_code", lambda: "303030")
    provider.resend_confirmation_code(
        context, {"ClientId": client["ClientId"], "Username": "alice"}
    )
    with pytest.raises(CommonServiceException) as quota:
        provider.sign_up(
            context,
            {
                "ClientId": client["ClientId"],
                "Password": "PermanentPass9!",
                "UserAttributes": [{"Name": "email", "Value": "bob@example.com"}],
                "Username": "bob",
            },
        )
    assert quota.value.code == "LimitExceededException"
    assert "bob" not in provider.get_store(context).user_pools[pool["Id"]].users
