import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

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


def _stack(provider, context, *, prompt=False):
    pool = provider.create_user_pool(
        context,
        {
            "DeviceConfiguration": {
                "ChallengeRequiredOnNewDevice": True,
                "DeviceOnlyRememberedOnUserPrompt": prompt,
            },
            "PoolName": "device-users",
        },
    )["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "device-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    for username in ("alice", "bob"):
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
                "Password": "PermanentPass9!",
                "Permanent": True,
                "UserPoolId": pool["Id"],
                "Username": username,
            },
        )
    return pool, client


def _auth(provider, context, client, username="alice"):
    return provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": username},
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]


def _confirm(provider, context, tokens, metadata, *, name="Alice phone"):
    return provider.confirm_device(
        context,
        {
            "AccessToken": tokens["AccessToken"],
            "DeviceKey": metadata["DeviceKey"],
            "DeviceName": name,
            "DeviceSecretVerifierConfig": {
                "PasswordVerifier": "AQIDBA==",
                "Salt": "BQYHCA==",
            },
        },
    )


def test_device_configuration_auth_metadata_and_confirm_are_bounded_hash_only(provider, context):
    pool, client = _stack(provider, context)
    assert provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"][
        "DeviceConfiguration"
    ] == {
        "ChallengeRequiredOnNewDevice": True,
        "DeviceOnlyRememberedOnUserPrompt": False,
    }

    tokens = _auth(provider, context, client)
    metadata = tokens["NewDeviceMetadata"]
    assert metadata["DeviceGroupKey"]
    assert metadata["DeviceKey"].startswith(f"{context.region}_")
    with cognito_idp_stores.lock:
        store = provider.get_store(context)
        assert metadata["DeviceKey"] not in store.pending_devices
        assert metadata["DeviceKey"] not in repr(store.pending_devices)

    assert _confirm(provider, context, tokens, metadata) == {"UserConfirmationNecessary": False}
    with pytest.raises(CommonServiceException) as replay:
        _confirm(provider, context, tokens, metadata)
    assert replay.value.code == "ResourceNotFoundException"


def test_confirm_device_is_atomic_under_replay(provider, context):
    _, client = _stack(provider, context)
    tokens = _auth(provider, context, client)
    metadata = tokens["NewDeviceMetadata"]

    def confirm_once():
        try:
            return _confirm(provider, context, tokens, metadata)
        except CommonServiceException as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: confirm_once(), range(2)))
    assert results.count({"UserConfirmationNecessary": False}) == 1
    assert results.count("ResourceNotFoundException") == 1


def test_auth_without_device_tracking_has_no_device_metadata(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "untracked-users"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "untracked-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
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
    assert "DeviceConfiguration" not in pool
    assert "NewDeviceMetadata" not in _auth(provider, context, client)


def test_device_crud_admin_self_isolation_and_status(provider, context):
    pool, client = _stack(provider, context, prompt=True)
    alice_tokens = _auth(provider, context, client)
    metadata = alice_tokens["NewDeviceMetadata"]
    assert _confirm(provider, context, alice_tokens, metadata) == {
        "UserConfirmationNecessary": True
    }

    got = provider.get_device(
        context,
        {"AccessToken": alice_tokens["AccessToken"], "DeviceKey": metadata["DeviceKey"]},
    )["Device"]
    assert got["DeviceKey"] == metadata["DeviceKey"]
    assert got["DeviceAttributes"] == [{"Name": "device_name", "Value": "Alice phone"}]
    assert got["DeviceCreateDate"] <= got["DeviceLastModifiedDate"]

    admin = provider.admin_get_device(
        context,
        {"DeviceKey": metadata["DeviceKey"], "UserPoolId": pool["Id"], "Username": "alice"},
    )["Device"]
    assert admin == got
    assert provider.admin_list_devices(context, {"UserPoolId": pool["Id"], "Username": "alice"})[
        "Devices"
    ] == [got]
    provider.admin_update_device_status(
        context,
        {
            "DeviceKey": metadata["DeviceKey"],
            "DeviceRememberedStatus": "remembered",
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    provider.update_device_status(
        context,
        {
            "AccessToken": alice_tokens["AccessToken"],
            "DeviceKey": metadata["DeviceKey"],
            "DeviceRememberedStatus": "remembered",
        },
    )
    with cognito_idp_stores.lock:
        assert (
            provider.get_store(context)
            .user_pools[pool["Id"]]
            .users["alice"]
            .devices[metadata["DeviceKey"]]
            .remembered_status
            == "remembered"
        )

    bob_tokens = _auth(provider, context, client, "bob")
    with pytest.raises(CommonServiceException) as cross_user:
        provider.get_device(
            context,
            {"AccessToken": bob_tokens["AccessToken"], "DeviceKey": metadata["DeviceKey"]},
        )
    assert cross_user.value.code == "ResourceNotFoundException"
    with pytest.raises(CommonServiceException) as admin_cross_user:
        provider.admin_get_device(
            context,
            {"DeviceKey": metadata["DeviceKey"], "UserPoolId": pool["Id"], "Username": "bob"},
        )
    assert admin_cross_user.value.code == "ResourceNotFoundException"

    provider.admin_forget_device(
        context,
        {"DeviceKey": metadata["DeviceKey"], "UserPoolId": pool["Id"], "Username": "alice"},
    )
    with pytest.raises(CommonServiceException) as missing:
        provider.get_device(
            context,
            {"AccessToken": alice_tokens["AccessToken"], "DeviceKey": metadata["DeviceKey"]},
        )
    assert missing.value.code == "ResourceNotFoundException"


def test_device_list_tokens_are_hmac_bound_to_operation_user_and_pool(provider, context):
    pool, client = _stack(provider, context)
    alice_tokens = _auth(provider, context, client)
    first_metadata = alice_tokens["NewDeviceMetadata"]
    _confirm(provider, context, alice_tokens, first_metadata, name="one")
    second_tokens = _auth(provider, context, client)
    _confirm(provider, context, second_tokens, second_tokens["NewDeviceMetadata"], name="two")

    first = provider.list_devices(context, {"AccessToken": alice_tokens["AccessToken"], "Limit": 1})
    assert len(first["Devices"]) == 1
    assert first["PaginationToken"]
    second = provider.list_devices(
        context,
        {
            "AccessToken": alice_tokens["AccessToken"],
            "Limit": 1,
            "PaginationToken": first["PaginationToken"],
        },
    )
    assert len(second["Devices"]) == 1
    assert second["Devices"][0]["DeviceKey"] != first["Devices"][0]["DeviceKey"]

    bob_tokens = _auth(provider, context, client, "bob")
    for call in (
        lambda: provider.list_devices(
            context,
            {
                "AccessToken": bob_tokens["AccessToken"],
                "Limit": 1,
                "PaginationToken": first["PaginationToken"],
            },
        ),
        lambda: provider.admin_list_devices(
            context,
            {
                "Limit": 1,
                "PaginationToken": first["PaginationToken"],
                "UserPoolId": pool["Id"],
                "Username": "alice",
            },
        ),
    ):
        with pytest.raises(CommonServiceException) as invalid:
            call()
        assert invalid.value.code == "InvalidParameterException"


def test_pending_device_expiry_quota_and_cleanup(provider, context, monkeypatch):
    pool, client = _stack(provider, context)
    tokens = _auth(provider, context, client)
    metadata = tokens["NewDeviceMetadata"]
    with cognito_idp_stores.lock:
        store = provider.get_store(context)
        pending = next(iter(store.pending_devices.values()))
        pending.expires_at = provider_module._now() - timedelta(seconds=1)
    with pytest.raises(CommonServiceException) as expired:
        _confirm(provider, context, tokens, metadata)
    assert expired.value.code == "ResourceNotFoundException"

    monkeypatch.setattr(provider_module, "_MAX_PENDING_DEVICES_PER_STORE", 1)
    evicted = _auth(provider, context, client)["NewDeviceMetadata"]
    latest_tokens = _auth(provider, context, client)
    with cognito_idp_stores.lock:
        assert len(provider.get_store(context).pending_devices) == 1
    with pytest.raises(CommonServiceException) as old_pending:
        _confirm(provider, context, tokens, evicted)
    assert old_pending.value.code == "ResourceNotFoundException"

    latest_metadata = latest_tokens["NewDeviceMetadata"]
    _confirm(provider, context, latest_tokens, latest_metadata)
    monkeypatch.setattr(provider_module, "_MAX_DEVICES_PER_USER", 1)
    overflow_tokens = _auth(provider, context, client)
    with pytest.raises(CommonServiceException) as quota:
        _confirm(provider, context, overflow_tokens, overflow_tokens["NewDeviceMetadata"])
    assert quota.value.code == "LimitExceededException"

    provider.delete_user_pool(context, {"UserPoolId": pool["Id"]})
    with cognito_idp_stores.lock:
        assert not provider.get_store(context).pending_devices


def test_user_settings_fail_closed_and_auth_factors(provider, context):
    pool, client = _stack(provider, context)
    tokens = _auth(provider, context, client)
    assert (
        provider.set_user_settings(
            context, {"AccessToken": tokens["AccessToken"], "MFAOptions": []}
        )
        == {}
    )
    assert (
        provider.admin_set_user_settings(
            context, {"MFAOptions": [], "UserPoolId": pool["Id"], "Username": "alice"}
        )
        == {}
    )
    with pytest.raises(CommonServiceException) as sms:
        provider.set_user_settings(
            context,
            {
                "AccessToken": tokens["AccessToken"],
                "MFAOptions": [{"AttributeName": "phone_number", "DeliveryMedium": "SMS"}],
            },
        )
    assert sms.value.code == "InvalidParameterException"

    factors = provider.get_user_auth_factors(context, {"AccessToken": tokens["AccessToken"]})
    assert factors == {"ConfiguredUserAuthFactors": ["PASSWORD"], "Username": "alice"}
