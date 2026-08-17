import threading

import pytest

from localstack.services.cognito_idp.friendly_device_names import (
    FriendlyDeviceNameError,
    FriendlyDeviceNames,
)


def test_name_is_persisted_by_pool_and_user_and_survives_store_reconstruction():
    state = {}
    names = FriendlyDeviceNames(state)
    names.set("pool-a", "user-a", "Cassio's authenticator")

    assert FriendlyDeviceNames(state).get("pool-a", "user-a") == "Cassio's authenticator"
    assert names.get("pool-b", "user-a") is None


def test_official_string_bound_is_enforced_in_characters_and_utf8_bytes_atomically():
    state = {}
    names = FriendlyDeviceNames(state)
    names.set("pool", "user", "original")

    for invalid in ("x" * 131_073, "á" * 65_537):
        with pytest.raises(FriendlyDeviceNameError):
            names.set("pool", "user", invalid)
        assert names.get("pool", "user") == "original"


def test_concurrent_updates_are_complete_values_and_cleanup_is_scoped():
    state = {}
    lock = threading.RLock()
    names = FriendlyDeviceNames(state, lock=lock)
    values = [f"authenticator-{index}" for index in range(20)]
    threads = [threading.Thread(target=names.set, args=("pool", "user", value)) for value in values]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert names.get("pool", "user") in values
    names.set("pool", "other", "keep")
    names.remove_user("pool", "user")
    assert names.get("pool", "user") is None
    assert names.get("pool", "other") == "keep"
    names.remove_pool("pool")
    assert state == {}


@pytest.mark.parametrize("pool_id,username", [("", "user"), ("pool", ""), (None, "user")])
def test_identity_keys_are_bounded(pool_id, username):
    with pytest.raises(FriendlyDeviceNameError):
        FriendlyDeviceNames({}).set(pool_id, username, "name")
