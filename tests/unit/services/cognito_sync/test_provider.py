import copy
import threading
from datetime import UTC, datetime, timedelta

import pytest

import localstack.services.cognito_sync.provider as sync_provider_module
from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_identity.models import cognito_identity_stores
from localstack.services.cognito_identity.provider import CognitoIdentityProvider
from localstack.services.cognito_sync.models import cognito_sync_stores
from localstack.services.cognito_sync.provider import (
    _MAX_SESSION_SNAPSHOT_BYTES_PER_IDENTITY,
    _MAX_SESSION_SNAPSHOT_RECORDS_PER_IDENTITY,
    _MAX_SESSIONS_PER_IDENTITY,
    CognitoSyncProvider,
    _scope_hash,
)
from localstack.services.plugins import Service


def _request(identity, dataset="profile", **overrides):
    pool_id, identity_id = identity
    return {
        "IdentityPoolId": pool_id,
        "IdentityId": identity_id,
        "DatasetName": dataset,
        **overrides,
    }


def _identity_request(identity, **overrides):
    return {
        "IdentityPoolId": identity[0],
        "IdentityId": identity[1],
        **overrides,
    }


def _session(provider, context, identity, dataset="profile", **overrides):
    return provider.list_records(context, _request(identity, dataset, **overrides))[
        "SyncSessionToken"
    ]


def _replace(key, value, sync_count=0, device_last_modified_date=None):
    patch = {"Key": key, "Op": "replace", "SyncCount": sync_count, "Value": value}
    if device_last_modified_date is not None:
        patch["DeviceLastModifiedDate"] = device_last_modified_date
    return patch


def test_dispatch_contains_all_native_operations(sync_provider):
    service = Service.for_provider(sync_provider)

    assert set(service.skeleton.dispatch_table) == {
        "BulkPublish",
        "DeleteDataset",
        "DescribeDataset",
        "DescribeIdentityPoolUsage",
        "DescribeIdentityUsage",
        "GetBulkPublishDetails",
        "GetCognitoEvents",
        "GetIdentityPoolConfiguration",
        "ListDatasets",
        "ListIdentityPoolUsage",
        "ListRecords",
        "RegisterDevice",
        "SetCognitoEvents",
        "SetIdentityPoolConfiguration",
        "SubscribeToDataset",
        "UnsubscribeFromDataset",
        "UpdateRecords",
    }
    assert len(service.skeleton.dispatch_table) == 17


def test_update_auto_creates_dataset_and_crud_preserves_request(sync_provider, context, identity):
    device_time = datetime(2026, 1, 2, 3, 4, tzinfo=UTC)
    token = _session(sync_provider, context, identity)
    request = _request(
        identity,
        DeviceId="mobile-device",
        RecordPatches=[_replace("theme", "dark", device_last_modified_date=device_time)],
        SyncSessionToken=token,
    )
    original = copy.deepcopy(request)

    updated = sync_provider.update_records(context, request)

    assert request == original
    assert updated["Records"] == [
        {
            "DeviceLastModifiedDate": device_time,
            "Key": "theme",
            "LastModifiedBy": "mobile-device",
            "LastModifiedDate": updated["Records"][0]["LastModifiedDate"],
            "SyncCount": 1,
            "Value": "dark",
        }
    ]
    described = sync_provider.describe_dataset(context, _request(identity))
    assert described["Dataset"]["DatasetName"] == "profile"
    assert described["Dataset"]["IdentityId"] == identity[1]
    assert described["Dataset"]["LastModifiedBy"] == "mobile-device"
    assert described["Dataset"]["NumRecords"] == 1
    assert described["Dataset"]["DataStorage"] == len(b"themedark")

    listed = sync_provider.list_records(context, _request(identity, LastSyncCount=0))
    assert listed["DatasetExists"] is True
    assert listed["DatasetDeletedAfterRequestedSyncCount"] is False
    assert listed["DatasetSyncCount"] == 1
    assert listed["Records"] == updated["Records"]

    deleted = sync_provider.delete_dataset(context, _request(identity))["Dataset"]
    assert deleted["DatasetName"] == "profile"
    after_delete = sync_provider.list_records(context, _request(identity, LastSyncCount=0))
    assert after_delete["DatasetExists"] is False
    assert after_delete["DatasetDeletedAfterRequestedSyncCount"] is True
    assert after_delete["DatasetSyncCount"] == 2
    with pytest.raises(CommonServiceException) as missing:
        sync_provider.describe_dataset(context, _request(identity))
    assert missing.value.code == "ResourceNotFoundException"
    with pytest.raises(CommonServiceException) as cannot_recreate_deleted:
        sync_provider.update_records(
            context,
            _request(
                identity,
                SyncSessionToken=after_delete["SyncSessionToken"],
                RecordPatches=[_replace("theme", "light", 0)],
            ),
        )
    assert cannot_recreate_deleted.value.code == "ResourceNotFoundException"
    already_synced = sync_provider.list_records(context, _request(identity, LastSyncCount=2))
    assert already_synced["DatasetDeletedAfterRequestedSyncCount"] is False
    with pytest.raises(CommonServiceException) as still_cannot_recreate:
        sync_provider.update_records(
            context,
            _request(
                identity,
                SyncSessionToken=already_synced["SyncSessionToken"],
                RecordPatches=[_replace("theme", "new", 0)],
            ),
        )
    assert still_cannot_recreate.value.code == "ResourceNotFoundException"


def test_update_is_atomic_and_stale_record_sync_count_conflicts(sync_provider, context, identity):
    token = _session(sync_provider, context, identity)
    created = sync_provider.update_records(
        context,
        _request(
            identity,
            SyncSessionToken=token,
            RecordPatches=[_replace("a", "one"), _replace("b", "two")],
        ),
    )
    assert {record["SyncCount"] for record in created["Records"]} == {1}
    token = _session(sync_provider, context, identity)

    with pytest.raises(CommonServiceException) as conflict:
        sync_provider.update_records(
            context,
            _request(
                identity,
                SyncSessionToken=token,
                RecordPatches=[_replace("a", "changed", 1), _replace("b", "stale", 0)],
            ),
        )
    assert conflict.value.code == "ResourceConflictException"

    unchanged = sync_provider.list_records(context, _request(identity, LastSyncCount=0))
    assert [
        (record["Key"], record["Value"], record["SyncCount"]) for record in unchanged["Records"]
    ] == [
        ("a", "one", 1),
        ("b", "two", 1),
    ]
    assert unchanged["DatasetSyncCount"] == 1


def test_update_rejects_a_session_when_the_dataset_changed(sync_provider, context, identity):
    initial_token = _session(sync_provider, context, identity)
    sync_provider.update_records(
        context,
        _request(
            identity,
            SyncSessionToken=initial_token,
            RecordPatches=[_replace("a", "one")],
        ),
    )
    stale_token = _session(sync_provider, context, identity)
    current_token = _session(sync_provider, context, identity)
    sync_provider.update_records(
        context,
        _request(
            identity,
            SyncSessionToken=current_token,
            RecordPatches=[_replace("b", "two")],
        ),
    )

    with pytest.raises(CommonServiceException) as conflict:
        sync_provider.update_records(
            context,
            _request(identity, SyncSessionToken=stale_token),
        )
    assert conflict.value.code == "ResourceConflictException"


def test_replace_remove_resurrection_and_monotonic_dataset_sync_count(
    sync_provider, context, identity
):
    token = _session(sync_provider, context, identity)
    first = sync_provider.update_records(
        context,
        _request(
            identity,
            SyncSessionToken=token,
            RecordPatches=[_replace("key", "value")],
        ),
    )["Records"][0]
    token = _session(sync_provider, context, identity)
    removed = sync_provider.update_records(
        context,
        _request(
            identity,
            DeviceId="device-2",
            SyncSessionToken=token,
            RecordPatches=[{"Key": "key", "Op": "remove", "SyncCount": first["SyncCount"]}],
        ),
    )["Records"][0]
    assert removed["SyncCount"] == 2
    assert removed["LastModifiedBy"] == "device-2"
    assert "Value" not in removed

    token = _session(sync_provider, context, identity)
    resurrected = sync_provider.update_records(
        context,
        _request(
            identity,
            SyncSessionToken=token,
            RecordPatches=[_replace("key", "again", removed["SyncCount"])],
        ),
    )["Records"][0]
    assert resurrected["SyncCount"] == 3
    assert resurrected["Value"] == "again"
    assert sync_provider.describe_dataset(context, _request(identity))["Dataset"]["NumRecords"] == 1


def test_session_and_page_tokens_are_scope_bound_reused_and_expire(context, identity):
    now = datetime(2026, 1, 1, tzinfo=UTC)

    def clock():
        return now

    provider = CognitoSyncProvider(clock=clock)
    token = _session(provider, context, identity)
    provider.update_records(
        context,
        _request(
            identity,
            SyncSessionToken=token,
            RecordPatches=[_replace("a", "1"), _replace("b", "2")],
        ),
    )
    first = provider.list_records(context, _request(identity, MaxResults=1))
    assert identity[0] not in first["SyncSessionToken"]
    assert identity[1] not in first["SyncSessionToken"]
    mutation_token = _session(provider, context, identity)
    provider.update_records(
        context,
        _request(
            identity,
            SyncSessionToken=mutation_token,
            RecordPatches=[_replace("b", "changed-after-session", 1)],
        ),
    )
    second = provider.list_records(
        context,
        _request(
            identity,
            MaxResults=1,
            NextToken=first["NextToken"],
            SyncSessionToken=first["SyncSessionToken"],
        ),
    )
    assert first["SyncSessionToken"] == second["SyncSessionToken"]
    assert [record["Key"] for record in first["Records"] + second["Records"]] == ["a", "b"]
    assert second["Records"][0]["Value"] == "2"
    assert second["DatasetSyncCount"] == 1
    assert "NextToken" not in second

    with pytest.raises(CommonServiceException) as wrong_dataset:
        provider.list_records(
            context,
            _request(identity, "other", SyncSessionToken=first["SyncSessionToken"]),
        )
    assert wrong_dataset.value.code == "InvalidParameterException"

    now += timedelta(minutes=16)
    with pytest.raises(CommonServiceException) as expired:
        provider.update_records(
            context,
            _request(identity, SyncSessionToken=first["SyncSessionToken"]),
        )
    assert expired.value.code == "NotAuthorizedException"


def test_tokens_reject_tampering_empty_values_and_cross_identity_scope(
    sync_provider, context, identity
):
    token = _session(sync_provider, context, identity)
    tampered_token = ("A" if token[0] != "A" else "B") + token[1:]
    with pytest.raises(CommonServiceException) as tampered_session:
        sync_provider.update_records(
            context,
            _request(identity, SyncSessionToken=tampered_token),
        )
    assert tampered_session.value.code == "InvalidParameterException"

    created = sync_provider.update_records(
        context,
        _request(
            identity,
            SyncSessionToken=token,
            RecordPatches=[_replace("a", "1"), _replace("b", "2")],
        ),
    )
    assert len(created["Records"]) == 2
    first = sync_provider.list_records(context, _request(identity, MaxResults=1))
    next_token = first["NextToken"]
    tampered_next_token = ("A" if next_token[0] != "A" else "B") + next_token[1:]
    with pytest.raises(CommonServiceException) as tampered_page:
        sync_provider.list_records(
            context,
            _request(
                identity,
                MaxResults=1,
                NextToken=tampered_next_token,
                SyncSessionToken=first["SyncSessionToken"],
            ),
        )
    assert tampered_page.value.code == "InvalidParameterException"

    for field in ("NextToken", "SyncSessionToken"):
        with pytest.raises(CommonServiceException) as empty:
            sync_provider.list_records(context, _request(identity, **{field: ""}))
        assert empty.value.code == "InvalidParameterException"


def test_dataset_and_storage_limits_fail_without_partial_write(sync_provider, context, identity):
    for index in range(20):
        dataset = f"dataset-{index:02d}"
        token = _session(sync_provider, context, identity, dataset)
        sync_provider.update_records(
            context,
            _request(
                identity,
                dataset,
                SyncSessionToken=token,
                RecordPatches=[_replace("k", "v")],
            ),
        )

    token = _session(sync_provider, context, identity, "dataset-over-limit")
    with pytest.raises(CommonServiceException) as dataset_limit:
        sync_provider.update_records(
            context,
            _request(identity, "dataset-over-limit", SyncSessionToken=token),
        )
    assert dataset_limit.value.code == "LimitExceededException"
    assert sync_provider.list_datasets(context, _identity_request(identity))["Count"] == 20

    token = _session(sync_provider, context, identity, "dataset-00")
    with pytest.raises(CommonServiceException) as storage_limit:
        sync_provider.update_records(
            context,
            _request(
                identity,
                "dataset-00",
                SyncSessionToken=token,
                RecordPatches=[_replace("large", "x" * (1024 * 1024 - 1))],
            ),
        )
    assert storage_limit.value.code == "LimitExceededException"
    existing = sync_provider.list_records(
        context, _request(identity, "dataset-00", LastSyncCount=0)
    )
    assert [(record["Key"], record["Value"]) for record in existing["Records"]] == [("k", "v")]

    token = _session(sync_provider, context, identity, "dataset-00")
    with pytest.raises(CommonServiceException) as record_limit:
        sync_provider.update_records(
            context,
            _request(
                identity,
                "dataset-00",
                SyncSessionToken=token,
                RecordPatches=[_replace(f"key-{index:04d}", "v") for index in range(1024)],
            ),
        )
    assert record_limit.value.code == "LimitExceededException"


def test_dataset_allows_exactly_one_mib_and_preserves_it_after_overflow(
    sync_provider, context, identity
):
    token = _session(sync_provider, context, identity, "exact")
    sync_provider.update_records(
        context,
        _request(
            identity,
            "exact",
            SyncSessionToken=token,
            RecordPatches=[_replace("k", "x" * (1024 * 1024 - 1))],
        ),
    )
    assert (
        sync_provider.describe_dataset(context, _request(identity, "exact"))["Dataset"][
            "DataStorage"
        ]
        == 1024 * 1024
    )

    token = _session(sync_provider, context, identity, "exact")
    with pytest.raises(CommonServiceException) as overflow:
        sync_provider.update_records(
            context,
            _request(
                identity,
                "exact",
                SyncSessionToken=token,
                RecordPatches=[_replace("another", "v")],
            ),
        )
    assert overflow.value.code == "LimitExceededException"
    assert (
        sync_provider.describe_dataset(context, _request(identity, "exact"))["Dataset"][
            "DataStorage"
        ]
        == 1024 * 1024
    )


def test_concurrent_dataset_creation_enforces_the_twenty_dataset_quota(
    sync_provider, context, identity
):
    datasets = [f"race-{index:02d}" for index in range(21)]
    tokens = {name: _session(sync_provider, context, identity, name) for name in datasets}
    barrier = threading.Barrier(len(datasets))
    outcomes = []

    def create(name):
        barrier.wait()
        try:
            sync_provider.update_records(
                context,
                _request(identity, name, SyncSessionToken=tokens[name]),
            )
            outcomes.append("ok")
        except CommonServiceException as error:
            outcomes.append(error.code)

    threads = [threading.Thread(target=create, args=(name,)) for name in datasets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert sorted(outcomes) == ["LimitExceededException"] + ["ok"] * 20
    assert sync_provider.list_datasets(context, _identity_request(identity))["Count"] == 20


def test_session_cache_is_bounded_per_identity(sync_provider, context, identity):
    token = _session(sync_provider, context, identity)
    sync_provider.update_records(
        context,
        _request(
            identity,
            SyncSessionToken=token,
            RecordPatches=[_replace("k", "x" * (1024 * 1024 - 1))],
        ),
    )

    for _ in range(_MAX_SESSIONS_PER_IDENTITY + 5):
        _session(sync_provider, context, identity)

    store = cognito_sync_stores[context.account_id][context.region]
    owned_sessions = [
        session
        for session in store.sessions.values()
        if session.scope_hash == _scope_hash(*identity)
    ]
    assert len(owned_sessions) <= _MAX_SESSIONS_PER_IDENTITY
    assert sum(session.snapshot_bytes for session in owned_sessions) <= (
        _MAX_SESSION_SNAPSHOT_BYTES_PER_IDENTITY
    )
    assert sum(session.snapshot_records for session in owned_sessions) <= (
        _MAX_SESSION_SNAPSHOT_RECORDS_PER_IDENTITY
    )


def test_session_cache_enforces_the_aggregate_store_budget(
    sync_provider, context, identity, monkeypatch
):
    token = _session(sync_provider, context, identity)
    sync_provider.update_records(
        context,
        _request(
            identity,
            SyncSessionToken=token,
            RecordPatches=[_replace("key", "value")],
        ),
    )
    store = cognito_sync_stores[context.account_id][context.region]
    baseline = len(store.sessions)
    baseline_digests = set(store.sessions)
    monkeypatch.setattr(sync_provider_module, "_MAX_SESSIONS_PER_IDENTITY", 1)
    monkeypatch.setattr(sync_provider_module, "_MAX_SESSION_SNAPSHOT_BYTES_PER_STORE", 1)

    with pytest.raises(CommonServiceException) as capacity:
        _session(sync_provider, context, identity)
    assert capacity.value.code == "TooManyRequestsException"
    assert len(store.sessions) == baseline
    assert set(store.sessions) == baseline_digests


def test_list_datasets_pagination_is_identity_scoped(sync_provider, context, identity):
    for name in ("a", "b", "c"):
        token = _session(sync_provider, context, identity, name)
        sync_provider.update_records(
            context,
            _request(identity, name, SyncSessionToken=token),
        )
    first = sync_provider.list_datasets(context, _identity_request(identity, MaxResults=2))
    second = sync_provider.list_datasets(
        context,
        _identity_request(identity, MaxResults=2, NextToken=first["NextToken"]),
    )
    assert [dataset["DatasetName"] for dataset in first["Datasets"] + second["Datasets"]] == [
        "a",
        "b",
        "c",
    ]
    assert first["Count"] == 2
    assert second["Count"] == 1

    identity_provider = CognitoIdentityProvider()
    other = identity_provider.get_id(context, {"IdentityPoolId": identity[0]})
    with pytest.raises(CommonServiceException) as wrong_scope:
        sync_provider.list_datasets(
            context,
            {
                "IdentityPoolId": identity[0],
                "IdentityId": other["IdentityId"],
                "MaxResults": 2,
                "NextToken": first["NextToken"],
            },
        )
    assert wrong_scope.value.code == "InvalidParameterException"


def test_requests_require_the_exact_live_pool_identity_binding(sync_provider, context, identity):
    wrong_context = RequestContext(None)
    wrong_context.account_id = f"{(int(context.account_id) + 1) % 10**12:012d}"
    wrong_context.region = context.region
    with pytest.raises(CommonServiceException) as wrong_account:
        sync_provider.list_records(wrong_context, _request(identity))
    assert wrong_account.value.code == "ResourceNotFoundException"
    assert wrong_context.account_id not in cognito_identity_stores
    assert wrong_context.account_id not in cognito_sync_stores

    second_pool = CognitoIdentityProvider().create_identity_pool(
        context,
        {
            "AllowUnauthenticatedIdentities": True,
            "IdentityPoolName": "other-sync-test",
        },
    )
    with pytest.raises(CommonServiceException) as wrong_pool:
        sync_provider.list_records(
            context,
            {
                "DatasetName": "profile",
                "IdentityId": identity[1],
                "IdentityPoolId": second_pool["IdentityPoolId"],
            },
        )
    assert wrong_pool.value.code == "ResourceNotFoundException"

    with cognito_identity_stores.lock:
        stored_identity = cognito_identity_stores[context.account_id][context.region].identities[
            identity[1]
        ]
        stored_identity.enabled = False
    with pytest.raises(CommonServiceException) as disabled:
        sync_provider.list_records(context, _request(identity))
    assert disabled.value.code == "ResourceNotFoundException"


def test_requests_cannot_cross_region_or_create_foreign_backends(sync_provider, context, identity):
    wrong_context = RequestContext(None)
    wrong_context.account_id = context.account_id
    wrong_context.region = "eu-west-1"

    with pytest.raises(CommonServiceException) as wrong_region:
        sync_provider.list_records(wrong_context, _request(identity))
    assert wrong_region.value.code == "InvalidParameterException"
    assert "eu-west-1" not in cognito_identity_stores[context.account_id]
    sync_bundle = cognito_sync_stores.get(context.account_id)
    assert sync_bundle is None or "eu-west-1" not in sync_bundle


def test_deleted_identity_pool_lazily_cleans_persisted_sync_state(sync_provider, context, identity):
    token = _session(sync_provider, context, identity)
    sync_provider.update_records(
        context,
        _request(
            identity,
            SyncSessionToken=token,
            RecordPatches=[_replace("key", "value")],
        ),
    )
    CognitoIdentityProvider().delete_identity_pool(context, {"IdentityPoolId": identity[0]})

    with pytest.raises(CommonServiceException) as deleted:
        sync_provider.list_records(context, _request(identity))
    assert deleted.value.code == "ResourceNotFoundException"
    with cognito_sync_stores.lock:
        store = cognito_sync_stores[context.account_id][context.region]
        assert not store.datasets
        assert not store.dataset_tombstones
        assert not store.sessions


def test_update_and_dataset_delete_are_serialized(sync_provider, context, identity):
    token = _session(sync_provider, context, identity)
    sync_provider.update_records(
        context,
        _request(
            identity,
            SyncSessionToken=token,
            RecordPatches=[_replace("key", "value")],
        ),
    )
    update_token = _session(sync_provider, context, identity)
    barrier = threading.Barrier(2)
    outcomes = []

    def update():
        barrier.wait()
        try:
            sync_provider.update_records(
                context,
                _request(
                    identity,
                    SyncSessionToken=update_token,
                    RecordPatches=[_replace("key", "changed", 1)],
                ),
            )
            outcomes.append("updated")
        except CommonServiceException as error:
            outcomes.append(error.code)

    def delete():
        barrier.wait()
        sync_provider.delete_dataset(context, _request(identity))
        outcomes.append("deleted")

    threads = [threading.Thread(target=target) for target in (update, delete)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert "deleted" in outcomes
    assert set(outcomes) <= {"deleted", "updated", "ResourceNotFoundException"}
    listed = sync_provider.list_records(context, _request(identity, LastSyncCount=0))
    assert listed["DatasetExists"] is False
    assert listed["DatasetDeletedAfterRequestedSyncCount"] is True


def test_update_and_identity_pool_delete_do_not_leave_orphaned_state(
    sync_provider, context, identity
):
    token = _session(sync_provider, context, identity)
    barrier = threading.Barrier(2)
    outcomes = []

    def update():
        barrier.wait()
        try:
            sync_provider.update_records(
                context,
                _request(
                    identity,
                    SyncSessionToken=token,
                    RecordPatches=[_replace("key", "value")],
                ),
            )
            outcomes.append("updated")
        except CommonServiceException as error:
            outcomes.append(error.code)

    def delete_pool():
        barrier.wait()
        CognitoIdentityProvider().delete_identity_pool(context, {"IdentityPoolId": identity[0]})
        outcomes.append("deleted")

    threads = [threading.Thread(target=target) for target in (update, delete_pool)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert "deleted" in outcomes
    assert set(outcomes) <= {"deleted", "updated", "ResourceNotFoundException"}
    with pytest.raises(CommonServiceException) as missing:
        sync_provider.list_records(context, _request(identity))
    assert missing.value.code == "ResourceNotFoundException"
    store = cognito_sync_stores[context.account_id][context.region]
    assert not store.datasets
    assert not store.dataset_tombstones
    assert not store.sessions


@pytest.mark.parametrize(
    "overrides",
    [
        {"DatasetName": "bad/name"},
        {
            "SyncSessionToken": "token",
            "RecordPatches": [{"Key": "", "Op": "replace", "SyncCount": 0, "Value": "v"}],
        },
        {
            "SyncSessionToken": "token",
            "RecordPatches": [{"Key": "k", "Op": "replace", "SyncCount": 0}],
        },
        {
            "SyncSessionToken": "token",
            "RecordPatches": [{"Key": "k", "Op": "remove", "SyncCount": 0, "Value": "v"}],
        },
        {
            "SyncSessionToken": "token",
            "RecordPatches": [{"Key": "k", "Op": "replace", "SyncCount": -1, "Value": "v"}],
        },
        {
            "SyncSessionToken": "token",
            "RecordPatches": [
                {"Key": "k", "Op": "replace", "SyncCount": 0, "Value": "v"},
                {"Key": "k", "Op": "remove", "SyncCount": 0},
            ],
        },
        {"SyncSessionToken": "token", "ClientContext": "unsupported"},
    ],
)
def test_update_validation_fails_before_dataset_creation(
    sync_provider, context, identity, overrides
):
    request = _request(identity, **overrides)
    with pytest.raises(CommonServiceException) as invalid:
        sync_provider.update_records(context, request)
    assert invalid.value.code == "InvalidParameterException"
    with pytest.raises(CommonServiceException) as missing:
        sync_provider.describe_dataset(context, _request(identity))
    assert missing.value.code == "ResourceNotFoundException"


def test_concurrent_updates_to_the_same_record_have_one_winner(sync_provider, context, identity):
    token = _session(sync_provider, context, identity)
    barrier = threading.Barrier(2)
    outcomes = []

    def update(value):
        barrier.wait()
        try:
            result = sync_provider.update_records(
                context,
                _request(
                    identity,
                    SyncSessionToken=token,
                    RecordPatches=[_replace("race", value)],
                ),
            )
            outcomes.append(("ok", result["Records"][0]["Value"]))
        except CommonServiceException as error:
            outcomes.append((error.code, value))

    threads = [threading.Thread(target=update, args=(value,)) for value in ("one", "two")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert sorted(outcome[0] for outcome in outcomes) == ["ResourceConflictException", "ok"]
