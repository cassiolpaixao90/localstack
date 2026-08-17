import localstack.services.cognito_sync.provider as sync_provider_module
from localstack.services.cognito_sync.models import cognito_sync_stores
from localstack.services.cognito_sync.provider import CognitoSyncProvider
from localstack.state import pickle
from localstack.state.inspect import ServiceBackendCollectorVisitor


def test_store_and_token_secret_survive_pickle_roundtrip(sync_provider, context, identity):
    listed = sync_provider.list_records(
        context,
        {
            "IdentityPoolId": identity[0],
            "IdentityId": identity[1],
            "DatasetName": "persistent",
        },
    )
    sync_provider.update_records(
        context,
        {
            "IdentityPoolId": identity[0],
            "IdentityId": identity[1],
            "DatasetName": "persistent",
            "RecordPatches": [{"Key": "key", "Op": "replace", "SyncCount": 0, "Value": "value"}],
            "SyncSessionToken": listed["SyncSessionToken"],
        },
    )

    restored = pickle.loads(pickle.dumps(cognito_sync_stores))
    store = restored[context.account_id][context.region]
    dataset = store.datasets[(identity[0], identity[1], "persistent")]

    assert dataset.records["key"].value == "value"
    assert dataset.sync_count == 1
    assert len(store.token_secret) == 32


def test_session_and_cursor_continue_after_pickle_roundtrip(
    sync_provider, context, identity, monkeypatch
):
    initial = sync_provider.list_records(
        context,
        {
            "IdentityPoolId": identity[0],
            "IdentityId": identity[1],
            "DatasetName": "persistent-pages",
        },
    )
    sync_provider.update_records(
        context,
        {
            "IdentityPoolId": identity[0],
            "IdentityId": identity[1],
            "DatasetName": "persistent-pages",
            "RecordPatches": [
                {"Key": "a", "Op": "replace", "SyncCount": 0, "Value": "1"},
                {"Key": "b", "Op": "replace", "SyncCount": 0, "Value": "2"},
            ],
            "SyncSessionToken": initial["SyncSessionToken"],
        },
    )
    first = sync_provider.list_records(
        context,
        {
            "IdentityPoolId": identity[0],
            "IdentityId": identity[1],
            "DatasetName": "persistent-pages",
            "MaxResults": 1,
        },
    )
    restored = pickle.loads(pickle.dumps(cognito_sync_stores))
    monkeypatch.setattr(sync_provider_module, "cognito_sync_stores", restored)

    second = CognitoSyncProvider().list_records(
        context,
        {
            "IdentityPoolId": identity[0],
            "IdentityId": identity[1],
            "DatasetName": "persistent-pages",
            "MaxResults": 1,
            "NextToken": first["NextToken"],
            "SyncSessionToken": first["SyncSessionToken"],
        },
    )

    assert [record["Key"] for record in first["Records"] + second["Records"]] == ["a", "b"]
    assert second["SyncSessionToken"] == first["SyncSessionToken"]


def test_provider_persistence_visits_only_the_sync_store():
    visitor = ServiceBackendCollectorVisitor()

    CognitoSyncProvider().accept_state_visitor(visitor)

    assert visitor.store is cognito_sync_stores
    assert visitor.backend_dict is None


def test_pool_configuration_device_and_subscription_survive_pickle_roundtrip(
    sync_provider, context, identity
):
    push_sync = {
        "ApplicationArns": [f"arn:aws:sns:{context.region}:{context.account_id}:app/GCM/mobile"],
        "RoleArn": f"arn:aws:iam::{context.account_id}:role/cognito-sync-push",
    }
    sync_provider.set_identity_pool_configuration(
        context, {"IdentityPoolId": identity[0], "PushSync": push_sync}
    )
    device_id = sync_provider.register_device(
        context,
        {
            "IdentityPoolId": identity[0],
            "IdentityId": identity[1],
            "Platform": "GCM",
            "Token": "persistent-push-token",
        },
    )["DeviceId"]
    sync_provider.subscribe_to_dataset(
        context,
        {
            "DatasetName": "persistent-subscription",
            "DeviceId": device_id,
            "IdentityId": identity[1],
            "IdentityPoolId": identity[0],
        },
    )

    restored = pickle.loads(pickle.dumps(cognito_sync_stores))
    store = restored[context.account_id][context.region]

    assert store.pool_configurations[identity[0]].push_sync == push_sync
    assert store.devices[device_id].token == "persistent-push-token"
    assert (
        store.device_index[(identity[0], identity[1], "GCM", "persistent-push-token")] == device_id
    )
    assert store.subscriptions == {(identity[0], identity[1], "persistent-subscription", device_id)}
