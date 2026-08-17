import concurrent.futures
import copy
from datetime import UTC

import pytest

import localstack.services.cognito_sync.provider as sync_provider_module
from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_identity.provider import CognitoIdentityProvider
from localstack.services.cognito_sync.models import cognito_sync_stores
from localstack.services.cognito_sync.provider import CognitoSyncProvider
from localstack.state import pickle


def _identity_request(identity, **overrides):
    return {
        "IdentityPoolId": identity[0],
        "IdentityId": identity[1],
        **overrides,
    }


def _dataset_request(identity, dataset="profile", **overrides):
    return _identity_request(identity, DatasetName=dataset, **overrides)


def _create_dataset(provider, context, identity, dataset="profile"):
    listed = provider.list_records(context, _dataset_request(identity, dataset))
    return provider.update_records(
        context,
        _dataset_request(
            identity,
            dataset,
            RecordPatches=[
                {"Key": "language", "Op": "replace", "SyncCount": 0, "Value": "pt-BR"},
                {"Key": "theme", "Op": "replace", "SyncCount": 0, "Value": "dark"},
            ],
            SyncSessionToken=listed["SyncSessionToken"],
        ),
    )


def _push_sync(context):
    return {
        "ApplicationArns": [f"arn:aws:sns:{context.region}:{context.account_id}:app/GCM/mobile"],
        "RoleArn": f"arn:aws:iam::{context.account_id}:role/cognito-sync-push",
    }


def _stream(context, status="ENABLED"):
    return {
        "RoleArn": f"arn:aws:iam::{context.account_id}:role/cognito-sync-stream",
        "StreamName": "sync-stream",
        "StreamingStatus": status,
    }


def test_usage_describe_and_hmac_paginated_pool_listing(sync_provider, context, identity):
    _create_dataset(sync_provider, context, identity)
    identity_provider = CognitoIdentityProvider()
    second_pool = identity_provider.create_identity_pool(
        context,
        {
            "AllowUnauthenticatedIdentities": True,
            "IdentityPoolName": "second-sync-pool",
        },
    )

    identity_usage = sync_provider.describe_identity_usage(context, _identity_request(identity))[
        "IdentityUsage"
    ]
    assert identity_usage == {
        "DatasetCount": 1,
        "DataStorage": len(b"languagept-BRthemedark"),
        "IdentityId": identity[1],
        "IdentityPoolId": identity[0],
        "LastModifiedDate": identity_usage["LastModifiedDate"],
    }
    assert identity_usage["LastModifiedDate"].tzinfo == UTC

    pool_usage = sync_provider.describe_identity_pool_usage(
        context, {"IdentityPoolId": identity[0]}
    )["IdentityPoolUsage"]
    assert pool_usage["DataStorage"] == identity_usage["DataStorage"]
    assert pool_usage["IdentityPoolId"] == identity[0]
    assert pool_usage["SyncSessionsCount"] >= 1

    first = sync_provider.list_identity_pool_usage(context, {"MaxResults": 1})
    second = sync_provider.list_identity_pool_usage(
        context, {"MaxResults": 1, "NextToken": first["NextToken"]}
    )
    assert first["Count"] == second["Count"] == 1
    assert first["MaxResults"] == second["MaxResults"] == 1
    assert {
        item["IdentityPoolId"]
        for item in first["IdentityPoolUsages"] + second["IdentityPoolUsages"]
    } == {identity[0], second_pool["IdentityPoolId"]}
    assert "NextToken" not in second

    token = first["NextToken"]
    tampered = ("A" if token[0] != "A" else "B") + token[1:]
    with pytest.raises(CommonServiceException) as invalid:
        sync_provider.list_identity_pool_usage(context, {"MaxResults": 1, "NextToken": tampered})
    assert invalid.value.code == "InvalidParameterException"
    body, signature = token.split(".")
    with pytest.raises(CommonServiceException) as noncanonical:
        sync_provider.list_identity_pool_usage(
            context, {"MaxResults": 1, "NextToken": f"{body}=.{signature}"}
        )
    assert noncanonical.value.code == "InvalidParameterException"

    regional_context = RequestContext(None)
    regional_context.account_id = context.account_id
    regional_context.region = "eu-west-1"
    identity_provider.create_identity_pool(
        regional_context,
        {
            "AllowUnauthenticatedIdentities": True,
            "IdentityPoolName": "regional-sync-pool",
        },
    )
    with pytest.raises(CommonServiceException) as wrong_region:
        sync_provider.list_identity_pool_usage(
            regional_context, {"MaxResults": 1, "NextToken": token}
        )
    assert wrong_region.value.code == "InvalidParameterException"


def test_usage_rejects_foreign_account_region_and_binding_without_creating_backends(
    sync_provider, context, identity
):
    wrong_account = RequestContext(None)
    wrong_account.account_id = f"{(int(context.account_id) + 1) % 10**12:012d}"
    wrong_account.region = context.region
    with pytest.raises(CommonServiceException) as foreign:
        sync_provider.describe_identity_pool_usage(wrong_account, {"IdentityPoolId": identity[0]})
    assert foreign.value.code == "ResourceNotFoundException"
    assert wrong_account.account_id not in cognito_sync_stores

    wrong_region = RequestContext(None)
    wrong_region.account_id = context.account_id
    wrong_region.region = "eu-west-1"
    with pytest.raises(CommonServiceException) as region:
        sync_provider.describe_identity_usage(wrong_region, _identity_request(identity))
    assert region.value.code == "InvalidParameterException"
    assert "eu-west-1" not in cognito_sync_stores[context.account_id]


def test_cognito_events_roundtrip_removal_persistence_and_fail_closed_callback(
    sync_provider, context, identity, monkeypatch
):
    pool_id = identity[0]
    function_arn = f"arn:aws:lambda:{context.region}:{context.account_id}:function:sync-trigger"
    assert sync_provider.get_cognito_events(context, {"IdentityPoolId": pool_id}) == {"Events": {}}
    request = {"IdentityPoolId": pool_id, "Events": {"SyncTrigger": function_arn}}
    original = copy.deepcopy(request)
    assert sync_provider.set_cognito_events(context, request) == {}
    assert request == original
    assert sync_provider.get_cognito_events(context, {"IdentityPoolId": pool_id}) == {
        "Events": {"SyncTrigger": function_arn}
    }

    restored = pickle.loads(pickle.dumps(cognito_sync_stores))
    monkeypatch.setattr(sync_provider_module, "cognito_sync_stores", restored)
    restored_provider = CognitoSyncProvider()
    assert restored_provider.get_cognito_events(context, {"IdentityPoolId": pool_id})["Events"] == {
        "SyncTrigger": function_arn
    }

    session = restored_provider.list_records(context, _dataset_request(identity))
    with pytest.raises(CommonServiceException) as callback:
        restored_provider.update_records(
            context,
            _dataset_request(
                identity,
                RecordPatches=[{"Key": "key", "Op": "replace", "SyncCount": 0, "Value": "value"}],
                SyncSessionToken=session["SyncSessionToken"],
            ),
        )
    assert callback.value.code == "InvalidConfigurationException"
    assert not restored[context.account_id][context.region].datasets

    restored_provider.set_cognito_events(
        context, {"IdentityPoolId": pool_id, "Events": {"SyncTrigger": ""}}
    )
    assert restored_provider.get_cognito_events(context, {"IdentityPoolId": pool_id}) == {
        "Events": {}
    }


@pytest.mark.parametrize(
    "events",
    [
        {"Other": "arn"},
        {"SyncTrigger": "not-an-arn"},
        {"SyncTrigger": "arn:aws:lambda:us-east-1:000000000000:function:foreign"},
        {"SyncTrigger": "arn:aws:lambda:eu-west-1:000000000000:function:foreign"},
        {"SyncTrigger": "arn", "Other": "arn"},
    ],
)
def test_cognito_events_invalid_values_do_not_mutate(sync_provider, context, identity, events):
    with pytest.raises(CommonServiceException) as invalid:
        sync_provider.set_cognito_events(context, {"IdentityPoolId": identity[0], "Events": events})
    assert invalid.value.code == "InvalidParameterException"
    assert sync_provider.get_cognito_events(context, {"IdentityPoolId": identity[0]}) == {
        "Events": {}
    }


def test_pool_configuration_partial_updates_roundtrip_and_validate_closed_shapes(
    sync_provider, context, identity
):
    pool_id = identity[0]
    assert sync_provider.get_identity_pool_configuration(context, {"IdentityPoolId": pool_id}) == {
        "IdentityPoolId": pool_id
    }
    request = {"IdentityPoolId": pool_id, "PushSync": _push_sync(context)}
    original = copy.deepcopy(request)
    first = sync_provider.set_identity_pool_configuration(context, request)
    assert request == original
    assert first == {"IdentityPoolId": pool_id, "PushSync": _push_sync(context)}

    second = sync_provider.set_identity_pool_configuration(
        context, {"IdentityPoolId": pool_id, "CognitoStreams": _stream(context, "DISABLED")}
    )
    assert second == {
        "CognitoStreams": _stream(context, "DISABLED"),
        "IdentityPoolId": pool_id,
        "PushSync": _push_sync(context),
    }
    assert (
        sync_provider.get_identity_pool_configuration(context, {"IdentityPoolId": pool_id})
        == second
    )

    invalid_configurations = [
        {"PushSync": {"Extra": "value"}},
        {"PushSync": {"ApplicationArns": ["bad"]}},
        {"PushSync": {"RoleArn": "bad"}},
        {"CognitoStreams": {"StreamName": "only-name"}},
        {"CognitoStreams": {**_stream(context), "Extra": "value"}},
    ]
    for configuration in invalid_configurations:
        with pytest.raises(CommonServiceException) as invalid:
            sync_provider.set_identity_pool_configuration(
                context, {"IdentityPoolId": pool_id, **configuration}
            )
        assert invalid.value.code in {
            "InvalidConfigurationException",
            "InvalidParameterException",
        }
    assert (
        sync_provider.get_identity_pool_configuration(context, {"IdentityPoolId": pool_id})
        == second
    )


def test_device_registration_subscription_idempotency_isolation_and_local_only_state(
    sync_provider, context, identity, monkeypatch
):
    sync_provider.set_identity_pool_configuration(
        context, {"IdentityPoolId": identity[0], "PushSync": _push_sync(context)}
    )
    request = _identity_request(identity, Platform="GCM", Token="push-token")
    first = sync_provider.register_device(context, request)
    second = sync_provider.register_device(context, request)
    assert first == second
    assert 1 <= len(first["DeviceId"]) <= 256

    subscription = _dataset_request(identity, DeviceId=first["DeviceId"])
    assert sync_provider.subscribe_to_dataset(context, subscription) == {}
    assert sync_provider.subscribe_to_dataset(context, subscription) == {}
    store = cognito_sync_stores[context.account_id][context.region]
    assert (identity[0], identity[1], "profile", first["DeviceId"]) in store.subscriptions

    monkeypatch.setattr(sync_provider_module, "_MAX_SUBSCRIPTIONS_PER_DEVICE", 1)
    with pytest.raises(CommonServiceException) as subscription_limit:
        sync_provider.subscribe_to_dataset(
            context,
            _dataset_request(identity, "other", DeviceId=first["DeviceId"]),
        )
    assert subscription_limit.value.code == "LimitExceededException"
    assert len(store.subscriptions) == 1

    other = CognitoIdentityProvider().get_id(context, {"IdentityPoolId": identity[0]})["IdentityId"]
    with pytest.raises(CommonServiceException) as wrong_identity:
        sync_provider.subscribe_to_dataset(
            context,
            {
                "IdentityPoolId": identity[0],
                "IdentityId": other,
                "DatasetName": "profile",
                "DeviceId": first["DeviceId"],
            },
        )
    assert wrong_identity.value.code == "ResourceNotFoundException"

    assert sync_provider.unsubscribe_from_dataset(context, subscription) == {}
    assert sync_provider.unsubscribe_from_dataset(context, subscription) == {}
    assert not store.subscriptions


def test_register_device_concurrency_and_caps_are_atomic(
    sync_provider, context, identity, monkeypatch
):
    sync_provider.set_identity_pool_configuration(
        context, {"IdentityPoolId": identity[0], "PushSync": _push_sync(context)}
    )
    request = _identity_request(identity, Platform="GCM", Token="same-token")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(lambda _: sync_provider.register_device(context, request), range(16))
        )
    assert len({result["DeviceId"] for result in results}) == 1

    monkeypatch.setattr(sync_provider_module, "_MAX_DEVICES_PER_IDENTITY", 1)
    with pytest.raises(CommonServiceException) as limit:
        sync_provider.register_device(
            context, _identity_request(identity, Platform="GCM", Token="other-token")
        )
    assert limit.value.code == "LimitExceededException"
    store = cognito_sync_stores[context.account_id][context.region]
    assert len(store.devices) == 1


def test_device_operations_fail_closed_without_push_configuration(sync_provider, context, identity):
    with pytest.raises(CommonServiceException) as configuration:
        sync_provider.register_device(
            context, _identity_request(identity, Platform="GCM", Token="push-token")
        )
    assert configuration.value.code == "InvalidConfigurationException"
    assert not cognito_sync_stores[context.account_id][context.region].devices


def test_bulk_publish_records_an_honest_failed_local_delivery_and_persists(
    sync_provider, context, identity
):
    pool_id = identity[0]
    assert sync_provider.get_bulk_publish_details(context, {"IdentityPoolId": pool_id}) == {
        "IdentityPoolId": pool_id,
        "BulkPublishStatus": "NOT_STARTED",
    }
    with pytest.raises(CommonServiceException) as missing_configuration:
        sync_provider.bulk_publish(context, {"IdentityPoolId": pool_id})
    assert missing_configuration.value.code == "InvalidConfigurationException"

    sync_provider.set_identity_pool_configuration(
        context, {"IdentityPoolId": pool_id, "CognitoStreams": _stream(context)}
    )
    assert sync_provider.bulk_publish(context, {"IdentityPoolId": pool_id}) == {
        "IdentityPoolId": pool_id
    }
    details = sync_provider.get_bulk_publish_details(context, {"IdentityPoolId": pool_id})
    assert details["BulkPublishStatus"] == "FAILED"
    assert details["BulkPublishStartTime"].tzinfo == UTC
    assert details["BulkPublishCompleteTime"] >= details["BulkPublishStartTime"]
    assert "not available" in details["FailureMessage"]

    restored = pickle.loads(pickle.dumps(cognito_sync_stores))
    restored_details = (
        restored[context.account_id][context.region].pool_configurations[pool_id].bulk_publish
    )
    assert restored_details.status == "FAILED"


def test_lazy_cleanup_removes_devices_subscriptions_and_pool_configuration(
    sync_provider, context, identity
):
    identity_provider = CognitoIdentityProvider()
    sync_provider.set_identity_pool_configuration(
        context, {"IdentityPoolId": identity[0], "PushSync": _push_sync(context)}
    )
    device = sync_provider.register_device(
        context, _identity_request(identity, Platform="GCM", Token="push-token")
    )
    sync_provider.subscribe_to_dataset(
        context, _dataset_request(identity, DeviceId=device["DeviceId"])
    )
    identity_provider.delete_identities(context, {"IdentityIdsToDelete": [identity[1]]})

    store = cognito_sync_stores[context.account_id][context.region]
    assert not store.devices
    assert not store.device_index
    assert not store.subscriptions
    with pytest.raises(CommonServiceException) as missing:
        sync_provider.describe_identity_usage(context, _identity_request(identity))
    assert missing.value.code == "ResourceNotFoundException"

    identity_provider.delete_identity_pool(context, {"IdentityPoolId": identity[0]})
    assert not store.pool_configurations
    assert sync_provider.list_identity_pool_usage(context, {}) == {
        "Count": 0,
        "IdentityPoolUsages": [],
        "MaxResults": sync_provider_module._DEFAULT_POOL_USAGE_RESULTS,
    }


@pytest.mark.parametrize(
    "operation,overrides",
    [
        ("list_identity_pool_usage", {"MaxResults": 0}),
        ("list_identity_pool_usage", {"MaxResults": 61}),
        ("register_device", {"Platform": "INVALID", "Token": "token"}),
        ("register_device", {"Platform": "GCM", "Token": ""}),
        ("subscribe_to_dataset", {"DatasetName": "bad/name", "DeviceId": "device"}),
        ("unsubscribe_from_dataset", {"DatasetName": "profile", "DeviceId": ""}),
    ],
)
def test_phase_two_bounds_fail_without_partial_mutation(
    sync_provider, context, identity, operation, overrides
):
    payload = (
        overrides
        if operation == "list_identity_pool_usage"
        else _identity_request(identity, **overrides)
    )
    with pytest.raises(CommonServiceException) as invalid:
        getattr(sync_provider, operation)(context, payload)
    assert invalid.value.code == "InvalidParameterException"
    store = cognito_sync_stores.get(context.account_id)
    if store is not None and context.region in store:
        assert not store[context.region].devices
        assert not store[context.region].subscriptions
