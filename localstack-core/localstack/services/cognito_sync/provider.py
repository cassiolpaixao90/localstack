import base64
import contextlib
import copy
import hashlib
import hmac
import json
import re
import secrets
import threading
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from localstack.aws.api import (
    CommonServiceException,
    RequestContext,
    ServiceRequest,
    ServiceResponse,
    handler,
)
from localstack.services.cognito_identity.models import cognito_identity_stores
from localstack.services.cognito_sync.models import (
    BulkPublishState,
    CognitoSyncStore,
    DatasetKey,
    DatasetTombstone,
    SyncDataset,
    SyncDevice,
    SyncPoolConfiguration,
    SyncRecord,
    SyncSession,
    cognito_sync_stores,
)
from localstack.state import StateVisitor

_DATASET_NAME_RE = re.compile(r"^[a-zA-Z0-9_.:-]+$")
_SCOPED_ID_RE = re.compile(r"^(?P<region>[\w-]+):(?P<uuid>[0-9a-f-]+)$")
_MAX_DATASETS_PER_IDENTITY = 20
_MAX_DATASET_BYTES = 1024 * 1024
_MAX_RECORDS_PER_DATASET = 1024
_MAX_RECORD_KEY_BYTES = 1024
_MAX_RECORD_VALUE_BYTES = 1024 * 1024 - 1
_MAX_PATCHES = 1024
_MAX_PAGE_RESULTS = 1024
_DEFAULT_PAGE_RESULTS = 100
_MAX_TOKEN_BYTES = 4096
_MAX_PUSH_TOKEN_BYTES = 4096
_MAX_DEVICES_PER_IDENTITY = 100
_MAX_SUBSCRIPTIONS_PER_DEVICE = 20
_MAX_PUSH_APPLICATIONS = 100
_MAX_POOL_USAGE_RESULTS = 60
_DEFAULT_POOL_USAGE_RESULTS = 10
_SUPPORTED_PUSH_PLATFORMS = {"ADM", "APNS", "APNS_SANDBOX", "GCM"}
_SESSION_TTL = timedelta(minutes=15)
_MAX_SESSIONS_PER_IDENTITY = 32
_MAX_SESSIONS_PER_STORE = 1024
_MAX_SESSION_SNAPSHOT_BYTES_PER_IDENTITY = 32 * 1024 * 1024
_MAX_SESSION_SNAPSHOT_BYTES_PER_STORE = 64 * 1024 * 1024
_MAX_SESSION_SNAPSHOT_RECORDS_PER_IDENTITY = 32 * 1024
_MAX_SESSION_SNAPSHOT_RECORDS_PER_STORE = 64 * 1024
_LOCKS_GUARD = threading.RLock()
_LOCKS: dict[str, tuple[threading.RLock, int]] = {}


@dataclass(frozen=True)
class _Patch:
    operation: str
    key: str
    value: str | None
    sync_count: int
    device_last_modified_date: datetime | None


@contextlib.contextmanager
def _named_guard(key: str) -> Iterator[None]:
    with _LOCKS_GUARD:
        lock, users = _LOCKS.get(key, (threading.RLock(), 0))
        _LOCKS[key] = (lock, users + 1)
    lock.acquire()
    try:
        yield
    finally:
        lock.release()
        with _LOCKS_GUARD:
            current_lock, current_users = _LOCKS[key]
            if current_lock is lock and current_users == 1:
                _LOCKS.pop(key)
            else:
                _LOCKS[key] = (current_lock, current_users - 1)


@contextlib.contextmanager
def _identity_dataset_guard(pool_id: str, identity_id: str, dataset_name: str | None):
    identity_key = f"identity\0{pool_id}\0{identity_id}"
    with _named_guard(identity_key):
        if dataset_name is None:
            yield
        else:
            with _named_guard(f"dataset\0{pool_id}\0{identity_id}\0{dataset_name}"):
                yield


class CognitoSyncProvider:
    service = "cognito-sync"

    def __init__(self, *, clock: Callable[[], datetime] | None = None):
        self._clock = clock or _utcnow

    def accept_state_visitor(self, visitor: StateVisitor) -> None:
        visitor.visit(cognito_sync_stores)

    def get_store(self, context: RequestContext) -> CognitoSyncStore:
        return cognito_sync_stores[context.account_id][context.region]

    @contextlib.contextmanager
    def _locked_pool(
        self,
        context: RequestContext,
        request: ServiceRequest,
    ) -> Iterator[tuple[CognitoSyncStore, str, Any]]:
        pool_id = _scoped_id(request.get("IdentityPoolId"), "IdentityPoolId", context.region)
        with _named_guard(f"pool\0{pool_id}"):
            with cognito_identity_stores.lock:
                identity_bundle = cognito_identity_stores.get(context.account_id)
                identity_store = (
                    identity_bundle.get(context.region) if identity_bundle is not None else None
                )
                pool = identity_store.identity_pools.get(pool_id) if identity_store else None
                pool_exists = pool is not None and identity_store.POOL_LOCATIONS.get(pool_id) == (
                    context.account_id,
                    context.region,
                )
                with cognito_sync_stores.lock:
                    sync_bundle = cognito_sync_stores.get(context.account_id)
                    store = sync_bundle.get(context.region) if sync_bundle is not None else None
                    if not pool_exists:
                        if store is not None:
                            _remove_pool_state(store, pool_id)
                        _error("ResourceNotFoundException", "Identity pool does not exist")
                    if store is None:
                        store = self.get_store(context)
                    yield store, pool_id, pool

    @contextlib.contextmanager
    def _locked_scope(
        self,
        context: RequestContext,
        request: ServiceRequest,
        *,
        dataset_required: bool,
    ) -> Iterator[tuple[CognitoSyncStore, str, str, str | None]]:
        pool_id = _scoped_id(request.get("IdentityPoolId"), "IdentityPoolId", context.region)
        identity_id = _scoped_id(request.get("IdentityId"), "IdentityId", context.region)
        dataset_name = _dataset_name(request.get("DatasetName")) if dataset_required else None
        with _identity_dataset_guard(pool_id, identity_id, dataset_name):
            with cognito_identity_stores.lock:
                identity_bundle = cognito_identity_stores.get(context.account_id)
                identity_store = (
                    identity_bundle.get(context.region) if identity_bundle is not None else None
                )
                pool = identity_store.identity_pools.get(pool_id) if identity_store else None
                identity = identity_store.identities.get(identity_id) if identity_store else None
                pool_exists = pool is not None and identity_store.POOL_LOCATIONS.get(pool_id) == (
                    context.account_id,
                    context.region,
                )
                identity_exists = (
                    pool is not None
                    and identity is not None
                    and identity.pool_id == pool_id
                    and identity_id in pool.identity_ids
                    and identity_store.IDENTITY_LOCATIONS.get(identity_id)
                    == (
                        context.account_id,
                        context.region,
                        pool_id,
                    )
                )
                identity_enabled = identity_exists and identity.enabled
                with cognito_sync_stores.lock:
                    sync_bundle = cognito_sync_stores.get(context.account_id)
                    store = sync_bundle.get(context.region) if sync_bundle is not None else None
                    if not pool_exists or not identity_exists:
                        if store is not None:
                            _remove_identity_state(store, pool_id, identity_id)
                        _error(
                            "ResourceNotFoundException",
                            "Identity pool or identity does not exist",
                        )
                    if not identity_enabled:
                        _error("ResourceNotFoundException", "Identity does not exist")
                    if store is None:
                        store = self.get_store(context)
                    yield store, pool_id, identity_id, dataset_name

    @handler("BulkPublish", expand=False)
    def bulk_publish(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityPoolId"})
        with self._locked_pool(context, request) as (store, pool_id, _):
            configuration = store.pool_configurations.get(pool_id)
            streams = configuration.cognito_streams if configuration is not None else None
            if not streams or streams.get("StreamingStatus") != "ENABLED":
                _error(
                    "InvalidConfigurationException",
                    "An enabled Cognito stream is required for bulk publish",
                )
            now = self._now()
            if configuration is None:
                configuration = _new_pool_configuration(now)
                store.pool_configurations[pool_id] = configuration
            configuration.bulk_publish = BulkPublishState(
                status="FAILED",
                start_time=now,
                complete_time=now,
                failure_message=(
                    "External Cognito Streams delivery is not available in the local emulator"
                ),
            )
            configuration.updated_at = now
            return {"IdentityPoolId": pool_id}

    @handler("DescribeIdentityPoolUsage", expand=False)
    def describe_identity_pool_usage(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityPoolId"})
        with self._locked_pool(context, request) as (store, pool_id, pool):
            _purge_expired_sessions(store, self._now())
            return {"IdentityPoolUsage": _pool_usage_response(store, pool_id, pool.updated_at)}

    @handler("DescribeIdentityUsage", expand=False)
    def describe_identity_usage(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityId", "IdentityPoolId"})
        with self._locked_scope(context, request, dataset_required=False) as (
            store,
            pool_id,
            identity_id,
            _,
        ):
            return {"IdentityUsage": _identity_usage_response(store, pool_id, identity_id)}

    @handler("GetBulkPublishDetails", expand=False)
    def get_bulk_publish_details(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityPoolId"})
        with self._locked_pool(context, request) as (store, pool_id, _):
            configuration = store.pool_configurations.get(pool_id)
            publish = configuration.bulk_publish if configuration is not None else None
            if publish is None:
                return {"IdentityPoolId": pool_id, "BulkPublishStatus": "NOT_STARTED"}
            response: dict[str, Any] = {
                "BulkPublishStartTime": publish.start_time,
                "BulkPublishStatus": publish.status,
                "IdentityPoolId": pool_id,
            }
            if publish.complete_time is not None:
                response["BulkPublishCompleteTime"] = publish.complete_time
            if publish.failure_message is not None:
                response["FailureMessage"] = publish.failure_message
            return response

    @handler("GetCognitoEvents", expand=False)
    def get_cognito_events(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityPoolId"})
        with self._locked_pool(context, request) as (store, pool_id, _):
            configuration = store.pool_configurations.get(pool_id)
            return {"Events": copy.deepcopy(configuration.events if configuration else {})}

    @handler("GetIdentityPoolConfiguration", expand=False)
    def get_identity_pool_configuration(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityPoolId"})
        with self._locked_pool(context, request) as (store, pool_id, _):
            return _pool_configuration_response(store, pool_id)

    @handler("ListIdentityPoolUsage", expand=False)
    def list_identity_pool_usage(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"MaxResults", "NextToken"})
        maximum = _pool_usage_maximum(request.get("MaxResults"), provided="MaxResults" in request)
        with cognito_identity_stores.lock:
            identity_bundle = cognito_identity_stores.get(context.account_id)
            identity_store = (
                identity_bundle.get(context.region) if identity_bundle is not None else None
            )
            pools = []
            if identity_store is not None:
                pools = sorted(
                    (
                        pool
                        for pool_id, pool in identity_store.identity_pools.items()
                        if identity_store.POOL_LOCATIONS.get(pool_id)
                        == (context.account_id, context.region)
                    ),
                    key=lambda pool: pool.pool_id,
                )
            with cognito_sync_stores.lock:
                store = self.get_store(context)
                _purge_expired_sessions(store, self._now())
                live_pool_ids = {pool.pool_id for pool in pools}
                for configured_pool_id in set(store.pool_configurations) - live_pool_ids:
                    _remove_pool_state(store, configured_pool_id)
                scope = _scope_hash("identity-pool-usage", context.account_id, context.region)
                after = None
                now = self._now()
                if "NextToken" in request:
                    payload = _decode_cursor(store, request.get("NextToken"), now)
                    if set(payload) != {"after", "expires", "kind", "scope", "version"} or (
                        payload.get("kind") != "identity-pool-usage"
                        or payload.get("scope") != scope
                        or not isinstance(payload.get("after"), str)
                    ):
                        _error("InvalidParameterException", "Invalid NextToken")
                    after = payload["after"]
                start = _after_index(pools, after, lambda pool: pool.pool_id)
                page = pools[start : start + maximum]
                response: dict[str, Any] = {
                    "Count": len(page),
                    "IdentityPoolUsages": [
                        _pool_usage_response(store, pool.pool_id, pool.updated_at) for pool in page
                    ],
                    "MaxResults": maximum,
                }
                if start + len(page) < len(pools):
                    response["NextToken"] = _encode_cursor(
                        store,
                        {
                            "after": page[-1].pool_id,
                            "expires": _epoch(now + _SESSION_TTL),
                            "kind": "identity-pool-usage",
                            "scope": scope,
                            "version": 1,
                        },
                    )
                return response

    @handler("RegisterDevice", expand=False)
    def register_device(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityId", "IdentityPoolId", "Platform", "Token"})
        platform = _push_platform(request.get("Platform"))
        token = _push_token(request.get("Token"))
        with self._locked_scope(context, request, dataset_required=False) as (
            store,
            pool_id,
            identity_id,
            _,
        ):
            configuration = store.pool_configurations.get(pool_id)
            _require_push_configuration(configuration, platform)
            index_key = (pool_id, identity_id, platform, token)
            device_id = store.device_index.get(index_key)
            if device_id is not None:
                device = store.devices.get(device_id)
                if (
                    device is not None
                    and (
                        device.pool_id,
                        device.identity_id,
                        device.platform,
                        device.token,
                    )
                    == index_key
                ):
                    device.updated_at = self._now()
                    return {"DeviceId": device_id}
                store.device_index.pop(index_key, None)
            if (
                sum(
                    device.pool_id == pool_id and device.identity_id == identity_id
                    for device in store.devices.values()
                )
                >= _MAX_DEVICES_PER_IDENTITY
            ):
                _error("LimitExceededException", "Device limit exceeded")
            while True:
                device_id = str(uuid.uuid4())
                if device_id not in store.devices:
                    break
            now = self._now()
            store.devices[device_id] = SyncDevice(
                device_id=device_id,
                pool_id=pool_id,
                identity_id=identity_id,
                platform=platform,
                token=token,
                created_at=now,
                updated_at=now,
            )
            store.device_index[index_key] = device_id
            return {"DeviceId": device_id}

    @handler("SetCognitoEvents", expand=False)
    def set_cognito_events(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Events", "IdentityPoolId"})
        events = _cognito_events(context, request.get("Events"))
        with self._locked_pool(context, request) as (store, pool_id, _):
            now = self._now()
            configuration = store.pool_configurations.get(pool_id)
            if configuration is None:
                configuration = _new_pool_configuration(now)
                store.pool_configurations[pool_id] = configuration
            if "SyncTrigger" in events:
                if events["SyncTrigger"]:
                    configuration.events["SyncTrigger"] = events["SyncTrigger"]
                else:
                    configuration.events.pop("SyncTrigger", None)
            configuration.updated_at = now
            return {}

    @handler("SetIdentityPoolConfiguration", expand=False)
    def set_identity_pool_configuration(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"CognitoStreams", "IdentityPoolId", "PushSync"})
        push_sync = (
            _push_sync_configuration(context, request.get("PushSync"))
            if "PushSync" in request
            else None
        )
        streams = (
            _stream_configuration(context, request.get("CognitoStreams"))
            if "CognitoStreams" in request
            else None
        )
        with self._locked_pool(context, request) as (store, pool_id, _):
            now = self._now()
            configuration = store.pool_configurations.get(pool_id)
            if configuration is None:
                configuration = _new_pool_configuration(now)
                store.pool_configurations[pool_id] = configuration
            if "PushSync" in request:
                configuration.push_sync = copy.deepcopy(push_sync)
                if push_sync is None:
                    _remove_pool_devices(store, pool_id)
            if "CognitoStreams" in request:
                configuration.cognito_streams = copy.deepcopy(streams)
            configuration.updated_at = now
            return _pool_configuration_response(store, pool_id)

    @handler("SubscribeToDataset", expand=False)
    def subscribe_to_dataset(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request, {"DatasetName", "DeviceId", "IdentityId", "IdentityPoolId"}
        )
        device_id = _device_id(request.get("DeviceId"), provided=True)
        with self._locked_scope(context, request, dataset_required=True) as (
            store,
            pool_id,
            identity_id,
            dataset_name,
        ):
            device = _owned_device(store, device_id, pool_id, identity_id)
            _require_push_configuration(store.pool_configurations.get(pool_id), device.platform)
            subscription = (pool_id, identity_id, dataset_name, device_id)
            if subscription not in store.subscriptions and (
                sum(item[3] == device_id for item in store.subscriptions)
                >= _MAX_SUBSCRIPTIONS_PER_DEVICE
            ):
                _error("LimitExceededException", "Device subscription limit exceeded")
            store.subscriptions.add(subscription)
            return {}

    @handler("UnsubscribeFromDataset", expand=False)
    def unsubscribe_from_dataset(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request, {"DatasetName", "DeviceId", "IdentityId", "IdentityPoolId"}
        )
        device_id = _device_id(request.get("DeviceId"), provided=True)
        with self._locked_scope(context, request, dataset_required=True) as (
            store,
            pool_id,
            identity_id,
            dataset_name,
        ):
            _owned_device(store, device_id, pool_id, identity_id)
            store.subscriptions.discard((pool_id, identity_id, dataset_name, device_id))
            return {}

    @handler("DescribeDataset", expand=False)
    def describe_dataset(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"DatasetName", "IdentityId", "IdentityPoolId"})
        with self._locked_scope(context, request, dataset_required=True) as (
            store,
            pool_id,
            identity_id,
            dataset_name,
        ):
            key = (pool_id, identity_id, dataset_name)
            dataset = store.datasets.get(key)
            if dataset is None:
                _error("ResourceNotFoundException", "Dataset does not exist")
            return {"Dataset": _dataset_response(dataset)}

    @handler("DeleteDataset", expand=False)
    def delete_dataset(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"DatasetName", "IdentityId", "IdentityPoolId"})
        with self._locked_scope(context, request, dataset_required=True) as (
            store,
            pool_id,
            identity_id,
            dataset_name,
        ):
            key = (pool_id, identity_id, dataset_name)
            dataset = store.datasets.get(key)
            if dataset is None:
                _error("ResourceNotFoundException", "Dataset does not exist")
            response = _dataset_response(dataset)
            deletion_count = dataset.sync_count + 1
            store.datasets.pop(key)
            store.dataset_tombstones[key] = DatasetTombstone(
                sync_count=deletion_count,
                deleted_at=self._now(),
            )
            return {"Dataset": response}

    @handler("ListDatasets", expand=False)
    def list_datasets(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request, {"IdentityId", "IdentityPoolId", "MaxResults", "NextToken"}
        )
        maximum = _maximum_results(request.get("MaxResults"), provided="MaxResults" in request)
        with self._locked_scope(context, request, dataset_required=False) as (
            store,
            pool_id,
            identity_id,
            _,
        ):
            now = self._now()
            scope = _scope_hash(pool_id, identity_id)
            after = None
            if "NextToken" in request:
                token = request.get("NextToken")
                payload = _decode_cursor(store, token, now)
                if set(payload) != {"after", "expires", "kind", "scope", "version"} or (
                    payload.get("kind") != "datasets" or payload.get("scope") != scope
                ):
                    _error("InvalidParameterException", "Invalid NextToken")
                after = payload.get("after")
                if not isinstance(after, str):
                    _error("InvalidParameterException", "Invalid NextToken")
            datasets = sorted(
                (
                    dataset
                    for key, dataset in store.datasets.items()
                    if key[0] == pool_id and key[1] == identity_id
                ),
                key=lambda item: item.name,
            )
            start = _after_index(datasets, after, lambda item: item.name)
            page = datasets[start : start + maximum]
            response: dict[str, Any] = {
                "Count": len(page),
                "Datasets": [_dataset_response(dataset) for dataset in page],
            }
            if start + len(page) < len(datasets):
                response["NextToken"] = _encode_cursor(
                    store,
                    {
                        "after": page[-1].name,
                        "expires": _epoch(now + _SESSION_TTL),
                        "kind": "datasets",
                        "scope": scope,
                        "version": 1,
                    },
                )
            return response

    @handler("ListRecords", expand=False)
    def list_records(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "DatasetName",
                "IdentityId",
                "IdentityPoolId",
                "LastSyncCount",
                "MaxResults",
                "NextToken",
                "SyncSessionToken",
            },
        )
        maximum = _maximum_results(request.get("MaxResults"), provided="MaxResults" in request)
        with self._locked_scope(context, request, dataset_required=True) as (
            store,
            pool_id,
            identity_id,
            dataset_name,
        ):
            now = self._now()
            key = (pool_id, identity_id, dataset_name)
            if "SyncSessionToken" not in request:
                session_token = None
                _purge_expired_sessions(store, now)
                if "NextToken" in request:
                    _error("InvalidParameterException", "NextToken requires SyncSessionToken")
                last_sync_count = _sync_count(request.get("LastSyncCount", 0), "LastSyncCount")
                session_token, session_digest, session = _new_session(
                    store,
                    key=key,
                    dataset=store.datasets.get(key),
                    tombstone=store.dataset_tombstones.get(key),
                    last_sync_count=last_sync_count,
                    now=now,
                )
            else:
                session_token = request.get("SyncSessionToken")
                session_digest, session = _load_session(
                    store,
                    session_token,
                    key=key,
                    now=now,
                )
                if (
                    "LastSyncCount" in request
                    and _sync_count(request.get("LastSyncCount"), "LastSyncCount")
                    != session.last_sync_count
                ):
                    _error(
                        "InvalidParameterException", "SyncSessionToken does not match LastSyncCount"
                    )

            offset = 0
            if "NextToken" in request:
                next_token = request.get("NextToken")
                payload = _decode_cursor(store, next_token, now)
                if set(payload) != {"expires", "kind", "offset", "session", "version"} or (
                    payload.get("kind") != "records"
                    or payload.get("session") != session_digest
                    or not isinstance(payload.get("offset"), int)
                    or isinstance(payload.get("offset"), bool)
                    or payload["offset"] <= 0
                ):
                    _error("InvalidParameterException", "Invalid NextToken")
                offset = payload["offset"]
                if offset >= len(session.records):
                    _error("InvalidParameterException", "Invalid NextToken")

            records = session.records[offset : offset + maximum]
            response: dict[str, Any] = {
                "Count": len(session.records),
                "DatasetDeletedAfterRequestedSyncCount": (
                    session.dataset_deleted_after_requested_sync_count
                ),
                "DatasetExists": session.dataset_exists,
                "DatasetSyncCount": session.dataset_sync_count,
                "Records": [_record_response(record) for record in records],
                "SyncSessionToken": session_token,
            }
            if session.last_modified_by is not None:
                response["LastModifiedBy"] = session.last_modified_by
            next_offset = offset + len(records)
            if next_offset < len(session.records):
                response["NextToken"] = _encode_cursor(
                    store,
                    {
                        "expires": _epoch(session.expires_at),
                        "kind": "records",
                        "offset": next_offset,
                        "session": session_digest,
                        "version": 1,
                    },
                )
            return response

    @handler("UpdateRecords", expand=False)
    def update_records(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "DatasetName",
                "DeviceId",
                "IdentityId",
                "IdentityPoolId",
                "RecordPatches",
                "SyncSessionToken",
            },
        )
        patches = _patches(request.get("RecordPatches"), provided="RecordPatches" in request)
        device_id = _device_id(request.get("DeviceId"), provided="DeviceId" in request)
        with self._locked_scope(context, request, dataset_required=True) as (
            store,
            pool_id,
            identity_id,
            dataset_name,
        ):
            now = self._now()
            key = (pool_id, identity_id, dataset_name)
            configuration = store.pool_configurations.get(pool_id)
            if configuration is not None and configuration.events.get("SyncTrigger"):
                _error(
                    "InvalidConfigurationException",
                    "Cognito Events invocation is not available in the local emulator",
                )
            token = request.get("SyncSessionToken")
            if not isinstance(token, str) or not token:
                _error("InvalidParameterException", "SyncSessionToken is required")
            _, session = _load_session(store, token, key=key, now=now)
            _purge_expired_sessions(store, now)
            dataset = store.datasets.get(key)
            if dataset is None and key in store.dataset_tombstones:
                _error("ResourceNotFoundException", "Dataset was deleted")
            current_dataset_sync_count = dataset.sync_count if dataset is not None else 0
            if session.dataset_sync_count != current_dataset_sync_count:
                _error("ResourceConflictException", "Dataset changed after the sync session")

            current_records = dataset.records if dataset is not None else {}
            for patch in patches:
                current = current_records.get(patch.key)
                current_sync_count = current.sync_count if current is not None else 0
                if patch.sync_count != current_sync_count:
                    _error("ResourceConflictException", f"Stale SyncCount for record {patch.key}")

            projected = copy.deepcopy(current_records)
            next_sync_count = (dataset.sync_count if dataset is not None else 0) + bool(patches)
            last_modified_by = device_id or identity_id
            updated_records: list[SyncRecord] = []
            for patch in patches:
                record = SyncRecord(
                    key=patch.key,
                    value=patch.value,
                    sync_count=next_sync_count,
                    last_modified_date=now,
                    last_modified_by=last_modified_by,
                    device_last_modified_date=patch.device_last_modified_date,
                    deleted=patch.operation == "remove",
                )
                projected[patch.key] = record
                updated_records.append(record)

            if len(projected) > _MAX_RECORDS_PER_DATASET:
                _error("LimitExceededException", "Record limit exceeded")
            if _data_storage(projected) > _MAX_DATASET_BYTES:
                _error("LimitExceededException", "Dataset storage limit exceeded")
            if dataset is None:
                if _dataset_count(store, pool_id, identity_id) >= _MAX_DATASETS_PER_IDENTITY:
                    _error("LimitExceededException", "Dataset limit exceeded")
                dataset = SyncDataset(
                    pool_id=pool_id,
                    identity_id=identity_id,
                    name=dataset_name,
                    creation_date=now,
                    last_modified_date=now,
                    last_modified_by=last_modified_by,
                )
            dataset.records = projected
            if patches:
                dataset.sync_count = next_sync_count
                dataset.last_modified_date = now
                dataset.last_modified_by = last_modified_by
            store.datasets[key] = dataset
            store.dataset_tombstones.pop(key, None)
            return {"Records": [_record_response(record) for record in updated_records]}

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("Cognito Sync clock must return datetime")
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _error(code: str, message: str):
    statuses = {
        "NotAuthorizedException": 403,
        "ResourceConflictException": 409,
        "ResourceNotFoundException": 404,
    }
    raise CommonServiceException(
        code,
        message,
        status_code=statuses.get(code, 400),
        sender_fault=True,
    )


def _reject_unsupported_fields(request: ServiceRequest, allowed: set[str]) -> None:
    if unsupported := sorted(set(request) - allowed):
        _error("InvalidParameterException", f"Unsupported request fields: {unsupported}")


def _scoped_id(value: Any, field: str, region: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= 55:
        _error("InvalidParameterException", f"Invalid {field}")
    match = _SCOPED_ID_RE.fullmatch(value)
    if match is None or match.group("region") != region:
        _error("InvalidParameterException", f"Invalid {field}")
    try:
        uuid.UUID(match.group("uuid"))
    except ValueError:
        _error("InvalidParameterException", f"Invalid {field}")
    return value


def _dataset_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode()) <= 128
        or _DATASET_NAME_RE.fullmatch(value) is None
    ):
        _error("InvalidParameterException", "Invalid DatasetName")
    return value


def _maximum_results(value: Any, *, provided: bool) -> int:
    if not provided:
        return _DEFAULT_PAGE_RESULTS
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= _MAX_PAGE_RESULTS:
        _error("InvalidParameterException", "MaxResults must be between 1 and 1024")
    return value


def _pool_usage_maximum(value: Any, *, provided: bool) -> int:
    if not provided:
        return _DEFAULT_POOL_USAGE_RESULTS
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= _MAX_POOL_USAGE_RESULTS
    ):
        _error("InvalidParameterException", "MaxResults must be between 1 and 60")
    return value


def _sync_count(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 2**63 - 1:
        _error("InvalidParameterException", f"Invalid {field}")
    return value


def _device_id(value: Any, *, provided: bool) -> str | None:
    if not provided:
        return None
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= 256:
        _error("InvalidParameterException", "Invalid DeviceId")
    return value


def _push_platform(value: Any) -> str:
    if not isinstance(value, str) or value not in _SUPPORTED_PUSH_PLATFORMS:
        _error("InvalidParameterException", "Invalid Platform")
    return value


def _push_token(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= _MAX_PUSH_TOKEN_BYTES:
        _error("InvalidParameterException", "Invalid push Token")
    return value


def _arn_parts(value: Any, field: str) -> tuple[str, str, str, str, str]:
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= 2048:
        _error("InvalidParameterException", f"Invalid {field}")
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or not parts[5]:
        _error("InvalidParameterException", f"Invalid {field}")
    return parts[1], parts[2], parts[3], parts[4], parts[5]


def _role_arn(context: RequestContext, value: Any, field: str) -> str:
    partition, service, region, account_id, resource = _arn_parts(value, field)
    if (
        partition != context.partition
        or service != "iam"
        or region
        or account_id != context.account_id
        or not resource.startswith("role/")
        or len(resource) <= len("role/")
    ):
        _error("InvalidParameterException", f"Invalid {field}")
    return value


def _application_arn(context: RequestContext, value: Any) -> str:
    partition, service, region, account_id, resource = _arn_parts(value, "ApplicationArn")
    resource_parts = resource.split("/", 2)
    if (
        partition != context.partition
        or service != "sns"
        or region != context.region
        or account_id != context.account_id
        or len(resource_parts) != 3
        or resource_parts[0] != "app"
        or resource_parts[1] not in _SUPPORTED_PUSH_PLATFORMS
        or not resource_parts[2]
    ):
        _error("InvalidParameterException", "Invalid ApplicationArn")
    return value


def _lambda_arn(context: RequestContext, value: Any) -> str:
    partition, service, region, account_id, resource = _arn_parts(value, "SyncTrigger")
    if (
        partition != context.partition
        or service != "lambda"
        or region != context.region
        or account_id != context.account_id
        or not resource.startswith("function:")
        or len(resource) <= len("function:")
    ):
        _error("InvalidParameterException", "Invalid SyncTrigger")
    return value


def _cognito_events(context: RequestContext, value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 1 or set(value) - {"SyncTrigger"}:
        _error("InvalidParameterException", "Events may contain only SyncTrigger")
    if "SyncTrigger" not in value:
        return {}
    trigger = value["SyncTrigger"]
    if not isinstance(trigger, str):
        _error("InvalidParameterException", "Invalid SyncTrigger")
    return {"SyncTrigger": _lambda_arn(context, trigger) if trigger else ""}


def _push_sync_configuration(context: RequestContext, value: Any) -> dict[str, object] | None:
    if not isinstance(value, dict) or set(value) - {"ApplicationArns", "RoleArn"}:
        _error("InvalidParameterException", "Invalid PushSync configuration")
    if not value:
        return None
    result: dict[str, object] = {}
    if "ApplicationArns" in value:
        applications = value["ApplicationArns"]
        if (
            not isinstance(applications, list)
            or len(applications) > _MAX_PUSH_APPLICATIONS
            or len({item for item in applications if isinstance(item, str)}) != len(applications)
        ):
            _error("InvalidParameterException", "Invalid PushSync ApplicationArns")
        result["ApplicationArns"] = [
            _application_arn(context, application) for application in applications
        ]
    if "RoleArn" in value:
        result["RoleArn"] = _role_arn(context, value["RoleArn"], "PushSync.RoleArn")
    return result


def _stream_configuration(context: RequestContext, value: Any) -> dict[str, object] | None:
    fields = {"RoleArn", "StreamName", "StreamingStatus"}
    if not isinstance(value, dict) or set(value) - fields:
        _error("InvalidParameterException", "Invalid CognitoStreams configuration")
    if not value:
        return None
    if set(value) != fields:
        _error(
            "InvalidConfigurationException",
            "CognitoStreams requires RoleArn, StreamName, and StreamingStatus",
        )
    stream_name = value["StreamName"]
    status = value["StreamingStatus"]
    if not isinstance(stream_name, str) or not 1 <= len(stream_name.encode()) <= 128:
        _error("InvalidParameterException", "Invalid CognitoStreams.StreamName")
    if status not in {"DISABLED", "ENABLED"}:
        _error("InvalidParameterException", "Invalid CognitoStreams.StreamingStatus")
    return {
        "RoleArn": _role_arn(context, value["RoleArn"], "CognitoStreams.RoleArn"),
        "StreamName": stream_name,
        "StreamingStatus": status,
    }


def _require_push_configuration(configuration: SyncPoolConfiguration | None, platform: str) -> None:
    push_sync = configuration.push_sync if configuration is not None else None
    if not push_sync or not isinstance(push_sync.get("RoleArn"), str):
        _error("InvalidConfigurationException", "PushSync is not configured")
    applications = push_sync.get("ApplicationArns")
    if not isinstance(applications, list) or not any(
        isinstance(application, str) and f":app/{platform}/" in application
        for application in applications
    ):
        _error(
            "InvalidConfigurationException",
            f"PushSync has no application for platform {platform}",
        )


def _patches(value: Any, *, provided: bool) -> list[_Patch]:
    if not provided:
        return []
    if not isinstance(value, list) or len(value) > _MAX_PATCHES:
        _error("InvalidParameterException", "Invalid RecordPatches")
    result: list[_Patch] = []
    seen_keys: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) - {
            "DeviceLastModifiedDate",
            "Key",
            "Op",
            "SyncCount",
            "Value",
        }:
            _error("InvalidParameterException", "Invalid RecordPatch")
        operation = item.get("Op")
        key = item.get("Key")
        if operation not in {"replace", "remove"}:
            _error("InvalidParameterException", "Invalid RecordPatch operation")
        if not isinstance(key, str) or not 1 <= len(key.encode()) <= _MAX_RECORD_KEY_BYTES:
            _error("InvalidParameterException", "Invalid record key")
        if key in seen_keys:
            _error("InvalidParameterException", "Duplicate record key")
        seen_keys.add(key)
        value_item = item.get("Value")
        if operation == "replace":
            if (
                not isinstance(value_item, str)
                or len(value_item.encode()) > _MAX_RECORD_VALUE_BYTES
            ):
                _error("InvalidParameterException", "Invalid record value")
        elif "Value" in item:
            _error("InvalidParameterException", "Remove patches cannot contain Value")
        device_date = item.get("DeviceLastModifiedDate")
        if device_date is not None:
            if not isinstance(device_date, datetime):
                _error("InvalidParameterException", "Invalid DeviceLastModifiedDate")
            if device_date.tzinfo is None:
                device_date = device_date.replace(tzinfo=UTC)
            else:
                device_date = device_date.astimezone(UTC)
        result.append(
            _Patch(
                operation=operation,
                key=key,
                value=value_item if operation == "replace" else None,
                sync_count=_sync_count(item.get("SyncCount"), "SyncCount"),
                device_last_modified_date=device_date,
            )
        )
    return result


def _dataset_response(dataset: SyncDataset) -> dict[str, Any]:
    return {
        "CreationDate": dataset.creation_date,
        "DatasetName": dataset.name,
        "DataStorage": _data_storage(dataset.records),
        "IdentityId": dataset.identity_id,
        "LastModifiedBy": dataset.last_modified_by,
        "LastModifiedDate": dataset.last_modified_date,
        "NumRecords": _active_record_count(dataset.records),
    }


def _record_response(record: SyncRecord) -> dict[str, Any]:
    response: dict[str, Any] = {
        "Key": record.key,
        "LastModifiedBy": record.last_modified_by,
        "LastModifiedDate": record.last_modified_date,
        "SyncCount": record.sync_count,
    }
    if not record.deleted:
        response["Value"] = record.value
    if record.device_last_modified_date is not None:
        response["DeviceLastModifiedDate"] = record.device_last_modified_date
    return response


def _active_record_count(records: dict[str, SyncRecord]) -> int:
    return sum(not record.deleted for record in records.values())


def _data_storage(records: dict[str, SyncRecord]) -> int:
    return sum(
        len(record.key.encode()) + len(record.value.encode())
        for record in records.values()
        if not record.deleted and record.value is not None
    )


def _new_pool_configuration(now: datetime) -> SyncPoolConfiguration:
    return SyncPoolConfiguration(updated_at=now)


def _pool_configuration_response(store: CognitoSyncStore, pool_id: str) -> dict[str, Any]:
    response: dict[str, Any] = {"IdentityPoolId": pool_id}
    configuration = store.pool_configurations.get(pool_id)
    if configuration is None:
        return response
    if configuration.push_sync is not None:
        response["PushSync"] = copy.deepcopy(configuration.push_sync)
    if configuration.cognito_streams is not None:
        response["CognitoStreams"] = copy.deepcopy(configuration.cognito_streams)
    return response


def _identity_datasets(
    store: CognitoSyncStore, pool_id: str, identity_id: str
) -> list[SyncDataset]:
    return [dataset for key, dataset in store.datasets.items() if key[:2] == (pool_id, identity_id)]


def _identity_usage_response(
    store: CognitoSyncStore, pool_id: str, identity_id: str
) -> dict[str, Any]:
    datasets = _identity_datasets(store, pool_id, identity_id)
    response: dict[str, Any] = {
        "DataStorage": sum(_data_storage(dataset.records) for dataset in datasets),
        "DatasetCount": len(datasets),
        "IdentityId": identity_id,
        "IdentityPoolId": pool_id,
    }
    if datasets:
        response["LastModifiedDate"] = max(dataset.last_modified_date for dataset in datasets)
    return response


def _pool_usage_response(
    store: CognitoSyncStore, pool_id: str, pool_last_modified: datetime
) -> dict[str, Any]:
    datasets = [dataset for key, dataset in store.datasets.items() if key[0] == pool_id]
    modified_dates = [pool_last_modified]
    modified_dates.extend(dataset.last_modified_date for dataset in datasets)
    configuration = store.pool_configurations.get(pool_id)
    if configuration is not None:
        modified_dates.append(configuration.updated_at)
    return {
        "DataStorage": sum(_data_storage(dataset.records) for dataset in datasets),
        "IdentityPoolId": pool_id,
        "LastModifiedDate": max(modified_dates),
        "SyncSessionsCount": sum(session.pool_id == pool_id for session in store.sessions.values()),
    }


def _owned_device(
    store: CognitoSyncStore, device_id: str, pool_id: str, identity_id: str
) -> SyncDevice:
    device = store.devices.get(device_id)
    if device is None or device.pool_id != pool_id or device.identity_id != identity_id:
        _error("ResourceNotFoundException", "Device does not exist")
    return device


def _dataset_count(store: CognitoSyncStore, pool_id: str, identity_id: str) -> int:
    return sum(key[0] == pool_id and key[1] == identity_id for key in store.datasets)


def _remove_identity_state(store: CognitoSyncStore, pool_id: str, identity_id: str) -> None:
    for key in [key for key in store.datasets if key[:2] == (pool_id, identity_id)]:
        store.datasets.pop(key, None)
    for key in [key for key in store.dataset_tombstones if key[:2] == (pool_id, identity_id)]:
        store.dataset_tombstones.pop(key, None)
    scope = _scope_hash(pool_id, identity_id)
    for digest, session in list(store.sessions.items()):
        if session.scope_hash == scope:
            store.sessions.pop(digest, None)
    for device_id, device in list(store.devices.items()):
        if device.pool_id == pool_id and device.identity_id == identity_id:
            _remove_device(store, device_id)
    store.subscriptions = {
        subscription
        for subscription in store.subscriptions
        if subscription[:2] != (pool_id, identity_id)
    }


def _remove_device(store: CognitoSyncStore, device_id: str) -> None:
    device = store.devices.pop(device_id, None)
    if device is not None:
        store.device_index.pop(
            (device.pool_id, device.identity_id, device.platform, device.token), None
        )
    store.subscriptions = {
        subscription for subscription in store.subscriptions if subscription[3] != device_id
    }


def _remove_pool_devices(store: CognitoSyncStore, pool_id: str) -> None:
    for device_id, device in list(store.devices.items()):
        if device.pool_id == pool_id:
            _remove_device(store, device_id)


def _remove_pool_state(store: CognitoSyncStore, pool_id: str) -> None:
    for key in [key for key in store.datasets if key[0] == pool_id]:
        store.datasets.pop(key, None)
    for key in [key for key in store.dataset_tombstones if key[0] == pool_id]:
        store.dataset_tombstones.pop(key, None)
    for digest, session in list(store.sessions.items()):
        if session.pool_id == pool_id:
            store.sessions.pop(digest, None)
    _remove_pool_devices(store, pool_id)
    store.subscriptions = {
        subscription for subscription in store.subscriptions if subscription[0] != pool_id
    }
    store.pool_configurations.pop(pool_id, None)


def _scope_hash(*values: Any) -> str:
    encoded = json.dumps(values, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _session_binding(key: DatasetKey, dataset_sync_count: int) -> str:
    return _scope_hash(*key, dataset_sync_count)


def _new_session(
    store: CognitoSyncStore,
    *,
    key: DatasetKey,
    dataset: SyncDataset | None,
    tombstone: DatasetTombstone | None,
    last_sync_count: int,
    now: datetime,
) -> tuple[str, str, SyncSession]:
    _token_secret(store)
    dataset_sync_count = (
        dataset.sync_count if dataset is not None else tombstone.sync_count if tombstone else 0
    )
    records = []
    if dataset is not None:
        records = [
            copy.deepcopy(record)
            for record in sorted(dataset.records.values(), key=lambda item: item.key)
            if last_sync_count < record.sync_count <= dataset_sync_count
        ]
    while True:
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        if digest not in store.sessions:
            break
    session = SyncSession(
        pool_id=key[0],
        identity_id=key[1],
        scope_hash=_scope_hash(key[0], key[1]),
        binding_hash=_session_binding(key, dataset_sync_count),
        dataset_sync_count=dataset_sync_count,
        last_sync_count=last_sync_count,
        expires_at=now + _SESSION_TTL,
        records=records,
        snapshot_bytes=_snapshot_bytes(records),
        snapshot_records=len(records),
        dataset_exists=dataset is not None,
        dataset_deleted_after_requested_sync_count=(
            dataset is None and tombstone is not None and tombstone.sync_count > last_sync_count
        ),
        last_modified_by=dataset.last_modified_by if dataset is not None else None,
    )
    _reserve_session_capacity(store, session)
    store.sessions[digest] = session
    return token, digest, session


def _load_session(
    store: CognitoSyncStore,
    token: Any,
    *,
    key: DatasetKey,
    now: datetime,
) -> tuple[str, SyncSession]:
    if not isinstance(token, str) or not token or len(token.encode()) > _MAX_TOKEN_BYTES:
        _error("InvalidParameterException", "Invalid SyncSessionToken")
    digest = hashlib.sha256(token.encode()).hexdigest()
    session = store.sessions.get(digest)
    if session is None:
        _error("InvalidParameterException", "Invalid SyncSessionToken")
    if session.expires_at <= now:
        store.sessions.pop(digest, None)
        _error("NotAuthorizedException", "SyncSessionToken has expired")
    if not hmac.compare_digest(
        session.binding_hash,
        _session_binding(key, session.dataset_sync_count),
    ):
        _error("InvalidParameterException", "SyncSessionToken does not match the dataset")
    return digest, session


def _purge_expired_sessions(store: CognitoSyncStore, now: datetime) -> None:
    for digest, session in list(store.sessions.items()):
        if session.expires_at <= now:
            store.sessions.pop(digest, None)


def _snapshot_bytes(records: list[SyncRecord]) -> int:
    return sum(
        len(record.key.encode())
        + len(record.value.encode() if record.value is not None else b"")
        + len(record.last_modified_by.encode())
        + 256
        for record in records
    )


def _reserve_session_capacity(store: CognitoSyncStore, session: SyncSession) -> None:
    owned = [
        (digest, candidate)
        for digest, candidate in store.sessions.items()
        if candidate.scope_hash == session.scope_hash
    ]
    owned.sort(key=lambda item: (item[1].expires_at, item[0]))
    evicted: list[str] = []

    def identity_over_limit() -> bool:
        return (
            len(owned) + 1 > _MAX_SESSIONS_PER_IDENTITY
            or sum(item.snapshot_bytes for _, item in owned) + session.snapshot_bytes
            > _MAX_SESSION_SNAPSHOT_BYTES_PER_IDENTITY
            or sum(item.snapshot_records for _, item in owned) + session.snapshot_records
            > _MAX_SESSION_SNAPSHOT_RECORDS_PER_IDENTITY
        )

    while owned and identity_over_limit():
        digest, _ = owned.pop(0)
        evicted.append(digest)
    if identity_over_limit():
        _error("LimitExceededException", "Sync session snapshot limit exceeded")

    retained = [item for digest, item in store.sessions.items() if digest not in evicted]
    if (
        len(retained) + 1 > _MAX_SESSIONS_PER_STORE
        or sum(item.snapshot_bytes for item in retained) + session.snapshot_bytes
        > _MAX_SESSION_SNAPSHOT_BYTES_PER_STORE
        or sum(item.snapshot_records for item in retained) + session.snapshot_records
        > _MAX_SESSION_SNAPSHOT_RECORDS_PER_STORE
    ):
        _error("TooManyRequestsException", "Sync session capacity exceeded")
    for digest in evicted:
        store.sessions.pop(digest, None)


def _token_secret(store: CognitoSyncStore) -> bytes:
    if not store.token_secret:
        store.token_secret = secrets.token_bytes(32)
    return store.token_secret


def _encode_cursor(store: CognitoSyncStore, payload: dict[str, Any]) -> str:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    signature = hmac.digest(_token_secret(store), body, "sha256")
    return f"{_b64encode(body)}.{_b64encode(signature)}"


def _decode_cursor(store: CognitoSyncStore, value: Any, now: datetime) -> dict[str, Any]:
    if not isinstance(value, str) or not value or len(value.encode()) > _MAX_TOKEN_BYTES:
        _error("InvalidParameterException", "Invalid NextToken")
    try:
        body_value, signature_value = value.split(".", 1)
        body = _b64decode(body_value)
        signature = _b64decode(signature_value)
        if _b64encode(body) != body_value or _b64encode(signature) != signature_value:
            raise ValueError
        expected = hmac.digest(_token_secret(store), body, "sha256")
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        payload = json.loads(body)
    except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
        _error("InvalidParameterException", "Invalid NextToken")
    if not isinstance(payload, dict) or payload.get("version") != 1:
        _error("InvalidParameterException", "Invalid NextToken")
    expires = payload.get("expires")
    if not isinstance(expires, int) or isinstance(expires, bool) or expires <= _epoch(now):
        _error("InvalidParameterException", "NextToken has expired")
    return payload


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _epoch(value: datetime) -> int:
    return int(value.timestamp())


def _after_index(items: list[Any], after: str | None, key: Callable[[Any], str]) -> int:
    if after is None:
        return 0
    index = next((index for index, item in enumerate(items) if key(item) == after), None)
    if index is None:
        _error("InvalidParameterException", "Invalid NextToken")
    return index + 1
