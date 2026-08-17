import dataclasses
from datetime import datetime

from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute

DatasetKey = tuple[str, str, str]


@dataclasses.dataclass
class SyncRecord:
    key: str
    value: str | None
    sync_count: int
    last_modified_date: datetime
    last_modified_by: str
    device_last_modified_date: datetime | None = None
    deleted: bool = False


@dataclasses.dataclass
class SyncDataset:
    pool_id: str
    identity_id: str
    name: str
    creation_date: datetime
    last_modified_date: datetime
    last_modified_by: str
    sync_count: int = 0
    records: dict[str, SyncRecord] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class DatasetTombstone:
    sync_count: int
    deleted_at: datetime


@dataclasses.dataclass
class SyncSession:
    pool_id: str
    identity_id: str
    scope_hash: str
    binding_hash: str
    dataset_sync_count: int
    last_sync_count: int
    expires_at: datetime
    records: list[SyncRecord]
    snapshot_bytes: int
    snapshot_records: int
    dataset_exists: bool
    dataset_deleted_after_requested_sync_count: bool
    last_modified_by: str | None


@dataclasses.dataclass
class BulkPublishState:
    status: str
    start_time: datetime
    complete_time: datetime | None = None
    failure_message: str | None = None


@dataclasses.dataclass
class SyncPoolConfiguration:
    updated_at: datetime
    events: dict[str, str] = dataclasses.field(default_factory=dict)
    push_sync: dict[str, object] | None = None
    cognito_streams: dict[str, object] | None = None
    bulk_publish: BulkPublishState | None = None


@dataclasses.dataclass
class SyncDevice:
    device_id: str
    pool_id: str
    identity_id: str
    platform: str
    token: str
    created_at: datetime
    updated_at: datetime


class CognitoSyncStore(BaseStore):
    datasets: dict[DatasetKey, SyncDataset] = LocalAttribute(default=dict)
    dataset_tombstones: dict[DatasetKey, DatasetTombstone] = LocalAttribute(default=dict)
    sessions: dict[str, SyncSession] = LocalAttribute(default=dict)
    token_secret: bytes = LocalAttribute(default=b"")
    pool_configurations: dict[str, SyncPoolConfiguration] = LocalAttribute(default=dict)
    devices: dict[str, SyncDevice] = LocalAttribute(default=dict)
    device_index: dict[tuple[str, str, str, str], str] = LocalAttribute(default=dict)
    subscriptions: set[tuple[str, str, str, str]] = LocalAttribute(default=set)


cognito_sync_stores = AccountRegionBundle("cognito-sync", CognitoSyncStore)
