import json
import os
import threading
import time
import uuid
from pathlib import Path

import pytest

from localstack import config
from localstack import plugins as localstack_plugins
from localstack.services.apigatewayv2.models import (
    ApiGatewayV2ApiMapping,
    ApiGatewayV2DomainName,
    ApiGatewayV2Store,
)
from localstack.services.cognito_idp.models import CognitoIdpStore
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
    LocalAttribute,
)
from localstack.state import service_persistence
from localstack.state.service_persistence import (
    ServicePersistenceError,
    load_service_snapshots,
    save_service_snapshots,
)


class ExampleStore(BaseStore):
    LOCATIONS = CrossAccountAttribute(default=dict)
    values = LocalAttribute(default=dict)


def _bundle(value=None) -> AccountRegionBundle[ExampleStore]:
    bundle = AccountRegionBundle("s3", ExampleStore)
    if value is not None:
        bundle["000000000000"]["us-east-1"].values.update(value)
    return bundle


def _manifest(tmp_path) -> tuple[Path, dict]:
    path = Path(tmp_path) / "native-v1" / "manifest.json"
    return path, json.loads(path.read_bytes())


def test_snapshot_roundtrip_rebinds_store_scope_and_preserves_cross_account_state(tmp_path):
    source = _bundle({"owned": {"value": 1}})
    source_store = source["000000000000"]["us-east-1"]
    source_store.LOCATIONS["owned"] = ("000000000000", "us-east-1")
    target = _bundle({"stale": True})
    stores = {"test-service": target}

    save_service_snapshots(tmp_path, {"test-service": source})
    load_service_snapshots(tmp_path, stores)

    restored = target["000000000000"]["us-east-1"]
    assert restored.values == {"owned": {"value": 1}}
    assert restored.LOCATIONS == {"owned": ("000000000000", "us-east-1")}
    assert restored._universal is target._universal
    assert target["000000000000"].lock is target.lock


def test_snapshot_roundtrip_preserves_http_api_custom_domain_and_mapping(tmp_path):
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    source = AccountRegionBundle("apigatewayv2", ApiGatewayV2Store)
    target = AccountRegionBundle("apigatewayv2", ApiGatewayV2Store)
    source_account = source[account_id]
    valid_regions = sorted(source_account.valid_regions)
    region_name = valid_regions[uuid.uuid4().int % len(valid_regions)]
    domain_name = "api.example.test"
    domain_arn = f"arn:aws:apigateway:{region_name}::/domainnames/{domain_name}"
    domain = ApiGatewayV2DomainName(
        domain_name=domain_name,
        arn=domain_arn,
        properties={
            "DomainName": domain_name,
            "DomainNameArn": domain_arn,
            "Tags": {"owner": "persistence-unit"},
        },
    )
    domain.api_mappings["mapping1"] = ApiGatewayV2ApiMapping(
        api_mapping_id="mapping1",
        properties={
            "ApiId": "api12345",
            "ApiMappingId": "mapping1",
            "ApiMappingKey": "v1",
            "Stage": "prod",
        },
    )
    source_account[region_name].domain_names[domain_name] = domain

    save_service_snapshots(tmp_path, {"apigatewayv2": source})
    load_service_snapshots(tmp_path, {"apigatewayv2": target})

    restored = target[account_id][region_name].domain_names[domain_name]
    assert restored.arn == domain_arn
    assert restored.properties["Tags"] == {"owner": "persistence-unit"}
    assert restored.api_mappings["mapping1"].properties == {
        "ApiId": "api12345",
        "ApiMappingId": "mapping1",
        "ApiMappingKey": "v1",
        "Stage": "prod",
    }


def test_load_validates_every_snapshot_before_mutating_any_store(tmp_path):
    sources = {"first": _bundle({"new": True}), "second": _bundle({"new": True})}
    targets = {"first": _bundle({"old": True}), "second": _bundle({"old": True})}
    save_service_snapshots(tmp_path, sources)
    _, manifest = _manifest(tmp_path)
    second_path = Path(tmp_path) / "native-v1" / manifest["files"]["second"]["filename"]
    data = second_path.read_bytes()
    second_path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))

    with pytest.raises(ServicePersistenceError, match="manifest integrity"):
        load_service_snapshots(tmp_path, targets)

    assert targets["first"]["000000000000"]["us-east-1"].values == {"old": True}
    assert targets["second"]["000000000000"]["us-east-1"].values == {"old": True}


def test_load_validates_all_bundle_topologies_before_mutating_any_store(tmp_path):
    sources = {"first": _bundle({"new": True}), "second": _bundle({"new": True})}
    sources["second"]["000000000000"].account_id = "111111111111"
    targets = {"first": _bundle({"old": True}), "second": _bundle({"old": True})}
    save_service_snapshots(tmp_path, sources)

    with pytest.raises(ServicePersistenceError, match="snapshot topology for second is invalid"):
        load_service_snapshots(tmp_path, targets)

    assert targets["first"]["000000000000"]["us-east-1"].values == {"old": True}
    assert targets["second"]["000000000000"]["us-east-1"].values == {"old": True}


def test_interrupted_generation_keeps_the_previous_commit(tmp_path, monkeypatch):
    source = _bundle({"version": "first"})
    target = _bundle()
    stores = {"test-service": source}
    save_service_snapshots(tmp_path, stores)
    first_manifest = _manifest(tmp_path)[1]
    source["000000000000"]["us-east-1"].values["version"] = "second"
    real_atomic_write = service_persistence._atomic_write

    def interrupt_manifest(directory_fd, filename, data):
        if filename == "manifest.json":
            raise ServicePersistenceError("simulated interruption before commit")
        return real_atomic_write(directory_fd, filename, data)

    monkeypatch.setattr(service_persistence, "_atomic_write", interrupt_manifest)
    with pytest.raises(ServicePersistenceError, match="simulated interruption"):
        save_service_snapshots(tmp_path, stores)

    assert _manifest(tmp_path)[1] == first_manifest
    load_service_snapshots(tmp_path, {"test-service": target})
    assert target["000000000000"]["us-east-1"].values == {"version": "first"}


@pytest.mark.parametrize("corruption", ["missing", "extra", "mixed"])
def test_manifest_generation_is_closed_and_load_is_all_or_nothing(tmp_path, corruption):
    sources = {"first": _bundle({"new": True}), "second": _bundle({"new": True})}
    targets = {"first": _bundle({"old": True}), "second": _bundle({"old": True})}
    save_service_snapshots(tmp_path, sources)
    manifest_path, manifest = _manifest(tmp_path)
    if corruption == "missing":
        (Path(tmp_path) / "native-v1" / manifest["files"]["second"]["filename"]).unlink()
    elif corruption == "extra":
        manifest["services"].append("third")
    else:
        manifest["files"]["second"]["filename"] = manifest["files"]["first"]["filename"]
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ServicePersistenceError):
        load_service_snapshots(tmp_path, targets)

    assert targets["first"]["000000000000"]["us-east-1"].values == {"old": True}
    assert targets["second"]["000000000000"]["us-east-1"].values == {"old": True}


def test_snapshot_capture_holds_all_bundle_locks_against_hybrid_state(tmp_path):
    first = _bundle({"version": "before"})
    second = _bundle({"version": "before"})
    stores = {"first": first, "second": second}
    second.lock.acquire()
    save_error = []

    def save():
        try:
            save_service_snapshots(tmp_path, stores)
        except Exception as error:
            save_error.append(error)

    saver = threading.Thread(target=save)
    saver.start()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not first.lock.acquire(blocking=False):
            break
        first.lock.release()
        time.sleep(0.01)
    else:
        pytest.fail("snapshot writer did not acquire the first bundle lock")
    mutation_completed = threading.Event()

    def mutate():
        with first.lock:
            first["000000000000"]["us-east-1"].values["version"] = "after"
        mutation_completed.set()

    mutator = threading.Thread(target=mutate)
    mutator.start()
    second.lock.release()
    saver.join(5)
    mutator.join(5)
    assert not save_error
    assert mutation_completed.is_set()
    restored = {"first": _bundle(), "second": _bundle()}
    load_service_snapshots(tmp_path, restored)
    assert restored["first"]["000000000000"]["us-east-1"].values == {"version": "before"}
    assert restored["second"]["000000000000"]["us-east-1"].values == {"version": "before"}


def test_cognito_snapshot_quiesces_active_and_new_pool_mutations(tmp_path, monkeypatch):
    from localstack.services.cognito_idp.models import cognito_idp_stores
    from localstack.services.cognito_idp.provider import _pool_guard

    active_entered = threading.Event()
    release_active = threading.Event()
    encoding_started = threading.Event()
    allow_encoding = threading.Event()
    late_entered = threading.Event()
    failures = []

    def active_mutation():
        with _pool_guard("snapshot-active"):
            active_entered.set()
            release_active.wait(2)

    def encode(*_):
        encoding_started.set()
        if not allow_encoding.wait(2):
            raise RuntimeError("encoding was not released")
        return b"snapshot"

    def save():
        try:
            save_service_snapshots(tmp_path, {"cognito-idp": cognito_idp_stores})
        except Exception as error:
            failures.append(error)

    def late_mutation():
        with _pool_guard("snapshot-late"):
            late_entered.set()

    active = threading.Thread(target=active_mutation)
    active.start()
    assert active_entered.wait(2)
    monkeypatch.setattr(service_persistence, "_encode_snapshot", encode)
    saver = threading.Thread(target=save)
    saver.start()
    late = None
    try:
        assert not encoding_started.wait(0.1)
        release_active.set()
        assert encoding_started.wait(2)

        late = threading.Thread(target=late_mutation)
        late.start()
        assert not late_entered.wait(0.1)
        allow_encoding.set()
        late.join(2)
        assert late_entered.is_set()
    finally:
        release_active.set()
        allow_encoding.set()
        if late is not None:
            late.join(2)
        active.join(2)
        saver.join(2)

    assert not failures


def test_snapshot_lock_order_does_not_deadlock_idp_then_identity_request(tmp_path, monkeypatch):
    idp = AccountRegionBundle("cognito-idp", CognitoIdpStore)
    identity = _bundle()
    idp_held = threading.Event()
    snapshot_waiting_for_idp = threading.Event()
    continue_request = threading.Event()
    request_acquired_identity = []
    failures = []
    real_idp_lock = idp.lock

    class ObservedIdpLock:
        def acquire(self, *args, **kwargs):
            if threading.current_thread().name == "snapshot-writer":
                snapshot_waiting_for_idp.set()
            return real_idp_lock.acquire(*args, **kwargs)

        def release(self):
            real_idp_lock.release()

    idp.lock = ObservedIdpLock()
    monkeypatch.setattr(service_persistence, "_encode_snapshot", lambda *_: b"snapshot")

    def authenticated_identity_request():
        idp.lock.acquire()
        try:
            idp_held.set()
            if not continue_request.wait(2):
                failures.append("snapshot writer did not reach the IDP lock")
                return
            acquired = identity.lock.acquire(timeout=1)
            request_acquired_identity.append(acquired)
            if acquired:
                identity.lock.release()
        finally:
            idp.lock.release()

    def save():
        try:
            save_service_snapshots(
                tmp_path,
                {"cognito-identity": identity, "cognito-idp": idp},
            )
        except Exception as error:
            failures.append(error)

    request = threading.Thread(target=authenticated_identity_request, name="identity-request")
    request.start()
    assert idp_held.wait(2)
    saver = threading.Thread(target=save, name="snapshot-writer")
    saver.start()
    assert snapshot_waiting_for_idp.wait(2)
    continue_request.set()
    request.join(3)
    saver.join(3)

    assert not request.is_alive()
    assert not saver.is_alive()
    assert not failures
    assert request_acquired_identity == [True]


def test_load_rejects_snapshot_directory_symlink(tmp_path):
    target = _bundle({"old": True})
    foreign = Path(tmp_path) / "foreign"
    foreign.mkdir()
    (Path(tmp_path) / "native-v1").symlink_to(foreign, target_is_directory=True)

    with pytest.raises(ServicePersistenceError, match="safe directory"):
        load_service_snapshots(tmp_path, {"test-service": target})

    assert target["000000000000"]["us-east-1"].values == {"old": True}


def test_load_rejects_snapshot_file_symlink_without_mutating_store(tmp_path):
    source = _bundle({"new": True})
    target = _bundle({"old": True})
    save_service_snapshots(tmp_path, {"test-service": source})
    _, manifest = _manifest(tmp_path)
    state_path = Path(tmp_path) / "native-v1" / manifest["files"]["test-service"]["filename"]
    state_path.unlink()
    foreign = Path(tmp_path) / "foreign.state"
    foreign.write_bytes(b"foreign")
    state_path.symlink_to(foreign)

    with pytest.raises(ServicePersistenceError, match="securely open"):
        load_service_snapshots(tmp_path, {"test-service": target})

    assert target["000000000000"]["us-east-1"].values == {"old": True}


def test_load_reads_from_pinned_descriptor_during_path_swap(tmp_path, monkeypatch):
    source = _bundle({"new": True})
    target = _bundle({"old": True})
    save_service_snapshots(tmp_path, {"test-service": source})
    _, manifest = _manifest(tmp_path)
    filename = manifest["files"]["test-service"]["filename"]
    foreign = Path(tmp_path) / "foreign.state"
    foreign.write_bytes(b"foreign")
    real_open = os.open
    swapped = False

    def swap_after_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == filename and not swapped:
            swapped = True
            os.unlink(filename, dir_fd=dir_fd)
            os.symlink(foreign, filename, dir_fd=dir_fd)
        return descriptor

    monkeypatch.setattr(service_persistence.os, "open", swap_after_open)
    load_service_snapshots(tmp_path, {"test-service": target})

    assert swapped
    assert target["000000000000"]["us-east-1"].values == {"new": True}


def test_missing_snapshot_directory_is_an_empty_first_start(tmp_path):
    target = _bundle()

    load_service_snapshots(tmp_path, {"test-service": target})

    assert not target


def test_orphan_state_without_manifest_is_not_treated_as_first_start(tmp_path):
    target = _bundle({"old": True})
    snapshot_dir = Path(tmp_path) / "native-v1"
    snapshot_dir.mkdir(mode=0o700)
    orphan = snapshot_dir / "test-service.00000000000000000000000000000000.state"
    orphan.write_bytes(b"orphan")
    orphan.chmod(0o600)

    with pytest.raises(ServicePersistenceError, match="without a committed manifest"):
        load_service_snapshots(tmp_path, {"test-service": target})

    assert target["000000000000"]["us-east-1"].values == {"old": True}


@pytest.mark.parametrize("strategy", ["ON_REQUEST", "SCHEDULED", "invalid"])
def test_native_persistence_does_not_claim_unsupported_save_strategies(monkeypatch, strategy):
    monkeypatch.setattr(config, "PERSISTENCE", True)
    monkeypatch.setattr(config, "SNAPSHOT_SAVE_STRATEGY", strategy)

    assert not localstack_plugins._native_snapshot_save_enabled()
