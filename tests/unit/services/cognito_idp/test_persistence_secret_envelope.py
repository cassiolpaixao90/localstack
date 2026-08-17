import base64
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from botocore.session import Session

from localstack.services.cognito_idp.models import (
    CognitoIdpStore,
    MfaSession,
    UserPool,
    UserPoolClient,
)
from localstack.services.cognito_idp.provider import _client_secret_values
from localstack.services.cognito_idp.user_import_models import UserImportJob, UserImportState
from localstack.services.stores import AccountRegionBundle
from localstack.state import pickle, service_persistence
from localstack.state.service_persistence import (
    ServicePersistenceError,
    load_service_snapshots,
    save_service_snapshots,
)


@pytest.fixture
def persistence_account_id():
    return f"{uuid.uuid4().int % 10**12:012d}"


@pytest.fixture
def persistence_region_name():
    regions = Session().get_available_regions("cognito-idp")
    return regions[uuid.uuid4().int % len(regions)]


def _bundle(account_id, region_name):
    bundle = AccountRegionBundle("cognito-idp", CognitoIdpStore)
    return bundle, bundle[account_id][region_name]


def _pool(account_id, region_name, *, access_key=b"access-key", id_key=b"id-key"):
    now = datetime.now(UTC)
    pool_id = f"{region_name}_EXAMPLE"
    return UserPool(
        pool_id=pool_id,
        name="enterprise-pool",
        arn=f"arn:aws:cognito-idp:{region_name}:{account_id}:userpool/{pool_id}",
        created_at=now,
        updated_at=now,
        access_signing_key_id="access-key-id",
        access_signing_private_key_pem=access_key,
        access_signing_jwk={"kid": "access-key-id"},
        id_signing_key_id="id-key-id",
        id_signing_private_key_pem=id_key,
        id_signing_jwk={"kid": "id-key-id"},
    )


def _snapshot_bytes(tmp_path):
    manifest = json.loads((Path(tmp_path) / "native-v1" / "manifest.json").read_bytes())
    filename = manifest["files"]["cognito-idp"]["filename"]
    return (Path(tmp_path) / "native-v1" / filename).read_bytes()


def _write_legacy_snapshot(tmp_path, source):
    payload = pickle.dumps(source)
    data = (
        service_persistence._MAGIC + hashlib.sha256(payload).hexdigest().encode() + b"\n" + payload
    )
    generation = uuid.uuid4().hex
    filename = f"cognito-idp.{generation}.state"
    directory = Path(tmp_path) / "native-v1"
    directory.mkdir(mode=0o700)
    state_file = directory / filename
    state_file.write_bytes(data)
    state_file.chmod(0o600)
    manifest = {
        "files": {
            "cognito-idp": {
                "filename": filename,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        },
        "format": "localstack-native-state-v1",
        "generation": generation,
        "services": ["cognito-idp"],
    }
    manifest_file = directory / "manifest.json"
    manifest_file.write_text(json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n")
    manifest_file.chmod(0o600)


def test_transient_client_metadata_is_encrypted_in_persisted_auth_sessions(
    tmp_path, persistence_account_id, persistence_region_name
):
    account_id, region_name = persistence_account_id, persistence_region_name
    source, store = _bundle(account_id, region_name)
    now = datetime.now(UTC)
    marker = "transient-metadata-secret-7c30ad845ffa"
    store.mfa_sessions["token-hash"] = MfaSession(
        token_hash="token-hash",
        pool_id=f"{region_name}_EXAMPLE",
        client_id="client-id",
        username="alice",
        kind="SMS_MFA",
        encrypted_secret=None,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        client_metadata={"tenant-secret": marker},
    )

    save_service_snapshots(tmp_path, {"cognito-idp": source})
    assert marker.encode() not in _snapshot_bytes(tmp_path)

    target, _ = _bundle(account_id, region_name)
    load_service_snapshots(tmp_path, {"cognito-idp": target})
    assert target[account_id][region_name].mfa_sessions["token-hash"].client_metadata == {
        "tenant-secret": marker
    }


def test_legacy_client_secret_is_eagerly_migrated_before_snapshot(
    tmp_path, persistence_account_id, persistence_region_name
):
    account_id, region_name = persistence_account_id, persistence_region_name
    source, store = _bundle(account_id, region_name)
    pool = _pool(account_id, region_name)
    marker = "legacy-client-secret-7c30ad845ffa"
    client = UserPoolClient(
        client_id="client-id",
        name="legacy-client",
        created_at=pool.created_at,
        updated_at=pool.updated_at,
        secret=marker,
        explicit_auth_flows=[],
    )
    pool.clients[client.client_id] = client
    store.user_pools[pool.pool_id] = pool

    save_service_snapshots(tmp_path, {"cognito-idp": source})

    assert client.secret is None
    assert client.primary_secret is not None
    assert marker.encode() not in _snapshot_bytes(tmp_path)
    target, _ = _bundle(account_id, region_name)
    load_service_snapshots(tmp_path, {"cognito-idp": target})
    restored_pool = target[account_id][region_name].user_pools[pool.pool_id]
    assert _client_secret_values(restored_pool, restored_pool.clients[client.client_id]) == [marker]


def test_user_pool_signing_private_keys_are_encrypted_in_snapshot(
    tmp_path, persistence_account_id, persistence_region_name
):
    account_id, region_name = persistence_account_id, persistence_region_name
    source, store = _bundle(account_id, region_name)
    access_key = b"plaintext-access-signing-private-key-7c30ad845ffa"
    id_key = b"plaintext-id-signing-private-key-7c30ad845ffa"
    pool = _pool(account_id, region_name, access_key=access_key, id_key=id_key)
    store.user_pools[pool.pool_id] = pool

    save_service_snapshots(tmp_path, {"cognito-idp": source})

    serialized = _snapshot_bytes(tmp_path)
    assert access_key not in serialized
    assert id_key not in serialized
    target, _ = _bundle(account_id, region_name)
    load_service_snapshots(tmp_path, {"cognito-idp": target})
    restored = target[account_id][region_name].user_pools[pool.pool_id]
    assert restored.access_signing_private_key_pem == access_key
    assert restored.id_signing_private_key_pem == id_key


def test_live_user_import_upload_capability_is_encrypted_in_snapshot(
    tmp_path, persistence_account_id, persistence_region_name
):
    account_id, region_name = persistence_account_id, persistence_region_name
    source, store = _bundle(account_id, region_name)
    now = datetime.now(UTC)
    signing_key = b"user-import-signing-key-7c30ad845ffa"
    nonce = "user-import-upload-nonce-7c30ad845ffa"
    job = UserImportJob(
        job_id="import-11111111-1111-4111-8111-111111111111",
        job_name="enterprise-import",
        pool_id=f"{region_name}_EXAMPLE",
        pool_name="enterprise-pool",
        cloudwatch_logs_role_arn=f"arn:aws:iam::{account_id}:role/import-role",
        status="Created",
        creation_date=now,
        presigned_url=f"https://localhost/import?nonce={nonce}",
        upload_expires_at=now + timedelta(minutes=15),
        upload_nonce=nonce,
        role_identity="role-snapshot",
    )
    store.user_import_jobs = UserImportState(signing_secret=signing_key, jobs={job.job_id: job})

    save_service_snapshots(tmp_path, {"cognito-idp": source})

    serialized = _snapshot_bytes(tmp_path)
    assert signing_key not in serialized
    assert nonce.encode() not in serialized
    target, _ = _bundle(account_id, region_name)
    load_service_snapshots(tmp_path, {"cognito-idp": target})
    restored = target[account_id][region_name].user_import_jobs
    assert restored.signing_secret == signing_key
    assert restored.jobs[job.job_id].upload_nonce == nonce


def test_snapshot_authentication_rejects_tamper_even_with_rewritten_manifest(
    tmp_path, persistence_account_id, persistence_region_name
):
    account_id, region_name = persistence_account_id, persistence_region_name
    source, store = _bundle(account_id, region_name)
    pool = _pool(account_id, region_name)
    store.user_pools[pool.pool_id] = pool
    save_service_snapshots(tmp_path, {"cognito-idp": source})
    manifest_path = Path(tmp_path) / "native-v1" / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    state_path = Path(tmp_path) / "native-v1" / manifest["files"]["cognito-idp"]["filename"]
    tampered = bytearray(state_path.read_bytes())
    tampered[-1] ^= 1
    state_path.write_bytes(tampered)
    manifest["files"]["cognito-idp"]["sha256"] = hashlib.sha256(tampered).hexdigest()
    manifest_path.write_text(json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n")

    target, target_store = _bundle(account_id, region_name)
    target_store.user_pools["stale"] = pool
    with pytest.raises(ServicePersistenceError, match="authentication failed"):
        load_service_snapshots(tmp_path, {"cognito-idp": target})
    assert set(target_store.user_pools) == {"stale"}


def test_explicit_environment_key_is_required_and_not_written_to_disk(
    tmp_path, persistence_account_id, persistence_region_name, monkeypatch
):
    account_id, region_name = persistence_account_id, persistence_region_name
    source, store = _bundle(account_id, region_name)
    pool = _pool(account_id, region_name)
    store.user_pools[pool.pool_id] = pool
    first_key = os.urandom(32)
    monkeypatch.setenv("LOCALSTACK_COGNITO_IDP_STATE_KEY", base64.b64encode(first_key).decode())
    save_service_snapshots(tmp_path, {"cognito-idp": source})
    assert not (Path(tmp_path) / "native-keys-v1").exists()

    monkeypatch.setenv(
        "LOCALSTACK_COGNITO_IDP_STATE_KEY", base64.b64encode(os.urandom(32)).decode()
    )
    target, _ = _bundle(account_id, region_name)
    with pytest.raises(ServicePersistenceError, match="authentication failed"):
        load_service_snapshots(tmp_path, {"cognito-idp": target})


def test_missing_external_key_fails_closed(
    tmp_path, persistence_account_id, persistence_region_name
):
    account_id, region_name = persistence_account_id, persistence_region_name
    source, store = _bundle(account_id, region_name)
    store.user_pools[f"{region_name}_EXAMPLE"] = _pool(account_id, region_name)
    save_service_snapshots(tmp_path, {"cognito-idp": source})
    (Path(tmp_path) / "native-keys-v1" / "cognito-idp.key").unlink()

    target, _ = _bundle(account_id, region_name)
    with pytest.raises(ServicePersistenceError, match="key is unavailable"):
        load_service_snapshots(tmp_path, {"cognito-idp": target})


def test_legacy_v1_snapshot_loads_and_is_encrypted_on_next_commit(
    tmp_path, persistence_account_id, persistence_region_name
):
    account_id, region_name = persistence_account_id, persistence_region_name
    marker = b"legacy-private-key-marker-7c30ad845ffa"
    source, store = _bundle(account_id, region_name)
    pool = _pool(account_id, region_name, access_key=marker)
    store.user_pools[pool.pool_id] = pool
    _write_legacy_snapshot(tmp_path, source)

    target, _ = _bundle(account_id, region_name)
    load_service_snapshots(tmp_path, {"cognito-idp": target})
    assert (
        target[account_id][region_name].user_pools[pool.pool_id].access_signing_private_key_pem
        == marker
    )

    save_service_snapshots(tmp_path, {"cognito-idp": target})
    assert marker not in _snapshot_bytes(tmp_path)
    assert _snapshot_bytes(tmp_path).startswith(service_persistence._ENCRYPTED_MAGIC)
