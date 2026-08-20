"""Graceful-shutdown persistence for native stores in a trusted LocalStack data directory.

The generation commit is crash-consistent once the shutdown hook starts, but service mutations are
not crash-durable before that hook. SIGKILL or a host crash can therefore lose all changes since the
last completed graceful-shutdown snapshot. The hashes detect accidental corruption; they do not
authenticate state against an attacker who can write to the LocalStack volume. The data directory
remains inside the local trust boundary. Cognito IDP snapshots additionally use AES-GCM with either
``LOCALSTACK_COGNITO_IDP_STATE_KEY`` or a service-owned 0600 key file outside the snapshot directory.
The key file and encrypted generation must be backed up together.
"""

import base64
import contextlib
import hashlib
import hmac
import importlib
import json
import os
import re
import stat
import uuid
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localstack.services.stores import AccountRegionBundle, BaseStore, RegionBundle
from localstack.state import pickle

_MAGIC = b"LOCALSTACK-NATIVE-STATE-V1\n"
_ENCRYPTED_MAGIC = b"LOCALSTACK-NATIVE-STATE-AESGCM-V1\n"
_FORMAT = "localstack-native-state-v1"
_DIGEST_SIZE = 64
_MANIFEST = "manifest.json"
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
_SNAPSHOT_DIRECTORY = "native-v1"
_KEY_DIRECTORY = "native-keys-v1"
_COGNITO_KEY_FILE = "cognito-idp.key"
_COGNITO_KEY_ENV = "LOCALSTACK_COGNITO_IDP_STATE_KEY"
_AES_KEY_BYTES = 32
_AES_NONCE_BYTES = 12
_GENERATION_RE = re.compile(r"^[a-f0-9]{32}$")
_SERVICE_RE = re.compile(r"^[a-z0-9-]+$")

# Keep this compatible with nested request paths. Cognito Identity validates IDP tokens while
# holding the IDP lock before it mutates Identity, and Cognito Sync resolves Identity before Sync.
# API Gateway v2 copies its route state under its own lock and releases it before JWT validation.
_LOCK_PRIORITY = {
    "cognito-idp": 0,
    "cognito-identity": 1,
    "cognito-sync": 2,
    "apigatewayv2": 3,
}

NATIVE_SERVICE_STORES = {
    "apigatewayv2": ("localstack.services.apigatewayv2.models", "apigatewayv2_stores"),
    "cloudformation": ("localstack.services.cloudformation.stores", "cloudformation_stores"),
    "cognito-idp": ("localstack.services.cognito_idp.models", "cognito_idp_stores"),
    "cognito-identity": (
        "localstack.services.cognito_identity.models",
        "cognito_identity_stores",
    ),
    "cognito-sync": ("localstack.services.cognito_sync.models", "cognito_sync_stores"),
    "dynamodb": ("localstack.services.dynamodb.models", "dynamodb_stores"),
    "lambda": ("localstack.services.lambda_.invocation.models", "lambda_stores"),
    "sns": ("localstack.services.sns.models", "sns_stores"),
    "sqs": ("localstack.services.sqs.models", "sqs_stores"),
}


class ServicePersistenceError(RuntimeError):
    pass


def native_service_stores() -> dict[str, AccountRegionBundle]:
    result = {}
    for service, (module_name, attribute_name) in NATIVE_SERVICE_STORES.items():
        module = importlib.import_module(module_name)
        store = getattr(module, attribute_name)
        if not isinstance(store, AccountRegionBundle) or store.service_name != service:
            raise ServicePersistenceError(f"invalid native store registration for {service}")
        result[service] = store
    return result


def save_service_snapshots(
    data_dir: str | os.PathLike, stores: Mapping[str, AccountRegionBundle]
) -> None:
    services = _validate_store_set(stores)
    directory_fd = _open_snapshot_directory(data_dir, create=True)
    cognito_key = (
        _cognito_snapshot_key(data_dir, create=True) if "cognito-idp" in services else None
    )
    generation = uuid.uuid4().hex
    acquired = []
    try:
        pool_guard = contextlib.nullcontext()
        if "cognito-idp" in services:
            from localstack.services.cognito_idp.provider import (
                quiesce_pool_guards_for_snapshot,
            )

            pool_guard = quiesce_pool_guards_for_snapshot()
        with pool_guard:
            try:
                for service in services:
                    lock = stores[service].lock
                    lock.acquire()
                    acquired.append(lock)
                if "cognito-idp" in services:
                    from localstack.services.cognito_idp.provider import (
                        prepare_cognito_idp_state_for_snapshot,
                    )

                    try:
                        prepare_cognito_idp_state_for_snapshot(stores["cognito-idp"])
                    except Exception as error:
                        raise ServicePersistenceError(
                            "unable to prepare Cognito IDP state for snapshot"
                        ) from error
                encoded = {
                    service: _encode_snapshot(
                        service,
                        stores[service],
                        cognito_key if service == "cognito-idp" else None,
                    )
                    for service in services
                }
            finally:
                for lock in reversed(acquired):
                    lock.release()
        files = {}
        committed_names = {_MANIFEST}
        for service, data in encoded.items():
            filename = _generation_filename(service, generation)
            _atomic_write(directory_fd, filename, data)
            committed_names.add(filename)
            files[service] = {
                "filename": filename,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        manifest = {
            "files": files,
            "format": _FORMAT,
            "generation": generation,
            "services": services,
        }
        manifest_bytes = (
            json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        )
        _atomic_write(directory_fd, _MANIFEST, manifest_bytes)
        _garbage_collect(directory_fd, committed_names)
    finally:
        os.close(directory_fd)


def load_service_snapshots(
    data_dir: str | os.PathLike, stores: Mapping[str, AccountRegionBundle]
) -> None:
    services = _validate_store_set(stores)
    directory_fd = _open_snapshot_directory(data_dir, create=False)
    if directory_fd is None:
        return
    try:
        names = set(os.listdir(directory_fd))
        if _MANIFEST not in names:
            if names:
                raise ServicePersistenceError("native state exists without a committed manifest")
            return
        manifest_data = _read_secure_file(directory_fd, _MANIFEST, _MAX_MANIFEST_BYTES)
        manifest = _decode_manifest(manifest_data, services)
        restored = {}
        for service in services:
            metadata = manifest["files"][service]
            data = _read_secure_file(
                directory_fd,
                metadata["filename"],
                len(_MAGIC) + _DIGEST_SIZE + 1 + _MAX_SNAPSHOT_BYTES,
            )
            if len(data) != metadata["size"] or not hmac.compare_digest(
                hashlib.sha256(data).hexdigest(), metadata["sha256"]
            ):
                raise ServicePersistenceError(f"manifest integrity check failed for {service}")
            key = None
            if service == "cognito-idp" and data.startswith(_ENCRYPTED_MAGIC):
                key = _cognito_snapshot_key(data_dir, create=False)
            restored[service] = _decode_snapshot(data, service, stores[service], key)
        for service in services:
            _restore_bundle(stores[service], restored[service])
    finally:
        os.close(directory_fd)


def _validate_store_set(stores: Mapping[str, AccountRegionBundle]) -> list[str]:
    services = sorted(stores, key=lambda service: (_LOCK_PRIORITY.get(service, 100), service))
    if not services or any(not _SERVICE_RE.fullmatch(service) for service in services):
        raise ServicePersistenceError("invalid persistence service set")
    if any(not isinstance(stores[service], AccountRegionBundle) for service in services):
        raise ServicePersistenceError("native state requires AccountRegionBundle stores")
    return services


def _generation_filename(service: str, generation: str) -> str:
    return f"{service}.{generation}.state"


def _encode_snapshot(
    service: str, store: AccountRegionBundle, encryption_key: bytes | None = None
) -> bytes:
    try:
        payload = pickle.dumps(store)
    except Exception as error:
        raise ServicePersistenceError(f"unable to serialize state for {service}") from error
    if len(payload) > _MAX_SNAPSHOT_BYTES:
        raise ServicePersistenceError(f"snapshot for {service} exceeds the size limit")
    if service == "cognito-idp":
        if not isinstance(encryption_key, bytes) or len(encryption_key) != _AES_KEY_BYTES:
            raise ServicePersistenceError("Cognito IDP snapshot encryption key is unavailable")
        nonce = os.urandom(_AES_NONCE_BYTES)
        ciphertext = AESGCM(encryption_key).encrypt(nonce, payload, _snapshot_aad(service))
        return _ENCRYPTED_MAGIC + nonce + ciphertext
    digest = hashlib.sha256(payload).hexdigest().encode("ascii")
    return _MAGIC + digest + b"\n" + payload


def _decode_manifest(data: bytes, services: list[str]) -> dict:
    try:
        manifest = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ServicePersistenceError("native state manifest is invalid") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "files",
        "format",
        "generation",
        "services",
    }:
        raise ServicePersistenceError("native state manifest schema is invalid")
    generation = manifest.get("generation")
    if (
        manifest.get("format") != _FORMAT
        or manifest.get("services") != services
        or not isinstance(generation, str)
        or not _GENERATION_RE.fullmatch(generation)
        or not isinstance(manifest.get("files"), dict)
        or set(manifest["files"]) != set(services)
    ):
        raise ServicePersistenceError("native state manifest identity is invalid")
    for service in services:
        metadata = manifest["files"][service]
        if (
            not isinstance(metadata, dict)
            or set(metadata) != {"filename", "sha256", "size"}
            or metadata.get("filename") != _generation_filename(service, generation)
            or not isinstance(metadata.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", metadata["sha256"])
            or not isinstance(metadata.get("size"), int)
            or not 0 < metadata["size"] <= len(_MAGIC) + _DIGEST_SIZE + 1 + _MAX_SNAPSHOT_BYTES
        ):
            raise ServicePersistenceError(f"native state manifest entry for {service} is invalid")
    return manifest


def _decode_snapshot(
    data: bytes,
    service: str,
    target: AccountRegionBundle,
    encryption_key: bytes | None = None,
) -> AccountRegionBundle:
    if data.startswith(_ENCRYPTED_MAGIC):
        if service != "cognito-idp":
            raise ServicePersistenceError(f"snapshot encryption for {service} is invalid")
        if not isinstance(encryption_key, bytes) or len(encryption_key) != _AES_KEY_BYTES:
            raise ServicePersistenceError("Cognito IDP snapshot encryption key is unavailable")
        payload_start = len(_ENCRYPTED_MAGIC) + _AES_NONCE_BYTES
        if len(data) <= payload_start + 16:
            raise ServicePersistenceError(f"snapshot format for {service} is invalid")
        nonce = data[len(_ENCRYPTED_MAGIC) : payload_start]
        try:
            payload = AESGCM(encryption_key).decrypt(
                nonce, data[payload_start:], _snapshot_aad(service)
            )
        except InvalidTag as error:
            raise ServicePersistenceError(
                f"snapshot authentication failed for {service}"
            ) from error
    else:
        header_size = len(_MAGIC) + _DIGEST_SIZE + 1
        if len(data) < header_size or not data.startswith(_MAGIC) or data[header_size - 1] != 10:
            raise ServicePersistenceError(f"snapshot format for {service} is invalid")
        expected_digest = data[len(_MAGIC) : header_size - 1]
        payload = data[header_size:]
        actual_digest = hashlib.sha256(payload).hexdigest().encode("ascii")
        if not hmac.compare_digest(expected_digest, actual_digest):
            raise ServicePersistenceError(f"snapshot integrity check failed for {service}")
    try:
        restored = pickle.loads(payload)
    except Exception as error:
        raise ServicePersistenceError(f"unable to deserialize state for {service}") from error
    if (
        not isinstance(restored, AccountRegionBundle)
        or restored.service_name != target.service_name
        or restored.store is not target.store
    ):
        raise ServicePersistenceError(f"snapshot identity for {service} is invalid")
    _validate_bundle_topology(service, restored, target)
    return restored


def _snapshot_aad(service: str) -> bytes:
    return _ENCRYPTED_MAGIC + service.encode("ascii")


def _cognito_snapshot_key(data_dir: str | os.PathLike, *, create: bool) -> bytes:
    configured = os.environ.get(_COGNITO_KEY_ENV)
    if configured is not None:
        try:
            key = base64.b64decode(configured.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError) as error:
            raise ServicePersistenceError(f"{_COGNITO_KEY_ENV} must be base64-encoded") from error
        if len(key) != _AES_KEY_BYTES:
            raise ServicePersistenceError(f"{_COGNITO_KEY_ENV} must decode to 32 bytes")
        return key

    directory_fd = _open_key_directory(data_dir, create=create)
    if directory_fd is None:
        raise ServicePersistenceError("Cognito IDP snapshot encryption key is unavailable")
    try:
        try:
            return _validate_cognito_key(
                _read_secure_file(directory_fd, _COGNITO_KEY_FILE, _AES_KEY_BYTES)
            )
        except ServicePersistenceError:
            if not create:
                raise ServicePersistenceError(
                    "Cognito IDP snapshot encryption key is unavailable"
                ) from None
        key = os.urandom(_AES_KEY_BYTES)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(_COGNITO_KEY_FILE, flags, 0o600, dir_fd=directory_fd)
        except FileExistsError:
            return _validate_cognito_key(
                _read_secure_file(directory_fd, _COGNITO_KEY_FILE, _AES_KEY_BYTES)
            )
        try:
            if os.write(descriptor, key) != len(key):
                raise OSError("short key write")
            os.fsync(descriptor)
        except OSError as error:
            raise ServicePersistenceError("unable to persist Cognito IDP snapshot key") from error
        finally:
            os.close(descriptor)
        os.fsync(directory_fd)
        return key
    finally:
        os.close(directory_fd)


def _validate_cognito_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != _AES_KEY_BYTES:
        raise ServicePersistenceError("Cognito IDP snapshot encryption key is invalid")
    return key


def _open_key_directory(data_dir: str | os.PathLike, *, create: bool) -> int | None:
    path = Path(data_dir) / _KEY_DIRECTORY
    if create:
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise ServicePersistenceError("unable to create native key directory") from error
    elif not path.exists() and not path.is_symlink():
        return None
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ServicePersistenceError("native key directory has unsafe ownership or mode")
        return descriptor
    except ServicePersistenceError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    except OSError as error:
        raise ServicePersistenceError("native key directory is not a safe directory") from error


def _validate_bundle_topology(
    service: str, source: AccountRegionBundle, target: AccountRegionBundle
) -> None:
    if source.validate != target.validate or not isinstance(source._universal, dict):
        raise ServicePersistenceError(f"snapshot topology for {service} is invalid")
    for account_id, region_bundle in source.items():
        if (
            not isinstance(account_id, str)
            or not isinstance(region_bundle, RegionBundle)
            or region_bundle.account_id != account_id
            or region_bundle.service_name != source.service_name
            or region_bundle.store is not source.store
            or region_bundle.validate != source.validate
            or region_bundle.lock is not source.lock
            or region_bundle._universal is not source._universal
            or not isinstance(region_bundle._global, dict)
        ):
            raise ServicePersistenceError(f"snapshot topology for {service} is invalid")
        for region_name, store in region_bundle.items():
            if (
                not isinstance(region_name, str)
                or not isinstance(store, BaseStore)
                or not isinstance(store, source.store)
                or store._service_name != source.service_name
                or store._account_id != account_id
                or store._region_name != region_name
                or store._global is not region_bundle._global
                or store._universal is not source._universal
            ):
                raise ServicePersistenceError(f"snapshot topology for {service} is invalid")


def _restore_bundle(target: AccountRegionBundle, source: AccountRegionBundle) -> None:
    with target.lock:
        target.reset()
        target._universal.update(source._universal)
        for account_id, region_bundle in source.items():
            region_bundle.lock = target.lock
            region_bundle._universal = target._universal
            for store in region_bundle.values():
                store._global = region_bundle._global
                store._universal = target._universal
            target[account_id] = region_bundle


def _open_snapshot_directory(data_dir: str | os.PathLike, *, create: bool) -> int | None:
    path = Path(data_dir) / _SNAPSHOT_DIRECTORY
    if create:
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise ServicePersistenceError("unable to create native state directory") from error
    elif not path.exists() and not path.is_symlink():
        return None
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ServicePersistenceError("native state directory has unsafe ownership or mode")
        return descriptor
    except ServicePersistenceError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    except OSError as error:
        raise ServicePersistenceError("native state directory is not a safe directory") from error


def _read_secure_file(directory_fd: int, filename: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(filename, flags, dir_fd=directory_fd)
    except OSError as error:
        raise ServicePersistenceError(f"unable to securely open {filename}") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ServicePersistenceError(f"{filename} is not a safe regular file")
        if metadata.st_size > maximum:
            raise ServicePersistenceError(f"{filename} exceeds the size limit")
        chunks = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ServicePersistenceError(f"{filename} changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ServicePersistenceError(f"{filename} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _atomic_write(directory_fd: int, filename: str, data: bytes) -> None:
    temporary_name = f".{filename}.{uuid.uuid4().hex}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = None
    try:
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short snapshot write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary_name,
            filename,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except OSError as error:
        raise ServicePersistenceError(f"unable to atomically write {filename}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _garbage_collect(directory_fd: int, committed_names: set[str]) -> None:
    for name in os.listdir(directory_fd):
        if name in committed_names or not name.endswith((".state", ".tmp")):
            continue
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
