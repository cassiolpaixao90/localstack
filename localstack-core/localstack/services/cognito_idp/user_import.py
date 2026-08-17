from __future__ import annotations

import base64
import csv
import fnmatch
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import stat
import tempfile
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlencode

from localstack import config
from localstack.services.cognito_idp.imported_password_hashes import (
    ImportedPasswordHashError,
    normalize_imported_password_hash,
)
from localstack.services.cognito_idp.models import CognitoUser, PasswordHash, cognito_idp_stores
from localstack.services.cognito_idp.user_import_models import UserImportJob, UserImportState
from localstack.utils.aws.arns import get_partition

MAX_IMPORT_BYTES = 100 * 1024 * 1024
MAX_IMPORT_USERS = 500_000
MAX_IMPORT_ROW_CHARACTERS = 16_000
MAX_IMPORT_JOBS_PER_POOL = 1_000
MAX_IMPORT_LOG_EVENTS = 1_000
MAX_NORMALIZED_BYTES = 128 * 1024 * 1024
UPLOAD_TTL = timedelta(minutes=15)
JOB_TTL = timedelta(hours=24)

_STATE_ATTRIBUTE = "attr_user_import_jobs"
_UPLOAD_ROUTE_PREFIX = "/_aws/cognito-idp/user-import"
_ACCOUNT_PATTERN = re.compile(r"^[0-9]{12}$")
_REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")
_POOL_PATTERN = re.compile(r"^[\w-]+_[0-9A-Za-z]+$")
_JOB_PATTERN = re.compile(r"^import-[0-9a-f-]{36}$")
_JOB_NAME_PATTERN = re.compile(r"^[\w\s+=,.@-]{1,128}$")
_ROLE_PATTERN = re.compile(
    r"^arn:(?P<partition>aws(?:-us-gov|-cn|-iso(?:-[bef])?)?):iam::(?P<account>[0-9]{12}):role/(?P<name>[\w+=,.@/-]{1,512})$"
)
_TERMINAL_STATUSES = frozenset({"Expired", "Stopped", "Failed", "Succeeded"})
_RUNNING_STATUSES = frozenset({"Pending", "InProgress", "Stopping"})
_BOOLEAN_ATTRIBUTES = frozenset({"email_verified", "phone_number_verified", "cognito:mfa_enabled"})
_STANDARD_HEADER = (
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "email_verified",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "address",
    "updated_at",
    "cognito:mfa_enabled",
    "password_hash",
    "cognito:username",
)
_SIGNED_UPLOAD_HEADERS = "x-amz-server-side-encryption"
_ACTIVE_ACCOUNTS_LOCK = threading.RLock()
_ACTIVE_ACCOUNTS: dict[str, str] = {}


class ImportJobError(Exception):
    def __init__(self, code: str, message: str, *, http_status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


def user_import_state(store: Any) -> UserImportState:
    state = getattr(store, _STATE_ATTRIBUTE, None)
    if state is None:
        state = UserImportState()
        setattr(store, _STATE_ATTRIBUTE, state)
    if not isinstance(state, UserImportState) or state.version != 1:
        raise ImportJobError("InternalErrorException", "Unsupported user import state version")
    if not isinstance(state.signing_secret, bytes) or len(state.signing_secret) != 32:
        raise ImportJobError("InternalErrorException", "Invalid user import signing state")
    return state


def csv_header_for_pool(pool: Any) -> list[str]:
    result = list(_STANDARD_HEADER)
    seen = set(result)
    for definition in pool.schema_attributes or []:
        if not isinstance(definition, dict) or not isinstance(definition.get("Name"), str):
            raise ImportJobError("InvalidParameterException", "Invalid user pool schema")
        if definition["Name"] == "sub":
            continue
        name = _schema_storage_name(definition)
        if name not in seen:
            result.append(name)
            seen.add(name)
    return result


class _BoundedLines:
    def __init__(self, stream: io.TextIOBase):
        self.stream = stream

    def __iter__(self):
        return self

    def __next__(self) -> str:
        line = self.stream.readline(MAX_IMPORT_ROW_CHARACTERS + 2)
        if line == "":
            raise StopIteration
        if len(line.rstrip("\r\n")) > MAX_IMPORT_ROW_CHARACTERS:
            raise ImportJobError("InvalidParameterException", "CSV row exceeds 16000 characters")
        return line


class UserImportJobs:
    def __init__(
        self,
        *,
        store: Any,
        account_id: str,
        region: str,
        partition: str,
        storage_root: str | os.PathLike,
        endpoint_url: str,
        pool_transaction: Callable[[str], Any],
        now: Callable[[], datetime] | None = None,
        state_lock: threading.RLock | None = None,
        role_validator: Callable[[str, str, str], str] | None = None,
        log_emitter: Callable[[UserImportJob, list[dict[str, int | str]]], None] | None = None,
        recover_orphans: bool = True,
        max_workers: int = 1,
        max_pending: int = 8,
    ):
        if not _ACCOUNT_PATTERN.fullmatch(account_id):
            raise ValueError("invalid account id")
        if not _REGION_PATTERN.fullmatch(region):
            raise ValueError("invalid region")
        if partition != get_partition(region):
            raise ValueError("partition does not match region")
        if max_workers < 1 or max_pending < max_workers:
            raise ValueError("invalid worker bounds")
        self.store = store
        self.account_id = account_id
        self.region = region
        self.partition = partition
        self.storage_base = Path(storage_root)
        self.storage_root = self.storage_base / "user-import-v1"
        self.endpoint_url = endpoint_url.rstrip("/")
        self.pool_transaction = pool_transaction
        self.now = now or (lambda: datetime.now(UTC))
        self.state_lock = state_lock or threading.RLock()
        self.role_validator = role_validator or self._validate_local_role
        self.log_emitter = log_emitter or self._emit_cloudwatch_logs
        self.before_commit: Callable[[], None] | None = None
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="cognito-user-import"
        )
        self._admission = threading.BoundedSemaphore(max_pending)
        self._futures: dict[str, Future] = {}
        self._stop_events: dict[str, threading.Event] = {}
        self._closed = False
        self._prepare_storage_root()
        if recover_orphans:
            self._recover_orphans()

    def shutdown(self, *, wait: bool = True) -> None:
        self._closed = True
        with self.state_lock:
            for job_id, event in self._stop_events.items():
                event.set()
                job = user_import_state(self.store).jobs.get(job_id)
                if job is not None and job.status in {"Pending", "InProgress"}:
                    job.status = "Stopping"
        self._executor.shutdown(wait=wait, cancel_futures=False)

    def get_csv_header(self, pool_id: str) -> list[str]:
        with self.pool_transaction(_pool_id(pool_id)) as pool:
            return csv_header_for_pool(pool)

    def create_job(
        self,
        pool_id: str,
        job_name: str,
        role_arn: str,
        password_hashing_algorithm: str | None = None,
    ) -> dict[str, Any]:
        pool_id = _pool_id(pool_id)
        if not isinstance(job_name, str) or _JOB_NAME_PATTERN.fullmatch(job_name) is None:
            raise ImportJobError("InvalidParameterException", "Invalid JobName")
        self._validate_role_arn(role_arn)
        if password_hashing_algorithm is not None and password_hashing_algorithm not in {
            "ARGON2ID",
            "BCRYPT",
            "PBKDF2_SHA256",
            "SCRYPT",
        }:
            raise ImportJobError("InvalidParameterException", "Invalid PasswordHashingAlgorithm")
        with self.pool_transaction(pool_id) as pool:
            pool_name = pool.name
        role_identity = self.role_validator(role_arn, pool_id, pool_name)
        if not isinstance(role_identity, str) or not role_identity:
            raise ImportJobError("InvalidParameterException", "Invalid CloudWatch logging role")
        now = self._utc_now()
        job_id = f"import-{uuid.uuid4()}"
        nonce = secrets.token_urlsafe(18)
        expires_at = now + UPLOAD_TTL
        path = self._upload_url_path(pool_id, job_id)
        expires = int(expires_at.timestamp())
        signature = self._sign_upload(path, expires, nonce, _SIGNED_UPLOAD_HEADERS)
        presigned_url = (
            f"{self.endpoint_url}{path}?"
            f"{urlencode({'expires': expires, 'nonce': nonce, 'signedHeaders': _SIGNED_UPLOAD_HEADERS, 'signature': signature})}"
        )
        job = UserImportJob(
            job_id=job_id,
            job_name=job_name,
            pool_id=pool_id,
            pool_name=pool_name,
            cloudwatch_logs_role_arn=role_arn,
            status="Created",
            creation_date=now,
            presigned_url=presigned_url,
            upload_expires_at=expires_at,
            upload_nonce=nonce,
            role_identity=role_identity,
            password_hashing_algorithm=password_hashing_algorithm,
        )
        with self.state_lock:
            state = user_import_state(self.store)
            self._expire_jobs_locked(state, now)
            pool_jobs = [
                candidate for candidate in state.jobs.values() if candidate.pool_id == pool_id
            ]
            if len(pool_jobs) >= MAX_IMPORT_JOBS_PER_POOL:
                removable = sorted(
                    (
                        candidate
                        for candidate in pool_jobs
                        if candidate.status in _TERMINAL_STATUSES
                    ),
                    key=lambda candidate: (candidate.creation_date, candidate.job_id),
                )
                while len(pool_jobs) >= MAX_IMPORT_JOBS_PER_POOL and removable:
                    victim = removable.pop(0)
                    state.jobs.pop(victim.job_id, None)
                    pool_jobs.remove(victim)
                    self._delete_upload(victim)
                if len(pool_jobs) >= MAX_IMPORT_JOBS_PER_POOL:
                    raise ImportJobError("LimitExceededException", "User import job quota exceeded")
            state.jobs[job_id] = job
        return self._job_response(job)

    def describe_job(self, pool_id: str, job_id: str) -> dict[str, Any]:
        pool_id, job_id = _pool_id(pool_id), _job_id(job_id)
        with self.pool_transaction(pool_id):
            pass
        with self.state_lock:
            state = user_import_state(self.store)
            self._expire_jobs_locked(state, self._utc_now())
            return self._job_response(self._job_locked(state, pool_id, job_id))

    def list_jobs(
        self, pool_id: str, *, max_results: int, pagination_token: str | None = None
    ) -> dict[str, Any]:
        pool_id = _pool_id(pool_id)
        if (
            isinstance(max_results, bool)
            or not isinstance(max_results, int)
            or not 1 <= max_results <= 60
        ):
            raise ImportJobError("InvalidParameterException", "MaxResults must be between 1 and 60")
        with self.pool_transaction(pool_id):
            pass
        with self.state_lock:
            state = user_import_state(self.store)
            self._expire_jobs_locked(state, self._utc_now())
            ordered = sorted(
                (job for job in state.jobs.values() if job.pool_id == pool_id),
                key=lambda job: (job.creation_date, job.job_id),
                reverse=True,
            )
            start = 0
            if pagination_token is not None:
                cursor = self._decode_page_token(state, pool_id, pagination_token)
                for index, job in enumerate(ordered):
                    if self._job_cursor(job) == cursor:
                        start = index + 1
                        break
                else:
                    raise ImportJobError("InvalidParameterException", "Invalid pagination token")
            page = ordered[start : start + max_results]
            result: dict[str, Any] = {"UserImportJobs": [self._job_response(job) for job in page]}
            if start + max_results < len(ordered) and page:
                result["PaginationToken"] = self._encode_page_token(
                    state, pool_id, self._job_cursor(page[-1])
                )
            return result

    def upload(
        self,
        *,
        path: str,
        query: Mapping[str, str],
        stream: BinaryIO,
        content_length: int | None,
        headers: Mapping[str, str],
    ) -> dict[str, int]:
        account_id, region, pool_id, job_id = self._parse_upload_path(path)
        if account_id != self.account_id or region != self.region:
            raise ImportJobError("AccessDenied", "Invalid upload target", http_status=403)
        if set(query) != {"expires", "nonce", "signedHeaders", "signature"}:
            raise ImportJobError("AccessDenied", "Invalid upload signature", http_status=403)
        try:
            expires = int(query["expires"])
        except (TypeError, ValueError):
            raise ImportJobError("AccessDenied", "Invalid upload signature", http_status=403)
        nonce, signed_headers, signature = (
            query["nonce"],
            query["signedHeaders"],
            query["signature"],
        )
        encryption = next(
            (
                value
                for name, value in headers.items()
                if isinstance(name, str) and name.lower() == "x-amz-server-side-encryption"
            ),
            None,
        )
        if (
            not isinstance(nonce, str)
            or len(nonce) > 64
            or not isinstance(signature, str)
            or len(signature) != 64
            or signed_headers != _SIGNED_UPLOAD_HEADERS
            or encryption != "aws:kms"
            or not hmac.compare_digest(
                signature, self._sign_upload(path, expires, nonce, signed_headers)
            )
        ):
            raise ImportJobError("AccessDenied", "Invalid upload signature", http_status=403)
        now = self._utc_now()
        if expires < int(now.timestamp()):
            raise ImportJobError("AccessDenied", "Upload URL has expired", http_status=403)
        if content_length is not None and (
            isinstance(content_length, bool)
            or not isinstance(content_length, int)
            or content_length < 0
            or content_length > MAX_IMPORT_BYTES
        ):
            raise ImportJobError("EntityTooLarge", "Import file exceeds 100 MiB", http_status=413)
        with self.state_lock:
            state = user_import_state(self.store)
            job = self._job_locked(state, pool_id, job_id)
            if (
                job.status != "Created"
                or job.upload_in_progress
                or expires != int(job.upload_expires_at.timestamp())
                or not hmac.compare_digest(nonce, job.upload_nonce)
            ):
                raise ImportJobError("Conflict", "Upload is not available", http_status=409)
            job.upload_in_progress = True

        destination = self._upload_path(job)
        temporary: str | None = None
        try:
            self._prepare_parent(destination.parent)
            descriptor, temporary = tempfile.mkstemp(
                dir=destination.parent, prefix=f".{job.job_id}.", suffix=".upload"
            )
            digest = hashlib.sha256()
            size = 0
            with os.fdopen(descriptor, "wb") as target:
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes):
                        raise ImportJobError(
                            "InvalidParameterException", "Upload stream must be bytes"
                        )
                    size += len(chunk)
                    if size > MAX_IMPORT_BYTES:
                        raise ImportJobError(
                            "EntityTooLarge", "Import file exceeds 100 MiB", http_status=413
                        )
                    digest.update(chunk)
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())
            if content_length is not None and size != content_length:
                raise ImportJobError(
                    "InvalidParameterException", "Content-Length does not match uploaded bytes"
                )
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
            temporary = None
            with self.state_lock:
                current = self._job_locked(user_import_state(self.store), pool_id, job_id)
                if current.status != "Created" or not current.upload_in_progress:
                    self._delete_path(destination)
                    raise ImportJobError("Conflict", "Upload job changed", http_status=409)
                current.uploaded_at = now
                current.uploaded_size = size
                current.uploaded_sha256 = digest.hexdigest()
                current.upload_in_progress = False
            return {"size": size}
        except BaseException:
            if temporary is not None:
                self._delete_path(Path(temporary))
            with self.state_lock:
                current = user_import_state(self.store).jobs.get(job_id)
                if current is not None:
                    current.upload_in_progress = False
            raise

    def start_job(self, pool_id: str, job_id: str) -> dict[str, Any]:
        pool_id, job_id = _pool_id(pool_id), _job_id(job_id)
        with self.pool_transaction(pool_id) as pool:
            auto_verified = pool.auto_verified_attributes
            if (
                not isinstance(auto_verified, list)
                or not auto_verified
                or set(auto_verified) - {"email", "phone_number"}
            ):
                raise ImportJobError(
                    "InvalidParameterException",
                    "User pool must configure AutoVerifiedAttributes before import",
                )
        with self.state_lock:
            state = user_import_state(self.store)
            candidate = self._job_locked(state, pool_id, job_id)
            if any(
                job.job_id != job_id and job.status in _RUNNING_STATUSES
                for job in state.jobs.values()
            ):
                raise ImportJobError(
                    "PreconditionNotMetException", "Another user import job is active"
                )
            current_role_identity = self.role_validator(
                candidate.cloudwatch_logs_role_arn,
                candidate.pool_id,
                candidate.pool_name,
            )
            if current_role_identity != candidate.role_identity:
                raise ImportJobError(
                    "InvalidParameterException", "CloudWatch logging role changed identity"
                )
        active_key = f"{self.region}:{job_id}"
        with _ACTIVE_ACCOUNTS_LOCK:
            if self.account_id in _ACTIVE_ACCOUNTS:
                raise ImportJobError(
                    "PreconditionNotMetException", "Another user import job is active"
                )
            _ACTIVE_ACCOUNTS[self.account_id] = active_key
        if self._closed:
            self._release_account(active_key)
            raise ImportJobError("InternalErrorException", "User import worker is shutting down")
        if not self._admission.acquire(blocking=False):
            self._release_account(active_key)
            raise ImportJobError("TooManyRequestsException", "User import worker capacity exceeded")
        with self.state_lock:
            try:
                state = user_import_state(self.store)
                job = self._job_locked(state, pool_id, job_id)
                if job.status != "Created":
                    raise ImportJobError(
                        "InvalidParameterException", "Import job cannot be started"
                    )
                if job.upload_in_progress or job.uploaded_sha256 is None:
                    raise ImportJobError(
                        "InvalidParameterException", "Import CSV has not been uploaded"
                    )
                job.status = "Pending"
                job.start_date = self._utc_now()
                stop_event = threading.Event()
                self._stop_events[job_id] = stop_event
                future = self._executor.submit(self._run_job, pool_id, job_id, stop_event)
                self._futures[job_id] = future
                future.add_done_callback(lambda _: self._release_worker(job_id))
                return self._job_response(job)
            except BaseException:
                self._admission.release()
                self._release_account(active_key)
                raise

    def stop_job(self, pool_id: str, job_id: str) -> dict[str, Any]:
        pool_id, job_id = _pool_id(pool_id), _job_id(job_id)
        with self.pool_transaction(pool_id):
            pass
        with self.state_lock:
            state = user_import_state(self.store)
            job = self._job_locked(state, pool_id, job_id)
            if job.status not in {"Pending", "InProgress", "Stopping"}:
                raise ImportJobError("InvalidParameterException", "Import job cannot be stopped")
            job.status = "Stopping"
            event = self._stop_events.get(job_id)
            if event is not None:
                event.set()
            future = self._futures.get(job_id)
            if future is not None and future.cancel():
                self._mark_stopped_locked(job)
            return self._job_response(job)

    def wait(self, job_id: str, *, timeout: float) -> dict[str, Any]:
        job_id = _job_id(job_id)
        with self.state_lock:
            future = self._futures.get(job_id)
        if future is not None:
            try:
                future.result(timeout=timeout)
            except TimeoutError:
                raise
        with self.state_lock:
            state = user_import_state(self.store)
            job = state.jobs.get(job_id)
            if job is None:
                raise ImportJobError("ResourceNotFoundException", "User import job does not exist")
            return self._job_response(job)

    def cleanup_pool(self, pool_id: str) -> None:
        pool_id = _pool_id(pool_id)
        with self.state_lock:
            state = user_import_state(self.store)
            jobs = [job for job in state.jobs.values() if job.pool_id == pool_id]
            for job in jobs:
                event = self._stop_events.get(job.job_id)
                if event is not None:
                    event.set()
                state.jobs.pop(job.job_id, None)
                self._delete_upload(job)

    def _run_job(self, pool_id: str, job_id: str, stop_event: threading.Event) -> None:
        normalized_path: Path | None = None
        try:
            with self.state_lock:
                job = self._job_locked(user_import_state(self.store), pool_id, job_id)
                if stop_event.is_set() or job.status == "Stopping":
                    self._mark_stopped_locked(job)
                    return
                job.status = "InProgress"
                source_path = self._upload_path(job)
                expected_size = job.uploaded_size
                expected_digest = job.uploaded_sha256
            with self.pool_transaction(pool_id) as pool:
                header = csv_header_for_pool(pool)
                schema = list(pool.schema_attributes or [])
                auto_verified = list(pool.auto_verified_attributes or [])
                mfa_configuration = pool.mfa_configuration
                password_hashing_algorithm = getattr(job, "password_hashing_algorithm", None)
            normalized_path, parse_failed = self._normalize_csv(
                source_path,
                expected_size=expected_size,
                expected_digest=expected_digest,
                expected_header=header,
                schema=schema,
                auto_verified=auto_verified,
                mfa_configuration=mfa_configuration,
                password_hashing_algorithm=password_hashing_algorithm,
                job_id=job_id,
                stop_event=stop_event,
            )
            if stop_event.is_set():
                self._finish_stopped(job_id)
                return
            if self.before_commit is not None:
                self.before_commit()
            if stop_event.is_set():
                self._finish_stopped(job_id)
                return
            imported = 0
            skipped = 0
            outcome_events: list[dict[str, int | str]] = []
            dropped_outcome_events = 0
            with self.pool_transaction(pool_id) as pool:
                staged = dict(pool.users)
                with normalized_path.open("r", encoding="utf-8") as normalized:
                    for line in normalized:
                        if stop_event.is_set():
                            self._finish_stopped(job_id)
                            return
                        record = json.loads(line)
                        username = record["username"]
                        if username in staged:
                            skipped += 1
                            if len(outcome_events) < max(0, MAX_IMPORT_LOG_EVENTS):
                                outcome_events.append(
                                    {
                                        "line": record["line"],
                                        "result": "Skipped",
                                        "reason": "User_already_exists",
                                    }
                                )
                            else:
                                dropped_outcome_events += 1
                            continue
                        now = self._utc_now()
                        imported_hash = record.get("password_hash")
                        staged[username] = CognitoUser(
                            username=username,
                            sub=str(uuid.uuid4()),
                            password=(
                                PasswordHash(
                                    algorithm=f"imported:{password_hashing_algorithm}",
                                    iterations=0,
                                    salt="",
                                    digest=imported_hash,
                                )
                                if imported_hash is not None
                                else PasswordHash(
                                    algorithm="disabled-user-import",
                                    iterations=0,
                                    salt="",
                                    digest="",
                                )
                            ),
                            status="CONFIRMED" if imported_hash is not None else "RESET_REQUIRED",
                            enabled=True,
                            created_at=now,
                            updated_at=now,
                            attributes=record["attributes"],
                        )
                        imported += 1
                        if len(outcome_events) < max(0, MAX_IMPORT_LOG_EVENTS):
                            outcome_events.append(
                                {
                                    "line": record["line"],
                                    "result": "Succeeded",
                                    "reason": "Imported",
                                }
                            )
                        else:
                            dropped_outcome_events += 1
                if stop_event.is_set():
                    self._finish_stopped(job_id)
                    return
                with self.state_lock:
                    job = self._job_locked(user_import_state(self.store), pool_id, job_id)
                    failure_events = list(job.log_events)
                    if job.dropped_log_events:
                        failure_events.append(
                            {
                                "line": 0,
                                "result": "Truncated",
                                "reason": f"{job.dropped_log_events}_failure_events_omitted",
                            }
                        )
                if dropped_outcome_events:
                    outcome_events.append(
                        {
                            "line": 0,
                            "result": "Truncated",
                            "reason": f"{dropped_outcome_events}_outcome_events_omitted",
                        }
                    )
                self.log_emitter(job, [*failure_events, *outcome_events])
                with self.state_lock:
                    job = self._job_locked(user_import_state(self.store), pool_id, job_id)
                    if stop_event.is_set() or job.status == "Stopping":
                        self._mark_stopped_locked(job)
                        return
                    pool.users = staged
                    pool.updated_at = self._utc_now()
                    job.imported_users = imported
                    job.skipped_users = skipped
                    job.failed_users = parse_failed
                    job.status = "Succeeded"
                    job.completion_date = self._utc_now()
                    job.completion_message = "Import_completed"
        except ImportJobError as error:
            self._finish_failed(job_id, error.message)
        except Exception:
            self._finish_failed(job_id, "Internal_import_error")
        finally:
            if normalized_path is not None:
                self._delete_path(normalized_path)
            with self.state_lock:
                job = user_import_state(self.store).jobs.get(job_id)
                if job is not None and job.status in _TERMINAL_STATUSES:
                    self._delete_upload(job)

    def _normalize_csv(
        self,
        source_path: Path,
        *,
        expected_size: int,
        expected_digest: str | None,
        expected_header: list[str],
        schema: list[dict[str, Any]],
        auto_verified: list[str],
        mfa_configuration: str,
        password_hashing_algorithm: str | None,
        job_id: str,
        stop_event: threading.Event,
    ) -> tuple[Path, int]:
        source = self._open_regular(source_path, expected_size)
        descriptor, normalized_name = tempfile.mkstemp(
            dir=source_path.parent, prefix=f".{job_id}.", suffix=".normalized"
        )
        normalized_path = Path(normalized_name)
        failed = 0
        seen: set[str] = set()
        digest = hashlib.sha256()
        try:
            with source, os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
                hashing_reader = _HashingReader(source, digest)
                text = io.TextIOWrapper(
                    hashing_reader, encoding="utf-8", errors="strict", newline=""
                )
                reader = csv.reader(_BoundedLines(text), strict=True, escapechar="\\")
                try:
                    actual_header = next(reader)
                except StopIteration:
                    raise ImportJobError("InvalidParameterException", "CSV header is missing")
                actual_header = [field.strip() for field in actual_header]
                if actual_header and actual_header[0].startswith("\ufeff"):
                    raise ImportJobError("InvalidParameterException", "UTF-8 BOM is not allowed")
                if (
                    len(actual_header) != len(set(actual_header))
                    or len(actual_header) != len(expected_header)
                    or set(actual_header) != set(expected_header)
                ):
                    raise ImportJobError("InvalidParameterException", "Invalid CSV header")
                normalized_bytes = 0
                row_count = 0
                for row in reader:
                    if stop_event.is_set():
                        break
                    row_count += 1
                    if row_count > MAX_IMPORT_USERS:
                        raise ImportJobError(
                            "LimitExceededException", "CSV exceeds 500000 user rows"
                        )
                    if (
                        len(row) != len(actual_header)
                        or sum(len(value) for value in row) > MAX_IMPORT_ROW_CHARACTERS
                    ):
                        failed += 1
                        self._record_log(job_id, reader.line_num, "Failed", "Invalid_row_length")
                        continue
                    values = dict(zip(actual_header, (value.strip() for value in row), strict=True))
                    username = values.get("cognito:username", "")
                    if username in seen:
                        failed += 1
                        self._record_log(job_id, reader.line_num, "Failed", "Duplicate_username")
                        continue
                    try:
                        record = self._validated_record(
                            values,
                            schema,
                            auto_verified=auto_verified,
                            mfa_configuration=mfa_configuration,
                            password_hashing_algorithm=password_hashing_algorithm,
                        )
                    except ImportJobError as error:
                        failed += 1
                        self._record_log(job_id, reader.line_num, "Failed", error.message)
                        continue
                    seen.add(username)
                    record["line"] = reader.line_num
                    encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
                    normalized_bytes += len(encoded.encode("utf-8"))
                    if normalized_bytes > MAX_NORMALIZED_BYTES:
                        raise ImportJobError(
                            "LimitExceededException", "Normalized import exceeds local bound"
                        )
                    output.write(encoded)
                text.detach()
                output.flush()
                os.fsync(output.fileno())
            if not stop_event.is_set() and digest.hexdigest() != expected_digest:
                raise ImportJobError(
                    "InvalidParameterException", "Uploaded CSV integrity check failed"
                )
            os.chmod(normalized_path, 0o600)
            return normalized_path, failed
        except (UnicodeDecodeError, csv.Error) as error:
            self._delete_path(normalized_path)
            raise ImportJobError(
                "InvalidParameterException", "Invalid CSV encoding or syntax"
            ) from error
        except BaseException:
            self._delete_path(normalized_path)
            raise

    def _validated_record(
        self,
        values: dict[str, str],
        schema: list[dict[str, Any]],
        *,
        auto_verified: list[str],
        mfa_configuration: str,
        password_hashing_algorithm: str | None,
    ) -> dict[str, Any]:
        username = values.get("cognito:username", "")
        if not 1 <= len(username) <= 128 or any(
            ord(character) < 32 or character.isspace() for character in username
        ):
            raise ImportJobError("InvalidParameterException", "Invalid_username")
        for name in _BOOLEAN_ATTRIBUTES:
            value = values.get(name, "")
            if value and value.lower() not in {"true", "false"}:
                raise ImportJobError("InvalidParameterException", f"Invalid_{name}")
            if value:
                values[name] = value.lower()
        if values.get("email_verified") == "true" and not values.get("email"):
            raise ImportJobError("InvalidParameterException", "Verified_email_is_missing")
        if values.get("phone_number_verified") == "true" and not values.get("phone_number"):
            raise ImportJobError("InvalidParameterException", "Verified_phone_is_missing")
        if values.get("email") and "@" not in values["email"]:
            raise ImportJobError("InvalidParameterException", "Invalid_email")
        if values.get("phone_number") and not values["phone_number"].startswith("+"):
            raise ImportJobError("InvalidParameterException", "Invalid_phone_number")
        if values.get("updated_at"):
            try:
                int(values["updated_at"])
            except ValueError:
                raise ImportJobError("InvalidParameterException", "Invalid_updated_at")
        if values.get("birthdate"):
            try:
                datetime.strptime(values["birthdate"], "%m/%d/%Y")
            except ValueError:
                raise ImportJobError("InvalidParameterException", "Invalid_birthdate")
        if not any(
            values.get(attribute) and values.get(f"{attribute}_verified") == "true"
            for attribute in auto_verified
        ):
            raise ImportJobError("InvalidParameterException", "Missing_auto_verified_attribute")
        mfa_enabled = values.get("cognito:mfa_enabled", "false") == "true"
        if mfa_enabled:
            raise ImportJobError("InvalidParameterException", "SMS_MFA_import_not_supported")
        if mfa_configuration == "ON":
            raise ImportJobError("InvalidParameterException", "MFA_required_for_pool")
        password_hash = values.get("password_hash", "")
        if password_hash:
            if password_hashing_algorithm is None:
                raise ImportJobError(
                    "InvalidParameterException", "Password_hashing_algorithm_is_missing"
                )
            try:
                password_hash = normalize_imported_password_hash(
                    password_hashing_algorithm, password_hash
                ).encoded
            except ImportedPasswordHashError as error:
                raise ImportJobError(
                    "InvalidParameterException", "Invalid_password_hash"
                ) from error
        definitions = {_schema_storage_name(item): item for item in schema}
        for name, definition in definitions.items():
            value = values.get(name, "")
            if definition.get("Required") is True and not value:
                raise ImportJobError("InvalidParameterException", f"Missing_{name}")
            if value:
                self._validate_schema_value(name, value, definition)
        attributes = {
            name: value
            for name, value in values.items()
            if value and name not in {"cognito:username", "cognito:mfa_enabled", "password_hash"}
        }
        result = {"username": username, "attributes": attributes}
        if password_hash:
            result["password_hash"] = password_hash
        return result

    def _validate_schema_value(self, name: str, value: str, definition: dict[str, Any]) -> None:
        data_type = definition.get("AttributeDataType", "String")
        if data_type == "String":
            constraints = definition.get("StringAttributeConstraints") or {}
            minimum = int(constraints.get("MinLength", 0))
            maximum = int(constraints.get("MaxLength", 2048))
            if not minimum <= len(value) <= maximum:
                raise ImportJobError("InvalidParameterException", f"Invalid_{name}")
        elif data_type == "Number":
            try:
                number = Decimal(value)
                minimum = Decimal(
                    (definition.get("NumberAttributeConstraints") or {}).get("MinValue", "-1e308")
                )
                maximum = Decimal(
                    (definition.get("NumberAttributeConstraints") or {}).get("MaxValue", "1e308")
                )
            except InvalidOperation:
                raise ImportJobError("InvalidParameterException", f"Invalid_{name}")
            if not number.is_finite() or not minimum <= number <= maximum:
                raise ImportJobError("InvalidParameterException", f"Invalid_{name}")
        elif data_type == "Boolean":
            if value.lower() not in {"true", "false"}:
                raise ImportJobError("InvalidParameterException", f"Invalid_{name}")
        elif data_type == "DateTime":
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                raise ImportJobError("InvalidParameterException", f"Invalid_{name}")
        else:
            raise ImportJobError("InvalidParameterException", f"Invalid_{name}")

    def _finish_stopped(self, job_id: str) -> None:
        with self.state_lock:
            job = user_import_state(self.store).jobs.get(job_id)
            if job is not None:
                self._mark_stopped_locked(job)

    def _mark_stopped_locked(self, job: UserImportJob) -> None:
        job.status = "Stopped"
        job.completion_date = self._utc_now()
        job.completion_message = "Import_stopped"

    def _finish_failed(self, job_id: str, message: str) -> None:
        with self.state_lock:
            job = user_import_state(self.store).jobs.get(job_id)
            if job is None:
                return
            job.status = "Failed"
            job.completion_date = self._utc_now()
            job.completion_message = _completion_message(message)

    def _release_worker(self, job_id: str) -> None:
        with self.state_lock:
            self._futures.pop(job_id, None)
            self._stop_events.pop(job_id, None)
        self._admission.release()
        self._release_account(f"{self.region}:{job_id}")

    def _release_account(self, active_key: str) -> None:
        with _ACTIVE_ACCOUNTS_LOCK:
            if _ACTIVE_ACCOUNTS.get(self.account_id) == active_key:
                _ACTIVE_ACCOUNTS.pop(self.account_id, None)

    def _record_log(self, job_id: str, line: int, result: str, reason: str) -> None:
        with self.state_lock:
            job = user_import_state(self.store).jobs.get(job_id)
            if job is not None and len(job.log_events) < MAX_IMPORT_LOG_EVENTS:
                job.log_events.append(
                    {"line": line, "result": result, "reason": _completion_message(reason)}
                )
            elif job is not None:
                job.dropped_log_events += 1

    def _recover_orphans(self) -> None:
        with self.state_lock:
            state = user_import_state(self.store)
            now = self._utc_now()
            self._expire_jobs_locked(state, now)
            for job in state.jobs.values():
                job.upload_in_progress = False
                if job.status in _RUNNING_STATUSES:
                    job.status = "Failed"
                    job.completion_date = now
                    job.completion_message = "Interrupted_by_restart"
                    self._delete_upload(job)

    def _expire_jobs_locked(self, state: UserImportState, now: datetime) -> None:
        for job in state.jobs.values():
            if job.status == "Created" and job.creation_date + JOB_TTL <= now:
                job.status = "Expired"
                job.completion_date = now
                job.completion_message = "Import_job_expired"
                job.upload_in_progress = False
                self._delete_upload(job)

    def _job_locked(self, state: UserImportState, pool_id: str, job_id: str) -> UserImportJob:
        job = state.jobs.get(job_id)
        if job is None or job.pool_id != pool_id:
            raise ImportJobError("ResourceNotFoundException", "User import job does not exist")
        return job

    def _job_response(self, job: UserImportJob) -> dict[str, Any]:
        result: dict[str, Any] = {
            "JobName": job.job_name,
            "JobId": job.job_id,
            "UserPoolId": job.pool_id,
            "PreSignedUrl": job.presigned_url,
            "CreationDate": job.creation_date,
            "Status": job.status,
            "CloudWatchLogsRoleArn": job.cloudwatch_logs_role_arn,
            "ImportedUsers": job.imported_users,
            "SkippedUsers": job.skipped_users,
            "FailedUsers": job.failed_users,
        }
        if job.start_date is not None:
            result["StartDate"] = job.start_date
        if job.completion_date is not None:
            result["CompletionDate"] = job.completion_date
        if job.completion_message is not None:
            result["CompletionMessage"] = job.completion_message
        if password_hashing_algorithm := getattr(job, "password_hashing_algorithm", None):
            result["PasswordHashingAlgorithm"] = password_hashing_algorithm
        return result

    def _validate_role_arn(self, role_arn: str) -> None:
        match = _ROLE_PATTERN.fullmatch(role_arn) if isinstance(role_arn, str) else None
        if match is None:
            raise ImportJobError("InvalidParameterException", "Invalid CloudWatchLogsRoleArn")
        if match.group("partition") != self.partition:
            raise ImportJobError(
                "InvalidParameterException", "IAM role must use the same partition"
            )
        if match.group("account") != self.account_id:
            raise ImportJobError(
                "InvalidParameterException", "IAM role must belong to the same account"
            )

    def _validate_local_role(self, role_arn: str, pool_id: str, pool_name: str) -> str:
        from moto.iam.models import iam_backends

        try:
            role = iam_backends[self.account_id][self.partition].get_role_by_arn(role_arn)
        except Exception as error:
            raise ImportJobError(
                "InvalidParameterException", "CloudWatch logging role does not exist locally"
            ) from error
        if role.arn != role_arn or role.account_id != self.account_id:
            raise ImportJobError("InvalidParameterException", "CloudWatch logging role changed")
        trust = _policy_document(role.assume_role_policy_document)
        if not _trusts_cognito_import(trust):
            raise ImportJobError(
                "InvalidParameterException",
                "CloudWatch logging role must trust cognito-idp.amazonaws.com",
            )
        policies = [
            _policy_document(document)
            for document in [
                *role.policies.values(),
                *(policy.document for policy in role.managed_policies.values()),
            ]
        ]
        log_group = self._log_group_name(pool_id, pool_name)
        group_arn = (
            f"arn:{self.partition}:logs:{self.region}:{self.account_id}:log-group:{log_group}"
        )
        for action, resource in (
            ("logs:CreateLogGroup", group_arn),
            ("logs:DescribeLogStreams", f"{group_arn}:*"),
            ("logs:CreateLogStream", f"{group_arn}:*"),
            ("logs:PutLogEvents", f"{group_arn}:*"),
        ):
            if not _policies_allow(policies, action, resource):
                raise ImportJobError(
                    "InvalidParameterException",
                    f"CloudWatch logging role does not allow {action}",
                )
        return role.id

    def _emit_cloudwatch_logs(self, job: UserImportJob, events: list[dict[str, int | str]]) -> None:
        from moto.logs.models import logs_backends

        backend = logs_backends[self.account_id][self.region]
        log_group = self._log_group_name(job.pool_id, job.pool_name)
        log_stream = f"{job.job_id}/{job.job_name}"
        if log_group not in backend.groups:
            backend.create_log_group(log_group, tags={})
        group = backend.groups[log_group]
        if log_stream not in group.streams:
            backend.create_log_stream(log_group, log_stream)
        base_timestamp = int((job.start_date or job.creation_date).timestamp() * 1000)
        for start in range(0, len(events), 10_000):
            batch = [
                {
                    "timestamp": base_timestamp + start + offset,
                    "message": json.dumps(event, separators=(",", ":"), sort_keys=True),
                }
                for offset, event in enumerate(events[start : start + 10_000])
            ]
            if batch:
                backend.put_log_events(log_group, log_stream, batch)

    @staticmethod
    def _log_group_name(pool_id: str, pool_name: str) -> str:
        return f"/aws/cognito/userpools/{pool_id}/{pool_name}"

    def _upload_url_path(self, pool_id: str, job_id: str) -> str:
        return f"{_UPLOAD_ROUTE_PREFIX}/{self.account_id}/{self.region}/{pool_id}/{job_id}"

    def _sign_upload(self, path: str, expires: int, nonce: str, signed_headers: str) -> str:
        with self.state_lock:
            secret = user_import_state(self.store).signing_secret
        canonical = f"PUT\n{path}\n{expires}\n{nonce}\n{signed_headers}:aws:kms".encode()
        return hmac.new(secret, canonical, hashlib.sha256).hexdigest()

    def _parse_upload_path(self, path: str) -> tuple[str, str, str, str]:
        prefix = f"{_UPLOAD_ROUTE_PREFIX}/"
        if not isinstance(path, str) or not path.startswith(prefix):
            raise ImportJobError("AccessDenied", "Invalid upload target", http_status=403)
        parts = path.removeprefix(prefix).split("/")
        if len(parts) != 4:
            raise ImportJobError("AccessDenied", "Invalid upload target", http_status=403)
        account_id, region, pool_id, job_id = parts
        if (
            _ACCOUNT_PATTERN.fullmatch(account_id) is None
            or _REGION_PATTERN.fullmatch(region) is None
            or _POOL_PATTERN.fullmatch(pool_id) is None
            or _JOB_PATTERN.fullmatch(job_id) is None
        ):
            raise ImportJobError("AccessDenied", "Invalid upload target", http_status=403)
        return account_id, region, pool_id, job_id

    def _upload_path(self, job: UserImportJob) -> Path:
        return self.storage_root / self.account_id / self.region / job.pool_id / f"{job.job_id}.csv"

    def _prepare_storage_root(self) -> None:
        try:
            base_metadata = self.storage_base.lstat()
        except FileNotFoundError:
            self.storage_base.mkdir(mode=0o700, parents=True)
            base_metadata = self.storage_base.lstat()
        if (
            stat.S_ISLNK(base_metadata.st_mode)
            or not stat.S_ISDIR(base_metadata.st_mode)
            or base_metadata.st_mode & 0o022
            or (hasattr(os, "getuid") and base_metadata.st_uid != os.getuid())
        ):
            raise ImportJobError("InternalErrorException", "Unsafe user import storage")
        self._prepare_parent(self.storage_root)

    def _prepare_parent(self, path: Path) -> None:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        current = path
        while current != self.storage_base:
            metadata = current.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
            ):
                raise ImportJobError("InternalErrorException", "Unsafe user import storage")
            os.chmod(current, 0o700)
            current = current.parent

    def _open_regular(self, path: Path, expected_size: int):
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected_size:
                raise ImportJobError(
                    "InvalidParameterException", "Uploaded CSV integrity check failed"
                )
            if metadata.st_mode & 0o022:
                raise ImportJobError(
                    "InvalidParameterException", "Uploaded CSV has unsafe permissions"
                )
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise ImportJobError("InvalidParameterException", "Uploaded CSV has unsafe owner")
            return os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise

    def _delete_upload(self, job: UserImportJob) -> None:
        self._delete_path(self._upload_path(job))

    @staticmethod
    def _delete_path(path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    def _utc_now(self) -> datetime:
        value = self.now()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ImportJobError("InternalErrorException", "Import clock must be timezone-aware")
        return value.astimezone(UTC)

    @staticmethod
    def _job_cursor(job: UserImportJob) -> tuple[int, str]:
        return int(job.creation_date.timestamp() * 1_000_000), job.job_id

    def _encode_page_token(
        self, state: UserImportState, pool_id: str, cursor: tuple[int, str]
    ) -> str:
        payload = json.dumps(
            {"v": 1, "pool": pool_id, "cursor": list(cursor)},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        signature = hmac.new(state.signing_secret, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(payload + signature).decode().rstrip("=")

    def _decode_page_token(
        self, state: UserImportState, pool_id: str, token: str
    ) -> tuple[int, str]:
        if not isinstance(token, str) or not 1 <= len(token) <= 4096:
            raise ImportJobError("InvalidParameterException", "Invalid pagination token")
        try:
            decoded = base64.b64decode(
                token + "=" * (-len(token) % 4), altchars=b"-_", validate=True
            )
            payload, signature = decoded[:-32], decoded[-32:]
            if len(signature) != 32 or not hmac.compare_digest(
                signature, hmac.new(state.signing_secret, payload, hashlib.sha256).digest()
            ):
                raise ValueError
            value = json.loads(payload)
            cursor = value["cursor"]
            if (
                value != {"v": 1, "pool": pool_id, "cursor": cursor}
                or not isinstance(cursor, list)
                or len(cursor) != 2
                or not isinstance(cursor[0], int)
                or not isinstance(cursor[1], str)
            ):
                raise ValueError
            return cursor[0], cursor[1]
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            raise ImportJobError("InvalidParameterException", "Invalid pagination token")


class _HashingReader(io.RawIOBase):
    def __init__(self, stream: BinaryIO, digest: Any):
        self.stream = stream
        self.digest = digest

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        chunk = self.stream.read(len(buffer))
        if not chunk:
            return 0
        self.digest.update(chunk)
        buffer[: len(chunk)] = chunk
        return len(chunk)


def _policy_document(value: Any) -> dict[str, Any]:
    from urllib.parse import unquote

    if isinstance(value, str):
        try:
            value = json.loads(unquote(value))
        except (TypeError, json.JSONDecodeError) as error:
            raise ImportJobError("InvalidParameterException", "Invalid IAM role policy") from error
    if not isinstance(value, dict) or set(value) - {"Version", "Statement", "Id"}:
        raise ImportJobError("InvalidParameterException", "Invalid IAM role policy")
    return value


def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    value = policy.get("Statement", [])
    if isinstance(value, dict):
        value = [value]
    if (
        not isinstance(value, list)
        or len(value) > 1_000
        or not all(isinstance(statement, dict) for statement in value)
    ):
        raise ImportJobError("InvalidParameterException", "Invalid IAM role policy statements")
    return value


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if (
        isinstance(value, list)
        and len(value) <= 1_000
        and all(isinstance(item, str) for item in value)
    ):
        return value
    return []


def _trusts_cognito_import(policy: dict[str, Any]) -> bool:
    for statement in _statements(policy):
        if statement.get("Effect") != "Allow" or statement.get("Condition"):
            continue
        principal = statement.get("Principal")
        services = principal.get("Service") if isinstance(principal, dict) else None
        if "cognito-idp.amazonaws.com" in _string_list(services) and any(
            fnmatch.fnmatchcase("sts:assumerole", action.lower())
            for action in _string_list(statement.get("Action"))
        ):
            return True
    return False


def _policies_allow(policies: list[dict[str, Any]], action: str, resource: str) -> bool:
    allowed = False
    for policy in policies:
        for statement in _statements(policy):
            if statement.get("Condition"):
                continue
            actions = _string_list(statement.get("Action"))
            resources = _string_list(statement.get("Resource"))
            if not any(
                fnmatch.fnmatchcase(action.lower(), pattern.lower()) for pattern in actions
            ) or not any(fnmatch.fnmatchcase(resource, pattern) for pattern in resources):
                continue
            if statement.get("Effect") == "Deny":
                return False
            if statement.get("Effect") == "Allow":
                allowed = True
    return allowed


def _schema_storage_name(definition: dict[str, Any]) -> str:
    name = definition["Name"]
    if name in _STANDARD_HEADER or name.startswith(("custom:", "dev:")):
        return name
    prefix = "dev:" if definition.get("DeveloperOnlyAttribute") is True else "custom:"
    return f"{prefix}{name}"


def _pool_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 55
        or _POOL_PATTERN.fullmatch(value) is None
    ):
        raise ImportJobError("InvalidParameterException", "Invalid UserPoolId")
    return value


def _job_id(value: Any) -> str:
    if not isinstance(value, str) or _JOB_PATTERN.fullmatch(value) is None:
        raise ImportJobError("InvalidParameterException", "Invalid JobId")
    return value


def _completion_message(value: str) -> str:
    result = re.sub(r"[^\w]", "_", value, flags=re.UNICODE).strip("_")
    return (result or "Import_failed")[:128]


_MANAGERS_LOCK = threading.RLock()
_MANAGERS: dict[tuple[str, str], UserImportJobs] = {}


def get_user_import_jobs(account_id: str, region: str) -> UserImportJobs:
    key = (account_id, region)
    with _MANAGERS_LOCK:
        manager = _MANAGERS.get(key)
        if manager is not None:
            return manager
        with cognito_idp_stores.lock:
            region_bundle = cognito_idp_stores.get(account_id)
            store = region_bundle.get(region) if region_bundle is not None else None
        if store is None:
            raise ImportJobError("ResourceNotFoundException", "Cognito store does not exist")

        @contextmanager
        def pool_transaction(pool_id: str) -> Iterator[Any]:
            from localstack.services.cognito_idp.provider import _pool_guard

            with _pool_guard(pool_id):
                with cognito_idp_stores.lock:
                    pool = store.user_pools.get(pool_id)
                if pool is None:
                    raise ImportJobError(
                        "ResourceNotFoundException", f"User pool {pool_id} does not exist"
                    )
                yield pool

        manager = UserImportJobs(
            store=store,
            account_id=account_id,
            region=region,
            partition=get_partition(region),
            storage_root=Path(config.dirs.data or config.dirs.tmp) / "cognito-idp",
            endpoint_url=config.external_service_url(),
            pool_transaction=pool_transaction,
            state_lock=cognito_idp_stores.lock,
        )
        _MANAGERS[key] = manager
        return manager


def shutdown_user_import_jobs() -> None:
    with _MANAGERS_LOCK:
        managers = list(_MANAGERS.values())
        _MANAGERS.clear()
    for manager in managers:
        manager.shutdown(wait=True)
