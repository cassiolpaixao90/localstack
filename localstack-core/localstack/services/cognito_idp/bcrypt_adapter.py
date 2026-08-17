"""Bounded adapter for one-time migration of imported bcrypt credentials."""

from __future__ import annotations

import dataclasses
import hashlib
import importlib
import math
import queue
import re
import threading
import time
from collections import deque
from collections.abc import Callable
from enum import StrEnum
from typing import Any, Protocol

from localstack.services.cognito_idp.bcrypt_verify import (
    BcryptBudgetExceeded,
    BcryptWorkBudget,
    verify_bcrypt_bounded,
)

_HASH = re.compile(rb"^\$2[aby]\$(?P<cost>[0-9]{2})\$[./A-Za-z0-9]{53}$")
_PURE_BCRYPT_GATE = threading.BoundedSemaphore(1)
_AUTO_BACKEND = object()


class NativeBcryptBackend(Protocol):
    def checkpw(self, password: bytes, hashed_password: bytes) -> bool: ...


class BcryptAdapterStatus(StrEnum):
    VERIFIED = "VERIFIED"
    INVALID = "INVALID"
    BUSY = "BUSY"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    REPLAY = "REPLAY"
    MIGRATION_FAILED = "MIGRATION_FAILED"


@dataclasses.dataclass(frozen=True)
class BcryptAdapterResult:
    status: BcryptAdapterStatus
    verified: bool = False
    migrated: bool = False


@dataclasses.dataclass(frozen=True)
class BcryptAdapterBudget:
    minimum_cost: int = 4
    maximum_cost: int = 10
    maximum_wall_seconds: float = 15.0
    maximum_cpu_seconds: float = 15.0
    attempts_per_account: int = 4
    admission_window_seconds: float = 60.0
    maximum_accounts: int = 10_000
    maximum_migrations: int = 100_000

    def __post_init__(self) -> None:
        numeric_seconds = (self.maximum_wall_seconds, self.maximum_cpu_seconds)
        if (
            not isinstance(self.minimum_cost, int)
            or isinstance(self.minimum_cost, bool)
            or not isinstance(self.maximum_cost, int)
            or isinstance(self.maximum_cost, bool)
            or not 4 <= self.minimum_cost <= self.maximum_cost <= 10
            or any(
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value <= 0
                for value in numeric_seconds
            )
            or not isinstance(self.attempts_per_account, int)
            or isinstance(self.attempts_per_account, bool)
            or not 1 <= self.attempts_per_account <= 1_000
            or not isinstance(self.admission_window_seconds, (int, float))
            or isinstance(self.admission_window_seconds, bool)
            or not math.isfinite(self.admission_window_seconds)
            or self.admission_window_seconds <= 0
            or not isinstance(self.maximum_accounts, int)
            or isinstance(self.maximum_accounts, bool)
            or not 1 <= self.maximum_accounts <= 1_000_000
            or not isinstance(self.maximum_migrations, int)
            or isinstance(self.maximum_migrations, bool)
            or not 1 <= self.maximum_migrations <= 1_000_000
        ):
            raise ValueError("invalid bcrypt adapter budget")


@dataclasses.dataclass
class BcryptAdmissionState:
    attempts: dict[str, deque[float]] = dataclasses.field(default_factory=dict)
    inflight: set[bytes] = dataclasses.field(default_factory=set)
    migrated: set[bytes] = dataclasses.field(default_factory=set)
    _lock: Any = dataclasses.field(
        default_factory=threading.RLock, init=False, repr=False, compare=False
    )

    def __getstate__(self) -> dict[str, Any]:
        with self._lock:
            state = dict(self.__dict__)
            state.pop("_lock", None)
            return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._lock = threading.RLock()


class BcryptVerificationAdapter:
    def __init__(
        self,
        state: BcryptAdmissionState,
        *,
        budget: BcryptAdapterBudget | None = None,
        native_backend: NativeBcryptBackend | None | object = _AUTO_BACKEND,
        pure_verifier: Callable[..., bool] = verify_bcrypt_bounded,
        clock: Callable[[], float] = time.monotonic,
        pure_gate: Any = _PURE_BCRYPT_GATE,
    ):
        if not isinstance(state, BcryptAdmissionState):
            raise ValueError("invalid bcrypt admission state")
        if not callable(pure_verifier) or not callable(clock):
            raise ValueError("invalid bcrypt adapter dependency")
        self._state = state
        self._budget = budget or BcryptAdapterBudget()
        self._native = (
            _load_native_backend() if native_backend is _AUTO_BACKEND else native_backend
        )
        self._pure_verifier = pure_verifier
        self._clock = clock
        self._pure_gate = pure_gate

    def verify_and_migrate(
        self,
        *,
        account_id: Any,
        credential_id: Any,
        password: Any,
        encoded: Any,
        migrate: Callable[[bytes], None],
    ) -> BcryptAdapterResult:
        normalized = _request(account_id, credential_id, password, encoded, migrate, self._budget)
        if normalized is None:
            return BcryptAdapterResult(BcryptAdapterStatus.INVALID)
        account_id, credential_key, password_bytes, encoded_bytes = normalized
        now = self._clock()
        if not isinstance(now, (int, float)) or isinstance(now, bool) or not math.isfinite(now):
            return BcryptAdapterResult(BcryptAdapterStatus.INVALID)
        admission = self._admit(account_id, credential_key, float(now))
        if admission is not None:
            return BcryptAdapterResult(admission)
        try:
            if self._native is None:
                if not self._pure_gate.acquire(blocking=False):
                    return BcryptAdapterResult(BcryptAdapterStatus.BUSY)
                operation = lambda: self._pure_verifier(
                    password_bytes,
                    encoded_bytes,
                    budget=BcryptWorkBudget(
                        minimum_cost=self._budget.minimum_cost,
                        maximum_cost=self._budget.maximum_cost,
                    ),
                    maximum_wall_seconds=self._budget.maximum_wall_seconds,
                    maximum_cpu_seconds=self._budget.maximum_cpu_seconds,
                )
                status, verified = self._run(operation, release_gate=True)
            else:
                operation = lambda: bool(self._native.checkpw(password_bytes, encoded_bytes))
                status, verified = self._run(operation, release_gate=False)
            if status is not None:
                return BcryptAdapterResult(status)
            if not verified:
                return BcryptAdapterResult(BcryptAdapterStatus.INVALID)
            try:
                migrate(password_bytes)
            except Exception:
                return BcryptAdapterResult(
                    BcryptAdapterStatus.MIGRATION_FAILED,
                    verified=True,
                )
            if not self._complete_migration(credential_key):
                return BcryptAdapterResult(
                    BcryptAdapterStatus.MIGRATION_FAILED,
                    verified=True,
                )
            return BcryptAdapterResult(
                BcryptAdapterStatus.VERIFIED,
                verified=True,
                migrated=True,
            )
        finally:
            self._finish(credential_key)

    def _run(
        self, operation: Callable[[], bool], *, release_gate: bool
    ) -> tuple[BcryptAdapterStatus | None, bool]:
        result: queue.Queue[tuple[BcryptAdapterStatus | None, bool]] = queue.Queue(maxsize=1)

        def worker() -> None:
            started = time.thread_time()
            try:
                verified = bool(operation())
                if time.thread_time() - started > self._budget.maximum_cpu_seconds:
                    result.put((BcryptAdapterStatus.BUDGET_EXCEEDED, False))
                else:
                    result.put((None, verified))
            except BcryptBudgetExceeded:
                result.put((BcryptAdapterStatus.BUDGET_EXCEEDED, False))
            except Exception:
                result.put((BcryptAdapterStatus.INVALID, False))
            finally:
                if release_gate:
                    self._pure_gate.release()

        thread = threading.Thread(target=worker, name="cognito-bcrypt-verify", daemon=True)
        try:
            thread.start()
        except Exception:
            if release_gate:
                self._pure_gate.release()
            return BcryptAdapterStatus.INVALID, False
        thread.join(self._budget.maximum_wall_seconds)
        if thread.is_alive():
            return BcryptAdapterStatus.TIMEOUT, False
        try:
            return result.get_nowait()
        except queue.Empty:
            return BcryptAdapterStatus.INVALID, False

    def _admit(
        self, account_id: str, credential_key: bytes, now: float
    ) -> BcryptAdapterStatus | None:
        with self._state._lock:
            if credential_key in self._state.migrated or credential_key in self._state.inflight:
                return BcryptAdapterStatus.REPLAY
            attempts = self._state.attempts.get(account_id)
            if attempts is None:
                self._prune_accounts(now)
                if len(self._state.attempts) >= self._budget.maximum_accounts:
                    return BcryptAdapterStatus.RATE_LIMITED
                attempts = self._state.attempts[account_id] = deque()
            cutoff = now - self._budget.admission_window_seconds
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if len(attempts) >= self._budget.attempts_per_account:
                return BcryptAdapterStatus.RATE_LIMITED
            attempts.append(now)
            self._state.inflight.add(credential_key)
            return None

    def _prune_accounts(self, now: float) -> None:
        cutoff = now - self._budget.admission_window_seconds
        for account_id, attempts in tuple(self._state.attempts.items()):
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if not attempts:
                self._state.attempts.pop(account_id, None)

    def _complete_migration(self, credential_key: bytes) -> bool:
        with self._state._lock:
            if len(self._state.migrated) >= self._budget.maximum_migrations:
                return False
            self._state.migrated.add(credential_key)
            return True

    def _finish(self, credential_key: bytes) -> None:
        with self._state._lock:
            self._state.inflight.discard(credential_key)


def _request(
    account_id: Any,
    credential_id: Any,
    password: Any,
    encoded: Any,
    migrate: Any,
    budget: BcryptAdapterBudget,
) -> tuple[str, bytes, bytes, bytes] | None:
    try:
        if (
            not isinstance(account_id, str)
            or re.fullmatch(r"[0-9]{12}", account_id) is None
            or not isinstance(credential_id, str)
            or not 1 <= len(credential_id.encode()) <= 512
            or not isinstance(password, (str, bytes))
            or not isinstance(encoded, (str, bytes))
            or not callable(migrate)
        ):
            return None
        password_bytes = password.encode() if isinstance(password, str) else password
        encoded_bytes = encoded.encode("ascii") if isinstance(encoded, str) else encoded
        if len(password_bytes) > 131_072:
            return None
        match = _HASH.fullmatch(encoded_bytes)
        if match is None or not budget.minimum_cost <= int(match.group("cost")) <= budget.maximum_cost:
            return None
        credential_key = hashlib.sha256(f"{account_id}\0{credential_id}".encode()).digest()
        return account_id, credential_key, password_bytes, encoded_bytes
    except Exception:
        return None


def _load_native_backend() -> NativeBcryptBackend | None:
    try:
        module = importlib.import_module("bcrypt")
    except (ImportError, ModuleNotFoundError):
        return None
    return module if callable(getattr(module, "checkpw", None)) else None
