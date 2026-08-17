import pickle
import threading
import time

import pytest

from localstack.services.cognito_idp.bcrypt_adapter import (
    BcryptAdapterBudget,
    BcryptAdapterStatus,
    BcryptAdmissionState,
    BcryptVerificationAdapter,
)

_HASH_04 = "$2b$04$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW"
_HASH_10 = "$2b$10$CtA.Rcu/szzn9U00wpUjOuvX2WwIsmGJq7qh/NNv7sYonMQD2H9dS"


class _NativeBackend:
    def __init__(self, result=True):
        self.result = result
        self.calls = []

    def checkpw(self, password, encoded):
        self.calls.append((password, encoded))
        return self.result


def _verify(
    adapter,
    *,
    account_id="123456789012",
    credential_id="pool/alice",
    password="password",
    encoded=_HASH_04,
    migrate=lambda _: None,
):
    return adapter.verify_and_migrate(
        account_id=account_id,
        credential_id=credential_id,
        password=password,
        encoded=encoded,
        migrate=migrate,
    )


def test_selects_available_native_backend_and_migrates_only_after_success():
    native = _NativeBackend()
    pure_called = False
    migrated = []

    def unexpected_pure(*_, **__):
        nonlocal pure_called
        pure_called = True
        raise AssertionError("native backend must be preferred")

    adapter = BcryptVerificationAdapter(
        BcryptAdmissionState(), native_backend=native, pure_verifier=unexpected_pure
    )

    result = _verify(adapter, migrate=migrated.append)

    assert result.status == BcryptAdapterStatus.VERIFIED
    assert result.verified and result.migrated
    assert native.calls == [(b"password", _HASH_04.encode())]
    assert migrated == [b"password"]
    assert not pure_called


def test_falls_back_to_pure_verifier_without_optional_dependency():
    calls = []

    def pure(password, encoded, **kwargs):
        calls.append((password, encoded, kwargs))
        return True

    adapter = BcryptVerificationAdapter(
        BcryptAdmissionState(),
        native_backend=None,
        pure_verifier=pure,
        pure_gate=threading.BoundedSemaphore(1),
    )

    result = _verify(adapter)

    assert result.status == BcryptAdapterStatus.VERIFIED
    assert calls[0][0:2] == (b"password", _HASH_04.encode())
    assert calls[0][2]["maximum_wall_seconds"] == 15.0
    assert calls[0][2]["maximum_cpu_seconds"] == 15.0


def test_global_pure_gate_rejects_concurrent_cpu_work_without_queueing():
    started = threading.Event()
    release = threading.Event()
    gate = threading.BoundedSemaphore(1)

    def blocking_pure(*_, **__):
        started.set()
        assert release.wait(2)
        return False

    adapter = BcryptVerificationAdapter(
        BcryptAdmissionState(),
        native_backend=None,
        pure_verifier=blocking_pure,
        pure_gate=gate,
    )
    first = []
    thread = threading.Thread(target=lambda: first.append(_verify(adapter)))
    thread.start()
    assert started.wait(1)

    second = _verify(adapter, credential_id="pool/bob")

    assert second.status == BcryptAdapterStatus.BUSY
    release.set()
    thread.join(2)
    assert first[0].status == BcryptAdapterStatus.INVALID


def test_wall_timeout_returns_without_migration_and_gate_stays_held_until_worker_exits():
    gate = threading.BoundedSemaphore(1)
    migrated = []

    def slow_pure(*_, **__):
        time.sleep(0.08)
        return True

    adapter = BcryptVerificationAdapter(
        BcryptAdmissionState(),
        budget=BcryptAdapterBudget(maximum_wall_seconds=0.01),
        native_backend=None,
        pure_verifier=slow_pure,
        pure_gate=gate,
    )

    started = time.monotonic()
    timed_out = _verify(adapter, migrate=migrated.append)
    elapsed = time.monotonic() - started
    busy = _verify(adapter, credential_id="pool/bob", migrate=migrated.append)

    assert timed_out.status == BcryptAdapterStatus.TIMEOUT
    assert elapsed < 0.06
    assert busy.status == BcryptAdapterStatus.BUSY
    assert migrated == []
    time.sleep(0.1)
    assert _verify(adapter, credential_id="pool/carol", migrate=migrated.append).status in {
        BcryptAdapterStatus.TIMEOUT,
        BcryptAdapterStatus.RATE_LIMITED,
    }
    assert migrated == []


def test_cooperative_cpu_budget_aborts_real_pure_key_setup():
    adapter = BcryptVerificationAdapter(
        BcryptAdmissionState(),
        budget=BcryptAdapterBudget(
            maximum_wall_seconds=1,
            maximum_cpu_seconds=0.001,
        ),
        native_backend=None,
        pure_gate=threading.BoundedSemaphore(1),
    )

    started = time.monotonic()
    result = _verify(adapter)

    assert result.status == BcryptAdapterStatus.BUDGET_EXCEEDED
    assert time.monotonic() - started < 0.3


def test_rate_limits_each_account_and_recovers_after_the_window():
    now = [100.0]
    backend = _NativeBackend(result=False)
    adapter = BcryptVerificationAdapter(
        BcryptAdmissionState(),
        budget=BcryptAdapterBudget(attempts_per_account=2, admission_window_seconds=10),
        native_backend=backend,
        clock=lambda: now[0],
    )

    assert _verify(adapter, credential_id="one").status == BcryptAdapterStatus.INVALID
    assert _verify(adapter, credential_id="two").status == BcryptAdapterStatus.INVALID
    assert _verify(adapter, credential_id="three").status == BcryptAdapterStatus.RATE_LIMITED
    assert (
        _verify(adapter, account_id="210987654321", credential_id="other").status
        == BcryptAdapterStatus.INVALID
    )
    now[0] += 11
    assert _verify(adapter, credential_id="three").status == BcryptAdapterStatus.INVALID


def test_successful_migration_is_one_shot_and_replay_never_rechecks_password():
    backend = _NativeBackend()
    state = BcryptAdmissionState()
    adapter = BcryptVerificationAdapter(state, native_backend=backend)
    migrated = []

    first = _verify(adapter, password="one-time-secret", migrate=migrated.append)
    replay = _verify(adapter, password="one-time-secret", migrate=migrated.append)

    assert first.status == BcryptAdapterStatus.VERIFIED
    assert replay.status == BcryptAdapterStatus.REPLAY
    assert len(backend.calls) == 1
    assert migrated == [b"one-time-secret"]
    persisted = pickle.dumps(state)
    assert b"one-time-secret" not in persisted
    assert "one-time-secret" not in repr(state)


def test_failed_migration_is_not_marked_complete_and_can_retry():
    backend = _NativeBackend()
    adapter = BcryptVerificationAdapter(BcryptAdmissionState(), native_backend=backend)

    failed = _verify(
        adapter,
        migrate=lambda _: (_ for _ in ()).throw(RuntimeError("storage unavailable")),
    )
    retried = _verify(adapter)

    assert failed.status == BcryptAdapterStatus.MIGRATION_FAILED
    assert failed.verified and not failed.migrated
    assert retried.status == BcryptAdapterStatus.VERIFIED
    assert len(backend.calls) == 2


@pytest.mark.parametrize(
    "encoded",
    [
        "$2b$03$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW",
        "$2b$11$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW",
        "$2x$04$DCq7YPn5Rq63x1Lad4cll.V212arh7HmBEQj/tjT9AzbAGCgFF0eW",
        "malformed",
    ],
)
def test_cost_and_format_are_rejected_before_any_backend_work(encoded):
    backend = _NativeBackend()
    adapter = BcryptVerificationAdapter(BcryptAdmissionState(), native_backend=backend)

    assert _verify(adapter, encoded=encoded).status == BcryptAdapterStatus.INVALID
    assert backend.calls == []


def test_native_backend_is_still_bounded_to_the_supported_cost_ten():
    backend = _NativeBackend()
    adapter = BcryptVerificationAdapter(BcryptAdmissionState(), native_backend=backend)

    result = _verify(adapter, encoded=_HASH_10)

    assert result.status == BcryptAdapterStatus.VERIFIED
    assert backend.calls == [(b"password", _HASH_10.encode())]


def test_account_table_is_bounded_and_stale_admissions_are_cleaned():
    now = [100.0]
    adapter = BcryptVerificationAdapter(
        BcryptAdmissionState(),
        budget=BcryptAdapterBudget(maximum_accounts=1, admission_window_seconds=10),
        native_backend=_NativeBackend(result=False),
        clock=lambda: now[0],
    )

    assert _verify(adapter).status == BcryptAdapterStatus.INVALID
    assert _verify(adapter, account_id="210987654321").status == BcryptAdapterStatus.RATE_LIMITED
    now[0] += 11
    assert _verify(adapter, account_id="210987654321").status == BcryptAdapterStatus.INVALID


@pytest.mark.parametrize(
    "kwargs",
    [
        {"minimum_cost": 3},
        {"maximum_cost": 11},
        {"maximum_wall_seconds": 0},
        {"maximum_cpu_seconds": float("inf")},
        {"attempts_per_account": 0},
        {"admission_window_seconds": -1},
        {"maximum_accounts": 0},
        {"maximum_migrations": 0},
    ],
)
def test_adapter_budget_is_validated(kwargs):
    with pytest.raises(ValueError, match="invalid bcrypt adapter budget"):
        BcryptAdapterBudget(**kwargs)
