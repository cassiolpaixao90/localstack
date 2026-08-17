import pickle
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from botocore.session import Session

from localstack.services.cognito_idp import provisioned_rate_enforcement as rate_module
from localstack.services.cognito_idp.provisioned_rate_enforcement import (
    ADJUSTABLE_OPERATION_CATEGORIES,
    PROVISIONED_RATE_EXEMPT_OPERATIONS,
    ProvisionedRateLimitError,
    ProvisionedRateLimitState,
    adjustable_category_for_operation,
    consume_provisioned_capacity,
)
from localstack.utils.aws.arns import get_partition

NOW = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)


@pytest.fixture
def scope(region_name, monkeypatch):
    monkeypatch.setitem(rate_module.DEFAULT_API_CATEGORY_LIMITS, "UserAuthentication", 5)
    return f"{uuid.uuid4().int % 10**12:012d}", region_name


def _consume(state, scope, *, now=NOW, limit=5, cost=1):
    return consume_provisioned_capacity(
        state,
        account_id=scope[0],
        region=scope[1],
        category="UserAuthentication",
        provisioned_limit=limit,
        cost=cost,
        now=now,
    )


def test_bucket_enforces_burst_and_refills_with_injected_clock(scope):
    state = ProvisionedRateLimitState()
    for remaining in (4, 3, 2, 1, 0):
        assert _consume(state, scope).remaining == remaining
    with pytest.raises(ProvisionedRateLimitError) as throttled:
        _consume(state, scope)
    assert throttled.value.code == "TooManyRequestsException"
    assert throttled.value.retry_after_seconds == pytest.approx(0.2)

    assert _consume(state, scope, now=NOW + timedelta(milliseconds=200)).remaining == 0
    assert _consume(state, scope, now=NOW + timedelta(seconds=1)).remaining == 3


def test_concurrent_consumption_is_atomic_and_never_over_admits(scope):
    state = ProvisionedRateLimitState()
    barrier = threading.Barrier(20)

    def attempt(_):
        barrier.wait(timeout=5)
        try:
            _consume(state, scope)
            return "admitted"
        except ProvisionedRateLimitError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=20) as executor:
        outcomes = list(executor.map(attempt, range(20)))

    assert outcomes.count("admitted") == 5
    assert outcomes.count("TooManyRequestsException") == 15


def test_pickle_restart_preserves_consumed_capacity_and_restores_lock(scope):
    state = ProvisionedRateLimitState()
    _consume(state, scope, cost=4)
    restored = pickle.loads(pickle.dumps(state))

    assert _consume(restored, scope).remaining == 0
    with pytest.raises(ProvisionedRateLimitError):
        _consume(restored, scope)
    assert _consume(restored, scope, now=NOW + timedelta(seconds=1)).remaining == 4


def test_limit_changes_do_not_create_capacity_and_decrease_clamps_atomically(scope):
    state = ProvisionedRateLimitState()
    _consume(state, scope, limit=5, cost=4)

    assert _consume(state, scope, limit=10).remaining == 0
    with pytest.raises(ProvisionedRateLimitError):
        _consume(state, scope, limit=5, cost=2)
    assert _consume(state, scope, limit=5, now=NOW + timedelta(milliseconds=200)).remaining == 0


def test_scope_category_clock_and_cost_validation_are_fail_closed_without_mutation(scope):
    state = ProvisionedRateLimitState()
    _consume(state, scope)
    before = pickle.dumps(state)
    invalid_requests = (
        {"account_id": "invalid"},
        {"region": "bad"},
        {"category": "UserUpdate"},
        {"provisioned_limit": 4},
        {"cost": 0},
        {"now": NOW - timedelta(seconds=1)},
    )
    base = {
        "account_id": scope[0],
        "region": scope[1],
        "category": "UserAuthentication",
        "provisioned_limit": 5,
        "cost": 1,
        "now": NOW,
    }
    for changes in invalid_requests:
        request = dict(base)
        request.update(changes)
        with pytest.raises(ProvisionedRateLimitError):
            consume_provisioned_capacity(state, **request)
    assert pickle.dumps(state) == before


def test_account_region_and_category_have_independent_buckets(scope):
    state = ProvisionedRateLimitState()
    monkeypatch_category_default = rate_module.DEFAULT_API_CATEGORY_LIMITS["UserToken"]
    alternate_region = next(
        region
        for region in Session().get_available_regions("cognito-idp")
        if region != scope[1] and get_partition(region) == get_partition(scope[1])
    )
    other_account = f"{uuid.uuid4().int % 10**12:012d}"
    for account_id, region, category in (
        (scope[0], scope[1], "UserAuthentication"),
        (scope[0], alternate_region, "UserAuthentication"),
        (other_account, scope[1], "UserAuthentication"),
        (scope[0], scope[1], "UserToken"),
    ):
        decision = consume_provisioned_capacity(
            state,
            account_id=account_id,
            region=region,
            category=category,
            provisioned_limit=(
                5 if category == "UserAuthentication" else monkeypatch_category_default
            ),
            cost=(5 if category == "UserAuthentication" else monkeypatch_category_default),
            now=NOW,
        )
        assert decision.remaining == 0
    assert len(state.buckets) == 4


def test_adjustable_operation_mapping_is_closed_and_unknown_operations_are_unmetered():
    assert adjustable_category_for_operation("AdminGetUserAuthFactors") == "UserRead"
    assert adjustable_category_for_operation("GetTokensFromRefreshToken") == "UserAuthentication"
    assert adjustable_category_for_operation("FederationCallback") == "UserFederation"
    assert adjustable_category_for_operation("DescribeUserPool") is None
    assert set(ADJUSTABLE_OPERATION_CATEGORIES.values()) == set(
        rate_module.DEFAULT_API_CATEGORY_LIMITS
    )
    with pytest.raises(ProvisionedRateLimitError):
        adjustable_category_for_operation("")
    with pytest.raises(ProvisionedRateLimitError):
        adjustable_category_for_operation("FutureUnreviewedOperation")


def test_every_modeled_operation_has_an_explicit_rate_classification():
    operations = set(Session().get_service_model("cognito-idp").operation_names)
    assert len(operations) == 129
    assert (
        operations
        == (set(ADJUSTABLE_OPERATION_CATEGORIES) & operations) | PROVISIONED_RATE_EXEMPT_OPERATIONS
    )
    assert not (set(ADJUSTABLE_OPERATION_CATEGORIES) & PROVISIONED_RATE_EXEMPT_OPERATIONS)


def test_bucket_quota_and_scope_cleanup_are_bounded(scope, monkeypatch):
    state = ProvisionedRateLimitState()
    monkeypatch.setattr(rate_module, "MAX_PROVISIONED_RATE_BUCKETS", 1)
    _consume(state, scope)

    with pytest.raises(ProvisionedRateLimitError) as full:
        consume_provisioned_capacity(
            state,
            account_id=scope[0],
            region=scope[1],
            category="UserToken",
            provisioned_limit=rate_module.DEFAULT_API_CATEGORY_LIMITS["UserToken"],
            now=NOW,
        )
    assert full.value.code == "LimitExceededException"
    assert len(state.buckets) == 1

    state.cleanup_scope(*scope)
    assert state.buckets == {}
