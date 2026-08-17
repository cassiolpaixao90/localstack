import pickle
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from localstack.services.cognito_idp.user_pool_replicas import (
    UserPoolReplicaError,
    UserPoolReplicaTopology,
    create_replica,
    delete_replica,
    list_replicas,
    update_replica,
)

SIGNING_KEY = b"replica-pagination-key-32-bytes"
NOW = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)


@pytest.fixture
def topology():
    return UserPoolReplicaTopology(
        account_id="123456789012",
        partition="aws",
        pool_id="us-east-1_EXAMPLE",
        primary_region="us-east-1",
    )


def _create(topology, region="us-west-2"):
    return create_replica(
        topology,
        caller_region="us-east-1",
        eligible=True,
        region_name=region,
        tags={"Environment": "Production"},
        now=NOW,
    )


def test_replica_crudl_includes_primary_and_enforces_lifecycle(topology):
    created = _create(topology)["UserPoolReplica"]
    assert created == {
        "RegionName": "us-west-2",
        "Role": "SECONDARY",
        "Status": "CREATING",
        "UserPoolArn": ("arn:aws:cognito-idp:us-west-2:123456789012:userpool/us-east-1_EXAMPLE"),
    }
    creating = list_replicas(topology, signing_key=SIGNING_KEY, now=NOW)["UserPoolReplicas"]
    assert creating[1]["Status"] == "CREATING"
    listed = list_replicas(
        topology, signing_key=SIGNING_KEY, now=NOW + timedelta(seconds=2)
    )["UserPoolReplicas"]
    assert listed[1]["Status"] == "INACTIVE"
    assert [replica["Role"] for replica in listed] == ["PRIMARY", "SECONDARY"]
    assert listed[0]["RegionName"] == "us-east-1"

    updated = update_replica(
        topology,
        caller_region="us-west-2",
        region_name="us-west-2",
        status="ACTIVE",
    )["UserPoolReplica"]
    assert updated["Status"] == "ACTIVE"
    with pytest.raises(UserPoolReplicaError, match="INACTIVE"):
        delete_replica(topology, caller_region="us-east-1", region_name="us-west-2")
    update_replica(
        topology,
        caller_region="us-east-1",
        region_name="us-west-2",
        status="INACTIVE",
    )
    deleted = delete_replica(
        topology,
        caller_region="us-east-1",
        region_name="us-west-2",
        now=NOW + timedelta(seconds=3),
    )["UserPoolReplica"]
    assert deleted["Status"] == "DELETING"
    deleting = list_replicas(
        topology, signing_key=SIGNING_KEY, now=NOW + timedelta(seconds=3)
    )["UserPoolReplicas"]
    assert deleting[1]["Status"] == "DELETING"
    assert list_replicas(
        topology, signing_key=SIGNING_KEY, now=NOW + timedelta(seconds=5)
    )["UserPoolReplicas"] == [listed[0]]


def test_replica_quota_region_authority_and_eligibility_are_fail_closed(topology):
    with pytest.raises(UserPoolReplicaError) as tier:
        create_replica(
            topology,
            caller_region="us-east-1",
            eligible=False,
            region_name="us-west-2",
        )
    assert tier.value.code == "FeatureUnavailableInTierException"
    with pytest.raises(UserPoolReplicaError) as primary:
        create_replica(
            topology,
            caller_region="us-west-2",
            eligible=True,
            region_name="eu-west-1",
        )
    assert primary.value.code == "OperationNotEnabledException"
    _create(topology)
    with pytest.raises(UserPoolReplicaError) as quota:
        _create(topology, "eu-west-1")
    assert quota.value.code == "LimitExceededException"


def test_replica_pagination_token_is_hmac_bound_to_pool_and_account(topology):
    _create(topology)
    first = list_replicas(
        topology, signing_key=SIGNING_KEY, page_size=1, now=NOW + timedelta(seconds=2)
    )
    assert len(first["UserPoolReplicas"]) == 1
    assert first["NextToken"]
    second = list_replicas(
        topology,
        next_token=first["NextToken"],
        signing_key=SIGNING_KEY,
        page_size=1,
        now=NOW + timedelta(seconds=2),
    )
    assert second["UserPoolReplicas"][0]["Role"] == "SECONDARY"
    assert "NextToken" not in second

    for other in (
        UserPoolReplicaTopology(
            account_id="999999999999",
            partition="aws",
            pool_id=topology.pool_id,
            primary_region=topology.primary_region,
        ),
        UserPoolReplicaTopology(
            account_id=topology.account_id,
            partition="aws",
            pool_id="us-east-1_OTHER",
            primary_region=topology.primary_region,
        ),
    ):
        with pytest.raises(UserPoolReplicaError, match="Invalid NextToken"):
            list_replicas(
                other,
                next_token=first["NextToken"],
                signing_key=SIGNING_KEY,
                page_size=1,
                now=NOW + timedelta(seconds=2),
            )


def test_replica_state_persists_and_create_is_atomic_under_caller_lock(topology):
    restored = pickle.loads(pickle.dumps(topology))
    lock = threading.Lock()

    def create_once(region):
        try:
            with lock:
                _create(restored, region)
            return "success"
        except UserPoolReplicaError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(create_once, ("us-west-2", "eu-west-1")))
    assert results.count("success") == 1
    assert results.count("LimitExceededException") == 1


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("region_name", "bad"),
        ("region_name", "us-east-1"),
        ("tags", {"": "invalid"}),
        ("tags", {"k": "x" * 257}),
    ),
)
def test_create_replica_rejects_invalid_modeled_inputs(topology, field, value):
    request = {
        "caller_region": "us-east-1",
        "eligible": True,
        "region_name": "us-west-2",
    }
    request[field] = value
    with pytest.raises(UserPoolReplicaError):
        create_replica(topology, **request)
