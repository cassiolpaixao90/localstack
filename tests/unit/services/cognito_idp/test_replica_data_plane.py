import base64
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from botocore.session import Session
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from localstack.services.cognito_idp.replica_data_plane import (
    ReplicaDataPlaneError,
    resolve_regional_pool,
)
from localstack.services.cognito_idp.tokens import (
    decode_jwt_segment,
    generate_signing_key,
    public_key_from_jwk,
    sign_jwt,
)
from localstack.services.cognito_idp.user_pool_replicas import (
    UserPoolReplica,
    UserPoolReplicaTopology,
)
from localstack.utils.aws.arns import get_partition

NOW = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)


@pytest.fixture
def regional_pool(region_name):
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    secondary_region = next(
        region
        for region in Session().get_available_regions("cognito-idp")
        if region != region_name and get_partition(region) == get_partition(region_name)
    )
    partition = get_partition(region_name)
    dns_suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
    access_key_id, access_private_key, access_jwk = generate_signing_key()
    id_key_id, id_private_key, id_jwk = generate_signing_key()
    pool = SimpleNamespace(
        access_signing_jwk=access_jwk,
        access_signing_key_id=access_key_id,
        access_signing_private_key_pem=access_private_key,
        arn=(
            f"arn:{partition}:cognito-idp:{region_name}:{account_id}:userpool/{region_name}_EXAMPLE"
        ),
        clients={"client-a": {"name": "web"}},
        id_signing_jwk=id_jwk,
        id_signing_key_id=id_key_id,
        id_signing_private_key_pem=id_private_key,
        pool_id=f"{region_name}_EXAMPLE",
        users={"alice": {"email": "alice@example.test"}},
    )
    topology = UserPoolReplicaTopology(
        account_id=account_id,
        partition=partition,
        pool_id=pool.pool_id,
        primary_region=region_name,
        secondary=UserPoolReplica(region_name=secondary_region, status="ACTIVE"),
    )
    return pool, topology, secondary_region, dns_suffix


@pytest.mark.parametrize("operation", ["AUTHENTICATE", "JWKS", "READ", "TOKEN"])
def test_active_secondary_shares_primary_state_with_regional_identity(regional_pool, operation):
    pool, topology, secondary_region, dns_suffix = regional_pool
    view = resolve_regional_pool(
        topology,
        pool,
        serving_region=secondary_region,
        operation=operation,
        dns_suffix=dns_suffix,
        now=NOW,
    )

    assert view.primary_pool is pool
    assert view.issuer == (
        f"https://cognito-idp.{secondary_region}.{dns_suffix}/{topology.pool_id}"
    )
    assert view.user_pool_arn == (
        f"arn:{topology.partition}:cognito-idp:{secondary_region}:{topology.account_id}:"
        f"userpool/{topology.pool_id}"
    )
    assert {key["kid"] for key in view.jwks()["keys"]} == {
        pool.access_signing_key_id,
        pool.id_signing_key_id,
    }
    pool.users["bob"] = {"email": "bob@example.test"}
    pool.clients["client-b"] = {"name": "mobile"}
    assert "bob" in view.users
    assert "client-b" in view.clients
    assert view.token_claims({"sub": "user-sub", "token_use": "id"})["iss"] == view.issuer


def test_secondary_token_uses_regional_issuer_and_primary_jwks_verifies_signature(regional_pool):
    pool, topology, secondary_region, dns_suffix = regional_pool
    view = resolve_regional_pool(
        topology,
        pool,
        serving_region=secondary_region,
        operation="TOKEN",
        dns_suffix=dns_suffix,
        now=NOW,
    )
    token = sign_jwt(
        pool.id_signing_private_key_pem,
        pool.id_signing_key_id,
        view.token_claims({"aud": "client-a", "sub": "user-sub", "token_use": "id"}),
        now=int(NOW.timestamp()),
    )
    encoded_header, encoded_claims, encoded_signature = token.split(".")

    assert decode_jwt_segment(encoded_claims)["iss"] == view.issuer
    jwk = next(key for key in view.jwks()["keys"] if key["kid"] == pool.id_signing_key_id)
    public_key_from_jwk(jwk).verify(
        base64.urlsafe_b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4)),
        f"{encoded_header}.{encoded_claims}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


@pytest.mark.parametrize("status", ["CREATING", "INACTIVE", "DELETING"])
def test_secondary_fails_closed_until_active(regional_pool, status):
    pool, topology, secondary_region, dns_suffix = regional_pool
    topology.secondary.status = status

    with pytest.raises(ReplicaDataPlaneError) as denied:
        resolve_regional_pool(
            topology,
            pool,
            serving_region=secondary_region,
            operation="AUTHENTICATE",
            dns_suffix=dns_suffix,
            now=NOW,
        )

    assert denied.value.code == "OperationNotEnabledException"


def test_transition_reconciles_before_authorization_and_user_writes_remain_primary_only(
    regional_pool,
):
    pool, topology, secondary_region, dns_suffix = regional_pool
    topology.secondary.status = "CREATING"
    topology.secondary.transition_at = NOW - timedelta(seconds=1)

    with pytest.raises(ReplicaDataPlaneError):
        resolve_regional_pool(
            topology,
            pool,
            serving_region=secondary_region,
            operation="AUTHENTICATE",
            dns_suffix=dns_suffix,
            now=NOW,
        )
    assert topology.secondary.status == "INACTIVE"

    topology.secondary.status = "ACTIVE"
    with pytest.raises(ReplicaDataPlaneError) as immutable:
        resolve_regional_pool(
            topology,
            pool,
            serving_region=secondary_region,
            operation="USER_WRITE",
            dns_suffix=dns_suffix,
            now=NOW,
        )
    assert immutable.value.code == "OperationNotEnabledException"

    primary = resolve_regional_pool(
        topology,
        pool,
        serving_region=topology.primary_region,
        operation="USER_WRITE",
        dns_suffix=dns_suffix,
        now=NOW,
    )
    assert primary.role == "PRIMARY"


def test_wrong_region_topology_pool_and_dns_suffix_fail_closed(regional_pool):
    pool, topology, secondary_region, dns_suffix = regional_pool
    unrelated_region = next(
        region
        for region in Session().get_available_regions("cognito-idp")
        if region not in {topology.primary_region, secondary_region}
        and get_partition(region) == topology.partition
    )
    for changes in (
        {"serving_region": unrelated_region},
        {"dns_suffix": "evil.example"},
    ):
        request = {
            "dns_suffix": dns_suffix,
            "now": NOW,
            "operation": "READ",
            "serving_region": secondary_region,
        }
        request.update(changes)
        with pytest.raises(ReplicaDataPlaneError):
            resolve_regional_pool(topology, pool, **request)

    pool.pool_id = f"{topology.primary_region}_OTHER"
    with pytest.raises(ReplicaDataPlaneError):
        resolve_regional_pool(
            topology,
            pool,
            serving_region=secondary_region,
            operation="READ",
            dns_suffix=dns_suffix,
            now=NOW,
        )
