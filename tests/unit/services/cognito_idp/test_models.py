import uuid
from datetime import UTC, datetime, timedelta

from localstack.services.cognito_idp.models import (
    CognitoIdpStore,
    CognitoUser,
    PasswordHash,
    RefreshSession,
    UserPool,
)
from localstack.services.cognito_idp.tokens import generate_signing_key, sign_jwt
from localstack.services.stores import AccountRegionBundle
from localstack.state import pickle


def test_cognito_bundle_round_trip_preserves_security_state_and_live_lock():
    stores = AccountRegionBundle("cognito-idp", CognitoIdpStore, validate=False)
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    region_name = "test-region"
    store = stores[account_id][region_name]
    now = datetime.now(UTC)
    access_kid, access_pem, access_jwk = generate_signing_key()
    id_kid, id_pem, id_jwk = generate_signing_key()
    pool = UserPool(
        pool_id="test-region_pool",
        name="persistent",
        arn="arn:aws:cognito-idp:test-region:account:userpool/test-region_pool",
        created_at=now,
        updated_at=now,
        access_signing_key_id=access_kid,
        access_signing_private_key_pem=access_pem,
        access_signing_jwk=access_jwk,
        id_signing_key_id=id_kid,
        id_signing_private_key_pem=id_pem,
        id_signing_jwk=id_jwk,
    )
    pool.users["alice"] = CognitoUser(
        username="alice",
        sub=str(uuid.uuid4()),
        password=PasswordHash.from_password("PersistentPass9!"),
        status="CONFIRMED",
        enabled=True,
        created_at=now,
        updated_at=now,
    )
    store.user_pools[pool.pool_id] = pool
    store.POOL_LOCATIONS[pool.pool_id] = (account_id, region_name)
    store.refresh_sessions["token-hash"] = RefreshSession(
        token_hash="token-hash",
        pool_id=pool.pool_id,
        client_id="client-id",
        username="alice",
        auth_time=int(now.timestamp()),
        origin_jti=str(uuid.uuid4()),
        expires_at=now + timedelta(days=1),
    )

    restored = pickle.loads(pickle.dumps(stores))
    restored_store = restored[account_id][region_name]
    restored_pool = restored_store.user_pools[pool.pool_id]

    assert restored.lock.acquire(blocking=False)
    restored.lock.release()
    assert restored_store.POOL_LOCATIONS[pool.pool_id] == (account_id, region_name)
    assert restored_pool.users["alice"].password.verify("PersistentPass9!")
    assert restored_store.refresh_sessions["token-hash"].origin_jti
    assert sign_jwt(restored_pool.id_signing_private_key_pem, restored_pool.id_signing_key_id, {})
