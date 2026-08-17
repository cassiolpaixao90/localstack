import uuid

from localstack.aws.api import RequestContext
from localstack.services.cognito_identity.models import cognito_identity_stores
from localstack.services.cognito_identity.provider import CognitoIdentityProvider
from localstack.state import pickle
from localstack.state.inspect import ServiceBackendCollectorVisitor


def test_account_region_bundle_and_cross_account_indexes_survive_raw_roundtrip():
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context = RequestContext(None)
    context.account_id = account_id
    context.region = "us-east-1"
    provider = CognitoIdentityProvider()
    pool = provider.create_identity_pool(
        context,
        {
            "IdentityPoolName": "persistent-pool",
            "AllowUnauthenticatedIdentities": True,
        },
    )
    identity = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})

    restored = pickle.loads(pickle.dumps(cognito_identity_stores))
    restored_store = restored[account_id][context.region]

    assert restored_store.identity_pools[pool["IdentityPoolId"]].name == "persistent-pool"
    assert restored_store.identities[identity["IdentityId"]].pool_id == pool["IdentityPoolId"]
    assert restored_store.POOL_LOCATIONS[pool["IdentityPoolId"]] == (
        account_id,
        context.region,
    )
    assert restored_store.IDENTITY_LOCATIONS[identity["IdentityId"]] == (
        account_id,
        context.region,
        pool["IdentityPoolId"],
    )

    with cognito_identity_stores.lock:
        store = cognito_identity_stores[account_id][context.region]
        store.POOL_LOCATIONS.pop(pool["IdentityPoolId"], None)
        store.IDENTITY_LOCATIONS.pop(identity["IdentityId"], None)
        cognito_identity_stores.pop(account_id, None)


def test_provider_persistence_visits_only_the_native_store():
    visitor = ServiceBackendCollectorVisitor()

    CognitoIdentityProvider().accept_state_visitor(visitor)

    assert visitor.store is cognito_identity_stores
    assert visitor.backend_dict is None
