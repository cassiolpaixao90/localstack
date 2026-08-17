import uuid

import pytest

from localstack.aws.api import RequestContext
from localstack.services.cognito_identity.models import cognito_identity_stores
from localstack.services.cognito_identity.provider import CognitoIdentityProvider
from localstack.services.cognito_sync.models import cognito_sync_stores
from localstack.services.cognito_sync.provider import CognitoSyncProvider


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    yield value
    with cognito_identity_stores.lock:
        identity_bundle = cognito_identity_stores.get(value.account_id)
        if identity_bundle is not None:
            for store in identity_bundle.values():
                for pool_id in list(store.identity_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
                for identity_id in list(store.identities):
                    store.IDENTITY_LOCATIONS.pop(identity_id, None)
            cognito_identity_stores.pop(value.account_id, None)
    with cognito_sync_stores.lock:
        cognito_sync_stores.pop(value.account_id, None)


@pytest.fixture
def sync_provider():
    return CognitoSyncProvider()


@pytest.fixture
def identity(context):
    provider = CognitoIdentityProvider()
    pool = provider.create_identity_pool(
        context,
        {
            "AllowUnauthenticatedIdentities": True,
            "IdentityPoolName": "sync-test",
        },
    )
    created = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})
    return pool["IdentityPoolId"], created["IdentityId"]
