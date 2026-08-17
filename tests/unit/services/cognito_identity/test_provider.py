import base64
import json
import threading
import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_identity.models import cognito_identity_stores
from localstack.services.cognito_identity.provider import CognitoIdentityProvider
from localstack.services.plugins import Service


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    yield value
    _remove_account(value.account_id)


@pytest.fixture
def provider():
    return CognitoIdentityProvider()


def _context(account_id: str, region: str = "us-east-1") -> RequestContext:
    value = RequestContext(None)
    value.account_id = account_id
    value.region = region
    return value


def _create_pool(provider, context, **overrides):
    request = {
        "IdentityPoolName": "mobile-app",
        "AllowUnauthenticatedIdentities": True,
        **overrides,
    }
    return provider.create_identity_pool(context, request)


def _remove_account(account_id: str) -> None:
    with cognito_identity_stores.lock:
        bundle = cognito_identity_stores.get(account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.identity_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
                for identity_id in list(store.identities):
                    store.IDENTITY_LOCATIONS.pop(identity_id, None)
            cognito_identity_stores.pop(account_id, None)


def test_service_registers_only_the_current_native_operations(provider):
    service = Service.for_provider(provider)

    assert set(service.skeleton.dispatch_table) == {
        "CreateIdentityPool",
        "DeleteIdentities",
        "DeleteIdentityPool",
        "DescribeIdentity",
        "DescribeIdentityPool",
        "GetCredentialsForIdentity",
        "GetId",
        "GetIdentityPoolRoles",
        "GetOpenIdToken",
        "GetOpenIdTokenForDeveloperIdentity",
        "GetPrincipalTagAttributeMap",
        "ListIdentities",
        "ListIdentityPools",
        "ListTagsForResource",
        "LookupDeveloperIdentity",
        "MergeDeveloperIdentities",
        "SetPrincipalTagAttributeMap",
        "SetIdentityPoolRoles",
        "TagResource",
        "UnlinkDeveloperIdentity",
        "UnlinkIdentity",
        "UntagResource",
        "UpdateIdentityPool",
    }
    assert len(service.skeleton.dispatch_table) == 23


def test_create_describe_update_and_account_region_isolation(provider, context):
    created = _create_pool(
        provider,
        context,
        AllowClassicFlow=True,
        DeveloperProviderName="login.example",
        CognitoIdentityProviders=[
            {
                "ClientId": "client_id",
                "ProviderName": "cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
                "ServerSideTokenCheck": True,
            }
        ],
        IdentityPoolTags={"environment": "test"},
    )
    pool_id = created["IdentityPoolId"]

    assert pool_id.startswith(f"{context.region}:")
    assert created["AllowClassicFlow"] is True
    assert created["IdentityPoolTags"] == {"environment": "test"}
    assert created["DeveloperProviderName"] == "login.example"
    assert provider.describe_identity_pool(context, {"IdentityPoolId": pool_id}) == created

    updated = provider.update_identity_pool(
        context,
        {
            "IdentityPoolId": pool_id,
            "IdentityPoolName": "mobile-app-v2",
            "AllowUnauthenticatedIdentities": False,
        },
    )
    assert updated["IdentityPoolName"] == "mobile-app-v2"
    assert updated["AllowUnauthenticatedIdentities"] is False
    assert updated == {
        "AllowClassicFlow": False,
        "AllowUnauthenticatedIdentities": False,
        "DeveloperProviderName": "login.example",
        "IdentityPoolId": pool_id,
        "IdentityPoolName": "mobile-app-v2",
    }
    with cognito_identity_stores.lock:
        stored = cognito_identity_stores[context.account_id][context.region].identity_pools[pool_id]
        assert stored.supported_login_providers == {}
        assert stored.open_id_connect_provider_arns == []
        assert stored.cognito_identity_providers == []
        assert stored.saml_provider_arns == []
        assert stored.tags == {}

    with pytest.raises(CommonServiceException) as immutable_developer_provider:
        provider.update_identity_pool(
            context,
            {
                "IdentityPoolId": pool_id,
                "IdentityPoolName": "mobile-app-v2",
                "AllowUnauthenticatedIdentities": False,
                "DeveloperProviderName": "login.changed",
            },
        )
    assert immutable_developer_provider.value.code == "InvalidParameterException"

    with pytest.raises(CommonServiceException) as wrong_account:
        provider.describe_identity_pool(
            _context(f"{(int(context.account_id) + 1) % 10**12:012d}"),
            {"IdentityPoolId": pool_id},
        )
    assert wrong_account.value.code == "ResourceNotFoundException"

    with pytest.raises(CommonServiceException) as wrong_region:
        provider.describe_identity_pool(
            _context(context.account_id, "us-west-2"), {"IdentityPoolId": pool_id}
        )
    assert wrong_region.value.code == "ResourceNotFoundException"


def test_external_provider_configuration_fails_closed_until_runtime_verification_exists(
    provider, context
):
    configurations = (
        {"SupportedLoginProviders": {"accounts.google.com": "application-id"}},
        {
            "OpenIdConnectProviderARNs": [
                f"arn:aws:iam::{context.account_id}:oidc-provider/accounts.example"
            ]
        },
        {"SamlProviderARNs": [f"arn:aws:iam::{context.account_id}:saml-provider/example"]},
    )
    for configuration in configurations:
        with pytest.raises(NotImplementedError, match="External identity providers"):
            _create_pool(provider, context, **configuration)

    with cognito_identity_stores.lock:
        assert not cognito_identity_stores[context.account_id][context.region].identity_pools

    created = _create_pool(provider, context)
    for configuration in configurations:
        with pytest.raises(NotImplementedError, match="External identity providers"):
            provider.update_identity_pool(
                context,
                {
                    "IdentityPoolId": created["IdentityPoolId"],
                    "IdentityPoolName": "must-not-change",
                    "AllowUnauthenticatedIdentities": False,
                    **configuration,
                },
            )
    assert (
        provider.describe_identity_pool(context, {"IdentityPoolId": created["IdentityPoolId"]})
        == created
    )


def test_list_identity_pools_uses_bounded_scope_bound_pagination(provider, context):
    ids = {
        _create_pool(provider, context, IdentityPoolName=f"pool-{index}")["IdentityPoolId"]
        for index in range(61)
    }

    first = provider.list_identity_pools(context, {"MaxResults": 60})
    second = provider.list_identity_pools(
        context, {"MaxResults": 60, "NextToken": first["NextToken"]}
    )

    listed = {pool["IdentityPoolId"] for pool in first["IdentityPools"] + second["IdentityPools"]}
    assert listed == ids
    assert len(first["IdentityPools"]) == 60
    assert len(second["IdentityPools"]) == 1
    assert "NextToken" not in second
    assert all(pool_id not in first["NextToken"] for pool_id in ids)

    with pytest.raises(CommonServiceException) as invalid:
        provider.list_identity_pools(
            _context(context.account_id, "us-west-2"),
            {"MaxResults": 60, "NextToken": first["NextToken"]},
        )
    assert invalid.value.code == "InvalidParameterException"
    tampered_token = f"{first['NextToken'][:-1]}{'A' if first['NextToken'][-1] != 'A' else 'B'}"
    with pytest.raises(CommonServiceException) as tampered:
        provider.list_identity_pools(
            context,
            {"MaxResults": 60, "NextToken": tampered_token},
        )
    assert tampered.value.code == "InvalidParameterException"
    forged_payload = json.dumps(
        {
            "after": sorted(ids)[30],
            "scope": f"pools:{context.account_id}:{context.region}",
            "version": 1,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    forged_token = base64.urlsafe_b64encode(forged_payload).rstrip(b"=").decode()
    with pytest.raises(CommonServiceException) as forged:
        provider.list_identity_pools(
            context,
            {"MaxResults": 60, "NextToken": forged_token},
        )
    assert forged.value.code == "InvalidParameterException"


def test_get_id_creates_isolated_guest_identities_and_rejects_untrusted_logins(provider, context):
    pool = _create_pool(provider, context)
    request = {"AccountId": context.account_id, "IdentityPoolId": pool["IdentityPoolId"]}

    first = provider.get_id(context, request)
    second = provider.get_id(context, request)

    assert first["IdentityId"].startswith(f"{context.region}:")
    assert second["IdentityId"].startswith(f"{context.region}:")
    assert first != second
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert set(store.identities) == {first["IdentityId"], second["IdentityId"]}
        assert store.IDENTITY_LOCATIONS[first["IdentityId"]] == (
            context.account_id,
            context.region,
            pool["IdentityPoolId"],
        )

    with pytest.raises(CommonServiceException) as invalid_login:
        provider.get_id(context, {**request, "Logins": {"accounts.example": "token"}})
    assert invalid_login.value.code == "NotAuthorizedException"


def test_get_id_enforces_guest_flag_account_and_region(provider, context):
    pool = _create_pool(provider, context, AllowUnauthenticatedIdentities=False)
    pool_id = pool["IdentityPoolId"]

    with pytest.raises(CommonServiceException) as disabled:
        provider.get_id(context, {"IdentityPoolId": pool_id})
    assert disabled.value.code == "NotAuthorizedException"

    with pytest.raises(CommonServiceException) as wrong_account:
        provider.get_id(
            context,
            {
                "AccountId": f"{(int(context.account_id) + 1) % 10**12:012d}",
                "IdentityPoolId": pool_id,
            },
        )
    assert wrong_account.value.code == "ResourceNotFoundException"

    with pytest.raises(CommonServiceException) as wrong_region:
        provider.get_id(_context(context.account_id, "us-west-2"), {"IdentityPoolId": pool_id})
    assert wrong_region.value.code == "ResourceNotFoundException"


def test_get_id_is_public_but_enforces_the_pool_owner_when_account_id_is_supplied(
    provider, context
):
    pool = _create_pool(provider, context)
    unsigned_context = _context(f"{(int(context.account_id) + 1) % 10**12:012d}")

    identity = provider.get_id(
        unsigned_context,
        {"AccountId": context.account_id, "IdentityPoolId": pool["IdentityPoolId"]},
    )

    assert identity["IdentityId"].startswith(f"{context.region}:")


def test_get_id_enforces_the_local_identity_safety_limit(provider, context, monkeypatch):
    pool = _create_pool(provider, context)
    monkeypatch.setattr("localstack.services.cognito_identity.provider._MAX_IDENTITIES_PER_POOL", 1)
    provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})

    with pytest.raises(CommonServiceException) as limited:
        provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})
    assert limited.value.code == "LimitExceededException"


def test_get_id_retries_global_identity_collision_across_pools_and_accounts_without_corruption(
    provider, context, monkeypatch
):
    other_account = f"{(int(context.account_id) + 1) % 10**12:012d}"
    other_context = _context(other_account)
    first_pool = _create_pool(provider, context)
    second_pool = _create_pool(provider, other_context)
    collision_id = f"{context.region}:{uuid.uuid4()}"
    replacement_id = f"{context.region}:{uuid.uuid4()}"
    generated = iter((collision_id, collision_id, replacement_id))
    monkeypatch.setattr(
        "localstack.services.cognito_identity.provider._new_identity_id",
        lambda _region: next(generated),
    )

    try:
        first = provider.get_id(context, {"IdentityPoolId": first_pool["IdentityPoolId"]})
        second = provider.get_id(
            other_context,
            {"AccountId": other_account, "IdentityPoolId": second_pool["IdentityPoolId"]},
        )

        assert first == {"IdentityId": collision_id}
        assert second == {"IdentityId": replacement_id}
        with cognito_identity_stores.lock:
            first_store = cognito_identity_stores[context.account_id][context.region]
            second_store = cognito_identity_stores[other_account][context.region]
            assert first_store.IDENTITY_LOCATIONS[collision_id] == (
                context.account_id,
                context.region,
                first_pool["IdentityPoolId"],
            )
            assert second_store.IDENTITY_LOCATIONS[replacement_id] == (
                other_account,
                context.region,
                second_pool["IdentityPoolId"],
            )
            assert collision_id not in second_store.identities

        provider.delete_identity_pool(
            other_context, {"IdentityPoolId": second_pool["IdentityPoolId"]}
        )
        with cognito_identity_stores.lock:
            first_store = cognito_identity_stores[context.account_id][context.region]
            assert collision_id in first_store.identities
            assert first_store.IDENTITY_LOCATIONS[collision_id] == (
                context.account_id,
                context.region,
                first_pool["IdentityPoolId"],
            )
            assert replacement_id not in first_store.IDENTITY_LOCATIONS
    finally:
        _remove_account(other_account)


def test_delete_waits_for_guest_creation_then_cleans_all_indexes(provider, context, monkeypatch):
    pool = _create_pool(provider, context)
    pool_id = pool["IdentityPoolId"]
    entered = threading.Event()
    release = threading.Event()
    deleted = threading.Event()

    def paused_identity_id(region):
        entered.set()
        assert release.wait(timeout=5)
        return f"{region}:{uuid.uuid4()}"

    monkeypatch.setattr(
        "localstack.services.cognito_identity.provider._new_identity_id", paused_identity_id
    )
    creator = threading.Thread(target=lambda: provider.get_id(context, {"IdentityPoolId": pool_id}))
    remover = threading.Thread(
        target=lambda: (
            provider.delete_identity_pool(context, {"IdentityPoolId": pool_id}),
            deleted.set(),
        )
    )
    creator.start()
    assert entered.wait(timeout=5)
    remover.start()
    assert not deleted.wait(timeout=0.1)
    release.set()
    creator.join(timeout=5)
    remover.join(timeout=5)

    assert deleted.is_set()
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert pool_id not in store.identity_pools
        assert pool_id not in store.POOL_LOCATIONS
        assert not store.identities
        assert not store.IDENTITY_LOCATIONS


@pytest.mark.parametrize(
    "payload",
    [
        {"IdentityPoolName": "", "AllowUnauthenticatedIdentities": True},
        {"IdentityPoolName": "invalid!", "AllowUnauthenticatedIdentities": True},
        {"IdentityPoolName": "valid", "AllowUnauthenticatedIdentities": "true"},
        {
            "IdentityPoolName": "valid",
            "AllowUnauthenticatedIdentities": True,
            "Unknown": "field",
        },
    ],
)
def test_create_rejects_invalid_or_unknown_input(provider, context, payload):
    with pytest.raises(CommonServiceException) as error:
        provider.create_identity_pool(context, payload)
    assert error.value.code == "InvalidParameterException"


def test_pagination_rejects_unbounded_limits_and_malformed_tokens(provider, context):
    for request in ({"MaxResults": 0}, {"MaxResults": 61}, {"MaxResults": True}):
        with pytest.raises(CommonServiceException) as error:
            provider.list_identity_pools(context, request)
        assert error.value.code == "InvalidParameterException"

    with pytest.raises(CommonServiceException) as malformed:
        provider.list_identity_pools(context, {"MaxResults": 1, "NextToken": "not-base64"})
    assert malformed.value.code == "InvalidParameterException"


def test_create_enforces_the_local_pool_safety_limit(provider, context, monkeypatch):
    monkeypatch.setattr("localstack.services.cognito_identity.provider._MAX_POOLS_PER_REGION", 1)
    _create_pool(provider, context)

    with pytest.raises(CommonServiceException) as limited:
        _create_pool(provider, context, IdentityPoolName="another-pool")
    assert limited.value.code == "LimitExceededException"
