import concurrent.futures
import hashlib
import json
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from moto.iam.models import iam_backends

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_identity.models import cognito_identity_stores
from localstack.services.cognito_identity.provider import CognitoIdentityProvider
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_sync.models import (
    DatasetTombstone,
    SyncDataset,
    SyncSession,
    cognito_sync_stores,
)
from localstack.services.iam.iam_patches import apply_iam_patches
from localstack.services.sts.credentials import resolve_session
from localstack.state import pickle


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    value.partition = "aws"
    apply_iam_patches()
    yield value
    _remove_account(value)


@pytest.fixture
def provider():
    return CognitoIdentityProvider()


def _remove_account(context):
    with cognito_identity_stores.lock:
        bundle = cognito_identity_stores.get(context.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.identity_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
                for identity_id in list(store.identities):
                    store.IDENTITY_LOCATIONS.pop(identity_id, None)
            cognito_identity_stores.pop(context.account_id, None)
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(context.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(context.account_id, None)
    with cognito_sync_stores.lock:
        cognito_sync_stores.pop(context.account_id, None)
    iam_backends[context.account_id][context.partition].reset()


def _pool(provider, context, name="identity-lifecycle", **overrides):
    return provider.create_identity_pool(
        context,
        {
            "IdentityPoolName": name,
            "AllowUnauthenticatedIdentities": True,
            **overrides,
        },
    )


def _pool_arn(context, pool_id):
    return (
        f"arn:{context.partition}:cognito-identity:{context.region}:"
        f"{context.account_id}:identitypool/{pool_id}"
    )


def _role(context, pool_id, amr="unauthenticated"):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
                },
            }
        ],
    }
    return (
        iam_backends[context.account_id][context.partition]
        .create_role(
            role_name=f"{amr}-{uuid.uuid4().hex[:8]}",
            assume_role_policy_document=json.dumps(policy),
            path="/",
            permissions_boundary=None,
            description="",
            tags=[],
            max_session_duration="3600",
        )
        .arn
    )


def _native_login(context):
    idp = CognitoIdpProvider()
    pool = idp.create_user_pool(context, {"PoolName": "unlink-users"})["UserPool"]
    client = idp.create_user_pool_client(
        context,
        {
            "UserPoolId": pool["Id"],
            "ClientName": "unlink-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        },
    )["UserPoolClient"]
    idp.admin_create_user(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "unlink@example.test",
            "TemporaryPassword": "TempPass9!",
        },
    )
    idp.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "unlink@example.test",
            "Password": "PermanentPass9!",
            "Permanent": True,
        },
    )
    token = idp.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {
                "USERNAME": "unlink@example.test",
                "PASSWORD": "PermanentPass9!",
            },
        },
    )["AuthenticationResult"]["IdToken"]
    name = f"cognito-idp.{context.region}.amazonaws.com/{pool['Id']}"
    return name, token, {"ClientId": client["ClientId"], "ProviderName": name}


def _sync_scope(pool_id, identity_id):
    encoded = json.dumps((pool_id, identity_id), separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def test_describe_and_list_identities_use_scope_bound_opaque_pagination(provider, context):
    pool = _pool(provider, context)
    identities = [
        provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})["IdentityId"]
        for _ in range(3)
    ]
    with cognito_identity_stores.lock:
        cognito_identity_stores[context.account_id][context.region].identities[
            identities[1]
        ].enabled = False

    description = provider.describe_identity(context, {"IdentityId": identities[0]})
    assert description["IdentityId"] == identities[0]
    assert description["Logins"] == []
    assert description["CreationDate"] <= description["LastModifiedDate"]

    first = provider.list_identities(
        context, {"IdentityPoolId": pool["IdentityPoolId"], "MaxResults": 2}
    )
    second = provider.list_identities(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "MaxResults": 2,
            "NextToken": first["NextToken"],
        },
    )
    assert {item["IdentityId"] for item in first["Identities"] + second["Identities"]} == set(
        identities
    )
    assert all(identity_id not in first["NextToken"] for identity_id in identities)
    with cognito_identity_stores.lock:
        live_secret = cognito_identity_stores[context.account_id][context.region].pagination_secret
        restored = pickle.loads(pickle.dumps(cognito_identity_stores))
    assert live_secret
    assert restored[context.account_id][context.region].pagination_secret == live_secret

    hidden = provider.list_identities(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "MaxResults": 60,
            "HideDisabled": True,
        },
    )
    assert {item["IdentityId"] for item in hidden["Identities"]} == {
        identities[0],
        identities[2],
    }
    other_pool = _pool(provider, context, name="other")
    with pytest.raises(CommonServiceException) as wrong_scope:
        provider.list_identities(
            context,
            {
                "IdentityPoolId": other_pool["IdentityPoolId"],
                "MaxResults": 1,
                "NextToken": first["NextToken"],
            },
        )
    assert wrong_scope.value.code == "InvalidParameterException"
    tampered_token = f"{first['NextToken'][:-1]}{'A' if first['NextToken'][-1] != 'A' else 'B'}"
    with pytest.raises(CommonServiceException) as tampered:
        provider.list_identities(
            context,
            {
                "IdentityPoolId": pool["IdentityPoolId"],
                "MaxResults": 1,
                "NextToken": tampered_token,
            },
        )
    assert tampered.value.code == "InvalidParameterException"


def test_delete_identities_is_atomic_and_cleans_credentials_and_sync(provider, context):
    first_pool = _pool(provider, context, name="first")
    second_pool = _pool(provider, context, name="second")
    first_id = provider.get_id(context, {"IdentityPoolId": first_pool["IdentityPoolId"]})[
        "IdentityId"
    ]
    second_id = provider.get_id(context, {"IdentityPoolId": second_pool["IdentityPoolId"]})[
        "IdentityId"
    ]
    role = _role(context, first_pool["IdentityPoolId"])
    provider.set_identity_pool_roles(
        context,
        {
            "IdentityPoolId": first_pool["IdentityPoolId"],
            "Roles": {"unauthenticated": role},
        },
    )
    credential = provider.get_credentials_for_identity(context, {"IdentityId": first_id})
    access_key = credential["Credentials"]["AccessKeyId"]
    now = datetime.now(UTC)
    with cognito_sync_stores.lock:
        sync = cognito_sync_stores[context.account_id][context.region]
        key = (first_pool["IdentityPoolId"], first_id, "profile")
        sync.datasets[key] = SyncDataset(
            pool_id=first_pool["IdentityPoolId"],
            identity_id=first_id,
            name="profile",
            creation_date=now,
            last_modified_date=now,
            last_modified_by=first_id,
        )
        sync.dataset_tombstones[key] = DatasetTombstone(sync_count=1, deleted_at=now)
        sync.sessions["session"] = SyncSession(
            pool_id=first_pool["IdentityPoolId"],
            identity_id=first_id,
            scope_hash=_sync_scope(first_pool["IdentityPoolId"], first_id),
            binding_hash="binding",
            dataset_sync_count=0,
            last_sync_count=0,
            expires_at=now + timedelta(minutes=5),
            records=[],
            snapshot_bytes=0,
            snapshot_records=0,
            dataset_exists=True,
            dataset_deleted_after_requested_sync_count=False,
            last_modified_by=first_id,
        )

    arbitrary = f"{context.region}:{uuid.uuid4()}"
    with pytest.raises(CommonServiceException) as atomic:
        provider.delete_identities(
            context, {"IdentityIdsToDelete": [first_id, arbitrary, second_id]}
        )
    assert atomic.value.code == "ResourceNotFoundException"
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert first_id in store.identities and second_id in store.identities
        assert access_key in store.credential_sessions
    with cognito_sync_stores.lock:
        assert cognito_sync_stores[context.account_id][context.region].datasets

    assert provider.delete_identities(context, {"IdentityIdsToDelete": [first_id, second_id]}) == {
        "UnprocessedIdentityIds": []
    }
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert first_id not in store.identities and second_id not in store.identities
        assert access_key not in store.credential_sessions
        assert first_id not in store.IDENTITY_LOCATIONS
        assert second_id not in store.IDENTITY_LOCATIONS
    assert access_key not in iam_backends[context.account_id][context.partition].access_keys
    with cognito_sync_stores.lock:
        sync = cognito_sync_stores[context.account_id][context.region]
        assert not sync.datasets and not sync.dataset_tombstones and not sync.sessions

    for invalid_batch in ([], [second_id, second_id], [arbitrary] * 61):
        with pytest.raises(CommonServiceException) as invalid:
            provider.delete_identities(context, {"IdentityIdsToDelete": invalid_batch})
        assert invalid.value.code == "InvalidParameterException"


def test_delete_identities_rejects_cross_account_batch_without_mutation(provider, context):
    local_pool = _pool(provider, context)
    local_id = provider.get_id(context, {"IdentityPoolId": local_pool["IdentityPoolId"]})[
        "IdentityId"
    ]
    other = RequestContext(None)
    other.account_id = f"{(int(context.account_id) + 1) % 10**12:012d}"
    other.region = context.region
    other.partition = context.partition
    try:
        foreign_pool = _pool(provider, other)
        foreign_id = provider.get_id(other, {"IdentityPoolId": foreign_pool["IdentityPoolId"]})[
            "IdentityId"
        ]

        with pytest.raises(CommonServiceException) as error:
            provider.delete_identities(context, {"IdentityIdsToDelete": [local_id, foreign_id]})
        assert error.value.code == "ResourceNotFoundException"
        with cognito_identity_stores.lock:
            assert (
                local_id in cognito_identity_stores[context.account_id][context.region].identities
            )
            assert foreign_id in cognito_identity_stores[other.account_id][other.region].identities
    finally:
        _remove_account(other)


def test_unlink_requires_validated_link_and_downgrades_atomically(provider, context):
    provider_name, token, configuration = _native_login(context)
    pool = _pool(provider, context, CognitoIdentityProviders=[configuration])
    identity = provider.get_id(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "Logins": {provider_name: token},
        },
    )
    role = _role(context, pool["IdentityPoolId"], "authenticated")
    provider.set_identity_pool_roles(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "Roles": {"authenticated": role},
        },
    )
    credential = provider.get_credentials_for_identity(
        context,
        {"IdentityId": identity["IdentityId"], "Logins": {provider_name: token}},
    )
    access_key = credential["Credentials"]["AccessKeyId"]

    with pytest.raises(CommonServiceException) as invalid:
        provider.unlink_identity(
            context,
            {
                "IdentityId": identity["IdentityId"],
                "Logins": {provider_name: "invalid"},
                "LoginsToRemove": [provider_name],
            },
        )
    assert invalid.value.code == "NotAuthorizedException"

    assert (
        provider.unlink_identity(
            context,
            {
                "IdentityId": identity["IdentityId"],
                "Logins": {provider_name: token},
                "LoginsToRemove": [provider_name],
            },
        )
        == {}
    )
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        model = store.identities[identity["IdentityId"]]
        assert model.authenticated is False
        assert model.logins == {}
        assert store.login_identities == {}
        assert access_key not in store.credential_sessions
    assert access_key not in iam_backends[context.account_id][context.partition].access_keys


def test_unlink_last_login_is_atomic_when_guest_access_is_disabled(provider, context):
    provider_name, token, configuration = _native_login(context)
    pool = _pool(
        provider,
        context,
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[configuration],
    )
    identity_id = provider.get_id(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "Logins": {provider_name: token},
        },
    )["IdentityId"]
    role = _role(context, pool["IdentityPoolId"], "authenticated")
    provider.set_identity_pool_roles(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "Roles": {"authenticated": role},
        },
    )
    access_key = provider.get_credentials_for_identity(
        context,
        {"IdentityId": identity_id, "Logins": {provider_name: token}},
    )["Credentials"]["AccessKeyId"]

    with pytest.raises(CommonServiceException) as error:
        provider.unlink_identity(
            context,
            {
                "IdentityId": identity_id,
                "Logins": {provider_name: token},
                "LoginsToRemove": [provider_name],
            },
        )
    assert error.value.code == "NotAuthorizedException"
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        model = store.identities[identity_id]
        assert model.authenticated is True
        assert model.logins == {provider_name: model.logins[provider_name]}
        assert (
            store.login_identities[
                (pool["IdentityPoolId"], provider_name, model.logins[provider_name])
            ]
            == identity_id
        )
        assert access_key in store.credential_sessions
    assert resolve_session(access_key, account_id=context.account_id) is not None


def test_pool_tags_are_bounded_isolated_and_persistent(provider, context):
    pool = _pool(provider, context)
    arn = _pool_arn(context, pool["IdentityPoolId"])

    assert provider.tag_resource(context, {"ResourceArn": arn, "Tags": {"a": "1"}}) == {}
    assert provider.tag_resource(context, {"ResourceArn": arn, "Tags": {"b": "2"}}) == {}
    assert provider.list_tags_for_resource(context, {"ResourceArn": arn}) == {
        "Tags": {"a": "1", "b": "2"}
    }
    assert provider.untag_resource(context, {"ResourceArn": arn, "TagKeys": ["a"]}) == {}
    assert provider.list_tags_for_resource(context, {"ResourceArn": arn}) == {"Tags": {"b": "2"}}

    with pytest.raises(CommonServiceException) as bounded:
        provider.tag_resource(
            context,
            {"ResourceArn": arn, "Tags": {f"key-{index}": "v" for index in range(50)}},
        )
    assert bounded.value.code == "LimitExceededException"
    wrong_arn = arn.replace(context.account_id, f"{(int(context.account_id) + 1) % 10**12:012d}")
    with pytest.raises(CommonServiceException) as isolated:
        provider.list_tags_for_resource(context, {"ResourceArn": wrong_arn})
    assert isolated.value.code == "ResourceNotFoundException"

    with cognito_identity_stores.lock:
        restored = pickle.loads(pickle.dumps(cognito_identity_stores))
    assert restored[context.account_id][context.region].identity_pools[
        pool["IdentityPoolId"]
    ].tags == {"b": "2"}


def test_principal_tag_attribute_map_enforces_native_provider_and_default_semantics(
    provider, context
):
    provider_name, _, configuration = _native_login(context)
    pool = _pool(provider, context, CognitoIdentityProviders=[configuration])
    request = {
        "IdentityPoolId": pool["IdentityPoolId"],
        "IdentityProviderName": provider_name,
    }

    assert provider.get_principal_tag_attribute_map(context, request) == {
        **request,
        "UseDefaults": True,
        "PrincipalTags": {},
    }
    custom = {
        **request,
        "UseDefaults": False,
        "PrincipalTags": {"department": "custom:department"},
    }
    assert provider.set_principal_tag_attribute_map(context, custom) == custom
    assert provider.get_principal_tag_attribute_map(context, request) == custom

    invalid = [
        {**request, "UseDefaults": True, "PrincipalTags": {"a": "b"}},
        {**request, "UseDefaults": False, "PrincipalTags": {}},
        {**request, "IdentityProviderName": "accounts.example"},
        {
            **request,
            "UseDefaults": False,
            "PrincipalTags": {f"tag-{index}": "claim" for index in range(51)},
        },
    ]
    for payload in invalid:
        with pytest.raises(CommonServiceException) as error:
            provider.set_principal_tag_attribute_map(context, payload)
        assert error.value.code == "InvalidParameterException"

    with cognito_identity_stores.lock:
        restored = pickle.loads(pickle.dumps(cognito_identity_stores))
    stored = (
        restored[context.account_id][context.region]
        .identity_pools[pool["IdentityPoolId"]]
        .principal_tag_attribute_maps[provider_name]
    )
    assert stored.use_defaults is False
    assert stored.principal_tags == {"department": "custom:department"}


def test_delete_identity_waits_for_get_credentials_and_revokes_result(
    provider, context, monkeypatch
):
    pool = _pool(provider, context)
    identity = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})
    role = _role(context, pool["IdentityPoolId"])
    provider.set_identity_pool_roles(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "Roles": {"unauthenticated": role},
        },
    )
    from localstack.services.cognito_identity import provider as provider_module

    original_issue = provider_module.issue_enhanced_flow_credentials
    entered = threading.Event()
    release = threading.Event()
    deleted = threading.Event()

    def paused_issue(**kwargs):
        issued = original_issue(**kwargs)
        entered.set()
        assert release.wait(timeout=5)
        return issued

    monkeypatch.setattr(provider_module, "issue_enhanced_flow_credentials", paused_issue)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        credential_future = executor.submit(
            provider.get_credentials_for_identity, context, identity
        )
        assert entered.wait(timeout=5)

        def delete_identity():
            result = provider.delete_identities(
                context, {"IdentityIdsToDelete": [identity["IdentityId"]]}
            )
            deleted.set()
            return result

        delete_future = executor.submit(delete_identity)
        assert not deleted.wait(timeout=0.1)
        release.set()
        credential = credential_future.result(timeout=5)
        assert delete_future.result(timeout=5) == {"UnprocessedIdentityIds": []}

    access_key = credential["Credentials"]["AccessKeyId"]
    assert deleted.is_set()
    assert access_key not in iam_backends[context.account_id][context.partition].access_keys
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert identity["IdentityId"] not in store.identities
        assert not store.credential_sessions
