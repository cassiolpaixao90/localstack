import base64
import concurrent.futures
import copy
import json
import time
import uuid
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from moto.iam.models import iam_backends

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_identity.models import CredentialSession, cognito_identity_stores
from localstack.services.cognito_identity.openid import (
    OpenIdTokenError,
    identity_issuer,
    verify_open_id_token,
)
from localstack.services.cognito_identity.provider import CognitoIdentityProvider
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.tokens import public_key_from_jwk
from localstack.services.cognito_sync.models import SyncDataset, cognito_sync_stores
from localstack.services.iam.iam_patches import apply_iam_patches
from localstack.state import pickle


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    value.partition = "aws"
    apply_iam_patches()
    yield value
    _remove_account(value.account_id)
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(value.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(value.account_id, None)
    with cognito_sync_stores.lock:
        cognito_sync_stores.pop(value.account_id, None)
    iam_backends[value.account_id][value.partition].reset()


@pytest.fixture
def provider():
    return CognitoIdentityProvider()


def _remove_account(account_id):
    with cognito_identity_stores.lock:
        bundle = cognito_identity_stores.get(account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.identity_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
                for identity_id in list(store.identities):
                    store.IDENTITY_LOCATIONS.pop(identity_id, None)
            cognito_identity_stores.pop(account_id, None)


def _context(account_id, region="us-east-1"):
    value = RequestContext(None)
    value.account_id = account_id
    value.region = region
    value.partition = "aws"
    return value


def _pool(provider, context, name="developer-pool", **overrides):
    return provider.create_identity_pool(
        context,
        {
            "IdentityPoolName": name,
            "AllowUnauthenticatedIdentities": True,
            "AllowClassicFlow": True,
            "DeveloperProviderName": "login.example",
            **overrides,
        },
    )


def _decode_token(token):
    header, claims, signature = token.split(".")

    def decode(value):
        return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))

    return header, claims, signature, decode(header), decode(claims)


def _assert_signed_token(context, pool_id, response, *, duration, authenticated=True):
    encoded_header, encoded_claims, encoded_signature, header, claims = _decode_token(
        response["Token"]
    )
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        key_id = store.open_id_signing_key_id
        jwk = store.open_id_signing_jwk
    assert header == {"alg": "RS256", "kid": key_id, "typ": "JWT"}
    assert claims["aud"] == pool_id
    assert claims["sub"] == response["IdentityId"]
    assert claims["iss"] == "https://cognito-identity.amazonaws.com"
    assert claims["amr"][0] == ("authenticated" if authenticated else "unauthenticated")
    assert claims["exp"] - claims["iat"] == duration
    assert abs(claims["iat"] - int(time.time())) <= 2
    assert isinstance(claims["jti"], str) and len(claims["jti"]) >= 16
    public_key_from_jwk(jwk).verify(
        base64.urlsafe_b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4)),
        f"{encoded_header}.{encoded_claims}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return claims


def _developer_token(provider, context, pool_id, identifier, **overrides):
    return provider.get_open_id_token_for_developer_identity(
        context,
        {
            "IdentityPoolId": pool_id,
            "Logins": {"login.example": identifier},
            **overrides,
        },
    )


def _authenticated_role(context, pool_id):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringEquals": {
                        "cognito-identity.amazonaws.com:amr": "authenticated"
                    },
                },
            }
        ],
    }
    return (
        iam_backends[context.account_id][context.partition]
        .create_role(
            role_name=f"developer-{uuid.uuid4().hex[:8]}",
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
    pool = idp.create_user_pool(context, {"PoolName": "classic-users"})["UserPool"]
    client = idp.create_user_pool_client(
        context,
        {
            "UserPoolId": pool["Id"],
            "ClientName": "classic-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        },
    )["UserPoolClient"]
    idp.admin_create_user(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "classic@example.test",
            "TemporaryPassword": "TempPass9!",
        },
    )
    idp.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "classic@example.test",
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
                "USERNAME": "classic@example.test",
                "PASSWORD": "PermanentPass9!",
            },
        },
    )["AuthenticationResult"]["IdToken"]
    provider_name = f"cognito-idp.{context.region}.amazonaws.com/{pool['Id']}"
    return provider_name, token, {"ClientId": client["ClientId"], "ProviderName": provider_name}


def test_developer_token_creates_reuses_and_persists_identity_and_signing_key(provider, context):
    pool = _pool(provider, context)
    first = _developer_token(provider, context, pool["IdentityPoolId"], "customer-1")
    second = _developer_token(
        provider,
        context,
        pool["IdentityPoolId"],
        "customer-1",
        TokenDuration=60,
        PrincipalTags={"tenant": "blue"},
    )

    assert first["IdentityId"] == second["IdentityId"]
    assert first["Token"] != second["Token"]
    first_claims = _assert_signed_token(context, pool["IdentityPoolId"], first, duration=900)
    second_claims = _assert_signed_token(context, pool["IdentityPoolId"], second, duration=60)
    assert first_claims["amr"] == ["authenticated", "login.example"]
    assert "principal_tags" not in first_claims
    assert second_claims["principal_tags"] == {"tenant": "blue"}
    assert provider.describe_identity(context, {"IdentityId": first["IdentityId"]})["Logins"] == [
        "login.example"
    ]

    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert (
            store.developer_identities[(pool["IdentityPoolId"], "login.example", "customer-1")]
            == first["IdentityId"]
        )
        restored = pickle.loads(pickle.dumps(cognito_identity_stores))
    restored_store = restored[context.account_id][context.region]
    assert restored_store.open_id_signing_key_id == store.open_id_signing_key_id
    assert restored_store.open_id_signing_private_key == store.open_id_signing_private_key
    assert restored_store.open_id_signing_jwk == store.open_id_signing_jwk
    assert restored_store.identities[first["IdentityId"]].developer_user_identifiers == {
        "customer-1"
    }


def test_developer_token_validates_shape_provider_identity_and_scope_atomically(provider, context):
    pool = _pool(provider, context)
    other = _developer_token(provider, context, pool["IdentityPoolId"], "other")
    target = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})

    invalid_requests = [
        {"IdentityPoolId": pool["IdentityPoolId"], "Logins": {}},
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "Logins": {"login.changed": "customer"},
        },
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "Logins": {"login.example": "customer"},
            "TokenDuration": 0,
        },
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "IdentityId": target["IdentityId"],
            "Logins": {"login.example": "other"},
        },
    ]
    for request in invalid_requests:
        with pytest.raises(CommonServiceException):
            provider.get_open_id_token_for_developer_identity(context, request)

    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert (
            store.developer_identities[(pool["IdentityPoolId"], "login.example", "other")]
            == other["IdentityId"]
        )
        assert store.identities[target["IdentityId"]].developer_user_identifiers == set()

    wrong_account = _context(f"{(int(context.account_id) + 1) % 10**12:012d}")
    with pytest.raises(CommonServiceException) as isolated:
        _developer_token(provider, wrong_account, pool["IdentityPoolId"], "customer")
    assert isolated.value.code == "ResourceNotFoundException"


def test_developer_token_is_accepted_by_enhanced_credentials_and_tampering_fails(provider, context):
    pool = _pool(provider, context)
    token = _developer_token(provider, context, pool["IdentityPoolId"], "customer")
    role = _authenticated_role(context, pool["IdentityPoolId"])
    provider.set_identity_pool_roles(
        context,
        {"IdentityPoolId": pool["IdentityPoolId"], "Roles": {"authenticated": role}},
    )

    credentials = provider.get_credentials_for_identity(
        context,
        {
            "IdentityId": token["IdentityId"],
            "Logins": {"cognito-identity.amazonaws.com": token["Token"]},
        },
    )
    assert credentials["IdentityId"] == token["IdentityId"]
    assert credentials["Credentials"]["AccessKeyId"]
    tampered_token = f"{token['Token'][:-1]}{'A' if token['Token'][-1] != 'A' else 'B'}"
    with pytest.raises(CommonServiceException) as tampered:
        provider.get_credentials_for_identity(
            context,
            {
                "IdentityId": token["IdentityId"],
                "Logins": {"cognito-identity.amazonaws.com": tampered_token},
            },
        )
    assert tampered.value.code == "NotAuthorizedException"


def test_open_id_token_verifier_enforces_expiry_audience_subject_and_canonical_signature(
    provider, context
):
    pool = _pool(provider, context)
    response = _developer_token(
        provider,
        context,
        pool["IdentityPoolId"],
        "customer",
        TokenDuration=30,
    )
    _, _, _, _, claims = _decode_token(response["Token"])
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        verified = verify_open_id_token(
            store,
            token=response["Token"],
            partition=context.partition,
            region=context.region,
            pool_id=pool["IdentityPoolId"],
            identity_id=response["IdentityId"],
            authenticated=True,
            now=claims["exp"] - 1,
        )
        assert verified == claims
        with pytest.raises(OpenIdTokenError):
            verify_open_id_token(
                store,
                token=response["Token"],
                partition=context.partition,
                region=context.region,
                pool_id=pool["IdentityPoolId"],
                identity_id=response["IdentityId"],
                authenticated=True,
                now=claims["exp"],
            )
        with pytest.raises(OpenIdTokenError):
            verify_open_id_token(
                store,
                token=response["Token"],
                partition=context.partition,
                region=context.region,
                pool_id=f"{context.region}:{uuid.uuid4()}",
                identity_id=response["IdentityId"],
                authenticated=True,
                now=claims["iat"],
            )
    assert identity_issuer("aws-cn", "cn-north-1") == (
        "https://cognito-identity.cn-north-1.amazonaws.com.cn"
    )
    assert identity_issuer("aws", "af-south-1") == (
        "https://cognito-identity.af-south-1.amazonaws.com"
    )


def test_lookup_developer_identity_supports_both_directions_and_opaque_pagination(
    provider, context
):
    pool = _pool(provider, context)
    identity_id = _developer_token(provider, context, pool["IdentityPoolId"], "customer-0")[
        "IdentityId"
    ]
    for index in range(1, 4):
        _developer_token(
            provider,
            context,
            pool["IdentityPoolId"],
            f"customer-{index}",
            IdentityId=identity_id,
        )

    by_identifier = provider.lookup_developer_identity(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "DeveloperUserIdentifier": "customer-0",
        },
    )
    assert by_identifier == {
        "IdentityId": identity_id,
        "DeveloperUserIdentifierList": ["customer-0"],
    }
    first = provider.lookup_developer_identity(
        context,
        {"IdentityPoolId": pool["IdentityPoolId"], "IdentityId": identity_id, "MaxResults": 2},
    )
    second = provider.lookup_developer_identity(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "IdentityId": identity_id,
            "MaxResults": 2,
            "NextToken": first["NextToken"],
        },
    )
    assert first["DeveloperUserIdentifierList"] + second["DeveloperUserIdentifierList"] == [
        "customer-0",
        "customer-1",
        "customer-2",
        "customer-3",
    ]
    assert all(value not in first["NextToken"] for value in (identity_id, "customer-1"))

    with pytest.raises(CommonServiceException) as conflict:
        provider.lookup_developer_identity(
            context,
            {
                "IdentityPoolId": pool["IdentityPoolId"],
                "IdentityId": identity_id,
                "DeveloperUserIdentifier": "missing",
            },
        )
    assert conflict.value.code == "ResourceConflictException"
    tampered = f"{first['NextToken'][:-1]}{'A' if first['NextToken'][-1] != 'A' else 'B'}"
    with pytest.raises(CommonServiceException) as invalid_token:
        provider.lookup_developer_identity(
            context,
            {
                "IdentityPoolId": pool["IdentityPoolId"],
                "IdentityId": identity_id,
                "MaxResults": 2,
                "NextToken": tampered,
            },
        )
    assert invalid_token.value.code == "InvalidParameterException"


def test_merge_and_unlink_developer_identities_are_atomic_and_recreate_unlinked_user(
    provider, context
):
    pool = _pool(provider, context)
    source = _developer_token(provider, context, pool["IdentityPoolId"], "source")
    destination = _developer_token(provider, context, pool["IdentityPoolId"], "destination")
    role = _authenticated_role(context, pool["IdentityPoolId"])
    provider.set_identity_pool_roles(
        context,
        {"IdentityPoolId": pool["IdentityPoolId"], "Roles": {"authenticated": role}},
    )
    access_key = provider.get_credentials_for_identity(
        context,
        {
            "IdentityId": source["IdentityId"],
            "Logins": {"cognito-identity.amazonaws.com": source["Token"]},
        },
    )["Credentials"]["AccessKeyId"]
    now = datetime.now(UTC)
    with cognito_sync_stores.lock:
        cognito_sync_stores[context.account_id][context.region].datasets[
            (pool["IdentityPoolId"], source["IdentityId"], "profile")
        ] = SyncDataset(
            pool_id=pool["IdentityPoolId"],
            identity_id=source["IdentityId"],
            name="profile",
            creation_date=now,
            last_modified_date=now,
            last_modified_by=source["IdentityId"],
        )

    merged = provider.merge_developer_identities(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "DeveloperProviderName": "login.example",
            "SourceUserIdentifier": "source",
            "DestinationUserIdentifier": "destination",
        },
    )
    assert merged == {"IdentityId": destination["IdentityId"]}
    assert (
        _developer_token(provider, context, pool["IdentityPoolId"], "source")["IdentityId"]
        == destination["IdentityId"]
    )
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert store.identities[source["IdentityId"]].enabled is False
        assert store.identities[source["IdentityId"]].developer_user_identifiers == set()
        assert store.identities[destination["IdentityId"]].developer_user_identifiers == {
            "source",
            "destination",
        }
        assert access_key not in store.credential_sessions
    assert access_key not in iam_backends[context.account_id][context.partition].access_keys
    with cognito_sync_stores.lock:
        assert not cognito_sync_stores[context.account_id][context.region].datasets

    assert (
        provider.unlink_developer_identity(
            context,
            {
                "IdentityPoolId": pool["IdentityPoolId"],
                "IdentityId": destination["IdentityId"],
                "DeveloperProviderName": "login.example",
                "DeveloperUserIdentifier": "source",
            },
        )
        == {}
    )
    replacement = _developer_token(provider, context, pool["IdentityPoolId"], "source")
    assert replacement["IdentityId"] not in {
        source["IdentityId"],
        destination["IdentityId"],
    }
    provider.delete_identities(
        context,
        {"IdentityIdsToDelete": [destination["IdentityId"], replacement["IdentityId"]]},
    )
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert not store.developer_identities


def test_developer_links_are_bounded_without_partial_mutation(provider, context):
    pool = _pool(provider, context)
    identity_id = _developer_token(provider, context, pool["IdentityPoolId"], "customer-0")[
        "IdentityId"
    ]
    for index in range(1, 20):
        assert (
            _developer_token(
                provider,
                context,
                pool["IdentityPoolId"],
                f"customer-{index}",
                IdentityId=identity_id,
            )["IdentityId"]
            == identity_id
        )
    with pytest.raises(CommonServiceException) as bounded:
        _developer_token(
            provider,
            context,
            pool["IdentityPoolId"],
            "customer-20",
            IdentityId=identity_id,
        )
    assert bounded.value.code == "LimitExceededException"
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert len(store.identities[identity_id].developer_user_identifiers) == 20
        assert (pool["IdentityPoolId"], "login.example", "customer-20") not in (
            store.developer_identities
        )


def test_concurrent_developer_registration_is_idempotent(provider, context):
    pool = _pool(provider, context)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda _: _developer_token(
                    provider, context, pool["IdentityPoolId"], "same-customer"
                ),
                range(16),
            )
        )
    assert len({result["IdentityId"] for result in results}) == 1


def test_get_open_id_token_enforces_classic_flow_and_identity_state(provider, context):
    classic = _pool(provider, context)
    guest = provider.get_id(context, {"IdentityPoolId": classic["IdentityPoolId"]})
    response = provider.get_open_id_token(context, guest)
    assert response["IdentityId"] == guest["IdentityId"]
    _assert_signed_token(
        context, classic["IdentityPoolId"], response, duration=600, authenticated=False
    )
    provider.update_identity_pool(
        context,
        {
            "IdentityPoolId": classic["IdentityPoolId"],
            "IdentityPoolName": classic["IdentityPoolName"],
            "AllowUnauthenticatedIdentities": False,
            "AllowClassicFlow": True,
        },
    )
    with pytest.raises(CommonServiceException) as guest_disabled:
        provider.get_open_id_token(context, guest)
    assert guest_disabled.value.code == "NotAuthorizedException"

    disabled_pool = _pool(provider, context, name="no-classic", AllowClassicFlow=False)
    disabled_guest = provider.get_id(context, {"IdentityPoolId": disabled_pool["IdentityPoolId"]})
    with pytest.raises(CommonServiceException) as disabled:
        provider.get_open_id_token(context, disabled_guest)
    assert disabled.value.code == "NotAuthorizedException"

    developer = _developer_token(provider, context, classic["IdentityPoolId"], "developer")
    with pytest.raises(CommonServiceException) as missing_login:
        provider.get_open_id_token(context, {"IdentityId": developer["IdentityId"]})
    assert missing_login.value.code == "NotAuthorizedException"


def test_get_open_id_token_validates_native_login_and_implicitly_merges_identity(provider, context):
    provider_name, id_token, configuration = _native_login(context)
    pool = _pool(provider, context, CognitoIdentityProviders=[configuration])
    guest_id = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})["IdentityId"]
    authenticated_id = provider.get_id(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "Logins": {provider_name: id_token},
        },
    )["IdentityId"]

    response = provider.get_open_id_token(
        context,
        {"IdentityId": guest_id, "Logins": {provider_name: id_token}},
    )
    assert response["IdentityId"] == guest_id
    claims = _assert_signed_token(
        context,
        pool["IdentityPoolId"],
        response,
        duration=600,
        authenticated=True,
    )
    assert claims["amr"] == ["authenticated", provider_name]
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert store.identities[guest_id].logins
        assert store.identities[authenticated_id].enabled is False
        assert (
            store.login_identities[
                (
                    pool["IdentityPoolId"],
                    provider_name,
                    next(iter(store.identities[guest_id].logins.values())),
                )
            ]
            == guest_id
        )

    with pytest.raises(CommonServiceException) as invalid:
        provider.get_open_id_token(
            context,
            {"IdentityId": guest_id, "Logins": {provider_name: f"{id_token}x"}},
        )
    assert invalid.value.code == "NotAuthorizedException"


def test_developer_identity_can_use_and_unlink_native_login_without_losing_authentication(
    provider, context
):
    provider_name, id_token, configuration = _native_login(context)
    pool = _pool(
        provider,
        context,
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[configuration],
    )
    developer = provider.get_open_id_token_for_developer_identity(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "Logins": {"login.example": "developer", provider_name: id_token},
        },
    )
    classic = provider.get_open_id_token(
        context,
        {"IdentityId": developer["IdentityId"], "Logins": {provider_name: id_token}},
    )
    claims = _assert_signed_token(
        context,
        pool["IdentityPoolId"],
        classic,
        duration=600,
        authenticated=True,
    )
    assert claims["amr"] == ["authenticated", provider_name, "login.example"]

    provider.unlink_identity(
        context,
        {
            "IdentityId": developer["IdentityId"],
            "Logins": {provider_name: id_token},
            "LoginsToRemove": [provider_name],
        },
    )
    with cognito_identity_stores.lock:
        identity = cognito_identity_stores[context.account_id][context.region].identities[
            developer["IdentityId"]
        ]
        assert identity.enabled is True
        assert identity.authenticated is True
        assert identity.logins == {}
        assert identity.developer_user_identifiers == {"developer"}


def test_developer_native_link_capacity_failure_is_atomic(provider, context):
    provider_name, id_token, configuration = _native_login(context)
    pool = _pool(
        provider,
        context,
        CognitoIdentityProviders=[configuration],
    )
    identity_id = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})["IdentityId"]
    now = datetime.now(UTC)
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        identity = store.identities[identity_id]
        for index in range(19):
            login_provider = f"synthetic-{index}"
            subject = f"subject-{index}"
            identity.logins[login_provider] = subject
            store.login_identities[(pool["IdentityPoolId"], login_provider, subject)] = identity_id
        store.credential_sessions["local-session"] = CredentialSession(
            access_key_id="local-session",
            identity_id=identity_id,
            pool_id=pool["IdentityPoolId"],
            role_arn=f"arn:aws:iam::{context.account_id}:role/test",
            assumed_role_arn=f"arn:aws:sts::{context.account_id}:assumed-role/test/session",
            account_id=context.account_id,
            partition=context.partition,
            issued_at=now,
            expires_at=now,
            authenticated=False,
        )
        original_logins = copy.deepcopy(identity.logins)
        original_index = copy.deepcopy(store.login_identities)

    with pytest.raises(CommonServiceException) as limited:
        provider.get_open_id_token_for_developer_identity(
            context,
            {
                "IdentityId": identity_id,
                "IdentityPoolId": pool["IdentityPoolId"],
                "Logins": {"login.example": "developer", provider_name: id_token},
            },
        )
    assert limited.value.code == "LimitExceededException"

    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        identity = store.identities[identity_id]
        assert identity.logins == original_logins
        assert not identity.developer_user_identifiers
        assert store.login_identities == original_index
        assert store.developer_identities == {}
        assert "local-session" in store.credential_sessions
