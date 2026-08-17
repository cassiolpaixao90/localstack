import base64
import concurrent.futures
import json
import threading
import time
import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_identity.models import cognito_identity_stores
from localstack.services.cognito_identity.provider import CognitoIdentityProvider
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.tokens import sign_jwt
from localstack.state import pickle


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    value.partition = "aws"
    yield value
    _remove_account(value.account_id)


@pytest.fixture
def provider():
    return CognitoIdentityProvider()


def _context(account_id: str, region: str = "us-east-1", partition: str = "aws"):
    value = RequestContext(None)
    value.account_id = account_id
    value.region = region
    value.partition = partition
    return value


def _native_user(context, username="person@example.test"):
    provider = CognitoIdpProvider()
    pool = provider.create_user_pool(context, {"PoolName": f"pool-{uuid.uuid4().hex}"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "UserPoolId": pool["Id"],
            "ClientName": "amplify-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": username,
            "TemporaryPassword": "TempPass9!",
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": username,
            "Password": "PermanentPass9!",
            "Permanent": True,
        },
    )
    authentication = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {"USERNAME": username, "PASSWORD": "PermanentPass9!"},
        },
    )["AuthenticationResult"]
    dns_suffix = "amazonaws.com.cn" if context.partition == "aws-cn" else "amazonaws.com"
    provider_name = f"cognito-idp.{context.region}.{dns_suffix}/{pool['Id']}"
    return provider, pool, client, provider_name, authentication


def _identity_pool(provider, context, providers, *, allow_guest=False):
    return provider.create_identity_pool(
        context,
        {
            "IdentityPoolName": "mobile-identities",
            "AllowUnauthenticatedIdentities": allow_guest,
            "CognitoIdentityProviders": providers,
        },
    )


def _configured_provider(client, provider_name, *, server_check=True):
    return {
        "ClientId": client["ClientId"],
        "ProviderName": provider_name,
        "ServerSideTokenCheck": server_check,
    }


def _replace_jwt_header(token, **overrides):
    header, payload, signature = token.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
    decoded.update(overrides)
    encoded = base64.urlsafe_b64encode(
        json.dumps(decoded, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=")
    return f"{encoded.decode()}.{payload}.{signature}"


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
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(account_id, None)


def test_set_and_get_default_identity_pool_roles_are_closed_and_account_scoped(provider, context):
    pool = _identity_pool(provider, context, [])
    roles = {
        "authenticated": f"arn:{context.partition}:iam::{context.account_id}:role/authenticated",
        "unauthenticated": f"arn:{context.partition}:iam::{context.account_id}:role/guest",
    }

    assert (
        provider.set_identity_pool_roles(
            context, {"IdentityPoolId": pool["IdentityPoolId"], "Roles": roles}
        )
        == {}
    )
    assert provider.get_identity_pool_roles(
        context, {"IdentityPoolId": pool["IdentityPoolId"]}
    ) == {"IdentityPoolId": pool["IdentityPoolId"], "Roles": roles, "RoleMappings": {}}

    invalid_roles = [
        {"administrator": roles["authenticated"]},
        {"authenticated": "not-an-arn"},
        {"authenticated": f"arn:aws:iam::{(int(context.account_id) + 1) % 10**12:012d}:role/auth"},
    ]
    for invalid in invalid_roles:
        with pytest.raises(CommonServiceException) as error:
            provider.set_identity_pool_roles(
                context, {"IdentityPoolId": pool["IdentityPoolId"], "Roles": invalid}
            )
        assert error.value.code == "InvalidParameterException"

    role_mappings = {
        "cognito-idp.us-east-1.amazonaws.com/example:client": {
            "Type": "Token",
            "AmbiguousRoleResolution": "AuthenticatedRole",
        }
    }
    provider.set_identity_pool_roles(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "Roles": roles,
            "RoleMappings": role_mappings,
        },
    )
    assert (
        provider.get_identity_pool_roles(context, {"IdentityPoolId": pool["IdentityPoolId"]})[
            "Roles"
        ]
        == roles
    )
    with cognito_identity_stores.lock:
        restored = pickle.loads(pickle.dumps(cognito_identity_stores))
    assert (
        restored[context.account_id][context.region]
        .identity_pools[pool["IdentityPoolId"]]
        .role_mappings
        == role_mappings
    )

    for invalid_mapping in (
        {"provider": {"Type": "Token"}},
        {
            "provider": {
                "Type": "Rules",
                "AmbiguousRoleResolution": "Deny",
                "RulesConfiguration": {"Rules": []},
            }
        },
        {
            "provider": {
                "Type": "Rules",
                "AmbiguousRoleResolution": "Deny",
                "RulesConfiguration": {
                    "Rules": [
                        {
                            "Claim": "department",
                            "MatchType": "Equals",
                            "RoleARN": "arn:aws:iam::000000000000:role/foreign",
                            "Value": "engineering",
                        }
                    ]
                },
            }
        },
    ):
        with pytest.raises(CommonServiceException) as error:
            provider.set_identity_pool_roles(
                context,
                {
                    "IdentityPoolId": pool["IdentityPoolId"],
                    "Roles": roles,
                    "RoleMappings": invalid_mapping,
                },
            )
        assert error.value.code == "InvalidParameterException"
    assert (
        provider.get_identity_pool_roles(context, {"IdentityPoolId": pool["IdentityPoolId"]})[
            "RoleMappings"
        ]
        == role_mappings
    )


def test_native_user_pool_login_is_stable_atomic_and_persistent(provider, context):
    _, idp_pool, client, provider_name, authentication = _native_user(context)
    pool = _identity_pool(provider, context, [_configured_provider(client, provider_name)])
    request = {
        "AccountId": context.account_id,
        "IdentityPoolId": pool["IdentityPoolId"],
        "Logins": {provider_name: authentication["IdToken"]},
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: provider.get_id(context, request), range(16)))

    assert len({result["IdentityId"] for result in results}) == 1
    identity_id = results[0]["IdentityId"]
    with cognito_idp_stores.lock:
        expected_subject = next(
            iter(
                cognito_idp_stores[context.account_id][context.region]
                .user_pools[idp_pool["Id"]]
                .users.values()
            )
        ).sub
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        identity = store.identities[identity_id]
        assert identity.authenticated is True
        assert identity.logins == {provider_name: expected_subject}
        assert (
            store.login_identities[
                (pool["IdentityPoolId"], provider_name, identity.logins[provider_name])
            ]
            == identity_id
        )
        restored = pickle.loads(pickle.dumps(cognito_identity_stores))
    restored_store = restored[context.account_id][context.region]
    assert (
        restored_store.login_identities[(pool["IdentityPoolId"], provider_name, expected_subject)]
        == identity_id
    )
    assert restored_store.identities[identity_id].authenticated is True

    provider.delete_identity_pool(context, {"IdentityPoolId": pool["IdentityPoolId"]})
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert identity_id not in store.identities
        assert not store.login_identities


def test_access_token_external_provider_and_disabled_user_fail_without_mutation(provider, context):
    _, idp_pool, client, provider_name, authentication = _native_user(context)
    pool = _identity_pool(provider, context, [_configured_provider(client, provider_name)])

    invalid_logins = [
        {provider_name: authentication["AccessToken"]},
        {"accounts.example": authentication["IdToken"]},
    ]
    for logins in invalid_logins:
        with pytest.raises(CommonServiceException) as error:
            provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"], "Logins": logins})
        assert error.value.code == "NotAuthorizedException"

    with cognito_idp_stores.lock:
        user = next(
            iter(
                cognito_idp_stores[context.account_id][context.region]
                .user_pools[idp_pool["Id"]]
                .users.values()
            )
        )
        user.enabled = False
    with pytest.raises(CommonServiceException) as disabled:
        provider.get_id(
            context,
            {
                "IdentityPoolId": pool["IdentityPoolId"],
                "Logins": {provider_name: authentication["IdToken"]},
            },
        )
    assert disabled.value.code == "NotAuthorizedException"
    with cognito_idp_stores.lock:
        user.enabled = True
        user.status = "FORCE_CHANGE_PASSWORD"
    with pytest.raises(CommonServiceException) as unconfirmed:
        provider.get_id(
            context,
            {
                "IdentityPoolId": pool["IdentityPoolId"],
                "Logins": {provider_name: authentication["IdToken"]},
            },
        )
    assert unconfirmed.value.code == "NotAuthorizedException"
    with cognito_idp_stores.lock:
        cognito_idp_stores[context.account_id][context.region].user_pools[idp_pool["Id"]].users.pop(
            user.username
        )
    with pytest.raises(CommonServiceException) as missing:
        provider.get_id(
            context,
            {
                "IdentityPoolId": pool["IdentityPoolId"],
                "Logins": {provider_name: authentication["IdToken"]},
            },
        )
    assert missing.value.code == "NotAuthorizedException"
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert store.identities == {}
        assert store.login_identities == {}


def test_strict_claim_validation_rejects_bad_issuer_audience_time_and_kid(provider, context):
    _, idp_pool, client, provider_name, authentication = _native_user(context)
    pool = _identity_pool(
        provider,
        context,
        [_configured_provider(client, provider_name, server_check=False)],
    )
    with cognito_idp_stores.lock:
        model = cognito_idp_stores[context.account_id][context.region].user_pools[idp_pool["Id"]]
        user = next(iter(model.users.values()))
    now = int(time.time())
    base = {
        "aud": client["ClientId"],
        "auth_time": now,
        "cognito:username": user.username,
        "exp": now + 3600,
        "iss": f"https://{provider_name}",
        "sub": user.sub,
        "token_use": "id",
    }
    bad_claims = [
        {**base, "iss": "https://attacker.invalid"},
        {**base, "aud": "wrong-client"},
        {**base, "exp": now - 1},
        {**base, "auth_time": now + 120},
        {**base, "token_use": "access"},
    ]
    tokens = [
        sign_jwt(model.id_signing_private_key_pem, model.id_signing_key_id, claims, now=now)
        for claims in bad_claims
    ]
    tokens.append(sign_jwt(model.id_signing_private_key_pem, "wrong-kid", base, now=now))
    tokens.append(
        sign_jwt(
            model.id_signing_private_key_pem,
            model.id_signing_key_id,
            {**base, "exp": now + 3600},
            now=now + 120,
        )
    )
    tokens.append(_replace_jwt_header(authentication["IdToken"], alg="HS256"))
    _, foreign_pool, _, _, _ = _native_user(context, "foreign-signer@example.test")
    with cognito_idp_stores.lock:
        foreign_model = cognito_idp_stores[context.account_id][context.region].user_pools[
            foreign_pool["Id"]
        ]
    tokens.append(
        sign_jwt(
            foreign_model.id_signing_private_key_pem,
            model.id_signing_key_id,
            base,
            now=now,
        )
    )
    for token in tokens:
        with pytest.raises(CommonServiceException) as error:
            provider.get_id(
                context,
                {
                    "IdentityPoolId": pool["IdentityPoolId"],
                    "Logins": {provider_name: token},
                },
            )
        assert error.value.code == "NotAuthorizedException"
    with cognito_identity_stores.lock:
        assert cognito_identity_stores[context.account_id][context.region].identities == {}


def test_authenticated_get_id_enforces_login_bounds_before_mutation(provider, context):
    _, _, client, provider_name, _ = _native_user(context)
    pool = _identity_pool(provider, context, [_configured_provider(client, provider_name)])
    invalid_logins = [
        {f"provider-{index}": "token" for index in range(11)},
        {provider_name: "x" * 50_001},
    ]
    for logins in invalid_logins:
        with pytest.raises(CommonServiceException) as error:
            provider.get_id(
                context,
                {"IdentityPoolId": pool["IdentityPoolId"], "Logins": logins},
            )
        assert error.value.code == "InvalidParameterException"
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert store.identities == {}
        assert store.login_identities == {}


def test_conflicting_multiple_native_logins_fail_atomically(provider, context):
    _, _, client_one, provider_one, auth_one = _native_user(context, "one@example.test")
    _, _, client_two, provider_two, auth_two = _native_user(context, "two@example.test")
    pool = _identity_pool(
        provider,
        context,
        [
            _configured_provider(client_one, provider_one),
            _configured_provider(client_two, provider_two),
        ],
    )
    identity_one = provider.get_id(
        context,
        {"IdentityPoolId": pool["IdentityPoolId"], "Logins": {provider_one: auth_one["IdToken"]}},
    )
    identity_two = provider.get_id(
        context,
        {"IdentityPoolId": pool["IdentityPoolId"], "Logins": {provider_two: auth_two["IdToken"]}},
    )
    assert identity_one != identity_two
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        before_identities = dict(store.identities)
        before_index = dict(store.login_identities)

    with pytest.raises(CommonServiceException) as conflict:
        provider.get_id(
            context,
            {
                "IdentityPoolId": pool["IdentityPoolId"],
                "Logins": {
                    provider_one: auth_one["IdToken"],
                    provider_two: auth_two["IdToken"],
                },
            },
        )
    assert conflict.value.code == "ResourceConflictException"
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert store.identities == before_identities
        assert store.login_identities == before_index


def test_native_login_rejects_cross_account_and_cross_region_user_pools(provider, context):
    _, _, client, provider_name, authentication = _native_user(context)
    cases = [
        _context(f"{(int(context.account_id) + 1) % 10**12:012d}"),
        _context(context.account_id, "us-west-2"),
    ]
    for identity_context in cases:
        pool = _identity_pool(
            provider,
            identity_context,
            [_configured_provider(client, provider_name)],
        )
        try:
            with pytest.raises(CommonServiceException) as error:
                provider.get_id(
                    identity_context,
                    {
                        "AccountId": identity_context.account_id,
                        "IdentityPoolId": pool["IdentityPoolId"],
                        "Logins": {provider_name: authentication["IdToken"]},
                    },
                )
            assert error.value.code == "NotAuthorizedException"
            with cognito_identity_stores.lock:
                assert (
                    cognito_identity_stores[identity_context.account_id][
                        identity_context.region
                    ].identities
                    == {}
                )
        finally:
            if identity_context.account_id != context.account_id:
                _remove_account(identity_context.account_id)


def test_partition_aware_cn_user_pool_issuer_is_accepted(provider):
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context = _context(account_id, "cn-north-1", "aws-cn")
    try:
        _, _, client, provider_name, authentication = _native_user(context)
        pool = _identity_pool(provider, context, [_configured_provider(client, provider_name)])

        identity = provider.get_id(
            context,
            {
                "AccountId": account_id,
                "IdentityPoolId": pool["IdentityPoolId"],
                "Logins": {provider_name: authentication["IdToken"]},
            },
        )

        assert identity["IdentityId"].startswith("cn-north-1:")
    finally:
        _remove_account(account_id)


def test_partition_dns_suffix_mismatch_is_rejected_without_mutation(provider):
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context = _context(account_id, "cn-north-1", "aws-cn")
    try:
        _, _, client, provider_name, authentication = _native_user(context)
        wrong_provider = provider_name.replace("amazonaws.com.cn", "amazonaws.com")
        pool = _identity_pool(
            provider,
            context,
            [_configured_provider(client, wrong_provider)],
        )

        with pytest.raises(CommonServiceException) as error:
            provider.get_id(
                context,
                {
                    "IdentityPoolId": pool["IdentityPoolId"],
                    "Logins": {wrong_provider: authentication["IdToken"]},
                },
            )

        assert error.value.code == "NotAuthorizedException"
        with cognito_identity_stores.lock:
            store = cognito_identity_stores[account_id][context.region]
            assert not store.identities
            assert not store.login_identities
    finally:
        _remove_account(account_id)


def test_delete_waits_for_authenticated_get_id_then_cleans_login_indexes(
    provider, context, monkeypatch
):
    _, _, client, provider_name, authentication = _native_user(context)
    pool = _identity_pool(provider, context, [_configured_provider(client, provider_name)])
    pool_id = pool["IdentityPoolId"]
    entered = threading.Event()
    release = threading.Event()
    deleted = threading.Event()
    from localstack.services.cognito_identity import provider as provider_module

    original_verify = provider_module.verify_native_id_token_claims

    def paused_verify(**kwargs):
        entered.set()
        assert release.wait(timeout=5)
        return original_verify(**kwargs)

    monkeypatch.setattr(provider_module, "verify_native_id_token_claims", paused_verify)
    creator = threading.Thread(
        target=lambda: provider.get_id(
            context,
            {
                "IdentityPoolId": pool_id,
                "Logins": {provider_name: authentication["IdToken"]},
            },
        )
    )
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
        assert not store.identities
        assert not store.login_identities
        assert not store.IDENTITY_LOCATIONS


def test_user_pool_delete_linearizes_after_server_checked_identity_link(
    provider, context, monkeypatch
):
    idp_provider, idp_pool, client, provider_name, authentication = _native_user(context)
    pool = _identity_pool(provider, context, [_configured_provider(client, provider_name)])
    entered = threading.Event()
    release = threading.Event()
    deleted = threading.Event()
    from localstack.services.cognito_identity import provider as provider_module

    original_verify = provider_module.verify_native_id_token_claims

    def paused_verify(**kwargs):
        claims = original_verify(**kwargs)
        entered.set()
        assert release.wait(timeout=5)
        return claims

    monkeypatch.setattr(provider_module, "verify_native_id_token_claims", paused_verify)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        identity_future = executor.submit(
            provider.get_id,
            context,
            {
                "IdentityPoolId": pool["IdentityPoolId"],
                "Logins": {provider_name: authentication["IdToken"]},
            },
        )
        assert entered.wait(timeout=5)

        def delete_pool():
            result = idp_provider.delete_user_pool(context, {"UserPoolId": idp_pool["Id"]})
            deleted.set()
            return result

        delete_future = executor.submit(delete_pool)
        assert not deleted.wait(timeout=0.1)
        release.set()
        identity = identity_future.result(timeout=5)
        assert delete_future.result(timeout=5) == {}

    assert deleted.is_set()
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert identity["IdentityId"] in store.identities
        assert store.login_identities
