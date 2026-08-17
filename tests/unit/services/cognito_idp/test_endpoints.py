import configparser
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from werkzeug.exceptions import MethodNotAllowed, NotFound

from localstack.constants import DEFAULT_AWS_ACCOUNT_ID
from localstack.http import Request, Router
from localstack.http.dispatcher import handler_dispatcher
from localstack.services.cognito_idp.endpoints import (
    MAX_JWKS_BYTES,
    CognitoIdpJwksEndpoint,
)
from localstack.services.cognito_idp.models import UserPool, cognito_idp_stores

REGION = "us-east-1"
POOL_ID = "us-east-1_EndpointTest123"
OTHER_ACCOUNT = "123456789012"
PROJECT_ROOT = Path(__file__).parents[4]


@pytest.fixture
def router():
    router = Router(dispatcher=handler_dispatcher())
    router.add(CognitoIdpJwksEndpoint())
    return router


@pytest.fixture
def add_pool():
    created: list[tuple[str, str, str]] = []

    def _add(account_id: str, pool_id: str, *, kid: str = "test-key", jwk=None):
        now = datetime.now(UTC)
        if jwk is None:
            jwk = {
                "alg": "RS256",
                "e": "AQAB",
                "kid": kid,
                "kty": "RSA",
                "n": "test-public-modulus",
                "use": "sig",
            }
        pool = UserPool(
            pool_id=pool_id,
            name="endpoint-test",
            arn=f"arn:aws:cognito-idp:{REGION}:{account_id}:userpool/{pool_id}",
            created_at=now,
            updated_at=now,
            access_signing_key_id=f"{kid}-access",
            access_signing_private_key_pem=b"private-access-material-must-not-be-served",
            access_signing_jwk={**jwk, "kid": f"{kid}-access"},
            id_signing_key_id=f"{kid}-id",
            id_signing_private_key_pem=b"private-id-material-must-not-be-served",
            id_signing_jwk={**jwk, "kid": f"{kid}-id"},
        )
        with cognito_idp_stores.lock:
            store = cognito_idp_stores[account_id][REGION]
            store.user_pools[pool_id] = pool
            store.POOL_LOCATIONS[pool_id] = (account_id, REGION)
        created.append((account_id, REGION, pool_id))
        return pool

    yield _add

    with cognito_idp_stores.lock:
        for account_id, region, pool_id in created:
            region_stores = cognito_idp_stores.get(account_id)
            store = region_stores.get(region) if region_stores is not None else None
            if store is not None:
                store.user_pools.pop(pool_id, None)
                if store.POOL_LOCATIONS.get(pool_id) == (account_id, region):
                    store.POOL_LOCATIONS.pop(pool_id, None)


def _path(pool_id=POOL_ID):
    return f"/{pool_id}/.well-known/jwks.json"


def test_unsigned_request_resolves_public_pool_from_global_index(router, add_pool):
    add_pool(OTHER_ACCOUNT, POOL_ID, kid="other-key")

    response = router.dispatch(Request("GET", _path()))

    assert response.status_code == 200
    assert response.json == {
        "keys": [
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "other-key-access",
                "kty": "RSA",
                "n": "test-public-modulus",
                "use": "sig",
            },
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "other-key-id",
                "kty": "RSA",
                "n": "test-public-modulus",
                "use": "sig",
            },
        ]
    }


def test_missing_pool_does_not_fall_back_to_another_store(router, add_pool):
    add_pool(OTHER_ACCOUNT, POOL_ID, kid="other-key")

    missing = router.dispatch(Request("GET", _path("us-east-1_MissingInOther1")))
    assert missing.status_code == 404
    assert missing.json == {"message": "Not Found"}


def test_public_jwks_does_not_depend_on_authorization_header(router, add_pool):
    add_pool(OTHER_ACCOUNT, POOL_ID)

    response = router.dispatch(Request("GET", _path(), headers={"Authorization": "malformed"}))

    assert response.status_code == 200


def test_response_is_public_bounded_and_never_serializes_private_fields(router, add_pool):
    add_pool(
        DEFAULT_AWS_ACCOUNT_ID,
        POOL_ID,
        jwk={
            "alg": "RS256",
            "d": "private-exponent",
            "e": "AQAB",
            "kid": "public-key",
            "kty": "RSA",
            "n": "public-modulus",
            "p": "private-prime",
            "use": "sig",
        },
    )

    response = router.dispatch(Request("GET", _path()))

    assert response.status_code == 200
    assert len(response.data) <= MAX_JWKS_BYTES
    assert b"private" not in response.data
    assert response.content_type == "application/json"
    assert response.headers["Cache-Control"] == "public, max-age=300, must-revalidate"
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_etag_supports_conditional_get(router, add_pool):
    add_pool(DEFAULT_AWS_ACCOUNT_ID, POOL_ID)
    first = router.dispatch(Request("GET", _path()))
    etag = first.headers["ETag"]

    cached = router.dispatch(Request("GET", _path(), headers={"If-None-Match": etag}))

    assert first.status_code == 200
    assert etag
    assert cached.status_code == 304
    assert cached.data == b""
    assert cached.headers["ETag"] == etag
    assert cached.headers["Cache-Control"] == "public, max-age=300, must-revalidate"
    assert cached.headers["Access-Control-Allow-Origin"] == "*"


def test_invalid_or_oversized_public_key_is_not_served(router, add_pool):
    pool = add_pool(DEFAULT_AWS_ACCOUNT_ID, POOL_ID)
    pool.id_signing_jwk["n"] = "x" * 4097

    response = router.dispatch(Request("GET", _path()))

    assert response.status_code == 500
    assert response.json == {"message": "Internal Server Error"}
    assert response.headers["Cache-Control"] == "no-store"
    assert b"x" not in response.data


def test_route_rejects_non_pool_paths_and_mutating_methods(router):
    with pytest.raises(NotFound):
        router.dispatch(Request("GET", "/not-a-pool/.well-known/jwks.json"))

    with pytest.raises(MethodNotAllowed):
        router.dispatch(Request("POST", _path(), body=json.dumps({"keys": []})))


def test_runtime_hooks_register_once_and_remove_public_endpoint(monkeypatch, add_pool):
    from localstack.services.cognito_idp import plugins

    router = Router(dispatcher=handler_dispatcher())
    monkeypatch.setattr(plugins, "ROUTER", router)
    monkeypatch.setattr(plugins, "COGNITO_IDP_JWKS_RULES", [])
    add_pool(OTHER_ACCOUNT, POOL_ID)

    plugins.register_cognito_idp_jwks()
    plugins.register_cognito_idp_jwks()
    assert router.dispatch(Request("GET", _path())).status_code == 200

    plugins.remove_cognito_idp_jwks()
    plugins.remove_cognito_idp_jwks()
    with pytest.raises(NotFound):
        router.dispatch(Request("GET", _path()))


def test_runtime_hooks_register_once_and_remove_oauth_endpoints(monkeypatch):
    from localstack.services.cognito_idp import plugins

    router = Router(dispatcher=handler_dispatcher())
    monkeypatch.setattr(plugins, "ROUTER", router)
    monkeypatch.setattr(plugins, "COGNITO_IDP_OAUTH_RULES", [])
    request = Request(
        "GET",
        "/oauth2/authorize",
        scheme="https",
        server=("missing-domain.localhost.localstack.cloud", None),
    )

    plugins.register_cognito_idp_oauth()
    plugins.register_cognito_idp_oauth()
    assert router.dispatch(request).status_code == 404

    plugins.remove_cognito_idp_oauth()
    plugins.remove_cognito_idp_oauth()
    with pytest.raises(NotFound):
        router.dispatch(request)


def test_runtime_plugin_manifest_registers_all_cognito_http_endpoints():
    manifest = configparser.ConfigParser(delimiters=("=",), interpolation=None)
    manifest.read(PROJECT_ROOT / "plux.ini")

    assert manifest["localstack.hooks.on_infra_start"]["register_cognito_idp_jwks"] == (
        "localstack.services.cognito_idp.plugins:register_cognito_idp_jwks"
    )
    assert manifest["localstack.hooks.on_infra_start"]["register_cognito_idp_oauth"] == (
        "localstack.services.cognito_idp.plugins:register_cognito_idp_oauth"
    )
    assert manifest["localstack.hooks.on_infra_start"]["register_cognito_idp_user_import"] == (
        "localstack.services.cognito_idp.plugins:register_cognito_idp_user_import"
    )
    assert manifest["localstack.hooks.on_infra_shutdown"]["remove_cognito_idp_jwks"] == (
        "localstack.services.cognito_idp.plugins:remove_cognito_idp_jwks"
    )
    assert manifest["localstack.hooks.on_infra_shutdown"]["remove_cognito_idp_oauth"] == (
        "localstack.services.cognito_idp.plugins:remove_cognito_idp_oauth"
    )
    assert manifest["localstack.hooks.on_infra_shutdown"]["remove_cognito_idp_user_import"] == (
        "localstack.services.cognito_idp.plugins:remove_cognito_idp_user_import"
    )
