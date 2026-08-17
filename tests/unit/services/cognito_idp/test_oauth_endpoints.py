import base64
import hashlib
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
import requests
import werkzeug
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.handlers.cors import CorsEnforcer
from localstack.http import Request, Router
from localstack.http.dispatcher import handler_dispatcher
from localstack.services.cognito_idp import endpoints as endpoints_module
from localstack.services.cognito_idp.endpoints import (
    MAX_BROWSER_TRANSACTIONS_PER_POOL,
    CognitoIdpJwksEndpoint,
    CognitoIdpOAuthEndpoint,
)
from localstack.services.cognito_idp.models import PasswordHash, cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.tokens import (
    decode_jwt_segment,
    generate_signing_key,
    sign_jwt,
)
from localstack.utils.net import get_free_tcp_port

CALLBACK = "https://app.example.test/callback"
DOMAIN = "amplify-oauth-test"
HOST = f"{DOMAIN}.localhost.localstack.cloud"
PASSWORD = "PermanentPass9!"
VERIFIER = "v" * 43
SPA_ORIGIN = "https://app.example.test"


def _challenge(verifier=VERIFIER):
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )


def test_managed_login_authentication_consumes_provisioned_capacity(oauth_stack):
    context, _, _, client, router = oauth_stack
    key = (context.account_id, context.region, "UserAuthentication")
    with cognito_idp_stores.lock:
        state = cognito_idp_stores[context.account_id][context.region].provisioned_rate_limits
        assert key not in state.buckets

    _complete_login(router, client["ClientId"])

    with cognito_idp_stores.lock:
        assert key in state.buckets


@pytest.fixture
def oauth_stack():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    provider = CognitoIdpProvider()
    pool = provider.create_user_pool(context, {"PoolName": "oauth-endpoint-users"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["implicit", "code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "email", "phone", "profile"],
            "CallbackURLs": [CALLBACK],
            "ClientName": "amplify-public-client",
            "DefaultRedirectURI": CALLBACK,
            "SupportedIdentityProviders": ["COGNITO"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.create_user_pool_domain(
        context,
        {"Domain": DOMAIN, "ManagedLoginVersion": 2, "UserPoolId": pool["Id"]},
    )
    provider.admin_create_user(
        context,
        {
            "TemporaryPassword": "TemporaryPass9!",
            "UserPoolId": pool["Id"],
            "UserAttributes": [
                {"Name": "email", "Value": "alice@example.test"},
                {"Name": "custom:secret", "Value": "must-not-leak-with-email-scope"},
                {"Name": "name", "Value": "Alice Example"},
                {"Name": "phone_number", "Value": "+12065550123"},
            ],
            "Username": "alice",
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": PASSWORD,
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    router = Router(dispatcher=handler_dispatcher())
    router.add(CognitoIdpJwksEndpoint())
    router.add(CognitoIdpOAuthEndpoint())
    yield context, provider, pool, client, router
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        for domain in list(store.user_pool_domains.values()):
            store.DOMAIN_LOCATIONS.pop(domain.local_hostname, None)
        for pool_id in list(store.user_pools):
            store.POOL_LOCATIONS.pop(pool_id, None)
        cognito_idp_stores.pop(context.account_id, None)


def _request(
    method,
    path,
    *,
    query=None,
    form=None,
    cookie=None,
    headers=None,
    host=HOST,
    port=None,
    remote_addr="127.0.0.1",
    scheme="https",
):
    headers = dict(headers or {})
    body = None
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urlencode(form)
    if cookie:
        headers["Cookie"] = cookie
    return Request(
        method,
        path,
        headers=headers,
        body=body,
        query_string=urlencode(query or {}, doseq=True),
        remote_addr=remote_addr,
        scheme=scheme,
        server=(host, port),
    )


def _authorize_query(client_id, **changes):
    query = {
        "client_id": client_id,
        "code_challenge": _challenge(),
        "code_challenge_method": "S256",
        "nonce": "nonce-123",
        "redirect_uri": CALLBACK,
        "response_type": "code",
        "scope": "openid email profile",
        "state": "state-123",
    }
    query.update(changes)
    return query


def _cookies(response):
    jar = SimpleCookie()
    for header in response.headers.getlist("Set-Cookie"):
        jar.load(header)
    return {key: morsel.value for key, morsel in jar.items()}


def _cookie_header(values):
    return "; ".join(f"{key}={value}" for key, value in values.items())


def _csrf(response):
    body = response.data if hasattr(response, "data") else response.content
    return re.search(rb'name="csrf_token" value="([A-Za-z0-9_-]+)"', body).group(1).decode()


def _begin_login(router, client_id, **query_changes):
    authorize = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=_authorize_query(client_id, **query_changes),
        )
    )
    assert authorize.status_code == 302
    assert authorize.headers["Location"] == "/login"
    transaction_cookies = _cookies(authorize)
    login = router.dispatch(_request("GET", "/login", cookie=_cookie_header(transaction_cookies)))
    assert login.status_code == 200
    return transaction_cookies, _csrf(login), authorize


def _complete_login(router, client_id, **query_changes):
    cookies, csrf, authorize = _begin_login(router, client_id, **query_changes)
    login = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=_cookie_header(cookies),
            form={"csrf_token": csrf, "password": PASSWORD, "username": "alice"},
        )
    )
    assert login.status_code == 302
    parameters = parse_qs(urlsplit(login.headers["Location"]).query)
    return parameters["code"][0], login, authorize


def _redeem(router, client_id, code, verifier=VERIFIER):
    return router.dispatch(
        _request(
            "POST",
            "/oauth2/token",
            form={
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "grant_type": "authorization_code",
                "redirect_uri": CALLBACK,
            },
        )
    )


def _oauth_tokens(router, client_id, **query_changes):
    code, login, _ = _complete_login(router, client_id, **query_changes)
    response = _redeem(router, client_id, code)
    assert response.status_code == 200
    return response.json, _cookies(login)


def test_managed_login_branding_and_localized_terms_signup_are_rendered(oauth_stack, monkeypatch):
    context, provider, pool, client, router = oauth_stack
    logo = b'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="32" viewBox="0 0 64 32"><rect width="64" height="32" fill="#1122aa"/></svg>'
    provider.create_managed_login_branding(
        context,
        {
            "Assets": [
                {
                    "Bytes": logo,
                    "Category": "FORM_LOGO",
                    "ColorMode": "LIGHT",
                    "Extension": "SVG",
                }
            ],
            "ClientId": client["ClientId"],
            "Settings": {
                "componentClasses": {
                    "buttons": {"borderRadius": 17},
                    "form": {"logo": {"enabled": True}},
                    "pageBackground": {"lightMode": {"color": "102030ff"}},
                    "primaryButton": {
                        "lightMode": {
                            "defaults": {
                                "backgroundColor": "1122aaff",
                                "textColor": "ffffffff",
                            }
                        }
                    },
                }
            },
            "UserPoolId": pool["Id"],
        },
    )
    terms = provider.create_terms(
        context,
        {
            "ClientId": client["ClientId"],
            "Enforcement": "NONE",
            "Links": {
                "cognito:default": "https://example.test/terms?a=1&b=2",
                "cognito:portuguese-brazil": "https://example.test/pt/termos",
            },
            "TermsName": "terms-of-use",
            "TermsSource": "LINK",
            "UserPoolId": pool["Id"],
        },
    )["Terms"]

    authorize = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=_authorize_query(client["ClientId"], lang="pt-BR"),
        )
    )
    cookie = _cookie_header(_cookies(authorize))
    login = router.dispatch(_request("GET", "/login", cookie=cookie))
    assert login.status_code == 200
    assert b"background:#102030ff" in login.data
    assert b"border-radius:17px" in login.data
    assert b"data:image/svg+xml;base64," in login.data
    assert b'href="/signup"' in login.data

    signup_with_one_document = router.dispatch(_request("GET", "/signup", cookie=cookie))
    assert signup_with_one_document.status_code == 200
    assert b"Terms of use" not in signup_with_one_document.data
    assert b"Privacy policy" not in signup_with_one_document.data

    privacy = provider.create_terms(
        context,
        {
            "ClientId": client["ClientId"],
            "Enforcement": "NONE",
            "Links": {"cognito:default": "https://example.test/privacy?a=1&b=2"},
            "TermsName": "privacy-policy",
            "TermsSource": "LINK",
            "UserPoolId": pool["Id"],
        },
    )["Terms"]
    signup = router.dispatch(_request("GET", "/signup", cookie=cookie))
    assert b'href="https://example.test/pt/termos"' in signup.data
    assert b'href="https://example.test/privacy?a=1&amp;b=2"' in signup.data
    assert b'rel="noopener noreferrer"' in signup.data
    monkeypatch.setattr(
        "localstack.services.cognito_idp.provider._new_numeric_code",
        lambda: "123456",
    )
    created = router.dispatch(
        _request(
            "POST",
            "/signup",
            cookie=cookie,
            form={
                "csrf_token": _csrf(signup),
                "email": "new-user@example.test",
                "password": PASSWORD,
                "username": "new-user",
            },
        )
    )
    assert created.status_code == 200
    assert b"Check your email" in created.data
    assert (
        provider.get_store(context).user_pools[pool["Id"]].users["new-user"].status == "UNCONFIRMED"
    )
    assert provider.describe_terms(
        context, {"TermsId": terms["TermsId"], "UserPoolId": pool["Id"]}
    )["Terms"]["Links"]["cognito:portuguese-brazil"].endswith("/pt/termos")
    assert provider.describe_terms(
        context, {"TermsId": privacy["TermsId"], "UserPoolId": pool["Id"]}
    )["Terms"]["Links"]["cognito:default"].endswith("b=2")
    confirmed = router.dispatch(
        _request(
            "POST",
            "/confirm",
            cookie=cookie,
            form={"confirmation_code": "123456", "csrf_token": _csrf(created)},
        )
    )
    assert confirmed.status_code == 302
    assert confirmed.headers["Location"] == "/login"
    login_after_confirmation = router.dispatch(_request("GET", "/login", cookie=cookie))
    authenticated = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=cookie,
            form={
                "csrf_token": _csrf(login_after_confirmation),
                "password": PASSWORD,
                "username": "new-user",
            },
        )
    )
    assert authenticated.status_code == 302
    assert "code=" in authenticated.headers["Location"]
    assert (
        provider.get_store(context).user_pools[pool["Id"]].users["new-user"].status == "CONFIRMED"
    )


def test_signup_csrf_is_one_use_under_concurrency(oauth_stack, monkeypatch):
    context, provider, pool, client, router = oauth_stack
    monkeypatch.setattr(
        "localstack.services.cognito_idp.provider._new_numeric_code",
        lambda: "654321",
    )
    cookies, _, _ = _begin_login(router, client["ClientId"])
    cookie = _cookie_header(cookies)
    signup = router.dispatch(_request("GET", "/signup", cookie=cookie))
    csrf = _csrf(signup)

    def submit():
        return router.dispatch(
            _request(
                "POST",
                "/signup",
                cookie=cookie,
                form={
                    "csrf_token": csrf,
                    "email": "race@example.test",
                    "password": PASSWORD,
                    "username": "race-user",
                },
            )
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = sorted(executor.map(lambda _: submit(), range(2)))
    assert statuses == [200, 400]
    users = provider.get_store(context).user_pools[pool["Id"]].users
    assert [username for username in users if username == "race-user"] == ["race-user"]


def test_signup_derives_required_schema_email_username_and_confidential_secret_hash(
    oauth_stack, monkeypatch
):
    context, provider, pool, _, router = oauth_stack
    stored_pool = provider.get_store(context).user_pools[pool["Id"]]
    stored_pool.username_attributes = ["email"]
    stored_pool.schema_attributes = [
        {
            "AttributeDataType": "String",
            "Mutable": True,
            "Name": "name",
            "Required": True,
        }
    ]
    confidential = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid"],
            "CallbackURLs": [CALLBACK],
            "ClientName": "managed-confidential",
            "GenerateSecret": True,
            "SupportedIdentityProviders": ["COGNITO"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    monkeypatch.setattr(
        "localstack.services.cognito_idp.provider._new_numeric_code", lambda: "246810"
    )

    cookies, _, _ = _begin_login(router, confidential["ClientId"], scope="openid")
    cookie = _cookie_header(cookies)
    signup = router.dispatch(_request("GET", "/signup", cookie=cookie))
    assert b'name="username"' not in signup.data
    assert b'name="attribute.name"' in signup.data
    created = router.dispatch(
        _request(
            "POST",
            "/signup",
            cookie=cookie,
            form={
                "attribute.name": "Managed User",
                "csrf_token": _csrf(signup),
                "email": "managed@example.test",
                "password": PASSWORD,
            },
        )
    )
    assert created.status_code == 200
    user = stored_pool.users["managed@example.test"]
    assert user.attributes == {"email": "managed@example.test", "name": "Managed User"}
    confirmed = router.dispatch(
        _request(
            "POST",
            "/confirm",
            cookie=cookie,
            form={"confirmation_code": "246810", "csrf_token": _csrf(created)},
        )
    )
    assert confirmed.status_code == 302
    assert user.status == "CONFIRMED"


def test_switching_to_classic_invalidates_managed_session_and_hides_terms(oauth_stack):
    context, provider, pool, client, router = oauth_stack
    provider.create_managed_login_branding(
        context,
        {
            "ClientId": client["ClientId"],
            "Settings": {
                "componentClasses": {"pageBackground": {"lightMode": {"color": "123456ff"}}}
            },
            "UserPoolId": pool["Id"],
        },
    )
    for name in ("terms-of-use", "privacy-policy"):
        provider.create_terms(
            context,
            {
                "ClientId": client["ClientId"],
                "Enforcement": "NONE",
                "Links": {"cognito:default": f"https://example.test/{name}"},
                "TermsName": name,
                "TermsSource": "LINK",
                "UserPoolId": pool["Id"],
            },
        )
    cookies, _, _ = _begin_login(router, client["ClientId"])
    cookie = _cookie_header(cookies)
    managed_signup = router.dispatch(_request("GET", "/signup", cookie=cookie))
    assert b"#123456ff" in managed_signup.data
    assert b"Terms of use" in managed_signup.data

    provider.update_user_pool_domain(
        context,
        {"Domain": DOMAIN, "ManagedLoginVersion": 1, "UserPoolId": pool["Id"]},
    )
    assert router.dispatch(_request("GET", "/signup", cookie=cookie)).status_code == 400

    classic_cookies, _, _ = _begin_login(router, client["ClientId"])
    classic_cookie = _cookie_header(classic_cookies)
    classic_login = router.dispatch(_request("GET", "/login", cookie=classic_cookie))
    assert b'data-managed-login-version="1"' in classic_login.data
    assert b"#123456ff" not in classic_login.data
    classic_signup = router.dispatch(_request("GET", "/signup", cookie=classic_cookie))
    assert b"Terms of use" not in classic_signup.data
    assert b"Privacy policy" not in classic_signup.data


def test_mobile_custom_scheme_authorization_code_pkce_round_trip(oauth_stack):
    context, provider, pool, _, router = oauth_stack
    callback = "billgym://auth/callback"
    logout_uri = "billgym://auth/signout"
    client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "profile"],
            "CallbackURLs": [callback],
            "ClientName": "billgym-mobile",
            "LogoutURLs": [logout_uri],
            "SupportedIdentityProviders": ["COGNITO"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]

    code, login, _ = _complete_login(
        router,
        client["ClientId"],
        redirect_uri=callback,
        scope="openid profile",
    )

    assert login.headers["Location"].startswith(f"{callback}?")
    token = router.dispatch(
        _request(
            "POST",
            "/oauth2/token",
            form={
                "client_id": client["ClientId"],
                "code": code,
                "code_verifier": VERIFIER,
                "grant_type": "authorization_code",
                "redirect_uri": callback,
            },
        )
    )
    assert token.status_code == 200
    assert (
        decode_jwt_segment(token.json["access_token"].split(".")[1])["client_id"]
        == client["ClientId"]
    )

    session_cookie = _cookies(login)["cognito_oauth_session"]
    logged_out = router.dispatch(
        _request(
            "GET",
            "/logout",
            cookie=f"cognito_oauth_session={session_cookie}",
            query={"client_id": client["ClientId"], "logout_uri": logout_uri},
        )
    )
    assert logged_out.status_code == 302
    assert logged_out.headers["Location"] == logout_uri


def test_oidc_discovery_and_userinfo_validate_local_access_token(oauth_stack):
    context, _, pool, client, router = oauth_stack
    tokens, _ = _oauth_tokens(router, client["ClientId"], scope="openid email")

    discovery = router.dispatch(_request("GET", f"/{pool['Id']}/.well-known/openid-configuration"))
    assert discovery.status_code == 200
    assert discovery.json == {
        "authorization_endpoint": f"https://{HOST}/oauth2/authorize",
        "id_token_signing_alg_values_supported": ["RS256"],
        "issuer": f"https://cognito-idp.{context.region}.amazonaws.com/{pool['Id']}",
        "jwks_uri": f"https://{HOST}/{pool['Id']}/.well-known/jwks.json",
        "response_types_supported": ["code", "token"],
        "revocation_endpoint": f"https://{HOST}/oauth2/revoke",
        "scopes_supported": ["email", "openid", "phone", "profile"],
        "subject_types_supported": ["public"],
        "token_endpoint": f"https://{HOST}/oauth2/token",
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "userinfo_endpoint": f"https://{HOST}/oauth2/userInfo",
    }

    userinfo = router.dispatch(
        _request(
            "GET",
            "/oauth2/userInfo",
            headers={
                "Authorization": f"Bearer {tokens['access_token']}",
                "Origin": SPA_ORIGIN,
            },
        )
    )
    assert userinfo.status_code == 200
    assert userinfo.headers["Access-Control-Allow-Origin"] == SPA_ORIGIN
    assert userinfo.headers["Access-Control-Allow-Credentials"] == "true"
    assert userinfo.json == {
        "email": "alice@example.test",
        "sub": decode_jwt_segment(tokens["access_token"].split(".")[1])["sub"],
        "username": "alice",
    }
    id_claims = decode_jwt_segment(tokens["id_token"].split(".")[1])
    assert id_claims["email"] == "alice@example.test"
    assert "custom:secret" not in id_claims


@pytest.mark.parametrize(
    ("scope", "expected_attributes"),
    (
        (
            "openid",
            {
                "email": "alice@example.test",
                "name": "Alice Example",
                "phone_number": "+12065550123",
            },
        ),
        ("openid email", {"email": "alice@example.test"}),
        ("openid phone", {"phone_number": "+12065550123"}),
        (
            "openid profile",
            {
                "name": "Alice Example",
            },
        ),
    ),
)
def test_oidc_scopes_limit_id_token_and_userinfo_attributes(
    oauth_stack, scope, expected_attributes
):
    _, _, _, client, router = oauth_stack
    tokens, _ = _oauth_tokens(router, client["ClientId"], scope=scope)
    id_claims = decode_jwt_segment(tokens["id_token"].split(".")[1])
    userinfo = router.dispatch(
        _request(
            "GET",
            "/oauth2/userInfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
    )

    assert userinfo.status_code == 200
    assert {
        key: value
        for key, value in id_claims.items()
        if key in {"custom:secret", "email", "name", "phone_number"}
    } == expected_attributes
    assert {
        key: value for key, value in userinfo.json.items() if key not in {"sub", "username"}
    } == expected_attributes


def test_refresh_scope_comparison_is_order_independent(oauth_stack):
    _, _, _, client, router = oauth_stack
    tokens, _ = _oauth_tokens(router, client["ClientId"])

    refreshed = router.dispatch(
        _request(
            "POST",
            "/oauth2/token",
            form={
                "client_id": client["ClientId"],
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "scope": "profile openid email",
            },
        )
    )

    assert refreshed.status_code == 200


def test_oauth_revoke_invalidates_refresh_family_and_userinfo(oauth_stack):
    _, _, _, client, router = oauth_stack
    tokens, _ = _oauth_tokens(router, client["ClientId"])

    revoked = router.dispatch(
        _request(
            "POST",
            "/oauth2/revoke",
            form={"client_id": client["ClientId"], "token": tokens["refresh_token"]},
        )
    )
    assert revoked.status_code == 200
    assert revoked.data == b""

    repeated = router.dispatch(
        _request(
            "POST",
            "/oauth2/revoke",
            form={"client_id": client["ClientId"], "token": tokens["refresh_token"]},
        )
    )
    assert repeated.status_code == 200
    userinfo = router.dispatch(
        _request(
            "GET",
            "/oauth2/userInfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
    )
    assert userinfo.status_code == 401


def test_userinfo_rejects_id_tampered_and_cross_origin_tokens(oauth_stack):
    _, _, _, client, router = oauth_stack
    tokens, _ = _oauth_tokens(router, client["ClientId"])
    access = tokens["access_token"]
    header, claims, signature = access.split(".")
    offset = len(claims) // 2
    replacement = "A" if claims[offset] != "A" else "B"
    tampered = f"{header}.{claims[:offset]}{replacement}{claims[offset + 1 :]}.{signature}"

    for token in (tokens["id_token"], tampered, "not-a-jwt"):
        response = router.dispatch(
            _request(
                "GET",
                "/oauth2/userInfo",
                headers={"Authorization": f"Bearer {token}"},
            )
        )
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'

    hostile_origin = router.dispatch(
        _request(
            "GET",
            "/oauth2/userInfo",
            headers={"Authorization": f"Bearer {access}", "Origin": "https://evil.test"},
        )
    )
    assert hostile_origin.status_code == 403


@pytest.mark.parametrize(
    ("path", "method"),
    (("/oauth2/userInfo", "GET"), ("/oauth2/revoke", "POST")),
)
def test_oidc_endpoint_preflight_is_origin_and_header_scoped(oauth_stack, path, method):
    _, _, _, _, router = oauth_stack
    accepted = router.dispatch(
        _request(
            "OPTIONS",
            path,
            headers={
                "Access-Control-Request-Headers": "authorization, content-type",
                "Access-Control-Request-Method": method,
                "Origin": SPA_ORIGIN,
            },
        )
    )
    assert accepted.status_code == 204
    assert accepted.headers["Access-Control-Allow-Origin"] == SPA_ORIGIN
    assert accepted.headers["Access-Control-Allow-Credentials"] == "true"

    rejected = router.dispatch(
        _request(
            "OPTIONS",
            path,
            headers={
                "Access-Control-Request-Headers": "x-hostile-header",
                "Access-Control-Request-Method": method,
                "Origin": SPA_ORIGIN,
            },
        )
    )
    assert rejected.status_code == 403


def test_logout_clears_only_owned_browser_session_and_validates_redirect(oauth_stack):
    _, provider, pool, client, router = oauth_stack
    provider.update_user_pool_client(
        _oauth_context_for_test(pool),
        {
            "AllowedOAuthFlows": ["implicit", "code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "email", "profile"],
            "CallbackURLs": [CALLBACK],
            "ClientId": client["ClientId"],
            "ClientName": client["ClientName"],
            "DefaultRedirectURI": CALLBACK,
            "LogoutURLs": ["https://app.example.test/signed-out"],
            "SupportedIdentityProviders": ["COGNITO"],
            "UserPoolId": pool["Id"],
        },
    )
    _, cookies = _oauth_tokens(router, client["ClientId"])
    browser_cookie = cookies["cognito_oauth_session"]

    invalid = router.dispatch(
        _request(
            "GET",
            "/logout",
            cookie=f"cognito_oauth_session={browser_cookie}",
            query={"client_id": client["ClientId"], "logout_uri": "https://evil.test/"},
        )
    )
    assert invalid.status_code == 400

    logged_out = router.dispatch(
        _request(
            "GET",
            "/logout",
            cookie=f"cognito_oauth_session={browser_cookie}",
            query={
                "client_id": client["ClientId"],
                "logout_uri": "https://app.example.test/signed-out",
            },
        )
    )
    assert logged_out.status_code == 302
    assert logged_out.headers["Location"] == "https://app.example.test/signed-out"
    assert any(
        header.startswith("cognito_oauth_session=;") and "Max-Age=0" in header
        for header in logged_out.headers.getlist("Set-Cookie")
    )


def _oauth_context_for_test(pool):
    context = RequestContext(None)
    arn = pool["Arn"].split(":")
    context.account_id = arn[4]
    context.region = arn[3]
    return context


def test_authorization_code_pkce_login_and_refresh_round_trip(oauth_stack):
    _, _, _, client, router = oauth_stack
    code, login, authorize = _complete_login(router, client["ClientId"])

    assert parse_qs(urlsplit(login.headers["Location"]).query)["state"] == ["state-123"]
    assert "Secure" in authorize.headers.getlist("Set-Cookie")[0]
    assert "HttpOnly" in authorize.headers.getlist("Set-Cookie")[0]
    assert "SameSite=Lax" in authorize.headers.getlist("Set-Cookie")[0]
    session_cookie = next(
        header
        for header in login.headers.getlist("Set-Cookie")
        if header.startswith("cognito_oauth_session=")
    )
    assert "Secure" in session_cookie

    token = _redeem(router, client["ClientId"], code)
    assert token.status_code == 200
    assert token.headers["Cache-Control"] == "no-store"
    assert token.json["token_type"] == "Bearer"
    assert token.json["expires_in"] >= 300
    assert token.json["refresh_token"]
    id_claims = decode_jwt_segment(token.json["id_token"].split(".")[1])
    access_claims = decode_jwt_segment(token.json["access_token"].split(".")[1])
    assert id_claims["nonce"] == "nonce-123"
    assert access_claims["scope"] == "openid email profile"

    refreshed = router.dispatch(
        _request(
            "POST",
            "/oauth2/token",
            form={
                "client_id": client["ClientId"],
                "grant_type": "refresh_token",
                "refresh_token": token.json["refresh_token"],
                "scope": "openid email profile",
            },
        )
    )
    assert refreshed.status_code == 200
    assert "refresh_token" not in refreshed.json
    assert decode_jwt_segment(refreshed.json["access_token"].split(".")[1])["scope"] == (
        "openid email profile"
    )


def test_http_development_transaction_cookie_is_not_marked_secure(oauth_stack):
    _, _, _, client, router = oauth_stack
    request = Request(
        "GET",
        "/oauth2/authorize",
        query_string=urlencode(_authorize_query(client["ClientId"])),
        scheme="http",
        server=(HOST, None),
    )

    response = router.dispatch(request)

    assert response.status_code == 302
    assert "Secure" not in response.headers.getlist("Set-Cookie")[0]


def test_http_black_box_session_and_strict_spa_cors(oauth_stack):
    _, _, _, client, router = oauth_stack

    def dispatch(chain, context, response):
        routed = router.dispatch(context.request)
        response.status_code = routed.status_code
        response.set_data(routed.get_data())
        response.headers.clear()
        response.headers.extend(routed.headers)

    chain = HandlerChain(request_handlers=[CorsEnforcer(), dispatch])

    @werkzeug.Request.application
    def app(request):
        response = werkzeug.Response()
        chain.handle(RequestContext(request), response)
        return response

    port = get_free_tcp_port()
    server = werkzeug.serving.make_server("127.0.0.1", port, app=app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = requests.Session()
    session.trust_env = False
    base_url = f"http://{HOST}:{port}"
    try:
        authorize = session.get(
            f"{base_url}/oauth2/authorize",
            params=_authorize_query(client["ClientId"]),
            headers={"Referer": f"{SPA_ORIGIN}/start"},
            allow_redirects=False,
            timeout=5,
        )
        assert authorize.status_code == 302
        assert session.cookies.get("cognito_oauth_transaction")

        login_form = session.get(f"{base_url}/login", timeout=5)
        assert login_form.status_code == 200
        csrf = _csrf(login_form)
        login = session.post(
            f"{base_url}/login",
            data={"csrf_token": csrf, "password": PASSWORD, "username": "alice"},
            allow_redirects=False,
            timeout=5,
        )
        assert login.status_code == 302
        assert session.cookies.get("cognito_oauth_session")
        assert "Secure" not in next(
            header
            for header in login.raw.headers.getlist("Set-Cookie")
            if header.startswith("cognito_oauth_session=")
        )
        code = parse_qs(urlsplit(login.headers["Location"]).query)["code"][0]

        session_authorize = session.get(
            f"{base_url}/oauth2/authorize",
            params=_authorize_query(client["ClientId"], state="session-cookie-sent"),
            headers={"Referer": f"{SPA_ORIGIN}/signed-in"},
            allow_redirects=False,
            timeout=5,
        )
        assert session_authorize.status_code == 302
        assert session_authorize.headers["Location"].startswith(CALLBACK)
        assert parse_qs(urlsplit(session_authorize.headers["Location"]).query)["state"] == [
            "session-cookie-sent"
        ]

        preflight = session.options(
            f"{base_url}/oauth2/token",
            headers={
                "Access-Control-Request-Headers": "content-type",
                "Access-Control-Request-Method": "POST",
                "Origin": SPA_ORIGIN,
            },
            timeout=5,
        )
        assert preflight.status_code == 204
        assert preflight.headers["Access-Control-Allow-Origin"] == SPA_ORIGIN
        assert preflight.headers["Access-Control-Allow-Credentials"] == "true"
        assert preflight.headers["Access-Control-Allow-Headers"] == "content-type"
        assert preflight.headers["Vary"] == "Origin"

        token = session.post(
            f"{base_url}/oauth2/token",
            data={
                "client_id": client["ClientId"],
                "code": code,
                "code_verifier": VERIFIER,
                "grant_type": "authorization_code",
                "redirect_uri": CALLBACK,
            },
            headers={"Origin": SPA_ORIGIN},
            timeout=5,
        )
        assert token.status_code == 200
        assert token.headers["Access-Control-Allow-Origin"] == SPA_ORIGIN
        assert token.headers["Access-Control-Allow-Credentials"] == "true"
        assert "*" not in token.headers["Access-Control-Allow-Origin"]

        forbidden = session.options(
            f"{base_url}/oauth2/token",
            headers={
                "Access-Control-Request-Headers": "content-type",
                "Access-Control-Request-Method": "POST",
                "Origin": "https://evil.example.test",
            },
            timeout=5,
        )
        assert forbidden.status_code == 403
        assert "Access-Control-Allow-Origin" not in forbidden.headers
    finally:
        session.close()
        server.shutdown()
        thread.join(timeout=10)


@pytest.mark.parametrize(
    "origin",
    [
        "null",
        "http://app.example.test",
        "https://app.example.test.evil",
        "https://app.example.test/path",
        "https://user@app.example.test",
        "https://app.example.test,https://evil.example.test",
    ],
)
def test_token_preflight_rejects_non_callback_origins(oauth_stack, origin):
    _, _, _, _, router = oauth_stack

    response = router.dispatch(
        _request(
            "OPTIONS",
            "/oauth2/token",
            headers={
                "Access-Control-Request-Headers": "content-type",
                "Access-Control-Request-Method": "POST",
                "Origin": origin,
            },
        )
    )

    assert response.status_code == 403
    assert "Access-Control-Allow-Origin" not in response.headers


def test_forbidden_token_origin_does_not_consume_authorization_code(oauth_stack):
    _, _, _, client, router = oauth_stack
    code, _, _ = _complete_login(router, client["ClientId"])
    form = {
        "client_id": client["ClientId"],
        "code": code,
        "code_verifier": VERIFIER,
        "grant_type": "authorization_code",
        "redirect_uri": CALLBACK,
    }

    forbidden = router.dispatch(
        _request(
            "POST",
            "/oauth2/token",
            form=form,
            headers={"Origin": "https://evil.example.test"},
        )
    )
    allowed = router.dispatch(
        _request("POST", "/oauth2/token", form=form, headers={"Origin": SPA_ORIGIN})
    )

    assert forbidden.status_code == 403
    assert "Access-Control-Allow-Origin" not in forbidden.headers
    assert allowed.status_code == 200
    assert allowed.headers["Access-Control-Allow-Origin"] == SPA_ORIGIN
    assert allowed.headers["Access-Control-Allow-Credentials"] == "true"


def test_existing_secure_session_skips_login(oauth_stack):
    _, _, _, client, router = oauth_stack
    _, login, _ = _complete_login(router, client["ClientId"], scope="openid email")
    session_cookie = {
        key: value for key, value in _cookies(login).items() if key == "cognito_oauth_session"
    }

    authorize = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=_authorize_query(client["ClientId"], state="state-second"),
            cookie=_cookie_header(session_cookie),
        )
    )

    assert authorize.status_code == 302
    parameters = parse_qs(urlsplit(authorize.headers["Location"]).query)
    assert parameters["code"]
    assert parameters["state"] == ["state-second"]


def test_login_rejects_user_until_password_is_permanent(oauth_stack):
    context, provider, pool, client, router = oauth_stack
    provider.admin_create_user(
        context,
        {
            "TemporaryPassword": "TemporaryPass9!",
            "UserPoolId": pool["Id"],
            "Username": "pending",
        },
    )
    cookies, csrf, _ = _begin_login(router, client["ClientId"])

    response = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=_cookie_header(cookies),
            form={
                "csrf_token": csrf,
                "password": "TemporaryPass9!",
                "username": "pending",
            },
        )
    )

    assert response.status_code == 401
    assert b"Incorrect username or password" in response.data


def test_login_transaction_rotates_csrf_and_stops_password_work_after_attempt_limit(
    oauth_stack, monkeypatch
):
    _, _, _, client, router = oauth_stack
    cookies, csrf, _ = _begin_login(router, client["ClientId"])
    original_verify = PasswordHash.verify
    calls = 0

    def counted_verify(password_hash, candidate):
        nonlocal calls
        calls += 1
        return original_verify(password_hash, candidate)

    monkeypatch.setattr(PasswordHash, "verify", counted_verify)
    for attempt in range(endpoints_module.MAX_LOGIN_ATTEMPTS_PER_TRANSACTION):
        response = router.dispatch(
            _request(
                "POST",
                "/login",
                cookie=_cookie_header(cookies),
                form={"csrf_token": csrf, "password": "WrongPassword9!", "username": "alice"},
            )
        )
        if attempt + 1 < endpoints_module.MAX_LOGIN_ATTEMPTS_PER_TRANSACTION:
            assert response.status_code == 401
            rotated_csrf = _csrf(response)
            assert rotated_csrf != csrf
            csrf = rotated_csrf
        else:
            assert response.status_code == 429
            assert response.json == {"error": "too_many_requests"}

    replay = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=_cookie_header(cookies),
            form={"csrf_token": csrf, "password": PASSWORD, "username": "alice"},
        )
    )

    assert replay.status_code == 400
    assert calls == endpoints_module.MAX_LOGIN_ATTEMPTS_PER_TRANSACTION


def test_login_rate_limit_survives_new_transactions_and_bounds_pool_password_work(
    oauth_stack, monkeypatch
):
    context, _, _, client, router = oauth_stack
    monkeypatch.setattr(endpoints_module, "MAX_LOGIN_ATTEMPTS_PER_USER_WINDOW", 2)
    monkeypatch.setattr(endpoints_module, "MAX_LOGIN_ATTEMPTS_PER_SOURCE_WINDOW", 2)
    original_verify = PasswordHash.verify
    calls = 0

    def counted_verify(password_hash, candidate):
        nonlocal calls
        calls += 1
        return original_verify(password_hash, candidate)

    monkeypatch.setattr(PasswordHash, "verify", counted_verify)
    for _ in range(2):
        cookies, csrf, _ = _begin_login(router, client["ClientId"])
        response = router.dispatch(
            _request(
                "POST",
                "/login",
                cookie=_cookie_header(cookies),
                form={"csrf_token": csrf, "password": "WrongPassword9!", "username": "alice"},
            )
        )
        assert response.status_code == 401

    cookies, csrf, _ = _begin_login(router, client["ClientId"])
    blocked = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=_cookie_header(cookies),
            form={"csrf_token": csrf, "password": PASSWORD, "username": "alice"},
        )
    )

    assert blocked.status_code == 429
    assert calls == 2
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert len(store.login_attempt_windows) == 2
        assert all(re.fullmatch(r"[0-9a-f]{64}", key) for key in store.login_attempt_windows)


def test_login_rate_limit_is_scoped_by_network_source_not_arbitrary_usernames(
    oauth_stack, monkeypatch
):
    _, _, _, client, router = oauth_stack
    monkeypatch.setattr(endpoints_module, "MAX_LOGIN_ATTEMPTS_PER_SOURCE_WINDOW", 2)
    first_source = "192.0.2.10"

    for username in ("invented-one", "invented-two"):
        cookies, csrf, _ = _begin_login(router, client["ClientId"])
        response = router.dispatch(
            _request(
                "POST",
                "/login",
                cookie=_cookie_header(cookies),
                form={
                    "csrf_token": csrf,
                    "password": "WrongPassword9!",
                    "username": username,
                },
                remote_addr=first_source,
            )
        )
        assert response.status_code == 401

    cookies, csrf, _ = _begin_login(router, client["ClientId"])
    blocked = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=_cookie_header(cookies),
            form={"csrf_token": csrf, "password": PASSWORD, "username": "alice"},
            remote_addr=first_source,
        )
    )
    assert blocked.status_code == 429

    allowed = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=_cookie_header(cookies),
            form={"csrf_token": csrf, "password": PASSWORD, "username": "alice"},
            remote_addr="198.51.100.20",
        )
    )
    assert allowed.status_code == 302


def test_confidential_client_uses_exact_http_basic_credentials(oauth_stack):
    context, provider, pool, _, router = oauth_stack
    client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "email", "profile"],
            "CallbackURLs": [CALLBACK],
            "ClientName": "confidential-client",
            "GenerateSecret": True,
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    code, _, _ = _complete_login(router, client["ClientId"], scope="openid email profile")
    credentials = base64.b64encode(
        f"{client['ClientId']}:{client['ClientSecret']}".encode()
    ).decode()

    response = router.dispatch(
        _request(
            "POST",
            "/oauth2/token",
            headers={"Authorization": f"Basic {credentials}"},
            form={
                "code": code,
                "code_verifier": VERIFIER,
                "grant_type": "authorization_code",
                "redirect_uri": CALLBACK,
            },
        )
    )

    assert response.status_code == 200
    assert response.json["access_token"]


@pytest.mark.parametrize("confidential", [False, True])
def test_oauth_refresh_grant_reuses_native_rotation_and_grace_with_cors(oauth_stack, confidential):
    context, provider, pool, _, router = oauth_stack
    client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "email", "profile"],
            "CallbackURLs": [CALLBACK],
            "ClientName": f"rotating-{'confidential' if confidential else 'public'}",
            "GenerateSecret": confidential,
            "RefreshTokenRotation": {
                "Feature": "ENABLED",
                "RetryGracePeriodSeconds": 30,
            },
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    code, _, _ = _complete_login(router, client["ClientId"], scope="openid email profile")
    credentials = (
        base64.b64encode(f"{client['ClientId']}:{client['ClientSecret']}".encode()).decode()
        if confidential
        else None
    )
    headers = {"Authorization": f"Basic {credentials}"} if credentials else {}
    initial = router.dispatch(
        _request(
            "POST",
            "/oauth2/token",
            headers=headers,
            form={
                **({} if confidential else {"client_id": client["ClientId"]}),
                "code": code,
                "code_verifier": VERIFIER,
                "grant_type": "authorization_code",
                "redirect_uri": CALLBACK,
            },
        )
    )
    assert initial.status_code == 200

    def refresh(token, scope="openid email"):
        return router.dispatch(
            _request(
                "POST",
                "/oauth2/token",
                headers={**headers, "Origin": "https://app.example.test"},
                form={
                    **({} if confidential else {"client_id": client["ClientId"]}),
                    "grant_type": "refresh_token",
                    "refresh_token": token,
                    "scope": scope,
                },
            )
        )

    invalid_scope = refresh(initial.json["refresh_token"], "openid phone")
    rotated = refresh(initial.json["refresh_token"])
    retried = refresh(initial.json["refresh_token"])

    assert invalid_scope.status_code == 400
    assert rotated.status_code == retried.status_code == 200
    assert rotated.json["refresh_token"] == retried.json["refresh_token"]
    assert decode_jwt_segment(rotated.json["access_token"].split(".")[1])["scope"] == (
        "openid email"
    )
    assert rotated.headers["Access-Control-Allow-Origin"] == "https://app.example.test"
    assert rotated.headers["Cache-Control"] == "no-store"


def test_oidc_federation_browser_flow_returns_to_code_pipeline(
    oauth_stack, httpserver, monkeypatch
):
    context, provider, pool, _, router = oauth_stack
    upstream = httpserver.url_for("").rstrip("/")
    authority = urlsplit(upstream).netloc
    monkeypatch.setattr(config, "COGNITO_IDP_EGRESS_ALLOWLIST", [authority])
    key_id, private_key, jwk = generate_signing_key()
    provider.create_identity_provider(
        context,
        {
            "AttributeMapping": {"email": "email"},
            "IdpIdentifiers": ["corp"],
            "ProviderDetails": {
                "attributes_request_method": "GET",
                "attributes_url": f"{upstream}/userinfo",
                "authorize_scopes": "openid email",
                "authorize_url": f"{upstream}/authorize",
                "client_id": "upstream-client",
                "client_secret": "upstream-secret",
                "jwks_uri": f"{upstream}/jwks",
                "oidc_issuer": upstream,
                "token_url": f"{upstream}/token",
            },
            "ProviderName": "CorporateOIDC",
            "ProviderType": "OIDC",
            "UserPoolId": pool["Id"],
        },
    )
    client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "email"],
            "CallbackURLs": [CALLBACK],
            "ClientName": "federated-public",
            "SupportedIdentityProviders": ["COGNITO", "CorporateOIDC"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]

    authorize = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=_authorize_query(
                client["ClientId"],
                scope="openid email",
            ),
        )
    )
    assert authorize.status_code == 302
    assert authorize.headers["Location"] == "/login"
    transaction_cookie = _cookie_header(_cookies(authorize))
    login_page = router.dispatch(_request("GET", "/login", cookie=transaction_cookie))
    assert login_page.status_code == 200
    assert b"Continue with CorporateOIDC" in login_page.data
    assert b'name="username"' in login_page.data
    federation_redirect = router.dispatch(
        _request(
            "GET",
            "/login",
            cookie=transaction_cookie,
            query={"identity_provider": "CorporateOIDC"},
        )
    )
    assert federation_redirect.status_code == 302
    upstream_query = parse_qs(urlsplit(federation_redirect.headers["Location"]).query)
    assert upstream_query["code_challenge_method"] == ["S256"]
    assert upstream_query["redirect_uri"][0].endswith("/oauth2/idpresponse")
    nonce = upstream_query["nonce"][0]
    state = upstream_query["state"][0]
    now = int(time.time())
    id_token = sign_jwt(
        private_key,
        key_id,
        {
            "aud": "upstream-client",
            "email": "federated@example.test",
            "exp": now + 300,
            "iss": upstream,
            "nonce": nonce,
            "sub": "external-123",
        },
        now=now,
    )
    httpserver.expect_request("/token", method="POST").respond_with_json(
        {"access_token": "upstream-access", "id_token": id_token, "token_type": "Bearer"}
    )
    httpserver.expect_request("/jwks", method="GET").respond_with_json({"keys": [jwk]})
    httpserver.expect_request("/userinfo", method="GET").respond_with_json(
        {"email": "federated@example.test", "sub": "external-123"}
    )

    wrong_state = router.dispatch(
        _request(
            "GET",
            "/oauth2/idpresponse",
            cookie=transaction_cookie,
            query={"code": "upstream-code", "state": f"{state}x"},
        )
    )
    assert wrong_state.status_code == 400
    callback = router.dispatch(
        _request(
            "GET",
            "/oauth2/idpresponse",
            cookie=transaction_cookie,
            query={"code": "upstream-code", "state": state},
        )
    )
    assert callback.status_code == 302
    replay = router.dispatch(
        _request(
            "GET",
            "/oauth2/idpresponse",
            cookie=transaction_cookie,
            query={"code": "upstream-code", "state": state},
        )
    )
    assert replay.status_code == 400
    callback_query = parse_qs(urlsplit(callback.headers["Location"]).query)
    assert callback_query["state"] == ["state-123"]
    local_token = router.dispatch(
        _request(
            "POST",
            "/oauth2/token",
            form={
                "client_id": client["ClientId"],
                "code": callback_query["code"][0],
                "code_verifier": VERIFIER,
                "grant_type": "authorization_code",
                "redirect_uri": CALLBACK,
            },
        )
    )
    assert local_token.status_code == 200
    claims = decode_jwt_segment(local_token.json["id_token"].split(".")[1])
    assert claims["email"] == "federated@example.test"
    assert claims["identities"][0]["providerName"] == "CorporateOIDC"

    capped_authorize = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=_authorize_query(
                client["ClientId"],
                identity_provider="CorporateOIDC",
                scope="openid email",
            ),
        )
    )
    capped_upstream = parse_qs(urlsplit(capped_authorize.headers["Location"]).query)
    capped_now = int(time.time())
    capped_id_token = sign_jwt(
        private_key,
        key_id,
        {
            "aud": "upstream-client",
            "email": "atomic@example.test",
            "exp": capped_now + 300,
            "iss": upstream,
            "nonce": capped_upstream["nonce"][0],
            "sub": "external-atomic",
        },
        now=capped_now,
    )
    httpserver.expect_request("/token", method="POST").respond_with_json(
        {
            "access_token": "upstream-access-atomic",
            "id_token": capped_id_token,
            "token_type": "Bearer",
        }
    )
    httpserver.expect_request("/userinfo", method="GET").respond_with_json(
        {"email": "atomic@example.test", "sub": "external-atomic"}
    )
    monkeypatch.setattr(endpoints_module, "MAX_AUTHORIZATION_CODES_PER_POOL", 0)
    capped_callback = router.dispatch(
        _request(
            "GET",
            "/oauth2/idpresponse",
            cookie=_cookie_header(_cookies(capped_authorize)),
            query={"code": "upstream-code-atomic", "state": capped_upstream["state"][0]},
        )
    )
    assert parse_qs(urlsplit(capped_callback.headers["Location"]).query)["error"] == [
        "temporarily_unavailable"
    ]
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert all(
            identity.provider_attribute_value != "external-atomic"
            for user in store.user_pools[pool["Id"]].users.values()
            for identity in user.federated_identities
        )
        assert all(
            user.attributes.get("email") != "atomic@example.test"
            for user in store.user_pools[pool["Id"]].users.values()
        )
        assert not store.browser_transactions

    external_only = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "email"],
            "CallbackURLs": [CALLBACK],
            "ClientName": "federated-external-only",
            "SupportedIdentityProviders": ["CorporateOIDC"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    external_authorize = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=_authorize_query(external_only["ClientId"], scope="openid email"),
        )
    )
    external_login = router.dispatch(
        _request(
            "GET",
            "/login",
            cookie=_cookie_header(_cookies(external_authorize)),
        )
    )
    assert b"Continue with CorporateOIDC" in external_login.data
    assert b'name="username"' not in external_login.data


@pytest.mark.parametrize(
    ("provider_type", "subject_field", "callback_method"),
    [
        ("Google", "sub", "GET"),
        ("Facebook", "id", "GET"),
        ("LoginWithAmazon", "user_id", "GET"),
        ("SignInWithApple", "sub", "POST"),
    ],
)
def test_social_provider_browser_adapters_use_local_fixture_without_real_egress(
    oauth_stack,
    httpserver,
    monkeypatch,
    provider_type,
    subject_field,
    callback_method,
):
    context, provider, pool, _, router = oauth_stack
    upstream = httpserver.url_for("").rstrip("/")
    authority = urlsplit(upstream).netloc
    monkeypatch.setattr(config, "COGNITO_IDP_EGRESS_ALLOWLIST", [authority])
    monkeypatch.setattr(config, "COGNITO_IDP_SOCIAL_ENDPOINTS", [f"{provider_type}={upstream}"])
    details = {
        "authorize_scopes": (
            "public_profile,email"
            if provider_type == "Facebook"
            else "profile postal_code"
            if provider_type == "LoginWithAmazon"
            else "name email"
            if provider_type == "SignInWithApple"
            else "openid email profile"
        ),
        "client_id": f"{provider_type}-client",
    }
    if provider_type == "SignInWithApple":
        details.update(
            {
                "key_id": "APPLEKEY",
                "private_key": ec.generate_private_key(ec.SECP256R1())
                .private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
                .decode(),
                "team_id": "APPLETEAM",
            }
        )
    else:
        details["client_secret"] = f"{provider_type}-secret"
    if provider_type == "Facebook":
        details["api_version"] = "v17.0"
    provider.create_identity_provider(
        context,
        {
            "AttributeMapping": {"email": "email"},
            "ProviderDetails": details,
            "ProviderName": provider_type,
            "ProviderType": provider_type,
            "UserPoolId": pool["Id"],
        },
    )
    client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "email"],
            "CallbackURLs": [CALLBACK],
            "ClientName": f"{provider_type}-public",
            "SupportedIdentityProviders": [provider_type],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    authorize = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=_authorize_query(
                client["ClientId"], identity_provider=provider_type, scope="openid email"
            ),
        )
    )
    upstream_query = parse_qs(urlsplit(authorize.headers["Location"]).query)
    assert upstream_query["code_challenge_method"] == ["S256"]
    if provider_type == "SignInWithApple":
        assert upstream_query["response_mode"] == ["form_post"]
    subject = f"{provider_type.lower()}-subject"
    token_response = {"access_token": f"{provider_type}-access"}
    if provider_type in {"Google", "SignInWithApple"}:
        key_id, private_key, jwk = generate_signing_key()
        token_response["id_token"] = sign_jwt(
            private_key,
            key_id,
            {
                "aud": details["client_id"],
                "email": f"{provider_type.lower()}@example.test",
                "exp": int(time.time()) + 300,
                "iss": upstream,
                "nonce": upstream_query["nonce"][0],
                "sub": subject,
            },
        )
        httpserver.expect_request("/jwks", method="GET").respond_with_json({"keys": [jwk]})
    httpserver.expect_request(
        "/token",
        method="GET" if provider_type == "Facebook" else "POST",
    ).respond_with_json(token_response)
    if provider_type != "SignInWithApple":
        httpserver.expect_request("/userinfo", method="GET").respond_with_json(
            {
                "email": f"{provider_type.lower()}@example.test",
                subject_field: subject,
            }
        )
    callback_parameters = {
        "code": "social-code",
        "state": upstream_query["state"][0],
    }
    callback = router.dispatch(
        _request(
            callback_method,
            "/oauth2/idpresponse",
            cookie=_cookie_header(_cookies(authorize)),
            **(
                {"form": callback_parameters}
                if callback_method == "POST"
                else {"query": callback_parameters}
            ),
        )
    )
    assert callback.status_code == 302
    local_code = parse_qs(urlsplit(callback.headers["Location"]).query)["code"][0]
    local_token = router.dispatch(
        _request(
            "POST",
            "/oauth2/token",
            form={
                "client_id": client["ClientId"],
                "code": local_code,
                "code_verifier": VERIFIER,
                "grant_type": "authorization_code",
                "redirect_uri": CALLBACK,
            },
        )
    )
    claims = decode_jwt_segment(local_token.json["id_token"].split(".")[1])
    assert claims["email"] == f"{provider_type.lower()}@example.test"
    assert claims["identities"][0]["providerType"] == provider_type


@pytest.mark.parametrize(
    "changes",
    [
        {"client_id": "missing-client"},
        {"redirect_uri": "https://evil.example.test/callback"},
    ],
)
def test_authorize_never_redirects_before_exact_client_and_uri_validation(oauth_stack, changes):
    _, _, _, client, router = oauth_stack
    query = _authorize_query(client["ClientId"])
    query.update(changes)

    response = router.dispatch(_request("GET", "/oauth2/authorize", query=query))

    assert response.status_code == 400
    assert "Location" not in response.headers
    assert response.headers["Cache-Control"] == "no-store"


def test_authorize_redirects_safe_protocol_error_after_client_and_uri(oauth_stack):
    _, _, _, client, router = oauth_stack
    response = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=_authorize_query(client["ClientId"], scope="openid unknown"),
        )
    )

    assert response.status_code == 302
    assert response.headers["Location"].startswith(CALLBACK)
    parameters = parse_qs(urlsplit(response.headers["Location"]).query)
    assert parameters["error"] == ["invalid_scope"]
    assert parameters["state"] == ["state-123"]


@pytest.mark.parametrize(
    "changes",
    [
        {"state": ""},
        {"state": ["one", "two"]},
        {"nonce": "bad\nnonce"},
        {"nonce": ["one", "two"]},
    ],
)
def test_authorize_rejects_ambiguous_state_and_nonce(oauth_stack, changes):
    _, _, _, client, router = oauth_stack

    response = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=_authorize_query(client["ClientId"], **changes),
        )
    )

    assert response.status_code == 302
    parameters = parse_qs(urlsplit(response.headers["Location"]).query)
    assert parameters["error"] == ["invalid_request"]


def test_configured_implicit_flow_returns_tokens_in_fragment_without_refresh(oauth_stack):
    context, _, _, client, router = oauth_stack
    query = _authorize_query(client["ClientId"], response_type="token")
    query.pop("code_challenge")
    query.pop("code_challenge_method")
    authorize = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=query,
        )
    )

    assert authorize.status_code == 302
    assert authorize.headers["Location"] == "/login"
    transaction_cookie = _cookies(authorize)["cognito_oauth_transaction"]
    form = router.dispatch(
        _request("GET", "/login", cookie=f"cognito_oauth_transaction={transaction_cookie}")
    )
    response = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=f"cognito_oauth_transaction={transaction_cookie}",
            form={"csrf_token": _csrf(form), "password": PASSWORD, "username": "alice"},
        )
    )

    assert response.status_code == 302
    fragment = parse_qs(urlsplit(response.headers["Location"]).fragment)
    assert set(fragment) == {"access_token", "expires_in", "id_token", "state", "token_type"}
    assert fragment["state"] == ["state-123"]
    assert fragment["token_type"] == ["Bearer"]
    assert decode_jwt_segment(fragment["id_token"][0].split(".")[1])["nonce"] == "nonce-123"
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert store.authorization_codes == {}
        assert store.refresh_sessions == {}


def test_csrf_is_required_and_transaction_cookie_contains_no_state(oauth_stack):
    context, _, _, client, router = oauth_stack
    cookies, csrf, authorize = _begin_login(router, client["ClientId"])

    rejected = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=_cookie_header(cookies),
            form={"csrf_token": "wrong", "password": PASSWORD, "username": "alice"},
        )
    )

    assert rejected.status_code == 400
    assert b"state-123" not in authorize.data
    raw_transaction = cookies["cognito_oauth_transaction"]
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert raw_transaction not in store.browser_transactions
        assert all(
            transaction.state == "state-123" for transaction in store.browser_transactions.values()
        )
        assert all(
            transaction.csrf_hash != csrf for transaction in store.browser_transactions.values()
        )


def test_authorization_code_is_atomic_one_use_under_concurrency(oauth_stack):
    _, _, _, client, router = oauth_stack
    code, _, _ = _complete_login(router, client["ClientId"])

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(
            executor.map(lambda _: _redeem(router, client["ClientId"], code), range(2))
        )

    assert sorted(response.status_code for response in responses) == [200, 400]
    error = next(response for response in responses if response.status_code == 400)
    assert error.json == {"error": "invalid_grant"}


def test_failed_pkce_consumes_code_and_replay_stays_invalid(oauth_stack):
    _, _, _, client, router = oauth_stack
    code, _, _ = _complete_login(router, client["ClientId"])

    wrong = _redeem(router, client["ClientId"], code, verifier="x" * 43)
    replay = _redeem(router, client["ClientId"], code)

    assert wrong.status_code == 400
    assert wrong.json == {"error": "invalid_grant"}
    assert replay.status_code == 400
    assert replay.json == {"error": "invalid_grant"}


def test_browser_transaction_store_is_bounded_and_hash_only(oauth_stack):
    context, _, _, client, router = oauth_stack
    raw_tokens = []
    for index in range(MAX_BROWSER_TRANSACTIONS_PER_POOL):
        response = router.dispatch(
            _request(
                "GET",
                "/oauth2/authorize",
                query=_authorize_query(client["ClientId"], state=f"state-{index}"),
            )
        )
        assert response.status_code == 302
        raw_tokens.append(_cookies(response)["cognito_oauth_transaction"])

    rejected = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=_authorize_query(client["ClientId"], state="over-capacity"),
        )
    )

    assert rejected.status_code == 503

    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert len(store.browser_transactions) == MAX_BROWSER_TRANSACTIONS_PER_POOL
        assert not set(raw_tokens) & set(store.browser_transactions)


def test_code_and_session_stores_are_bounded_hash_only_and_code_ttl_is_five_minutes(
    oauth_stack, monkeypatch
):
    context, _, _, client, router = oauth_stack
    monkeypatch.setattr(endpoints_module, "MAX_AUTHORIZATION_CODES_PER_POOL", 2)
    monkeypatch.setattr(endpoints_module, "MAX_BROWSER_SESSIONS_PER_POOL", 2)
    raw_codes = []
    raw_sessions = []
    for index in range(2):
        code, login, _ = _complete_login(router, client["ClientId"], state=f"bounded-{index}")
        raw_codes.append(code)
        raw_sessions.append(_cookies(login)["cognito_oauth_session"])

    pending_cookies, pending_csrf, _ = _begin_login(
        router, client["ClientId"], state="bounded-over-capacity"
    )
    rejected = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=_cookie_header(pending_cookies),
            form={"csrf_token": pending_csrf, "password": PASSWORD, "username": "alice"},
        )
    )

    assert rejected.status_code == 503

    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert len(store.authorization_codes) == 2
        assert len(store.browser_sessions) == 2
        assert not set(raw_codes) & set(store.authorization_codes)
        assert not set(raw_sessions) & set(store.browser_sessions)
        assert all(
            (code.expires_at - code.created_at).total_seconds() == 300
            for code in store.authorization_codes.values()
        )


def test_pool_deletion_cleans_all_oauth_browser_state(oauth_stack):
    context, provider, pool, client, router = oauth_stack
    _complete_login(router, client["ClientId"])
    _begin_login(router, client["ClientId"], state="pending")
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert store.browser_transactions
        assert store.authorization_codes
        assert store.browser_sessions

    provider.delete_user_pool(context, {"UserPoolId": pool["Id"]})

    with cognito_idp_stores.lock:
        assert store.browser_transactions == {}
        assert store.authorization_codes == {}
        assert store.browser_sessions == {}


def test_authorize_revalidates_domain_pool_and_client_before_persisting(oauth_stack, monkeypatch):
    context, provider, pool, client, router = oauth_stack
    original = endpoints_module._scope_parameter
    deleted = False

    def delete_before_persist(parameters, key):
        nonlocal deleted
        result = original(parameters, key)
        if not deleted:
            deleted = True
            provider.delete_user_pool(context, {"UserPoolId": pool["Id"]})
        return result

    monkeypatch.setattr(endpoints_module, "_scope_parameter", delete_before_persist)

    response = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=_authorize_query(client["ClientId"]),
        )
    )

    assert response.status_code == 404
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert store.browser_transactions == {}


def test_oauth_eviction_never_removes_another_pool_state(oauth_stack, monkeypatch):
    context, provider, _, client, router = oauth_stack
    monkeypatch.setattr(endpoints_module, "MAX_BROWSER_TRANSACTIONS_PER_POOL", 2)
    victim = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            query=_authorize_query(client["ClientId"], state="victim"),
        )
    )
    victim_hash = hashlib.sha256(_cookies(victim)["cognito_oauth_transaction"].encode()).hexdigest()

    other_pool = provider.create_user_pool(context, {"PoolName": "other-oauth-pool"})["UserPool"]
    other_client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid"],
            "CallbackURLs": [CALLBACK],
            "ClientName": "other-client",
            "UserPoolId": other_pool["Id"],
        },
    )["UserPoolClient"]
    provider.create_user_pool_domain(
        context,
        {"Domain": "other-oauth-domain", "UserPoolId": other_pool["Id"]},
    )
    for index in range(3):
        response = router.dispatch(
            _request(
                "GET",
                "/oauth2/authorize",
                host="other-oauth-domain.localhost.localstack.cloud",
                query=_authorize_query(
                    other_client["ClientId"], state=f"attacker-{index}", scope="openid"
                ),
            )
        )
        assert response.status_code == (302 if index < 2 else 503)

    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert victim_hash in store.browser_transactions
        assert (
            sum(
                transaction.pool_id == other_pool["Id"]
                for transaction in store.browser_transactions.values()
            )
            == 2
        )


@pytest.mark.parametrize(
    ("scheme", "port", "authority"),
    (("https", 80, f"{HOST}:80"), ("http", 443, f"{HOST}:443")),
)
def test_discovery_preserves_explicit_nondefault_port_and_never_reflects_host(
    oauth_stack, scheme, port, authority
):
    _, _, pool, _, router = oauth_stack
    request = _request(
        "GET",
        f"/{pool['Id']}/.well-known/openid-configuration",
        headers={"Host": f"attacker.example.test:{port}"},
        host="attacker.example.test",
        port=port,
        scheme=scheme,
    )

    response = router.dispatch(request)

    assert response.status_code == 200
    assert response.json["jwks_uri"] == (
        f"{scheme}://{authority}/{pool['Id']}/.well-known/jwks.json"
    )
    assert response.json["authorization_endpoint"] == f"{scheme}://{authority}/oauth2/authorize"


def test_revoke_rejects_access_tokens_without_claiming_revocation(oauth_stack):
    _, _, _, client, router = oauth_stack
    tokens, _ = _oauth_tokens(router, client["ClientId"])

    response = router.dispatch(
        _request(
            "POST",
            "/oauth2/revoke",
            form={"client_id": client["ClientId"], "token": tokens["access_token"]},
            headers={"Origin": SPA_ORIGIN},
        )
    )

    assert response.status_code == 400
    assert response.json == {"error": "unsupported_token_type"}


def test_prompt_login_bypasses_an_existing_browser_session(oauth_stack):
    _, _, _, client, router = oauth_stack
    _, login, _ = _complete_login(router, client["ClientId"], scope="openid email")
    session_cookie = _cookies(login)["cognito_oauth_session"]

    response = router.dispatch(
        _request(
            "GET",
            "/oauth2/authorize",
            cookie=f"cognito_oauth_session={session_cookie}",
            query=_authorize_query(client["ClientId"], prompt="login"),
        )
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"
    assert "cognito_oauth_transaction" in _cookies(response)


def test_logout_can_redirect_to_managed_login_for_confidential_client_reauthentication(
    oauth_stack,
):
    context, provider, pool, _, router = oauth_stack
    client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "email"],
            "CallbackURLs": [CALLBACK],
            "ClientName": "logout-confidential-client",
            "GenerateSecret": True,
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    _, login, _ = _complete_login(router, client["ClientId"], scope="openid email")
    session_cookie = _cookies(login)["cognito_oauth_session"]
    query = {
        "client_id": client["ClientId"],
        "nonce": "logout-nonce",
        "redirect_uri": CALLBACK,
        "response_type": "code",
        "scope": "openid email",
        "state": "logout-state",
    }

    response = router.dispatch(
        _request(
            "GET",
            "/logout",
            cookie=f"cognito_oauth_session={session_cookie}",
            query=query,
        )
    )

    assert response.status_code == 302
    assert urlsplit(response.headers["Location"]).path == "/login"
    assert parse_qs(urlsplit(response.headers["Location"]).query) == {
        key: [value] for key, value in query.items()
    }
    transaction_cookie = _cookies(response)["cognito_oauth_transaction"]
    login_form = router.dispatch(
        _request("GET", "/login", cookie=f"cognito_oauth_transaction={transaction_cookie}")
    )
    assert login_form.status_code == 200
    login = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=f"cognito_oauth_transaction={transaction_cookie}",
            form={"csrf_token": _csrf(login_form), "password": PASSWORD, "username": "alice"},
        )
    )
    code = parse_qs(urlsplit(login.headers["Location"]).query)["code"][0]
    tokens = router.dispatch(
        _request(
            "POST",
            "/oauth2/token",
            form={
                "client_id": client["ClientId"],
                "client_secret": client["ClientSecret"],
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": CALLBACK,
            },
        )
    )
    assert tokens.status_code == 200
    assert tokens.json["token_type"] == "Bearer"


def test_logout_reauthentication_fails_closed_for_public_client_without_pkce(oauth_stack):
    _, _, _, client, router = oauth_stack
    _, login, _ = _complete_login(router, client["ClientId"])
    session_cookie = _cookies(login)["cognito_oauth_session"]

    response = router.dispatch(
        _request(
            "GET",
            "/logout",
            cookie=f"cognito_oauth_session={session_cookie}",
            query={
                "client_id": client["ClientId"],
                "redirect_uri": CALLBACK,
                "response_type": "code",
                "scope": "openid",
            },
        )
    )

    assert response.status_code == 400
    assert response.json == {"error": "invalid_request"}


def test_logout_public_client_reauthentication_preserves_pkce_to_token_exchange(oauth_stack):
    _, _, _, client, router = oauth_stack
    _, login, _ = _complete_login(router, client["ClientId"])
    query = _authorize_query(client["ClientId"], scope="openid")

    response = router.dispatch(
        _request(
            "GET",
            "/logout",
            cookie=f"cognito_oauth_session={_cookies(login)['cognito_oauth_session']}",
            query=query,
        )
    )

    assert response.status_code == 302
    assert urlsplit(response.headers["Location"]).path == "/login"
    transaction_cookie = _cookies(response)["cognito_oauth_transaction"]
    login_form = router.dispatch(
        _request("GET", "/login", cookie=f"cognito_oauth_transaction={transaction_cookie}")
    )
    authenticated = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=f"cognito_oauth_transaction={transaction_cookie}",
            form={"csrf_token": _csrf(login_form), "password": PASSWORD, "username": "alice"},
        )
    )
    code = parse_qs(urlsplit(authenticated.headers["Location"]).query)["code"][0]

    tokens = _redeem(router, client["ClientId"], code)

    assert tokens.status_code == 200
    assert tokens.json["token_type"] == "Bearer"


def test_logout_reauthentication_accepts_associated_inactive_scope_but_token_omits_it(
    oauth_stack,
):
    context, provider, pool, _, router = oauth_stack
    provider.create_resource_server(
        context,
        {
            "Identifier": "logout-api",
            "Name": "Logout API",
            "Scopes": [{"ScopeDescription": "Read", "ScopeName": "read"}],
            "UserPoolId": pool["Id"],
        },
    )
    client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "logout-api/read"],
            "CallbackURLs": [CALLBACK],
            "ClientName": "logout-inactive-scope-client",
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    _, login, _ = _complete_login(router, client["ClientId"], scope="openid logout-api/read")
    provider.delete_resource_server(context, {"Identifier": "logout-api", "UserPoolId": pool["Id"]})

    response = router.dispatch(
        _request(
            "GET",
            "/logout",
            cookie=f"cognito_oauth_session={_cookies(login)['cognito_oauth_session']}",
            query=_authorize_query(client["ClientId"], scope="openid logout-api/read"),
        )
    )

    assert response.status_code == 302
    transaction_cookie = _cookies(response)["cognito_oauth_transaction"]
    login_form = router.dispatch(
        _request("GET", "/login", cookie=f"cognito_oauth_transaction={transaction_cookie}")
    )
    authenticated = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=f"cognito_oauth_transaction={transaction_cookie}",
            form={"csrf_token": _csrf(login_form), "password": PASSWORD, "username": "alice"},
        )
    )
    code = parse_qs(urlsplit(authenticated.headers["Location"]).query)["code"][0]
    tokens = _redeem(router, client["ClientId"], code)

    assert tokens.status_code == 200
    claims = decode_jwt_segment(tokens.json["access_token"].split(".")[1])
    assert claims["scope"] == "openid"


def test_login_capacity_failure_preserves_existing_code_and_transaction(oauth_stack, monkeypatch):
    context, _, _, client, router = oauth_stack
    existing_code, _, _ = _complete_login(router, client["ClientId"], state="existing-code")
    existing_digest = hashlib.sha256(existing_code.encode()).hexdigest()
    transaction_cookies, csrf, _ = _begin_login(
        router, client["ClientId"], state="capacity-failure"
    )
    transaction_digest = hashlib.sha256(
        transaction_cookies["cognito_oauth_transaction"].encode()
    ).hexdigest()
    monkeypatch.setattr(endpoints_module, "MAX_AUTHORIZATION_CODES_PER_POOL", 1)
    monkeypatch.setattr(endpoints_module, "MAX_BROWSER_SESSIONS_PER_STORE", 0)

    response = router.dispatch(
        _request(
            "POST",
            "/login",
            cookie=_cookie_header(transaction_cookies),
            form={"csrf_token": csrf, "password": PASSWORD, "username": "alice"},
        )
    )

    assert response.status_code == 503
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert existing_digest in store.authorization_codes
        assert transaction_digest in store.browser_transactions


def test_logout_capacity_failure_does_not_destroy_browser_session(oauth_stack, monkeypatch):
    context, provider, pool, _, router = oauth_stack
    client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid"],
            "CallbackURLs": [CALLBACK],
            "ClientName": "capacity-confidential-client",
            "GenerateSecret": True,
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    _, login, _ = _complete_login(router, client["ClientId"], scope="openid")
    session_token = _cookies(login)["cognito_oauth_session"]
    session_digest = hashlib.sha256(session_token.encode()).hexdigest()
    monkeypatch.setattr(endpoints_module, "MAX_BROWSER_TRANSACTIONS_PER_STORE", 0)

    response = router.dispatch(
        _request(
            "GET",
            "/logout",
            cookie=f"cognito_oauth_session={session_token}",
            query={
                "client_id": client["ClientId"],
                "redirect_uri": CALLBACK,
                "response_type": "code",
                "scope": "openid",
            },
        )
    )

    assert response.status_code == 503
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert session_digest not in store.browser_sessions
