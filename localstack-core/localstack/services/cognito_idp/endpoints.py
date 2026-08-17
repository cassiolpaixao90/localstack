"""Public HTTP endpoints for the native Cognito IDP provider.

Cognito JWTs deliberately keep the AWS-compatible issuer
``https://cognito-idp.<region>.amazonaws.com/<pool-id>``.  The public key is
served from the configured LocalStack endpoint instead, so a verifier must be
configured with this JWKS URL (or use a DNS/proxy rewrite).  Amplify clients
that derive the AWS hostname only from a user-pool ID cannot discover this
local endpoint without such an override.

JWKS is public, as it is in Cognito. The endpoint resolves the globally unique
pool ID through the store's cross-account index; it neither depends on SigV4
nor scans stores across accounts or regions.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import html
import json
import math
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote_plus, urlencode, urlsplit, urlunsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from rolo import Request, route

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.http import Response, Router
from localstack.services.cognito_idp.classic_ui import (
    ClassicUIError,
    classic_markup,
    inherited_customization,
    safe_image_path,
)
from localstack.services.cognito_idp.federation import (
    OidcFederationError,
    apple_form_claims,
    oidc_configuration,
    secure_json_request,
    social_claims,
    social_configuration,
    verify_id_token,
)
from localstack.services.cognito_idp.models import (
    AuthorizationCode,
    BrowserSession,
    BrowserTransaction,
    FederationTransaction,
    LoginAttemptWindow,
    PasswordHash,
    SamlReplay,
    cognito_idp_stores,
    resolve_domain_location,
    resolve_pool_location,
)
from localstack.services.cognito_idp.provider import (
    _MANAGED_LOGIN_DEFAULT_SETTINGS,
    CognitoIdpProvider,
    _active_oauth_scopes,
    _client_has_secret,
    _client_secret_matches,
    _decrypt_client_state,
    _deep_merge,
    _encrypt_client_state,
    _identity_provider_client_secret,
    _oauth_user_attributes,
    _partition_dns_suffix,
    _pool_guard,
    _readable_user_attributes,
)
from localstack.services.cognito_idp.replica_data_plane import (
    ReplicaDataPlaneError,
    resolve_regional_pool,
)
from localstack.services.cognito_idp.saml import (
    SamlFederationError,
    saml_authorization_location,
    validate_saml_response,
)
from localstack.services.cognito_idp.tokens import public_key_from_jwk

JWKS_CACHE_SECONDS = 300
MAX_JWKS_BYTES = 8 * 1024
MAX_BROWSER_TRANSACTIONS_PER_POOL = 256
MAX_AUTHORIZATION_CODES_PER_POOL = 512
MAX_BROWSER_SESSIONS_PER_POOL = 256
MAX_BROWSER_TRANSACTIONS_PER_STORE = 4096
MAX_AUTHORIZATION_CODES_PER_STORE = 8192
MAX_BROWSER_SESSIONS_PER_STORE = 4096
MAX_OAUTH_REQUEST_BYTES = 16 * 1024
MAX_ACCESS_TOKEN_BYTES = 16 * 1024
MAX_LOGIN_ATTEMPTS_PER_TRANSACTION = 5
MAX_LOGIN_ATTEMPTS_PER_USER_WINDOW = 10
MAX_LOGIN_ATTEMPTS_PER_SOURCE_WINDOW = 100
MAX_LOGIN_ATTEMPT_WINDOWS_PER_POOL = 512
MAX_LOGIN_ATTEMPT_WINDOWS_PER_STORE = 4096
MAX_FEDERATION_TRANSACTIONS_PER_POOL = 256
MAX_FEDERATION_TRANSACTIONS_PER_STORE = 4096
MAX_SAML_REPLAYS_PER_POOL = 4096
MAX_SAML_REPLAYS_PER_STORE = 16_384

_TRANSACTION_TTL = timedelta(minutes=10)
_FEDERATION_TRANSACTION_TTL = timedelta(minutes=5)
_AUTHORIZATION_CODE_TTL = timedelta(minutes=5)
_BROWSER_SESSION_TTL = timedelta(hours=1)
_LOGIN_ATTEMPT_WINDOW_TTL = timedelta(minutes=5)
_TRANSACTION_COOKIE = "cognito_oauth_transaction"
_SESSION_COOKIE = "cognito_oauth_session"
_LOCAL_DOMAIN_SUFFIX = ".localhost.localstack.cloud"
_DOMAIN_PREFIX_PATTERN = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_OAUTH_HOST = f"<regex('{_DOMAIN_PREFIX_PATTERN}'):domain>{_LOCAL_DOMAIN_SUFFIX}<port:port>"
_PKCE_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_PKCE_CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_PROVIDER = CognitoIdpProvider()
_DUMMY_PASSWORD = PasswordHash(
    algorithm="pbkdf2-sha256",
    iterations=310_000,
    salt="AAAAAAAAAAAAAAAAAAAAAA==",
    digest="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
)

_POOL_ID_PATTERN = r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]_[A-Za-z0-9]{1,64}"
_POOL_ID_RE = re.compile(r"^(?P<region>[a-z]{2}(?:-[a-z0-9]+)+-[0-9])_[A-Za-z0-9]{1,64}$")
_JWKS_ROUTE = f'/<regex("{_POOL_ID_PATTERN}"):pool_id>/.well-known/jwks.json'
_DISCOVERY_ROUTE = f'/<regex("{_POOL_ID_PATTERN}"):pool_id>/.well-known/openid-configuration'
_JWK_FIELDS = ("alg", "e", "kid", "kty", "n", "use")
_JWK_FIELD_LIMITS = {
    "alg": 16,
    "e": 32,
    "kid": 128,
    "kty": 16,
    "n": 4096,
    "use": 16,
}
_MANAGED_LOGIN_LANGUAGES = {
    "de": "german",
    "en": "english",
    "es": "spanish",
    "fr": "french",
    "id": "bahasa-indonesia",
    "it": "italian",
    "ja": "japanese",
    "ko": "korean",
    "nl": "dutch",
    "pt-BR": "portuguese-brazil",
    "zh-CN": "chinese-simplified",
    "zh-TW": "chinese-traditional",
}


class CognitoIdpJwksEndpoint:
    @route(_JWKS_ROUTE, methods=["GET"])
    def get_jwks(self, request: Request, pool_id: str) -> Response:
        region = _pool_region(pool_id)
        if region is None:
            return _not_found()

        with cognito_idp_stores.lock:
            identity = resolve_pool_location(pool_id)
            if identity is None:
                return _not_found()
            account_id, primary_region = identity
            if primary_region != region:
                return _not_found()
            region_stores = cognito_idp_stores.get(account_id)
            store = region_stores.get(primary_region) if region_stores is not None else None
            pool = store.user_pools.get(pool_id) if store is not None else None
            if pool is None:
                return _not_found()
            try:
                topology = store.user_pool_replicas.get(pool_id)
                serving_region = _regional_endpoint_region(request, pool, primary_region)
                if serving_region != primary_region:
                    if topology is None:
                        return _not_found()
                    view = resolve_regional_pool(
                        topology,
                        pool,
                        serving_region=serving_region,
                        operation="JWKS",
                        dns_suffix=_partition_dns_suffix(pool.arn.split(":", 2)[1]),
                    )
                    raw_keys = view.jwks()["keys"]
                else:
                    raw_keys = [pool.access_signing_jwk, pool.id_signing_jwk]
                payload = _serialize_jwks(raw_keys)
            except ReplicaDataPlaneError:
                return _not_found()
            except (TypeError, ValueError):
                return _internal_error()

        etag = hashlib.sha256(payload).hexdigest()
        if request.if_none_match.contains(etag):
            response = Response(status=304)
        else:
            response = Response(payload, status=200, mimetype="application/json")
        response.set_etag(etag)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Cache-Control"] = f"public, max-age={JWKS_CACHE_SECONDS}, must-revalidate"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @route(_DISCOVERY_ROUTE, methods=["GET"])
    def get_openid_configuration(self, request: Request, pool_id: str) -> Response:
        with cognito_idp_stores.lock:
            resolved = _resolve_pool(pool_id)
            if resolved is None:
                return _not_found()
            _, primary_region, store, pool = resolved
            serving_region = _regional_endpoint_region(request, pool, primary_region)
            if serving_region != primary_region:
                topology = store.user_pool_replicas.get(pool_id)
                if topology is None:
                    return _not_found()
                try:
                    resolve_regional_pool(
                        topology,
                        pool,
                        serving_region=serving_region,
                        operation="READ",
                        dns_suffix=_partition_dns_suffix(pool.arn.split(":", 2)[1]),
                    )
                except ReplicaDataPlaneError:
                    return _not_found()
            domains = [
                domain
                for domain in store.user_pool_domains.values()
                if domain.user_pool_id == pool.pool_id
            ]
            if len(domains) != 1:
                return _not_found()
            domain = domains[0]
            managed_base = _managed_base_url(request, domain.local_hostname)
            issuer = _pool_issuer(pool, serving_region)
            scopes = sorted(
                {
                    scope
                    for client in pool.clients.values()
                    for scope in client.allowed_oauth_scopes
                    if scope in _active_oauth_scopes(pool)
                }
            )
        document = {
            "authorization_endpoint": f"{managed_base}/oauth2/authorize",
            "id_token_signing_alg_values_supported": ["RS256"],
            "issuer": issuer,
            "jwks_uri": f"{managed_base}/{pool.pool_id}/.well-known/jwks.json",
            "response_types_supported": ["code", "token"],
            "revocation_endpoint": f"{managed_base}/oauth2/revoke",
            "scopes_supported": scopes,
            "subject_types_supported": ["public"],
            "token_endpoint": f"{managed_base}/oauth2/token",
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "userinfo_endpoint": f"{managed_base}/oauth2/userInfo",
        }
        return _public_json(document, cache_seconds=JWKS_CACHE_SECONDS)


class CognitoIdpOAuthEndpoint:
    @route("/oauth2/authorize", host=_OAUTH_HOST, methods=["GET"])
    def authorize(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        resolved = _resolve_domain(domain)
        if resolved is None:
            return _oauth_local_error(404, "invalid_request")
        account_id, region, store, managed_domain, pool = resolved
        if len(request.query_string) > MAX_OAUTH_REQUEST_BYTES or set(request.args) - {
            "client_id",
            "code_challenge",
            "code_challenge_method",
            "identity_provider",
            "idp_identifier",
            "lang",
            "login_hint",
            "nonce",
            "prompt",
            "redirect_uri",
            "response_type",
            "scope",
            "state",
        }:
            return _oauth_local_error(400, "invalid_request")

        client_id = _single_parameter(request.args, "client_id", maximum=128)
        redirect_uri = _single_parameter(request.args, "redirect_uri", maximum=1024)
        client = pool.clients.get(client_id) if client_id is not None else None
        if (
            client is None
            or not client.allowed_oauth_flows_user_pool_client
            or redirect_uri not in client.callback_urls
        ):
            return _oauth_local_error(400, "invalid_request")

        valid_state, state = _optional_parameter(request.args, "state", maximum=1024)
        if not valid_state or (state is not None and not _safe_opaque_value(state)):
            return _oauth_redirect_error(redirect_uri, "invalid_request", None)
        response_type = _single_parameter(request.args, "response_type", maximum=32)
        if response_type not in {"code", "token"}:
            return _oauth_redirect_error(redirect_uri, "unsupported_response_type", state)
        required_flow = "code" if response_type == "code" else "implicit"
        if required_flow not in client.allowed_oauth_flows:
            return _oauth_redirect_error(redirect_uri, "unauthorized_client", state)
        scopes = _scope_parameter(request.args, "scope")
        allowed_scopes = set(client.allowed_oauth_scopes)
        if scopes is None or not scopes or not set(scopes) <= allowed_scopes:
            return _oauth_redirect_error(redirect_uri, "invalid_scope", state)
        valid_nonce, nonce = _optional_parameter(request.args, "nonce", maximum=1024)
        if not valid_nonce or (nonce is not None and not _safe_opaque_value(nonce)):
            return _oauth_redirect_error(redirect_uri, "invalid_request", state)
        valid_prompt, prompt = _optional_parameter(request.args, "prompt", maximum=32)
        if not valid_prompt or prompt not in {None, "login", "none"}:
            return _oauth_redirect_error(redirect_uri, "invalid_request", state)
        valid_challenge, challenge = _optional_parameter(
            request.args, "code_challenge", maximum=128
        )
        valid_challenge_method, challenge_method = _optional_parameter(
            request.args, "code_challenge_method", maximum=16
        )
        if not valid_challenge or not valid_challenge_method:
            return _oauth_redirect_error(redirect_uri, "invalid_request", state)
        if response_type == "code":
            if (
                challenge is not None
                and (
                    challenge_method != "S256"
                    or _PKCE_CHALLENGE_PATTERN.fullmatch(challenge) is None
                )
            ) or (
                challenge is None
                and (challenge_method is not None or not _client_has_secret(client))
            ):
                return _oauth_redirect_error(redirect_uri, "invalid_request", state)
        elif challenge is not None or challenge_method is not None:
            return _oauth_redirect_error(redirect_uri, "invalid_request", state)

        try:
            selected_provider = _selected_identity_provider(request, pool, client)
        except ValueError:
            return _oauth_redirect_error(redirect_uri, "invalid_request", state)
        valid_login_hint, login_hint = _optional_parameter(request.args, "login_hint", maximum=256)
        if not valid_login_hint or (login_hint is not None and not _safe_opaque_value(login_hint)):
            return _oauth_redirect_error(redirect_uri, "invalid_request", state)
        valid_language, language = _optional_parameter(request.args, "lang", maximum=5)
        if not valid_language or language not in {None, *_MANAGED_LOGIN_LANGUAGES}:
            return _oauth_redirect_error(redirect_uri, "invalid_request", state)

        now = _now()
        if selected_provider is not None:
            with cognito_idp_stores.lock:
                federation_source = request.remote_addr or "unknown"
                if not _domain_binding_is_current(store, managed_domain, pool, client):
                    return _oauth_local_error(404, "invalid_request")
                if not _reserve_login_attempt(
                    store,
                    pool.pool_id,
                    f"federation:{selected_provider.provider_name}:{federation_source}",
                    federation_source,
                    now,
                ):
                    return _oauth_local_error(429, "too_many_requests")
        transaction_token = secrets.token_urlsafe(32)
        transaction_hash = _token_hash(transaction_token)
        if selected_provider is not None:
            try:
                federation_transaction, location = _prepare_external_federation(
                    request,
                    managed_domain,
                    pool,
                    client,
                    selected_provider,
                    transaction_hash,
                    login_hint=login_hint,
                    prompt=prompt,
                    now=now,
                )
            except OidcFederationError:
                return _oauth_redirect_error(redirect_uri, "temporarily_unavailable", state)
        else:
            federation_transaction = None
            location = "/login"
        with cognito_idp_stores.lock:
            if not _domain_binding_is_current(store, managed_domain, pool, client):
                return _oauth_local_error(404, "invalid_request")
            session = (
                None if prompt == "login" else _browser_session(request, store, pool.pool_id, now)
            )
            if selected_provider is not None:
                session = None
            if session is not None:
                if response_type == "token":
                    tokens = _issue_implicit_tokens(
                        account_id,
                        region,
                        store,
                        pool,
                        client,
                        session.username,
                        scopes,
                        nonce,
                    )
                    return _oauth_implicit_redirect(redirect_uri, tokens, state)
                try:
                    code = _store_authorization_code(
                        store,
                        pool.pool_id,
                        client.client_id,
                        redirect_uri,
                        session.username,
                        scopes,
                        nonce,
                        challenge or "",
                        now,
                    )
                except OverflowError:
                    return _oauth_local_error(503, "temporarily_unavailable")
                return _oauth_code_redirect(redirect_uri, code, state)
            if prompt == "none" and selected_provider is None:
                return _oauth_redirect_error(redirect_uri, "login_required", state)
            if not _prune_bounded(
                store.browser_transactions,
                MAX_BROWSER_TRANSACTIONS_PER_POOL,
                now,
                pool_id=pool.pool_id,
                store_limit=MAX_BROWSER_TRANSACTIONS_PER_STORE,
            ):
                return _oauth_local_error(503, "temporarily_unavailable")
            if federation_transaction is not None and not _prune_bounded(
                store.federation_transactions,
                MAX_FEDERATION_TRANSACTIONS_PER_POOL,
                now,
                pool_id=pool.pool_id,
                store_limit=MAX_FEDERATION_TRANSACTIONS_PER_STORE,
            ):
                return _oauth_local_error(503, "temporarily_unavailable")
            store.browser_transactions[transaction_hash] = BrowserTransaction(
                token_hash=transaction_hash,
                pool_id=managed_domain.user_pool_id,
                client_id=client.client_id,
                redirect_uri=redirect_uri,
                scopes=scopes,
                state=state,
                nonce=nonce,
                code_challenge=challenge or "",
                csrf_hash=None,
                created_at=now,
                expires_at=now + _TRANSACTION_TTL,
                response_type=response_type,
                language=language,
            )
            if federation_transaction is not None:
                store.federation_transactions[federation_transaction.token_hash] = (
                    federation_transaction
                )

        response = Response(status=302, headers={"Location": location})
        _set_secure_cookie(
            response,
            _TRANSACTION_COOKIE,
            transaction_token,
            max_age=int(_TRANSACTION_TTL.total_seconds()),
            secure=request.is_secure,
        )
        return _secure_no_store(response)

    @route("/login", host=_OAUTH_HOST, methods=["GET"])
    def login_form(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        if set(request.args) - {"identity_provider"}:
            return _oauth_local_error(400, "invalid_request")
        resolved = _resolve_domain(domain)
        if resolved is None:
            return _oauth_local_error(404, "invalid_request")
        _, _, store, managed_domain, pool = resolved
        transaction_hash = _cookie_hash(request, _TRANSACTION_COOKIE)
        now = _now()
        with cognito_idp_stores.lock:
            transaction = store.browser_transactions.get(transaction_hash)
            client = pool.clients.get(transaction.client_id) if transaction is not None else None
            if (
                not _domain_binding_is_current(store, managed_domain, pool)
                or transaction is None
                or client is None
                or transaction.pool_id != managed_domain.user_pool_id
                or transaction.expires_at <= now
            ):
                if transaction is not None and transaction.expires_at <= now:
                    store.browser_transactions.pop(transaction_hash, None)
                return _oauth_local_error(400, "invalid_request")
            provider_names = tuple(
                name
                for name in client.supported_identity_providers
                if name != "COGNITO"
                and (provider := pool.identity_providers.get(name)) is not None
                and provider.provider_type
                in {
                    "OIDC",
                    "SAML",
                    "Google",
                    "Facebook",
                    "LoginWithAmazon",
                    "SignInWithApple",
                }
            )
            selected_name = _single_parameter(request.args, "identity_provider", maximum=32)
            if "identity_provider" in request.args and selected_name not in provider_names:
                store.browser_transactions.pop(transaction_hash, None)
                return _federation_redirect_error(request, transaction, "invalid_request")
            selected_provider = (
                pool.identity_providers.get(selected_name) if selected_name is not None else None
            )
            if selected_provider is not None:
                federation_source = request.remote_addr or "unknown"
                if not _reserve_login_attempt(
                    store,
                    pool.pool_id,
                    f"federation:{selected_provider.provider_name}:{federation_source}",
                    federation_source,
                    now,
                ):
                    store.browser_transactions.pop(transaction_hash, None)
                    return _federation_redirect_error(
                        request, transaction, "temporarily_unavailable"
                    )
                provider_version = selected_provider.updated_at
            else:
                provider_version = None
            csrf_token = secrets.token_urlsafe(32)
            transaction.csrf_hash = _token_hash(csrf_token)
            transaction_language = transaction.language
            managed_login_version = managed_domain.managed_login_version
        presentation = _managed_login_presentation(
            pool,
            client,
            transaction_language,
            managed_login_version,
        )
        if selected_provider is None:
            return _login_page(
                csrf_token,
                provider_names=provider_names,
                show_cognito="COGNITO" in client.supported_identity_providers,
                presentation=presentation,
            )
        try:
            federation_transaction, location = _prepare_external_federation(
                request,
                managed_domain,
                pool,
                client,
                selected_provider,
                transaction_hash,
                login_hint=None,
                prompt=None,
                now=now,
            )
        except OidcFederationError:
            with cognito_idp_stores.lock:
                store.browser_transactions.pop(transaction_hash, None)
            return _federation_redirect_error(request, transaction, "temporarily_unavailable")
        with cognito_idp_stores.lock:
            current = store.browser_transactions.get(transaction_hash)
            current_provider = pool.identity_providers.get(selected_provider.provider_name)
            if (
                current is not transaction
                or current.expires_at <= _now()
                or current_provider is not selected_provider
                or current_provider.updated_at != provider_version
                or not _domain_binding_is_current(store, managed_domain, pool, client)
                or not _prune_bounded(
                    store.federation_transactions,
                    MAX_FEDERATION_TRANSACTIONS_PER_POOL,
                    now,
                    pool_id=pool.pool_id,
                    store_limit=MAX_FEDERATION_TRANSACTIONS_PER_STORE,
                )
            ):
                store.browser_transactions.pop(transaction_hash, None)
                return _federation_redirect_error(request, transaction, "temporarily_unavailable")
            store.federation_transactions[federation_transaction.token_hash] = (
                federation_transaction
            )
        return _secure_no_store(Response(status=302, headers={"Location": location}))

    @route("/signup", host=_OAUTH_HOST, methods=["GET"])
    def signup_form(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        if request.args:
            return _oauth_local_error(400, "invalid_request")
        resolved = _resolve_domain(domain)
        if resolved is None:
            return _oauth_local_error(404, "invalid_request")
        _, _, store, managed_domain, pool = resolved
        transaction_hash = _cookie_hash(request, _TRANSACTION_COOKIE)
        now = _now()
        with cognito_idp_stores.lock:
            transaction = store.browser_transactions.get(transaction_hash)
            client = pool.clients.get(transaction.client_id) if transaction else None
            if (
                not _domain_binding_is_current(store, managed_domain, pool, client)
                or transaction is None
                or client is None
                or transaction.expires_at <= now
                or pool.allow_admin_create_user_only
            ):
                return _oauth_local_error(400, "invalid_request")
            csrf_token = secrets.token_urlsafe(32)
            transaction.csrf_hash = _token_hash(csrf_token)
            transaction_language = transaction.language
            managed_login_version = managed_domain.managed_login_version
        presentation = _managed_login_presentation(
            pool,
            client,
            transaction_language,
            managed_login_version,
        )
        return _signup_page(csrf_token, presentation=presentation)

    @route(
        "/cognito-idp/classic-ui/<pool_id>/<client_id>/<version>/logo.<extension>",
        host=_OAUTH_HOST,
        methods=["GET"],
    )
    def classic_ui_image(
        self,
        request: Request,
        domain: str,
        pool_id: str,
        client_id: str,
        version: str,
        extension: str,
        port: int | None = None,
    ) -> Response:
        del port
        resolved = _resolve_domain(domain)
        if resolved is None:
            return _secure_no_store(Response(status=404))
        _, _, _, managed_domain, pool = resolved
        if pool.pool_id != pool_id or managed_domain.managed_login_version != 1:
            return _secure_no_store(Response(status=404))
        try:
            expected_path = safe_image_path(pool_id, client_id, version, extension)
        except ClassicUIError:
            return _secure_no_store(Response(status=404))
        with _pool_guard(pool.pool_id):
            item = pool.ui_customizations.get(client_id)
            if (
                item is None
                or item.image is None
                or item.image_extension != extension
                or item.css_version != version
                or item.image_url != expected_path
            ):
                return _secure_no_store(Response(status=404))
            content = bytes(item.image)
        etag = hashlib.sha256(content).hexdigest()
        if request.if_none_match.contains(etag):
            response = Response(status=304)
        else:
            response = Response(
                content,
                status=200,
                mimetype={"jpeg": "image/jpeg", "jpg": "image/jpeg", "png": "image/png"}[extension],
            )
        response.set_etag(etag)
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @route("/signup", host=_OAUTH_HOST, methods=["POST"])
    def signup(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        if not _valid_form_request(request) or any(
            name not in {"csrf_token", "email", "password", "username"}
            and re.fullmatch(r"attribute\.[A-Za-z0-9_:.-]{1,64}", name) is None
            for name in request.form
        ):
            return _oauth_local_error(400, "invalid_request")
        resolved = _resolve_domain(domain)
        if resolved is None:
            return _oauth_local_error(404, "invalid_request")
        account_id, region, store, managed_domain, pool = resolved
        transaction_hash = _cookie_hash(request, _TRANSACTION_COOKIE)
        csrf_token = _single_parameter(request.form, "csrf_token", maximum=128)
        supplied_username = _single_parameter(request.form, "username", maximum=128)
        password = _single_parameter(request.form, "password", maximum=256)
        email = _single_parameter(request.form, "email", maximum=2048)
        if None in {csrf_token, password, email}:
            return _oauth_local_error(400, "invalid_request")
        now = _now()
        with _pool_guard(pool.pool_id):
            with cognito_idp_stores.lock:
                transaction = store.browser_transactions.get(transaction_hash)
                client = pool.clients.get(transaction.client_id) if transaction else None
                signup_fields = _managed_login_signup_fields(pool)
                username_is_email = pool.username_attributes == ["email"]
                username = email if username_is_email else supplied_username
                expected_attribute_fields = {
                    f"attribute.{field['name']}": field for field in signup_fields
                }
                supplied_attribute_fields = {
                    name for name in request.form if name.startswith("attribute.")
                }
                if (
                    not _domain_binding_is_current(store, managed_domain, pool, client)
                    or transaction is None
                    or client is None
                    or username is None
                    or (username_is_email and supplied_username not in {None, email})
                    or supplied_attribute_fields - set(expected_attribute_fields)
                    or transaction.expires_at <= now
                    or transaction.csrf_hash is None
                    or not hmac.compare_digest(transaction.csrf_hash, _token_hash(csrf_token))
                    or pool.allow_admin_create_user_only
                    or not _reserve_login_attempt(
                        store,
                        pool.pool_id,
                        f"signup:{username}",
                        request.remote_addr or "unknown",
                        now,
                    )
                ):
                    return _oauth_local_error(400, "invalid_request")
                presentation = _managed_login_presentation(
                    pool,
                    client,
                    transaction.language,
                    managed_domain.managed_login_version,
                )
                # Claim the browser action before doing password hashing. A
                # concurrent replay cannot execute a second SignUp request.
                transaction.csrf_hash = None
                attributes = {"email": email}
                for form_name, field in expected_attribute_fields.items():
                    value = _single_parameter(request.form, form_name, maximum=2048)
                    if value is None:
                        if field["required"]:
                            transaction.csrf_hash = _token_hash(csrf_token)
                            return _oauth_local_error(400, "invalid_request")
                        continue
                    attributes[field["name"]] = value
                secret_hash = _managed_login_secret_hash(pool, client, username)
            try:
                signup_request = {
                    "ClientId": client.client_id,
                    "Password": password,
                    "UserAttributes": [
                        {"Name": name, "Value": value} for name, value in attributes.items()
                    ],
                    "Username": username,
                }
                if secret_hash is not None:
                    signup_request["SecretHash"] = secret_hash
                _PROVIDER.sign_up(
                    _oauth_context(account_id, region, pool.arn),
                    signup_request,
                )
            except CommonServiceException:
                with cognito_idp_stores.lock:
                    current = store.browser_transactions.get(transaction_hash)
                    if (
                        current is not transaction
                        or current.expires_at <= _now()
                        or not _domain_binding_is_current(store, managed_domain, pool, client)
                    ):
                        return _oauth_local_error(400, "invalid_request")
                    rotated_csrf = secrets.token_urlsafe(32)
                    current.csrf_hash = _token_hash(rotated_csrf)
                return _signup_page(rotated_csrf, status=400, error=True, presentation=presentation)
            with cognito_idp_stores.lock:
                if not _domain_binding_is_current(store, managed_domain, pool, client):
                    return _oauth_local_error(400, "invalid_request")
                confirmation_csrf = secrets.token_urlsafe(32)
                transaction.csrf_hash = _token_hash(confirmation_csrf)
                transaction.signup_username = username
        return _signup_complete_page(confirmation_csrf, presentation=presentation)

    @route("/confirm", host=_OAUTH_HOST, methods=["POST"])
    def confirm_signup(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        if not _valid_form_request(request) or set(request.form) - {
            "confirmation_code",
            "csrf_token",
        }:
            return _oauth_local_error(400, "invalid_request")
        resolved = _resolve_domain(domain)
        if resolved is None:
            return _oauth_local_error(404, "invalid_request")
        account_id, region, store, managed_domain, pool = resolved
        transaction_hash = _cookie_hash(request, _TRANSACTION_COOKIE)
        csrf_token = _single_parameter(request.form, "csrf_token", maximum=128)
        code = _single_parameter(request.form, "confirmation_code", maximum=2048)
        if csrf_token is None or code is None:
            return _oauth_local_error(400, "invalid_request")
        with _pool_guard(pool.pool_id):
            with cognito_idp_stores.lock:
                transaction = store.browser_transactions.get(transaction_hash)
                client = pool.clients.get(transaction.client_id) if transaction else None
                username = transaction.signup_username if transaction else None
                if (
                    not _domain_binding_is_current(store, managed_domain, pool, client)
                    or transaction is None
                    or client is None
                    or username is None
                    or transaction.expires_at <= _now()
                    or transaction.csrf_hash is None
                    or not hmac.compare_digest(transaction.csrf_hash, _token_hash(csrf_token))
                    or not _reserve_login_attempt(
                        store,
                        pool.pool_id,
                        f"confirm:{username}",
                        request.remote_addr or "unknown",
                        _now(),
                    )
                ):
                    return _oauth_local_error(400, "invalid_request")
                presentation = _managed_login_presentation(
                    pool,
                    client,
                    transaction.language,
                    managed_domain.managed_login_version,
                )
                transaction.csrf_hash = None
                secret_hash = _managed_login_secret_hash(pool, client, username)
            try:
                confirmation_request = {
                    "ClientId": client.client_id,
                    "ConfirmationCode": code,
                    "Username": username,
                }
                if secret_hash is not None:
                    confirmation_request["SecretHash"] = secret_hash
                _PROVIDER.confirm_sign_up(
                    _oauth_context(account_id, region, pool.arn),
                    confirmation_request,
                )
            except CommonServiceException:
                with cognito_idp_stores.lock:
                    current = store.browser_transactions.get(transaction_hash)
                    if current is not transaction or current.expires_at <= _now():
                        return _oauth_local_error(400, "invalid_request")
                    retry_csrf = secrets.token_urlsafe(32)
                    current.csrf_hash = _token_hash(retry_csrf)
                return _signup_complete_page(
                    retry_csrf,
                    status=400,
                    error=True,
                    presentation=presentation,
                )
            with cognito_idp_stores.lock:
                transaction.signup_username = None
                transaction.csrf_hash = None
        return _secure_no_store(Response(status=302, headers={"Location": "/login"}))

    @route("/login", host=_OAUTH_HOST, methods=["POST"])
    def login(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        if not _valid_form_request(request):
            return _oauth_local_error(400, "invalid_request")
        if not set(request.form) <= {"csrf_token", "password", "username"}:
            return _oauth_local_error(400, "invalid_request")
        resolved = _resolve_domain(domain)
        if resolved is None:
            return _oauth_local_error(404, "invalid_request")
        account_id, region, store, managed_domain, pool = resolved
        transaction_hash = _cookie_hash(request, _TRANSACTION_COOKIE)
        csrf_token = _single_parameter(request.form, "csrf_token", maximum=128)
        username = _single_parameter(request.form, "username", maximum=128)
        password = _single_parameter(request.form, "password", maximum=256)
        if csrf_token is None or username is None or password is None:
            return _oauth_local_error(400, "invalid_request")
        try:
            _PROVIDER._consume_provisioned_rate(
                _oauth_context(account_id, region, pool.arn), "ManagedLoginAuthentication"
            )
        except CommonServiceException as error:
            return _oauth_rate_error(error)

        now = _now()
        with cognito_idp_stores.lock:
            transaction = store.browser_transactions.get(transaction_hash)
            client = pool.clients.get(transaction.client_id) if transaction else None
            if (
                transaction is None
                or client is None
                or transaction.pool_id != managed_domain.user_pool_id
                or transaction.expires_at <= now
                or transaction.csrf_hash is None
                or not hmac.compare_digest(transaction.csrf_hash, _token_hash(csrf_token))
            ):
                return _oauth_local_error(400, "invalid_request")
            if not _reserve_login_attempt(
                store,
                pool.pool_id,
                username,
                request.remote_addr or "unknown",
                now,
            ):
                return _oauth_local_error(429, "too_many_requests")
            user = pool.users.get(username)

        password_hash = user.password if user is not None else _DUMMY_PASSWORD
        password_valid = password_hash.verify(password)
        if user is None or not password_valid or not user.enabled or user.status != "CONFIRMED":
            with cognito_idp_stores.lock:
                current = store.browser_transactions.get(transaction_hash)
                if (
                    not _domain_binding_is_current(store, managed_domain, pool)
                    or current is not transaction
                    or current.expires_at <= _now()
                    or current.csrf_hash is None
                    or not hmac.compare_digest(current.csrf_hash, _token_hash(csrf_token))
                ):
                    return _oauth_local_error(400, "invalid_request")
                current.failed_attempts += 1
                if current.failed_attempts >= MAX_LOGIN_ATTEMPTS_PER_TRANSACTION:
                    store.browser_transactions.pop(transaction_hash, None)
                    response = _oauth_local_error(429, "too_many_requests")
                    _set_secure_cookie(
                        response,
                        _TRANSACTION_COOKIE,
                        "",
                        max_age=0,
                        secure=request.is_secure,
                    )
                    return response
                rotated_csrf = secrets.token_urlsafe(32)
                current.csrf_hash = _token_hash(rotated_csrf)
            return _login_page(
                rotated_csrf,
                status=401,
                error=True,
                provider_names=tuple(
                    name
                    for name in client.supported_identity_providers
                    if name != "COGNITO" and name in pool.identity_providers
                ),
                show_cognito="COGNITO" in client.supported_identity_providers,
                presentation=_managed_login_presentation(
                    pool,
                    client,
                    transaction.language,
                    managed_domain.managed_login_version,
                ),
            )

        code_token = secrets.token_urlsafe(32)
        session_token = secrets.token_urlsafe(32)
        with cognito_idp_stores.lock:
            transaction = store.browser_transactions.get(transaction_hash)
            current_user = pool.users.get(username)
            if (
                not _domain_binding_is_current(store, managed_domain, pool)
                or transaction is None
                or transaction.expires_at <= _now()
                or transaction.csrf_hash is None
                or not hmac.compare_digest(transaction.csrf_hash, _token_hash(csrf_token))
                or current_user is not user
                or not user.enabled
                or user.status != "CONFIRMED"
            ):
                return _oauth_local_error(400, "invalid_request")
            store.login_attempt_windows.pop(_login_attempt_key(pool.pool_id, username), None)
            code_evictions = (
                _bounded_evictions(
                    store.authorization_codes,
                    MAX_AUTHORIZATION_CODES_PER_POOL,
                    now,
                    pool_id=pool.pool_id,
                    store_limit=MAX_AUTHORIZATION_CODES_PER_STORE,
                )
                if transaction.response_type == "code"
                else []
            )
            session_evictions = _bounded_evictions(
                store.browser_sessions,
                MAX_BROWSER_SESSIONS_PER_POOL,
                now,
                pool_id=pool.pool_id,
                store_limit=MAX_BROWSER_SESSIONS_PER_STORE,
            )
            if code_evictions is None or session_evictions is None:
                return _oauth_local_error(503, "temporarily_unavailable")
            _apply_evictions(store.authorization_codes, code_evictions)
            _apply_evictions(store.browser_sessions, session_evictions)
            if transaction.response_type == "code":
                try:
                    code = _store_authorization_code(
                        store,
                        transaction.pool_id,
                        transaction.client_id,
                        transaction.redirect_uri,
                        username,
                        transaction.scopes,
                        transaction.nonce,
                        transaction.code_challenge,
                        now,
                        token=code_token,
                    )
                except OverflowError:
                    return _oauth_local_error(503, "temporarily_unavailable")
                tokens = None
            else:
                client = pool.clients[transaction.client_id]
                tokens = _issue_implicit_tokens(
                    account_id,
                    region,
                    store,
                    pool,
                    client,
                    username,
                    transaction.scopes,
                    transaction.nonce,
                )
                code = None
            session_hash = _token_hash(session_token)
            store.browser_transactions.pop(transaction_hash, None)
            store.browser_sessions[session_hash] = BrowserSession(
                token_hash=session_hash,
                pool_id=pool.pool_id,
                username=username,
                created_at=now,
                expires_at=now + _BROWSER_SESSION_TTL,
            )
            redirect_uri = transaction.redirect_uri
            state = transaction.state

        response = (
            _oauth_code_redirect(redirect_uri, code, state)
            if code is not None
            else _oauth_implicit_redirect(redirect_uri, tokens, state)
        )
        _set_secure_cookie(
            response,
            _TRANSACTION_COOKIE,
            "",
            max_age=0,
            secure=request.is_secure,
        )
        _set_secure_cookie(
            response,
            _SESSION_COOKIE,
            session_token,
            max_age=int(_BROWSER_SESSION_TTL.total_seconds()),
            secure=request.is_secure,
        )
        return response

    @route("/oauth2/idpresponse", host=_OAUTH_HOST, methods=["GET", "POST"])
    def idp_response(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        if request.method == "POST":
            if not _valid_form_request(request):
                return _oauth_local_error(400, "invalid_request")
            parameters = request.form
        else:
            if len(request.query_string) > MAX_OAUTH_REQUEST_BYTES:
                return _oauth_local_error(400, "invalid_request")
            parameters = request.args
        if set(parameters) - {
            "code",
            "error",
            "error_description",
            "state",
            "user",
        }:
            return _oauth_local_error(400, "invalid_request")
        resolved = _resolve_domain(domain)
        state = _single_parameter(parameters, "state", maximum=256)
        if resolved is None or state is None:
            return _oauth_local_error(400, "invalid_request")
        account_id, region, store, managed_domain, pool = resolved
        try:
            _PROVIDER._consume_provisioned_rate(
                _oauth_context(account_id, region, pool.arn), "FederationCallback"
            )
        except CommonServiceException as error:
            return _oauth_rate_error(error)
        state_hash = _token_hash(state)
        browser_hash = _cookie_hash(request, _TRANSACTION_COOKIE)
        now = _now()
        with cognito_idp_stores.lock:
            federation = store.federation_transactions.pop(state_hash, None)
            transaction = (
                store.browser_transactions.get(federation.browser_transaction_hash)
                if federation is not None
                else None
            )
            provider = (
                pool.identity_providers.get(federation.provider_name)
                if federation is not None
                else None
            )
            client = pool.clients.get(federation.client_id) if federation is not None else None
            if (
                federation is None
                or transaction is None
                or provider is None
                or client is None
                or browser_hash != federation.browser_transaction_hash
                or federation.pool_id != pool.pool_id
                or federation.expires_at <= now
                or transaction.expires_at <= now
                or transaction.client_id != client.client_id
                or provider.provider_name not in client.supported_identity_providers
                or not _domain_binding_is_current(store, managed_domain, pool, client)
            ):
                return _oauth_local_error(400, "invalid_request")
            provider_version = provider.updated_at
            encrypted_verifier = federation.encrypted_code_verifier
            callback_uri = federation.redirect_uri
            browser_transaction_hash = federation.browser_transaction_hash
        if _single_parameter(parameters, "error", maximum=128) is not None:
            with cognito_idp_stores.lock:
                store.browser_transactions.pop(browser_transaction_hash, None)
            return _federation_redirect_error(request, transaction, "access_denied")
        code = _single_parameter(parameters, "code", maximum=4096)
        if code is None:
            with cognito_idp_stores.lock:
                store.browser_transactions.pop(browser_transaction_hash, None)
            return _federation_redirect_error(request, transaction, "invalid_request")
        try:
            verifier = _decrypt_client_state(
                pool,
                encrypted_verifier,
                f"federation-verifier:{state_hash}",
            )
            raw_apple_user = _single_parameter(parameters, "user", maximum=8192)
            if "user" in parameters and raw_apple_user is None:
                raise OidcFederationError("Invalid Apple user response")
            if provider.provider_type != "SignInWithApple" and raw_apple_user is not None:
                raise OidcFederationError("Unexpected social user response")
            if provider.provider_type == "OIDC":
                configuration = oidc_configuration(provider)
                token_response = secure_json_request(
                    configuration["token_endpoint"],
                    method="POST",
                    form={
                        "client_id": provider.provider_details["client_id"],
                        "client_secret": _identity_provider_client_secret(pool, provider),
                        "code": code,
                        "code_verifier": verifier,
                        "grant_type": "authorization_code",
                        "redirect_uri": callback_uri,
                    },
                )
                access_token = token_response.get("access_token")
                id_token = token_response.get("id_token")
                if (
                    not isinstance(access_token, str)
                    or not 1 <= len(access_token) <= MAX_ACCESS_TOKEN_BYTES
                    or not isinstance(id_token, str)
                ):
                    raise OidcFederationError("OIDC token response is incomplete")
                id_claims = verify_id_token(
                    id_token,
                    provider=provider,
                    configuration=configuration,
                    nonce_hash=federation.nonce_hash,
                    access_token=access_token,
                )
                user_info = secure_json_request(
                    configuration["userinfo_endpoint"], bearer_token=access_token
                )
                if user_info.get("sub") not in {None, id_claims["sub"]}:
                    raise OidcFederationError("OIDC userInfo subject mismatch")
                claims = {**user_info, **id_claims}
            else:
                claims = social_claims(
                    provider,
                    social_configuration(provider),
                    code=code,
                    code_verifier=verifier,
                    redirect_uri=callback_uri,
                    nonce_hash=federation.nonce_hash,
                    secret=_identity_provider_client_secret(pool, provider),
                )
                if provider.provider_type == "SignInWithApple":
                    claims = {**apple_form_claims(raw_apple_user), **claims}
        except (CommonServiceException, OidcFederationError):
            with cognito_idp_stores.lock:
                store.browser_transactions.pop(browser_transaction_hash, None)
            return _federation_redirect_error(request, transaction, "temporarily_unavailable")

        return _complete_federated_browser_sign_in(
            request,
            account_id=account_id,
            region=region,
            store=store,
            managed_domain=managed_domain,
            pool=pool,
            client=client,
            provider=provider,
            provider_version=provider_version,
            transaction=transaction,
            browser_transaction_hash=browser_transaction_hash,
            claims=claims,
            now=now,
        )

    @route("/saml2/idpresponse", host=_OAUTH_HOST, methods=["POST"])
    def saml_idp_response(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        if (
            request.mimetype != "application/x-www-form-urlencoded"
            or (request.content_length is not None and request.content_length > 128 * 1024)
            or len(request.get_data(cache=True)) > 128 * 1024
            or set(request.form) != {"RelayState", "SAMLResponse"}
        ):
            return _oauth_local_error(400, "invalid_request")
        resolved = _resolve_domain(domain)
        relay_state = _single_parameter(request.form, "RelayState", maximum=256)
        encoded_response = _single_parameter(request.form, "SAMLResponse", maximum=100_000)
        if resolved is None or relay_state is None or encoded_response is None:
            return _oauth_local_error(400, "invalid_request")
        account_id, region, store, managed_domain, pool = resolved
        try:
            _PROVIDER._consume_provisioned_rate(
                _oauth_context(account_id, region, pool.arn), "FederationCallback"
            )
        except CommonServiceException as error:
            return _oauth_rate_error(error)
        relay_hash = _token_hash(relay_state)
        browser_hash = _cookie_hash(request, _TRANSACTION_COOKIE)
        now = _now()
        with cognito_idp_stores.lock:
            federation = store.federation_transactions.pop(relay_hash, None)
            transaction = (
                store.browser_transactions.get(federation.browser_transaction_hash)
                if federation is not None
                else None
            )
            provider = (
                pool.identity_providers.get(federation.provider_name)
                if federation is not None
                else None
            )
            client = pool.clients.get(federation.client_id) if federation is not None else None
            if (
                federation is None
                or transaction is None
                or provider is None
                or provider.provider_type != "SAML"
                or client is None
                or browser_hash != federation.browser_transaction_hash
                or federation.pool_id != pool.pool_id
                or federation.expires_at <= now
                or transaction.expires_at <= now
                or transaction.client_id != client.client_id
                or provider.provider_name not in client.supported_identity_providers
                or not _domain_binding_is_current(store, managed_domain, pool, client)
            ):
                return _oauth_local_error(400, "invalid_request")
            provider_version = provider.updated_at
            browser_transaction_hash = federation.browser_transaction_hash
        try:
            claims, replay_hash, replay_expires_at = validate_saml_response(
                encoded_response,
                provider,
                pool_id=pool.pool_id,
                acs_url=federation.redirect_uri,
                request_id_hash=federation.nonce_hash,
                now=now,
                encryption_private_key=_identity_provider_client_secret(pool, provider),
            )
        except SamlFederationError:
            with cognito_idp_stores.lock:
                store.browser_transactions.pop(browser_transaction_hash, None)
            return _federation_redirect_error(request, transaction, "temporarily_unavailable")
        return _complete_federated_browser_sign_in(
            request,
            account_id=account_id,
            region=region,
            store=store,
            managed_domain=managed_domain,
            pool=pool,
            client=client,
            provider=provider,
            provider_version=provider_version,
            transaction=transaction,
            browser_transaction_hash=browser_transaction_hash,
            claims=claims,
            now=now,
            replay=(replay_hash, replay_expires_at),
        )

    @route("/oauth2/token", host=_OAUTH_HOST, methods=["OPTIONS"])
    def token_preflight(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        resolved = _resolve_domain(domain)
        origin = _normalize_origin(request.headers.get("Origin"))
        if resolved is None or origin is None:
            return _oauth_local_error(403, "invalid_request")
        _, _, _, _, pool = resolved
        if not any(
            client.allowed_oauth_flows_user_pool_client
            and origin in _client_allowed_origins(client)
            for client in pool.clients.values()
        ):
            return _oauth_local_error(403, "invalid_request")
        if request.headers.get("Access-Control-Request-Method") != "POST":
            return _oauth_local_error(403, "invalid_request")
        requested_headers = _preflight_headers(
            request.headers.get("Access-Control-Request-Headers")
        )
        if requested_headers is None:
            return _oauth_local_error(403, "invalid_request")
        response = Response(status=204)
        response.headers["Access-Control-Allow-Methods"] = "POST"
        if requested_headers:
            response.headers["Access-Control-Allow-Headers"] = ", ".join(requested_headers)
        response.headers["Access-Control-Max-Age"] = "600"
        return _cors_response(_secure_no_store(response), origin)

    @route("/oauth2/token", host=_OAUTH_HOST, methods=["POST"])
    def token(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        if not _valid_form_request(request):
            return _oauth_token_error("invalid_request")
        resolved = _resolve_domain(domain)
        if resolved is None:
            return _oauth_token_error("invalid_client", status=401)
        account_id, region, store, _, pool = resolved
        valid_credentials, client_id, client_secret = _client_credentials(request)
        if not valid_credentials:
            return _oauth_token_error("invalid_client", status=401)
        client = pool.clients.get(client_id) if client_id is not None else None
        if client is None or not client.allowed_oauth_flows_user_pool_client:
            return _oauth_token_error("invalid_client", status=401)
        cors_origin = _normalize_origin(request.headers.get("Origin"))
        if "Origin" in request.headers and (
            cors_origin is None or cors_origin not in _client_allowed_origins(client)
        ):
            return _oauth_local_error(403, "invalid_request")

        def finish(response: Response) -> Response:
            return _cors_response(response, cors_origin) if cors_origin is not None else response

        if not _client_secret_matches(pool, client, client_secret):
            return finish(_oauth_token_error("invalid_client", status=401))

        grant_type = _single_parameter(request.form, "grant_type", maximum=64)
        if grant_type == "authorization_code":
            if not set(request.form) <= {
                "client_id",
                "client_secret",
                "code",
                "code_verifier",
                "grant_type",
                "redirect_uri",
            }:
                return finish(_oauth_token_error("invalid_request"))
            result = self._authorization_code_grant(
                request, account_id, region, store, pool, client
            )
        elif grant_type == "refresh_token":
            if not set(request.form) <= {
                "client_id",
                "client_secret",
                "grant_type",
                "refresh_token",
                "scope",
            }:
                return finish(_oauth_token_error("invalid_request"))
            result = self._refresh_token_grant(
                request, account_id, region, pool, client, client_secret
            )
        else:
            return finish(_oauth_token_error("unsupported_grant_type"))
        if isinstance(result, Response):
            return finish(result)
        return finish(_oauth_token_response(result))

    def _authorization_code_grant(
        self, request, account_id, region, store, pool, client
    ) -> dict[str, Any] | Response:
        code_token = _single_parameter(request.form, "code", maximum=256)
        redirect_uri = _single_parameter(request.form, "redirect_uri", maximum=1024)
        valid_verifier, verifier = _optional_parameter(request.form, "code_verifier", maximum=128)
        if code_token is None or redirect_uri is None or not valid_verifier:
            return _oauth_token_error("invalid_request")
        code_hash = _token_hash(code_token)
        with cognito_idp_stores.lock:
            code = store.authorization_codes.pop(code_hash, None)
        if code is not None and code.code_challenge:
            expected_challenge = (
                base64_url_sha256(verifier)
                if verifier is not None and _PKCE_PATTERN.fullmatch(verifier)
                else None
            )
            verifier_valid = expected_challenge is not None and hmac.compare_digest(
                code.code_challenge, expected_challenge
            )
        else:
            verifier_valid = verifier is None
        if (
            code is None
            or code.expires_at <= _now()
            or code.pool_id != pool.pool_id
            or code.client_id != client.client_id
            or code.redirect_uri != redirect_uri
            or not verifier_valid
        ):
            return _oauth_token_error("invalid_grant")
        context = _oauth_context(account_id, region, pool.arn)
        try:
            return _PROVIDER.issue_oauth_tokens(
                context,
                code.pool_id,
                code.client_id,
                code.username,
                code.scopes,
                code.nonce,
            )
        except CommonServiceException:
            return _oauth_token_error("invalid_grant")

    def _refresh_token_grant(
        self, request, account_id, region, pool, client, client_secret
    ) -> dict[str, Any] | Response:
        refresh_token = _single_parameter(request.form, "refresh_token", maximum=4096)
        valid_scopes, requested_scopes = _optional_scope_parameter(request.form, "scope")
        if not valid_scopes:
            return _oauth_token_error("invalid_request")
        if refresh_token is None:
            return _oauth_token_error("invalid_request")
        context = _oauth_context(account_id, region, pool.arn)
        try:
            return _PROVIDER.refresh_oauth_tokens(
                context,
                pool.pool_id,
                client.client_id,
                refresh_token,
                requested_scopes,
                client_secret,
            )
        except CommonServiceException:
            return _oauth_token_error("invalid_grant")

    @route("/oauth2/userInfo", host=_OAUTH_HOST, methods=["GET", "POST"])
    def user_info(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        resolved = _resolve_domain(domain)
        token = _bearer_token(request)
        if resolved is None or token is None:
            return _userinfo_error()
        _, region, store, _, pool = resolved
        claims = _validate_access_token(token, pool, region, store)
        if claims is None:
            return _userinfo_error()
        client = pool.clients.get(claims["client_id"])
        user = pool.users.get(claims["username"])
        if client is None or user is None:
            return _userinfo_error()
        origin = _normalize_origin(request.headers.get("Origin"))
        if "Origin" in request.headers and (
            origin is None or origin not in _client_allowed_origins(client)
        ):
            return _oauth_local_error(403, "invalid_request")
        payload = {
            "sub": user.sub,
            "username": user.username,
            **_oauth_user_attributes(
                _readable_user_attributes(client, user),
                claims["scope"].split(" "),
            ),
        }
        response = _secure_no_store(
            Response(
                json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
                status=200,
                mimetype="application/json",
            )
        )
        return _cors_response(response, origin) if origin is not None else response

    @route("/oauth2/userInfo", host=_OAUTH_HOST, methods=["OPTIONS"])
    def user_info_preflight(
        self, request: Request, domain: str, port: int | None = None
    ) -> Response:
        del port
        return _managed_preflight(request, domain, {"GET", "POST"})

    @route("/oauth2/revoke", host=_OAUTH_HOST, methods=["POST"])
    def revoke(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        if not _valid_form_request(request) or not set(request.form) <= {
            "client_id",
            "client_secret",
            "token",
        }:
            return _oauth_token_error("invalid_request")
        resolved = _resolve_domain(domain)
        if resolved is None:
            return _oauth_token_error("invalid_client", status=401)
        _, _, store, _, pool = resolved
        valid_credentials, client_id, client_secret = _client_credentials(request)
        client = pool.clients.get(client_id) if valid_credentials and client_id else None
        if client is None:
            return _oauth_token_error("invalid_client", status=401)
        if not _client_secret_matches(pool, client, client_secret):
            return _oauth_token_error("invalid_client", status=401)
        if not client.enable_token_revocation:
            return _oauth_token_error("invalid_request")
        cors_origin = _normalize_origin(request.headers.get("Origin"))
        if "Origin" in request.headers and (
            cors_origin is None or cors_origin not in _client_allowed_origins(client)
        ):
            return _oauth_local_error(403, "invalid_request")
        token = _single_parameter(request.form, "token", maximum=4096)
        if token is None:
            return _oauth_token_error("invalid_request")
        with cognito_idp_stores.lock:
            session = store.refresh_sessions.get(_token_hash(token))
            if (
                session is not None
                and session.pool_id == pool.pool_id
                and session.client_id == client.client_id
            ):
                session.revoked = True
            elif _is_signed_pool_jwt(token, pool):
                return _oauth_token_error("unsupported_token_type")
        response = _secure_no_store(Response(status=200))
        return _cors_response(response, cors_origin) if cors_origin is not None else response

    @route("/oauth2/revoke", host=_OAUTH_HOST, methods=["OPTIONS"])
    def revoke_preflight(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        return _managed_preflight(request, domain, {"POST"})

    @route("/logout", host=_OAUTH_HOST, methods=["GET"])
    def logout(self, request: Request, domain: str, port: int | None = None) -> Response:
        del port
        if len(request.query_string) > MAX_OAUTH_REQUEST_BYTES or set(request.args) - {
            "client_id",
            "code_challenge",
            "code_challenge_method",
            "logout_uri",
            "nonce",
            "redirect_uri",
            "response_type",
            "scope",
            "state",
        }:
            return _oauth_local_error(400, "invalid_request")
        resolved = _resolve_domain(domain)
        client_id = _single_parameter(request.args, "client_id", maximum=128)
        valid_logout_uri, logout_uri = _optional_parameter(request.args, "logout_uri", maximum=1024)
        valid_redirect_uri, redirect_uri = _optional_parameter(
            request.args, "redirect_uri", maximum=1024
        )
        if (
            resolved is None
            or client_id is None
            or not valid_logout_uri
            or not valid_redirect_uri
            or (logout_uri is None and redirect_uri is None)
        ):
            return _oauth_local_error(400, "invalid_request")
        _, _, store, managed_domain, pool = resolved
        client = pool.clients.get(client_id)
        if client is None:
            return _oauth_local_error(400, "invalid_request")
        reauthenticate = logout_uri is None
        if not reauthenticate:
            if logout_uri not in client.logout_urls:
                return _oauth_local_error(400, "invalid_request")
            location = logout_uri
            transaction_token = None
        else:
            response_type = _single_parameter(request.args, "response_type", maximum=32)
            valid_state, state = _optional_parameter(request.args, "state", maximum=1024)
            valid_nonce, nonce = _optional_parameter(request.args, "nonce", maximum=1024)
            valid_scopes, scopes = _optional_scope_parameter(request.args, "scope")
            allowed_scopes = set(client.allowed_oauth_scopes)
            scopes = (
                [scope for scope in client.allowed_oauth_scopes if scope in allowed_scopes]
                if scopes is None
                else scopes
            )
            valid_challenge, challenge = _optional_parameter(
                request.args, "code_challenge", maximum=128
            )
            valid_challenge_method, challenge_method = _optional_parameter(
                request.args, "code_challenge_method", maximum=16
            )
            if (
                redirect_uri not in client.callback_urls
                or response_type not in {"code", "token"}
                or ("code" if response_type == "code" else "implicit")
                not in client.allowed_oauth_flows
                or not valid_state
                or not valid_nonce
                or not valid_scopes
                or not valid_challenge
                or not valid_challenge_method
                or not scopes
                or not set(scopes) <= allowed_scopes
                or (state is not None and not _safe_opaque_value(state))
                or (nonce is not None and not _safe_opaque_value(nonce))
                or (
                    challenge is not None
                    and (
                        challenge_method != "S256"
                        or _PKCE_CHALLENGE_PATTERN.fullmatch(challenge) is None
                    )
                )
                or (challenge is None and challenge_method is not None)
                or (
                    response_type == "code" and not _client_has_secret(client) and challenge is None
                )
                or (response_type == "token" and challenge is not None)
            ):
                return _oauth_local_error(400, "invalid_request")
            transaction_token = secrets.token_urlsafe(32)
            transaction_hash = _token_hash(transaction_token)
            reauthenticate_parameters = [
                ("client_id", client.client_id),
                ("redirect_uri", redirect_uri),
                ("response_type", response_type),
                ("scope", " ".join(scopes)),
            ]
            if state is not None:
                reauthenticate_parameters.append(("state", state))
            if nonce is not None:
                reauthenticate_parameters.append(("nonce", nonce))
            if challenge is not None:
                reauthenticate_parameters.extend(
                    [("code_challenge", challenge), ("code_challenge_method", "S256")]
                )
        session_hash = _cookie_hash(request, _SESSION_COOKIE)
        with cognito_idp_stores.lock:
            if not _domain_binding_is_current(store, managed_domain, pool, client):
                return _oauth_local_error(404, "invalid_request")
            if reauthenticate:
                transaction_evictions = _bounded_evictions(
                    store.browser_transactions,
                    MAX_BROWSER_TRANSACTIONS_PER_POOL,
                    _now(),
                    pool_id=pool.pool_id,
                    store_limit=MAX_BROWSER_TRANSACTIONS_PER_STORE,
                )
            session = store.browser_sessions.get(session_hash)
            if session is not None and session.pool_id == pool.pool_id:
                store.browser_sessions.pop(session_hash, None)
            if reauthenticate and transaction_evictions is None:
                response = _oauth_local_error(503, "temporarily_unavailable")
                _set_secure_cookie(
                    response,
                    _SESSION_COOKIE,
                    "",
                    max_age=0,
                    secure=request.is_secure,
                )
                return response
            if reauthenticate:
                _apply_evictions(store.browser_transactions, transaction_evictions)
            if reauthenticate:
                now = _now()
                store.browser_transactions[transaction_hash] = BrowserTransaction(
                    token_hash=transaction_hash,
                    pool_id=pool.pool_id,
                    client_id=client.client_id,
                    redirect_uri=redirect_uri,
                    scopes=scopes,
                    state=state,
                    nonce=nonce,
                    code_challenge=challenge or "",
                    csrf_hash=None,
                    created_at=now,
                    expires_at=now + _TRANSACTION_TTL,
                    response_type=response_type,
                )
                location = f"/login?{urlencode(reauthenticate_parameters)}"
        response = _secure_no_store(Response(status=302, headers={"Location": location}))
        _set_secure_cookie(
            response,
            _SESSION_COOKIE,
            "",
            max_age=0,
            secure=request.is_secure,
        )
        if transaction_token is not None:
            _set_secure_cookie(
                response,
                _TRANSACTION_COOKIE,
                transaction_token,
                max_age=int(_TRANSACTION_TTL.total_seconds()),
                secure=request.is_secure,
            )
        return response


def register_cognito_idp_jwks_endpoint(router: Router) -> list:
    """Register the endpoint and return its rules for lifecycle cleanup."""

    return router.add(CognitoIdpJwksEndpoint())


def register_cognito_idp_oauth_endpoint(router: Router) -> list:
    return router.add(CognitoIdpOAuthEndpoint())


def _resolve_domain(domain_name: str):
    hostname = f"{domain_name}{_LOCAL_DOMAIN_SUFFIX}"
    with cognito_idp_stores.lock:
        identity = resolve_domain_location(hostname)
        if identity is None:
            return None
        account_id, region = identity
        region_stores = cognito_idp_stores.get(account_id)
        store = region_stores.get(region) if region_stores is not None else None
        managed_domain = store.user_pool_domains.get(domain_name) if store is not None else None
        pool = (
            store.user_pools.get(managed_domain.user_pool_id)
            if store is not None and managed_domain is not None
            else None
        )
        if managed_domain is None or pool is None:
            return None
        return account_id, region, store, managed_domain, pool


def _resolve_pool(pool_id: str):
    region = _pool_region(pool_id)
    if region is None:
        return None
    with cognito_idp_stores.lock:
        location = resolve_pool_location(pool_id)
        if location is None or location[1] != region:
            return None
        account_id, region_name = location
        region_stores = cognito_idp_stores.get(account_id)
        store = region_stores.get(region_name) if region_stores is not None else None
        pool = store.user_pools.get(pool_id) if store is not None else None
        if pool is None:
            return None
        return account_id, region_name, store, pool


def _selected_identity_provider(request: Request, pool, client):
    valid_name, provider_name = _optional_parameter(request.args, "identity_provider", maximum=32)
    valid_identifier, identifier = _optional_parameter(request.args, "idp_identifier", maximum=40)
    if (
        not valid_name
        or not valid_identifier
        or (provider_name is not None and identifier is not None)
    ):
        raise ValueError("ambiguous identity provider")
    if provider_name in {None, "COGNITO"} and identifier is None:
        return None
    if identifier is not None:
        matches = [
            provider
            for provider in pool.identity_providers.values()
            if identifier in provider.idp_identifiers
        ]
        if len(matches) != 1:
            raise ValueError("unknown identity provider identifier")
        provider = matches[0]
    else:
        provider = pool.identity_providers.get(provider_name)
    if (
        provider is None
        or provider.provider_type
        not in {
            "OIDC",
            "SAML",
            "Google",
            "Facebook",
            "LoginWithAmazon",
            "SignInWithApple",
        }
        or provider.provider_name not in client.supported_identity_providers
    ):
        raise ValueError("identity provider is not enabled")
    return provider


def _prepare_external_federation(
    request: Request,
    managed_domain,
    pool,
    client,
    provider,
    browser_transaction_hash: str,
    *,
    login_hint: str | None,
    prompt: str | None,
    now: datetime,
) -> tuple[FederationTransaction, str]:
    if provider.provider_type == "SAML":
        return _prepare_saml_federation(
            request,
            managed_domain,
            pool,
            client,
            provider,
            browser_transaction_hash,
            now=now,
        )
    configuration = (
        oidc_configuration(provider)
        if provider.provider_type == "OIDC"
        else social_configuration(provider)
    )
    state = secrets.token_urlsafe(32)
    state_hash = _token_hash(state)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    callback_uri = f"{_managed_base_url(request, managed_domain.local_hostname)}/oauth2/idpresponse"
    parameters = [
        ("client_id", provider.provider_details["client_id"]),
        ("code_challenge", base64_url_sha256(verifier)),
        ("code_challenge_method", "S256"),
        ("nonce", nonce),
        ("redirect_uri", callback_uri),
        ("response_type", "code"),
        ("scope", provider.provider_details["authorize_scopes"]),
        ("state", state),
    ]
    if login_hint is not None:
        parameters.append(("login_hint", login_hint))
    if prompt is not None:
        parameters.append(("prompt", prompt))
    if provider.provider_type == "SignInWithApple":
        parameters.append(("response_mode", "form_post"))
    transaction = FederationTransaction(
        token_hash=state_hash,
        browser_transaction_hash=browser_transaction_hash,
        pool_id=pool.pool_id,
        client_id=client.client_id,
        provider_name=provider.provider_name,
        redirect_uri=callback_uri,
        encrypted_code_verifier=_encrypt_client_state(
            pool, verifier, f"federation-verifier:{state_hash}"
        ),
        nonce_hash=_token_hash(nonce),
        created_at=now,
        expires_at=now + _FEDERATION_TRANSACTION_TTL,
    )
    return transaction, _append_query(configuration["authorization_endpoint"], parameters)


def _prepare_saml_federation(
    request: Request,
    managed_domain,
    pool,
    client,
    provider,
    browser_transaction_hash: str,
    *,
    now: datetime,
) -> tuple[FederationTransaction, str]:
    relay_state = secrets.token_urlsafe(32)
    relay_hash = _token_hash(relay_state)
    request_id = f"_{secrets.token_urlsafe(24)}"
    acs_url = f"{_managed_base_url(request, managed_domain.local_hostname)}/saml2/idpresponse"
    transaction = FederationTransaction(
        token_hash=relay_hash,
        browser_transaction_hash=browser_transaction_hash,
        pool_id=pool.pool_id,
        client_id=client.client_id,
        provider_name=provider.provider_name,
        redirect_uri=acs_url,
        encrypted_code_verifier="",
        nonce_hash=_token_hash(request_id),
        created_at=now,
        expires_at=now + _FEDERATION_TRANSACTION_TTL,
    )
    location = saml_authorization_location(
        provider,
        pool,
        acs_url=acs_url,
        request_id=request_id,
        relay_state=relay_state,
        now=now,
    )
    return transaction, location


def _complete_federated_browser_sign_in(
    request: Request,
    *,
    account_id: str,
    region: str,
    store,
    managed_domain,
    pool,
    client,
    provider,
    provider_version: datetime,
    transaction: BrowserTransaction,
    browser_transaction_hash: str,
    claims: dict[str, Any],
    now: datetime,
    replay: tuple[str, datetime] | None = None,
) -> Response:
    session_token = secrets.token_urlsafe(32)
    with _pool_guard(pool.pool_id):
        with cognito_idp_stores.lock:
            current = store.browser_transactions.get(browser_transaction_hash)
            current_provider = pool.identity_providers.get(provider.provider_name)
            if (
                current is not transaction
                or current.expires_at <= _now()
                or current_provider is not provider
                or current_provider.updated_at != provider_version
                or not _domain_binding_is_current(store, managed_domain, pool, client)
            ):
                store.browser_transactions.pop(browser_transaction_hash, None)
                return _federation_redirect_error(request, transaction, "invalid_request")
            if replay is not None:
                for key, item in list(store.saml_replays.items()):
                    if item.expires_at <= now:
                        store.saml_replays.pop(key, None)
                replay_hash, replay_expires_at = replay
                pool_replays = sum(
                    item.pool_id == pool.pool_id for item in store.saml_replays.values()
                )
                if (
                    replay_hash in store.saml_replays
                    or pool_replays >= MAX_SAML_REPLAYS_PER_POOL
                    or len(store.saml_replays) >= MAX_SAML_REPLAYS_PER_STORE
                ):
                    store.browser_transactions.pop(browser_transaction_hash, None)
                    return _federation_redirect_error(
                        request, transaction, "temporarily_unavailable"
                    )
            code_evictions = (
                _bounded_evictions(
                    store.authorization_codes,
                    MAX_AUTHORIZATION_CODES_PER_POOL,
                    now,
                    pool_id=pool.pool_id,
                    store_limit=MAX_AUTHORIZATION_CODES_PER_STORE,
                )
                if transaction.response_type == "code"
                else []
            )
            session_evictions = _bounded_evictions(
                store.browser_sessions,
                MAX_BROWSER_SESSIONS_PER_POOL,
                now,
                pool_id=pool.pool_id,
                store_limit=MAX_BROWSER_SESSIONS_PER_STORE,
            )
            if code_evictions is None or session_evictions is None:
                store.browser_transactions.pop(browser_transaction_hash, None)
                return _federation_redirect_error(request, transaction, "temporarily_unavailable")
            user_before = {
                name: (
                    dict(user.attributes),
                    copy.deepcopy(user.federated_identities),
                    user.updated_at,
                )
                for name, user in pool.users.items()
            }
            pool_updated_before = pool.updated_at
            authorization_keys_before = set(store.authorization_codes)
            browser_session_keys_before = set(store.browser_sessions)
            evicted_authorization_codes = {
                key: store.authorization_codes[key]
                for key in code_evictions
                if key in store.authorization_codes
            }
            evicted_browser_sessions = {
                key: store.browser_sessions[key]
                for key in session_evictions
                if key in store.browser_sessions
            }
            try:
                username = _PROVIDER.federated_sign_in(
                    _oauth_context(account_id, region, pool.arn),
                    pool.pool_id,
                    client.client_id,
                    provider.provider_name,
                    claims,
                    provider_version=provider_version,
                )
                _apply_evictions(store.authorization_codes, code_evictions)
                _apply_evictions(store.browser_sessions, session_evictions)
                if transaction.response_type == "code":
                    code_token = _store_authorization_code(
                        store,
                        transaction.pool_id,
                        transaction.client_id,
                        transaction.redirect_uri,
                        username,
                        transaction.scopes,
                        transaction.nonce,
                        transaction.code_challenge,
                        now,
                    )
                    tokens = None
                else:
                    tokens = _issue_implicit_tokens(
                        account_id,
                        region,
                        store,
                        pool,
                        client,
                        username,
                        transaction.scopes,
                        transaction.nonce,
                    )
                    code_token = None
                store.browser_sessions[_token_hash(session_token)] = BrowserSession(
                    token_hash=_token_hash(session_token),
                    pool_id=pool.pool_id,
                    username=username,
                    created_at=now,
                    expires_at=now + _BROWSER_SESSION_TTL,
                )
                if replay is not None:
                    store.saml_replays[replay_hash] = SamlReplay(
                        token_hash=replay_hash,
                        pool_id=pool.pool_id,
                        expires_at=replay_expires_at,
                    )
            except (CommonServiceException, OverflowError):
                for key in set(store.authorization_codes) - authorization_keys_before:
                    store.authorization_codes.pop(key, None)
                store.authorization_codes.update(evicted_authorization_codes)
                for key in set(store.browser_sessions) - browser_session_keys_before:
                    store.browser_sessions.pop(key, None)
                store.browser_sessions.update(evicted_browser_sessions)
                if replay is not None:
                    store.saml_replays.pop(replay_hash, None)
                for name in set(pool.users) - set(user_before):
                    pool.users.pop(name, None)
                for name, (attributes, identities, updated_at) in user_before.items():
                    user = pool.users.get(name)
                    if user is not None:
                        user.attributes = attributes
                        user.federated_identities = identities
                        user.updated_at = updated_at
                pool.updated_at = pool_updated_before
                store.browser_transactions.pop(browser_transaction_hash, None)
                return _federation_redirect_error(request, transaction, "temporarily_unavailable")
            federation_source = request.remote_addr or "unknown"
            store.login_attempt_windows.pop(
                _login_attempt_key(
                    pool.pool_id,
                    f"federation:{provider.provider_name}:{federation_source}",
                ),
                None,
            )
            store.login_attempt_windows.pop(
                _login_source_key(pool.pool_id, federation_source), None
            )
            store.browser_transactions.pop(browser_transaction_hash, None)
    response = (
        _oauth_code_redirect(transaction.redirect_uri, code_token, transaction.state)
        if code_token is not None
        else _oauth_implicit_redirect(transaction.redirect_uri, tokens, transaction.state)
    )
    _set_secure_cookie(
        response,
        _TRANSACTION_COOKIE,
        "",
        max_age=0,
        secure=request.is_secure,
    )
    _set_secure_cookie(
        response,
        _SESSION_COOKIE,
        session_token,
        max_age=int(_BROWSER_SESSION_TTL.total_seconds()),
        secure=request.is_secure,
    )
    return response


def _federation_redirect_error(
    request: Request, transaction: BrowserTransaction, error: str
) -> Response:
    response = _oauth_redirect_error(transaction.redirect_uri, error, transaction.state)
    _set_secure_cookie(
        response,
        _TRANSACTION_COOKIE,
        "",
        max_age=0,
        secure=request.is_secure,
    )
    return response


def _domain_binding_is_current(store, domain, pool, client=None) -> bool:
    if (
        store.user_pool_domains.get(domain.domain) is not domain
        or store.user_pools.get(pool.pool_id) is not pool
        or domain.user_pool_id != pool.pool_id
        or store.DOMAIN_LOCATIONS.get(domain.local_hostname) != (domain.account_id, domain.region)
    ):
        return False
    return client is None or pool.clients.get(client.client_id) is client


def _managed_base_url(request: Request, hostname: str) -> str:
    raw_host = request.headers.get("Host")
    try:
        port = urlsplit(f"{request.scheme}://{raw_host}").port if raw_host else None
    except ValueError:
        port = None
    authority = hostname
    default_port = 443 if request.scheme == "https" else 80
    if port is not None and port != default_port:
        authority = f"{authority}:{port}"
    return f"{request.scheme}://{authority}"


def _pool_issuer(pool, region: str) -> str:
    partition = pool.arn.split(":", 2)[1]
    return f"https://cognito-idp.{region}.{_partition_dns_suffix(partition)}/{pool.pool_id}"


def _regional_endpoint_region(request: Request, pool, primary_region: str) -> str:
    raw_host = request.headers.get("Host")
    try:
        hostname = urlsplit(f"https://{raw_host}").hostname if raw_host else None
    except ValueError:
        return primary_region
    if not hostname:
        return primary_region
    partition = pool.arn.split(":", 2)[1]
    suffix = re.escape(_partition_dns_suffix(partition))
    match = re.fullmatch(rf"cognito-idp\.([a-z0-9-]+)\.{suffix}", hostname.lower())
    return match.group(1) if match else primary_region


def _public_json(value: dict[str, Any], *, cache_seconds: int) -> Response:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    response = Response(payload, status=200, mimetype="application/json")
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Cache-Control"] = f"public, max-age={cache_seconds}, must-revalidate"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _bearer_token(request: Request) -> str | None:
    authorization = request.headers.get("Authorization")
    if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
        return None
    token = authorization[7:]
    if not 1 <= len(token.encode("utf-8")) <= MAX_ACCESS_TOKEN_BYTES:
        return None
    return token


def _strict_json_object(payload: bytes) -> dict[str, Any]:
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if not isinstance(key, str) or key in result:
                raise ValueError("duplicate or invalid JSON key")
            result[key] = value
        return result

    value = json.loads(payload, object_pairs_hook=object_pairs)
    if not isinstance(value, dict):
        raise ValueError("JWT segment must be an object")
    return value


def _decode_jwt_part(value: str, *, maximum: int) -> tuple[dict[str, Any], bytes]:
    payload = _decode_b64url(value, maximum=maximum)
    return _strict_json_object(payload), payload


def _decode_b64url(value: str, *, maximum: int) -> bytes:
    if not value or len(value) > maximum or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid JWT encoding")
    payload = base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))
    if not payload or len(payload) > maximum:
        raise ValueError("invalid JWT segment size")
    return payload


def _validate_access_token(token: str, pool, region: str, store) -> dict[str, Any] | None:
    try:
        encoded_header, encoded_claims, encoded_signature = token.split(".")
        header, _ = _decode_jwt_part(encoded_header, maximum=2048)
        claims, _ = _decode_jwt_part(encoded_claims, maximum=12 * 1024)
        if set(header) != {"alg", "kid", "typ"} or header != {
            "alg": "RS256",
            "kid": pool.access_signing_key_id,
            "typ": "JWT",
        }:
            return None
        signature = _decode_b64url(encoded_signature, maximum=1024)
    except (UnicodeEncodeError, ValueError, json.JSONDecodeError):
        return None
    try:
        public_key_from_jwk(pool.access_signing_jwk).verify(
            signature,
            f"{encoded_header}.{encoded_claims}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return None

    string_fields = ("client_id", "iss", "origin_jti", "scope", "sub", "token_use", "username")
    if any(
        not isinstance(claims.get(field), str)
        or not 1 <= len(claims[field].encode("utf-8")) <= 4096
        for field in string_fields
    ):
        return None
    time_fields = ("auth_time", "exp", "iat")
    if any(
        not isinstance(claims.get(field), int) or isinstance(claims[field], bool)
        for field in time_fields
    ):
        return None
    now = int(_now().timestamp())
    if not claims["auth_time"] <= claims["iat"] <= now + 300 or claims["exp"] <= now:
        return None
    if claims["iss"] != _pool_issuer(pool, region) or claims["token_use"] != "access":
        return None
    scopes = claims["scope"].split(" ")
    if "openid" not in scopes or len(scopes) != len(set(scopes)):
        return None
    client = pool.clients.get(claims["client_id"])
    user = pool.users.get(claims["username"])
    if (
        client is None
        or user is None
        or not user.enabled
        or user.status not in {"CONFIRMED", "EXTERNAL_PROVIDER"}
        or claims["sub"] != user.sub
    ):
        return None
    with cognito_idp_stores.lock:
        session = next(
            (
                candidate
                for candidate in store.refresh_sessions.values()
                if candidate.origin_jti == claims["origin_jti"]
                and candidate.pool_id == pool.pool_id
                and candidate.client_id == client.client_id
                and candidate.username == user.username
            ),
            None,
        )
        if session is None or session.revoked or session.expires_at <= _now():
            return None
    return claims


def _is_signed_pool_jwt(token: str, pool) -> bool:
    try:
        encoded_header, encoded_claims, encoded_signature = token.split(".")
        header, _ = _decode_jwt_part(encoded_header, maximum=2048)
        if (
            set(header) != {"alg", "kid", "typ"}
            or header.get("alg") != "RS256"
            or header.get("typ") != "JWT"
        ):
            return False
        if header.get("kid") == pool.access_signing_key_id:
            jwk = pool.access_signing_jwk
        elif header.get("kid") == pool.id_signing_key_id:
            jwk = pool.id_signing_jwk
        else:
            return False
        _decode_jwt_part(encoded_claims, maximum=12 * 1024)
        signature = _decode_b64url(encoded_signature, maximum=1024)
        public_key_from_jwk(jwk).verify(
            signature,
            f"{encoded_header}.{encoded_claims}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


def _userinfo_error() -> Response:
    response = _oauth_token_error("invalid_token", status=401)
    response.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
    return response


def _single_parameter(parameters, key: str, *, maximum: int):
    values = parameters.getlist(key)
    if not values:
        return None
    if len(values) != 1:
        return None
    value = values[0]
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        return None
    return value


def _optional_parameter(parameters, key: str, *, maximum: int) -> tuple[bool, str | None]:
    if key not in parameters:
        return True, None
    value = _single_parameter(parameters, key, maximum=maximum)
    return value is not None, value


def _scope_parameter(parameters, key: str) -> list[str] | None:
    raw = _single_parameter(parameters, key, maximum=2048)
    if raw is None:
        return None
    scopes = raw.split(" ")
    if (
        not scopes
        or any(not scope or len(scope) > 256 for scope in scopes)
        or len(scopes) > 50
        or len(set(scopes)) != len(scopes)
    ):
        return None
    return scopes


def _optional_scope_parameter(parameters, key: str) -> tuple[bool, list[str] | None]:
    if key not in parameters:
        return True, None
    scopes = _scope_parameter(parameters, key)
    return scopes is not None, scopes


def _client_credentials(request: Request) -> tuple[bool, str | None, str | None]:
    authorization = request.headers.get("Authorization")
    if authorization is None:
        client_id = _single_parameter(request.form, "client_id", maximum=128)
        valid_secret, client_secret = _optional_parameter(
            request.form, "client_secret", maximum=256
        )
        return client_id is not None and valid_secret, client_id, client_secret
    if "client_id" in request.form or "client_secret" in request.form:
        return False, None, None
    if not authorization.startswith("Basic ") or len(authorization) > 1024:
        return False, None, None
    try:
        decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
        raw_client_id, raw_secret = decoded.split(":", 1)
        client_id = unquote_plus(raw_client_id)
        client_secret = unquote_plus(raw_secret)
    except (ValueError, UnicodeDecodeError):
        return False, None, None
    if not 1 <= len(client_id) <= 128 or not 1 <= len(client_secret) <= 256:
        return False, None, None
    return True, client_id, client_secret


def _normalize_origin(value: str | None) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 1024:
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return None
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    if port is not None and not (
        (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    return f"{parsed.scheme}://{host}"


def _client_allowed_origins(client) -> set[str]:
    return {
        origin
        for callback_url in client.callback_urls
        if (origin := _redirect_origin(callback_url)) is not None
    }


def _redirect_origin(callback_url: str) -> str | None:
    parsed = urlsplit(callback_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return _normalize_origin(origin)


def _preflight_headers(value: str | None) -> list[str] | None:
    if value is None or value == "":
        return []
    if len(value) > 1024:
        return None
    headers = [header.strip().lower() for header in value.split(",")]
    if (
        any(not header for header in headers)
        or len(set(headers)) != len(headers)
        or not set(headers) <= {"authorization", "content-type"}
    ):
        return None
    return headers


def _managed_preflight(request: Request, domain: str, methods: set[str]) -> Response:
    resolved = _resolve_domain(domain)
    origin = _normalize_origin(request.headers.get("Origin"))
    requested_method = request.headers.get("Access-Control-Request-Method")
    if resolved is None or origin is None or requested_method not in methods:
        return _oauth_local_error(403, "invalid_request")
    _, _, _, _, pool = resolved
    if not any(
        client.allowed_oauth_flows_user_pool_client and origin in _client_allowed_origins(client)
        for client in pool.clients.values()
    ):
        return _oauth_local_error(403, "invalid_request")
    requested_headers = _preflight_headers(request.headers.get("Access-Control-Request-Headers"))
    if requested_headers is None:
        return _oauth_local_error(403, "invalid_request")
    response = Response(status=204)
    response.headers["Access-Control-Allow-Methods"] = ", ".join(sorted(methods))
    if requested_headers:
        response.headers["Access-Control-Allow-Headers"] = ", ".join(requested_headers)
    response.headers["Access-Control-Max-Age"] = "600"
    return _cors_response(_secure_no_store(response), origin)


def _cors_response(response: Response, origin: str) -> Response:
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Vary"] = "Origin"
    return response


def _safe_opaque_value(value: str) -> bool:
    return all(ord(character) >= 0x20 and ord(character) != 0x7F for character in value)


def _cookie_hash(request: Request, name: str) -> str | None:
    token = request.cookies.get(name)
    if not isinstance(token, str) or not 20 <= len(token) <= 256:
        return None
    return _token_hash(token)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


def _prune_bounded(
    items: dict,
    pool_limit: int,
    now: datetime,
    *,
    pool_id: str,
    store_limit: int,
) -> bool:
    evictions = _bounded_evictions(
        items,
        pool_limit,
        now,
        pool_id=pool_id,
        store_limit=store_limit,
    )
    if evictions is None:
        return False
    _apply_evictions(items, evictions)
    return True


def _bounded_evictions(
    items: dict,
    pool_limit: int,
    now: datetime,
    *,
    pool_id: str,
    store_limit: int,
) -> list[str] | None:
    evictions = {key for key, item in items.items() if item.expires_at <= now}
    scoped_count = sum(
        1 for key, item in items.items() if key not in evictions and item.pool_id == pool_id
    )
    if scoped_count >= pool_limit:
        return None
    if len(items) - len(evictions) >= store_limit:
        return None
    return sorted(evictions)


def _apply_evictions(items: dict, evictions: list[str]) -> None:
    for key in evictions:
        items.pop(key, None)


def _login_attempt_key(pool_id: str, username: str) -> str:
    return hashlib.sha256(f"user\0{pool_id}\0{username}".encode()).hexdigest()


def _login_source_key(pool_id: str, source: str) -> str:
    if not isinstance(source, str) or not source or len(source) > 128:
        source = "unknown"
    return hashlib.sha256(f"source\0{pool_id}\0{source}".encode()).hexdigest()


def _reserve_login_attempt(store, pool_id: str, username: str, source: str, now: datetime) -> bool:
    windows = store.login_attempt_windows
    for key, window in list(windows.items()):
        if window.expires_at <= now:
            windows.pop(key, None)
    user_key = _login_attempt_key(pool_id, username)
    source_key = _login_source_key(pool_id, source)
    current_user = windows.get(user_key)
    current_source = windows.get(source_key)
    pool_windows = [window for window in windows.values() if window.pool_id == pool_id]
    if (
        current_user is not None and current_user.attempts >= MAX_LOGIN_ATTEMPTS_PER_USER_WINDOW
    ) or (
        current_source is not None
        and current_source.attempts >= MAX_LOGIN_ATTEMPTS_PER_SOURCE_WINDOW
    ):
        return False
    missing = int(current_user is None) + int(current_source is None)
    if (
        len(pool_windows) + missing > MAX_LOGIN_ATTEMPT_WINDOWS_PER_POOL
        or len(windows) + missing > MAX_LOGIN_ATTEMPT_WINDOWS_PER_STORE
    ):
        return False
    for key, current in ((user_key, current_user), (source_key, current_source)):
        if current is None:
            windows[key] = LoginAttemptWindow(
                key=key,
                pool_id=pool_id,
                attempts=1,
                expires_at=now + _LOGIN_ATTEMPT_WINDOW_TTL,
            )
        else:
            current.attempts += 1
    return True


def _browser_session(request: Request, store, pool_id: str, now: datetime):
    session_hash = _cookie_hash(request, _SESSION_COOKIE)
    if session_hash is None:
        return None
    session = store.browser_sessions.get(session_hash)
    if session is None:
        return None
    user = store.user_pools[pool_id].users.get(session.username)
    if (
        session.pool_id != pool_id
        or session.expires_at <= now
        or user is None
        or not user.enabled
        or user.status not in {"CONFIRMED", "EXTERNAL_PROVIDER"}
    ):
        store.browser_sessions.pop(session_hash, None)
        return None
    return session


def _store_authorization_code(
    store,
    pool_id: str,
    client_id: str,
    redirect_uri: str,
    username: str,
    scopes: list[str],
    nonce: str | None,
    code_challenge: str,
    now: datetime,
    *,
    token: str | None = None,
) -> str:
    token = secrets.token_urlsafe(32) if token is None else token
    token_hash = _token_hash(token)
    if not _prune_bounded(
        store.authorization_codes,
        MAX_AUTHORIZATION_CODES_PER_POOL,
        now,
        pool_id=pool_id,
        store_limit=MAX_AUTHORIZATION_CODES_PER_STORE,
    ):
        raise OverflowError("authorization-code store is full")
    store.authorization_codes[token_hash] = AuthorizationCode(
        token_hash=token_hash,
        pool_id=pool_id,
        client_id=client_id,
        redirect_uri=redirect_uri,
        username=username,
        scopes=list(scopes),
        nonce=nonce,
        created_at=now,
        expires_at=now + _AUTHORIZATION_CODE_TTL,
        code_challenge=code_challenge,
    )
    return token


def _oauth_code_redirect(redirect_uri: str, code: str, state: str | None) -> Response:
    parameters = [("code", code)]
    if state is not None:
        parameters.append(("state", state))
    response = Response(status=302, headers={"Location": _append_query(redirect_uri, parameters)})
    return _secure_no_store(response)


def _oauth_implicit_redirect(
    redirect_uri: str, result: dict[str, Any], state: str | None
) -> Response:
    parameters = [
        ("access_token", result["AccessToken"]),
        ("expires_in", str(result["ExpiresIn"])),
        ("id_token", result["IdToken"]),
        ("token_type", result["TokenType"]),
    ]
    if state is not None:
        parameters.append(("state", state))
    parsed = urlsplit(redirect_uri)
    response = Response(
        status=302,
        headers={
            "Location": urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.query, urlencode(parameters))
            )
        },
    )
    return _secure_no_store(response)


def _issue_implicit_tokens(
    account_id: str,
    region: str,
    store,
    pool,
    client,
    username: str,
    scopes: list[str],
    nonce: str | None,
) -> dict[str, Any]:
    user = pool.users.get(username)
    if (
        user is None
        or not user.enabled
        or user.status not in {"CONFIRMED", "EXTERNAL_PROVIDER"}
        or "implicit" not in client.allowed_oauth_flows
    ):
        raise CommonServiceException("NotAuthorizedException", "Invalid OAuth session")
    result = _PROVIDER._authentication_result(
        _oauth_context(account_id, region, pool.arn),
        pool,
        client,
        user,
        include_refresh=False,
        scopes=scopes,
        nonce=nonce,
        filter_oauth_attributes=True,
    )
    if "RefreshToken" in result:
        store.refresh_sessions.pop(_token_hash(result.pop("RefreshToken")), None)
    return result


def _oauth_redirect_error(redirect_uri: str, error: str, state: str | None) -> Response:
    parameters = [("error", error)]
    if state is not None:
        parameters.append(("state", state))
    response = Response(status=302, headers={"Location": _append_query(redirect_uri, parameters)})
    return _secure_no_store(response)


def _append_query(uri: str, parameters: list[tuple[str, str]]) -> str:
    parsed = urlsplit(uri)
    query = f"{parsed.query}&{urlencode(parameters)}" if parsed.query else urlencode(parameters)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def _oauth_local_error(status: int, error: str) -> Response:
    return _oauth_token_error(error, status=status)


def _oauth_rate_error(error: CommonServiceException) -> Response:
    response = _oauth_local_error(429, "too_many_requests")
    retry_after = getattr(error, "retry_after_seconds", None)
    if (
        isinstance(retry_after, (int, float))
        and not isinstance(retry_after, bool)
        and math.isfinite(retry_after)
        and retry_after > 0
    ):
        response.headers["Retry-After"] = str(min(2**31 - 1, max(1, math.ceil(retry_after))))
    return response


def _oauth_token_error(error: str, *, status: int = 400) -> Response:
    payload = json.dumps({"error": error}, separators=(",", ":")).encode()
    return _secure_no_store(Response(payload, status=status, mimetype="application/json"))


def _oauth_token_response(result: dict[str, Any]) -> Response:
    payload = {
        "access_token": result["AccessToken"],
        "expires_in": result["ExpiresIn"],
        "id_token": result["IdToken"],
        "token_type": result["TokenType"],
    }
    if "RefreshToken" in result:
        payload["refresh_token"] = result["RefreshToken"]
    response = Response(
        json.dumps(payload, separators=(",", ":")).encode(),
        status=200,
        mimetype="application/json",
    )
    return _secure_no_store(response)


def _secure_no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _set_secure_cookie(
    response: Response, name: str, value: str, *, max_age: int, secure: bool
) -> None:
    """Use Secure under TLS; plain HTTP is supported only as an insecure local-dev mode."""

    response.set_cookie(
        name,
        value,
        max_age=max_age,
        path="/",
        secure=secure,
        httponly=True,
        samesite="Lax",
    )


def _valid_form_request(request: Request) -> bool:
    if request.mimetype != "application/x-www-form-urlencoded":
        return False
    if request.content_length is not None and request.content_length > MAX_OAUTH_REQUEST_BYTES:
        return False
    return len(request.get_data(cache=True)) <= MAX_OAUTH_REQUEST_BYTES


def _login_page(
    csrf_token: str,
    *,
    status: int = 200,
    error: bool = False,
    provider_names: tuple[str, ...] = (),
    show_cognito: bool = True,
    presentation: dict[str, Any] | None = None,
) -> Response:
    escaped_csrf = html.escape(csrf_token, quote=True)
    error_html = (
        '<p class="error" role="alert">Incorrect username or password.</p>' if error else ""
    )
    provider_html = "".join(
        '<a class="provider" href="/login?'
        f'{urlencode({"identity_provider": provider_name})}">Continue with '
        f"{html.escape(provider_name)}</a>"
        for provider_name in provider_names
    )
    password_form = (
        f'''<form method="post" action="/login">
<input type="hidden" name="csrf_token" value="{escaped_csrf}"><label for="username">Username</label>
<input id="username" name="username" autocomplete="username" maxlength="128" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" maxlength="256" required>
<button type="submit">Sign in</button></form>'''
        if show_cognito
        else ""
    )
    signup_link = (
        '<p class="signup"><a href="/signup">Create an account</a></p>'
        if (presentation or {}).get("signup_enabled", True)
        else ""
    )
    return _managed_login_page(
        f"<h1>Sign in</h1>{error_html}{password_form}{provider_html}{signup_link}",
        title="Sign in",
        status=status,
        presentation=presentation,
    )


def _signup_page(
    csrf_token: str,
    *,
    status: int = 200,
    error: bool = False,
    presentation: dict[str, Any] | None = None,
) -> Response:
    escaped_csrf = html.escape(csrf_token, quote=True)
    error_html = '<p class="error" role="alert">Unable to create the account.</p>' if error else ""
    terms = (presentation or {}).get("terms") or {}
    signup_fields = (presentation or {}).get("signup_fields") or []
    username_is_email = (presentation or {}).get("username_is_email") is True
    terms_html = ""
    if set(terms) == {"privacy-policy", "terms-of-use"}:
        terms_url = html.escape(terms["terms-of-use"], quote=True)
        privacy_url = html.escape(terms["privacy-policy"], quote=True)
        terms_html = (
            '<p class="terms">By signing up, you agree to our '
            f'<a href="{terms_url}" rel="noopener noreferrer" target="_blank">Terms of use</a> '
            "and "
            f'<a href="{privacy_url}" rel="noopener noreferrer" target="_blank">Privacy policy</a>.</p>'
        )
    username_html = (
        ""
        if username_is_email
        else (
            '<label for="signup-username">Username</label>'
            '<input id="signup-username" name="username" autocomplete="username" maxlength="128" required>'
        )
    )
    attribute_html = "".join(
        f'<label for="signup-attribute-{index}">{html.escape(field["label"])}</label>'
        f'<input id="signup-attribute-{index}" name="attribute.{html.escape(field["name"], quote=True)}" '
        f'type="{field["input_type"]}" maxlength="2048" required>'
        for index, field in enumerate(signup_fields)
    )
    content = f'''<h1>Create account</h1>{error_html}<form method="post" action="/signup">
<input type="hidden" name="csrf_token" value="{escaped_csrf}">{username_html}
<label for="signup-email">Email</label><input id="signup-email" name="email" type="email" autocomplete="email" maxlength="2048" required>
{attribute_html}
<label for="signup-password">Password</label><input id="signup-password" name="password" type="password" autocomplete="new-password" maxlength="256" required>
{terms_html}<button type="submit">Create account</button></form><p class="signup"><a href="/login">Back to sign in</a></p>'''
    return _managed_login_page(
        content,
        title="Create account",
        status=status,
        presentation=presentation,
    )


def _signup_complete_page(
    csrf_token: str,
    *,
    status: int = 200,
    error: bool = False,
    presentation: dict[str, Any] | None = None,
) -> Response:
    escaped_csrf = html.escape(csrf_token, quote=True)
    error_html = (
        '<p class="error" role="alert">Invalid or expired confirmation code.</p>' if error else ""
    )
    return _managed_login_page(
        f'''<h1>Check your email</h1>{error_html}<p>Your account was created. Enter the confirmation code sent to you.</p>
<form method="post" action="/confirm"><input type="hidden" name="csrf_token" value="{escaped_csrf}">
<label for="confirmation-code">Confirmation code</label><input id="confirmation-code" name="confirmation_code" inputmode="numeric" autocomplete="one-time-code" maxlength="2048" required>
<button type="submit">Confirm account</button></form><p class="signup"><a href="/login">Back to sign in</a></p>''',
        title="Confirm account",
        status=status,
        presentation=presentation,
    )


def _managed_login_presentation(
    pool, client, language: str | None, managed_login_version: int
) -> dict[str, Any]:
    with _pool_guard(pool.pool_id):
        settings = copy.deepcopy(_MANAGED_LOGIN_DEFAULT_SETTINGS)
        assets = []
        if (
            managed_login_version == 2
            and (branding := pool.managed_login_branding.get(client.client_id)) is not None
        ):
            settings = _deep_merge(settings, copy.deepcopy(branding.settings))
            assets = [copy.deepcopy(asset) for asset in list(branding.assets.values())]
        terms_by_name = (
            {
                item.terms_name: copy.deepcopy(item)
                for item in list(pool.terms.values())
                if item.client_id == client.client_id
            }
            if managed_login_version == 2
            else {}
        )
        signup_enabled = not pool.allow_admin_create_user_only
        username_is_email = pool.username_attributes == ["email"]
        signup_fields = _managed_login_signup_fields(pool)
        classic_customization = (
            inherited_customization(pool.ui_customizations, client.client_id)
            if managed_login_version == 1
            else None
        )
    rendered_terms = {}
    if set(terms_by_name) == {"privacy-policy", "terms-of-use"}:
        language_key = (
            f"cognito:{_MANAGED_LOGIN_LANGUAGES[language]}"
            if language in _MANAGED_LOGIN_LANGUAGES
            else "cognito:default"
        )
        for name, item in terms_by_name.items():
            link = item.links.get(language_key) or item.links.get("cognito:default")
            if link is None:
                rendered_terms = {}
                break
            rendered_terms[name] = link
    return {
        "assets": assets,
        "classic_customization": classic_customization,
        "managed_login_version": managed_login_version,
        "settings": settings,
        "signup_enabled": signup_enabled,
        "signup_fields": signup_fields,
        "terms": rendered_terms,
        "username_is_email": username_is_email,
    }


def _managed_login_signup_fields(pool) -> list[dict[str, Any]]:
    fields = []
    for definition in pool.schema_attributes or []:
        if definition.get("Required") is not True:
            continue
        name = definition.get("Name")
        if not isinstance(name, str) or name in {"email", "sub"}:
            continue
        if not name.startswith(("custom:", "dev:")) and name not in {
            "address",
            "birthdate",
            "family_name",
            "gender",
            "given_name",
            "locale",
            "middle_name",
            "name",
            "nickname",
            "phone_number",
            "picture",
            "preferred_username",
            "profile",
            "updated_at",
            "website",
            "zoneinfo",
        }:
            name = f"custom:{name}"
        if name.startswith("dev:"):
            continue
        fields.append(
            {
                "input_type": "tel" if name == "phone_number" else "text",
                "label": name.replace("custom:", "").replace("_", " ").title(),
                "name": name,
                "required": True,
            }
        )
    return sorted(fields, key=lambda field: field["name"])


def _managed_login_secret_hash(pool, client, username: str) -> str | None:
    secret = client.secret
    if client.primary_secret is not None:
        descriptor = client.primary_secret
        secret = _decrypt_client_state(
            pool,
            descriptor.encrypted_value,
            f"client-secret:{client.client_id}:{descriptor.secret_id}",
        )
    if secret is None:
        return None
    digest = hmac.new(
        secret.encode(), f"{username}{client.client_id}".encode(), hashlib.sha256
    ).digest()
    return base64.b64encode(digest).decode()


def _managed_login_page(
    content: str,
    *,
    title: str,
    status: int,
    presentation: dict[str, Any] | None,
) -> Response:
    presentation = presentation or {
        "assets": [],
        "settings": copy.deepcopy(_MANAGED_LOGIN_DEFAULT_SETTINGS),
    }
    settings = presentation.get("settings") or _MANAGED_LOGIN_DEFAULT_SETTINGS
    scheme = _nested(settings, "categories", "global", "colorSchemeMode")
    mode = "darkMode" if scheme == "DARK" else "lightMode"
    page_color = _css_color(
        _nested(settings, "componentClasses", "pageBackground", mode, "color"),
        "#f6f7f9",
    )
    form_color = _css_color(
        _nested(settings, "componentClasses", "form", mode, "backgroundColor"),
        "#ffffff",
    )
    form_border = _css_color(
        _nested(settings, "componentClasses", "form", mode, "borderColor"),
        "#d9dde3",
    )
    button_color = _css_color(
        _nested(
            settings,
            "componentClasses",
            "primaryButton",
            mode,
            "defaults",
            "backgroundColor",
        ),
        "#146dd6",
    )
    button_text = _css_color(
        _nested(
            settings,
            "componentClasses",
            "primaryButton",
            mode,
            "defaults",
            "textColor",
        ),
        "#ffffff",
    )
    form_radius = _css_radius(_nested(settings, "componentClasses", "form", "borderRadius"), 12)
    button_radius = _css_radius(_nested(settings, "componentClasses", "buttons", "borderRadius"), 7)
    input_radius = _css_radius(_nested(settings, "componentClasses", "input", "borderRadius"), 7)
    horizontal = _nested(settings, "categories", "form", "location", "horizontal")
    vertical = _nested(settings, "categories", "form", "location", "vertical")
    margin_left, margin_right = {
        "LEFT": ("1.5rem", "auto"),
        "RIGHT": ("auto", "1.5rem"),
    }.get(horizontal, ("auto", "auto"))
    margin_top, margin_bottom = {
        "TOP": ("1.5rem", "auto"),
        "BOTTOM": ("auto", "1.5rem"),
    }.get(vertical, ("auto", "auto"))
    main_margin = f"{margin_top} {margin_right} {margin_bottom} {margin_left}"
    spacing = _nested(settings, "categories", "global", "spacingDensity")
    form_padding, field_margin, heading_margin = {
        "COMPACT": ("1.25rem", ".55rem", "1rem"),
        "SPACIOUS": ("2.75rem", "1.25rem", "2rem"),
    }.get(spacing, ("2rem", ".9rem", "1.5rem"))
    assets = presentation.get("assets") or []
    page_image_enabled = (
        _nested(settings, "componentClasses", "pageBackground", "image", "enabled") is not False
    )
    logo_enabled = _nested(settings, "componentClasses", "form", "logo", "enabled") is True
    form_image_enabled = (
        _nested(settings, "componentClasses", "form", "backgroundImage", "enabled") is True
    )
    page_background = (
        _asset_data_uri(_select_asset(assets, "PAGE_BACKGROUND", scheme))
        if page_image_enabled
        else None
    )
    form_background = (
        _asset_data_uri(_select_asset(assets, "FORM_BACKGROUND", scheme))
        if form_image_enabled
        else None
    )
    form_logo = (
        _asset_data_uri(_select_asset(assets, "FORM_LOGO", scheme)) if logo_enabled else None
    )
    favicon = _asset_data_uri(
        _select_asset(assets, "FAVICON_SVG", scheme) or _select_asset(assets, "FAVICON_ICO", scheme)
    )
    header_enabled = _nested(settings, "categories", "global", "pageHeader", "enabled") is True
    footer_enabled = _nested(settings, "categories", "global", "pageFooter", "enabled") is True
    header_logo = _asset_data_uri(_select_asset(assets, "PAGE_HEADER_LOGO", scheme))
    header_background = _asset_data_uri(_select_asset(assets, "PAGE_HEADER_BACKGROUND", scheme))
    footer_logo = _asset_data_uri(_select_asset(assets, "PAGE_FOOTER_LOGO", scheme))
    footer_background = _asset_data_uri(_select_asset(assets, "PAGE_FOOTER_BACKGROUND", scheme))
    background_css = (
        f'background-image:url("{page_background}");background-size:cover;'
        if page_background
        else ""
    )
    form_background_css = (
        f'background-image:url("{form_background}");background-size:cover;'
        if form_background
        else ""
    )
    adaptive_css = ""
    if scheme == "DYNAMIC":
        dark_page = _css_color(
            _nested(settings, "componentClasses", "pageBackground", "darkMode", "color"),
            page_color,
        )
        dark_form = _css_color(
            _nested(settings, "componentClasses", "form", "darkMode", "backgroundColor"),
            form_color,
        )
        dark_border = _css_color(
            _nested(settings, "componentClasses", "form", "darkMode", "borderColor"),
            form_border,
        )
        dark_button = _css_color(
            _nested(
                settings,
                "componentClasses",
                "primaryButton",
                "darkMode",
                "defaults",
                "backgroundColor",
            ),
            button_color,
        )
        dark_text = _css_color(
            _nested(
                settings,
                "componentClasses",
                "primaryButton",
                "darkMode",
                "defaults",
                "textColor",
            ),
            button_text,
        )
        dark_page_image = (
            _asset_data_uri(_select_asset(assets, "PAGE_BACKGROUND", "DARK"))
            if page_image_enabled
            else None
        )
        dark_image_css = (
            f'background-image:url("{dark_page_image}");background-size:cover;'
            if dark_page_image
            else ""
        )
        adaptive_css = (
            "@media (prefers-color-scheme:dark){"
            f"body{{background:{dark_page};{dark_image_css}}}"
            f"main{{background-color:{dark_form};border-color:{dark_border}}}"
            f"button{{background:{dark_button};color:{dark_text}}}"
            f".provider{{border-color:{dark_button};color:{dark_button}}}"
            "}"
        )
    favicon_html = f'<link rel="icon" href="{html.escape(favicon, quote=True)}">' if favicon else ""
    logo_html = (
        f'<img class="form-logo" alt="" src="{html.escape(form_logo, quote=True)}">'
        if form_logo
        else ""
    )
    logo_position = _nested(settings, "componentClasses", "form", "logo", "position")
    logo_inclusion = _nested(settings, "componentClasses", "form", "logo", "formInclusion")
    logo_location = _nested(settings, "componentClasses", "form", "logo", "location")
    logo_alignment = {"LEFT": "flex-start", "RIGHT": "flex-end"}.get(logo_location, "center")
    logo_before = logo_html if logo_position != "BOTTOM" else ""
    logo_after = logo_html if logo_position == "BOTTOM" else ""
    inner_logo_before = logo_before if logo_inclusion != "OUT" else ""
    inner_logo_after = logo_after if logo_inclusion != "OUT" else ""
    outer_logo_before = logo_before if logo_inclusion == "OUT" else ""
    outer_logo_after = logo_after if logo_inclusion == "OUT" else ""
    header_html = (
        '<header class="global-header">'
        + (f'<img alt="" src="{html.escape(header_logo, quote=True)}">' if header_logo else "")
        + "</header>"
        if header_enabled
        else ""
    )
    footer_html = (
        '<footer class="global-footer">'
        + (f'<img alt="" src="{html.escape(footer_logo, quote=True)}">' if footer_logo else "")
        + "</footer>"
        if footer_enabled
        else ""
    )
    header_background_css = (
        f'background-image:url("{header_background}");background-size:cover;'
        if header_background
        else ""
    )
    footer_background_css = (
        f'background-image:url("{footer_background}");background-size:cover;'
        if footer_background
        else ""
    )
    managed_login_version = presentation.get("managed_login_version", 1)
    classic_style = classic_logo = ""
    if managed_login_version == 1:
        classic_style, classic_logo = classic_markup(presentation.get("classic_customization"))
        content = _classic_content(content)
    page_class = (
        "managed-login-v2"
        if managed_login_version == 2
        else "classic-login background-customizable"
    )
    classic_brand = (
        ""
        if managed_login_version == 2
        else classic_logo or '<div class="classic-brand logo-customizable">Cognito</div>'
    )
    main_class = "" if managed_login_version == 2 else ' class="banner-customizable"'
    body = f"""<!doctype html>
<html lang="en" data-managed-login-version="{managed_login_version}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>{favicon_html}<style>
body{{font-family:system-ui,sans-serif;background:{page_color};{background_css}margin:0;display:flex;flex-direction:column;min-height:100vh}}
main{{box-sizing:border-box;background-color:{form_color};{form_background_css}border:1px solid {form_border};border-radius:{form_radius};padding:{form_padding};width:min(24rem,calc(100% - 3rem));box-shadow:0 8px 30px #17203314;margin:{main_margin}}}
.global-header,.global-footer{{box-sizing:border-box;min-height:4rem;padding:1rem;{header_background_css}}}.global-footer{{{footer_background_css}}}.global-header img,.global-footer img{{display:block;max-height:3rem;max-width:14rem;margin:auto}}
.form-logo{{display:block;align-self:{logo_alignment};max-height:5rem;max-width:70%;margin:1rem}}main .form-logo{{margin:0 0 {heading_margin}}}h1{{font-size:1.5rem;margin:0 0 {heading_margin}}}label{{display:block;font-weight:600;margin:{field_margin} 0 .35rem}}
input{{box-sizing:border-box;width:100%;padding:.75rem;border:1px solid #8b95a5;border-radius:{input_radius};font:inherit}}
button{{width:100%;margin-top:1.4rem;padding:.8rem;border:0;border-radius:{button_radius};background:{button_color};color:{button_text};font:inherit;font-weight:700}}
.provider{{box-sizing:border-box;display:block;width:100%;margin-top:1rem;padding:.8rem;border:1px solid {button_color};border-radius:{button_radius};color:{button_color};text-align:center;text-decoration:none;font-weight:700}}
.error{{color:#b42318;background:#fef3f2;padding:.7rem;border-radius:7px}}.signup,.terms{{font-size:.875rem;text-align:center;margin-top:1rem}}{adaptive_css}
</style>{classic_style}</head><body class="{page_class}">{header_html}{outer_logo_before}<main{main_class}>{classic_brand}{inner_logo_before}{content}{inner_logo_after}</main>{outer_logo_after}{footer_html}</body></html>"""
    response = Response(body, status=status, mimetype="text/html")
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return _secure_no_store(response)


def _classic_content(content: str) -> str:
    result = re.sub(r"<label(?=[ >])", '<label class="label-customizable"', content)
    result = re.sub(r"<input(?=[ >])", '<input class="inputField-customizable"', result)
    result = re.sub(r"<button(?=[ >])", '<button class="submitButton-customizable"', result)
    result = result.replace('class="provider"', 'class="provider idpButton-customizable"')
    result = result.replace('class="error"', 'class="error errorMessage-customizable"')
    result = result.replace('class="signup"', 'class="signup redirect-customizable"')
    result = result.replace("<h1>", '<h1 class="textDescription-customizable">')
    return result


def _nested(value: Any, *path: str) -> Any:
    for name in path:
        if not isinstance(value, dict):
            return None
        value = value.get(name)
    return value


def _css_color(value: Any, fallback: str) -> str:
    if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{8}", value):
        return f"#{value}"
    return fallback


def _css_radius(value: Any, fallback: int) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 64:
        return f"{value:g}px"
    return f"{fallback}px"


def _select_asset(assets: list[Any], category: str, scheme: Any):
    desired = "DARK" if scheme == "DARK" else "LIGHT"
    return next(
        (asset for asset in assets if asset.category == category and asset.color_mode == desired),
        next(
            (
                asset
                for asset in assets
                if asset.category == category and asset.color_mode == "DYNAMIC"
            ),
            None,
        ),
    )


def _asset_data_uri(asset: Any) -> str | None:
    if asset is None:
        return None
    mime = {
        "ICO": "image/x-icon",
        "JPEG": "image/jpeg",
        "PNG": "image/png",
        "SVG": "image/svg+xml",
        "WEBP": "image/webp",
    }.get(asset.extension)
    if mime is None or not isinstance(asset.content, bytes):
        return None
    return f"data:{mime};base64,{base64.b64encode(asset.content).decode()}"


def base64_url_sha256(value: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).rstrip(b"=").decode()


def _oauth_context(account_id: str, region: str, arn: str) -> RequestContext:
    context = RequestContext(None)
    context.account_id = account_id
    context.region = region
    context.partition = arn.split(":", 2)[1]
    return context


def _pool_region(pool_id: str) -> str | None:
    if match := _POOL_ID_RE.fullmatch(pool_id):
        return match.group("region")
    return None


def _serialize_jwks(raw_jwks: Any) -> bytes:
    if not isinstance(raw_jwks, list) or len(raw_jwks) != 2:
        raise TypeError("JWKS must contain the access and ID signing keys")

    keys: list[dict[str, str]] = []
    for raw_jwk in raw_jwks:
        if not isinstance(raw_jwk, dict):
            raise TypeError("JWK must be an object")

        key: dict[str, str] = {}
        for field in _JWK_FIELDS:
            value = raw_jwk.get(field)
            if not isinstance(value, str) or not value or len(value) > _JWK_FIELD_LIMITS[field]:
                raise ValueError(f"invalid public JWK field: {field}")
            key[field] = value

        if key["alg"] != "RS256" or key["kty"] != "RSA" or key["use"] != "sig":
            raise ValueError("unsupported public JWK")
        keys.append(key)

    if keys[0]["kid"] == keys[1]["kid"]:
        raise ValueError("access and ID signing keys must have distinct key IDs")

    payload = json.dumps(
        {"keys": keys},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(payload) > MAX_JWKS_BYTES:
        raise ValueError("JWKS response exceeds size limit")
    return payload


def _not_found() -> Response:
    return _error_response(404, "Not Found")


def _internal_error() -> Response:
    return _error_response(500, "Internal Server Error")


def _error_response(status: int, message: str) -> Response:
    payload = json.dumps({"message": message}, separators=(",", ":")).encode("utf-8")
    response = Response(payload, status=status, mimetype="application/json")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
